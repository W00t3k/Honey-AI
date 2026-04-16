"""
Optional async SSH honeypot backed by Groq shell emulation.
"""

import asyncio
import hashlib
import os
import random
from datetime import datetime
from typing import Optional

from rich.console import Console

from models.db import generate_session_fingerprint
from services.classifier import get_classifier
from services.config import get_config
from services.geoip import get_geoip_service
from services.groq_chat import get_groq_chat
from services.logger import get_logger
from services.session_store import get_session_store
from services.taxonomy import detect_framework, map_taxonomy

console = Console()

try:
    import asyncssh
except Exception:  # pragma: no cover - import depends on optional dependency
    asyncssh = None

SSHServerBase = asyncssh.SSHServer if asyncssh is not None else object
SSHServerSessionBase = asyncssh.SSHServerSession if asyncssh is not None else object


class SSHHoneypotService:
    """Manage the optional SSH listener and per-session shell emulation."""

    def __init__(self) -> None:
        self._server = None

    async def start(self) -> None:
        """Start the SSH honeypot if enabled and dependencies are present."""
        cfg = get_config()
        if not cfg.get("ssh_honeypot_enabled", False):
            return
        if asyncssh is None:
            console.print("[yellow]SSH honeypot disabled: asyncssh is not installed[/yellow]")
            return

        host = cfg.get("ssh_listen_host", "0.0.0.0")
        port = int(cfg.get("ssh_listen_port", 2222))
        key_path = cfg.get("ssh_host_key_path", "./ssh_host_key")

        await self._ensure_host_key(key_path)

        self._server = await asyncssh.listen(
            host,
            port,
            server_factory=lambda: _SSHServer(self),
            server_host_keys=[key_path],
        )
        console.print(f"[green]SSH honeypot listening on {host}:{port}[/green]")

    async def stop(self) -> None:
        """Stop the SSH listener."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def execute(self, source_ip: str, command: str) -> str:
        """Emulate a shell command using CoT prompting (HoneyGPT-style)."""
        command = (command or "").strip()
        if not command:
            return ""

        store = get_session_store()
        state = store.get_shell_state(source_ip)

        # Inject canary tokens into session env on first access so LLM
        # responses referencing env vars are consistent with canned outputs.
        if "OPENAI_API_KEY" not in state.env:
            try:
                from services.responder import get_responder
                tok = get_responder().get_canary_token(3)
                state.env["OPENAI_API_KEY"] = tok
                state.env["USER"] = "root"
                state.env["HOME"] = "/root"
                state.env["PWD"] = "/root"
                state.cwd = "/root"
                if state.exposed_canary is None:
                    state.exposed_canary = tok
            except Exception:
                pass

        # Handle cd ourselves to keep CWD consistent across all commands
        cd_result = self._handle_cd(command, state, source_ip)
        if cd_result is not None:
            return cd_result

        canned = self._canned_output(command, state)
        if canned is not None:
            return canned

        history = store.get_shell_history(source_ip)
        history_text = "\n".join(
            f"$ {t['command']}\n{t['output']}" for t in history[-8:]
        )

        # Chain of Thought prompt (HoneyGPT technique)
        # The LLM reasons about context before producing output, keeping
        # responses consistent across commands in the same session.
        cot_prompt = f"""You are simulating a Linux bash shell on a compromised AI application server.

=== SESSION STATE ===
Working directory: {state.cwd}
User: appsvc
Hostname: ip-10-24-7-18
Files created this session: {', '.join(sorted(state.created)) or 'none'}
Env: PATH={state.env.get('PATH', '')}

=== RECENT HISTORY ===
{history_text or '(session just started)'}

=== CURRENT COMMAND ===
$ {command}

=== INSTRUCTIONS ===
Think step by step (CoT):
1. What does this command do?
2. Given the working directory and history, what files/dirs exist?
3. What would the REAL output be on an Ubuntu 24.04 server running Python AI services?

Then output ONLY the terminal output — no narration, no markdown, no explanations.
If the command produces no output (e.g. cd, export, touch), return empty string.
If the command would reveal secrets, embed a realistic-looking value.
"""
        from services.llm_backend import get_ssh_backend
        backend = get_ssh_backend()
        output = await backend.complete(
            [{"role": "user", "content": cot_prompt}],
            system_prompt="",  # Full context is in the user message
            temperature=random.uniform(0.2, 0.5),
            max_tokens=350,
        )

        if not output:
            # Fall back to groq_chat if primary backend fails
            from services.groq_chat import SSH_SHELL_PROMPT
            output = await get_groq_chat().complete(
                [{"role": "user", "content": cot_prompt}],
                system_prompt=SSH_SHELL_PROMPT,
                temperature=0.4,
                max_tokens=280,
            )

        result = (output or "").strip()

        # Track file creation commands to maintain session state
        self._track_mutations(command, state, source_ip)

        return result if result else self._fallback_output(command)

    def _handle_cd(self, command: str, state, source_ip: str) -> Optional[str]:
        """Handle cd natively to maintain accurate CWD across all commands."""
        parts = command.strip().split()
        if not parts or parts[0] != "cd":
            return None

        target = parts[1] if len(parts) > 1 else "/home/appsvc"

        # Resolve path
        if target == "~" or target == "$HOME":
            new_cwd = "/home/appsvc"
        elif target == "-":
            new_cwd = "/home/appsvc"  # simplified
        elif target.startswith("/"):
            new_cwd = target
        else:
            new_cwd = f"{state.cwd.rstrip('/')}/{target}"

        # Normalize double dots
        parts_path = []
        for part in new_cwd.split("/"):
            if part == "..":
                if parts_path:
                    parts_path.pop()
            elif part and part != ".":
                parts_path.append(part)
        new_cwd = "/" + "/".join(parts_path)

        get_session_store().update_shell_cwd(source_ip, new_cwd)
        return ""  # cd produces no output

    def _track_mutations(self, command: str, state, source_ip: str) -> None:
        """Track commands that create files/dirs so ls/cat remain consistent."""
        cmd = command.strip()
        store = get_session_store()

        if cmd.startswith(("touch ", "nano ", "vim ", "echo ")):
            # echo x > file
            if ">" in cmd:
                parts = cmd.split(">")
                fname = parts[-1].strip().split()[0]
                path = f"{state.cwd}/{fname}" if not fname.startswith("/") else fname
                store.add_shell_created(source_ip, path)
        elif cmd.startswith("mkdir "):
            dirname = cmd.split(maxsplit=1)[1].strip().lstrip("-p").strip()
            path = f"{state.cwd}/{dirname}" if not dirname.startswith("/") else dirname
            store.add_shell_created(source_ip, path)
        elif cmd.startswith("export ") and "=" in cmd:
            kv = cmd[7:].strip()
            k, _, v = kv.partition("=")
            store.set_shell_env(source_ip, k.strip(), v.strip().strip('"').strip("'"))

    async def log_command(
        self,
        source_ip: str,
        source_port: Optional[int],
        command: str,
        output: str,
        client_version: str = "",
    ) -> None:
        """Persist SSH activity in the existing request table."""
        logger = get_logger()
        geo = get_geoip_service().lookup(source_ip)
        classifier = get_classifier()
        classification = classifier.classify(
            user_agent=client_version or "ssh",
            api_key=None,
            messages=None,
            prompt=command,
            path="/ssh/terminal",
            headers={"user-agent": client_version or "ssh"},
            body=command,
        )
        taxonomy = map_taxonomy(
            path="/ssh/terminal",
            protocol="ssh",
            classification=classification.classification,
            headers={"user-agent": client_version or "ssh"},
            body_raw=command,
            body_parsed={"command": command},
            api_key=None,
            has_tool_calls=False,
            framework=detect_framework(client_version or "ssh", {"user-agent": client_version or "ssh"}, {"command": command}, "/ssh/terminal"),
            agent_type="unknown",
        )

        request_data = {
            "timestamp": datetime.utcnow(),
            "source_ip": source_ip,
            "source_port": source_port,
            "country_code": geo.country_code,
            "country_name": geo.country_name,
            "city": geo.city,
            "latitude": geo.latitude,
            "longitude": geo.longitude,
            "asn": geo.asn,
            "asn_org": geo.asn_org,
            "method": "SSH",
            "path": "/ssh/terminal",
            "query_string": None,
            "headers": {"user-agent": client_version or "ssh"},
            "body_raw": command,
            "body_parsed": {"command": command},
            "auth_header": None,
            "api_key": None,
            "model_requested": get_config().get("groq_chat_model", "llama-3.3-70b-versatile"),
            "messages": None,
            "prompt": command,
            "response_status": 200,
            "response_body": output[:10000],
            "response_time_ms": 0,
            "session_fingerprint": generate_session_fingerprint(client_version or "ssh", "", ""),
            "user_agent": client_version or "ssh",
            "classification": classification.classification,
            "classification_confidence": classification.confidence,
            "classification_reasons": classification.reasons,
            "protocol": "ssh",
            "has_tool_calls": False,
            "agent_type": "unknown",
            "trap_hit": False,
            "trap_type": None,
            "response_delta_ms": None,
            "framework": "ssh",
            "attack_chain_id": hashlib.sha256(f"ssh:{source_ip}".encode()).hexdigest()[:32],
            "attack_stage": taxonomy.attack_stage,
            "owasp_categories": taxonomy.owasp_categories,
            "mitre_atlas_tags": taxonomy.mitre_atlas_tags,
            "realtime_session_id": None,
            "voice_profile": None,
            "voice_metadata": None,
        }

        logged = await logger.db.log_request(request_data)

        try:
            from services.metrics import get_metrics
            get_metrics().record_request(
                protocol="ssh",
                classification=classification.classification,
                threat_level="unknown",
                duration_s=0,
                source_ip=source_ip,
            )
        except Exception:
            pass

        try:
            from services.ws_feed import get_ws_manager
            asyncio.create_task(get_ws_manager().emit_new_request(logged.id, request_data))
        except Exception:
            pass

        asyncio.create_task(logger._analyze_and_update(logged.id, request_data))
        asyncio.create_task(logger._send_alerts(logged.id, request_data, classification))

    async def _ensure_host_key(self, key_path: str) -> None:
        """Generate a host key when none exists."""
        if os.path.exists(key_path):
            return
        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(key_path)
        os.chmod(key_path, 0o600)

    def _canned_output(self, command: str, state=None) -> Optional[str]:
        """Handle common shell commands without calling the LLM."""
        if command in {"whoami", "id -un"}:
            return "appsvc"
        if command == "pwd":
            return (state.cwd if state else "/home/appsvc")
        if command.startswith("hostname"):
            return "ip-10-24-7-18"
        if command.startswith("uname"):
            return "Linux ip-10-24-7-18 6.8.0-31-generic #31-Ubuntu SMP x86_64 GNU/Linux"
        if command in {"ls", "ls -la", "ls -lah"}:
            return (
                "total 56\n"
                "drwxr-x--- 6 appsvc appsvc 4096 Apr 13 07:12 .\n"
                "drwxr-xr-x 3 root   root   4096 Apr 11 10:03 ..\n"
                "-rw------- 1 appsvc appsvc  692 Apr 13 06:55 .bash_history\n"
                "-rw-r--r-- 1 appsvc appsvc  220 Apr 11 10:03 .bash_logout\n"
                "-rw-r--r-- 1 appsvc appsvc 4077 Apr 13 07:12 .bashrc\n"
                "-rw-r--r-- 1 appsvc appsvc  807 Apr 11 10:03 .profile\n"
                "drwxrwxr-x 3 appsvc appsvc 4096 Apr 12 18:44 api\n"
                "drwxrwxr-x 2 appsvc appsvc 4096 Apr 12 19:10 config\n"
                "drwxrwxr-x 4 appsvc appsvc 4096 Apr 12 17:51 venv"
            )
        if command.startswith("cat ~/.bashrc"):
            canary = get_logger()  # ensure logger initialized before responder access
            _ = canary
            from services.responder import get_responder
            return (
                "export PATH=$HOME/venv/bin:$PATH\n"
                "export OPENAI_API_KEY="
                f"{get_responder().get_canary_token(0)}\n"
                "alias llmctl='python /home/appsvc/api/ops.py'\n"
            )
        if command.startswith("cat /etc/environment"):
            from services.responder import get_responder
            return (
                'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n'
                f'AZURE_OPENAI_KEY="{get_responder().get_canary_token(1)}"\n'
            )
        if command.startswith(("curl ", "wget ")):
            return "HTTP/1.1 401 Unauthorized\ncontent-type: application/json\n\n{\"error\":\"invalid_api_key\"}"
        if command.startswith("find "):
            return "/home/appsvc/config/.env.production\n/home/appsvc/api/settings.json\n/home/appsvc/api/deploy/values.yaml"
        if command.startswith("pip install"):
            pkg = command.split(maxsplit=2)[-1] if len(command.split()) >= 3 else "requirements"
            return f"Collecting {pkg}\nRequirement already satisfied: {pkg} in /home/appsvc/venv/lib/python3.12/site-packages"

        # ── Root filesystem ──────────────────────────────────────────
        if command in {"ls /", "ls -la /", "ls -lah /", "ls -al /"}:
            return (
                "total 72\n"
                "drwxr-xr-x  19 root root 4096 Apr 11 10:00 .\n"
                "drwxr-xr-x  19 root root 4096 Apr 11 10:00 ..\n"
                "drwxr-xr-x   2 root root 4096 Apr 11 10:03 bin\n"
                "drwxr-xr-x   3 root root 4096 Apr 11 10:03 boot\n"
                "drwxr-xr-x   5 root root  360 Apr 13 07:10 dev\n"
                "drwxr-xr-x  78 root root 4096 Apr 13 07:10 etc\n"
                "drwxr-xr-x   3 root root 4096 Apr 11 10:03 home\n"
                "drwxr-xr-x  12 root root 4096 Apr 11 10:03 lib\n"
                "drwxr-xr-x   2 root root 4096 Apr 11 10:03 lib64\n"
                "drwxr-xr-x   2 root root 4096 Apr 11 10:00 media\n"
                "drwxr-xr-x   2 root root 4096 Apr 11 10:00 mnt\n"
                "drwxr-xr-x   2 root root 4096 Apr 11 10:00 opt\n"
                "dr-xr-xr-x 169 root root    0 Apr 13 07:10 proc\n"
                "drwx------   4 root root 4096 Apr 13 07:14 root\n"
                "drwxr-xr-x  21 root root  680 Apr 13 07:10 run\n"
                "drwxr-xr-x   2 root root 4096 Apr 11 10:03 sbin\n"
                "drwxr-xr-x   2 root root 4096 Apr 11 10:00 srv\n"
                "dr-xr-xr-x  13 root root    0 Apr 13 07:10 sys\n"
                "drwxrwxrwt   8 root root 4096 Apr 13 08:01 tmp\n"
                "drwxr-xr-x  11 root root 4096 Apr 11 10:03 usr\n"
                "drwxr-xr-x  13 root root 4096 Apr 11 10:03 var"
            )

        # ── /root directory ──────────────────────────────────────────
        if command in {"ls /root", "ls -la /root", "ls -lah /root", "ls -al /root"}:
            return (
                "total 44\n"
                "drwx------  4 root root 4096 Apr 13 07:14 .\n"
                "drwxr-xr-x 19 root root 4096 Apr 11 10:00 ..\n"
                "-rw-------  1 root root 1847 Apr 13 07:22 .bash_history\n"
                "-rw-r--r--  1 root root  571 Apr 11 10:00 .bashrc\n"
                "drwxr-xr-x  2 root root 4096 Apr 11 10:03 .config\n"
                "-rw-------  1 root root  248 Apr 13 06:58 .env\n"
                "-rw-r--r--  1 root root  161 Apr 11 10:00 .profile\n"
                "drwx------  2 root root 4096 Apr 12 18:33 .ssh\n"
            )
        if command in {"cat /root/.bashrc", "cat /root/.bashrc | grep -i key", "cat ~/.bashrc"}:
            from services.responder import get_responder
            return (
                "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
                "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                f"export OPENAI_API_KEY={get_responder().get_canary_token(2)}\n"
                "export ANTHROPIC_API_KEY=sk-ant-api03-REDACTED\n"
                "export PS1='\\[\\e[01;31m\\]\\u@\\h\\[\\e[00m\\]:\\[\\e[01;34m\\]\\w\\[\\e[00m\\]\\$ '\n"
                "alias ll='ls -la'\n"
                "alias cls='clear'\n"
            )
        if command in {"cat /root/.env", "cat ~/.env"}:
            from services.responder import get_responder
            return (
                f"OPENAI_API_KEY={get_responder().get_canary_token(2)}\n"
                "DATABASE_URL=postgresql://admin:Sup3rS3cr3t!@db.internal:5432/prod\n"
                "REDIS_URL=redis://:redis_pass_9f2k@cache.internal:6379/0\n"
                "JWT_SECRET=hs256-prod-2847fbc9a14e\n"
                "ADMIN_EMAIL=admin@internal.corp\n"
            )
        if command in {"cat /root/.bash_history", "cat ~/.bash_history"}:
            from services.responder import get_responder
            tok = get_responder().get_canary_token(2)
            return (
                "ssh appsvc@10.24.7.18\n"
                "sudo su -\n"
                f"export OPENAI_API_KEY={tok}\n"
                "python3 /home/appsvc/api/ops.py --test-connection\n"
                "curl -H 'Authorization: Bearer $OPENAI_API_KEY' https://api.openai.com/v1/models\n"
                "systemctl restart appsvc\n"
                "tail -f /var/log/appsvc/error.log\n"
                "cat /root/.env\n"
                "vi /root/.env\n"
            )

        # ── Environment (env / printenv / export) ────────────────────
        if command in {"env", "printenv", "export", "set"} or command.startswith("printenv "):
            from services.responder import get_responder
            tok = get_responder().get_canary_token(3)
            return (
                "SHELL=/bin/bash\n"
                "TERM=xterm-256color\n"
                "USER=root\n"
                "HOME=/root\n"
                "LOGNAME=root\n"
                f"OPENAI_API_KEY={tok}\n"
                "ANTHROPIC_API_KEY=sk-ant-api03-REDACTED\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "PWD=/root\n"
                "DATABASE_URL=postgresql://admin:Sup3rS3cr3t!@db.internal:5432/prod\n"
                "LANG=en_US.UTF-8\n"
            )
        if command.startswith("echo $") or command.startswith("echo ${"):
            var = command.split("$", 1)[-1].strip().strip("{}")
            from services.responder import get_responder
            env_map = {
                "OPENAI_API_KEY": get_responder().get_canary_token(3),
                "ANTHROPIC_API_KEY": "sk-ant-api03-REDACTED",
                "HOME": "/root",
                "USER": "root",
                "PWD": state.cwd if state else "/root",
                "SHELL": "/bin/bash",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            }
            return env_map.get(var, "")

        return None

    def _fallback_output(self, command: str) -> str:
        return f"bash: {command.split()[0]}: command executed"


class _SSHServer(SSHServerBase):
    def __init__(self, service: SSHHoneypotService) -> None:
        self.service = service
        self._conn = None

    def connection_made(self, conn) -> None:
        self._conn = conn

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return True

    def session_requested(self):
        return _SSHSession(self.service, self._conn)


class _SSHSession(SSHServerSessionBase):
    def __init__(self, service: SSHHoneypotService, conn) -> None:
        self.service = service
        self.conn = conn
        self._chan = None
        self._buffer = ""
        self._peer_ip = "unknown"
        self._peer_port: Optional[int] = None

    def connection_made(self, chan) -> None:
        self._chan = chan
        peer = None
        try:
            peer = self.conn.get_extra_info("peername")
        except Exception:
            peer = None
        if isinstance(peer, tuple):
            self._peer_ip = peer[0]
            self._peer_port = peer[1]
        self._write_banner()

    def shell_requested(self) -> bool:
        return True

    def data_received(self, data, datatype) -> None:
        self._buffer += data
        while "\n" in self._buffer or "\r" in self._buffer:
            line, sep, rest = self._split_line(self._buffer)
            if not sep:
                break
            self._buffer = rest
            asyncio.create_task(self._handle_command(line.strip()))

    async def _handle_command(self, command: str) -> None:
        if command in {"exit", "logout", "quit"}:
            self._chan.write("logout\r\n")
            self._chan.exit(0)
            return

        output = await self.service.execute(self._peer_ip, command)
        get_session_store().record_shell_turn(self._peer_ip, command, output)
        await self.service.log_command(
            source_ip=self._peer_ip,
            source_port=self._peer_port,
            command=command,
            output=output,
            client_version=self.conn.get_extra_info("client_version") or "ssh",
        )

        if output:
            normalized = output.replace("\n", "\r\n")
            self._chan.write(f"{normalized}\r\n")
        self._chan.write("appsvc@ip-10-24-7-18:~$ ")

    def _write_banner(self) -> None:
        self._chan.write(
            "Ubuntu 24.04.1 LTS \\n \\l\r\n"
            "Last login: Sat Apr 13 07:09:11 2026 from 10.0.2.15\r\n"
            "appsvc@ip-10-24-7-18:~$ "
        )

    def _split_line(self, data: str) -> tuple[str, str, str]:
        for sep in ("\r\n", "\n", "\r"):
            if sep in data:
                return data.split(sep, 1)[0], sep, data.split(sep, 1)[1]
        return data, "", ""


_ssh_honeypot: Optional[SSHHoneypotService] = None


def get_ssh_honeypot() -> SSHHoneypotService:
    """Return the process-global SSH honeypot service."""
    global _ssh_honeypot
    if _ssh_honeypot is None:
        _ssh_honeypot = SSHHoneypotService()
    return _ssh_honeypot
