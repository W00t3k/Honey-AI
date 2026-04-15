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
from services.groq_chat import SSH_SHELL_PROMPT, get_groq_chat
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
        """Emulate a shell command."""
        command = (command or "").strip()
        if not command:
            return ""

        canned = self._canned_output(command)
        if canned is not None:
            return canned

        history = get_session_store().get_shell_history(source_ip)
        history_text = "\n".join(
            f"$ {turn['command']}\n{turn['output']}" for turn in history[-6:]
        )
        prompt = (
            f"Recent terminal history:\n{history_text or '(none)'}\n\n"
            f"Current command:\n{command}\n"
        )
        output = await get_groq_chat().complete(
            [{"role": "user", "content": prompt}],
            system_prompt=SSH_SHELL_PROMPT,
            temperature=random.uniform(0.35, 0.8),
            max_tokens=280,
        )
        return output.strip() if output else self._fallback_output(command)

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

    def _canned_output(self, command: str) -> Optional[str]:
        """Handle common shell commands without calling the LLM."""
        if command in {"whoami", "id -un"}:
            return "appsvc"
        if command == "pwd":
            return "/home/appsvc"
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
