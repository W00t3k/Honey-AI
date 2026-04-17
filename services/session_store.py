"""
In-memory session history for conversational deception.

Tracks recent chat and shell turns per source so the honeypot can respond
consistently across repeated requests from the same attacker infrastructure.
"""

from collections import defaultdict, deque
from threading import Lock
from typing import Optional


class ShellState:
    """Persistent state for an SSH session — working directory, files, env vars."""

    def __init__(self):
        self.cwd: str = "/home/appsvc"
        self.env: dict[str, str] = {
            "USER": "appsvc",
            "HOME": "/home/appsvc",
            "SHELL": "/bin/bash",
            "PATH": "/home/appsvc/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": "/home/appsvc",
        }
        # Track files/dirs created in this session (set of absolute paths)
        self.created: set[str] = set()
        # Track any canary key the session has been exposed to
        self.exposed_canary: Optional[str] = None


class SessionStore:
    """Bounded in-memory conversation store keyed by source and protocol."""

    def __init__(self, max_messages: int = 20, max_shell_turns: int = 30) -> None:
        self.max_messages = max_messages
        self.max_shell_turns = max_shell_turns
        self._lock = Lock()
        self._chat_sessions: dict[str, deque[dict]] = defaultdict(
            lambda: deque(maxlen=self.max_messages)
        )
        self._shell_sessions: dict[str, deque[dict]] = defaultdict(
            lambda: deque(maxlen=self.max_shell_turns)
        )
        # Persistent shell state per IP
        self._shell_state: dict[str, ShellState] = {}
        # Engagement turn counter per (protocol, source) — how many probes sent
        self._engagement_turns: dict[str, int] = defaultdict(int)
        # Accumulated tradecraft per source (survives across turns)
        self._tradecraft: dict[str, dict] = defaultdict(dict)

    def _chat_key(self, source: str, protocol: str) -> str:
        return f"{protocol}:{source or 'unknown'}"

    def _shell_key(self, source: str) -> str:
        return source or "unknown"

    def get_chat_history(self, source: str, protocol: str = "openai_api") -> list[dict]:
        """Return recent messages for the source/protocol pair."""
        with self._lock:
            return list(self._chat_sessions[self._chat_key(source, protocol)])

    def record_chat_turn(
        self,
        source: str,
        incoming_messages: Optional[list],
        assistant_content: str,
        protocol: str = "openai_api",
    ) -> None:
        """Persist a compact version of the latest request/response turn."""
        if not assistant_content:
            return

        key = self._chat_key(source, protocol)
        normalized_messages: list[dict] = []
        for msg in incoming_messages or []:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "")).strip()
            if role not in {"user", "assistant", "tool"}:
                continue
            content = self._coerce_content(msg.get("content"))
            if content:
                normalized_messages.append({"role": role, "content": content})

        with self._lock:
            session = self._chat_sessions[key]
            for msg in normalized_messages[-6:]:
                session.append(msg)
            session.append({"role": "assistant", "content": assistant_content})

    def get_shell_history(self, source: str) -> list[dict]:
        """Return recent shell commands and outputs for the source."""
        with self._lock:
            return list(self._shell_sessions[self._shell_key(source)])

    def record_shell_turn(self, source: str, command: str, output: str) -> None:
        """Persist a shell command/result pair."""
        if not command:
            return
        with self._lock:
            self._shell_sessions[self._shell_key(source)].append(
                {"command": command.strip(), "output": output.strip()}
            )

    # ── Shell state (HoneyGPT-style persistent session) ───────────────────────

    def get_shell_state(self, source: str) -> "ShellState":
        """Return (or create) the persistent shell state for this IP."""
        with self._lock:
            key = self._shell_key(source)
            if key not in self._shell_state:
                self._shell_state[key] = ShellState()
            return self._shell_state[key]

    def update_shell_cwd(self, source: str, new_cwd: str) -> None:
        """Update the working directory for a session."""
        with self._lock:
            state = self._shell_state.setdefault(self._shell_key(source), ShellState())
            state.cwd = new_cwd
            state.env["PWD"] = new_cwd

    def add_shell_created(self, source: str, path: str) -> None:
        """Track a file/directory created during the session."""
        with self._lock:
            state = self._shell_state.setdefault(self._shell_key(source), ShellState())
            state.created.add(path)

    def set_shell_env(self, source: str, key: str, value: str) -> None:
        """Set an environment variable for the session."""
        with self._lock:
            state = self._shell_state.setdefault(self._shell_key(source), ShellState())
            state.env[key] = value

    # ── Engagement tracking ───────────────────────────────────────────────────

    def get_engagement_turn(self, source: str, protocol: str = "openai_api") -> int:
        """Return current engagement turn count for this source/protocol."""
        with self._lock:
            return self._engagement_turns[self._chat_key(source, protocol)]

    def bump_engagement_turn(self, source: str, protocol: str = "openai_api") -> int:
        """Increment and return the new turn count."""
        with self._lock:
            key = self._chat_key(source, protocol)
            self._engagement_turns[key] += 1
            return self._engagement_turns[key]

    def get_tradecraft(self, source: str) -> dict:
        """Return accumulated tradecraft fields for this source."""
        with self._lock:
            return dict(self._tradecraft[self._shell_key(source)])

    def merge_tradecraft(self, source: str, fields: dict) -> dict:
        """Merge new non-empty tradecraft fields into accumulated state."""
        with self._lock:
            key = self._shell_key(source)
            for k, v in (fields or {}).items():
                if v and v != "unknown":
                    self._tradecraft[key][k] = v
            return dict(self._tradecraft[key])

    def _coerce_content(self, content: object) -> str:
        """Flatten provider-specific content blocks into text."""
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            parts: list[str] = []
            for block in content:
                if isinstance(block, str):
                    parts.append(block)
                elif isinstance(block, dict):
                    text = block.get("text") or block.get("content")
                    if isinstance(text, str):
                        parts.append(text)
            return "\n".join(part.strip() for part in parts if part and part.strip())
        return str(content).strip() if content is not None else ""


_session_store: Optional[SessionStore] = None


def get_session_store() -> SessionStore:
    """Return the process-global session store."""
    global _session_store
    if _session_store is None:
        _session_store = SessionStore()
    return _session_store
