"""
In-memory session history for conversational deception.

Tracks recent chat and shell turns per source so the honeypot can respond
consistently across repeated requests from the same attacker infrastructure.
"""

from collections import defaultdict, deque
from threading import Lock
from typing import Optional


class SessionStore:
    """Bounded in-memory conversation store keyed by source and protocol."""

    def __init__(self, max_messages: int = 20, max_shell_turns: int = 20) -> None:
        self.max_messages = max_messages
        self.max_shell_turns = max_shell_turns
        self._lock = Lock()
        self._chat_sessions: dict[str, deque[dict]] = defaultdict(
            lambda: deque(maxlen=self.max_messages)
        )
        self._shell_sessions: dict[str, deque[dict]] = defaultdict(
            lambda: deque(maxlen=self.max_shell_turns)
        )

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
