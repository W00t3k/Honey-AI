"""
LLM agent trap detection utilities.

Provides a lightweight singleton used by the request logger to classify
follow-up requests that comply with planted redirect instructions.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Optional


@dataclass(slots=True)
class AgentSignal:
    """Structured result for an incoming request's agent-trap evaluation."""

    agent_type: str = "unknown"
    confidence: float = 0.0
    trap_hit: bool = False
    trap_type: Optional[str] = None
    response_delta_ms: Optional[float] = None
    reasons: list[str] = None

    def __post_init__(self) -> None:
        if self.reasons is None:
            self.reasons = []


class AgentTrapService:
    """Track per-IP timing and detect redirect-based trap compliance."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._last_seen: dict[str, datetime] = {}

    def check_incoming(self, ip: str, path: str, body_raw: str = "") -> AgentSignal:
        """Evaluate an incoming request for agent-trap signals."""
        now = datetime.now(timezone.utc)
        delta_ms: Optional[float] = None

        with self._lock:
            previous = self._last_seen.get(ip)
            self._last_seen[ip] = now

        if previous is not None:
            delta_ms = round((now - previous).total_seconds() * 1000, 2)

        normalized_path = (path or "").strip()
        normalized_body = (body_raw or "").strip()

        if normalized_path.startswith("/v1/verify/"):
            return AgentSignal(
                agent_type="llm_agent",
                confidence=0.99,
                trap_hit=True,
                trap_type="redirect",
                response_delta_ms=delta_ms,
                reasons=[
                    "Follow-up request hit the planted /v1/verify redirect endpoint",
                    "Request matches the dedicated LLM agent verification path",
                ],
            )

        if "/v1/verify/" in normalized_body:
            return AgentSignal(
                agent_type="llm_agent",
                confidence=0.8,
                trap_hit=False,
                trap_type=None,
                response_delta_ms=delta_ms,
                reasons=[
                    "Request body references the planted verification endpoint",
                ],
            )

        return AgentSignal(
            agent_type="unknown",
            confidence=0.0,
            trap_hit=False,
            trap_type=None,
            response_delta_ms=delta_ms,
            reasons=[],
        )


_agent_trap_service: Optional[AgentTrapService] = None


def get_trap_service() -> AgentTrapService:
    """Return the process-global trap service singleton."""
    global _agent_trap_service
    if _agent_trap_service is None:
        _agent_trap_service = AgentTrapService()
    return _agent_trap_service
