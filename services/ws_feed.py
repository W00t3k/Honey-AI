"""
WebSocket broadcast service for real-time dashboard feed.

Maintains a set of connected admin WebSocket clients and broadcasts
structured events the moment they happen — no polling required.

Event types emitted:
  - request_new      : a new request was logged (summary fields only, fast)
  - request_analysis : Groq analysis completed for a request
  - canary_hit       : a canary key was reused (confirmed credential theft)
  - trap_hit         : an LLM agent trap was triggered
  - stats_update     : aggregate stat counters changed
"""

import asyncio
import json
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Optional

from fastapi import WebSocket
from rich.console import Console

console = Console()


@dataclass
class FeedEvent:
    """A single event broadcast to all connected dashboard clients."""
    event_type: str                           # request_new | request_analysis | canary_hit | trap_hit | stats_update
    request_id: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    data: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({
            "type": self.event_type,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "data": self.data,
        }, default=str)


class WebSocketFeedManager:
    """
    Manages all active admin WebSocket connections and broadcasts events.

    Thread-safe enough for asyncio — all mutations happen from the same
    event loop so we don't need explicit locking.
    """

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)
        console.print(f"[dim cyan]WS feed: client connected ({len(self._connections)} total)[/dim cyan]")

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)
        console.print(f"[dim cyan]WS feed: client disconnected ({len(self._connections)} remaining)[/dim cyan]")

    async def broadcast(self, event: FeedEvent) -> None:
        """Send an event to all connected clients. Remove stale connections silently."""
        if not self._connections:
            return
        payload = event.to_json()
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)

    @property
    def connected_count(self) -> int:
        return len(self._connections)

    # ------------------------------------------------------------------
    # Convenience emitters called from logger.py
    # ------------------------------------------------------------------

    async def emit_new_request(self, request_id: int, data: dict) -> None:
        """Broadcast a newly logged request (trimmed payload for speed)."""
        await self.broadcast(FeedEvent(
            event_type="request_new",
            request_id=request_id,
            data={
                "id": request_id,
                "timestamp": data.get("timestamp", datetime.utcnow()).isoformat()
                    if hasattr(data.get("timestamp"), "isoformat") else str(data.get("timestamp", "")),
                "source_ip": data.get("source_ip"),
                "country_name": data.get("country_name"),
                "country_code": data.get("country_code"),
                "method": data.get("method"),
                "path": data.get("path"),
                "protocol": data.get("protocol"),
                "classification": data.get("classification"),
                "threat_level": None,               # filled later by analysis event
                "agent_type": data.get("agent_type"),
                "trap_hit": data.get("trap_hit"),
                "trap_type": data.get("trap_type"),
                "response_delta_ms": data.get("response_delta_ms"),
                "has_tool_calls": data.get("has_tool_calls"),
                "framework": data.get("framework"),
                "model_requested": data.get("model_requested"),
                "api_key": (data.get("api_key") or "")[:14] or None,
                "user_agent": (data.get("user_agent") or "")[:120] or None,
                "asn_org": data.get("asn_org"),
                "attack_stage": data.get("attack_stage"),
                "attack_chain_id": data.get("attack_chain_id"),
                "owasp_categories": data.get("owasp_categories") or [],
                "mitre_atlas_tags": data.get("mitre_atlas_tags") or [],
                "cwe_ids": data.get("cwe_ids") or [],
                "source_port": data.get("source_port"),
                "city": data.get("city"),
                "session_fingerprint": data.get("session_fingerprint"),
                "classification_confidence": data.get("classification_confidence"),
                "response_time_ms": data.get("response_time_ms"),
                "notes": None,
                "is_flagged": False,
            },
        ))

    async def emit_analysis(self, request_id: int, analysis) -> None:
        """Broadcast Groq analysis completion so the row updates in place."""
        await self.broadcast(FeedEvent(
            event_type="request_analysis",
            request_id=request_id,
            data={
                "threat_level": analysis.threat_level,
                "threat_type": analysis.threat_type,
                "ai_actor_type": getattr(analysis, "actor_type", "unknown"),
                "ai_summary": analysis.summary,
                "ai_details": analysis.details,
                "ai_recommendations": analysis.recommendations,
                "ai_iocs": analysis.iocs,
                "ai_confidence": analysis.confidence,
            },
        ))

    async def emit_canary_hit(self, request_id: int, api_key: str, source_ip: str,
                               country: str, path: str, label: str) -> None:
        """Broadcast a confirmed canary key reuse — highest priority alert."""
        await self.broadcast(FeedEvent(
            event_type="canary_hit",
            request_id=request_id,
            data={
                "api_key_prefix": api_key[:20],
                "source_ip": source_ip,
                "country": country,
                "path": path,
                "label": label,
            },
        ))

    async def emit_trap_hit(self, request_id: int, trap_type: str, source_ip: str,
                             path: str, delta_ms: Optional[float]) -> None:
        """Broadcast a confirmed agent trap hit."""
        await self.broadcast(FeedEvent(
            event_type="trap_hit",
            request_id=request_id,
            data={
                "trap_type": trap_type,
                "source_ip": source_ip,
                "path": path,
                "response_delta_ms": delta_ms,
            },
        ))


# Process-global singleton
_manager: Optional[WebSocketFeedManager] = None


def get_ws_manager() -> WebSocketFeedManager:
    global _manager
    if _manager is None:
        _manager = WebSocketFeedManager()
    return _manager
