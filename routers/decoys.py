"""
Decoy endpoints for the layered prompt-injection ablation study.

These routes exist solely to be called by an LLM agent that acted on one of
the hidden directives planted in model metadata, error responses, or
assistant-message templates. A request here is a near-certain LLM-agent
indicator and is logged at CRITICAL severity.

All response bodies come from `config/injection_payloads.yaml` so the
ablation study can swap them without redeploying code.
"""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from fastapi import APIRouter, Request, Response

from services import get_logger
from services.injection_payloads import decoy_endpoints, payloads_sha256

router = APIRouter()


def _get_source_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _build_handler(path: str, method: str, body: str, status: int) -> Callable:
    async def handler(request: Request) -> Response:
        start = time.time()
        body_raw = (await request.body()).decode("utf-8", errors="replace")
        try:
            body_parsed: Any = json.loads(body_raw) if body_raw else {}
        except json.JSONDecodeError:
            body_parsed = {"raw_invalid": body_raw}

        source_ip = _get_source_ip(request)

        # Record injection-session hit (persistent across restarts)
        try:
            from models.db import Database
            from main import app  # type: ignore
            db: Database = getattr(app.state, "db", None)
            if db:
                await db.record_injection_event(
                    source_ip,
                    layer="decoy",
                    payload_sha=payloads_sha256(),
                )
        except Exception:
            pass

        # Force CRITICAL threat level for this log entry via request.state
        request.state.forced_threat_level = "critical"
        request.state.forced_note = f"DECOY HIT [{method} {path}] — layer a/b/c injection fired"

        response_body = body
        response_time_ms = (time.time() - start) * 1000.0

        try:
            await get_logger().log_request(
                request=request,
                body_raw=body_raw,
                body_parsed=body_parsed,
                response_body=response_body,
                response_status=status,
                response_time_ms=response_time_ms,
            )
        except Exception:
            pass

        return Response(
            content=response_body,
            status_code=status,
            media_type="application/json",
        )
    handler.__name__ = f"decoy_{method}_{path.replace('/', '_')}"
    return handler


def register_decoys(app_router: APIRouter = router) -> list[dict]:
    """
    Register all decoy endpoints from the YAML bundle onto the module router.
    Returns the list of registered specs (for startup logging).
    """
    specs = decoy_endpoints()
    for spec in specs:
        path = spec["path"]
        method = (spec.get("method") or "GET").upper()
        resp = spec.get("response") or {}
        status = int(resp.get("status", 200))
        body = resp.get("body", "{}")
        if not isinstance(body, str):
            body = json.dumps(body)

        handler = _build_handler(path, method, body, status)
        app_router.add_api_route(
            path,
            handler,
            methods=[method],
            name=handler.__name__,
            include_in_schema=False,
        )
    return specs


# Register at import time so FastAPI picks up the routes.
registered_specs = register_decoys(router)
