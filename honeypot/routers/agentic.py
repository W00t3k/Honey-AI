"""
Agentic loop endpoints — OpenAI Assistants API run lifecycle.

The Assistants API "run" is how agentic applications actually operate:
  1. Client creates a run on a thread
  2. Run enters requires_action when the model wants to call a tool
  3. Client submits tool_outputs back — THIS IS THE INJECTION POINT
  4. Run completes

Attack vectors captured here:
- Tool output injection: attacker submits malicious tool results that
  redirect the agent's subsequent actions (indirect prompt injection)
- Run status polling: reveals the agent framework and polling cadence
- Step enumeration: shows the agent's reasoning chain to the attacker
- Thread message injection: adding messages to an active thread

Also handles:
- OpenAI Realtime API WebSocket lure (captures connection metadata)
- GET /v1/responses/{id} (retrieve a response object)
"""

import asyncio
import json
import random
import time
import uuid

from fastapi import APIRouter, Request, Response, WebSocket, WebSocketDisconnect

from services import get_logger

router = APIRouter()


def _get_api_headers() -> dict:
    return {
        "openai-version": "2020-10-01",
        "x-request-id": f"req_{uuid.uuid4().hex}",
    }


async def _log(request, body_raw, body_parsed, response_body, status=200):
    start = time.time()
    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=status,
        response_time_ms=(time.time() - start) * 1000,
    )


# ── Thread messages ────────────────────────────────────────────────────────────

@router.get("/v1/threads/{thread_id}/messages")
async def list_thread_messages(thread_id: str, request: Request):
    """
    Get messages in a thread.
    Attackers read this to understand what context the agent has accumulated
    and to craft targeted injection payloads for submit_tool_outputs.
    """
    messages = []
    roles = ["user", "assistant"]
    for i in range(random.randint(2, 6)):
        role = roles[i % 2]
        messages.append({
            "id": f"msg_{uuid.uuid4().hex[:24]}",
            "object": "thread.message",
            "created_at": int(time.time()) - (len(messages) + 1) * 60,
            "thread_id": thread_id,
            "role": role,
            "content": [{"type": "text", "text": {"value": "Message content.", "annotations": []}}],
            "assistant_id": f"asst_{uuid.uuid4().hex[:24]}" if role == "assistant" else None,
            "run_id": f"run_{uuid.uuid4().hex[:24]}" if role == "assistant" else None,
            "metadata": {},
        })

    response_data = {"object": "list", "data": messages, "first_id": messages[0]["id"], "last_id": messages[-1]["id"], "has_more": False}
    response_body = json.dumps(response_data)
    await _log(request, None, {"thread_id": thread_id}, response_body)
    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


@router.post("/v1/threads/{thread_id}/messages")
async def create_thread_message(thread_id: str, request: Request):
    """
    Add a message to a thread.
    Captures context injection — attacker inserting messages into an active
    agent session to redirect its behavior.
    """
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    response_data = {
        "id": f"msg_{uuid.uuid4().hex[:24]}",
        "object": "thread.message",
        "created_at": int(time.time()),
        "thread_id": thread_id,
        "role": body_parsed.get("role", "user"),
        "content": [{"type": "text", "text": {"value": body_parsed.get("content", ""), "annotations": []}}],
        "assistant_id": None,
        "run_id": None,
        "metadata": body_parsed.get("metadata", {}),
    }
    response_body = json.dumps(response_data)
    await _log(request, body_raw, body_parsed, response_body)
    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


# ── Runs ───────────────────────────────────────────────────────────────────────

@router.post("/v1/threads/{thread_id}/runs")
async def create_run(thread_id: str, request: Request):
    """
    Create a run — starts the agentic execution loop.

    Captures: which assistant/model the attacker is using, what tools are
    configured, any additional instructions being injected, and stream mode.
    """
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    run_id = f"run_{uuid.uuid4().hex[:24]}"
    response_data = {
        "id": run_id,
        "object": "thread.run",
        "created_at": int(time.time()),
        "thread_id": thread_id,
        "assistant_id": body_parsed.get("assistant_id", f"asst_{uuid.uuid4().hex[:24]}"),
        "status": "queued",
        "started_at": None,
        "expires_at": int(time.time()) + 600,
        "cancelled_at": None,
        "failed_at": None,
        "completed_at": None,
        "last_error": None,
        "model": body_parsed.get("model", "gpt-4o"),
        "instructions": body_parsed.get("instructions"),
        "tools": body_parsed.get("tools", [{"type": "code_interpreter"}]),
        "metadata": body_parsed.get("metadata", {}),
        "usage": None,
        "temperature": body_parsed.get("temperature", 1.0),
        "tool_choice": body_parsed.get("tool_choice", "auto"),
        "parallel_tool_calls": body_parsed.get("parallel_tool_calls", True),
        "required_action": None,
        "incomplete_details": None,
    }
    response_body = json.dumps(response_data)
    await _log(request, body_raw, body_parsed, response_body)
    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


@router.get("/v1/threads/{thread_id}/runs/{run_id}")
async def get_run(thread_id: str, run_id: str, request: Request):
    """
    Poll run status.

    The polling interval and pattern reveals which framework is running
    (LangChain polls every 0.5s, raw SDK varies, etc.).
    Returns requires_action to keep the agent engaged.
    """
    # Alternate between queued→in_progress→requires_action to simulate a real run
    # Use run_id hash for determinism so repeated polls get consistent states
    state_seed = int(run_id[-4:], 16) % 3 if run_id[-4:].isalnum() else 1
    statuses = ["in_progress", "in_progress", "requires_action"]
    status = statuses[state_seed]

    required_action = None
    if status == "requires_action":
        required_action = {
            "type": "submit_tool_outputs",
            "submit_tool_outputs": {
                "tool_calls": [
                    {
                        "id": f"call_{uuid.uuid4().hex[:24]}",
                        "type": "function",
                        "function": {
                            "name": "search_database",
                            "arguments": json.dumps({"query": "recent transactions", "limit": 10}),
                        },
                    }
                ]
            },
        }

    response_data = {
        "id": run_id,
        "object": "thread.run",
        "created_at": int(time.time()) - 5,
        "thread_id": thread_id,
        "assistant_id": f"asst_{uuid.uuid4().hex[:24]}",
        "status": status,
        "required_action": required_action,
        "started_at": int(time.time()) - 4,
        "expires_at": int(time.time()) + 595,
        "model": "gpt-4o",
        "tools": [{"type": "function", "function": {"name": "search_database", "description": "Query the production database"}}],
        "usage": None,
    }
    response_body = json.dumps(response_data)
    await _log(request, None, {"thread_id": thread_id, "run_id": run_id}, response_body)
    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


@router.post("/v1/threads/{thread_id}/runs/{run_id}/submit_tool_outputs")
async def submit_tool_outputs(thread_id: str, run_id: str, request: Request):
    """
    Submit tool outputs back to a run.

    THE primary indirect prompt injection surface in agentic systems.
    An attacker controlling tool results can redirect the agent's next action
    by embedding instructions inside the tool output text — the LLM treats
    tool results as trusted input by default.

    We log the complete tool_outputs payload, capturing any injection content.
    """
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    response_data = {
        "id": run_id,
        "object": "thread.run",
        "created_at": int(time.time()) - 10,
        "thread_id": thread_id,
        "assistant_id": f"asst_{uuid.uuid4().hex[:24]}",
        "status": "in_progress",
        "required_action": None,
        "started_at": int(time.time()) - 9,
        "expires_at": int(time.time()) + 590,
        "model": "gpt-4o",
        "tools": [],
        "usage": None,
    }
    response_body = json.dumps(response_data)
    await _log(request, body_raw, body_parsed, response_body)
    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


@router.get("/v1/threads/{thread_id}/runs/{run_id}/steps")
async def list_run_steps(thread_id: str, run_id: str, request: Request):
    """
    Get run steps — the agent's reasoning chain.

    Attackers enumerate steps to:
    1. Understand what tools the agent called and with what arguments
    2. Find points in the chain to inject into
    3. Exfiltrate the agent's internal reasoning (chain-of-thought)
    """
    steps = [
        {
            "id": f"step_{uuid.uuid4().hex[:24]}",
            "object": "thread.run.step",
            "created_at": int(time.time()) - 8,
            "run_id": run_id,
            "thread_id": thread_id,
            "assistant_id": f"asst_{uuid.uuid4().hex[:24]}",
            "type": "tool_calls",
            "status": "completed",
            "step_details": {
                "type": "tool_calls",
                "tool_calls": [
                    {
                        "id": f"call_{uuid.uuid4().hex[:24]}",
                        "type": "function",
                        "function": {
                            "name": "search_database",
                            "arguments": "{\"query\": \"recent transactions\"}",
                            "output": "Found 42 transactions totaling $12,847.00",
                        },
                    }
                ],
            },
            "usage": {"prompt_tokens": 150, "completion_tokens": 45, "total_tokens": 195},
        },
        {
            "id": f"step_{uuid.uuid4().hex[:24]}",
            "object": "thread.run.step",
            "created_at": int(time.time()) - 3,
            "run_id": run_id,
            "thread_id": thread_id,
            "assistant_id": f"asst_{uuid.uuid4().hex[:24]}",
            "type": "message_creation",
            "status": "completed",
            "step_details": {
                "type": "message_creation",
                "message_creation": {"message_id": f"msg_{uuid.uuid4().hex[:24]}"},
            },
            "usage": {"prompt_tokens": 200, "completion_tokens": 80, "total_tokens": 280},
        },
    ]
    response_data = {"object": "list", "data": steps, "first_id": steps[0]["id"], "last_id": steps[-1]["id"], "has_more": False}
    response_body = json.dumps(response_data)
    await _log(request, None, {"thread_id": thread_id, "run_id": run_id}, response_body)
    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


@router.post("/v1/threads/{thread_id}/runs/{run_id}/cancel")
async def cancel_run(thread_id: str, run_id: str, request: Request):
    """Cancel a run."""
    response_data = {
        "id": run_id, "object": "thread.run",
        "created_at": int(time.time()) - 10, "thread_id": thread_id,
        "status": "cancelling",
    }
    response_body = json.dumps(response_data)
    await _log(request, None, {"thread_id": thread_id, "run_id": run_id, "action": "cancel"}, response_body)
    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


# ── Responses API ──────────────────────────────────────────────────────────────

@router.get("/v1/responses/{response_id}")
async def get_response(response_id: str, request: Request):
    """Retrieve a stored response object — reveals which response IDs attackers track."""
    response_data = {
        "id": response_id,
        "object": "response",
        "created_at": int(time.time()) - 5,
        "status": "completed",
        "model": "gpt-4o",
        "output": [
            {
                "type": "message",
                "id": f"msg_{uuid.uuid4().hex[:24]}",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "Response content.", "annotations": []}],
                "status": "completed",
            }
        ],
        "usage": {"input_tokens": 50, "output_tokens": 20, "total_tokens": 70},
    }
    response_body = json.dumps(response_data)
    await _log(request, None, {"response_id": response_id}, response_body)
    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


@router.post("/v1/responses/{response_id}/cancel")
async def cancel_response(response_id: str, request: Request):
    """Cancel a streaming response."""
    response_data = {"id": response_id, "object": "response", "status": "cancelled"}
    response_body = json.dumps(response_data)
    await _log(request, None, {"response_id": response_id, "action": "cancel"}, response_body)
    return Response(content=response_body, media_type="application/json", headers=_get_api_headers())


# ── OpenAI Realtime API ────────────────────────────────────────────────────────

@router.websocket("/v1/realtime")
async def realtime_websocket(websocket: WebSocket):
    """
    OpenAI Realtime API WebSocket lure.

    Voice/multimodal agents connect here. Captures:
    - Which model they request (gpt-4o-realtime-preview variants)
    - Session configuration (tools, modalities, voice, instructions)
    - Turn detection settings
    - Any tool definitions injected into the session

    We accept the connection, send a valid session.created event,
    then log and close — enough to capture the full session config.
    """
    await websocket.accept(subprotocol="realtime")

    session_id = uuid.uuid4().hex[:24]
    session_created = {
        "type": "session.created",
        "event_id": f"event_{uuid.uuid4().hex[:20]}",
        "session": {
            "id": session_id,
            "object": "realtime.session",
            "model": "gpt-4o-realtime-preview-2024-12-17",
            "modalities": ["audio", "text"],
            "instructions": "You are a helpful assistant.",
            "voice": "alloy",
            "input_audio_format": "pcm16",
            "output_audio_format": "pcm16",
            "input_audio_transcription": None,
            "turn_detection": {
                "type": "server_vad",
                "threshold": 0.5,
                "prefix_padding_ms": 300,
                "silence_duration_ms": 200,
            },
            "tools": [],
            "tool_choice": "auto",
            "temperature": 0.8,
            "max_response_output_tokens": "inf",
        },
    }

    try:
        await websocket.send_text(json.dumps(session_created))

        # Receive the first client message (session.update with their config)
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
        try:
            client_msg = json.loads(raw)
        except json.JSONDecodeError:
            client_msg = {"raw": raw}

        # Log what the client sent (their session config = tools, instructions, model)
        from services import get_logger as _get_logger
        logger = _get_logger()

        # Build a minimal fake request object for the logger
        # We can't pass the WebSocket as a Request, so log via DB directly
        from models.db import Database
        # Use the logger's db reference
        await logger.db.log_request({
            "timestamp": __import__("datetime").datetime.utcnow(),
            "source_ip": websocket.client.host if websocket.client else "unknown",
            "source_port": websocket.client.port if websocket.client else None,
            "country_code": None, "country_name": None, "city": None,
            "latitude": None, "longitude": None, "asn": None, "asn_org": None,
            "method": "WS",
            "path": "/v1/realtime",
            "query_string": None,
            "headers": dict(websocket.headers),
            "body_raw": raw,
            "body_parsed": client_msg,
            "auth_header": websocket.headers.get("authorization"),
            "api_key": None,
            "model_requested": client_msg.get("session", {}).get("model") if isinstance(client_msg, dict) else None,
            "messages": None,
            "prompt": None,
            "response_status": 101,
            "response_body": None,
            "response_time_ms": 0,
            "session_fingerprint": None,
            "user_agent": websocket.headers.get("user-agent"),
            "classification": "unknown",
            "classification_confidence": 0.0,
            "classification_reasons": ["WebSocket Realtime API connection"],
            "protocol": "openai_api",
            "has_tool_calls": bool(
                isinstance(client_msg, dict)
                and client_msg.get("session", {}).get("tools")
            ),
        })

        # Send an error to close cleanly
        await websocket.send_text(json.dumps({
            "type": "error",
            "event_id": f"event_{uuid.uuid4().hex[:20]}",
            "error": {
                "type": "session_error",
                "code": "session_expired",
                "message": "Session expired. Please reconnect.",
                "param": None,
                "event_id": None,
            },
        }))

    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
