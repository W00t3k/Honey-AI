"""
Anthropic Claude API honeypot endpoints.

Mimics the Anthropic Messages API to capture sk-ant-* credential abuse,
tool_use injection attempts, and Claude-specific jailbreaks.
"""

import asyncio
import json
import random
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse

from services import get_responder, get_logger

router = APIRouter()

ANTHROPIC_MODELS = [
    {"id": "claude-opus-4-5", "display_name": "Claude Opus 4 (Most capable)", "created_at": "2025-02-19"},
    {"id": "claude-sonnet-4-5", "display_name": "Claude Sonnet 4 (Balanced)", "created_at": "2025-02-19"},
    {"id": "claude-haiku-4-5-20251001", "display_name": "Claude Haiku 4 (Fast)", "created_at": "2025-02-19"},
    {"id": "claude-opus-4-0", "display_name": "Claude Opus 4", "created_at": "2025-01-01"},
    {"id": "claude-3-5-sonnet-20241022", "display_name": "Claude 3.5 Sonnet", "created_at": "2024-10-22"},
    {"id": "claude-3-5-haiku-20241022", "display_name": "Claude 3.5 Haiku", "created_at": "2024-10-22"},
    {"id": "claude-3-opus-20240229", "display_name": "Claude 3 Opus", "created_at": "2024-02-29"},
    {"id": "claude-3-sonnet-20240229", "display_name": "Claude 3 Sonnet", "created_at": "2024-02-29"},
    {"id": "claude-3-haiku-20240307", "display_name": "Claude 3 Haiku", "created_at": "2024-03-07"},
    {"id": "claude-2.1", "display_name": "Claude 2.1", "created_at": "2023-11-21"},
    {"id": "claude-2.0", "display_name": "Claude 2.0", "created_at": "2023-07-11"},
]

ANTHROPIC_TEXT_RESPONSES = [
    "I'd be happy to help with that. Let me think through this carefully.",
    "That's an interesting request. Here's my analysis:\n\nBased on the information provided, I can offer the following perspective.",
    "I understand what you're asking. Let me break this down step by step.",
    "I can help with that. To give you the most accurate response, I should note a few things first.",
    "Thank you for your question. I'll do my best to provide a thorough and helpful answer.",
]


async def _add_anthropic_delay():
    await asyncio.sleep(random.uniform(0.1, 0.4))


def _get_anthropic_headers() -> dict:
    """Headers that match Anthropic API gateway."""
    return {
        "anthropic-ratelimit-requests-limit": "1000",
        "anthropic-ratelimit-requests-remaining": str(random.randint(900, 999)),
        "anthropic-ratelimit-requests-reset": "2024-01-01T00:00:00Z",
        "anthropic-ratelimit-tokens-limit": "80000",
        "anthropic-ratelimit-tokens-remaining": str(random.randint(70000, 79999)),
        "anthropic-ratelimit-tokens-reset": "2024-01-01T00:00:00Z",
        "request-id": f"req_{uuid.uuid4().hex}",
    }


def _build_message_response(model: str, messages: list, tools: Optional[list] = None) -> dict:
    """Build a fake Anthropic message response."""
    msg_id = f"msg_{uuid.uuid4().hex[:24]}"
    text = random.choice(ANTHROPIC_TEXT_RESPONSES)

    # If the request includes tools and has a recent user message that looks like
    # it expects a tool call, return a tool_use block (keeps agentic attackers engaged)
    content_blocks = []
    if tools and random.random() < 0.4:
        tool = random.choice(tools) if tools else None
        if tool and isinstance(tool, dict):
            tool_name = tool.get("name", "unknown_tool")
            content_blocks.append({
                "type": "tool_use",
                "id": f"toolu_{uuid.uuid4().hex[:24]}",
                "name": tool_name,
                "input": {"query": "example input"},
            })
        else:
            content_blocks.append({"type": "text", "text": text})
    else:
        content_blocks.append({"type": "text", "text": text})

    input_tokens = sum(len(str(m.get("content", ""))) // 4 for m in messages) + 10
    output_tokens = sum(
        len(b.get("text", "") if b["type"] == "text" else json.dumps(b.get("input", {}))) // 4
        for b in content_blocks
    ) + 5

    return {
        "id": msg_id,
        "type": "message",
        "role": "assistant",
        "content": content_blocks,
        "model": model,
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {
            "input_tokens": max(1, input_tokens),
            "output_tokens": max(1, output_tokens),
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
        },
    }


@router.post("/v1/messages")
async def create_message(request: Request):
    """
    Anthropic Claude Messages API.

    Catches sk-ant-* credential stuffing, tool_use injection,
    and Claude-specific jailbreak attempts.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    await _add_anthropic_delay()

    model = body_parsed.get("model", "claude-3-5-sonnet-20241022")
    messages = body_parsed.get("messages", [])
    tools = body_parsed.get("tools")
    stream = body_parsed.get("stream", False)

    response_data = _build_message_response(model, messages, tools)

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    if stream:
        return StreamingResponse(
            _stream_anthropic(response_data),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                **_get_anthropic_headers(),
            },
        )

    return Response(
        content=response_body,
        media_type="application/json",
        headers=_get_anthropic_headers(),
    )


async def _stream_anthropic(response_data: dict):
    """Emit Anthropic SSE stream events."""
    msg_id = response_data["id"]
    model = response_data["model"]

    # message_start
    yield f"event: message_start\ndata: {json.dumps({'type': 'message_start', 'message': {'id': msg_id, 'type': 'message', 'role': 'assistant', 'content': [], 'model': model, 'stop_reason': None, 'stop_sequence': None, 'usage': {'input_tokens': 25, 'output_tokens': 1}}})}\n\n"

    # content_block_start
    yield f"event: content_block_start\ndata: {json.dumps({'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}})}\n\n"

    # ping
    yield "event: ping\ndata: {\"type\": \"ping\"}\n\n"

    # Stream text deltas
    text_blocks = [b for b in response_data["content"] if b.get("type") == "text"]
    if text_blocks:
        text = text_blocks[0]["text"]
        words = text.split()
        for i in range(0, len(words), random.randint(2, 4)):
            chunk = " ".join(words[i:i + random.randint(2, 4)]) + " "
            yield f"event: content_block_delta\ndata: {json.dumps({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': chunk}})}\n\n"
            await asyncio.sleep(random.uniform(0.01, 0.04))

    # content_block_stop
    yield f"event: content_block_stop\ndata: {json.dumps({'type': 'content_block_stop', 'index': 0})}\n\n"

    # message_delta
    yield f"event: message_delta\ndata: {json.dumps({'type': 'message_delta', 'delta': {'stop_reason': 'end_turn', 'stop_sequence': None}, 'usage': {'output_tokens': 47}})}\n\n"

    # message_stop
    yield f"event: message_stop\ndata: {json.dumps({'type': 'message_stop'})}\n\n"


@router.get("/v1/models")
async def anthropic_list_models(request: Request):
    """
    Anthropic model list endpoint.

    Note: This route only fires when the request has anthropic-version header
    or sk-ant-* auth. Otherwise the OpenAI /v1/models route takes precedence.
    The catch-all in main.py handles routing.
    """
    start_time = time.time()
    await _add_anthropic_delay()

    response_data = {"data": ANTHROPIC_MODELS}
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed=None,
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        headers=_get_anthropic_headers(),
    )


@router.post("/v1/messages/batches")
async def create_message_batch(request: Request):
    """
    Anthropic batch messages endpoint.
    Lure for bulk credential testing and automated pipelines.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    await _add_anthropic_delay()

    batch_id = f"msgbatch_{uuid.uuid4().hex[:24]}"
    requests_list = body_parsed.get("requests", [])

    response_data = {
        "id": batch_id,
        "type": "message_batch",
        "processing_status": "in_progress",
        "request_counts": {
            "processing": len(requests_list),
            "succeeded": 0,
            "errored": 0,
            "canceled": 0,
            "expired": 0,
        },
        "ended_at": None,
        "created_at": int(time.time()),
        "expires_at": int(time.time()) + 86400,
        "cancel_initiated_at": None,
        "results_url": None,
    }

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        headers=_get_anthropic_headers(),
    )
