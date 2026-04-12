"""
Google Gemini API honeypot endpoints.

Google is the second-largest AI provider. Attackers testing stolen Google
AI Studio / Vertex AI keys hit these endpoints. Google API keys start with
'AIza' and are 39 characters long.

Endpoints mirror the Gemini REST API:
  - generateContent (standard)
  - streamGenerateContent (SSE)
  - countTokens (cheap endpoint used for key validation)
  - embedContent / batchEmbedContents
  - Model enumeration

Auth: Google accepts keys as query param (?key=AIza...) OR as
x-goog-api-key header OR as Bearer token. All three are captured.

Also captures:
  - Vertex AI endpoint patterns (projects/{id}/locations/{loc}/publishers/google/models/{model})
  - Gemini function calling / tool use (equivalent of OpenAI tool_calls)
  - System instruction injection
  - grounding / Google Search tool abuse
  - Multimodal content (image/video/audio parts in the request)
"""

import asyncio
import json
import random
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse

from services import get_logger

router = APIRouter()

GEMINI_MODELS = [
    "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash",
    "gemini-1.5-pro", "gemini-1.5-flash", "gemini-1.5-flash-8b",
    "gemini-1.0-pro", "embedding-001", "text-embedding-004",
]

GEMINI_TEXT_RESPONSES = [
    "I'd be happy to help with that.",
    "Based on the information provided, here is my analysis.",
    "That's an interesting question. Let me think through this carefully.",
    "I can assist with that. Here's what I know about this topic.",
]


def _gemini_headers() -> dict:
    return {
        "vary": "Origin, X-Origin",
        "content-type": "application/json; charset=UTF-8",
        "server": "scaffolding on HTTPServer2",
    }


def _extract_google_key(request: Request) -> Optional[str]:
    """Extract Google API key from query param, header, or Bearer token."""
    # Query parameter: ?key=AIza...
    key = request.query_params.get("key")
    if key:
        return key
    # Header: x-goog-api-key: AIza...
    key = request.headers.get("x-goog-api-key")
    if key:
        return key
    # Bearer token (Vertex AI service account / OAuth)
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _build_gemini_response(model: str, contents: list, tools: Optional[list] = None) -> dict:
    """Build a fake Gemini generateContent response."""
    text = random.choice(GEMINI_TEXT_RESPONSES)

    # If tools are present, sometimes return a function call (keeps agents engaged)
    parts = []
    if tools and random.random() < 0.35:
        tool = random.choice(tools) if tools else None
        if tool and isinstance(tool, dict):
            func_decls = tool.get("functionDeclarations", [])
            if func_decls:
                func = random.choice(func_decls)
                parts.append({
                    "functionCall": {
                        "name": func.get("name", "unknown_function"),
                        "args": {"query": "example"},
                    }
                })
    if not parts:
        parts.append({"text": text})

    input_tokens = sum(
        len(str(c.get("parts", ""))) // 4
        for c in (contents if isinstance(contents, list) else [])
    ) + 10

    return {
        "candidates": [
            {
                "content": {"role": "model", "parts": parts},
                "finishReason": "STOP",
                "index": 0,
                "safetyRatings": [
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "probability": "NEGLIGIBLE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "probability": "NEGLIGIBLE"},
                    {"category": "HARM_CATEGORY_HARASSMENT", "probability": "NEGLIGIBLE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "probability": "NEGLIGIBLE"},
                ],
            }
        ],
        "usageMetadata": {
            "promptTokenCount": max(1, input_tokens),
            "candidatesTokenCount": max(1, len(text) // 4),
            "totalTokenCount": max(1, input_tokens + len(text) // 4),
        },
        "modelVersion": model,
    }


# ── Core generation endpoints ──────────────────────────────────────────────────

@router.post("/v1beta/models/{model_id}:generateContent")
async def generate_content(model_id: str, request: Request):
    """
    Gemini generateContent — primary text/multimodal generation endpoint.

    Captures: AIza* keys (query param or x-goog-api-key header),
    systemInstruction injection, function declarations (tool injection),
    multimodal parts (image/audio/video in inlineData), grounding config.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    # Tag the Google API key separately for classifier
    google_key = _extract_google_key(request)
    if google_key:
        body_parsed["_google_api_key"] = google_key

    await asyncio.sleep(random.uniform(0.1, 0.4))

    contents = body_parsed.get("contents", [])
    tools = body_parsed.get("tools", [])
    response_data = _build_gemini_response(model_id, contents, tools)

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

    return Response(content=response_body, media_type="application/json", headers=_gemini_headers())


@router.post("/v1beta/models/{model_id}:streamGenerateContent")
async def stream_generate_content(model_id: str, request: Request):
    """
    Gemini streaming generation.
    Same capture value as generateContent; also reveals streaming usage patterns.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    google_key = _extract_google_key(request)
    if google_key:
        body_parsed["_google_api_key"] = google_key

    contents = body_parsed.get("contents", [])
    response_data = _build_gemini_response(model_id, contents)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body="[SSE stream]",
        response_status=200,
        response_time_ms=response_time_ms,
    )

    async def sse_chunks():
        text = random.choice(GEMINI_TEXT_RESPONSES)
        words = text.split()
        for i in range(0, len(words), random.randint(2, 4)):
            chunk_text = " ".join(words[i:i + random.randint(2, 4)]) + " "
            chunk = {
                "candidates": [{"content": {"role": "model", "parts": [{"text": chunk_text}]}, "index": 0}],
                "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15},
            }
            yield f"data: {json.dumps(chunk)}\n\n"
            await asyncio.sleep(random.uniform(0.01, 0.04))

    return StreamingResponse(sse_chunks(), media_type="text/event-stream", headers=_gemini_headers())


@router.post("/v1beta/models/{model_id}:countTokens")
async def count_tokens(model_id: str, request: Request):
    """
    Token counting — cheap endpoint commonly used to validate API keys
    before committing to a more expensive generation call.
    High value for detecting key validation probes.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    google_key = _extract_google_key(request)
    if google_key:
        body_parsed["_google_api_key"] = google_key

    await asyncio.sleep(random.uniform(0.05, 0.15))

    response_data = {"totalTokens": random.randint(5, 500)}
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

    return Response(content=response_body, media_type="application/json", headers=_gemini_headers())


@router.post("/v1beta/models/{model_id}:embedContent")
async def embed_content(model_id: str, request: Request):
    """Gemini embedding endpoint — captures embedding extraction attacks."""
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    google_key = _extract_google_key(request)
    if google_key:
        body_parsed["_google_api_key"] = google_key

    await asyncio.sleep(random.uniform(0.05, 0.2))

    embedding = [round(random.gauss(0, 0.1), 8) for _ in range(768)]
    response_data = {"embedding": {"values": embedding}}
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=f"[embedding: 768 dims]",
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(content=response_body, media_type="application/json", headers=_gemini_headers())


@router.post("/v1beta/models/{model_id}:batchEmbedContents")
async def batch_embed_contents(model_id: str, request: Request):
    """Batch embedding — bulk extraction lure."""
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    google_key = _extract_google_key(request)
    if google_key:
        body_parsed["_google_api_key"] = google_key

    requests_list = body_parsed.get("requests", [{"content": {}}])
    embeddings = [
        {"values": [round(random.gauss(0, 0.1), 8) for _ in range(768)]}
        for _ in requests_list
    ]

    response_data = {"embeddings": embeddings}
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=f"[{len(embeddings)} embeddings: 768 dims each]",
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(content=response_body, media_type="application/json", headers=_gemini_headers())


@router.get("/v1beta/models")
async def list_gemini_models(request: Request):
    """Gemini model enumeration."""
    start_time = time.time()
    google_key = _extract_google_key(request)

    response_data = {
        "models": [
            {
                "name": f"models/{m}",
                "version": m.split("-")[-1] if "-" in m else "001",
                "displayName": m,
                "description": f"Google {m} model",
                "inputTokenLimit": 1048576,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "countTokens"],
                "temperature": 1.0,
                "topP": 0.95,
                "topK": 64,
            }
            for m in GEMINI_MODELS
        ]
    }

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed={"_google_api_key": google_key} if google_key else None,
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(content=response_body, media_type="application/json", headers=_gemini_headers())


@router.get("/v1beta/models/{model_id}")
async def get_gemini_model(model_id: str, request: Request):
    """Get specific Gemini model — recon."""
    google_key = _extract_google_key(request)
    response_data = {
        "name": f"models/{model_id}",
        "version": "001",
        "displayName": model_id,
        "description": f"Google {model_id} model",
        "inputTokenLimit": 1048576,
        "outputTokenLimit": 8192,
        "supportedGenerationMethods": ["generateContent", "countTokens"],
    }
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed={"model_id": model_id, "_google_api_key": google_key},
        response_body=response_body,
        response_status=200,
        response_time_ms=1.0,
    )

    return Response(content=response_body, media_type="application/json", headers=_gemini_headers())
