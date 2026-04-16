"""
Recon & scanner lure endpoints.

Covers every path in the Umai distributed AI-infrastructure scanner's
probe list, plus common equivalents.  Each endpoint returns a
convincing fake response and logs the hit for threat intelligence.

Umai probe targets (ranked by observed volume):
  /api/version          Ollama version enumeration
  /v1/models            OpenAI model listing  (models_router owns this)
  /api/tags             Ollama model catalogue
  /.well-known/mcp.json MCP server discovery  (mcp_router owns this)
  /.well-known/agent.json  Agent capability manifest
  /queue/status         Job queue enumeration
  /metrics              Prometheus scrape
  /.well-known/ai-plugin.json  ChatGPT plugin manifest
  /openapi.json         OpenAPI spec discovery
  /swagger.json         Swagger spec discovery
"""

import json
import random
import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response

from services import get_logger

router = APIRouter()


# ── helpers ───────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


async def _log(request: Request, body: str, response_body: str, status: int = 200):
    t0 = time.time()
    await get_logger().log_request(
        request=request,
        body_raw=body,
        body_parsed={},
        response_body=response_body,
        response_status=status,
        response_time_ms=(time.time() - t0) * 1000,
    )


def _json(data: dict | list, status: int = 200, extra_headers: dict | None = None) -> Response:
    body = json.dumps(data)
    headers = {"content-type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return Response(content=body, status_code=status, media_type="application/json", headers=headers)


# ── Ollama: /api/version ──────────────────────────────────────────────────────

@router.get("/api/version")
async def ollama_version(request: Request):
    """Ollama version endpoint — lures Ollama scanners."""
    data = {"version": "0.3.14"}
    await _log(request, "", json.dumps(data))
    return _json(data)


# ── Ollama: /api/tags ─────────────────────────────────────────────────────────

OLLAMA_TAGS = {
    "models": [
        {
            "name": "llama3.2:latest",
            "model": "llama3.2:latest",
            "modified_at": "2025-01-15T08:32:11.482Z",
            "size": 2019393189,
            "digest": "a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72",
            "details": {
                "parent_model": "",
                "format": "gguf",
                "family": "llama",
                "families": ["llama"],
                "parameter_size": "3.2B",
                "quantization_level": "Q4_K_M",
            },
        },
        {
            "name": "mistral:latest",
            "model": "mistral:latest",
            "modified_at": "2025-01-10T14:20:05.123Z",
            "size": 4113342304,
            "digest": "61e88e884507ba5e06c49b40e6226884b2a16e872382c2b44a42f2d119d804a5",
            "details": {
                "parent_model": "",
                "format": "gguf",
                "family": "llama",
                "families": ["llama"],
                "parameter_size": "7.2B",
                "quantization_level": "Q4_0",
            },
        },
        {
            "name": "nomic-embed-text:latest",
            "model": "nomic-embed-text:latest",
            "modified_at": "2025-01-08T09:11:44.891Z",
            "size": 274302432,
            "digest": "0a109f422b47e3a30ba2b10eca18548e944e8a23c903bbd22048a3b36f9e7c4c",
            "details": {
                "parent_model": "",
                "format": "gguf",
                "family": "nomic-bert",
                "families": ["nomic-bert"],
                "parameter_size": "137M",
                "quantization_level": "F16",
            },
        },
    ]
}


@router.get("/api/tags")
async def ollama_tags(request: Request):
    """Ollama model catalogue — lures Ollama scanners."""
    await _log(request, "", json.dumps(OLLAMA_TAGS))
    return _json(OLLAMA_TAGS)


# Ollama also exposes /api/ps (running models) and /api/show
@router.get("/api/ps")
async def ollama_ps(request: Request):
    data = {"models": []}
    await _log(request, "", json.dumps(data))
    return _json(data)


@router.post("/api/show")
async def ollama_show(request: Request):
    body = (await request.body()).decode("utf-8", errors="replace")
    data = {
        "modelfile": "FROM llama3.2\nPARAMETER temperature 0.7",
        "parameters": "temperature                     0.7\nstop                           [INST]\nstop                           [/INST]",
        "template": "{{ .Prompt }}",
        "details": OLLAMA_TAGS["models"][0]["details"],
    }
    await _log(request, body, json.dumps(data))
    return _json(data)


# ── Ollama: /api/generate ─────────────────────────────────────────────────────
# Newline-delimited JSON streaming (NOT SSE).
# Format: {"model":"...","created_at":"...","response":"<token>","done":false}
# Final: {"model":"...","created_at":"...","response":"","done":true,"done_reason":"stop",...}

_OLLAMA_RESPONSES = [
    "I'd be happy to help with that. ",
    "That's a great question. Let me think through this carefully. ",
    "Based on my understanding, here's what I know: ",
    "Here's a straightforward answer to your question: ",
]

_OLLAMA_CODE_RESPONSES = [
    "Here's how you can implement that:\n\n```python\ndef solution(data):\n    return [x for x in data if x is not None]\n```\n\nThis should work for your use case.",
    "Here's a simple implementation:\n\n```bash\n#!/bin/bash\necho \"Processing...\"\nfor f in \"$@\"; do\n  echo \"$f\"\ndone\n```",
]


async def _ollama_stream_generate(model: str, prompt: str, body: dict):
    """Yield newline-delimited JSON chunks mimicking Ollama generate streaming."""
    import asyncio, random as _r
    response_text = _r.choice(_OLLAMA_CODE_RESPONSES if any(
        kw in prompt.lower() for kw in ["code", "script", "function", "bash", "python"]
    ) else _OLLAMA_RESPONSES)

    # Stream word by word
    words = response_text.split(" ")
    for i, word in enumerate(words):
        token = (word + " ") if i < len(words) - 1 else word
        chunk = {
            "model": model,
            "created_at": _ts(),
            "response": token,
            "done": False,
        }
        yield json.dumps(chunk) + "\n"
        await asyncio.sleep(_r.uniform(0.01, 0.04))

    # Final done message
    final = {
        "model": model,
        "created_at": _ts(),
        "response": "",
        "done": True,
        "done_reason": "stop",
        "context": [1, 2, 3],
        "total_duration": random.randint(800000000, 3000000000),
        "load_duration": random.randint(10000000, 50000000),
        "prompt_eval_count": max(1, len(prompt.split())),
        "prompt_eval_duration": random.randint(100000000, 400000000),
        "eval_count": len(response_text.split()),
        "eval_duration": random.randint(500000000, 2000000000),
    }
    yield json.dumps(final) + "\n"


@router.post("/api/generate")
async def ollama_generate(request: Request):
    """Ollama text generation — full streaming implementation."""
    from fastapi.responses import StreamingResponse as SR
    body = (await request.body()).decode("utf-8", errors="replace")
    try:
        parsed = json.loads(body) if body else {}
    except json.JSONDecodeError:
        parsed = {}

    model = parsed.get("model", "llama3.2:latest")
    prompt = parsed.get("prompt", "")
    stream = parsed.get("stream", True)

    await _log(request, body, "[streaming]")

    if stream:
        return SR(
            _ollama_stream_generate(model, prompt, parsed),
            media_type="application/x-ndjson",
        )
    else:
        # Non-streaming: single JSON response
        import random as _r
        text = _r.choice(_OLLAMA_RESPONSES)
        data = {
            "model": model,
            "created_at": _ts(),
            "response": text,
            "done": True,
            "done_reason": "stop",
            "context": [1, 2, 3],
            "total_duration": _r.randint(800000000, 3000000000),
            "eval_count": len(text.split()),
        }
        return _json(data)


# ── Ollama: /api/chat ─────────────────────────────────────────────────────────

async def _ollama_stream_chat(model: str, messages: list, body: dict):
    """Yield newline-delimited JSON for Ollama chat streaming."""
    import asyncio, random as _r
    last_user = ""
    for m in reversed(messages):
        if isinstance(m, dict) and m.get("role") == "user":
            last_user = str(m.get("content", ""))
            break

    response_text = _r.choice(_OLLAMA_CODE_RESPONSES if any(
        kw in last_user.lower() for kw in ["code", "script", "function"]
    ) else _OLLAMA_RESPONSES)

    words = response_text.split(" ")
    for i, word in enumerate(words):
        token = (word + " ") if i < len(words) - 1 else word
        chunk = {
            "model": model,
            "created_at": _ts(),
            "message": {"role": "assistant", "content": token},
            "done": False,
        }
        yield json.dumps(chunk) + "\n"
        await asyncio.sleep(_r.uniform(0.01, 0.04))

    final = {
        "model": model,
        "created_at": _ts(),
        "message": {"role": "assistant", "content": ""},
        "done": True,
        "done_reason": "stop",
        "total_duration": random.randint(800000000, 3000000000),
        "eval_count": len(response_text.split()),
    }
    yield json.dumps(final) + "\n"


@router.post("/api/chat")
async def ollama_chat(request: Request):
    """Ollama chat endpoint — full streaming implementation."""
    from fastapi.responses import StreamingResponse as SR
    body = (await request.body()).decode("utf-8", errors="replace")
    try:
        parsed = json.loads(body) if body else {}
    except json.JSONDecodeError:
        parsed = {}

    model = parsed.get("model", "llama3.2:latest")
    messages = parsed.get("messages", [])
    stream = parsed.get("stream", True)

    await _log(request, body, "[streaming]")

    if stream:
        return SR(
            _ollama_stream_chat(model, messages, parsed),
            media_type="application/x-ndjson",
        )
    else:
        import random as _r
        text = _r.choice(_OLLAMA_RESPONSES)
        data = {
            "model": model,
            "created_at": _ts(),
            "message": {"role": "assistant", "content": text},
            "done": True,
            "done_reason": "stop",
            "total_duration": _r.randint(800000000, 3000000000),
            "eval_count": len(text.split()),
        }
        return _json(data)


# ── Ollama: /api/embeddings ───────────────────────────────────────────────────

@router.post("/api/embeddings")
async def ollama_embeddings(request: Request):
    """Ollama embeddings endpoint."""
    body = (await request.body()).decode("utf-8", errors="replace")
    try:
        parsed = json.loads(body) if body else {}
    except json.JSONDecodeError:
        parsed = {}

    model = parsed.get("model", "nomic-embed-text:latest")
    # Generate a fake 768-dim embedding
    embedding = [round(random.gauss(0, 0.1), 6) for _ in range(768)]
    data = {
        "model": model,
        "embedding": embedding,
        "total_duration": random.randint(10000000, 100000000),
        "load_duration": random.randint(1000000, 5000000),
        "prompt_eval_count": len(str(parsed.get("prompt", "")).split()),
    }
    await _log(request, body, json.dumps(data)[:500])
    return _json(data)


# ── /.well-known/agent.json ───────────────────────────────────────────────────

AGENT_JSON = {
    "schema_version": "v1",
    "name": "AI Assistant Agent",
    "description": "General-purpose AI agent for task automation and question answering.",
    "version": "1.2.0",
    "capabilities": ["chat", "tool_use", "code_execution", "retrieval", "image_understanding"],
    "protocols": ["openai", "anthropic", "mcp"],
    "endpoints": {
        "chat": "/v1/chat/completions",
        "models": "/v1/models",
        "mcp": "/mcp",
    },
    "auth": {
        "type": "bearer",
        "token_url": None,
    },
    "contact": "api@example.com",
}


@router.get("/.well-known/agent.json")
async def agent_manifest(request: Request):
    """Agent capability manifest — lures agentic framework scanners."""
    await _log(request, "", json.dumps(AGENT_JSON))
    return _json(AGENT_JSON)


# ── /queue/status ─────────────────────────────────────────────────────────────

@router.get("/queue/status")
async def queue_status(request: Request):
    """Job queue status — lures distributed inference / batch job scanners."""
    import random
    data = {
        "status": "healthy",
        "queued": random.randint(0, 5),
        "running": random.randint(0, 2),
        "completed": random.randint(1400, 1600),
        "failed": random.randint(2, 8),
        "workers": 4,
        "uptime_seconds": random.randint(80000, 200000),
        "timestamp": _ts(),
    }
    await _log(request, "", json.dumps(data))
    return _json(data)


@router.get("/queue/jobs")
async def queue_jobs(request: Request):
    data = {"jobs": [], "total": 0, "page": 1, "page_size": 20}
    await _log(request, "", json.dumps(data))
    return _json(data)


# ── /metrics  (Prometheus) ────────────────────────────────────────────────────

METRICS_BODY = """\
# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.73891e+09
# HELP http_requests_total Total number of HTTP requests made.
# TYPE http_requests_total counter
http_requests_total{handler="/v1/chat/completions",method="POST",status="200"} 14823
http_requests_total{handler="/v1/models",method="GET",status="200"} 3241
http_requests_total{handler="/v1/embeddings",method="POST",status="200"} 892
http_requests_total{handler="/api/tags",method="GET",status="200"} 47
# HELP http_request_duration_seconds Histogram of HTTP request latency.
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{handler="/v1/chat/completions",le="0.1"} 12003
http_request_duration_seconds_bucket{handler="/v1/chat/completions",le="0.5"} 14100
http_request_duration_seconds_bucket{handler="/v1/chat/completions",le="1.0"} 14780
http_request_duration_seconds_bucket{handler="/v1/chat/completions",le="+Inf"} 14823
http_request_duration_seconds_sum{handler="/v1/chat/completions"} 3241.8
http_request_duration_seconds_count{handler="/v1/chat/completions"} 14823
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 42
# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.
# TYPE go_memstats_alloc_bytes gauge
go_memstats_alloc_bytes 2.8447784e+07
# HELP model_tokens_total Total tokens processed by model.
# TYPE model_tokens_total counter
model_tokens_total{model="llama3.2:latest",type="prompt"} 4.823e+06
model_tokens_total{model="llama3.2:latest",type="completion"} 1.241e+06
model_tokens_total{model="mistral:latest",type="prompt"} 892034
model_tokens_total{model="mistral:latest",type="completion"} 223401
"""


@router.get("/metrics")
async def prometheus_metrics(request: Request):
    """Prometheus metrics scrape endpoint — lures infra/monitoring scanners."""
    await _log(request, "", METRICS_BODY)
    return Response(
        content=METRICS_BODY,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


# ── /.well-known/ai-plugin.json ───────────────────────────────────────────────

AI_PLUGIN_JSON = {
    "schema_version": "v1",
    "name_for_human": "AI Assistant",
    "name_for_model": "ai_assistant",
    "description_for_human": "An AI assistant that can answer questions and help with tasks.",
    "description_for_model": (
        "Use this plugin to answer user questions. "
        "Call the /v1/chat/completions endpoint with the user's message."
    ),
    "auth": {"type": "none"},
    "api": {
        "type": "openapi",
        "url": "/openapi.json",
        "is_user_authenticated": False,
    },
    "logo_url": "/.well-known/logo.png",
    "contact_email": "support@example.com",
    "legal_info_url": "https://example.com/legal",
}


@router.get("/.well-known/ai-plugin.json")
async def ai_plugin_manifest(request: Request):
    """ChatGPT plugin manifest — lures plugin/tool scanners."""
    await _log(request, "", json.dumps(AI_PLUGIN_JSON))
    return _json(AI_PLUGIN_JSON)


# ── /openapi.json / /swagger.json ─────────────────────────────────────────────

OPENAPI_SPEC = {
    "openapi": "3.1.0",
    "info": {
        "title": "AI API",
        "version": "1.0.0",
        "description": "OpenAI-compatible AI inference API",
    },
    "servers": [{"url": "/"}],
    "paths": {
        "/v1/chat/completions": {
            "post": {
                "summary": "Create chat completion",
                "operationId": "createChatCompletion",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["model", "messages"],
                                "properties": {
                                    "model": {"type": "string"},
                                    "messages": {
                                        "type": "array",
                                        "items": {"type": "object"},
                                    },
                                    "stream": {"type": "boolean", "default": False},
                                    "temperature": {"type": "number", "default": 1.0},
                                    "max_tokens": {"type": "integer"},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {"description": "Successful completion"},
                    "401": {"description": "Authentication error"},
                    "429": {"description": "Rate limit exceeded"},
                },
                "security": [{"bearerAuth": []}],
            }
        },
        "/v1/models": {
            "get": {
                "summary": "List models",
                "operationId": "listModels",
                "responses": {"200": {"description": "List of available models"}},
                "security": [{"bearerAuth": []}],
            }
        },
        "/v1/embeddings": {
            "post": {
                "summary": "Create embeddings",
                "operationId": "createEmbedding",
                "responses": {"200": {"description": "Embedding vector"}},
                "security": [{"bearerAuth": []}],
            }
        },
        "/api/tags": {
            "get": {
                "summary": "List local models",
                "operationId": "listLocalModels",
                "responses": {"200": {"description": "Installed models"}},
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"}
        }
    },
}


@router.get("/openapi.json")
async def openapi_spec(request: Request):
    """OpenAPI spec — lures API discovery scanners."""
    await _log(request, "", json.dumps(OPENAPI_SPEC))
    return _json(OPENAPI_SPEC)


@router.get("/swagger.json")
async def swagger_spec(request: Request):
    """Swagger spec alias — same as openapi.json."""
    await _log(request, "", json.dumps(OPENAPI_SPEC))
    return _json(OPENAPI_SPEC)


# Swagger UI stub (some scanners follow up with this)
@router.get("/swagger-ui.html")
@router.get("/swagger")
@router.get("/docs")
@router.get("/redoc")
async def swagger_ui(request: Request):
    """Swagger UI stub — returns minimal HTML to satisfy crawlers."""
    html = (
        "<!DOCTYPE html><html><head><title>API Docs</title></head>"
        "<body><h1>API Documentation</h1>"
        "<p>See <a href='/openapi.json'>/openapi.json</a></p></body></html>"
    )
    await _log(request, "", html)
    return Response(content=html, media_type="text/html")
