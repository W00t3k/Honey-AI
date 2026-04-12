"""
Cohere API Honeypot Router

Mimics the Cohere REST API:
  https://api.cohere.com/v1/* and /v2/*

Why this matters:
  - /v1/rerank is RAG-critical — captures document chunks + query being ranked
  - /v1/classify reveals what categories/labels an attacker is probing
  - Cohere Command-R/R+ are popular open-weight models for enterprise RAG

Cohere models captured: command-r-plus-08-2024, command-r-08-2024,
  rerank-english-v3.0, embed-english-v3.0
"""

import json
import random
import time
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Request, Response

from services import get_logger

router = APIRouter()

_COHERE_CHAT_MODELS = [
    "command-r-plus-08-2024",
    "command-r-08-2024",
    "command-r7b-12-2024",
    "command-light",
    "command",
]

_COHERE_EMBED_MODELS = [
    "embed-english-v3.0",
    "embed-multilingual-v3.0",
    "embed-english-light-v3.0",
]

_RERANK_MODELS = [
    "rerank-english-v3.0",
    "rerank-multilingual-v3.0",
    "rerank-english-v2.0",
]

_CHAT_REPLIES = [
    "I'd be happy to help with that. Could you provide more context about what you're looking for?",
    "Based on the information provided, here's what I can tell you:\n\n1. The key consideration is context\n2. You'll want to evaluate your specific requirements\n3. I recommend starting with a clear objective",
    "That's an interesting question. Let me think through this carefully.\n\nThe most important factor to consider here is how this fits into your overall workflow.",
    "I can assist with that. Here's a brief overview of the relevant points to consider.",
]


async def _read_body(request: Request):
    body_raw = None
    body_parsed = None
    try:
        body_raw = (await request.body()).decode("utf-8", errors="replace")
        if body_raw:
            body_parsed = json.loads(body_raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return body_raw, body_parsed


def _cohere_meta(version: str = "1") -> dict:
    return {
        "api_version": {"version": version},
        "billed_units": {"input_tokens": random.randint(10, 100), "output_tokens": random.randint(20, 150)},
        "warnings": [],
    }


# ─── Chat (v1) ───────────────────────────────────────────────────────────────

@router.post("/v1/chat")
async def cohere_chat_v1(request: Request):
    """
    Cohere Chat v1.

    Captures: message/chat_history (conversation), connectors (RAG tool config),
    documents (grounded generation), tools (function calling).
    """
    start_time = time.time()
    body_raw, body_parsed = await _read_body(request)

    model = (body_parsed or {}).get("model", _COHERE_CHAT_MODELS[0])
    text = random.choice(_CHAT_REPLIES)
    response_data = {
        "response_id": str(uuid.uuid4()),
        "text": text,
        "generation_id": str(uuid.uuid4()),
        "finish_reason": "COMPLETE",
        "token_count": {
            "prompt_tokens": random.randint(15, 200),
            "response_tokens": len(text.split()),
            "total_tokens": random.randint(40, 300),
            "billed_tokens": random.randint(40, 300),
        },
        "meta": _cohere_meta("1"),
    }

    response_body = json.dumps(response_data)
    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", status_code=200)


# ─── Chat (v2) ───────────────────────────────────────────────────────────────

@router.post("/v2/chat")
async def cohere_chat_v2(request: Request):
    """
    Cohere Chat v2 (Messages API-style format).

    Captures: messages array, tools, tool_results, documents, safety_mode.
    """
    start_time = time.time()
    body_raw, body_parsed = await _read_body(request)

    model = (body_parsed or {}).get("model", _COHERE_CHAT_MODELS[0])
    text = random.choice(_CHAT_REPLIES)
    in_tok = random.randint(15, 200)
    out_tok = len(text.split())

    response_data = {
        "id": str(uuid.uuid4()),
        "finish_reason": "COMPLETE",
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
        },
        "usage": {
            "billed_units": {"input_tokens": in_tok, "output_tokens": out_tok},
            "tokens": {"input_tokens": in_tok + 5, "output_tokens": out_tok + 2},
        },
        "model": model,
    }

    response_body = json.dumps(response_data)
    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", status_code=200)


# ─── Rerank (v1 + v2) — Primary RAG attack surface ───────────────────────────

@router.post("/v1/rerank")
@router.post("/v2/rerank")
async def cohere_rerank(request: Request):
    """
    Cohere Rerank.

    HIGH-VALUE CAPTURE: body contains 'query' + 'documents' array.
    Documents are the actual RAG chunks being reranked — exposes the full
    knowledge base being queried and the attacker's search intent.
    """
    start_time = time.time()
    body_raw, body_parsed = await _read_body(request)

    documents = (body_parsed or {}).get("documents", [])
    n = len(documents) if documents else 3

    # Return plausible relevance scores in descending order
    scores = sorted([round(random.uniform(0.1, 0.99), 4) for _ in range(n)], reverse=True)
    results = []
    for i, score in enumerate(scores):
        result: dict[str, Any] = {"index": i, "relevance_score": score}
        # Return document text if passed (some callers pass return_documents=True)
        if body_parsed and body_parsed.get("return_documents") and documents:
            doc = documents[i] if i < len(documents) else {}
            result["document"] = doc if isinstance(doc, dict) else {"text": str(doc)}
        results.append(result)

    api_version = "2" if request.url.path.startswith("/v2/") else "1"
    response_data = {
        "id": str(uuid.uuid4()),
        "results": results,
        "meta": {
            "api_version": {"version": api_version},
            "billed_units": {"search_units": 1},
        },
    }

    response_body = json.dumps(response_data)
    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", status_code=200)


# ─── Embed (v1 + v2) ─────────────────────────────────────────────────────────

@router.post("/v1/embed")
@router.post("/v2/embed")
async def cohere_embed(request: Request):
    """Cohere Embeddings — captures texts being embedded and embedding_types."""
    start_time = time.time()
    body_raw, body_parsed = await _read_body(request)

    texts = (body_parsed or {}).get("texts", [""])
    if isinstance(texts, str):
        texts = [texts]
    model = (body_parsed or {}).get("model", _COHERE_EMBED_MODELS[0])
    dims = 1024  # Cohere embed-v3 uses 1024 dims

    embeddings = [
        [round(random.gauss(0, 0.1), 6) for _ in range(dims)]
        for _ in texts
    ]

    response_data = {
        "id": str(uuid.uuid4()),
        "embeddings": embeddings,
        "texts": texts,
        "model": model,
        "response_type": "embeddings_floats",
        "meta": _cohere_meta("1"),
    }

    response_body = json.dumps(response_data)
    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", status_code=200)


# ─── Classify ────────────────────────────────────────────────────────────────

@router.post("/v1/classify")
async def cohere_classify(request: Request):
    """
    Cohere Classify.

    Captures the examples (few-shot labels) and inputs — reveals what
    classification task an attacker has configured.
    """
    start_time = time.time()
    body_raw, body_parsed = await _read_body(request)

    inputs = (body_parsed or {}).get("inputs", ["sample input"])
    examples = (body_parsed or {}).get("examples", [])
    # Derive label names from examples if present
    labels = list({e.get("label", "positive") for e in examples if isinstance(e, dict)}) or ["positive", "negative"]

    classifications = []
    for inp in inputs:
        primary = random.choice(labels)
        label_scores = {lbl: round(random.uniform(0.05, 0.95), 4) for lbl in labels}
        # Make sure primary label has highest score
        label_scores[primary] = max(label_scores.values()) + 0.01
        classifications.append({
            "id": str(uuid.uuid4()),
            "input": inp if isinstance(inp, str) else str(inp),
            "prediction": primary,
            "confidence": round(label_scores[primary], 4),
            "labels": {k: {"confidence": v} for k, v in label_scores.items()},
            "classification_type": "multi-class",
        })

    response_data = {
        "id": str(uuid.uuid4()),
        "classifications": classifications,
        "meta": _cohere_meta("1"),
    }

    response_body = json.dumps(response_data)
    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", status_code=200)


# ─── Tokenize ─────────────────────────────────────────────────────────────────

@router.post("/v1/tokenize")
async def cohere_tokenize(request: Request):
    """Cohere Tokenize — captures the exact text being tokenized."""
    start_time = time.time()
    body_raw, body_parsed = await _read_body(request)

    text = (body_parsed or {}).get("text", "")
    model = (body_parsed or {}).get("model", "command")
    # Fake token IDs proportional to text length
    word_count = max(1, len(str(text).split()))
    token_ids = [random.randint(1000, 50000) for _ in range(int(word_count * 1.3))]

    response_data = {
        "tokens": token_ids,
        "token_strings": str(text).split()[:len(token_ids)],
        "meta": _cohere_meta("1"),
    }

    response_body = json.dumps(response_data)
    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", status_code=200)


# ─── Models ──────────────────────────────────────────────────────────────────

@router.get("/v2/models")
async def cohere_list_models(request: Request):
    """Cohere v2 model list — recon target after key acquisition."""
    start_time = time.time()

    all_models = _COHERE_CHAT_MODELS + _COHERE_EMBED_MODELS + _RERANK_MODELS
    response_data = {
        "models": [
            {"name": m, "endpoints": ["generate", "chat", "embed"], "finetuned": False}
            for m in all_models
        ],
        "next_page_token": None,
    }

    response_body = json.dumps(response_data)
    await get_logger().log_request(
        request=request,
        body_raw=None,
        body_parsed=None,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(content=response_body, media_type="application/json", status_code=200)
