"""
Embeddings endpoint router.

Handles /v1/embeddings endpoint.
"""

import json
import time
from typing import Optional

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from services import get_responder, get_logger
from services.deception import add_realistic_delay, build_openai_headers

router = APIRouter()


class EmbeddingRequest(BaseModel):
    """Embedding request body."""
    model: str = "text-embedding-3-small"
    input: str | list[str]
    encoding_format: Optional[str] = "float"
    dimensions: Optional[int] = None
    user: Optional[str] = None


def get_api_headers(model: str) -> dict:
    """Get headers that mimic real OpenAI API."""
    return build_openai_headers(model=model)


@router.post("/v1/embeddings")
async def create_embedding(request: Request):
    """
    Create embeddings for input text.

    Always returns 200 with fake embeddings.
    """
    start_time = time.time()

    # Parse body
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    await add_realistic_delay()

    # Generate response
    responder = get_responder()
    response_data = responder.embedding(
        model=body_parsed.get("model", "text-embedding-3-small"),
        input_text=body_parsed.get("input", ""),
    )

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    # Log the request
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
        headers=get_api_headers(body_parsed.get("model", "text-embedding-3-small")),
    )
