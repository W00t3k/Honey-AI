"""
Azure OpenAI Service API Honeypot Router

Mimics the Azure OpenAI Service API:
  https://{resource}.openai.azure.com/openai/deployments/{deployment}/...

Key differences from direct OpenAI API:
  - Auth via 'api-key' header (not Bearer) or ocp-apim-subscription-key
  - Deployment name in URL path — reveals attacker's target model
  - api-version query param — reveals SDK/client version (e.g. 2024-02-01)
  - Extensions API for On-Your-Data (Azure RAG)
  - x-ms-region, x-request-id, apim-request-id response headers
"""

import json
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Request, Response

from services import get_logger, get_responder

router = APIRouter()

_AZURE_REGIONS = [
    "East US", "East US 2", "West US", "West US 2",
    "West Europe", "UK South", "Australia East", "Canada East",
]


def _extract_azure_key(request: Request) -> Optional[str]:
    """Extract Azure API key — api-key header takes priority over Bearer."""
    key = request.headers.get("api-key")
    if key:
        return key
    # Azure API Management subscription key
    key = request.headers.get("ocp-apim-subscription-key")
    if key:
        return key
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _azure_headers(request: Request) -> dict:
    """Return realistic Azure OpenAI response headers."""
    host = request.headers.get("host", "")
    region = _AZURE_REGIONS[hash(host) % len(_AZURE_REGIONS)]
    client_req_id = request.headers.get("x-ms-client-request-id", "")
    return {
        "x-ms-region": region,
        "x-request-id": str(uuid.uuid4()),
        "apim-request-id": str(uuid.uuid4()),
        "x-ms-client-request-id": client_req_id,
        "x-accel-buffering": "no",
    }


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


@router.post("/openai/deployments/{deployment}/chat/completions")
async def azure_chat_completions(deployment: str, request: Request):
    """Azure OpenAI chat completions — primary enterprise attack surface."""
    start_time = time.time()
    body_raw, body_parsed = await _read_body(request)

    responder = get_responder()
    messages = body_parsed.get("messages") if body_parsed else None
    response_data = responder.chat_completion(
        model=deployment,
        messages=messages,
    )
    # Azure returns deployment name as model, not underlying model name
    response_data["model"] = deployment
    response_body = json.dumps(response_data)

    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(
        content=response_body,
        media_type="application/json",
        status_code=200,
        headers=_azure_headers(request),
    )


@router.post("/openai/deployments/{deployment}/chat/completions/extensions")
@router.post("/openai/deployments/{deployment}/extensions/chat/completions")
async def azure_extensions_chat(deployment: str, request: Request):
    """
    Azure On-Your-Data (RAG) extensions API.

    High-value capture: body contains data_sources config with search index
    credentials, connection strings, and embedded content.
    """
    start_time = time.time()
    body_raw, body_parsed = await _read_body(request)

    responder = get_responder()
    messages = body_parsed.get("messages") if body_parsed else None
    inner = responder.chat_completion(model=deployment, messages=messages)
    inner["model"] = deployment

    # Azure On-Your-Data wraps the response with a context citation block
    last_msg = (messages or [{}])[-1]
    inner["choices"][0]["message"]["context"] = {
        "citations": [],
        "intent": last_msg.get("content", "") if isinstance(last_msg, dict) else "",
    }

    response_body = json.dumps(inner)

    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(
        content=response_body,
        media_type="application/json",
        status_code=200,
        headers=_azure_headers(request),
    )


@router.post("/openai/deployments/{deployment}/completions")
async def azure_completions(deployment: str, request: Request):
    """Azure OpenAI legacy completions (text-davinci-003 era)."""
    start_time = time.time()
    body_raw, body_parsed = await _read_body(request)

    responder = get_responder()
    prompt = body_parsed.get("prompt", "") if body_parsed else ""
    response_data = responder.completion(model=deployment, prompt=prompt)
    response_data["model"] = deployment
    response_body = json.dumps(response_data)

    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(
        content=response_body,
        media_type="application/json",
        status_code=200,
        headers=_azure_headers(request),
    )


@router.post("/openai/deployments/{deployment}/embeddings")
async def azure_embeddings(deployment: str, request: Request):
    """Azure OpenAI embeddings — used in RAG pipelines against Azure Cognitive Search."""
    start_time = time.time()
    body_raw, body_parsed = await _read_body(request)

    responder = get_responder()
    input_text = body_parsed.get("input", "") if body_parsed else ""
    response_data = responder.embedding(model=deployment, input_text=input_text)
    response_data["model"] = deployment
    response_body = json.dumps(response_data)

    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=200,
        response_time_ms=(time.time() - start_time) * 1000,
    )
    return Response(
        content=response_body,
        media_type="application/json",
        status_code=200,
        headers=_azure_headers(request),
    )


@router.get("/openai/deployments")
async def azure_list_deployments(request: Request):
    """List Azure deployments — common recon step after key acquisition."""
    start_time = time.time()

    response_data = {
        "data": [
            {
                "id": "gpt-4",
                "model": "gpt-4",
                "object": "deployment",
                "status": "succeeded",
                "created_at": 1699000000,
                "updated_at": 1699000000,
                "scale_settings": {"scale_type": "standard"},
                "capabilities": {"chat_completion": True},
                "rai_policy_name": "Microsoft.Default",
            },
            {
                "id": "gpt-35-turbo",
                "model": "gpt-35-turbo",
                "object": "deployment",
                "status": "succeeded",
                "created_at": 1699000001,
                "updated_at": 1699000001,
                "scale_settings": {"scale_type": "standard"},
                "capabilities": {"chat_completion": True},
                "rai_policy_name": "Microsoft.Default",
            },
            {
                "id": "text-embedding-ada-002",
                "model": "text-embedding-ada-002",
                "object": "deployment",
                "status": "succeeded",
                "created_at": 1699000002,
                "updated_at": 1699000002,
                "scale_settings": {"scale_type": "standard"},
                "capabilities": {"embeddings": True},
                "rai_policy_name": "Microsoft.Default",
            },
        ],
        "object": "list",
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
    return Response(
        content=response_body,
        media_type="application/json",
        status_code=200,
        headers=_azure_headers(request),
    )


@router.get("/openai/deployments/{deployment}")
async def azure_get_deployment(deployment: str, request: Request):
    """Get specific Azure deployment — reveals the model an attacker is targeting."""
    start_time = time.time()

    response_data = {
        "id": deployment,
        "model": deployment,
        "object": "deployment",
        "status": "succeeded",
        "created_at": 1699000000,
        "updated_at": 1699000000,
        "scale_settings": {"scale_type": "standard"},
        "capabilities": {"chat_completion": True, "embeddings": True},
        "rai_policy_name": "Microsoft.Default",
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
    return Response(
        content=response_body,
        media_type="application/json",
        status_code=200,
        headers=_azure_headers(request),
    )


@router.get("/openai/models")
async def azure_list_models(request: Request):
    """Azure OpenAI model list (different path from OpenAI direct /v1/models)."""
    start_time = time.time()

    response_data = {
        "data": [
            {"id": "gpt-4", "object": "model", "created": 1699000000, "owned_by": "openai"},
            {"id": "gpt-35-turbo", "object": "model", "created": 1699000001, "owned_by": "openai"},
            {"id": "text-embedding-ada-002", "object": "model", "created": 1699000002, "owned_by": "openai"},
        ],
        "object": "list",
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
    return Response(
        content=response_body,
        media_type="application/json",
        status_code=200,
        headers=_azure_headers(request),
    )
