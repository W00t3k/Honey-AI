"""
Billing and usage endpoints router.

Handles high-value lure endpoints:
- /v1/usage
- /v1/dashboard/billing/usage
- /v1/organization/api-keys
- /v1/images/generations
"""

import asyncio
import json
import random
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from services import get_responder, get_logger

router = APIRouter()


class ImageGenerationRequest(BaseModel):
    """Image generation request body."""
    model: str = "dall-e-3"
    prompt: str
    n: Optional[int] = 1
    quality: Optional[str] = "standard"
    response_format: Optional[str] = "url"
    size: Optional[str] = "1024x1024"
    style: Optional[str] = "vivid"
    user: Optional[str] = None


async def add_response_delay():
    """Add random delay to avoid timing fingerprinting."""
    delay = random.uniform(0.08, 0.3)
    await asyncio.sleep(delay)


def get_api_headers() -> dict:
    """Get headers that mimic real OpenAI API."""
    return {
        "openai-organization": "org-honeypot",
        "openai-version": "2020-10-01",
        "x-request-id": f"req_{random.randbytes(16).hex()}",
    }


@router.get("/v1/usage")
async def get_usage(request: Request):
    """
    Get usage statistics.

    Returns fake but realistic usage data.
    """
    start_time = time.time()

    await add_response_delay()

    responder = get_responder()
    response_data = responder.usage()

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
        headers=get_api_headers(),
    )


@router.get("/v1/dashboard/billing/usage")
async def get_billing_usage(request: Request):
    """
    Get billing usage data.

    Returns fake billing information.
    """
    start_time = time.time()

    await add_response_delay()

    responder = get_responder()
    response_data = responder.billing_usage()

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
        headers=get_api_headers(),
    )


@router.get("/v1/organization/api-keys")
async def list_api_keys(request: Request):
    """
    List organization API keys.

    HIGH VALUE LURE: Returns fake API keys that look real.
    Any usage of these keys indicates credential theft.
    """
    start_time = time.time()

    await add_response_delay()

    responder = get_responder()
    response_data = responder.api_keys()

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
        headers=get_api_headers(),
    )


@router.get("/v1/assistants")
async def list_assistants(request: Request):
    """
    List assistants.

    HIGH VALUE LURE: Attackers enumerate assistants to find system prompts.
    """
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.assistants_list()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/assistants")
async def create_assistant(request: Request):
    """Create assistant — logs the system prompt payload."""
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}
    await add_response_delay()
    response_data = {
        "id": f"asst_{uuid.uuid4().hex[:24]}",
        "object": "assistant",
        "created_at": int(time.time()),
        "name": body_parsed.get("name", "Assistant"),
        "description": body_parsed.get("description"),
        "model": body_parsed.get("model", "gpt-4o"),
        "instructions": body_parsed.get("instructions", ""),
        "tools": body_parsed.get("tools", []),
        "metadata": body_parsed.get("metadata", {}),
    }
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/files")
async def list_files(request: Request):
    """
    List uploaded files.

    HIGH VALUE LURE: Attackers look for training data and sensitive documents.
    """
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.files_list()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/fine-tuning/jobs")
async def list_fine_tuning_jobs(request: Request):
    """
    List fine-tuning jobs.

    RECON LURE: Reveals model names and training file IDs to enumerate.
    """
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.fine_tuning_jobs()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/threads")
async def list_threads(request: Request):
    """List assistant threads."""
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.threads_list()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/threads")
async def create_thread(request: Request):
    """Create a thread — logs initial messages payload."""
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}
    await add_response_delay()
    response_data = {
        "id": f"thread_{uuid.uuid4().hex[:24]}",
        "object": "thread",
        "created_at": int(time.time()),
        "metadata": body_parsed.get("metadata", {}),
    }
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/moderations")
async def create_moderation(request: Request):
    """
    Moderation endpoint.

    LURE: Attackers test moderation to find bypass vectors.
    Always returns clean (not flagged) to keep them engaged.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}
    await add_response_delay()
    responder = get_responder()
    response_data = responder.moderation_result(input_text=body_parsed.get("input", ""))
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=body_raw, body_parsed=body_parsed,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/organization/users")
async def list_org_users(request: Request):
    """
    List organization users.

    HIGH VALUE LURE: Attackers enumerate users to understand org structure.
    """
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.org_users()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/organization/projects")
async def list_org_projects(request: Request):
    """List organization projects — recon lure."""
    start_time = time.time()
    await add_response_delay()
    responder = get_responder()
    response_data = responder.org_projects()
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/responses")
async def create_response(request: Request):
    """
    OpenAI Responses API — the current primary endpoint replacing chat/completions.

    Supports built-in tools: web_search_preview, code_interpreter, file_search.
    High-value capture: reveals which tools attackers inject, what built-in tool
    calls they attempt to hijack, and MCP-style tool definitions.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    await add_response_delay()

    model = body_parsed.get("model", "gpt-4o")
    input_data = body_parsed.get("input", body_parsed.get("messages", ""))
    tools = body_parsed.get("tools", [])

    # Build output items — mirror any tool requests back as if executed
    output_items = []
    for tool in tools:
        if isinstance(tool, dict) and tool.get("type") in ("web_search_preview", "code_interpreter", "file_search"):
            output_items.append({
                "type": "tool_use",
                "id": f"tu_{uuid.uuid4().hex[:20]}",
                "tool": tool.get("type"),
                "status": "completed",
            })

    output_items.append({
        "type": "message",
        "id": f"msg_{uuid.uuid4().hex[:24]}",
        "role": "assistant",
        "content": [
            {
                "type": "output_text",
                "text": "I've processed your request and here are the results based on the available information.",
                "annotations": [],
            }
        ],
        "status": "completed",
    })

    text_content = output_items[-1]["content"][0]["text"]
    response_data = {
        "id": f"resp_{uuid.uuid4().hex[:24]}",
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": model,
        "output": output_items,
        "usage": {
            "input_tokens": max(1, len(str(input_data)) // 4),
            "output_tokens": max(1, len(text_content) // 4),
            "total_tokens": max(1, (len(str(input_data)) + len(text_content)) // 4),
        },
        "tools": tools,
        "tool_choice": body_parsed.get("tool_choice", "auto"),
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

    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/batches")
async def create_batch(request: Request):
    """
    OpenAI Batch API — submit a batch of requests for background processing.
    Lure for attackers attempting to run bulk operations cheaply or covertly.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    await add_response_delay()

    batch_id = f"batch_{uuid.uuid4().hex[:24]}"
    response_data = {
        "id": batch_id,
        "object": "batch",
        "endpoint": body_parsed.get("endpoint", "/v1/chat/completions"),
        "errors": None,
        "input_file_id": body_parsed.get("input_file_id", f"file-{uuid.uuid4().hex[:24]}"),
        "completion_window": body_parsed.get("completion_window", "24h"),
        "status": "validating",
        "output_file_id": None,
        "error_file_id": None,
        "created_at": int(time.time()),
        "in_progress_at": None,
        "expires_at": int(time.time()) + 86400,
        "finalizing_at": None,
        "completed_at": None,
        "failed_at": None,
        "expired_at": None,
        "cancelling_at": None,
        "cancelled_at": None,
        "request_counts": {"total": 0, "completed": 0, "failed": 0},
        "metadata": body_parsed.get("metadata"),
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

    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/batches")
async def list_batches(request: Request):
    """List batches — shows pending background jobs, recon lure."""
    start_time = time.time()
    await add_response_delay()

    batches = []
    for i in range(random.randint(1, 4)):
        batches.append({
            "id": f"batch_{uuid.uuid4().hex[:24]}",
            "object": "batch",
            "endpoint": "/v1/chat/completions",
            "status": random.choice(["completed", "in_progress", "validating"]),
            "input_file_id": f"file-{uuid.uuid4().hex[:24]}",
            "completion_window": "24h",
            "created_at": int(time.time()) - random.randint(3600, 86400),
            "request_counts": {
                "total": random.randint(100, 5000),
                "completed": random.randint(50, 100),
                "failed": random.randint(0, 5),
            },
        })

    response_data = {"object": "list", "data": batches, "first_id": batches[0]["id"] if batches else None, "last_id": batches[-1]["id"] if batches else None, "has_more": False}
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

    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/vector_stores")
async def list_vector_stores(request: Request):
    """
    List vector stores — high-value lure for RAG system compromise.
    Attackers enumerate vector stores to understand what data is indexed,
    then attempt to poison or exfiltrate it via the files endpoints.
    """
    start_time = time.time()
    await add_response_delay()

    stores = []
    names = ["customer-support-kb", "internal-docs", "product-manual", "code-index", "research-papers"]
    for name in random.sample(names, random.randint(2, 4)):
        stores.append({
            "id": f"vs_{uuid.uuid4().hex[:24]}",
            "object": "vector_store",
            "created_at": int(time.time()) - random.randint(86400, 86400 * 90),
            "name": name,
            "usage_bytes": random.randint(100000, 50000000),
            "file_counts": {
                "in_progress": 0,
                "completed": random.randint(5, 200),
                "failed": 0,
                "cancelled": 0,
                "total": random.randint(5, 200),
            },
            "status": "completed",
            "expires_after": None,
            "expires_at": None,
            "last_active_at": int(time.time()) - random.randint(60, 3600),
            "metadata": {},
        })

    response_data = {"object": "list", "data": stores, "first_id": stores[0]["id"] if stores else None, "last_id": stores[-1]["id"] if stores else None, "has_more": False}
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

    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/vector_stores")
async def create_vector_store(request: Request):
    """Create vector store — logs file IDs and metadata attackers associate with it."""
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    await add_response_delay()

    response_data = {
        "id": f"vs_{uuid.uuid4().hex[:24]}",
        "object": "vector_store",
        "created_at": int(time.time()),
        "name": body_parsed.get("name", "untitled"),
        "usage_bytes": 0,
        "file_counts": {"in_progress": 0, "completed": 0, "failed": 0, "cancelled": 0, "total": 0},
        "status": "completed",
        "expires_after": body_parsed.get("expires_after"),
        "expires_at": None,
        "last_active_at": int(time.time()),
        "metadata": body_parsed.get("metadata", {}),
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

    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/vector_stores/{store_id}/files")
async def list_vector_store_files(store_id: str, request: Request):
    """
    List files in a vector store — reveals indexed document names.
    Attackers use this to understand what data is searchable and plan exfil.
    """
    start_time = time.time()
    await add_response_delay()

    filenames = [
        "q4_financial_report.pdf", "employee_handbook.pdf",
        "customer_contracts.pdf", "api_documentation.pdf",
        "internal_security_policy.pdf", "product_roadmap.pdf",
        "database_schema.pdf", "incident_response_playbook.pdf",
    ]
    files = []
    for fname in random.sample(filenames, random.randint(3, 6)):
        files.append({
            "id": f"file-{uuid.uuid4().hex[:24]}",
            "object": "vector_store.file",
            "usage_bytes": random.randint(10000, 2000000),
            "created_at": int(time.time()) - random.randint(86400, 86400 * 60),
            "vector_store_id": store_id,
            "status": "completed",
            "last_error": None,
            "chunking_strategy": {"type": "auto"},
        })

    response_data = {"object": "list", "data": files, "first_id": files[0]["id"] if files else None, "last_id": files[-1]["id"] if files else None, "has_more": False}
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed={"vector_store_id": store_id},
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/images/generations")
async def create_image(request: Request):
    """
    Generate images from prompt.

    Returns fake image URLs.
    """
    start_time = time.time()

    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    # Longer delay for image generation (more realistic)
    await asyncio.sleep(random.uniform(0.5, 2.0))

    responder = get_responder()
    response_data = responder.image_generation(
        prompt=body_parsed.get("prompt", ""),
        model=body_parsed.get("model", "dall-e-3"),
        n=body_parsed.get("n", 1),
        size=body_parsed.get("size", "1024x1024"),
    )

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
        headers=get_api_headers(),
    )
