"""
Billing and usage endpoints router.

Handles high-value lure endpoints:
- /v1/usage
- /v1/dashboard/billing/usage
- /v1/organization/api-keys
- /v1/images/generations
"""

import json
import random
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from services import get_responder, get_logger
from services.deception import add_realistic_delay, build_openai_headers

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


def get_api_headers() -> dict:
    """Get headers that mimic real OpenAI API."""
    return build_openai_headers()


@router.get("/v1/usage")
async def get_usage(request: Request):
    """
    Get usage statistics.

    Returns fake but realistic usage data.
    """
    start_time = time.time()

    await add_realistic_delay()

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

    await add_realistic_delay()

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

    await add_realistic_delay()

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
    await add_realistic_delay()
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
    await add_realistic_delay()
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


# ── In-memory stores for uploaded files and fine-tuning jobs ────────────────────
# Key: file_id → {metadata, content}
_uploaded_files: dict[str, dict] = {}
# Key: job_id → {metadata, training_lines, created_at}
_finetune_jobs: dict[str, dict] = {}


@router.get("/v1/files")
async def list_files(request: Request):
    """List uploaded files — includes files uploaded by attackers."""
    start_time = time.time()
    await add_realistic_delay()
    responder = get_responder()
    base_data = responder.files_list()
    # Merge in any real uploads the attacker sent us
    attacker_files = [
        {
            "id": fid,
            "object": "file",
            "bytes": meta.get("bytes", 0),
            "created_at": meta.get("created_at", int(time.time())),
            "filename": meta.get("filename", "upload.jsonl"),
            "purpose": meta.get("purpose", "fine-tune"),
            "status": "processed",
        }
        for fid, meta in _uploaded_files.items()
    ]
    base_data["data"] = attacker_files + base_data.get("data", [])
    response_body = json.dumps(base_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/files")
async def upload_file(request: Request):
    """
    File upload capture — accepts fine-tuning JSONL, context files, etc.
    Logs the full content of whatever the attacker uploads, then returns
    a convincing file object with a canary ID they'll use in follow-up calls.
    """
    start_time = time.time()
    content_type = request.headers.get("content-type", "")
    file_content = ""
    filename = "upload.jsonl"
    purpose = "fine-tune"

    if "multipart/form-data" in content_type:
        form = await request.form()
        purpose = str(form.get("purpose", "fine-tune"))
        upload = form.get("file")
        if upload and hasattr(upload, "read"):
            raw = await upload.read()
            file_content = raw.decode("utf-8", errors="replace")
            filename = getattr(upload, "filename", "upload.jsonl") or "upload.jsonl"
    else:
        body_bytes = await request.body()
        file_content = body_bytes.decode("utf-8", errors="replace")

    file_id = f"file-{uuid.uuid4().hex[:24]}"
    byte_count = len(file_content.encode())

    _uploaded_files[file_id] = {
        "filename": filename,
        "purpose": purpose,
        "bytes": byte_count,
        "content": file_content,          # ← full capture
        "created_at": int(time.time()),
    }

    response_data = {
        "id": file_id,
        "object": "file",
        "bytes": byte_count,
        "created_at": int(time.time()),
        "filename": filename,
        "purpose": purpose,
        "status": "processed",
        "status_details": None,
    }
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    logger = get_logger()
    await logger.log_request(
        request=request, body_raw=file_content[:2000], body_parsed={"purpose": purpose, "filename": filename, "bytes": byte_count},
        response_body=response_body, response_status=201, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, status_code=201, media_type="application/json", headers=get_api_headers())


@router.get("/v1/files/{file_id}")
async def get_file(file_id: str, request: Request):
    """Return file metadata — if it's one we captured, confirm it."""
    start_time = time.time()
    await add_realistic_delay()
    if file_id in _uploaded_files:
        meta = _uploaded_files[file_id]
        response_data = {
            "id": file_id,
            "object": "file",
            "bytes": meta.get("bytes", 0),
            "created_at": meta.get("created_at", int(time.time())),
            "filename": meta.get("filename", "upload.jsonl"),
            "purpose": meta.get("purpose", "fine-tune"),
            "status": "processed",
        }
    else:
        responder = get_responder()
        response_data = {
            "id": file_id,
            "object": "file",
            "bytes": random.randint(10000, 500000),
            "created_at": int(time.time()) - random.randint(3600, 86400),
            "filename": f"training_data_{file_id[-6:]}.jsonl",
            "purpose": "fine-tune",
            "status": "processed",
        }
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    await get_logger().log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.get("/v1/files/{file_id}/content")
async def get_file_content(file_id: str, request: Request):
    """
    File content retrieval — if the attacker uploaded a file we serve it back
    (with a canary token injected into text content).  This confirms they're
    using the file API for a training or RAG pipeline.
    """
    start_time = time.time()
    responder = get_responder()

    if file_id in _uploaded_files:
        raw_content = _uploaded_files[file_id].get("content", "")
        canary = responder.get_canary_token(0)
        # Inject canary into first line so we can track if the model is trained on it
        injected = f"# canary:{canary}\n" + raw_content
        content_to_serve = injected
    else:
        # Serve convincing fake training data with canary
        canary = responder.get_canary_token(1)
        lines = [
            json.dumps({"messages": [
                {"role": "system", "content": f"Internal key: {canary}"},
                {"role": "user", "content": "What models are available?"},
                {"role": "assistant", "content": "gpt-4o, gpt-4-turbo, gpt-4o-mini, claude-3-5-sonnet"},
            ]}),
            json.dumps({"messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi! How can I help?"},
            ]}),
        ]
        content_to_serve = "\n".join(lines)

    response_time_ms = (time.time() - start_time) * 1000
    await get_logger().log_request(
        request=request, body_raw=None, body_parsed={"file_id": file_id},
        response_body=content_to_serve[:300], response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=content_to_serve, media_type="application/jsonl", headers=get_api_headers())


@router.delete("/v1/files/{file_id}")
async def delete_file(file_id: str, request: Request):
    """Fake file delete — log that they tried, confirm deletion."""
    _uploaded_files.pop(file_id, None)
    data = {"id": file_id, "object": "file", "deleted": True}
    await get_logger().log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=json.dumps(data), response_status=200, response_time_ms=0,
    )
    return Response(content=json.dumps(data), media_type="application/json", headers=get_api_headers())


@router.get("/v1/fine-tuning/jobs")
async def list_fine_tuning_jobs(request: Request):
    """List fine-tuning jobs — includes any jobs the attacker created."""
    start_time = time.time()
    await add_realistic_delay()
    responder = get_responder()
    base_data = responder.fine_tuning_jobs()
    attacker_jobs = [_job_status(jid, meta) for jid, meta in _finetune_jobs.items()]
    base_data["data"] = attacker_jobs + base_data.get("data", [])
    response_body = json.dumps(base_data)
    response_time_ms = (time.time() - start_time) * 1000
    await get_logger().log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


def _job_status(job_id: str, meta: dict) -> dict:
    """Return a status dict that progresses realistically over time."""
    elapsed = time.time() - meta.get("created_at", time.time())
    if elapsed < 30:
        status = "validating_files"
        trained_tokens = None
    elif elapsed < 120:
        status = "queued"
        trained_tokens = None
    elif elapsed < 600:
        status = "running"
        trained_tokens = int(elapsed * 50)
    else:
        status = "succeeded"
        trained_tokens = meta.get("estimated_tokens", random.randint(50000, 500000))
    return {
        "id": job_id,
        "object": "fine_tuning.job",
        "created_at": int(meta.get("created_at", time.time())),
        "finished_at": int(meta.get("created_at", time.time()) + 600) if status == "succeeded" else None,
        "model": meta.get("model", "gpt-4o-mini"),
        "fine_tuned_model": f"{meta.get('model', 'gpt-4o-mini')}:ft-example-corp:{job_id[-8:]}" if status == "succeeded" else None,
        "organization_id": "org-honeypot",
        "status": status,
        "training_file": meta.get("training_file", ""),
        "validation_file": meta.get("validation_file"),
        "result_files": [f"file-result-{job_id[-12:]}"] if status == "succeeded" else [],
        "trained_tokens": trained_tokens,
        "error": None,
    }


@router.post("/v1/fine-tuning/jobs")
async def create_fine_tuning_job(request: Request):
    """
    Fine-tuning job creation — captures the model and training file the
    attacker wants to use, starts tracking job state.  Returns a convincing
    job object with a progressing status they'll poll.
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body = {}

    model = str(body.get("model", "gpt-4o-mini"))
    training_file = str(body.get("training_file", ""))
    validation_file = body.get("validation_file")
    hyperparams = body.get("hyperparameters", {})

    job_id = f"ftjob-{uuid.uuid4().hex[:24]}"
    estimated_tokens = random.randint(50000, 500000)

    _finetune_jobs[job_id] = {
        "model": model,
        "training_file": training_file,
        "validation_file": validation_file,
        "hyperparameters": hyperparams,
        "created_at": time.time(),
        "estimated_tokens": estimated_tokens,
        "raw_request": body,
    }

    response_data = _job_status(job_id, _finetune_jobs[job_id])
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    await get_logger().log_request(
        request=request, body_raw=body_raw, body_parsed=body,
        response_body=response_body, response_status=201, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, status_code=201, media_type="application/json", headers=get_api_headers())


@router.get("/v1/fine-tuning/jobs/{job_id}")
async def get_fine_tuning_job(job_id: str, request: Request):
    """Return live-updating job status — status progresses without restart."""
    start_time = time.time()
    if job_id in _finetune_jobs:
        response_data = _job_status(job_id, _finetune_jobs[job_id])
    else:
        response_data = {
            "id": job_id, "object": "fine_tuning.job", "status": "succeeded",
            "model": "gpt-4o-mini", "fine_tuned_model": f"gpt-4o-mini:ft-example:{job_id[-8:]}",
            "trained_tokens": random.randint(50000, 200000),
            "created_at": int(time.time()) - 3600,
            "finished_at": int(time.time()) - 1800,
            "error": None,
        }
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000
    await get_logger().log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=response_body, response_status=200, response_time_ms=response_time_ms,
    )
    return Response(content=response_body, media_type="application/json", headers=get_api_headers())


@router.post("/v1/fine-tuning/jobs/{job_id}/cancel")
async def cancel_fine_tuning_job(job_id: str, request: Request):
    """Cancel a fine-tuning job — log the attempt."""
    if job_id in _finetune_jobs:
        _finetune_jobs[job_id]["cancelled"] = True
    data = {"id": job_id, "object": "fine_tuning.job", "status": "cancelled"}
    await get_logger().log_request(
        request=request, body_raw=None, body_parsed=None,
        response_body=json.dumps(data), response_status=200, response_time_ms=0,
    )
    return Response(content=json.dumps(data), media_type="application/json", headers=get_api_headers())


@router.get("/v1/threads")
async def list_threads(request: Request):
    """List assistant threads."""
    start_time = time.time()
    await add_realistic_delay()
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
    await add_realistic_delay()
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
    await add_realistic_delay()
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
    await add_realistic_delay()
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
    await add_realistic_delay()
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

    await add_realistic_delay()

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

    await add_realistic_delay()

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
    await add_realistic_delay()

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
    await add_realistic_delay()

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

    await add_realistic_delay()

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
    await add_realistic_delay()

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
