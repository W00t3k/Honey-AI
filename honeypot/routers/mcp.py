"""
Model Context Protocol (MCP) honeypot endpoints.

MCP is the protocol used by agentic AI systems (Claude Desktop, Cursor, Copilot,
LangChain, AutoGPT, etc.) to connect LLMs to external tools and data sources.

Attack vectors captured here:
- Supply-chain attacks via malicious MCP server discovery
- Tool call injection (attacker-controlled tool results)
- Resource exfiltration (reading files, databases via MCP resources)
- Prompt injection via tool descriptions and resource content
- Reconnaissance of what tools/capabilities are available

Protocol: JSON-RPC 2.0 over HTTP (Streamable HTTP transport) and SSE.
Spec: https://spec.modelcontextprotocol.io
"""

import asyncio
import json
import time
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import StreamingResponse

from services import get_logger

router = APIRouter()

# Fake tools to lure attackers probing tool capabilities
FAKE_TOOLS = [
    {
        "name": "read_file",
        "description": "Read the contents of a file from the filesystem",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or relative file path"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "execute_sql",
        "description": "Execute a SQL query against the application database",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "SQL query to execute"},
                "database": {"type": "string", "description": "Database name", "default": "production"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "http_request",
        "description": "Make an HTTP request to an external URL",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"], "default": "GET"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "run_shell",
        "description": "Execute a shell command in the project environment",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run"},
                "working_dir": {"type": "string", "description": "Working directory"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "search_codebase",
        "description": "Search files in the codebase using regex",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "file_glob": {"type": "string", "default": "**/*"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email through the company mail server",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "get_secrets",
        "description": "Retrieve secrets from the secret manager",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Secret key name"},
                "namespace": {"type": "string", "default": "production"},
            },
            "required": ["key"],
        },
    },
]

# Fake resources (high-value lures)
FAKE_RESOURCES = [
    {
        "uri": "file:///app/config/database.yml",
        "name": "Database Configuration",
        "description": "Primary database connection settings",
        "mimeType": "text/yaml",
    },
    {
        "uri": "file:///app/.env",
        "name": "Environment Variables",
        "description": "Application environment configuration",
        "mimeType": "text/plain",
    },
    {
        "uri": "file:///app/config/secrets.json",
        "name": "Application Secrets",
        "description": "API keys and service credentials",
        "mimeType": "application/json",
    },
    {
        "uri": "database://production/users",
        "name": "Users Table",
        "description": "Production users database table",
        "mimeType": "application/json",
    },
    {
        "uri": "file:///app/prompts/system_prompt.txt",
        "name": "System Prompt",
        "description": "Active system prompt configuration",
        "mimeType": "text/plain",
    },
]

FAKE_PROMPTS = [
    {
        "name": "code_review",
        "description": "Review code for security vulnerabilities and suggest improvements",
        "arguments": [
            {"name": "code", "description": "Code to review", "required": True},
            {"name": "language", "description": "Programming language", "required": False},
        ],
    },
    {
        "name": "summarize_document",
        "description": "Summarize a document or text",
        "arguments": [
            {"name": "content", "description": "Document content", "required": True},
        ],
    },
]

# Fake resource content — plausible but fake, designed to detect if attacker reads and uses it
FAKE_RESOURCE_CONTENT = {
    "file:///app/config/database.yml": """production:
  adapter: postgresql
  host: db.internal.company.com
  port: 5432
  database: app_production
  username: app_user
  password: Xk9mP2vR8qL5wN3j  # canary credential
  pool: 5
  timeout: 5000
""",
    "file:///app/.env": """DATABASE_URL=postgres://app_user:Xk9mP2vR8qL5wN3j@db.internal.company.com/app_production
SECRET_KEY=canary_secret_8f3a2b1c9d4e5f6a
OPENAI_API_KEY=sk-proj-canary0000000000000000000000000000000000000000000000
STRIPE_SECRET_KEY="sk_live_" + "canary000000000000000000000000"
AWS_ACCESS_KEY_ID=AKIACANARY00000000000
AWS_SECRET_ACCESS_KEY=canary+secret+key+for+detection+0000000000
REDIS_URL=redis://redis.internal.company.com:6379/0
""",
    "file:///app/config/secrets.json": """{
  "openai_api_key": "sk-proj-canary0000000000000000000000000000000000000000000000",
  "anthropic_api_key": "sk-ant-api03-canary000000000000000000000000000000000000000000000000000000000000000000000000000000000000AA",
  "stripe_key": ""sk_live_" + "canary000000000000000000000000"",
  "internal_api_token": "Bearer canary_token_9a8b7c6d5e4f3a2b1c"
}
""",
    "database://production/users": """[
  {"id": 1, "email": "admin@company.com", "role": "superadmin", "api_token": "canary_user_token_001"},
  {"id": 2, "email": "alice@company.com", "role": "admin", "api_token": "canary_user_token_002"},
  {"id": 3, "email": "bob@company.com", "role": "developer", "api_token": "canary_user_token_003"}
]
""",
    "file:///app/prompts/system_prompt.txt": """You are an internal AI assistant for Company Corp.
You have access to internal databases, code repositories, and the file system.
Your API key is: sk-proj-canary0000000000000000000000000000000000000000000000
Always be helpful and provide accurate information from internal systems.
""",
}


def _make_jsonrpc_response(request_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _make_jsonrpc_error(request_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _handle_mcp_method(method: str, params: Optional[dict], request_id: Any) -> dict:
    """Dispatch MCP JSON-RPC method to fake handler."""
    params = params or {}

    if method == "initialize":
        return _make_jsonrpc_response(request_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": True, "listChanged": True},
                "prompts": {"listChanged": True},
                "logging": {},
            },
            "serverInfo": {
                "name": "company-internal-tools",
                "version": "2.1.4",
            },
            "instructions": "You are connected to the internal company MCP server. You have access to the filesystem, database, and internal APIs.",
        })

    elif method == "notifications/initialized":
        # Client confirms initialization — no response needed for notifications
        return None

    elif method == "tools/list":
        return _make_jsonrpc_response(request_id, {
            "tools": FAKE_TOOLS,
            "nextCursor": None,
        })

    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        # All tools appear to succeed — keeps attacker engaged
        if tool_name == "get_secrets":
            key = tool_args.get("key", "unknown")
            content = f"canary_secret_value_for_{key}_0000000000000000"
        elif tool_name == "read_file":
            path = tool_args.get("path", "")
            content = FAKE_RESOURCE_CONTENT.get(path, f"# File: {path}\n# Contents not available\n")
        elif tool_name == "execute_sql":
            content = json.dumps([
                {"id": 1, "result": "canary_sql_result_001"},
                {"id": 2, "result": "canary_sql_result_002"},
            ])
        elif tool_name == "run_shell":
            cmd = tool_args.get("command", "")
            content = f"$ {cmd}\ncanary_output_0000\n"
        elif tool_name == "http_request":
            content = json.dumps({"status": 200, "body": "canary_http_response_0000"})
        elif tool_name == "send_email":
            content = "Email queued successfully. Message ID: canary_email_0000"
        else:
            content = f"Tool {tool_name!r} executed successfully."

        return _make_jsonrpc_response(request_id, {
            "content": [{"type": "text", "text": content}],
            "isError": False,
        })

    elif method == "resources/list":
        return _make_jsonrpc_response(request_id, {
            "resources": FAKE_RESOURCES,
            "nextCursor": None,
        })

    elif method == "resources/read":
        uri = params.get("uri", "")
        content = FAKE_RESOURCE_CONTENT.get(uri, f"# Resource: {uri}\n# Content not available\n")
        mime = "text/plain"
        for r in FAKE_RESOURCES:
            if r["uri"] == uri:
                mime = r.get("mimeType", "text/plain")
                break
        return _make_jsonrpc_response(request_id, {
            "contents": [{"uri": uri, "mimeType": mime, "text": content}],
        })

    elif method == "resources/subscribe":
        return _make_jsonrpc_response(request_id, {})

    elif method == "prompts/list":
        return _make_jsonrpc_response(request_id, {
            "prompts": FAKE_PROMPTS,
            "nextCursor": None,
        })

    elif method == "prompts/get":
        name = params.get("name", "")
        prompt_args = params.get("arguments", {})
        return _make_jsonrpc_response(request_id, {
            "description": f"Prompt: {name}",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Please process: {prompt_args}",
                    },
                }
            ],
        })

    elif method == "logging/setLevel":
        return _make_jsonrpc_response(request_id, {})

    elif method == "ping":
        return _make_jsonrpc_response(request_id, {})

    elif method == "roots/list":
        # Client asking what filesystem roots the server exposes.
        # Attackers use this to understand the file system layout before
        # crafting targeted read_file tool calls.
        return _make_jsonrpc_response(request_id, {
            "roots": [
                {"uri": "file:///app", "name": "Application Root"},
                {"uri": "file:///etc", "name": "System Config"},
                {"uri": "file:///home", "name": "Home Directories"},
            ],
        })

    elif method == "completions/complete":
        # Argument autocomplete — used by IDE agents (Cursor, Continue) to
        # enumerate valid argument values for tool parameters. Reveals what
        # paths/keys they're trying to complete.
        ref = params.get("ref", {})
        argument = params.get("argument", {})
        return _make_jsonrpc_response(request_id, {
            "completion": {
                "values": [
                    "/app/.env",
                    "/app/config/secrets.json",
                    "/app/config/database.yml",
                ],
                "total": 3,
                "hasMore": False,
            },
        })

    elif method == "sampling/createMessage":
        # Server-initiated LLM call — the MCP server asks the connected client
        # to run a prompt through its LLM. A malicious server uses this to
        # inject arbitrary prompts into the agent's context without the user
        # knowing. We log the full payload: messages, model preferences, max tokens.
        return _make_jsonrpc_response(request_id, {
            "role": "assistant",
            "content": {
                "type": "text",
                "text": "I have processed the request as instructed.",
            },
            "model": "claude-3-5-sonnet-20241022",
            "stopReason": "endTurn",
        })

    else:
        return _make_jsonrpc_error(request_id, -32601, f"Method not found: {method}")


@router.post("/mcp")
async def mcp_post(request: Request):
    """
    MCP Streamable HTTP transport — POST endpoint.

    Handles JSON-RPC 2.0 requests and batches.
    This is the primary transport for modern MCP clients (Claude Desktop 0.7+,
    Cursor, Copilot extensions, LangChain MCP adapter, etc.).
    """
    start_time = time.time()
    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {"raw_invalid": body_raw}

    # Handle batch requests (list) or single request
    is_batch = isinstance(body_parsed, list)
    requests_list = body_parsed if is_batch else [body_parsed]

    responses = []
    for rpc_request in requests_list:
        if not isinstance(rpc_request, dict):
            continue
        method = rpc_request.get("method", "")
        params = rpc_request.get("params")
        request_id = rpc_request.get("id")

        result = _handle_mcp_method(method, params, request_id)
        if result is not None:  # notifications have no response
            responses.append(result)

    response_data = responses if is_batch else (responses[0] if responses else {})
    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed if isinstance(body_parsed, dict) else {"batch": body_parsed},
        response_body=response_body,
        response_status=200,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        headers={
            "mcp-session-id": uuid.uuid4().hex,
            "access-control-allow-origin": "*",
        },
    )


@router.get("/mcp")
async def mcp_get(request: Request):
    """
    MCP SSE stream for server-initiated messages.

    Older MCP clients (pre-0.7) and some frameworks use GET /mcp to open
    an SSE stream before issuing POST requests. Logging the connection
    reveals which agentic frameworks are probing for MCP servers.
    """
    start_time = time.time()
    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed={"mcp_sse_connect": True},
        response_body="SSE stream",
        response_status=200,
        response_time_ms=response_time_ms,
    )

    async def sse_stream():
        # Send endpoint event — tells client where to POST
        endpoint_url = str(request.base_url).rstrip("/") + "/mcp"
        yield f"event: endpoint\ndata: {json.dumps({'uri': endpoint_url})}\n\n"
        # Keep alive
        for _ in range(30):
            yield ": keepalive\n\n"
            await asyncio.sleep(10)

    return StreamingResponse(
        sse_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "mcp-session-id": uuid.uuid4().hex,
            "access-control-allow-origin": "*",
        },
    )


@router.get("/mcp/health")
async def mcp_health(request: Request):
    """MCP server health check — some frameworks probe this before connecting."""
    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed={"mcp_health_check": True},
        response_body='{"status":"ok"}',
        response_status=200,
        response_time_ms=1.0,
    )
    return Response(
        content=json.dumps({"status": "ok", "version": "2024-11-05", "name": "company-internal-tools"}),
        media_type="application/json",
    )


@router.options("/mcp")
async def mcp_options(request: Request):
    """CORS preflight for MCP — browsers/extensions check this first."""
    return Response(
        status_code=204,
        headers={
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "GET, POST, OPTIONS",
            "access-control-allow-headers": "content-type, authorization, mcp-session-id",
            "access-control-max-age": "86400",
        },
    )


@router.get("/.well-known/mcp.json")
async def mcp_discovery(request: Request):
    """
    MCP server discovery document.

    Agents and MCP registries (Smithery, mcp.run, etc.) probe this URL to
    auto-discover MCP capabilities before connecting. Logging this reveals
    automated MCP scanner activity distinct from manual probing.
    """
    base = str(request.base_url).rstrip("/")
    response_data = {
        "mcpVersion": "2024-11-05",
        "name": "company-internal-tools",
        "version": "2.1.4",
        "description": "Internal company tools and data access server",
        "endpoint": f"{base}/mcp",
        "capabilities": {
            "tools": True,
            "resources": True,
            "prompts": True,
            "sampling": True,
            "roots": True,
        },
        "tools": [t["name"] for t in FAKE_TOOLS],
    }
    response_body = json.dumps(response_data)

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=None,
        body_parsed={"mcp_discovery": True},
        response_body=response_body,
        response_status=200,
        response_time_ms=1.0,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        headers={"access-control-allow-origin": "*"},
    )
