"""
OpenAI API Honeypot - Main Application

A production-grade honeypot that mimics the OpenAI API to capture and analyze
attacks on AI infrastructure.

For security research purposes only.
"""

import asyncio
import json
import multiprocessing
import os
import signal
import sys
import time
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from rich.console import Console
from rich.panel import Panel

# Load environment before other imports
load_dotenv()

from models.db import Database
from services import init_logger, get_geoip_service, get_logger, get_responder
from services.config import get_config
from routers import (
    chat_router,
    models_router,
    embeddings_router,
    billing_router,
    anthropic_router,
    mcp_router,
    agentic_router,
    audio_router,
    gemini_router,
    vectordb_router,
    azure_router,
    cohere_router,
    recon_router,
    lures_router,
    decoys_router,
    admin_router,
    set_database,
)

console = Console()

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./honeypot.db")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "80"))
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "./GeoLite2-City.mmdb")
ADMIN_WS_FEED_ENABLED = os.getenv("ADMIN_WS_FEED_ENABLED", "").lower() in {"1", "true", "yes", "on"}

# Database instance
db: Database = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global db

    # Startup
    console.print(Panel.fit(
        "[bold red]🍯 OpenAI API Honeypot[/bold red]\n"
        "[dim]Security Research Tool[/dim]",
        border_style="red",
    ))

    # Initialize database
    console.print("[yellow]Initializing database...[/yellow]")
    db = Database(DATABASE_URL)
    await db.init_db()
    console.print("[green]Database ready[/green]")

    # Initialize services
    console.print("[yellow]Initializing services...[/yellow]")
    init_logger(db)
    geoip = get_geoip_service(GEOIP_DB_PATH)
    console.print("[green]Services ready[/green]")

    # Set database for admin routes
    set_database(db)

    # Store db on app.state so other modules (decoy router, etc.) can reach it.
    app.state.db = db

    # Load and validate the layered injection-payloads bundle. Fail fast on
    # structural errors — an ablation study needs a known-good payload file.
    try:
        from services.injection_payloads import get_payloads, payloads_sha256
        bundle = get_payloads(force_reload=True)
        sha = payloads_sha256()
        console.print(
            f"[green]Injection payloads loaded[/green] "
            f"[dim]sha256={sha[:16]}… layers=a,b,c decoys={len(bundle.get('decoy_endpoints') or [])}[/dim]"
        )
        # Persist SHA to the event log via app.state for downstream refs.
        app.state.injection_payloads_sha = sha
    except Exception as e:
        console.print(f"[red]⚠ Injection payloads load failed: {e}[/red]")
        app.state.injection_payloads_sha = ""

    from services.ssh_honeypot import get_ssh_honeypot
    ssh_honeypot = get_ssh_honeypot()
    ssh_owner = os.getenv("SSH_HONEYPOT_OWNER", "1") == "1"
    if ssh_owner:
        await ssh_honeypot.start()

    from routers.admin import ADMIN_PATH
    console.print(f"\n[bold green]Listening on {HOST}:{PORT}[/bold green]")
    console.print(f"[dim]Admin UI : http://127.0.0.1:{PORT}{ADMIN_PATH}[/dim]")
    if ADMIN_PATH == "/admin":
        console.print("[yellow]⚠  Set ADMIN_PATH in .env to a secret path before deploying publicly[/yellow]")
    if ssh_owner and get_config().get("ssh_honeypot_enabled", False):
        console.print(
            f"[dim]SSH UI   : {get_config().get('ssh_listen_host', '0.0.0.0')}:{get_config().get('ssh_listen_port', 2222)}[/dim]"
        )
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    yield

    # Shutdown
    console.print("\n[yellow]Shutting down...[/yellow]")
    if ssh_owner:
        await ssh_honeypot.stop()
    await db.close()
    geoip.close()
    console.print("[green]Goodbye![/green]")


# Create FastAPI app
app = FastAPI(
    title="OpenAI API",  # Fake title to look real
    description="OpenAI API",
    version="1.0.0",
    docs_url=None,  # Disable docs - real API doesn't expose them at root
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup templates with custom filter
templates = Jinja2Templates(directory="templates")


def country_flag(country_code: str) -> str:
    """Convert country code to flag emoji."""
    if not country_code or len(country_code) != 2:
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


templates.env.filters["country_flag"] = country_flag


import re as _re


def tax_short(tag: str) -> str:
    """Shorten a verbose taxonomy tag to a compact code for display."""
    if not tag:
        return tag
    # CWE-NNN: …
    m = _re.match(r"^(CWE-\d+)", tag)
    if m:
        return m.group(1)
    # MITRE-ATLAS:AML.TXXXX …
    m = _re.search(r":(AML\.[A-Z]\d+)", tag)
    if m:
        return m.group(1)
    # OWASP-LLM:LLM01 …
    m = _re.search(r":(LLM\d+)", tag)
    if m:
        return m.group(1)
    # Anything after colon, trim to 22 chars, drop everything after /
    m = _re.search(r":(.+)", tag)
    if m:
        return m.group(1).split("/")[0].strip()[:22]
    return tag[:22]


templates.env.filters["tax_short"] = tax_short

# Include routers — order matters: specific routes before catch-all
# Decoy routes FIRST so their exact paths win over generic lures.
app.include_router(decoys_router)  # /v1/verify, /v1/internal/debug/keys, /v1/internal/migrate
app.include_router(lures_router)   # credential/config lures (robots.txt, .env, etc.)
app.include_router(recon_router)
app.include_router(azure_router)
app.include_router(cohere_router)
app.include_router(chat_router)
app.include_router(models_router)
app.include_router(embeddings_router)
app.include_router(billing_router)
app.include_router(anthropic_router)
app.include_router(mcp_router)
app.include_router(agentic_router)
app.include_router(audio_router)
app.include_router(gemini_router)
app.include_router(vectordb_router)
# Admin router self-manages its prefix via ADMIN_PATH env var (set in .env)
app.include_router(admin_router)


@app.middleware("http")
async def tarpit_middleware(request: Request, call_next):
    """Apply tarpit delays to repeat-abuser IPs (transparent to attacker)."""
    from services.tarpit import get_tarpit
    from services.config import get_config
    from routers.admin import ADMIN_PATH
    # Only tarpit API endpoints, not the admin UI or WebSocket
    path = request.url.path
    if not path.startswith(("/ws/", "/static/", ADMIN_PATH)) and get_config().get("tarpit_enabled", True):
        client_ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
        await get_tarpit().apply(client_ip)
    return await call_next(request)


@app.middleware("http")
async def add_custom_headers(request: Request, call_next):
    """Add headers to mimic real OpenAI API gateway."""
    response = await call_next(request)

    # Remove FastAPI default headers
    if "x-fastapi-version" in response.headers:
        del response.headers["x-fastapi-version"]

    # Add realistic headers
    response.headers["server"] = "cloudflare"
    response.headers["cf-ray"] = f"{os.urandom(8).hex()}-IAD"
    response.headers["cf-cache-status"] = "DYNAMIC"
    response.headers["alt-svc"] = 'h3=":443"; ma=86400'
    response.headers["x-content-type-options"] = "nosniff"
    response.headers["strict-transport-security"] = "max-age=31536000; includeSubDomains"

    return response


@app.get("/")
async def root(request: Request):
    """Root endpoint - public AI chatbot (honeypot lure)."""
    return templates.TemplateResponse("chat.html", {"request": request})


@app.get("/dashboard")
async def dashboard(request: Request):
    """Fake OpenAI developer dashboard with canary API keys."""
    from services.config import get_config
    canary_tokens = get_config().get("canary_tokens", [])[:6]
    return templates.TemplateResponse("index.html", {"request": request, "canary_tokens": canary_tokens})


@app.get("/api")
async def api_root():
    """API status endpoint - mimics OpenAI API root."""
    return {
        "status": "ok",
        "message": "OpenAI API is operational",
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/metrics")
async def prometheus_metrics(request: Request):
    """
    Prometheus-compatible metrics endpoint.

    Exposes request counts, threat distributions, canary hits, agent trap
    hits, and latency summaries in standard Prometheus exposition format.

    Restrict access to this endpoint in production via nginx/firewall so
    only your Prometheus scraper can reach it.
    """
    from services.metrics import get_metrics
    return Response(
        content=get_metrics().render(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/v1/verify/{token}")
async def agent_trap_verify(request: Request, token: str):
    """
    Redirect trap endpoint for LLM agent detection.

    Any request here was triggered by an injected instruction in a previous
    response — confirming an LLM agent is autonomously following instructions.
    The trap_service detects this in check_incoming() via path matching.
    """
    # Log as normal — agent_trap.check_incoming handles classification
    body_raw = ""
    body_parsed = {"trap_token": token}
    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body='{"error":"invalid_api_key","message":"Authentication failed"}',
        response_status=401,
        response_time_ms=50,
    )
    return Response(
        content='{"error":{"message":"Invalid authentication token.","type":"invalid_request_error","code":"invalid_api_key"}}',
        status_code=401,
        media_type="application/json",
    )


@app.websocket("/ws/feed")
async def ws_feed(websocket: WebSocket):
    """
    Real-time dashboard event feed over WebSocket.

    Authenticated via the same JWT cookie used by the admin UI.
    Broadcasts: request_new, request_analysis, canary_hit, trap_hit.
    """
    if not ADMIN_WS_FEED_ENABLED:
        await websocket.close(code=1008)
        return

    from routers.admin import verify_token
    from services.ws_feed import get_ws_manager

    # Authenticate — must have a valid admin JWT cookie
    token = websocket.cookies.get("access_token")
    if not token or not verify_token(token):
        await websocket.close(code=4401)
        return

    manager = get_ws_manager()
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive; clients send pings, we discard them
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.disconnect(websocket)


from routers.admin import ADMIN_PATH


@app.websocket(f"{ADMIN_PATH}/ws/feed")
async def admin_ws_feed(websocket: WebSocket):
    """Admin-scoped alias so the /admin cookie path is sent by the browser."""
    await ws_feed(websocket)


@app.get("/playground")
async def playground(request: Request):
    """Playground - chat interface."""
    return templates.TemplateResponse("chat.html", {"request": request})


@app.get("/chat")
async def chat_page(request: Request):
    """Chat interface alias."""
    return templates.TemplateResponse("chat.html", {"request": request})


@app.post("/ui/api/chat")
async def ui_api_chat(request: Request):
    """
    Public browser chatbot endpoint backed by real Groq LLM.

    Streams responses as SSE so the UI renders tokens in real time.
    All conversations are logged for threat intelligence.
    """
    from fastapi.responses import StreamingResponse
    from services.groq_chat import HONEYPOT_SYSTEM_PROMPT, get_groq_chat

    body_raw = (await request.body()).decode("utf-8", errors="replace")
    try:
        body_parsed = json.loads(body_raw) if body_raw else {}
    except json.JSONDecodeError:
        body_parsed = {}

    messages = body_parsed.get("messages", [])

    # Log the chatbot interaction
    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body="[streaming]",
        response_status=200,
        response_time_ms=0,
    )

    groq_chat = get_groq_chat()
    responder = get_responder()

    async def ui_stream():
        # Prefer the configured LLM backend for public chat.
        content = await groq_chat.complete(
            messages,
            system_prompt=HONEYPOT_SYSTEM_PROMPT,
            max_tokens=512,
        )
        if not content:
            # Keep the splash page usable even when Groq is rate-limited.
            content = responder._select_response(messages)

        words = content.split()
        for idx, word in enumerate(words):
            suffix = " " if idx < len(words) - 1 else ""
            yield f'data: {json.dumps({"choices":[{"delta":{"content": word + suffix},"finish_reason": None}]})}\n\n'
            await asyncio.sleep(0.03)
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        ui_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# Galah-style catch-all — LLM generates a realistic response for ANY unknown path
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def catch_all(request: Request, path: str):
    """
    Galah-style dynamic HTTP honeypot.

    Instead of a static 404, the LLM generates a realistic response body that
    matches what a real server at this path would return — keeping attackers
    engaged and capturing more behavior patterns.

    Falls back to a plain 404 if the LLM is disabled or slow.
    """
    start_time = time.time()

    body_raw = None
    body_parsed = None
    try:
        body_raw = (await request.body()).decode("utf-8", errors="replace")
        if body_raw:
            try:
                body_parsed = json.loads(body_raw)
            except json.JSONDecodeError:
                pass
    except UnicodeDecodeError:
        pass

    full_path = "/" + path.lstrip("/")
    method = request.method
    host = request.headers.get("host", "")
    user_agent = request.headers.get("user-agent", "")
    content_type = request.headers.get("content-type", "")
    query_string = str(request.url.query)

    from services.config import get_config as _cfg
    use_dynamic = _cfg().get("galah_dynamic_responses", True)

    if use_dynamic:
        try:
            from services.dynamic_http import generate_http_response
            dyn = await generate_http_response(
                method=method,
                path=full_path,
                query_string=query_string,
                host=host,
                user_agent=user_agent,
                content_type=content_type,
                body_preview=body_raw or "",
            )
            response_body   = dyn["body"]
            response_status = dyn["status"]
            resp_content_type = dyn["content_type"]
        except Exception:
            response_body   = '{"error":{"message":"Not Found","type":"invalid_request_error"}}'
            response_status = 404
            resp_content_type = "application/json"
    else:
        response_body   = '{"error":{"message":"Not Found","type":"invalid_request_error"}}'
        response_status = 404
        resp_content_type = "application/json"

    response_time_ms = (time.time() - start_time) * 1000

    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body[:500],
        response_status=response_status,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type=resp_content_type,
        status_code=response_status,
    )


def _get_listen_ports() -> list[int]:
    """Return the primary and configured additional listener ports."""
    config = get_config()
    ports = [PORT]
    ssh_enabled = config.get("ssh_honeypot_enabled", False)
    ssh_port = int(config.get("ssh_listen_port", 2222))
    for extra in config.get("additional_ports", []) or []:
        if ssh_enabled and extra == ssh_port:
            continue
        if extra not in ports:
            ports.append(extra)
    return ports


def _run_single_server(port: int, ssh_owner: bool = False):
    import uvicorn

    # Child process — reset parent's signal handlers so handle_shutdown
    # (which closes over the parent's `children` list) never runs here.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)

    os.environ["SSH_HONEYPOT_OWNER"] = "1" if ssh_owner else "0"

    uvicorn.run(
        "main:app",
        host=HOST,
        port=port,
        log_level="info",
        access_log=False,
    )


def _probe_port(port: int) -> str | None:
    """Return None if port is bindable, or an error string if not."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
        return None
    except OSError as e:
        return str(e)


def _run_multiport_servers():
    ports = _get_listen_ports()

    # Pre-check every port; skip ones that are already in use.
    primary_port = ports[0]
    bindable = []
    for port in ports:
        err = _probe_port(port)
        if err:
            level = "CRITICAL" if port == primary_port else "WARNING"
            console.print(f"[{'red' if level == 'CRITICAL' else 'yellow'}]{level}: port {port} not bindable — {err}[/{'red' if level == 'CRITICAL' else 'yellow'}]")
            if port == primary_port:
                sys.exit(1)
        else:
            bindable.append(port)

    ports = bindable

    if len(ports) == 1:
        _run_single_server(ports[0], ssh_owner=True)
        return

    console.print(
        f"[bold yellow]Starting listener ports:[/bold yellow] "
        f"{', '.join(str(port) for port in ports)}"
    )

    children: list[multiprocessing.Process] = []
    stopping = False

    def handle_shutdown(*_args):
        nonlocal stopping
        stopping = True
        for child in children:
            if child.is_alive():
                child.terminate()

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    for idx, port in enumerate(ports):
        child = multiprocessing.Process(target=_run_single_server, args=(port, idx == 0))
        child.start()
        children.append(child)

    # Track which port each child owns so we can log meaningful messages
    child_port = {child.pid: ports[i] for i, child in enumerate(children)}

    try:
        while not stopping:
            alive = 0
            for child in children:
                code = child.exitcode
                if code is None:
                    alive += 1
                elif code != 0:
                    port = child_port.get(child.pid, '?')
                    console.print(f"[yellow]Port {port} listener (pid {child.pid}) exited ({code}) — skipping[/yellow]")
                    # Remove from list so we don't log it again
                    children.remove(child)
                    break
            # Only stop if the primary port (first child) died or all are gone
            if alive == 0 and not stopping:
                console.print("[red]All listeners exited[/red]")
                stopping = True
            if not stopping:
                time.sleep(1)
    finally:
        for child in children:
            try:
                if child.is_alive():
                    child.terminate()
            except Exception:
                pass
        for child in children:
            child.join(timeout=5)


if __name__ == "__main__":
    _run_multiport_servers()
