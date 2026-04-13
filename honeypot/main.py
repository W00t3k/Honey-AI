"""
OpenAI API Honeypot - Main Application

A production-grade honeypot that mimics the OpenAI API to capture and analyze
attacks on AI infrastructure.

For security research purposes only.
"""

import json
import multiprocessing
import os
import signal
import sys
import time
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from rich.console import Console
from rich.panel import Panel

# Load environment before other imports
load_dotenv()

from models.db import Database
from services import init_logger, get_geoip_service, get_logger
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
    admin_router,
    set_database,
)

console = Console()

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./honeypot.db")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "80"))
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "./GeoLite2-City.mmdb")

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

    from routers.admin import ADMIN_PATH
    console.print(f"\n[bold green]Listening on {HOST}:{PORT}[/bold green]")
    console.print(f"[dim]Admin UI : http://127.0.0.1:{PORT}{ADMIN_PATH}[/dim]")
    if ADMIN_PATH == "/admin":
        console.print("[yellow]⚠  Set ADMIN_PATH in .env to a secret path before deploying publicly[/yellow]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    yield

    # Shutdown
    console.print("\n[yellow]Shutting down...[/yellow]")
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

# Include routers — order matters: specific routes before catch-all
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
    from services.groq_chat import get_groq_chat

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
    return StreamingResponse(
        groq_chat.stream(messages),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# Catch-all for unknown paths (log but return generic response)
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all(request: Request, path: str):
    """Catch all other requests and log them."""
    start_time = time.time()

    # Parse body if present
    body_raw = None
    body_parsed = None
    try:
        body_raw = (await request.body()).decode("utf-8", errors="replace")
        if body_raw:
            body_parsed = json.loads(body_raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # Match real OpenAI 404 format exactly
    response_data = {
        "error": {
            "message": "Not Found",
            "type": "invalid_request_error",
            "param": None,
            "code": None,
        }
    }

    response_body = json.dumps(response_data)
    response_time_ms = (time.time() - start_time) * 1000

    # Log the request
    logger = get_logger()
    await logger.log_request(
        request=request,
        body_raw=body_raw,
        body_parsed=body_parsed,
        response_body=response_body,
        response_status=404,
        response_time_ms=response_time_ms,
    )

    return Response(
        content=response_body,
        media_type="application/json",
        status_code=404,
    )


def _get_listen_ports() -> list[int]:
    """Return the primary and configured additional listener ports."""
    config = get_config()
    ports = [PORT]
    for extra in config.get("additional_ports", []) or []:
        if extra not in ports:
            ports.append(extra)
    return ports


def _run_single_server(port: int):
    import uvicorn

    uvicorn.run(
        "main:app",
        host=HOST,
        port=port,
        log_level="info",
        access_log=False,
    )


def _run_multiport_servers():
    ports = _get_listen_ports()
    if len(ports) == 1:
        _run_single_server(ports[0])
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

    for port in ports:
        child = multiprocessing.Process(target=_run_single_server, args=(port,))
        child.start()
        children.append(child)

    try:
        while not stopping:
            for child in children:
                if child.exitcode not in (None, 0):
                    console.print(f"[red]Listener on child pid {child.pid} exited with {child.exitcode}[/red]")
                    stopping = True
                    break
            time.sleep(1)
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
        for child in children:
            child.join(timeout=5)


if __name__ == "__main__":
    _run_multiport_servers()
