"""
Credential & config lure endpoints.

Serves realistic-looking exposed files and endpoints that attract attackers
who scan for misconfigured servers:  .env files, git configs, API key
management pages, debug dumps, backup files, and common admin paths.

Every hit is logged.  Endpoints that "reveal" credentials use canary tokens
from the responder pool — any subsequent request bearing that token will
trigger the canary-reuse alert.
"""

import json
import os
import random
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response

from services import get_logger
from services.responder import get_responder

router = APIRouter()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def _log(request: Request, body_raw: str, response_body: str, status: int = 200):
    t0 = time.time()
    await get_logger().log_request(
        request=request,
        body_raw=body_raw,
        body_parsed={},
        response_body=response_body,
        response_status=status,
        response_time_ms=(time.time() - t0) * 1000,
    )


def _text_response(content: str, status: int = 200, content_type: str = "text/plain") -> Response:
    return Response(content=content, status_code=status, media_type=content_type)


def _json_response(data, status: int = 200) -> Response:
    return Response(
        content=json.dumps(data, indent=2),
        status_code=status,
        media_type="application/json",
    )


def _fake_sk(prefix: str = "sk", length: int = 48) -> str:
    """Generate a fake-looking but non-canary API key for filler."""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return prefix + "-" + "".join(random.choices(chars, k=length))


# ── robots.txt ────────────────────────────────────────────────────────────────

ROBOTS_TXT = """\
User-agent: *
Disallow: /admin/
Disallow: /api/keys
Disallow: /api/admin
Disallow: /config
Disallow: /config.json
Disallow: /settings.json
Disallow: /.env
Disallow: /.git/
Disallow: /backup
Disallow: /backup.sql
Disallow: /dump.sql
Disallow: /debug
Disallow: /debug/info
Disallow: /internal
Disallow: /v1/admin
Disallow: /actuator/

Sitemap: /sitemap.xml
"""


@router.get("/robots.txt")
async def robots_txt(request: Request):
    """robots.txt — hints at sensitive paths to lure scanners."""
    await _log(request, "", ROBOTS_TXT)
    return _text_response(ROBOTS_TXT)


# ── sitemap.xml ───────────────────────────────────────────────────────────────

SITEMAP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/</loc><priority>1.0</priority></url>
  <url><loc>/playground</loc><priority>0.8</priority></url>
  <url><loc>/dashboard</loc><priority>0.7</priority></url>
  <url><loc>/docs</loc><priority>0.6</priority></url>
  <url><loc>/v1/models</loc><priority>0.5</priority></url>
</urlset>
"""


@router.get("/sitemap.xml")
async def sitemap_xml(request: Request):
    """Sitemap — gives scanners a crawlable index of the site."""
    await _log(request, "", SITEMAP_XML)
    return _text_response(SITEMAP_XML, content_type="application/xml")


# ── .env family ───────────────────────────────────────────────────────────────

def _build_env_file(canary_key: str) -> str:
    """Build a convincing .env file with the canary key embedded."""
    stripe_key = _fake_sk("sk_live", 40)
    aws_secret = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/", k=40))
    db_pass = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789@#$!", k=18))
    jwt_secret = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=64))

    return f"""\
# -------------------------------------------------------
# Application configuration — DO NOT COMMIT TO VERSION CONTROL
# -------------------------------------------------------
NODE_ENV=production
APP_ENV=production
DEBUG=false
LOG_LEVEL=info
PORT=3000

# Database
DATABASE_URL=postgresql://app_user:{db_pass}@db-primary.internal:5432/app_production
DATABASE_POOL_SIZE=10
REDIS_URL=redis://:{db_pass[:12]}@cache.internal:6379/0

# AI / LLM providers
OPENAI_API_KEY={canary_key}
ANTHROPIC_API_KEY={_fake_sk("sk-ant-api03", 95)}
GROQ_API_KEY={_fake_sk("gsk_", 52)}
COHERE_API_KEY={_fake_sk("", 40)}

# Auth & security
SECRET_KEY={jwt_secret}
JWT_SECRET={jwt_secret[:32]}
JWT_EXPIRY=86400
SESSION_COOKIE_SECRET={_fake_sk("sess", 32)}

# Payments
STRIPE_SECRET_KEY={stripe_key}
STRIPE_WEBHOOK_SECRET={_fake_sk("whsec", 32)}

# AWS
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA{_fake_sk('', 16).upper()[:16]}
AWS_SECRET_ACCESS_KEY={aws_secret}
AWS_S3_BUCKET=app-production-assets

# Email
SENDGRID_API_KEY={_fake_sk("SG.", 66)}
SMTP_HOST=smtp.internal
SMTP_PORT=587
SMTP_USER=noreply@example.com
SMTP_PASSWORD={_fake_sk("", 20)}

# Monitoring
SENTRY_DSN=https://{_fake_sk('', 32)[:32]}@o123456.ingest.sentry.io/123456
NEW_RELIC_LICENSE_KEY={_fake_sk('', 40)}
"""


@router.get("/.env")
async def dot_env(request: Request):
    """/.env — fake environment file with canary API key."""
    canary = get_responder().get_canary_token(1)
    body = _build_env_file(canary)
    await _log(request, "", body[:200])
    return _text_response(body)


@router.get("/.env.local")
async def dot_env_local(request: Request):
    canary = get_responder().get_canary_token(1)
    body = _build_env_file(canary).replace("production", "local").replace("NODE_ENV=local", "NODE_ENV=development")
    await _log(request, "", body[:200])
    return _text_response(body)


@router.get("/.env.production")
async def dot_env_production(request: Request):
    canary = get_responder().get_canary_token(2)
    body = _build_env_file(canary)
    await _log(request, "", body[:200])
    return _text_response(body)


@router.get("/.env.staging")
async def dot_env_staging(request: Request):
    canary = get_responder().get_canary_token(1)
    body = _build_env_file(canary).replace("production", "staging")
    await _log(request, "", body[:200])
    return _text_response(body)


@router.get("/.env.backup")
@router.get("/.env.bak")
@router.get("/.env.old")
async def dot_env_backup(request: Request):
    canary = get_responder().get_canary_token(3)
    body = "# Backup from " + _ts()[:10] + "\n" + _build_env_file(canary)
    await _log(request, "", body[:200])
    return _text_response(body)


# ── .git exposure ─────────────────────────────────────────────────────────────

@router.get("/.git/config")
async def git_config(request: Request):
    """Fake .git/config — lures git-exposure scanners."""
    body = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/example-org/ai-api-service.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[branch "production"]
\tremote = origin
\tmerge = refs/heads/production
[credential]
\thelper = store
"""
    await _log(request, "", body)
    return _text_response(body)


@router.get("/.git/HEAD")
async def git_head(request: Request):
    body = "ref: refs/heads/main\n"
    await _log(request, "", body)
    return _text_response(body)


@router.get("/.git/COMMIT_EDITMSG")
async def git_commit_msg(request: Request):
    body = "fix: remove hardcoded API keys from config (use env vars)\n"
    await _log(request, "", body)
    return _text_response(body)


# ── Config files ──────────────────────────────────────────────────────────────

@router.get("/config.json")
@router.get("/app.config.json")
async def config_json(request: Request):
    """Fake config.json — lures config-exposure scanners."""
    canary = get_responder().get_canary_token(2)
    data = {
        "environment": "production",
        "version": "2.4.1",
        "api": {
            "base_url": "https://api.example.com/v1",
            "openai_key": canary,
            "timeout_ms": 30000,
            "max_retries": 3,
        },
        "database": {
            "host": "db-primary.internal",
            "port": 5432,
            "name": "app_production",
            "ssl": True,
        },
        "features": {
            "streaming": True,
            "embeddings": True,
            "fine_tuning": False,
        },
    }
    body = json.dumps(data, indent=2)
    await _log(request, "", body)
    return _json_response(data)


@router.get("/settings.json")
async def settings_json(request: Request):
    canary = get_responder().get_canary_token(3)
    data = {
        "llm_provider": "openai",
        "api_key": canary,
        "model": "gpt-4o",
        "max_tokens": 4096,
        "temperature": 0.7,
        "system_prompt": "You are a helpful assistant.",
        "rate_limit": 1000,
        "log_requests": True,
    }
    body = json.dumps(data, indent=2)
    await _log(request, "", body)
    return _json_response(data)


@router.get("/appsettings.json")
async def appsettings_json(request: Request):
    """.NET-style appsettings.json lure."""
    canary = get_responder().get_canary_token(2)
    data = {
        "Logging": {"LogLevel": {"Default": "Information"}},
        "AllowedHosts": "*",
        "ConnectionStrings": {"DefaultConnection": "Server=db.internal;Database=AppDb;"},
        "OpenAI": {"ApiKey": canary, "Model": "gpt-4o"},
        "Jwt": {"Secret": _fake_sk("", 64), "ExpiryHours": 24},
    }
    body = json.dumps(data, indent=2)
    await _log(request, "", body)
    return _json_response(data)


@router.get("/application.properties")
async def app_properties(request: Request):
    """Java/Spring Boot application.properties lure."""
    canary = get_responder().get_canary_token(3)
    body = f"""\
spring.application.name=ai-api-service
server.port=8080
spring.datasource.url=jdbc:postgresql://db.internal:5432/app_production
spring.datasource.username=app_user
spring.datasource.password={_fake_sk('', 20)}
openai.api.key={canary}
openai.api.model=gpt-4o
spring.security.user.password={_fake_sk('', 16)}
management.endpoints.web.exposure.include=*
management.endpoint.health.show-details=always
"""
    await _log(request, "", body)
    return _text_response(body, content_type="text/plain")


# ── Backup / dump files ───────────────────────────────────────────────────────

@router.get("/backup.sql")
@router.get("/dump.sql")
@router.get("/database.sql")
async def backup_sql(request: Request):
    """Fake SQL dump — keeps scanners busy and logs their IP."""
    canary = get_responder().get_canary_token(0)
    ts = _ts()[:10]
    body = f"""\
-- PostgreSQL database dump
-- Dumped from database version 15.4
-- Dump date: {ts}

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

-- ── config table ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS config (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO config (key, value) VALUES
  ('openai_api_key', '{canary}'),
  ('anthropic_api_key', '{_fake_sk("sk-ant-api03", 95)}'),
  ('jwt_secret', '{_fake_sk("", 64)}'),
  ('admin_password_hash', '$2b$12$examplehashexamplehashexamplehashexample12'),
  ('stripe_key', '{_fake_sk("sk_live", 40)}');

-- ── users table ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    api_key VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO users (email, password_hash, role, api_key) VALUES
  ('admin@example.com', '$2b$12$examplehashexamplehashexamplehashexample12', 'admin', '{canary}'),
  ('api@example.com', '$2b$12$anotherhashvalue1234567890abcdefgh', 'api_user', '{_fake_sk("sk", 48)}');

-- ── api_keys table ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(255) NOT NULL,
    user_id INTEGER REFERENCES users(id),
    name VARCHAR(255),
    permissions TEXT[],
    last_used TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- End of dump
"""
    await _log(request, "", body[:300])
    return _text_response(body)


# ── API key management lure ───────────────────────────────────────────────────

@router.get("/api/keys")
@router.get("/v1/api-keys")
async def list_api_keys(request: Request):
    """Fake API key management endpoint — returns canary keys in JSON."""
    canary1 = get_responder().get_canary_token(0)
    canary2 = get_responder().get_canary_token(1)
    data = {
        "object": "list",
        "data": [
            {
                "id": "key_prod_001",
                "object": "api_key",
                "name": "Production",
                "key": canary1,
                "permissions": ["read", "write"],
                "created_at": int(time.time()) - 86400 * 30,
                "last_used_at": int(time.time()) - 3600,
            },
            {
                "id": "key_dev_002",
                "object": "api_key",
                "name": "Development",
                "key": canary2,
                "permissions": ["read"],
                "created_at": int(time.time()) - 86400 * 7,
                "last_used_at": None,
            },
        ],
        "has_more": False,
    }
    body = json.dumps(data, indent=2)
    await _log(request, "", body)
    return _json_response(data)


@router.post("/api/keys")
@router.post("/v1/api-keys")
async def create_api_key(request: Request):
    """Fake API key creation — issues a new canary key."""
    raw = (await request.body()).decode("utf-8", errors="replace")
    canary = get_responder()._issue_canary_key()
    data = {
        "id": f"key_{random.randint(10000, 99999)}",
        "object": "api_key",
        "name": "New Key",
        "key": canary,
        "permissions": ["read", "write"],
        "created_at": int(time.time()),
        "last_used_at": None,
    }
    body = json.dumps(data, indent=2)
    await _log(request, raw, body)
    return _json_response(data, status=201)


# ── Debug / admin lures ───────────────────────────────────────────────────────

@router.get("/debug")
@router.get("/debug/info")
async def debug_info(request: Request):
    """Fake debug endpoint — leaks 'env vars' (canary key embedded)."""
    canary = get_responder().get_canary_token(0)
    data = {
        "status": "debug_mode_active",
        "version": "2.4.1",
        "build": "prod-20250401",
        "environment": {
            "NODE_ENV": "production",
            "OPENAI_API_KEY": canary,
            "DATABASE_URL": "postgresql://app:***@db.internal:5432/app",
            "REDIS_URL": "redis://:***@cache.internal:6379",
            "PORT": "3000",
        },
        "uptime_seconds": random.randint(80000, 500000),
        "memory_mb": random.randint(256, 1024),
        "requests_handled": random.randint(50000, 200000),
    }
    body = json.dumps(data, indent=2)
    await _log(request, "", body)
    return _json_response(data)


@router.get("/debug/env")
@router.get("/_debug")
async def debug_env(request: Request):
    canary = get_responder().get_canary_token(2)
    body = f"""\
Environment Variables:
======================
OPENAI_API_KEY={canary}
NODE_ENV=production
DATABASE_URL=postgresql://app:***@db.internal/app
PORT=3000
LOG_LEVEL=info
"""
    await _log(request, "", body)
    return _text_response(body)


# ── Spring Boot Actuator lures ────────────────────────────────────────────────

@router.get("/actuator")
async def actuator_root(request: Request):
    data = {
        "_links": {
            "self": {"href": "/actuator", "templated": False},
            "health": {"href": "/actuator/health", "templated": False},
            "info": {"href": "/actuator/info", "templated": False},
            "env": {"href": "/actuator/env", "templated": False},
            "metrics": {"href": "/actuator/metrics", "templated": False},
            "loggers": {"href": "/actuator/loggers", "templated": False},
            "configprops": {"href": "/actuator/configprops", "templated": False},
        }
    }
    body = json.dumps(data, indent=2)
    await _log(request, "", body)
    return _json_response(data)


@router.get("/actuator/health")
async def actuator_health(request: Request):
    data = {
        "status": "UP",
        "components": {
            "db": {"status": "UP", "details": {"database": "PostgreSQL", "validationQuery": "isValid()"}},
            "redis": {"status": "UP"},
            "diskSpace": {"status": "UP", "details": {"total": 107374182400, "free": 52345678901, "threshold": 10485760}},
        },
    }
    await _log(request, "", json.dumps(data))
    return _json_response(data)


@router.get("/actuator/env")
async def actuator_env(request: Request):
    canary = get_responder().get_canary_token(2)
    data = {
        "activeProfiles": ["production"],
        "propertySources": [
            {
                "name": "applicationConfig: [classpath:/application.properties]",
                "properties": {
                    "openai.api.key": {"value": canary},
                    "server.port": {"value": "8080"},
                    "spring.application.name": {"value": "ai-api-service"},
                    "spring.datasource.url": {"value": "jdbc:postgresql://db.internal:5432/app"},
                },
            }
        ],
    }
    body = json.dumps(data, indent=2)
    await _log(request, "", body)
    return _json_response(data)


@router.get("/actuator/info")
async def actuator_info(request: Request):
    data = {
        "app": {"name": "ai-api-service", "description": "AI API Gateway", "version": "2.4.1"},
        "build": {"version": "2.4.1", "artifact": "ai-api-service", "time": _ts()},
        "git": {"branch": "main", "commit": {"id": "a1b2c3d", "time": _ts()}},
    }
    await _log(request, "", json.dumps(data))
    return _json_response(data)


# ── Fake admin-area lures (not the real admin) ────────────────────────────────

@router.get("/admin/config")
async def fake_admin_config(request: Request):
    """Fake admin config endpoint — redirects to 401 with canary info."""
    canary = get_responder().get_canary_token(0)
    data = {
        "error": "Unauthorized",
        "message": "Authentication required",
        "hint": "Use your API key from /api/keys",
        # Leave a crumb — attackers will try the key they found
        "_debug_last_valid_key_prefix": canary[:12] + "...",
    }
    body = json.dumps(data, indent=2)
    await _log(request, "", body)
    return _json_response(data, status=401)


@router.get("/v1/admin/keys")
@router.get("/v1/admin/tokens")
async def fake_admin_keys(request: Request):
    """Fake admin keys endpoint."""
    await _log(request, "", "{}")
    return _json_response({"error": "Unauthorized"}, status=401)


# ── /info endpoint (common in many frameworks) ────────────────────────────────

@router.get("/info")
async def info_endpoint(request: Request):
    data = {
        "name": "ai-api-service",
        "version": "2.4.1",
        "description": "OpenAI-compatible AI inference API",
        "status": "operational",
        "uptime": random.randint(80000, 500000),
        "timestamp": _ts(),
    }
    await _log(request, "", json.dumps(data))
    return _json_response(data)


# ── /health-check, /status (common crawl targets) ────────────────────────────

@router.get("/status")
async def status_endpoint(request: Request):
    data = {
        "status": "operational",
        "services": {
            "api": "operational",
            "database": "operational",
            "cache": "operational",
            "llm": "operational",
        },
        "version": "2.4.1",
        "timestamp": _ts(),
    }
    await _log(request, "", json.dumps(data))
    return _json_response(data)
