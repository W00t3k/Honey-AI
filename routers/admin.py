"""
Admin dashboard router.

Password-protected admin interface for viewing honeypot data.
"""

import csv
import io
import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Request, Response, Depends, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext

from models.db import Database
from services.config import get_config

# Configurable admin path — set ADMIN_PATH env var to hide admin UI from discovery
ADMIN_PATH = os.getenv("ADMIN_PATH", "/admin")

router = APIRouter(prefix=ADMIN_PATH)
templates = Jinja2Templates(directory="templates")
ACCESS_COOKIE_NAME = "access_token"


def _country_flag(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


templates.env.filters["country_flag"] = _country_flag


import re as _re


def _tax_short(tag: str) -> str:
    if not tag:
        return tag
    m = _re.match(r"^(CWE-\d+)", tag)
    if m:
        return m.group(1)
    m = _re.search(r":(AML\.[A-Z]\d+)", tag)
    if m:
        return m.group(1)
    m = _re.search(r":(LLM\d+)", tag)
    if m:
        return m.group(1)
    m = _re.search(r":(.+)", tag)
    if m:
        return m.group(1).split("/")[0].strip()[:22]
    return tag[:22]


templates.env.filters["tax_short"] = _tax_short

# Password hashing
pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")

# JWT settings
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Fallback env credentials (used only when setup not yet complete)
_ENV_ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
_ENV_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, _get_jwt_secret(), algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Optional[str]:
    """Verify JWT token and return username."""
    try:
        payload = jwt.decode(token, _get_jwt_secret(), algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except JWTError:
        return None


async def get_current_user(request: Request) -> Optional[str]:
    """Get current authenticated user from cookie."""
    token = request.cookies.get(ACCESS_COOKIE_NAME)
    if not token:
        return None
    return verify_token(token)


def _request_uses_https(request: Request) -> bool:
    """Honor reverse-proxy TLS headers when deciding cookie security."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    return request.url.scheme == "https" or forwarded_proto == "https"


def _set_auth_cookie(response: Response, request: Request, username: str) -> None:
    """Set the admin auth cookie consistently across login and secret rotation."""
    access_token = create_access_token(data={"sub": username})
    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        path=ADMIN_PATH,
        secure=_request_uses_https(request),
        samesite="lax",
    )


def require_auth(request: Request):
    """Dependency to require authentication."""

    async def check():
        user = await get_current_user(request)
        if not user:
            raise HTTPException(
                status_code=303,
                headers={"Location": f"{ADMIN_PATH}/login"},
            )
        return user

    return check


# Database instance (set by main.py)
_db: Optional[Database] = None


def set_database(db: Database):
    """Set the database instance for admin routes."""
    global _db
    _db = db


def get_database() -> Database:
    """Get database instance."""
    if _db is None:
        raise HTTPException(status_code=500, detail="Database not initialized")
    return _db


def _check_credentials(username: str, password: str) -> bool:
    """Verify admin credentials against config (bcrypt) or env fallback."""
    config = get_config()
    if config.is_setup_done():
        stored_user = config.get("admin_username", "")
        stored_hash = config.get("admin_password", "")
        if username != stored_user:
            return username == _ENV_ADMIN_USERNAME and password == _ENV_ADMIN_PASSWORD
        if stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
            if pwd_context.verify(password, stored_hash):
                return True
        elif stored_hash.startswith("$pbkdf2-sha256$"):
            if pwd_context.verify(password, stored_hash):
                return True
        elif password == stored_hash:  # plaintext fallback
            return True
        return username == _ENV_ADMIN_USERNAME and password == _ENV_ADMIN_PASSWORD
    else:
        return username == _ENV_ADMIN_USERNAME and password == _ENV_ADMIN_PASSWORD


def _get_jwt_secret() -> str:
    """Use saved config first so settings changes take effect immediately."""
    return get_config().get("jwt_secret") or os.getenv("JWT_SECRET", "change-this-secret-key")


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    """First-run setup wizard."""
    config = get_config()
    if config.is_setup_done():
        return RedirectResponse(url=f"{ADMIN_PATH}/login", status_code=303)
    return templates.TemplateResponse(
        "admin/setup.html",
        {"request": request, "error": None, "admin_path": ADMIN_PATH},
    )


@router.post("/setup")
async def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    """Handle first-run setup form."""
    config = get_config()
    if config.is_setup_done():
        return RedirectResponse(url=f"{ADMIN_PATH}/login", status_code=303)

    error = None
    if len(username) < 3:
        error = "Username must be at least 3 characters."
    elif username.lower() in ("admin", "administrator", "root"):
        error = "Choose a less obvious username."
    elif len(password) < 10:
        error = "Password must be at least 10 characters."
    elif password.lower() in ("changeme", "password", "admin", "12345678", "honeypot"):
        error = "That password is too common. Choose something stronger."
    elif password != confirm_password:
        error = "Passwords do not match."

    if error:
        return templates.TemplateResponse(
            "admin/setup.html",
            {"request": request, "error": error, "admin_path": ADMIN_PATH},
        )

    password_hash = pwd_context.hash(password)
    config.complete_setup(username=username, password_hash=password_hash)
    return RedirectResponse(url=f"{ADMIN_PATH}/login?setup=done", status_code=303)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render login page, redirect to setup if not configured."""
    config = get_config()
    if not config.is_setup_done():
        return RedirectResponse(url=f"{ADMIN_PATH}/setup", status_code=303)
    setup_done = request.query_params.get("setup") == "done"
    return templates.TemplateResponse(
        "admin/login.html",
        {"request": request, "error": None, "admin_path": ADMIN_PATH,
         "setup_done": setup_done},
    )


@router.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Handle login form submission."""
    if _check_credentials(username, password):
        response = RedirectResponse(url=ADMIN_PATH, status_code=303)
        _set_auth_cookie(response, request, username)
        return response

    return templates.TemplateResponse(
        "admin/login.html",
        {"request": request, "error": "Invalid credentials", "admin_path": ADMIN_PATH,
         "setup_done": False},
    )


@router.get("/logout")
async def logout(request: Request):
    """Handle logout."""
    response = RedirectResponse(url=f"{ADMIN_PATH}/login", status_code=303)
    response.delete_cookie(
        key=ACCESS_COOKIE_NAME,
        path=ADMIN_PATH,
        secure=_request_uses_https(request),
    )
    return response


@router.get("/tokens", response_class=HTMLResponse)
async def tokens_page(request: Request):
    """Canary token management page."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"{ADMIN_PATH}/login", status_code=303)
    config = get_config()
    tokens = config.get("canary_tokens", [])
    return templates.TemplateResponse(
        "admin/tokens.html",
        {"request": request, "tokens": tokens, "admin_path": ADMIN_PATH},
    )


@router.post("/api/tokens")
async def add_token(request: Request):
    """Add a new canary token."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)
    data = await request.json()
    import random, string as _string
    label = data.get("label", "").strip()
    token = data.get("token", "").strip()
    note = data.get("note", "").strip()
    if not label:
        raise HTTPException(status_code=400, detail="label is required")
    if not token:
        prefix = random.choice(["sk-proj-", "sk-"])
        chars = _string.ascii_letters + _string.digits
        token = prefix + "".join(random.choices(chars, k=48))
    config = get_config()
    tokens = list(config.get("canary_tokens", []))
    if any(t["token"] == token for t in tokens):
        raise HTTPException(status_code=409, detail="Token already exists")
    tokens.append({
        "id": str(uuid.uuid4())[:8],
        "label": label,
        "token": token,
        "note": note,
        "added_at": datetime.utcnow().isoformat(),
    })
    config.update(canary_tokens=tokens)
    return {"status": "ok", "count": len(tokens)}


@router.delete("/api/tokens/{token_id}")
async def delete_token(request: Request, token_id: str):
    """Remove a canary token by ID."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)
    config = get_config()
    tokens = [t for t in config.get("canary_tokens", []) if t.get("id") != token_id]
    config.update(canary_tokens=tokens)
    return {"status": "ok", "count": len(tokens)}


@router.get("", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    """Render admin dashboard."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"{ADMIN_PATH}/login", status_code=303)

    db = get_database()

    # Get stats and recent requests
    stats = await db.get_stats()
    threat_stats = await db.get_threat_stats()
    recent_requests = await db.get_recent_requests(limit=100)

    # Merge threat stats into main stats
    stats.update(threat_stats)

    return templates.TemplateResponse(
        "admin/dashboard.html",
        {
            "request": request,
            "user": user,
            "stats": stats,
            "recent_requests": [r.to_dict() for r in recent_requests],
            "admin_path": ADMIN_PATH,
        },
    )


@router.get("/api/stats")
async def api_stats(request: Request):
    """API endpoint for stats (for real-time updates)."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    stats = await db.get_stats()
    threat_stats = await db.get_threat_stats()
    stats.update(threat_stats)
    return stats


@router.get("/api/agents")
async def api_agents(request: Request):
    """Detected LLM agents feed."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    threat_stats = await db.get_threat_stats()
    return {
        "agent_types": threat_stats.get("agent_types", {}),
        "trap_hits": threat_stats.get("trap_hits", 0),
        "trap_type_breakdown": threat_stats.get("trap_type_breakdown", {}),
        "detected_agents": threat_stats.get("detected_agents", []),
        "recent_attack_chains": threat_stats.get("recent_attack_chains", []),
    }


@router.get("/api/chains/{attack_chain_id}")
async def api_attack_chain(request: Request, attack_chain_id: str):
    """Replay a correlated attack chain."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    return await db.get_attack_chain(attack_chain_id)


@router.get("/api/requests")
async def api_requests(request: Request, limit: int = 100, offset: int = 0):
    """API endpoint for recent requests."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    requests = await db.get_recent_requests(limit=limit)
    return [r.to_dict() for r in requests]


@router.delete("/api/requests/{request_id}")
async def delete_request_endpoint(request: Request, request_id: int):
    """Delete a logged request by ID."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)
    db = get_database()
    ok = await db.delete_request(request_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Request not found")
    return {"status": "deleted", "id": request_id}


@router.patch("/api/requests/{request_id}")
async def update_request_endpoint(request: Request, request_id: int):
    """Update is_flagged and/or notes on a request."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)
    data = await request.json()
    db = get_database()
    ok = await db.update_request_meta(request_id, data)
    if not ok:
        raise HTTPException(status_code=404, detail="Request not found")
    return {"status": "updated", "id": request_id}


@router.get("/api/map")
async def api_map_data(request: Request):
    """API endpoint for map data."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    return await db.get_map_data()


@router.get("/api/timeline")
async def api_timeline(request: Request):
    """24-hour request timeline — used by the dashboard activity chart."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    stats = await db.get_stats()
    # Fill in all 24 hours so the chart has no gaps
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    hours = [(now - timedelta(hours=i)).strftime("%Y-%m-%d %H:00") for i in range(23, -1, -1)]
    hourly_map = {r["hour"]: r["count"] for r in stats.get("requests_per_hour", [])}
    return [{"hour": h, "count": hourly_map.get(h, 0)} for h in hours]


@router.get("/export/json")
async def export_json(
    request: Request,
    limit: Optional[int] = None,
    classification: Optional[str] = None,
):
    """Export requests as JSON."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    data = await db.export_requests(format="json", limit=limit, classification=classification)

    content = json.dumps(data, indent=2, default=str)
    filename = f"honeypot_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/stix")
async def export_stix(
    request: Request,
    limit: Optional[int] = 500,
):
    """
    Export recent threat intel as a STIX 2.1 Bundle (JSON).

    Each honeypot request becomes an Observed-Data SDO.  High-confidence
    classifications also generate Threat-Actor and Indicator SDOs.
    Compatible with MISP, Elastic SIEM, Splunk ES, and any other STIX 2.1
    consumer.
    """
    import uuid as _uuid
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    rows = await db.export_requests(format="json", limit=limit)

    now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    objects = []

    # Identity SDO (the honeypot itself as the data source)
    identity_id = "identity--" + str(_uuid.uuid5(_uuid.NAMESPACE_DNS, "honeypot.local"))
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "name": "AI Honeypot",
        "identity_class": "system",
        "created": now_iso,
        "modified": now_iso,
    })

    seen_ips: dict[str, str] = {}  # ip → threat-actor id

    for row in (rows or []):
        ts = str(row.get("timestamp", now_iso)).replace(" ", "T")
        if not ts.endswith("Z"):
            ts += "Z"
        ip = row.get("source_ip") or "0.0.0.0"
        classification = row.get("classification") or "unknown"
        threat_level = row.get("threat_level") or "unknown"
        row_id = row.get("id", 0)

        # Observed-Data SDO — one per request
        obs_id = f"observed-data--{_uuid.uuid4()}"
        objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": obs_id,
            "created_by_ref": identity_id,
            "created": ts,
            "modified": ts,
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": 1,
            "object_refs": [],
            "x_honeypot": {
                "request_id": row_id,
                "source_ip": ip,
                "country": row.get("country_name"),
                "asn_org": row.get("asn_org"),
                "method": row.get("method"),
                "path": row.get("path"),
                "api_key_prefix": (row.get("api_key") or "")[:12] or None,
                "model_requested": row.get("model_requested"),
                "classification": classification,
                "classification_confidence": row.get("classification_confidence"),
                "threat_level": threat_level,
                "threat_type": row.get("threat_type"),
                "ai_summary": row.get("ai_summary"),
                "protocol": row.get("protocol"),
                "agent_type": row.get("agent_type"),
                "trap_hit": row.get("trap_hit"),
                "is_flagged": row.get("is_flagged"),
                "mitre_atlas_tags": row.get("mitre_atlas_tags"),
            },
        })

        # Threat-Actor SDO — one per unique IP (deduped)
        if ip not in seen_ips and classification not in ("human", "researcher", "unknown"):
            ta_id = f"threat-actor--{_uuid.uuid5(_uuid.NAMESPACE_URL, f'honeypot-ip-{ip}')}"
            seen_ips[ip] = ta_id
            objects.append({
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": ta_id,
                "created_by_ref": identity_id,
                "created": ts,
                "modified": ts,
                "name": f"Honeypot Attacker {ip}",
                "threat_actor_types": ["criminal" if classification == "credential_stuffer" else "hacker"],
                "aliases": [ip],
                "first_seen": ts,
                "sophistication": "intermediate" if threat_level in ("high", "critical") else "minimal",
                "resource_level": "individual",
                "primary_motivation": (
                    "financial-gain" if classification == "credential_stuffer"
                    else "organizational-gain"
                ),
            })

            # Indicator SDO for the IP
            ind_id = f"indicator--{_uuid.uuid4()}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created_by_ref": identity_id,
                "created": ts,
                "modified": ts,
                "name": f"Malicious IP: {ip}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": ts,
                "confidence": int((row.get("classification_confidence") or 0.5) * 100),
            })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{_uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }

    filename = f"honeypot_stix_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        content=json.dumps(bundle, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/csv")
async def export_csv(
    request: Request,
    limit: Optional[int] = None,
    classification: Optional[str] = None,
):
    """Export requests as CSV."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    data = await db.export_requests(format="csv", limit=limit, classification=classification)

    if not data:
        return Response(content="No data", media_type="text/plain")

    # Create CSV
    output = io.StringIO()
    fieldnames = [
        "id",
        "timestamp",
        "source_ip",
        "country_code",
        "city",
        "asn_org",
        "method",
        "path",
        "api_key",
        "model_requested",
        "classification",
        "classification_confidence",
        "threat_level",
        "threat_type",
        "ai_summary",
        "user_agent",
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for row in data:
        # Flatten the row for CSV
        flat_row = {k: row.get(k) for k in fieldnames}
        writer.writerow(flat_row)

    content = output.getvalue()
    filename = f"honeypot_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Render settings page."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url=f"{ADMIN_PATH}/login", status_code=303)

    config = get_config()

    # Check if GeoIP is loaded
    from services.geoip import get_geoip_service
    geoip = get_geoip_service()
    geoip_loaded = geoip._initialized

    return templates.TemplateResponse(
        "admin/settings.html",
        {
            "request": request,
            "config": config.get_safe(),
            "geoip_loaded": geoip_loaded,
            "admin_path": ADMIN_PATH,
        },
    )


@router.get("/api/settings")
async def get_settings(request: Request):
    """Get current settings."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    config = get_config()
    return config.get_safe()


@router.post("/api/settings")
async def save_settings(request: Request):
    """Save settings."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    try:
        data = await request.json()
        config = get_config()
        current_jwt_secret = config.get("jwt_secret")

        # Update configuration
        config.update(**data)

        # Reinitialize services that depend on config
        from services.analyzer import get_analyzer
        from services.groq_chat import get_groq_chat
        analyzer = get_analyzer()
        analyzer.reload_from_config()
        get_groq_chat().reload_from_config()

        from services.alerts import get_alert_service
        get_alert_service().reload_from_config()

        response = Response(
            content=json.dumps({"status": "ok", "message": "Settings saved"}),
            media_type="application/json",
        )
        if config.get("jwt_secret") != current_jwt_secret:
            _set_auth_cookie(response, request, user)
        return response
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api/test-groq")
async def test_groq(request: Request):
    """Test Groq API key."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    try:
        data = await request.json()
        api_key = data.get("api_key")

        if not api_key:
            return {"success": False, "message": "No API key provided"}

        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "llama-3.1-8b-instant",
                    "messages": [{"role": "user", "content": "Say 'API key valid' in exactly 3 words."}],
                    "max_tokens": 10,
                },
            )

            if response.status_code == 200:
                return {"success": True, "message": "✅ API key is valid!"}
            elif response.status_code == 401:
                return {"success": False, "message": "❌ Invalid API key"}
            else:
                return {"success": False, "message": f"❌ Error: {response.status_code}"}

    except Exception as e:
        return {"success": False, "message": f"❌ Connection error: {str(e)}"}


@router.post("/api/test-webhook")
async def test_webhook(request: Request):
    """Test webhook endpoint."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    try:
        data = await request.json()
        webhook_type = data.get("type")
        url = data.get("url")

        if not url:
            return {"success": False, "message": "No URL provided"}

        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            if webhook_type == "slack":
                payload = {
                    "text": "*Alert Monitor Test*\nWebhook connectivity confirmed.",
                    "username": "Alert Monitor",
                    "icon_emoji": ":bell:"
                }
            elif webhook_type == "discord":
                payload = {
                    "content": "**Alert Monitor Test**\nWebhook connectivity confirmed.",
                    "username": "Alert Monitor"
                }
            else:  # generic
                payload = {
                    "event": "test",
                    "message": "Webhook connectivity test",
                    "timestamp": datetime.utcnow().isoformat()
                }

            response = await client.post(url, json=payload)

            if response.status_code in [200, 204]:
                return {"success": True, "message": "✅ Webhook test sent successfully!"}
            else:
                return {"success": False, "message": f"❌ Webhook returned {response.status_code}"}

    except Exception as e:
        return {"success": False, "message": f"❌ Error: {str(e)}"}


@router.post("/api/download-geoip")
async def download_geoip(request: Request):
    """Download GeoLite2 database."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    try:
        data = await request.json()
        license_key = data.get("license_key")

        if not license_key:
            return {"success": False, "message": "No license key provided"}

        import httpx
        import tarfile
        import io
        import os

        url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"

        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            response = await client.get(url)

            if response.status_code != 200:
                return {"success": False, "message": f"❌ Download failed: {response.status_code}. Check your license key."}

            # Extract the mmdb file
            tar_bytes = io.BytesIO(response.content)
            with tarfile.open(fileobj=tar_bytes, mode="r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith(".mmdb"):
                        # Extract to current directory
                        member.name = os.path.basename(member.name)
                        tar.extract(member, path=".")

                        # Reinitialize GeoIP service
                        from services.geoip import get_geoip_service
                        geoip = get_geoip_service()
                        geoip.initialize()

                        return {"success": True, "message": "✅ GeoLite2-City.mmdb downloaded and loaded!"}

            return {"success": False, "message": "❌ No .mmdb file found in archive"}

    except Exception as e:
        return {"success": False, "message": f"❌ Error: {str(e)}"}


# ── Lure intelligence ─────────────────────────────────────────────────────────

_LURE_PATH_PREFIXES = [
    "/.env", "/.git/", "/config.json", "/settings.json", "/appsettings.json",
    "/application.properties", "/backup.sql", "/dump.sql", "/database.sql",
    "/api/keys", "/debug", "/_debug", "/actuator",
    "/.cursorrules", "/CLAUDE.md", "/.claude/", "/.windsurfrules",
    "/.aider", "/.continue/", "/docker-compose", "/Makefile",
    "/.github/workflows/", "/internal/", "/system-prompt.txt",
    "/prompts/", "/slack-export", "/download/", "/openapi.json",
    "/swagger.json", "/api-docs", "/llms.txt", "/llmstxt",
    "/.well-known/ai-plugin.json", "/.well-known/jwks.json",
    "/robots.txt", "/sitemap.xml",
]


@router.get("/api/lure-stats")
async def api_lure_stats(request: Request):
    """Lure hit statistics — which traps fired and how often."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    from sqlalchemy import select, func, or_
    from models.db import Request as Req
    db = get_database()
    since = datetime.utcnow() - timedelta(days=30)

    filters = [Req.path.like(f"{prefix}%") for prefix in _LURE_PATH_PREFIXES]
    lure_filter = or_(*filters)

    async with db.async_session() as session:
        top_paths_q = await session.execute(
            select(Req.path, func.count(Req.id).label("hits"))
            .where(Req.timestamp >= since)
            .where(lure_filter)
            .group_by(Req.path)
            .order_by(func.count(Req.id).desc())
            .limit(20)
        )
        top_lure_paths = [{"path": r[0], "hits": r[1]} for r in top_paths_q.all()]

        recent_q = await session.execute(
            select(Req.id, Req.timestamp, Req.source_ip, Req.country_code, Req.path, Req.classification)
            .where(lure_filter)
            .order_by(Req.timestamp.desc())
            .limit(20)
        )
        recent_hits = [
            {"id": r[0], "timestamp": r[1].isoformat() if r[1] else None,
             "ip": r[2], "country": r[3], "path": r[4], "classification": r[5]}
            for r in recent_q.all()
        ]

        total_q = await session.execute(
            select(func.count(Req.id)).where(lure_filter).where(Req.timestamp >= since)
        )
        trap_q = await session.execute(select(func.count(Req.id)).where(Req.trap_hit == True))  # noqa: E712
        ft_q = await session.execute(
            select(func.count(Req.id)).where(Req.path.like("/v1/fine-tuning/jobs%")).where(Req.method == "POST")
        )
        fu_q = await session.execute(
            select(func.count(Req.id)).where(Req.path == "/v1/files").where(Req.method == "POST")
        )

    return {
        "total_lure_hits_30d": total_q.scalar() or 0,
        "canary_reuse_hits": trap_q.scalar() or 0,
        "finetune_job_captures": ft_q.scalar() or 0,
        "file_upload_captures": fu_q.scalar() or 0,
        "top_lure_paths": top_lure_paths,
        "recent_hits": recent_hits,
    }


# ── On-demand analysis ────────────────────────────────────────────────────────

@router.post("/api/analyze/{request_id}")
async def analyze_request_now(request: Request, request_id: int):
    """Trigger immediate Groq AI analysis for a single request."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    from services import get_logger
    from services.analyzer import get_analyzer

    db = get_database()
    req = await db.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")

    analyzer = get_analyzer()
    if not analyzer.enabled:
        raise HTTPException(status_code=503, detail="Analyzer not configured — set GROQ_API_KEY in .env")

    try:
        req_dict = req.to_dict()
        analysis = await analyzer.analyze(req_dict)
        if not analysis:
            raise HTTPException(status_code=500, detail="Analysis returned no result")

        await db.update_analysis(
            request_id=request_id,
            threat_level=analysis.threat_level,
            threat_type=analysis.threat_type,
            ai_summary=analysis.summary,
            ai_details=analysis.details,
            ai_recommendations=analysis.recommendations,
            ai_iocs=analysis.iocs,
            ai_confidence=analysis.confidence,
            ai_actor_type=getattr(analysis, "actor_type", "unknown"),
        )
        updated = await db.get_request(request_id)
        return {
            "status": "analyzed",
            "request_id": request_id,
            "threat_level": updated.threat_level if updated else None,
            "threat_type": updated.threat_type if updated else None,
            "ai_summary": updated.ai_summary if updated else None,
            "ai_actor_type": updated.ai_actor_type if updated else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
