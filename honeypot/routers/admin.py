"""
Admin dashboard router.

Password-protected admin interface for viewing honeypot data.
"""

import csv
import io
import json
import os
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

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("JWT_SECRET", "change-this-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Credentials from env
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")


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
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Optional[str]:
    """Verify JWT token and return username."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except JWTError:
        return None


async def get_current_user(request: Request) -> Optional[str]:
    """Get current authenticated user from cookie."""
    token = request.cookies.get("access_token")
    if not token:
        return None
    return verify_token(token)


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


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render login page."""
    return templates.TemplateResponse(
        "admin/login.html",
        {"request": request, "error": None, "admin_path": ADMIN_PATH},
    )


@router.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Handle login form submission."""
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        access_token = create_access_token(data={"sub": username})
        response = RedirectResponse(url=ADMIN_PATH, status_code=303)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            max_age=ACCESS_TOKEN_EXPIRE_HOURS * 3600,
            samesite="lax",
        )
        return response

    return templates.TemplateResponse(
        "admin/login.html",
        {"request": request, "error": "Invalid credentials", "admin_path": ADMIN_PATH},
    )


@router.get("/logout")
async def logout():
    """Handle logout."""
    response = RedirectResponse(url=f"{ADMIN_PATH}/login", status_code=303)
    response.delete_cookie(key="access_token")
    return response


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


@router.get("/api/requests")
async def api_requests(request: Request, limit: int = 100, offset: int = 0):
    """API endpoint for recent requests."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    requests = await db.get_recent_requests(limit=limit)
    return [r.to_dict() for r in requests]


@router.get("/api/map")
async def api_map_data(request: Request):
    """API endpoint for map data."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401)

    db = get_database()
    return await db.get_map_data()


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
            "config": config.get_all(),
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

        # Update configuration
        config.update(**data)

        # Reinitialize services that depend on config
        if data.get("groq_api_key"):
            from services.analyzer import get_analyzer
            analyzer = get_analyzer()
            analyzer.api_key = data["groq_api_key"]
            analyzer.model = data.get("groq_model", "llama-3.1-8b-instant")
            analyzer.enabled = bool(data["groq_api_key"]) and data.get("groq_enabled", True)

        return {"status": "ok", "message": "Settings saved"}
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
