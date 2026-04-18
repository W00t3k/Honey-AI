"""
Configuration service - stores settings in database/JSON.

Allows runtime configuration via admin GUI instead of .env files.
"""

import os
import json
import random
import string
import uuid
from datetime import datetime, timezone
from typing import Optional, Any
from pathlib import Path
from dataclasses import dataclass, field, asdict
from copy import deepcopy
from rich.console import Console

console = Console()

CONFIG_FILE = Path("./config.json")


@dataclass
class HoneypotConfig:
    """Honeypot configuration settings."""

    # Groq AI Analysis
    groq_api_key: str = ""
    groq_enabled: bool = True
    groq_model: str = "llama-3.1-8b-instant"
    groq_chat_model: str = "llama-3.3-70b-versatile"

    # Alert Webhooks
    slack_webhook_url: str = ""
    discord_webhook_url: str = ""
    webhook_url: str = ""  # Generic webhook for SIEM
    alert_threshold: str = "medium"  # low, medium, high, critical
    alert_rate_limit: int = 60  # seconds between alerts per IP

    # Email Alerts (SMTP)
    smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""  # Comma-separated list
    smtp_tls: bool = True

    # Multi-port Configuration
    additional_ports: list = field(default_factory=list)  # e.g., [8080, 8443, 443]

    # Logging Verbosity
    log_headers: bool = True
    log_body: bool = True
    log_response: bool = True
    verbose_console: bool = True

    # Data Retention
    retention_days: int = 90  # Auto-delete logs older than X days (0 = never)
    max_db_size_mb: int = 0  # Max database size in MB (0 = unlimited)

    # Admin Settings
    admin_username: str = "admin"
    admin_password: str = ""  # bcrypt hash stored here after setup
    jwt_secret: str = ""
    setup_complete: bool = False  # True after first-run wizard is done

    # GeoIP
    geoip_enabled: bool = True
    geoip_db_path: str = "./GeoLite2-City.mmdb"
    maxmind_license_key: str = ""

    # Canary Tokens — list of {"id": str, "label": str, "token": str, "added_at": str, "note": str}
    canary_tokens: list = field(default_factory=list)

    # Response Customization
    fake_org_name: str = "org-honeypot"
    fake_company_name: str = "Company Corp"
    fake_company_domain: str = "company.internal"
    response_delay_min_ms: int = 80
    response_delay_max_ms: int = 300

    # Ollama local LLM backend
    ollama_enabled: bool = False
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:1.5b"

    # Custom OpenAI-compatible backend
    custom_llm_enabled: bool = False
    custom_llm_base_url: str = ""
    custom_llm_api_key: str = ""
    custom_llm_model: str = ""

    # SSH honeypot
    ssh_honeypot_enabled: bool = False
    ssh_listen_host: str = "0.0.0.0"
    ssh_listen_port: int = 2222
    ssh_host_key_path: str = "./ssh_host_key"

    def to_dict(self) -> dict:
        """Convert to dictionary, hiding sensitive fields."""
        d = asdict(self)
        # Mask sensitive fields for display
        if d.get("groq_api_key"):
            d["groq_api_key_masked"] = f"{d['groq_api_key'][:8]}...{d['groq_api_key'][-4:]}" if len(d["groq_api_key"]) > 12 else "***"
        if d.get("slack_webhook_url"):
            d["slack_webhook_masked"] = "Configured ✓"
        if d.get("discord_webhook_url"):
            d["discord_webhook_masked"] = "Configured ✓"
        return d

    def to_safe_dict(self) -> dict:
        """Convert to dictionary without sensitive values."""
        d = asdict(self)
        sensitive_keys = ["groq_api_key", "slack_webhook_url", "discord_webhook_url",
                         "webhook_url", "smtp_password", "admin_password", "jwt_secret", "maxmind_license_key"]
        for key in sensitive_keys:
            if d.get(key):
                d[key] = "••••••••" if d[key] else ""
        return d


class ConfigService:
    """Manages honeypot configuration."""

    def __init__(self):
        self.config = HoneypotConfig()
        self._load()

    def _load(self):
        """Load configuration from file, falling back to env vars."""
        # First load from env vars (backwards compatibility)
        self.config.groq_api_key = os.getenv("GROQ_API_KEY", "")
        self.config.slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        self.config.discord_webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "")
        self.config.webhook_url = os.getenv("WEBHOOK_URL", "")
        self.config.admin_username = os.getenv("ADMIN_USERNAME", "admin")
        self.config.admin_password = os.getenv("ADMIN_PASSWORD", "")
        self.config.jwt_secret = os.getenv("JWT_SECRET", "")
        self.config.geoip_db_path = os.getenv("GEOIP_DB_PATH", "./GeoLite2-City.mmdb")
        self.config.maxmind_license_key = os.getenv("MAXMIND_LICENSE_KEY", "")
        self.config.ssh_honeypot_enabled = os.getenv("SSH_HONEYPOT_ENABLED", "").lower() in {"1", "true", "yes", "on"}
        self.config.ssh_listen_host = os.getenv("SSH_LISTEN_HOST", "0.0.0.0")
        self.config.ssh_listen_port = _coerce_int(os.getenv("SSH_LISTEN_PORT", 2222), 2222, minimum=1, maximum=65535)
        self.config.ssh_host_key_path = os.getenv("SSH_HOST_KEY_PATH", "./ssh_host_key")

        # Parse additional ports from env
        ports_env = os.getenv("ADDITIONAL_PORTS", "")
        if ports_env:
            try:
                self.config.additional_ports = [int(p.strip()) for p in ports_env.split(",") if p.strip()]
            except ValueError:
                pass

        # Then override with config file if exists
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                    for key, value in data.items():
                        if hasattr(self.config, key):
                            setattr(self.config, key, value)
                console.print(f"[green]Loaded config from {CONFIG_FILE}[/green]")
            except Exception as e:
                console.print(f"[yellow]Config load warning: {e}[/yellow]")

        # Backwards-compat: if ADMIN_PASSWORD env var is a non-default value, treat setup as done
        env_pw = os.getenv("ADMIN_PASSWORD", "")
        if env_pw and env_pw not in ("changeme", "admin", "") and not self.config.setup_complete:
            self.config.setup_complete = True

        self._normalize_config()

        # Auto-seed canary tokens if none exist
        self._auto_seed_canary_tokens()

    def save(self):
        """Save configuration to file."""
        try:
            self._normalize_config()
            with open(CONFIG_FILE, "w") as f:
                json.dump(asdict(self.config), f, indent=2)
            console.print(f"[green]Config saved to {CONFIG_FILE}[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Config save failed: {e}[/red]")
            return False

    def _auto_seed_canary_tokens(self):
        """Generate a persistent pool of canary tokens on first run."""
        if self.config.canary_tokens:
            return
        labels = [
            ("Production API Key", "sk-proj-"),
            ("GitHub Actions CI", "sk-proj-"),
            ("Backend Service", "sk-"),
            ("Data Pipeline", "sk-proj-"),
            ("Internal Tooling", "sk-"),
            ("Analytics Service", "sk-proj-"),
            ("Mobile App Backend", "sk-"),
            ("Staging Environment", "sk-proj-"),
        ]
        chars = string.ascii_letters + string.digits
        tokens = []
        for label, prefix in labels:
            key = "".join(random.choices(chars, k=48))
            tokens.append({
                "id": uuid.uuid4().hex[:8],
                "label": label,
                "token": f"{prefix}{key}",
                "note": "auto-generated",
                "added_at": datetime.now(timezone.utc).isoformat(),
            })
        self.config.canary_tokens = tokens
        self.save()
        console.print(f"[cyan]Auto-seeded {len(tokens)} canary tokens[/cyan]")

    def is_setup_done(self) -> bool:
        """Return True if first-run setup has been completed."""
        return self.config.setup_complete

    def complete_setup(self, username: str, password_hash: str) -> bool:
        """Save admin credentials and mark setup as complete."""
        self.config.admin_username = username
        self.config.admin_password = password_hash
        self.config.setup_complete = True
        return self.save()

    def update(self, **kwargs) -> bool:
        """Update configuration values."""
        masked_secret_values = {"••••••••", "***"}
        protected_secret_keys = {
            "groq_api_key",
            "slack_webhook_url",
            "discord_webhook_url",
            "webhook_url",
            "smtp_password",
            "admin_password",
            "jwt_secret",
            "maxmind_license_key",
        }
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                # Blank secret fields from the UI mean "leave the current value unchanged".
                if value == "" and key in protected_secret_keys:
                    continue
                if key in protected_secret_keys and value in masked_secret_values:
                    continue
                setattr(self.config, key, value)
        self._normalize_config()
        return self.save()

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return getattr(self.config, key, default)

    def get_all(self) -> dict:
        """Get all configuration as dict."""
        return asdict(self.config)

    def get_safe(self) -> dict:
        """Get configuration without sensitive values."""
        return self.config.to_safe_dict()

    def _normalize_config(self):
        """Normalize settings loaded from env/UI to a sane internal shape."""
        cfg = self.config

        if not cfg.jwt_secret:
            cfg.jwt_secret = os.getenv("JWT_SECRET", "") or secrets_token(64)

        cfg.alert_threshold = (cfg.alert_threshold or "medium").lower()
        if cfg.alert_threshold not in {"all", "low", "medium", "high", "critical"}:
            cfg.alert_threshold = "medium"

        cfg.smtp_port = _coerce_int(cfg.smtp_port, 587, minimum=1, maximum=65535)
        cfg.alert_rate_limit = _coerce_int(cfg.alert_rate_limit, 60, minimum=0, maximum=86400)
        cfg.retention_days = _coerce_int(cfg.retention_days, 90, minimum=0, maximum=3650)
        cfg.max_db_size_mb = _coerce_int(cfg.max_db_size_mb, 0, minimum=0, maximum=1024 * 1024)
        cfg.response_delay_min_ms = _coerce_int(cfg.response_delay_min_ms, 80, minimum=0, maximum=15000)
        cfg.response_delay_max_ms = _coerce_int(cfg.response_delay_max_ms, 300, minimum=0, maximum=15000)
        cfg.ssh_listen_port = _coerce_int(cfg.ssh_listen_port, 2222, minimum=1, maximum=65535)
        if cfg.response_delay_max_ms < cfg.response_delay_min_ms:
            cfg.response_delay_max_ms = cfg.response_delay_min_ms

        cfg.additional_ports = sorted({
            port for port in (_parse_port(p) for p in (cfg.additional_ports or []))
            if port is not None
        })
        if cfg.ssh_honeypot_enabled:
            cfg.additional_ports = [
                port for port in cfg.additional_ports
                if port != cfg.ssh_listen_port
            ]

        cfg.canary_tokens = _normalize_canary_tokens(cfg.canary_tokens)

        cfg.fake_org_name = (cfg.fake_org_name or "org-honeypot").strip()
        cfg.fake_company_name = (cfg.fake_company_name or "Company Corp").strip()
        cfg.fake_company_domain = (cfg.fake_company_domain or "company.internal").strip().lower()

        # Migrate legacy plaintext admin passwords into bcrypt on write.
        if cfg.setup_complete and cfg.admin_password and not _looks_hashed(cfg.admin_password):
            try:
                from passlib.context import CryptContext
                pwd_context = CryptContext(schemes=["pbkdf2_sha256", "bcrypt"], deprecated="auto")
                cfg.admin_password = pwd_context.hash(cfg.admin_password)
                console.print("[yellow]Migrated plaintext admin password to a password hash[/yellow]")
            except Exception as e:
                console.print(f"[yellow]Admin password migration warning: {e}[/yellow]")

        # Prevent accidental mutation by callers that retain references.
        cfg.canary_tokens = deepcopy(cfg.canary_tokens)


# Singleton
_config_service: Optional[ConfigService] = None


def get_config() -> ConfigService:
    global _config_service
    if _config_service is None:
        _config_service = ConfigService()
    return _config_service


def _coerce_int(value: Any, default: Optional[int], minimum: Optional[int] = None, maximum: Optional[int] = None) -> Optional[int]:
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and coerced < minimum:
        return minimum
    if maximum is not None and coerced > maximum:
        return maximum
    return coerced


def _looks_hashed(value: str) -> bool:
    return (
        value.startswith("$2a$")
        or value.startswith("$2b$")
        or value.startswith("$pbkdf2-sha256$")
    )


def secrets_token(length: int = 64) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def _normalize_canary_tokens(tokens: Any) -> list[dict]:
    """Accept both legacy string arrays and structured token objects."""
    if not isinstance(tokens, list):
        return []

    normalized: list[dict] = []
    seen: set[str] = set()

    for item in tokens:
        if isinstance(item, str):
            token_value = item.strip()
            token = {
                "id": uuid.uuid4().hex[:8],
                "label": "Imported Canary",
                "token": token_value,
                "note": "migrated from legacy format",
                "added_at": datetime.now(timezone.utc).isoformat(),
            }
        elif isinstance(item, dict):
            token_value = str(item.get("token", "")).strip()
            token = {
                "id": str(item.get("id") or uuid.uuid4().hex[:8])[:8],
                "label": str(item.get("label") or "Canary Token").strip(),
                "token": token_value,
                "note": str(item.get("note") or "").strip(),
                "added_at": str(item.get("added_at") or datetime.now(timezone.utc).isoformat()),
            }
        else:
            continue

        if not token_value or token_value in seen:
            continue
        seen.add(token_value)
        normalized.append(token)

    return normalized


def _parse_port(value: Any) -> Optional[int]:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None
