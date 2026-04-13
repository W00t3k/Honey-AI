"""
Helpers for consistent honeypot timing, headers, and fake company profile.
"""

import asyncio
import random

from services.config import get_config


async def add_realistic_delay() -> None:
    """Delay responses using the configured jitter window."""
    config = get_config()
    min_ms = config.get("response_delay_min_ms", 80)
    max_ms = config.get("response_delay_max_ms", 300)
    delay_ms = random.uniform(min_ms, max_ms if max_ms >= min_ms else min_ms)
    await asyncio.sleep(delay_ms / 1000.0)


def build_openai_headers(model: str | None = None, include_org: bool = True) -> dict:
    """Build OpenAI-like headers from the active deception profile."""
    config = get_config()
    headers = {
        "openai-version": "2020-10-01",
        "x-request-id": f"req_{random.randbytes(16).hex()}",
        "openai-processing-ms": str(random.randint(55, 420)),
    }
    if model:
        headers["openai-model"] = model
    if include_org:
        headers["openai-organization"] = config.get("fake_org_name", "org-honeypot")
        headers["x-ratelimit-limit-requests"] = "10000"
        headers["x-ratelimit-limit-tokens"] = "2000000"
        headers["x-ratelimit-remaining-requests"] = str(random.randint(9000, 9999))
        headers["x-ratelimit-remaining-tokens"] = str(random.randint(1900000, 1999999))
        headers["x-ratelimit-reset-requests"] = "1ms"
        headers["x-ratelimit-reset-tokens"] = "1ms"
    return headers


def get_company_profile() -> dict[str, str]:
    """Return the fake organization metadata used across deception surfaces."""
    config = get_config()
    company_name = config.get("fake_company_name", "Company Corp")
    company_domain = config.get("fake_company_domain", "company.internal")
    company_slug = company_name.lower().replace(" ", "-")
    return {
        "company_name": company_name,
        "company_domain": company_domain,
        "company_slug": company_slug,
        "fake_org_name": config.get("fake_org_name", "org-honeypot"),
    }
