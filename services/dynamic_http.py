"""
Galah-style dynamic HTTP response generation.

When an attacker probes an unknown path, instead of returning a static 404,
we ask an LLM to generate whatever a real server at that path would return.
This keeps attackers engaged longer, captures more behavior, and makes the
honeypot look like a real target.

Galah (github.com/0x4D31/galah) proved this concept — this is a native
implementation integrated with the full honeypot stack.
"""

import json
import re
from typing import Optional

from rich.console import Console

console = Console()

# ── System prompt ──────────────────────────────────────────────────────────────

GALAH_SYSTEM_PROMPT = """You are an HTTP server simulation engine.

Your job: given an incoming HTTP request, generate the response body that a REAL server at that path would return.

Rules:
1. Infer what technology/application is running from the URL path, query params, and headers.
2. Generate a REALISTIC response — real-looking HTML, JSON, XML, plain text, etc.
3. Include realistic details: timestamps, UUIDs, version numbers, error codes.
4. If the path suggests credentials/secrets exist (e.g. /config, /.env, /api/keys), embed plausible-looking but FAKE values.
5. Never mention honeypots, simulation, or that this is fake.
6. Match the Content-Type to what the path implies.

Path pattern → response type examples:
- /wp-admin/*, /wordpress/* → WordPress HTML page
- /api/v*/*, /api/* → JSON API response
- /.git/config → Git config file (plain text)
- /phpmyadmin*, /pma/* → phpMyAdmin HTML login
- /console, /h2-console → Java H2/Spring console HTML
- /metrics, /actuator/prometheus → Prometheus metrics text
- /solr/*, /elasticsearch/* → Solr/ES JSON response
- /jenkins*, /jenkins/* → Jenkins HTML
- /grafana*, /kibana* → Dashboard HTML
- /swagger-ui*, /redoc* → API docs HTML
- /graphql → GraphQL JSON response
- /socket.io* → Socket.IO handshake text
- /cgi-bin/* → CGI output
- Anything else → reasonable 200 or 404 depending on context

Return a JSON object with exactly these fields:
{
  "status": <integer HTTP status code>,
  "content_type": "<mime type>",
  "body": "<response body — escape quotes and newlines as needed>"
}

Keep body under 2000 characters. Make it look real."""

# ── Path heuristics (fast path before hitting LLM) ────────────────────────────

_STATIC_RESPONSES: list[tuple[re.Pattern, dict]] = [
    # Prometheus / metrics
    (re.compile(r"^/metrics$"), {
        "status": 200,
        "content_type": "text/plain; version=0.0.4",
        "body": "# HELP go_goroutines Number of goroutines\n# TYPE go_goroutines gauge\ngo_goroutines 42\n# HELP process_cpu_seconds_total Total user and system CPU\n# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 12.34\n",
    }),
    # Socket.IO
    (re.compile(r"^/socket\.io"), {
        "status": 200,
        "content_type": "text/plain",
        "body": "0{\"sid\":\"FAKESID123456789\",\"upgrades\":[\"websocket\"],\"pingInterval\":25000,\"pingTimeout\":20000}",
    }),
    # Jenkins favicon / static assets
    (re.compile(r"^/jenkins/static"), {
        "status": 200,
        "content_type": "application/javascript",
        "body": "/* Jenkins static resource */",
    }),
]


def _fast_path(path: str) -> Optional[dict]:
    """Return a static response if the path matches a known pattern (avoids LLM call)."""
    for pattern, response in _STATIC_RESPONSES:
        if pattern.match(path):
            return response
    return None


# ── LLM generation ────────────────────────────────────────────────────────────

async def generate_http_response(
    method: str,
    path: str,
    query_string: str,
    host: str,
    user_agent: str,
    content_type: str,
    body_preview: str,
) -> dict:
    """
    Ask the LLM to generate a realistic HTTP response for the given request.

    Returns a dict with: status, content_type, body
    Falls back to a static 404 if LLM is unavailable or fails.
    """
    # Fast path first
    fast = _fast_path(path)
    if fast:
        return fast

    from services.llm_backend import get_http_backend
    backend = get_http_backend()

    user_msg = f"""HTTP Request:
Method: {method}
Path: {path}{('?' + query_string) if query_string else ''}
Host: {host or 'target.internal'}
User-Agent: {user_agent[:80] if user_agent else 'unknown'}
Content-Type: {content_type or 'none'}
Body preview: {body_preview[:200] if body_preview else '(empty)'}

Generate a realistic HTTP response body for this request."""

    try:
        raw = await backend.complete(
            [{"role": "user", "content": user_msg}],
            system_prompt=GALAH_SYSTEM_PROMPT,
            temperature=0.4,
            max_tokens=600,
        )
        if raw:
            # Parse JSON response from LLM
            parsed = _parse_llm_response(raw)
            if parsed:
                return parsed
    except Exception as e:
        console.print(f"[yellow]Dynamic HTTP generation failed: {e}[/yellow]")

    # Fallback
    return {
        "status": 404,
        "content_type": "text/html",
        "body": "<html><body><h1>404 Not Found</h1></body></html>",
    }


def _parse_llm_response(raw: str) -> Optional[dict]:
    """Extract the JSON response object from LLM output."""
    # Try direct JSON parse
    raw = raw.strip()
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "status" in data and "body" in data:
            return {
                "status": int(data.get("status", 200)),
                "content_type": str(data.get("content_type", "text/html")),
                "body": str(data.get("body", "")),
            }
    except (json.JSONDecodeError, ValueError):
        pass

    # Try to extract JSON block from markdown
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if not match:
        match = re.search(r"(\{[^{}]*\"status\"[^{}]*\})", raw, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(1))
            return {
                "status": int(data.get("status", 200)),
                "content_type": str(data.get("content_type", "text/html")),
                "body": str(data.get("body", "")),
            }
        except (json.JSONDecodeError, ValueError):
            pass

    # Couldn't parse — treat entire output as HTML body
    if len(raw) > 20:
        return {"status": 200, "content_type": "text/html", "body": raw}
    return None
