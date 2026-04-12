# AI Honeypot — Project Context

## What this is
A multi-protocol AI API honeypot. Mimics OpenAI, Anthropic, and MCP servers to capture
attackers testing stolen keys, injecting prompts, and probing agentic/MCP infrastructure.

## Stack
- Python 3.12, FastAPI, SQLite (aiosqlite), Jinja2 admin UI
- Runs from `honeypot/` directory with `python main.py`
- Always activate venv first: `source venv/bin/activate`
- Working directory for running: `honeypot/`

## Key files
- `main.py` — app entry, registers all routers
- `routers/` — one file per API surface (chat, models, embeddings, billing, anthropic, mcp, agentic, admin)
- `services/classifier.py` — rule-based request classifier (no ML, pure regex/heuristics)
- `services/analyzer.py` — async Groq LLM analysis of each request (background task)
- `services/logger.py` — central request logger, canary key reuse detection
- `services/responder.py` — fake response generator for all endpoints
- `models/db.py` — SQLAlchemy models + migration system (SCHEMA_MIGRATIONS dict)
- `templates/admin/dashboard.html` — admin UI

## DB schema migrations
Add new columns via `SCHEMA_MIGRATIONS` dict in `models/db.py`, increment `SCHEMA_VERSION`.
Migration runs automatically on startup via `ALTER TABLE ... ADD COLUMN`. Never drop columns — SQLite.

## Protocols covered
- OpenAI API: `/v1/*` → `protocol = openai_api`
- Anthropic API: `/v1/messages`, `/v1/messages/batches` → `protocol = anthropic_api`
- MCP: `/mcp`, `/.well-known/mcp.json` → `protocol = mcp`
- Web/other: everything else → `protocol = web`

## Canary tracking
`services/logger._check_canary_reuse()` — checks every incoming key against
`responder.issued_canary_keys` and operator tokens in config. On match: DB flagged,
console banner, webhook alert.

## Classification labels
scanner | credential_stuffer | prompt_harvester | data_exfil | recon | researcher | human | unknown

## Admin UI
Path set by `ADMIN_PATH` env var (default `/admin`, change before deploying publicly).
Stats API at `{ADMIN_PATH}/api/stats` returns `protocol_breakdown` and `agentic_requests`.
