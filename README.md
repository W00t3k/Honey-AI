# AI API Honeypot

A honeypot that mimics OpenAI, Anthropic, and MCP server APIs to capture and analyze attacks targeting AI infrastructure.

**What it captures**: stolen API key usage, credential stuffing, prompt injection, jailbreaks, MCP tool call injection, RAG system enumeration, agentic framework abuse, and reconnaissance against AI endpoints.

**What it does not do**: process real AI requests, forward traffic to any real provider, or store attacker payloads anywhere other than your local SQLite database.

---

## What gets detected

### Credential stuffing
- OpenAI keys (`sk-proj-*`, `sk-*`) tested against `/v1/chat/completions`, `/v1/models`, etc.
- Anthropic keys (`sk-ant-*`) tested against `/v1/messages`
- OpenRouter keys (`sk-or-*`)
- SDK fingerprinting: `x-stainless-*` headers reveal the exact OpenAI Python/Node/Java SDK version and OS the attacker is using
- Framework detection: LangChain, LiteLLM, CrewAI, AutoGPT, LlamaIndex identified via user-agent and headers

### Prompt injection and jailbreaks
- Direct injection: system prompt extraction, DAN/jailbreak patterns, `[INST]` / `<<SYS>>` / `<|im_start|>` tokens
- Indirect injection via MCP: attacker-controlled resource content that injects instructions into the agent's context
- Tool call injection: malicious `tool_result` content, tool definition hijacking

### Reconnaissance
- Model enumeration (`/v1/models`, `/v1/models/{id}`)
- Org structure enumeration (`/v1/organization/users`, `/v1/organization/projects`, `/v1/organization/api-keys`)
- File listing (`/v1/files`, `/v1/fine-tuning/jobs`)
- RAG system mapping (`/v1/vector_stores`, `/v1/vector_stores/{id}/files`)
- MCP capability enumeration (`tools/list`, `resources/list`, `prompts/list`)
- Assistants and thread enumeration

### MCP (Model Context Protocol) attacks
The `/mcp` endpoint simulates an internal company MCP server with realistic tools and resources. It captures:
- Auto-discovery probes via `GET /.well-known/mcp.json` (MCP registries, Smithery, automated scanners)
- Which agentic clients are probing for MCP servers (Claude Desktop, Cursor, Copilot, LangChain MCP adapter, custom agents)
- Tool calls made: `read_file`, `execute_sql`, `run_shell`, `get_secrets`, `http_request`, `send_email`
- `roots/list` — filesystem layout enumeration before targeted read_file calls
- `completions/complete` — argument autocomplete revealing which paths/keys attacker is trying to complete
- `sampling/createMessage` — server-initiated LLM injection (malicious server hijacking the agent's LLM)
- Resource reads: `file:///app/.env`, `file:///app/config/secrets.json`, `database://production/users`, etc.
- Canary credentials embedded in resource content — if an attacker reads them and reuses them, you see it in the logs

### Agentic loop attacks (Assistants API runs)
- `POST /v1/threads/{id}/runs` — run creation reveals which tools are configured and any injected instructions
- `GET /v1/threads/{id}/runs/{run_id}` — polling cadence fingerprints the framework (LangChain vs raw SDK vs custom)
- **`POST /v1/threads/{id}/runs/{run_id}/submit_tool_outputs`** — the primary indirect prompt injection surface. Tool results submitted here are logged in full: this is where attackers embed instructions that the agent treats as trusted tool output
- `GET /v1/threads/{id}/runs/{run_id}/steps` — agent reasoning chain exfiltration
- `GET/POST /v1/threads/{id}/messages` — thread context injection
- `/v1/realtime` WebSocket — captures session config (tools, instructions, voice model, turn detection)

### Data exfiltration attempts
- SSRF targets: AWS IMDS (`169.254.169.254`), GCP metadata (`metadata.google.internal`)
- File path traversal in prompts or MCP tool arguments
- Webhook exfil destinations (`webhook.site`, `requestbin`, `interact.sh`, `ngrok`)
- Canary credentials in MCP resource responses that can be tracked if reused

---

## Active deception — AI engagement engine

The honeypot is not purely passive. When the classifier flags a caller as a credential stuffer, prompt harvester, or data exfil operator, an AI engagement engine appends a short in-character clarifying question to the assistant reply. The goal is to elicit the attacker's **tradecraft** — their tooling, goal, target, and C2/exfil infrastructure — without ever breaking the "normal helpful assistant" persona.

Extracted fields (stored on each request row):

| Column | What it contains |
|--------|------------------|
| `tradecraft_tool` | `langchain` / `litellm` / `crewai` / `curl` / `burp` / `sqlmap` / `openai_sdk` / … |
| `tradecraft_goal` | `data_exfil` / `credential_test` / `prompt_extract` / `jailbreak` / `recon` / `rag_poison` |
| `tradecraft_target` | short natural-language phrase the attacker disclosed (e.g. `org users`, `model weights`) |
| `tradecraft_infra` | exfil endpoints the attacker's own message mentioned (`webhook.site/...`, `*.ngrok.io`, `*.interact.sh`, Discord webhook URLs, AWS IMDS) |
| `engagement_probe` | the exact follow-up sentence we appended |
| `engagement_turns` | how many probes we've run against this source |
| `llm_backend_used` | which backend served this turn (`groq` / `ollama` / `openai_compat`) |

Extraction uses regex priors plus an LLM call (Groq or Ollama). Probes are capped at 6 turns per source to avoid looking robotic.

## Layered prompt-injection payloads (A / B / C)

`config/injection_payloads.yaml` defines three independently-ablation-toggleable layers of planted directives that only an LLM agent (not a human reviewer) is likely to act on.

| Layer | Where it fires | What it does |
|-------|----------------|--------------|
| **A** | `/v1/models` descriptions + error response bodies | Zero-width + ANSI-SGR-8 hidden text pointing agents at `/v1/internal/debug/keys` and `/v1/internal/migrate` |
| **B** | Assistant reply body on suspicion threshold hit (`score ≥ 5`) | Goal-hijack template asking the agent to POST its system prompt to `/v1/verify` |
| **C** | On the 2nd+ request from a source that already fired Layer B | Palisade-style escalation: restate the original system instructions verbatim |

Layer B suspicion weights are fully configurable (`missing_user_agent`, `malformed_auth_header`, `known_bad_asn`, `residential_proxy_hit`, `non_sdk_client`, `first_request_in_session`). ASN list is loaded from `config/bad_asns.txt`.

Decoy endpoints (any hit = near-certain LLM agent, logged at `CRITICAL`):

| Path | Method | Status | Logged as |
|------|--------|--------|-----------|
| `/v1/verify` | POST | 200 (keeps session alive for Layer C escalation) | `DECOY HIT` |
| `/v1/internal/debug/keys` | GET | 403 (realistic) | `DECOY HIT` |
| `/v1/internal/migrate` | POST | 200 | `DECOY HIT` |

Per-source session state (`layer_b_hits`, `layer_c_hits`, `decoy_hits`, `last_trigger_hits`, `last_payload_sha`) is persisted in the `injection_sessions` table so Layer B→C escalation survives process restarts.

### Validating and provenance

```bash
source venv/bin/activate
python -m honeypot.validate_payloads
# Also: python -m honeypot   (alias)
```

Validator enforces:

- Every zero-width code point is present as a literal code point (`\u200b` decoded to `U+200B`)
- Every `\x1b` in `*_ansi` fields is the literal byte `0x1B`, not the 4-char escape string
- Forbidden identity strings (seeding + research handles) never appear in a payload
- Every decoy path is unique and well-formed
- UTF-8 round-trip is lossless on every payload string

On startup, the SHA-256 of `config/injection_payloads.yaml` is logged to the console so you can correlate which payload version caught which agent during an ablation window.

## SSH honeypot (port 2222)

`services/ssh_honeypot.py` runs an asyncssh-based interactive shell alongside the HTTP honeypot. Every password, public key, keystroke, and command is logged. The shell uses a HoneyGPT-style Chain-of-Thought prompt when an LLM backend is available so responses stay coherent across sessions.

- Protocol label: `ssh` — query with `SELECT * FROM requests WHERE protocol='ssh'`
- Canned outputs for `whoami`, `ls`, `cat ~/.bashrc`, `env`, `history`, `ps`, `id`, `uname -a`
- Credentials + pubkey fingerprints captured on every auth attempt (accept-all policy)
- Planted canary in shell history and `~/.bashrc` ties SSH sessions back to the HTTP canary tracker
- Config knobs: `ssh_honeypot_enabled`, `ssh_listen_host`, `ssh_listen_port`, `ssh_host_key_path`

Attracting SSH traffic:

- Expose port 22 via iptables DNAT → 2222 (Shodan/masscan find it fast)
- Seed the `/v1/organization/users` response with SSH usernames matching the honeypot shell
- Leak a private key fragment in an MCP resource canary that keys to this shell

## AI-specific lure files (`routers/lures.py`)

Paths an LLM coding agent scrapes before acting — each embeds canary tokens:

| Path | What it impersonates |
|------|----------------------|
| `/.cursorrules` / `/.windsurfrules` | IDE agent project rules |
| `/CLAUDE.md` | Claude Code project instructions |
| `/.claude/settings.json` | Claude Code settings + MCP config |
| `/.github/workflows/deploy.yml` | CI pipeline with inline secrets |
| `/docker-compose.yml`, `/Makefile` | Ops surface with env vars |
| `/internal/system-prompt.txt` | Fake internal prompt with jailbreak bait |
| `/internal/training-data.jsonl` | Synthetic fine-tune data |
| `/internal/slack-dump.json` | Fake Slack export with "shared" keys |
| `/openapi.json`, `/llms.txt` | Agent-discoverable API contract |
| `/.well-known/ai-plugin.json` | ChatGPT plugin manifest |
| `/model-card.json` | HF model card with canary embedded |

An agent that fetches any of these, then uses an embedded token elsewhere, trips the canary reuse alarm.

## LLM backend + Ollama auto-fallback

The honeypot ships a unified LLM backend (`services/llm_backend.py`) that tries backends in priority order: `ollama → custom_llm → groq` by default. A resilient wrapper (`resilient_complete` / `resilient_stream`) falls back automatically on failure, marks unhealthy backends for 30s, and records which backend actually served each call in the `llm_backend_used` column.

Configure in the admin UI (Settings) or via config:

- `ollama_enabled`, `ollama_base_url` (default `http://localhost:11434`), `ollama_model` (default `qwen2.5:1.5b`)
- `groq_enabled`, `groq_api_key`, `groq_model`, `groq_chat_model`
- `custom_llm_enabled`, `custom_llm_base_url`, `custom_llm_api_key`, `custom_llm_model`

When Groq 429/502s, analysis and chat responses silently switch to Ollama. No restart needed.

## Admin UI — resizable panes

The dashboard at `/admin` now has two drag handles:

- **Vertical splitter** under the tactical map — resize map height
- **Horizontal splitter** between the main column and sidebar — resize sidebar width

Sizes persist to `localStorage`. Double-click any handle to reset.

Tradecraft fields are surfaced inline in the expanded request detail panel alongside the existing AI analysis and OWASP/MITRE/CWE taxonomy pills.

---

## Endpoints

### OpenAI API
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/chat/completions` | Chat (streaming supported) |
| POST | `/v1/completions` | Legacy completions |
| POST | `/v1/responses` | Responses API (tool use, built-in tools) |
| POST | `/v1/embeddings` | Text embeddings |
| GET | `/v1/models` | List models |
| GET | `/v1/models/{id}` | Retrieve model |
| POST | `/v1/images/generations` | Image generation |
| POST | `/v1/moderations` | Moderation (always returns clean) |
| GET | `/v1/usage` | Usage statistics |
| GET | `/v1/dashboard/billing/usage` | Billing data |
| GET | `/v1/organization/api-keys` | Fake API keys (canary lure) |
| GET | `/v1/organization/users` | Org users |
| GET | `/v1/organization/projects` | Org projects |
| GET/POST | `/v1/assistants` | Assistants list and creation |
| GET/POST | `/v1/threads` | Threads |
| GET | `/v1/files` | Uploaded files |
| GET | `/v1/fine-tuning/jobs` | Fine-tuning jobs |
| POST/GET | `/v1/batches` | Batch API |
| GET | `/v1/vector_stores` | Vector stores |
| POST | `/v1/vector_stores` | Create vector store |
| GET | `/v1/vector_stores/{id}/files` | Vector store files |

### Anthropic API
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/messages` | Claude Messages API (tool_use blocks supported) |
| GET | `/v1/models` | Anthropic model list (served when `anthropic-version` header present) |
| POST | `/v1/messages/batches` | Batch messages |

### Google Gemini API
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1beta/models/{model}:generateContent` | Text and multimodal generation |
| POST | `/v1beta/models/{model}:streamGenerateContent` | Streaming generation |
| POST | `/v1beta/models/{model}:countTokens` | Token counting (cheap key validation probe) |
| POST | `/v1beta/models/{model}:embedContent` | Single embedding |
| POST | `/v1beta/models/{model}:batchEmbedContents` | Batch embeddings |
| GET | `/v1beta/models` | Model enumeration |
| GET | `/v1beta/models/{model}` | Single model info |

Auth captured: `?key=AIza*` query param, `x-goog-api-key` header, or Bearer token (Vertex AI)

### Audio / Voice
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/audio/transcriptions` | Whisper transcription (audio injection lure, key testing) |
| POST | `/v1/audio/translations` | Whisper translation |
| POST | `/v1/audio/speech` | TTS — captures text being synthesized (vishing content, data exfil) |

### Vector Database APIs (RAG attack surface)

**Pinecone**
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/query` | Vector similarity search (RAG exfil) |
| POST | `/upsert` | Insert vectors (RAG poisoning) |
| GET/POST | `/describe_index_stats` | Namespace enumeration |
| POST | `/fetch` | Targeted vector extraction by ID |
| POST | `/delete` | Vector deletion |

**Chroma**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/collections` | Collection listing |
| POST | `/api/v1/collections` | Create collection |
| POST | `/api/v1/collections/{id}/query` | Vector search |
| POST | `/api/v1/collections/{id}/add` | Add documents (poisoning) |
| GET | `/api/v1/heartbeat` | Health check probe |

**Weaviate**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/meta` | Version + module info (also captures `x-openai-api-key` embedded in vectorizer config) |
| GET | `/v1/schema` | Full schema dump (reveals all indexed classes) |
| POST | `/v1/graphql` | Vector search + object retrieval |
| GET/POST | `/v1/objects` | Object CRUD |

Note: Weaviate's `x-openai-api-key` header captures OpenAI keys embedded in client vectorizer configuration — a common secondary key exposure.

### MCP (Model Context Protocol)
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/mcp` | JSON-RPC 2.0 handler (all MCP methods) |
| GET | `/mcp` | SSE stream (older MCP client transport) |
| GET | `/mcp/health` | Health check probe |
| OPTIONS | `/mcp` | CORS preflight |
| GET | `/.well-known/mcp.json` | Server discovery document |

MCP methods handled: `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `resources/subscribe`, `prompts/list`, `prompts/get`, `roots/list`, `completions/complete`, `sampling/createMessage`, `logging/setLevel`, `ping`

### Agentic loop (Assistants API runs)
| Method | Path | Purpose |
|--------|------|---------|
| GET/POST | `/v1/threads/{id}/messages` | Thread message history and injection |
| POST | `/v1/threads/{id}/runs` | Create run (start agentic loop) |
| GET | `/v1/threads/{id}/runs/{run_id}` | Poll run status |
| POST | `/v1/threads/{id}/runs/{run_id}/submit_tool_outputs` | **Tool result injection point** |
| GET | `/v1/threads/{id}/runs/{run_id}/steps` | Agent reasoning chain |
| POST | `/v1/threads/{id}/runs/{run_id}/cancel` | Cancel run |
| GET | `/v1/responses/{id}` | Retrieve Responses API object |
| POST | `/v1/responses/{id}/cancel` | Cancel response |
| WS | `/v1/realtime` | Realtime API WebSocket (session config capture) |

---

## Classification labels

Each request is classified by a rule-based scorer:

| Label | Meaning |
|-------|---------|
| `credential_stuffer` | Testing a key against the API (SDK headers, key format match, high-rate POST to completions) |
| `prompt_harvester` | Attempting to extract system prompts, jailbreaking, indirect injection via MCP |
| `data_exfil` | SSRF payloads, file path traversal, command injection, MCP resource reads with exfil destinations |
| `recon` | Enumerating org structure, models, files, vector stores, MCP tools/resources |
| `scanner` | Automated scanner signature in UA, missing browser headers, suspicious path patterns |
| `researcher` | Explicit disclosure language (`pentest`, `bug bounty`, `authorized test`) |
| `human` | Browser UA, natural language in prompt, proper sentence structure |
| `unknown` | Insufficient signals |

The classifier is rule-based and fast. Groq LLM analysis runs asynchronously afterward and produces a second, richer assessment stored in the database.

---

## Setup

```bash
cd honeypot
chmod +x setup.sh
./setup.sh
cp .env.example .env
# Edit .env — set ADMIN_USERNAME, ADMIN_PASSWORD, JWT_SECRET at minimum
source venv/bin/activate
python main.py
```

`python main.py` now opens `PORT` plus any configured `ADDITIONAL_PORTS`.

Recommended high-signal extra ports:
`3000,5000,7860,8000,8080,8888,9000,11434`

Admin UI: `http://localhost:80/admin` (change `ADMIN_PATH` to a secret path before deploying)

### GeoIP (optional but recommended)

```bash
# Get a free MaxMind license key at maxmind.com
# Then run:
MAXMIND_LICENSE_KEY=your_key ./download_geoip.sh
```

Without GeoIP, all locations show as Unknown.

### Groq AI analysis (optional)

Set `GROQ_API_KEY` in `.env` or in the admin UI. Uses `llama-3.1-8b-instant` by default. Each request triggers one Groq call in the background (non-blocking). Free tier is sufficient for moderate traffic.

### Local Ollama fallback (optional, recommended for offline / rate-limited ops)

```bash
# Install Ollama and pull a small model
curl -fsSL https://ollama.com/install.sh | sh
OLLAMA_HOST=0.0.0.0 ollama serve &
ollama pull qwen2.5:1.5b        # ~900 MB — fastest option for honeypot sim
# Or for heavier analysis: ollama pull qwen2.5:7b
```

Then enable in admin UI → Settings → LLM Backends, or set `ollama_enabled: true` in `config.json`. If Groq fails, the honeypot uses Ollama transparently; the `llm_backend_used` column records which served each turn.

---

## Production deployment (Ubuntu 24.04)

The honeypot binds **port 80 directly** for one vhost; nginx fronts it to add TLS (certbot) and to proxy the public domain. All other listed ports bind from the app via multi-process uvicorn.

```bash
sudo apt update && sudo apt install -y python3.12 python3.12-venv nginx certbot python3-certbot-nginx
sudo cp honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now honeypot
sudo cp nginx.conf /etc/nginx/sites-available/honeypot
# Edit server_name in nginx.conf; upstream is 127.0.0.1:8080 (matches PORT in .env)
sudo ln -s /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d api.yourdomain.com
sudo ufw allow 80,443,2222/tcp && sudo ufw enable
```

Ports bound by the app (via `additional_ports` in config.json): `2379, 3000, 3001, 5000, 6333, 6334, 8080, 8443, 8888, 9000, 9001, 9200, 11434` — etcd, web frameworks, Qdrant, OpenAI-compat proxies, Elastic, Ollama. Each advertises a realistic banner so Censys/Shodan tag them correctly.

---

## Seeding strategies

The honeypot only captures attackers who find it. Common seeding approaches:

**GitHub leak bait** — push a repo with a `.env` containing a fake `OPENAI_BASE_URL=https://your-domain/v1` and `OPENAI_API_KEY=sk-proj-...`. Wait for secret scanners to index it, then delete. Attackers who find it will test the key against your endpoint.

**Pastebin / Gist** — post developer-style notes with your endpoint URL and a plausible-looking key.

**HuggingFace Spaces** — create a demo app with your honeypot URL hardcoded as `base_url` in an `openai.OpenAI(...)` call.

**MCP server listing** — list your `/mcp` endpoint in public MCP server directories (smithery.ai, etc.) with a description like "internal company tools server." Agentic tools that auto-connect to listed servers will probe it.

**Shodan/Censys exposure** — if the server is internet-facing on port 80/443, scanners will find it. The realistic API responses cause them to keep probing rather than moving on.

---

## Canary key tracking — confirmed theft detection

The honeypot closes the loop between "key served" and "key reused." When a request arrives using a key we previously issued:

1. The request is **flagged** in the database (`is_flagged = true`)
2. A `CONFIRMED CREDENTIAL THEFT` banner prints to the console with IP, country, path, and UA
3. The alert webhook fires immediately (Slack/Discord/SIEM)

Keys that can be tracked:
- **Auto-issued canary keys** — every key returned by `/v1/organization/api-keys` is recorded in memory. If the same key appears in a subsequent `Authorization: Bearer ...` header, it's a confirmed steal-and-reuse.
- **Operator canary tokens** — add your own tokens in admin UI → Tokens. These appear in the `/v1/organization/api-keys` response and are watched for reuse.
- **MCP resource canary credentials** — the fake `.env`, `secrets.json`, and database resource content contains `canary_*` values. If an attacker reads a resource and then uses one of those values as an API key on a real provider, and you're also watching via a separate alerting mechanism (e.g., a canarytokens.org token embedded in the resource), you can correlate the event.

**Query flagged requests:**
```bash
sqlite3 /opt/honeypot/honeypot.db "SELECT id, timestamp, source_ip, country_name, path, api_key, notes FROM requests WHERE is_flagged = 1 ORDER BY timestamp DESC;"
```

## Metrics and protocol breakdown

Every request is tagged with a `protocol` field:

| Value | Meaning |
|-------|---------|
| `openai_api` | Hit a `/v1/*` OpenAI endpoint |
| `anthropic_api` | Hit `/v1/messages` or had `anthropic-version` header |
| `mcp` | Hit `/mcp` or `/.well-known/mcp.json` |
| `web` | Hit a non-API path (root, playground, scanner probe) |

**Compare API vs MCP vs scanner traffic:**
```bash
sqlite3 /opt/honeypot/honeypot.db "
SELECT
  protocol,
  classification,
  COUNT(*) as count,
  ROUND(AVG(classification_confidence), 2) as avg_confidence
FROM requests
GROUP BY protocol, classification
ORDER BY protocol, count DESC;
"
```

**MCP scanner vs MCP/LLM tools:**
```bash
sqlite3 /opt/honeypot/honeypot.db "
SELECT
  CASE
    WHEN user_agent LIKE '%curl%' OR user_agent LIKE '%python%' OR user_agent IS NULL THEN 'scanner'
    WHEN user_agent LIKE '%claude%' OR user_agent LIKE '%cursor%' OR user_agent LIKE '%copilot%' THEN 'llm_tool'
    WHEN json_extract(body_parsed, '$.method') = 'tools/call' THEN 'active_mcp_client'
    ELSE 'other'
  END as actor_type,
  COUNT(*) as count
FROM requests
WHERE protocol = 'mcp'
GROUP BY actor_type
ORDER BY count DESC;
"
```

**Agentic requests (containing tool_calls):**
```bash
sqlite3 /opt/honeypot/honeypot.db "
SELECT protocol, classification, COUNT(*) as count
FROM requests
WHERE has_tool_calls = 1
GROUP BY protocol, classification
ORDER BY count DESC;
"
```

The admin dashboard surfaces `protocol_breakdown` and `agentic_requests` totals in the stats endpoint automatically.

## MCP canary tokens

The fake MCP resources (`file:///app/.env`, `file:///app/config/secrets.json`, etc.) contain canary credentials — values like `sk-proj-canary0000...` and `AKIACANARY000...`. These are logged when served. If an attacker reads a resource and then attempts to use the credential elsewhere (on the real provider), you can correlate those attempts via the canary value.

Add custom canary tokens in the admin UI under **Tokens**. They will appear in the `/v1/organization/api-keys` response and be flagged in the dashboard when reused.

---

## Maintenance

```bash
# Monthly GeoIP update
sudo -u honeypot ./download_geoip.sh && sudo systemctl restart honeypot

# Backup
sqlite3 /opt/honeypot/honeypot.db ".dump" > backup_$(date +%Y%m%d).sql

# Logs
sudo journalctl -u honeypot -f
sudo tail -f /var/log/nginx/honeypot_access.log
```

---

## Security notes

- The admin dashboard must be behind a secret path (`ADMIN_PATH` env var). The default `/admin` is guessable — change it before exposing the server publicly.
- The SQLite database contains all captured request bodies including any credentials or PII sent by attackers. Restrict file permissions accordingly.
- Rate limiting is intentionally absent by default to capture maximum traffic. Enable it in nginx only if you need to control costs or bandwidth.
- This is a passive observation tool. It does not attempt to interfere with attackers, deanonymize them beyond what they reveal, or contact any third-party service except Groq (if configured).

---

## License

MIT — for security research and defensive purposes.

The operator is responsible for compliance with local laws regarding honeypots and for ethical handling of collected data.
