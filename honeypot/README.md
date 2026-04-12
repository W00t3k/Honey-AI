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

Admin UI: `http://localhost:8000/admin` (change `ADMIN_PATH` to a secret path before deploying)

### GeoIP (optional but recommended)

```bash
# Get a free MaxMind license key at maxmind.com
# Then run:
MAXMIND_LICENSE_KEY=your_key ./download_geoip.sh
```

Without GeoIP, all locations show as Unknown.

### Groq AI analysis (optional)

Set `GROQ_API_KEY` in `.env` or in the admin UI. Uses `llama-3.1-8b-instant` by default. Each request triggers one Groq call in the background (non-blocking). Free tier is sufficient for moderate traffic.

---

## Production deployment (Ubuntu 24.04)

```bash
sudo apt update && sudo apt install -y python3.12 python3.12-venv nginx certbot python3-certbot-nginx
sudo useradd -r -s /bin/false honeypot
sudo mkdir -p /opt/honeypot
sudo chown honeypot:honeypot /opt/honeypot
scp -r honeypot/* user@server:/opt/honeypot/
cd /opt/honeypot && sudo -u honeypot ./setup.sh
sudo cp honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now honeypot
sudo cp nginx.conf /etc/nginx/sites-available/honeypot
# Edit nginx.conf — set your domain
sudo ln -s /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d api.yourdomain.com
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable
```

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
