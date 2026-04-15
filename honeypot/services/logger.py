"""
Request logging service for the honeypot.

Handles capturing, processing, and storing all request data.
Integrates with Groq for AI-powered threat analysis.
"""

import asyncio
import json
import math
import re
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Request
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from models.db import Database, generate_session_fingerprint
from services.geoip import GeoIPService, get_geoip_service
from services.classifier import get_classifier, ClassificationResult
from services.taxonomy import detect_framework, map_taxonomy

console = Console()


class RequestLogger:
    """Logs and processes honeypot requests."""

    def __init__(self, db: Database, geoip: Optional[GeoIPService] = None):
        self.db = db
        self.geoip = geoip or get_geoip_service()
        self.classifier = get_classifier()
        self._analyzer = None  # Lazy load

        # Track request counts per IP for rate analysis
        self._ip_request_counts: dict[str, list[datetime]] = defaultdict(list)
        self._session_request_counts: dict[str, int] = defaultdict(int)
        self._ip_cleanup_counter: int = 0  # Periodic sweep to evict stale IPs

    async def _get_analyzer(self):
        """Lazy load the Groq analyzer."""
        if self._analyzer is None:
            from services.analyzer import get_analyzer
            self._analyzer = get_analyzer()
        return self._analyzer

    def _get_ip_request_rate(self, ip: str, window_minutes: int = 5) -> dict:
        """Get request rate info for an IP."""
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=window_minutes)

        # Periodic full sweep to evict IPs idle for >1 hour (prevents unbounded growth)
        self._ip_cleanup_counter += 1
        if self._ip_cleanup_counter >= 500:
            stale_cutoff = now - timedelta(hours=1)
            self._ip_request_counts = defaultdict(
                list,
                {k: v for k, v in self._ip_request_counts.items() if v and v[-1] > stale_cutoff},
            )
            self._ip_cleanup_counter = 0

        # Clean old entries for this IP
        self._ip_request_counts[ip] = [
            t for t in self._ip_request_counts[ip] if t > cutoff
        ]

        # Add current request
        self._ip_request_counts[ip].append(now)

        count = len(self._ip_request_counts[ip])
        rate_per_min = count / window_minutes if window_minutes > 0 else count

        return {
            "requests_in_window": count,
            "window_minutes": window_minutes,
            "rate_per_minute": round(rate_per_min, 2),
            "is_high_rate": rate_per_min > 10,  # More than 10 req/min
        }

    async def log_request(
        self,
        request: Request,
        body_raw: Optional[str] = None,
        body_parsed: Optional[dict] = None,
        response_body: Optional[str] = None,
        response_status: int = 200,
        response_time_ms: Optional[float] = None,
    ) -> int:
        """
        Log a complete request to the database.

        Returns the logged request ID.
        """
        # Get client IP (handle proxies)
        client_ip = self._get_client_ip(request)
        client_port = request.client.port if request.client else None

        # GeoIP lookup
        geo = self.geoip.lookup(client_ip)

        # Extract headers
        headers = dict(request.headers)
        from services.config import get_config
        config = get_config()

        # Extract specific header values for analysis
        content_type = headers.get("content-type", "")
        content_length = headers.get("content-length", "0")
        referer = headers.get("referer", "")
        origin = headers.get("origin", "")
        accept = headers.get("accept", "")
        accept_language = headers.get("accept-language", "")
        accept_encoding = headers.get("accept-encoding", "")
        connection = headers.get("connection", "")

        # Extract cookies (redact values but keep names)
        cookies_raw = headers.get("cookie", "")
        cookie_names = []
        if cookies_raw:
            cookie_names = [c.split("=")[0].strip() for c in cookies_raw.split(";") if "=" in c]

        # Extract auth info
        auth_header = headers.get("authorization", "")
        api_key = self._extract_api_key(auth_header)

        # Extract OpenAI-specific fields
        model_requested = None
        messages = None
        prompt = None
        temperature = None
        max_tokens = None
        stream = None
        has_tool_calls = False

        if body_parsed:
            model_requested = body_parsed.get("model")
            messages = body_parsed.get("messages")
            prompt = body_parsed.get("prompt") or body_parsed.get("input")
            temperature = body_parsed.get("temperature")
            max_tokens = body_parsed.get("max_tokens")
            stream = body_parsed.get("stream", False)

            # Detect tool_calls — present in agentic loops (model requesting a tool)
            # or in messages that contain tool result injection
            if messages and isinstance(messages, list):
                for msg in messages:
                    if isinstance(msg, dict):
                        if msg.get("tool_calls") or msg.get("role") == "tool":
                            has_tool_calls = True
                            break
            # Also check top-level tools/tool_calls fields (Responses API, Anthropic)
            if body_parsed.get("tools") or body_parsed.get("tool_calls"):
                has_tool_calls = True

        # Determine protocol from path
        path_str = str(request.url.path)
        auth_val = headers.get("authorization", "")
        if path_str.startswith("/mcp") or path_str == "/.well-known/mcp.json":
            protocol = "mcp"
        elif (
            headers.get("anthropic-version")
            or (isinstance(auth_val, str) and "sk-ant-" in auth_val)
            or path_str in ("/v1/messages", "/v1/messages/batches")
        ):
            protocol = "anthropic_api"
        elif path_str.startswith("/v1beta/") or headers.get("x-goog-api-key") or (
            isinstance(auth_val, str) and "AIza" in auth_val
        ):
            protocol = "gemini_api"
        elif path_str.startswith(("/query", "/upsert", "/fetch", "/delete", "/describe_index_stats",
                                   "/api/v1/collections", "/v1/schema", "/v1/graphql", "/v1/objects",
                                   "/v1/meta")):
            protocol = "vector_db"
        elif path_str.startswith("/v1/"):
            protocol = "openai_api"
        else:
            protocol = "web"

        # Generate session fingerprint
        fingerprint = generate_session_fingerprint(
            user_agent=headers.get("user-agent", ""),
            accept_language=accept_language,
            accept_encoding=accept_encoding,
        )

        # Track session requests
        self._session_request_counts[fingerprint] += 1
        session_request_num = self._session_request_counts[fingerprint]

        # Get IP rate info
        ip_rate = self._get_ip_request_rate(client_ip)

        # Classify the request
        classification_result = self.classifier.classify(
            user_agent=headers.get("user-agent"),
            api_key=api_key,
            messages=messages,
            prompt=prompt,
            path=str(request.url.path),
            headers=headers,
            body=body_raw,
        )

        # ── LLM Agent trap detection ──────────────────────────────────────
        from services.agent_trap import get_trap_service
        trap_svc = get_trap_service()
        agent_signal = trap_svc.check_incoming(
            ip=client_ip,
            path=str(request.url.path),
            body_raw=body_raw or "",
        )
        # Elevate classification if we have strong agent evidence
        if agent_signal.agent_type == "llm_agent" and agent_signal.confidence >= 0.7:
            if classification_result.classification not in ("credential_stuffer", "prompt_harvester"):
                classification_result.classification = "credential_stuffer"
                classification_result.reasons = (
                    classification_result.reasons + agent_signal.reasons
                )

        # Broadcast trap hit immediately (before DB write so dashboard lights up fast)
        if agent_signal.trap_hit:
            try:
                from services.ws_feed import get_ws_manager
                asyncio.create_task(get_ws_manager().emit_trap_hit(
                    request_id=0,  # ID not known yet; updated below after DB write
                    trap_type=agent_signal.trap_type or "unknown",
                    source_ip=client_ip,
                    path=str(request.url.path),
                    delta_ms=agent_signal.response_delta_ms,
                ))
            except Exception:
                pass

        framework = detect_framework(
            user_agent=headers.get("user-agent"),
            headers=headers,
            body_parsed=body_parsed,
            path=path_str,
        )
        attack_chain_id = self._build_attack_chain_id(
            client_ip=client_ip,
            api_key=api_key,
            fingerprint=fingerprint,
            framework=framework,
        )
        taxonomy = map_taxonomy(
            path=path_str,
            protocol=protocol,
            classification=classification_result.classification,
            headers=headers,
            body_raw=body_raw,
            body_parsed=body_parsed or {},
            api_key=api_key,
            has_tool_calls=has_tool_calls,
            framework=framework,
            agent_type=agent_signal.agent_type,
        )

        # Build request data
        request_data = {
            "timestamp": datetime.utcnow(),
            "source_ip": client_ip,
            "source_port": client_port,
            "country_code": geo.country_code,
            "country_name": geo.country_name,
            "city": geo.city,
            "latitude": geo.latitude,
            "longitude": geo.longitude,
            "asn": geo.asn,
            "asn_org": geo.asn_org,
            "method": request.method,
            "path": str(request.url.path),
            "query_string": str(request.url.query) if request.url.query else None,
            "headers": headers if config.get("log_headers", True) else None,
            "body_raw": body_raw if config.get("log_body", True) else None,
            "body_parsed": body_parsed if config.get("log_body", True) else None,
            "auth_header": auth_header if auth_header else None,
            "api_key": api_key,
            "model_requested": model_requested,
            "messages": messages,
            "prompt": prompt,
            "response_status": response_status,
            "response_body": response_body[:10000] if response_body and config.get("log_response", True) else None,
            "response_time_ms": response_time_ms,
            "session_fingerprint": fingerprint,
            "user_agent": headers.get("user-agent"),
            "classification": classification_result.classification,
            "classification_confidence": classification_result.confidence,
            "classification_reasons": classification_result.reasons,
            "protocol": protocol,
            "has_tool_calls": has_tool_calls,
            "agent_type": agent_signal.agent_type,
            "trap_hit": agent_signal.trap_hit,
            "trap_type": agent_signal.trap_type,
            "response_delta_ms": agent_signal.response_delta_ms,
            "framework": framework,
            "attack_chain_id": attack_chain_id,
            "attack_stage": taxonomy.attack_stage,
            "owasp_categories": taxonomy.owasp_categories,
            "mitre_atlas_tags": taxonomy.mitre_atlas_tags,
            "cwe_ids": taxonomy.cwe_ids,
            "realtime_session_id": self._extract_realtime_session_id(path_str, body_parsed),
            "voice_profile": taxonomy.voice_profile,
            "voice_metadata": taxonomy.voice_metadata,
        }

        # Log to database first to get ID
        logged = await self.db.log_request(request_data)
        request_id = logged.id

        # Record Prometheus metrics
        try:
            from services.metrics import get_metrics
            get_metrics().record_request(
                protocol=protocol,
                classification=classification_result.classification,
                threat_level="unknown",  # filled in after Groq analysis
                duration_s=(response_time_ms or 0) / 1000.0,
                source_ip=client_ip,
            )
            if agent_signal.trap_hit:
                get_metrics().record_agent_trap_hit()
        except Exception:
            pass

        # Broadcast to live dashboard WebSocket clients immediately
        try:
            from services.ws_feed import get_ws_manager
            asyncio.create_task(get_ws_manager().emit_new_request(request_id, request_data))
        except Exception:
            pass

        # Build extended data for verbose console output
        extended_data = {
            "content_type": content_type,
            "content_length": content_length,
            "referer": referer,
            "origin": origin,
            "accept": accept,
            "accept_language": accept_language,
            "accept_encoding": accept_encoding,
            "connection": connection,
            "cookie_names": cookie_names,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": stream,
            "session_request_num": session_request_num,
            "ip_rate": ip_rate,
            "framework": framework,
            "attack_chain_id": attack_chain_id,
            "owasp_categories": taxonomy.owasp_categories,
            "mitre_atlas_tags": taxonomy.mitre_atlas_tags,
        }

        # Console output with correct ID
        self._print_request_verbose(request_id, request_data, classification_result, extended_data)

        # Canary key reuse detection — check if this key was previously served by us
        if api_key:
            asyncio.create_task(self._check_canary_reuse(request_id, api_key, request_data))

        # Run Groq analysis in background (don't block response)
        asyncio.create_task(self._analyze_and_update(request_id, request_data))

        # Send alerts if configured
        asyncio.create_task(self._send_alerts(request_id, request_data, classification_result))

        return request_id

    async def _check_canary_reuse(self, request_id: int, api_key: str, data: dict):
        """
        Check if an incoming API key matches one we previously issued (canary token reuse).

        This is the closed-loop: key served → key reused → confirmed theft.
        Two sources of canary keys:
          1. Randomly generated keys issued by /v1/organization/api-keys
          2. Operator-defined canary tokens from admin UI config

        When a match is found:
          - Flag the request in the DB
          - Print a high-visibility alert to console
          - Fire the alert webhook
        """
        try:
            from services.responder import get_responder
            from services.config import get_config

            responder = get_responder()
            config = get_config()

            canary_label = None
            is_canary = api_key in responder.issued_canary_keys

            # Check operator-defined tokens
            if not is_canary:
                for ct in config.get("canary_tokens", []):
                    if ct.get("token") == api_key:
                        is_canary = True
                        canary_label = ct.get("label", "custom canary")
                        break

            # Check MCP resource canary values — these appear in resource content,
            # not in auth headers, but an attacker might copy them to a real provider
            mcp_canary_prefixes = [
                "canary_secret_value_for_",
                "canary_user_token_",
                "canary_sql_result_",
                "canary_http_response_",
                "canary_email_",
            ]
            if not is_canary:
                for prefix in mcp_canary_prefixes:
                    if api_key.startswith(prefix):
                        is_canary = True
                        canary_label = f"MCP resource canary ({prefix}...)"
                        break

            if not is_canary:
                return

            label_str = f" [{canary_label}]" if canary_label else ""

            # Flag the request in DB
            async with self.db.async_session() as session:
                from sqlalchemy import select as sa_select
                from models.db import Request as DBRequest
                result = await session.execute(
                    sa_select(DBRequest).where(DBRequest.id == request_id)
                )
                req = result.scalar_one_or_none()
                if req:
                    req.is_flagged = True
                    existing_notes = req.notes or ""
                    req.notes = f"CANARY REUSE{label_str}: key={api_key[:20]}... | {existing_notes}".strip(" |")
                    await session.commit()

            # Record Prometheus canary hit
            try:
                from services.metrics import get_metrics
                get_metrics().record_canary_hit()
            except Exception:
                pass

            # Console alert
            from rich.panel import Panel as RichPanel
            console.print()
            console.print(RichPanel(
                f"[bold white]🎯 CANARY KEY REUSE CONFIRMED{label_str}[/bold white]\n\n"
                f"[yellow]Key:[/yellow]    {api_key[:20]}...\n"
                f"[yellow]Used by:[/yellow] {data['source_ip']} ({data.get('country_name', 'Unknown')})\n"
                f"[yellow]Path:[/yellow]   {data['method']} {data['path']}\n"
                f"[yellow]UA:[/yellow]     {str(data.get('user_agent', 'none'))[:80]}\n\n"
                f"[dim]Request #{request_id} has been flagged in the database.[/dim]",
                title="[bold red on white] CONFIRMED CREDENTIAL THEFT [/bold red on white]",
                border_style="bold red",
            ))
            console.print()

            # Broadcast canary hit to live dashboard clients
            try:
                from services.ws_feed import get_ws_manager
                asyncio.create_task(get_ws_manager().emit_canary_hit(
                    request_id=request_id,
                    api_key=api_key,
                    source_ip=data["source_ip"],
                    country=data.get("country_name", "Unknown"),
                    path=data["path"],
                    label=canary_label or "canary",
                ))
            except Exception:
                pass

            # Fire alert webhook
            from services.alerts import get_alert_service
            alert_service = get_alert_service()
            await alert_service.send_alert(
                title=f"🎯 CANARY KEY REUSED — Confirmed Credential Theft #{request_id}",
                classification="credential_stuffer",
                confidence=1.0,
                source_ip=data["source_ip"],
                country=data.get("country_name", "Unknown"),
                path=data["path"],
                api_key=api_key,
                reasons=[f"Canary key reuse confirmed{label_str}"],
            )

        except Exception as e:
            console.print(f"[red]Canary check error: {e}[/red]")

    async def _send_alerts(self, request_id: int, data: dict, classification: ClassificationResult):
        """Send webhook alerts for high-threat requests."""
        try:
            from services.alerts import get_alert_service
            from services.config import get_config

            config = get_config()
            alert_threshold = config.get("alert_threshold", "high")

            # Determine if we should alert
            should_alert = False
            if alert_threshold == "all":
                should_alert = True
            elif alert_threshold == "medium":
                should_alert = classification.confidence >= 0.4
            elif alert_threshold == "high":
                should_alert = classification.confidence >= 0.6 or classification.classification in ["credential_stuffer", "prompt_harvester"]

            if should_alert:
                alert_service = get_alert_service()
                await alert_service.send_alert(
                    title=f"Honeypot Alert #{request_id}",
                    classification=classification.classification,
                    confidence=classification.confidence,
                    source_ip=data["source_ip"],
                    country=data.get("country_name", "Unknown"),
                    path=data["path"],
                    api_key=data.get("api_key"),
                    reasons=classification.reasons,
                )
        except Exception as e:
            console.print(f"[dim red]Alert error: {e}[/dim red]")

    async def _analyze_and_update(self, request_id: int, request_data: dict):
        """Run Groq analysis and update database."""
        try:
            analyzer = await self._get_analyzer()
            if not analyzer.enabled:
                console.print(f"[dim yellow]Groq Interpretation #{request_id}: unavailable (analyzer disabled)[/dim yellow]")
                return

            analysis = await analyzer.analyze(request_data)
            if analysis:
                # Update database with analysis
                await self.db.update_analysis(
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

                # Broadcast analysis update to live dashboard clients
                try:
                    from services.ws_feed import get_ws_manager
                    asyncio.create_task(get_ws_manager().emit_analysis(request_id, analysis))
                except Exception:
                    pass

                # Print analysis to console
                self._print_analysis(request_id, analysis)
            else:
                console.print(f"[dim yellow]Groq Interpretation #{request_id}: unavailable (no result returned)[/dim yellow]")

        except Exception as e:
            console.print(f"[red]Analysis error for #{request_id}: {e}[/red]")

    def _get_client_ip(self, request: Request) -> str:
        """Extract real client IP, handling reverse proxies."""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

        if request.client:
            return request.client.host

        return "unknown"

    def _extract_api_key(self, auth_header: str) -> Optional[str]:
        """Extract API key from Authorization header."""
        if not auth_header:
            return None

        if auth_header.lower().startswith("bearer "):
            return auth_header[7:].strip()

        return auth_header.strip()

    def _truncate(self, text: str, max_len: int = 100) -> str:
        """Truncate text with ellipsis."""
        if not text:
            return ""
        if len(text) <= max_len:
            return text
        return text[:max_len-3] + "..."

    def _calc_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string (high = possibly encrypted/encoded)."""
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _detect_sdk(self, headers: dict) -> Optional[str]:
        """Detect the SDK/tool being used from headers."""
        lower = {k.lower(): v for k, v in headers.items()}
        # Official OpenAI SDK fingerprint
        stainless = [k for k in lower if k.startswith("x-stainless-")]
        if stainless:
            lang = lower.get("x-stainless-lang", "?")
            ver = lower.get("x-stainless-package-version", "?")
            os_hint = lower.get("x-stainless-os", "?")
            return f"OpenAI SDK ({lang} v{ver}, {os_hint})"
        ua = lower.get("user-agent", "").lower()
        if "openai-python" in ua or re.search(r"openai/[0-9]", ua):
            return "openai-python SDK"
        if "langchain" in ua:
            return "LangChain"
        if "litellm" in ua:
            return "LiteLLM"
        if "llamaindex" in ua:
            return "LlamaIndex"
        if "curl" in ua:
            return "cURL"
        if "python-requests" in ua:
            return "Python requests"
        if "python-httpx" in ua:
            return "Python httpx"
        if "go-http-client" in ua:
            return "Go HTTP client"
        if "axios" in ua:
            return "Axios (Node.js)"
        if "postman" in ua:
            return "Postman"
        if "insomnia" in ua:
            return "Insomnia"
        return None

    def _build_attack_chain_id(self, client_ip: str, api_key: Optional[str], fingerprint: str, framework: Optional[str]) -> str:
        basis = f"{client_ip}|{api_key or '-'}|{fingerprint}|{framework or '-'}"
        return hashlib.sha256(basis.encode()).hexdigest()[:20]

    def _extract_realtime_session_id(self, path: str, body_parsed: Optional[dict]) -> Optional[str]:
        if path != "/v1/realtime" or not isinstance(body_parsed, dict):
            return None
        session = body_parsed.get("session", {})
        if isinstance(session, dict):
            return session.get("id")
        return None

    def _print_request_verbose(
        self,
        request_id: int,
        data: dict,
        classification: ClassificationResult,
        extended: dict,
    ):
        """Print detailed request info to console."""
        colors = {
            "scanner": "yellow",
            "credential_stuffer": "red",
            "prompt_harvester": "magenta",
            "researcher": "blue",
            "human": "green",
            "data_exfil": "bold red",
            "recon": "dark_orange",
            "unknown": "white",
        }
        color = colors.get(classification.classification, "white")

        # Header with request ID and timestamp
        timestamp_str = (
            data["timestamp"].strftime("%Y-%m-%d %H:%M:%S UTC")
            if isinstance(data["timestamp"], datetime)
            else str(data["timestamp"])
        )

        console.print()
        console.rule(
            f"[bold {color}]Request #{request_id}[/bold {color}]  [{color}]{classification.classification.upper()}[/{color}]  {timestamp_str}",
            style=color,
        )

        # ── THREAT BANNER for high-severity ──────────────────────────────
        if classification.classification in ("data_exfil", "credential_stuffer") and classification.confidence >= 0.6:
            console.print(
                Panel(
                    f"[bold red]⚠  HIGH SEVERITY: {classification.classification.upper()}  ({classification.confidence:.0%} confidence)[/bold red]",
                    border_style="red",
                    padding=(0, 2),
                )
            )
        elif classification.classification == "prompt_harvester" and classification.confidence >= 0.5:
            console.print(
                Panel(
                    f"[bold magenta]⚠  PROMPT INJECTION / HARVEST ATTEMPT  ({classification.confidence:.0%} confidence)[/bold magenta]",
                    border_style="magenta",
                    padding=(0, 2),
                )
            )

        # ── MAIN INFO TABLE ───────────────────────────────────────────────
        table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
        table.add_column("Field", style="bold cyan", width=20)
        table.add_column("Value", overflow="fold")

        # Source info
        location_parts = []
        if data.get("city"):
            location_parts.append(data["city"])
        if data.get("country_name"):
            location_parts.append(data["country_name"])
        location = ", ".join(location_parts) if location_parts else "Unknown"
        flag = ""
        if data.get("country_code") and len(data["country_code"]) == 2:
            flag = "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in data["country_code"].upper()) + " "

        table.add_row("Source IP", f"[bold]{data['source_ip']}[/bold]:{data.get('source_port', '?')}")
        table.add_row("Location", f"{flag}{location}")
        if data.get("asn_org"):
            table.add_row("ASN/Org", f"[dim]AS{data.get('asn', '?')}[/dim] {data['asn_org']}")

        # Request info
        method_colors = {"GET": "cyan", "POST": "green", "DELETE": "red", "PUT": "yellow", "PATCH": "yellow"}
        mc = method_colors.get(data["method"], "white")
        table.add_row("Request", f"[bold {mc}]{data['method']}[/bold {mc}] {data['path']}")
        if data.get("query_string"):
            table.add_row("Query", f"[dim]{self._truncate(data['query_string'], 100)}[/dim]")

        # Content info
        if extended.get("content_type"):
            table.add_row("Content-Type", extended["content_type"])
        if extended.get("content_length") and extended["content_length"] != "0":
            table.add_row("Content-Length", f"{extended['content_length']} bytes")

        # SDK / Tool fingerprint
        headers_raw = data.get("headers", {})
        sdk = self._detect_sdk(headers_raw)
        if sdk:
            table.add_row("Tool / SDK", f"[bold yellow]{sdk}[/bold yellow]")

        # Auth info with canary key flag
        if data.get("api_key"):
            key = data["api_key"]
            from services.responder import get_responder
            from services.config import get_config
            is_canary = key in get_responder().issued_canary_keys
            canary_label = None
            # Check operator-defined canary tokens too
            for ct in get_config().get("canary_tokens", []):
                if ct.get("token") == key:
                    is_canary = True
                    canary_label = ct.get("label", "custom canary")
                    break
            if len(key) > 20:
                redacted = f"{key[:12]}...{key[-6:]}"
            else:
                redacted = key
            if is_canary:
                label_str = f" [{canary_label}]" if canary_label else ""
                table.add_row(
                    "API Key",
                    f"[bold red on yellow] 🎯 CANARY KEY USED{label_str}: {redacted} [/bold red on yellow]",
                )
            else:
                table.add_row("API Key", f"[bold yellow]{redacted}[/bold yellow]")

        # OpenAI-specific
        if data.get("model_requested"):
            table.add_row("Model", data["model_requested"])
        if extended.get("temperature") is not None:
            table.add_row("Temperature", str(extended["temperature"]))
        if extended.get("max_tokens"):
            table.add_row("Max Tokens", str(extended["max_tokens"]))
        if extended.get("stream"):
            table.add_row("Streaming", "[cyan]Yes[/cyan]")

        # Session/Rate info
        fp = data.get("session_fingerprint", "N/A")
        table.add_row(
            "Session",
            f"Request [bold]#{extended['session_request_num']}[/bold] | "
            f"Fingerprint: [dim]{fp[:16]}...[/dim]",
        )

        ip_rate = extended.get("ip_rate", {})
        rate_per_min = ip_rate.get("rate_per_minute", 0)
        if rate_per_min > 30:
            rate_color = "bold red"
            rate_label = "🚨 VERY HIGH"
        elif rate_per_min > 10:
            rate_color = "red"
            rate_label = "HIGH"
        elif rate_per_min > 3:
            rate_color = "yellow"
            rate_label = "ELEVATED"
        else:
            rate_color = "green"
            rate_label = "normal"
        table.add_row(
            "Request Rate",
            f"[{rate_color}]{ip_rate.get('requests_in_window', 0)} reqs/{ip_rate.get('window_minutes', 5)}min "
            f"({rate_per_min}/min) — {rate_label}[/{rate_color}]",
        )

        # Response time
        if data.get("response_time_ms") is not None:
            table.add_row("Response Time", f"{data['response_time_ms']:.1f} ms")

        # Classification (winner + confidence)
        table.add_row(
            "Classification",
            f"[bold {color}]{classification.classification.upper()}[/bold {color}] "
            f"({classification.confidence:.0%} confidence)",
        )
        if classification.classification == "human":
            verdict = "[bold green]HUMAN[/bold green]"
        elif classification.classification in ("scanner", "credential_stuffer", "prompt_harvester", "data_exfil", "recon"):
            verdict = "[bold red]NOT HUMAN[/bold red]"
        elif classification.classification == "researcher":
            verdict = "[bold blue]RESEARCHER / MANUAL[/bold blue]"
        else:
            verdict = "[bold yellow]UNCERTAIN[/bold yellow]"
        table.add_row("Human / Not", verdict)
        if data.get("framework"):
            table.add_row("Framework", f"[bold cyan]{data['framework']}[/bold cyan]")
        if data.get("attack_chain_id"):
            table.add_row("Attack Chain", f"[dim]{data['attack_chain_id']}[/dim] ({data.get('attack_stage', 'unknown')})")
        if extended.get("owasp_categories"):
            table.add_row("OWASP", ", ".join(extended["owasp_categories"][:3]))
        if extended.get("mitre_atlas_tags"):
            table.add_row("MITRE ATLAS", ", ".join(extended["mitre_atlas_tags"][:2]))

        # LLM Agent Detection row
        agent_type = data.get("agent_type", "unknown")
        trap_hit = data.get("trap_hit", False)
        trap_type = data.get("trap_type")
        delta_ms = data.get("response_delta_ms")

        if agent_type != "unknown" or trap_hit or delta_ms is not None:
            agent_parts = []
            if agent_type == "llm_agent":
                agent_parts.append("[bold red]🤖 LLM AGENT[/bold red]")
            elif agent_type == "bot":
                agent_parts.append("[yellow]🤖 BOT[/yellow]")
            elif agent_type == "human":
                agent_parts.append("[green]👤 HUMAN[/green]")
            if delta_ms is not None:
                agent_parts.append(f"Δ{delta_ms:.0f}ms")
            if trap_hit:
                agent_parts.append(f"[bold red]⚡ TRAP HIT ({trap_type})[/bold red]")
            table.add_row("Agent Signal", " | ".join(agent_parts) if agent_parts else "—")

        observables = [f"ip:{data['source_ip']}"]
        ua = str(data.get("user_agent") or "").strip()
        if ua:
            observables.append(f"ua:{self._truncate(ua, 60)}")
        if data.get("api_key"):
            observables.append(f"key:{data['api_key'][:12]}...")
        if data.get("model_requested"):
            observables.append(f"model:{data['model_requested']}")
        if data.get("path"):
            observables.append(f"path:{data['path']}")
        if data.get("realtime_session_id"):
            observables.append(f"rt_session:{data['realtime_session_id']}")
        table.add_row("Observables", "\n".join(f"[dim]• {item}[/dim]" for item in observables[:6]))

        console.print(table)

        # LLM Agent confirmed banner
        if agent_type == "llm_agent" and data.get("trap_hit"):
            console.print()
            console.print(Panel(
                f"[bold white]🤖 CONFIRMED LLM AGENT — TRAP COMPLIANCE[/bold white]\n\n"
                f"[yellow]IP:[/yellow]      {data['source_ip']}\n"
                f"[yellow]Trap:[/yellow]    {trap_type}\n"
                f"[yellow]Timing:[/yellow]  {delta_ms:.0f}ms response delta\n"
                f"[yellow]Path:[/yellow]    {data['path']}\n\n"
                f"[dim]An autonomous LLM agent followed an injected instruction in our response.[/dim]",
                title="[bold yellow on red] 🤖 LLM AGENT DETECTED [/bold yellow on red]",
                border_style="bold yellow",
            ))
            console.print()

        # ── SCORE BREAKDOWN ───────────────────────────────────────────────
        all_scores = getattr(classification, "all_scores", {})
        nonzero = {k: v for k, v in all_scores.items() if v > 0}
        if len(nonzero) > 1:
            console.print("\n[bold cyan]Score Breakdown:[/bold cyan]")
            score_table = Table(show_header=False, box=None, padding=(0, 1))
            score_table.add_column("Label", style="dim", width=22)
            score_table.add_column("Bar", width=30)
            score_table.add_column("Score", justify="right", width=6)
            sorted_scores = sorted(nonzero.items(), key=lambda x: x[1], reverse=True)
            score_colors = {
                "scanner": "yellow", "credential_stuffer": "red", "prompt_harvester": "magenta",
                "data_exfil": "red", "recon": "dark_orange", "researcher": "blue", "human": "green",
            }
            for label, score in sorted_scores:
                bar_len = max(1, int(min(score, 1.0) * 25))
                sc = score_colors.get(label, "white")
                winner = " ◀" if label == classification.classification else ""
                score_table.add_row(
                    f"[{sc}]{label}[/{sc}]{winner}",
                    f"[{sc}]{'█' * bar_len}{'░' * (25 - bar_len)}[/{sc}]",
                    f"[{sc}]{score:.2f}[/{sc}]",
                )
            console.print(score_table)

        # ── HEADERS ───────────────────────────────────────────────────────
        headers = data.get("headers", {})
        if headers:
            console.print("\n[bold cyan]Headers:[/bold cyan]")
            headers_table = Table(show_header=False, box=None, padding=(0, 1))
            headers_table.add_column("Header", style="dim", width=28)
            headers_table.add_column("Value", overflow="fold")

            priority_headers = [
                "user-agent", "authorization", "content-type", "accept",
                "origin", "referer", "x-forwarded-for", "x-real-ip",
                "x-stainless-lang", "x-stainless-package-version", "x-stainless-os",
                "x-stainless-runtime",
            ]
            shown = set()

            for h in priority_headers:
                if h in headers:
                    val = headers[h]
                    if h == "authorization" and len(val) > 40:
                        val = val[:40] + "..."
                    # Highlight x-stainless headers (SDK fingerprint)
                    if h.startswith("x-stainless-"):
                        headers_table.add_row(f"[yellow]{h}[/yellow]", f"[yellow]{val}[/yellow]")
                    else:
                        headers_table.add_row(h, val)
                    shown.add(h)

            for h, v in headers.items():
                if h.lower() not in shown:
                    headers_table.add_row(h, self._truncate(str(v), 80))

            console.print(headers_table)

        # ── BODY PREVIEW ──────────────────────────────────────────────────
        if data.get("body_raw"):
            body = data["body_raw"]
            entropy = self._calc_entropy(body)
            entropy_warn = ""
            if entropy > 5.5:
                entropy_warn = f" [yellow](high entropy: {entropy:.2f} — possible encoded/encrypted payload)[/yellow]"

            console.print(f"\n[bold cyan]Request Body[/bold cyan] ({len(body)} bytes){entropy_warn}:")

            try:
                parsed = json.loads(body)
                pretty = json.dumps(parsed, indent=2)
                if len(pretty) > 1000:
                    pretty = pretty[:1000] + f"\n[dim]... ({len(pretty) - 1000} more chars)[/dim]"
                console.print(Syntax(pretty, "json", theme="monokai", line_numbers=False))
            except Exception:
                display_body = body[:800] + (f"\n[dim]... ({len(body) - 800} more bytes)[/dim]" if len(body) > 800 else "")
                console.print(f"[dim]{display_body}[/dim]")

        # ── MESSAGES (chat completions) ───────────────────────────────────
        if data.get("messages"):
            msgs = data["messages"]
            console.print(f"\n[bold cyan]Messages[/bold cyan] ({len(msgs)} total):")
            for i, msg in enumerate(msgs[:8]):
                if isinstance(msg, dict):
                    role = msg.get("role", "?")
                    content_raw = msg.get("content", "")
                    content = str(content_raw)[:300]
                    if len(str(content_raw)) > 300:
                        content += f"[dim]...[/dim]"
                    role_color = {
                        "system": "yellow", "user": "green",
                        "assistant": "blue", "tool": "cyan",
                    }.get(role, "white")
                    prefix = f"  [{role_color}]{role:>9}[/{role_color}]"
                    console.print(f"{prefix} │ {content}")
            if len(msgs) > 8:
                console.print(f"  [dim]  ... and {len(msgs) - 8} more messages[/dim]")

        # ── CLASSIFICATION SIGNALS ────────────────────────────────────────
        if classification.reasons:
            console.print(f"\n[bold cyan]Classification Signals ({len(classification.reasons)}):[/bold cyan]")
            for reason in classification.reasons:
                # Color-code by signal type
                if any(w in reason.lower() for w in ["canary", "stolen", "sdk", "stainless"]):
                    console.print(f"  [red]⚑ {reason}[/red]")
                elif any(w in reason.lower() for w in ["injection", "exfil", "traversal", "sql"]):
                    console.print(f"  [magenta]⚑ {reason}[/magenta]")
                elif any(w in reason.lower() for w in ["scanner", "bot", "empty", "missing"]):
                    console.print(f"  [yellow]• {reason}[/yellow]")
                else:
                    console.print(f"  [dim]• {reason}[/dim]")

        # ── REFERER / ORIGIN ──────────────────────────────────────────────
        if extended.get("referer") or extended.get("origin"):
            if extended.get("referer"):
                console.print(f"[dim]  Referer : {extended['referer']}[/dim]")
            if extended.get("origin"):
                console.print(f"[dim]  Origin  : {extended['origin']}[/dim]")

        console.print()

    def _print_analysis(self, request_id: int, analysis):
        """Print Groq analysis to console."""
        level_colors = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }
        color = level_colors.get(analysis.threat_level, "white")

        actor_map = {
            "human": "[bold green]HUMAN[/bold green]",
            "bot": "[bold yellow]BOT[/bold yellow]",
            "llm_agent": "[bold red]LLM AGENT[/bold red]",
            "researcher": "[bold blue]RESEARCHER[/bold blue]",
            "unknown": "[bold white]UNKNOWN[/bold white]",
        }
        actor_label = actor_map.get(getattr(analysis, "actor_type", "unknown"), "[bold white]UNKNOWN[/bold white]")

        panel_content = f"""[{color}]Threat Level: {analysis.threat_level.upper()}[/{color}]
Type: {analysis.threat_type}
Groq Actor Verdict: {actor_label}
Confidence: {analysis.confidence:.0%}

{analysis.summary}

{analysis.details}"""

        if analysis.recommendations:
            panel_content += "\n\n[bold]Recommendations:[/bold]"
            for rec in analysis.recommendations[:3]:
                panel_content += f"\n  • {rec}"

        if analysis.iocs:
            panel_content += "\n\n[bold]IOCs:[/bold]"
            for ioc in analysis.iocs[:6]:
                panel_content += f"\n  • {ioc}"
        else:
            panel_content += "\n\n[bold]IOCs:[/bold]\n  • none extracted by Groq"

        console.print(Panel(
            panel_content,
            title=f"[bold]Groq Interpretation #{request_id}[/bold]",
            border_style=color,
        ))
        console.print()


# Singleton
_logger: Optional[RequestLogger] = None


def get_logger(db: Optional[Database] = None) -> RequestLogger:
    """Get or create logger singleton."""
    global _logger
    if _logger is None:
        if db is None:
            raise ValueError("Database must be provided on first initialization")
        _logger = RequestLogger(db)
    return _logger


def init_logger(db: Database) -> RequestLogger:
    """Initialize the logger with a database."""
    global _logger
    _logger = RequestLogger(db)
    return _logger
