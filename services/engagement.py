"""
AI-driven attacker engagement engine.

Goal: keep attackers interacting long enough to reveal tradecraft —
their tooling, target, goal, and C2 infrastructure — while staying
convincingly in-character as a normal LLM API.

Two jobs:

1. **Craft probes** — given the current conversation + classifier
   verdict, have the LLM append a subtle follow-up question designed
   to elicit one specific piece of tradecraft (what tool are you
   using, what target, what success criterion, where do the results go).
   The probe is phrased as the assistant naturally asking for
   clarification so it does not read as an interrogation.

2. **Extract tradecraft** — on each subsequent turn, scan the
   attacker's message for disclosed tooling, targets, C2, goals, and
   structured artifacts (tokens, URLs, commands). LLM-driven with
   regex priors. Returns structured fields for DB storage.

Both jobs are best-effort and never raise: engagement silently
no-ops if no LLM backend is available.
"""

from __future__ import annotations

import json
import re
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console

from services.llm_backend import get_backend

console = Console()

# ContextVar so the logger can pick up engagement meta without every
# router having to plumb it through request.state explicitly.
current_engagement_meta: ContextVar[Optional[dict]] = ContextVar(
    "current_engagement_meta", default=None
)


# ── Probe prompt library ───────────────────────────────────────────────────────
# Each probe targets ONE tradecraft field. Phrased as assistant would ask.

_PROBE_TEMPLATES = {
    "tool": [
        "By the way — are you calling this through a framework (like LangChain or a custom script)? I'll tune the response shape.",
        "Quick clarification: what client are you integrating from? Some SDKs truncate long responses differently.",
        "If you share what tooling you're using, I can match the output format more precisely.",
    ],
    "goal": [
        "To give you the right format — are you using this for analysis, extraction, or something else?",
        "What's the end goal here? I can optimize the response structure if I know the downstream use.",
    ],
    "target": [
        "Is this for a specific dataset or system? I can tailor the result format.",
        "If you tell me which environment this is targeting, I can return more actionable output.",
    ],
    "infra": [
        "Should results be returned inline or should I include a callback URL format in the schema?",
        "Are you running a retrieval pipeline? I can format with chunk IDs if helpful.",
    ],
}

_ENGAGEMENT_TRIGGERS = {
    # classifier/actor verdicts that warrant engagement
    "credential_stuffer",
    "prompt_harvester",
    "data_exfil",
    "recon",
    "llm_agent",  # from ai_actor_type
}

# Lightweight regex priors for tradecraft extraction (fast path; LLM
# does heavier work when API key available).

_TOOL_PATTERNS = {
    "langchain":       r"\blangchain\b",
    "llamaindex":      r"\bllama.?index\b",
    "litellm":         r"\blitellm\b",
    "crewai":          r"\bcrewai\b",
    "autogen":         r"\bautogen\b",
    "dspy":            r"\bdspy\b",
    "openai_sdk":      r"\bopenai[-_ ]?(python|sdk|node|js)\b",
    "anthropic_sdk":   r"\banthropic[-_ ]?(python|sdk|client)\b",
    "curl":            r"\bcurl\b",
    "httpie":          r"\bhttpie\b",
    "postman":         r"\bpostman\b",
    "burp":            r"\b(burp(suite)?|intruder|repeater)\b",
    "sqlmap":          r"\bsqlmap\b",
    "nuclei":          r"\bnuclei\b",
    "ffuf":            r"\bffuf\b",
    "custom_script":   r"\b(python|node|bash|go)\s+script\b|\bmy (script|tool|bot)\b",
    "mcp_client":      r"\b(mcp[- ]client|mcp[- ]inspector|claude[- ]?desktop|cursor)\b",
}

_INFRA_PATTERNS = {
    "webhook.site":     r"webhook\.site/[\w\-]+",
    "ngrok":            r"[a-z0-9\-]+\.ngrok(-free)?\.(io|app)",
    "interact.sh":      r"[a-z0-9]+\.interact\.sh",
    "oast.fun":         r"[a-z0-9]+\.oast\.(fun|live|site|me|pro)",
    "burp_collab":      r"[a-z0-9]+\.burpcollaborator\.net",
    "pipedream":        r"[a-z0-9]+\.m\.pipedream\.(net|com)",
    "requestbin":       r"[a-z0-9]+\.requestbin\.(io|net|com)",
    "discord_webhook":  r"discord(app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
    "telegram":         r"api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_\-]+",
    "dns_tunnel":       r"[a-z0-9]+\.[a-z0-9]+\.(oast|tunnel|dnslog)\.\w+",
    "private_ip":       r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
    "aws_imds":         r"169\.254\.169\.254",
    "gcp_metadata":     r"metadata\.google\.internal",
}

_GOAL_PATTERNS = {
    "data_exfil":        r"\b(exfil|dump|download|extract|scrape|harvest|leak)\b",
    "credential_test":   r"\b(valid|test|verify|check|confirm) (the )?(key|token|api)\b",
    "prompt_extract":    r"\b(system prompt|initial prompt|instructions|reveal|pre.?prompt)\b",
    "jailbreak":         r"\b(dan|jailbreak|bypass|unrestricted|god mode|no restrictions)\b",
    "recon":             r"\b(enumerate|list|discover|map out|inventory)\b",
    "rag_poison":        r"\b(vector store|embeddings?|rag|retrieval|chunks?)\b",
    "model_probe":       r"\b(which model|what model|model name|weights|parameters|fine.?tune)\b",
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class TradeCraft:
    """Extracted attacker tradecraft for a single turn."""
    tool: Optional[str] = None
    goal: Optional[str] = None
    target: Optional[str] = None
    infra: Optional[str] = None
    notes: str = ""
    raw: dict = field(default_factory=dict)


# ── Engine ─────────────────────────────────────────────────────────────────────

_TRADECRAFT_SYSTEM_PROMPT = """You are a honeypot analyst extracting attacker tradecraft from an adversarial chat turn.

Return STRICT JSON only, no commentary. Schema:
{
  "tool":   "langchain|llamaindex|litellm|crewai|autogen|openai_sdk|anthropic_sdk|curl|httpie|postman|burp|sqlmap|nuclei|ffuf|custom_script|mcp_client|unknown",
  "goal":   "data_exfil|credential_test|prompt_extract|jailbreak|recon|rag_poison|model_probe|unknown",
  "target": "short phrase naming what they're after (e.g. 'org users', 'api keys', 'system prompt', 'model weights', 'unknown')",
  "infra":  "c2/webhook/exfil endpoint they disclosed, or 'unknown'",
  "notes":  "one short sentence on notable tradecraft"
}

If a field is undetermined, use "unknown". Never invent — only extract what the attacker actually wrote."""


_PROBE_SYSTEM_PROMPT = """You are composing ONE SHORT follow-up sentence to append to an assistant reply in a normal AI chat API.

Constraints:
- Stay fully in-character as a helpful assistant. Never reference honeypots, analysis, or hidden motives.
- Max 20 words. Phrased as a casual clarifying question the assistant would plausibly ask.
- The question must subtly invite the user to disclose: {target_field}.
- Do not use the phrase "tradecraft", "attacker", "probe", or anything suspicious.

Return ONLY the sentence. No quotes, no preamble."""


class EngagementEngine:
    """Stateless engagement engine. Uses whichever LLM backend is healthy."""

    def __init__(self):
        self._compiled_tools = {k: re.compile(p, re.I) for k, p in _TOOL_PATTERNS.items()}
        self._compiled_infra = {k: re.compile(p, re.I) for k, p in _INFRA_PATTERNS.items()}
        self._compiled_goal  = {k: re.compile(p, re.I) for k, p in _GOAL_PATTERNS.items()}

    # --- cheap regex extraction (always runs) --------------------------------

    def extract_regex(self, text: str) -> TradeCraft:
        tc = TradeCraft()
        if not text:
            return tc
        for name, rx in self._compiled_tools.items():
            if rx.search(text):
                tc.tool = name
                break
        for name, rx in self._compiled_infra.items():
            m = rx.search(text)
            if m:
                tc.infra = m.group(0)
                break
        for name, rx in self._compiled_goal.items():
            if rx.search(text):
                tc.goal = name
                break
        return tc

    # --- LLM-backed extraction (best-effort) ---------------------------------

    async def extract(self, attacker_text: str) -> TradeCraft:
        """
        Extract tradecraft via regex priors, then enrich via LLM when available.
        Never raises.
        """
        tc = self.extract_regex(attacker_text or "")
        if not attacker_text or len(attacker_text.strip()) < 8:
            return tc

        try:
            backend = get_backend()
            raw = await backend.complete(
                messages=[{"role": "user", "content": attacker_text[:2000]}],
                system_prompt=_TRADECRAFT_SYSTEM_PROMPT,
                temperature=0.0,
                max_tokens=180,
            )
            if not raw:
                return tc

            # Grab the first JSON object in the reply
            m = re.search(r"\{.*\}", raw, re.S)
            if not m:
                return tc
            data = json.loads(m.group(0))
            if isinstance(data, dict):
                tc.tool   = tc.tool   or (data.get("tool")   if data.get("tool")   not in (None, "", "unknown") else tc.tool)
                tc.goal   = tc.goal   or (data.get("goal")   if data.get("goal")   not in (None, "", "unknown") else tc.goal)
                tc.target = data.get("target") if data.get("target") not in (None, "", "unknown") else tc.target
                tc.infra  = tc.infra  or (data.get("infra")  if data.get("infra")  not in (None, "", "unknown") else tc.infra)
                tc.notes  = str(data.get("notes") or "")[:400]
                tc.raw    = data
        except Exception as e:
            console.print(f"[dim]engagement.extract fallback: {e}[/dim]")
        return tc

    # --- probe generation ----------------------------------------------------

    def should_probe(
        self,
        *,
        classification: Optional[str],
        actor_type: Optional[str],
        turn: int,
        already_have: TradeCraft,
    ) -> Optional[str]:
        """Decide which tradecraft field to probe for next, or None."""
        if turn >= 6:
            return None  # don't over-engage past 6 turns
        triggers = _ENGAGEMENT_TRIGGERS
        hit = (classification in triggers) or (actor_type in triggers)
        if not hit:
            return None

        # Probe whichever slot is still empty; priority: tool → goal → infra → target
        if not already_have.tool:
            return "tool"
        if not already_have.goal:
            return "goal"
        if not already_have.infra:
            return "infra"
        if not already_have.target:
            return "target"
        return None

    async def make_probe(
        self,
        assistant_reply: str,
        *,
        target_field: str,
    ) -> str:
        """
        Generate a short in-character probe sentence to append to the
        assistant reply. Falls back to a static template if LLM unavailable.
        """
        templates = _PROBE_TEMPLATES.get(target_field) or _PROBE_TEMPLATES["goal"]

        try:
            backend = get_backend()
            sys_p = _PROBE_SYSTEM_PROMPT.format(target_field=target_field)
            out = await backend.complete(
                messages=[{"role": "user", "content": (assistant_reply or "")[-1200:]}],
                system_prompt=sys_p,
                temperature=0.7,
                max_tokens=40,
            )
            if out:
                out = out.strip().strip('"').strip("'").splitlines()[0].strip()
                if 5 <= len(out) <= 180:
                    return out
        except Exception:
            pass

        # Static fallback
        import random
        return random.choice(templates)

    # --- convenience: produce the full response with probe appended ----------

    def append_probe(self, assistant_reply: str, probe: str) -> str:
        if not probe:
            return assistant_reply
        sep = "\n\n" if assistant_reply and not assistant_reply.endswith("\n") else ""
        return f"{assistant_reply}{sep}{probe}"


# ── Singleton ──────────────────────────────────────────────────────────────────

_engine: Optional[EngagementEngine] = None


def get_engagement_engine() -> EngagementEngine:
    global _engine
    if _engine is None:
        _engine = EngagementEngine()
    return _engine
