"""
OWASP + MITRE ATLAS mappings for LLM, MCP, agentic, and voice attack surfaces.

The mappings are intentionally pragmatic: they turn observed behavior into
security categories analysts can filter on during triage and replay.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TaxonomyMapping:
    framework: Optional[str] = None
    attack_chain_id: Optional[str] = None
    attack_stage: Optional[str] = None
    owasp_categories: list[str] = field(default_factory=list)
    mitre_atlas_tags: list[str] = field(default_factory=list)
    voice_profile: Optional[str] = None
    voice_metadata: dict = field(default_factory=dict)


def detect_framework(
    user_agent: str | None,
    headers: dict | None,
    body_parsed: dict | None,
    path: str,
) -> Optional[str]:
    ua = (user_agent or "").lower()
    lower_headers = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    body_text = str(body_parsed or "").lower()

    candidates = [
        ("cursor", ["cursor/", "cursor"]),
        ("claude_desktop", ["claude-desktop"]),
        ("copilot", ["copilot", "github-copilot"]),
        ("continue", ["continue-dev"]),
        ("cline", ["cline/"]),
        ("aider", ["aider"]),
        ("langchain", ["langchain"]),
        ("litellm", ["litellm"]),
        ("llamaindex", ["llamaindex"]),
        ("crewai", ["crewai"]),
        ("autogen", ["autogen"]),
        ("dspy", ["dspy"]),
        ("openai_sdk", ["openai-python", "openai/"]),
        ("openai_agents_sdk", ["openai-agents", "agents sdk", "agent runner"]),
        ("anthropic_sdk", ["anthropic-sdk", "anthropic"]),
        ("ollama", ["ollama"]),
        ("postman", ["postman"]),
        ("insomnia", ["insomnia"]),
    ]

    for label, needles in candidates:
        haystacks = [ua, body_text, " ".join(f"{k}:{v}" for k, v in lower_headers.items())]
        if any(needle in hay for needle in needles for hay in haystacks):
            return label

    if path.startswith("/mcp"):
        return "mcp_client"
    if path == "/v1/realtime":
        return "realtime_agent"
    return None


def map_taxonomy(
    *,
    path: str,
    protocol: str,
    classification: str,
    headers: dict | None,
    body_raw: str | None,
    body_parsed: dict | None,
    api_key: str | None,
    has_tool_calls: bool,
    framework: Optional[str],
    agent_type: Optional[str],
) -> TaxonomyMapping:
    body = (body_raw or "").lower()
    mapping = TaxonomyMapping(framework=framework)

    # Attack stage
    if path in ("/v1/models", "/v1/files", "/v1/organization/users", "/v1/organization/projects", "/mcp", "/.well-known/mcp.json"):
        mapping.attack_stage = "recon"
    elif "submit_tool_outputs" in path or has_tool_calls:
        mapping.attack_stage = "execution"
    elif classification in ("data_exfil", "prompt_harvester"):
        mapping.attack_stage = "exfiltration"
    else:
        mapping.attack_stage = "access"

    # OWASP categories
    if "prompt" in body or classification == "prompt_harvester" or "submit_tool_outputs" in path:
        mapping.owasp_categories.append("OWASP-LLM:Prompt Injection")
    if path.startswith("/mcp") or has_tool_calls:
        mapping.owasp_categories.append("OWASP-Agentic:Tool Misuse / Excessive Agency")
    if classification == "data_exfil" or any(x in body for x in [".env", "/etc/passwd", "database://", "file://"]):
        mapping.owasp_categories.append("OWASP-LLM:Sensitive Information Disclosure")
    if path in ("/api/chat", "/api/generate", "/v1/realtime"):
        mapping.owasp_categories.append("OWASP-Agentic:Agent Surface Expansion")
    if framework in {"cursor", "claude_desktop", "continue", "mcp_client"}:
        mapping.owasp_categories.append("OWASP-Agentic:Untrusted Plugin / Tool Ecosystem")

    # MITRE ATLAS tags
    if classification == "prompt_harvester" or "ignore previous" in body:
        mapping.mitre_atlas_tags.append("MITRE-ATLAS:AML.T0051 LLM Prompt Injection")
    if "system prompt" in body or "instructions" in body:
        mapping.mitre_atlas_tags.append("MITRE-ATLAS:AML.T0056 Extract LLM System Prompt")
    if classification == "data_exfil":
        mapping.mitre_atlas_tags.append("MITRE-ATLAS:AML.T0057 LLM Data Leakage")
    if has_tool_calls or "submit_tool_outputs" in path or path.startswith("/mcp"):
        mapping.mitre_atlas_tags.append("MITRE-ATLAS:AML.T0086 Exfiltration via AI Agent Tool Invocation")
    if api_key and path.startswith("/v1/"):
        mapping.mitre_atlas_tags.append("MITRE-ATLAS:AML.T0024 Exfiltration via AI Inference API")
    if classification in ("scanner", "recon"):
        mapping.mitre_atlas_tags.append("MITRE-ATLAS:Reconnaissance")

    # Voice / realtime
    if path == "/v1/realtime":
        session = body_parsed.get("session", {}) if isinstance(body_parsed, dict) else {}
        mapping.voice_profile = session.get("voice") or _guess_voice_from_body(body_parsed)
        mapping.voice_metadata = {
            "modalities": session.get("modalities"),
            "turn_detection": session.get("turn_detection"),
            "input_audio_format": session.get("input_audio_format"),
            "output_audio_format": session.get("output_audio_format"),
            "tools": session.get("tools", []),
            "agent_type": agent_type,
        }
        mapping.owasp_categories.append("OWASP-Agentic:Realtime / Voice Agent Exposure")

    mapping.owasp_categories = sorted(set(mapping.owasp_categories))
    mapping.mitre_atlas_tags = sorted(set(mapping.mitre_atlas_tags))
    return mapping


def _guess_voice_from_body(body_parsed: dict | None) -> Optional[str]:
    if not isinstance(body_parsed, dict):
        return None
    for key in ("voice", "speaker", "persona"):
        if body_parsed.get(key):
            return str(body_parsed[key])
    return None
