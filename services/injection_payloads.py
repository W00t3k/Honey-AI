"""
Layered prompt-injection payload loader, validator, and runtime picker.

Loads config/injection_payloads.yaml and exposes:

- `get_payloads()` — cached, validated payload bundle
- `score_suspicion(request)` — Layer B heuristic scorer
- `pick_layer_a_model_description(model_id)` — returns {visible, hidden}
- `pick_layer_a_error(kind)` — returns {visible, hidden_ansi}
- `pick_layer_b_template()` — random B template (already includes separator)
- `pick_layer_c_template()` — random C template
- `payloads_sha256()` — raw-file digest for provenance logging
- `validate_loaded(bundle)` — post-load structural + byte-level checks

YAML strings are interpreted by PyYAML (double-quoted scalars decode
`\\u200b` and `\\x1b`). A fallback pass promotes any `*_ansi` field that
arrived as a literal escape-string into its byte form, so the validator
always sees the raw 0x1B byte. Binary fields tagged `!!binary` are
decoded as bytes and UTF-8 round-tripped.
"""

from __future__ import annotations

import codecs
import hashlib
import os
import random
import re
from pathlib import Path
from threading import Lock
from typing import Any, Optional

import yaml
from rich.console import Console

console = Console()

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "injection_payloads.yaml"
BAD_ASNS_PATH = Path(__file__).resolve().parent.parent / "config" / "bad_asns.txt"

# Identity strings that MUST NOT appear in any template (seeding/research leakage check)
FORBIDDEN_IDENTITIES = {
    "W00t3k",
    # Research identity goes here when known — intentionally empty until operator sets env var.
}
# Environment override: comma-separated additional forbidden substrings.
_env_forbidden = os.getenv("INJECTION_FORBIDDEN_IDENTITIES", "")
if _env_forbidden:
    for item in _env_forbidden.split(","):
        item = item.strip()
        if item:
            FORBIDDEN_IDENTITIES.add(item)


# ── Zero-width char detection ─────────────────────────────────────────────────

_ZW_CODEPOINTS = ("\u200b", "\u200c", "\u200d", "\u2060")


def _contains_any_zw(s: str) -> bool:
    return any(c in s for c in _ZW_CODEPOINTS)


def _looks_like_escape_literal(s: str) -> bool:
    """Detect strings that contain the literal 4-char escape `\\xHH` or `\\uHHHH`."""
    return bool(re.search(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", s))


# ── Loader ────────────────────────────────────────────────────────────────────

class PayloadLoadError(RuntimeError):
    pass


class PayloadValidationError(RuntimeError):
    pass


def _promote_escape_strings(node: Any) -> Any:
    """
    Walk the loaded YAML tree. Any string in an `*_ansi` field that still
    contains the literal characters '\\x' or '\\u' is promoted via
    `unicode_escape` decoding so the byte form is present at runtime.
    """
    if isinstance(node, dict):
        for k, v in list(node.items()):
            if isinstance(v, str) and k.endswith("_ansi") and _looks_like_escape_literal(v):
                try:
                    node[k] = codecs.decode(v, "unicode_escape")
                except Exception:
                    pass
            else:
                node[k] = _promote_escape_strings(v)
    elif isinstance(node, list):
        return [_promote_escape_strings(x) for x in node]
    return node


def _binary_to_text(node: Any) -> Any:
    """Convert any bytes (from `!!binary` tags) to UTF-8 strings."""
    if isinstance(node, dict):
        return {k: _binary_to_text(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_binary_to_text(x) for x in node]
    if isinstance(node, (bytes, bytearray)):
        return bytes(node).decode("utf-8")
    return node


def load_payloads(path: Path = DEFAULT_PATH) -> dict:
    """Load, promote, and return the payload bundle. Does NOT validate."""
    if not path.exists():
        raise PayloadLoadError(f"Payloads file not found: {path}")

    with open(path, "rb") as f:
        raw = f.read()

    try:
        bundle = yaml.safe_load(raw.decode("utf-8"))
    except yaml.YAMLError as e:
        raise PayloadLoadError(f"YAML parse failed: {e}") from e

    if not isinstance(bundle, dict):
        raise PayloadLoadError("Top-level payload must be a mapping")

    bundle = _binary_to_text(bundle)
    bundle = _promote_escape_strings(bundle)
    bundle["_sha256"] = hashlib.sha256(raw).hexdigest()
    bundle["_source_path"] = str(path)
    return bundle


# ── Validator ─────────────────────────────────────────────────────────────────

def _iter_strings(node: Any):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _iter_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _iter_strings(v)


def validate_loaded(bundle: dict) -> list[str]:
    """
    Run structural + byte-level checks. Returns list of error strings.
    Empty list = valid.
    """
    errors: list[str] = []

    for required in ("layer_a", "layer_b", "layer_c", "decoy_endpoints"):
        if required not in bundle:
            errors.append(f"Missing top-level section: {required}")

    # Layer A: zero-width in hidden fields, ANSI byte in *_ansi fields
    layer_a = bundle.get("layer_a") or {}
    for entry in (layer_a.get("model_descriptions") or []):
        h = entry.get("hidden", "")
        if not isinstance(h, str) or not h:
            errors.append(f"layer_a.model_descriptions[{entry.get('model_id')}].hidden empty")
            continue
        if not _contains_any_zw(h):
            errors.append(
                f"layer_a.model_descriptions[{entry.get('model_id')}].hidden missing "
                f"literal zero-width code point"
            )
        if _looks_like_escape_literal(h):
            errors.append(
                f"layer_a.model_descriptions[{entry.get('model_id')}].hidden still contains "
                f"escape literal after loader promotion"
            )

    for kind, body in (layer_a.get("error_messages") or {}).items():
        ansi = body.get("hidden_ansi", "") if isinstance(body, dict) else ""
        if not isinstance(ansi, str) or not ansi:
            errors.append(f"layer_a.error_messages.{kind}.hidden_ansi empty")
            continue
        if "\x1b" not in ansi:
            errors.append(
                f"layer_a.error_messages.{kind}.hidden_ansi missing literal 0x1B byte"
            )
        if _looks_like_escape_literal(ansi):
            errors.append(
                f"layer_a.error_messages.{kind}.hidden_ansi still contains escape literal"
            )

    # Layers B/C: must have at least one template
    for layer_name in ("layer_b", "layer_c"):
        layer = bundle.get(layer_name) or {}
        templates = layer.get("templates") or []
        if not templates:
            errors.append(f"{layer_name}.templates empty")
        for i, t in enumerate(templates):
            if not isinstance(t, str) or not t.strip():
                errors.append(f"{layer_name}.templates[{i}] not a non-empty string")

    # Suspicion config
    lb = bundle.get("layer_b") or {}
    triggers = lb.get("suspicion_triggers") or {}
    if not isinstance(triggers, dict) or not triggers:
        errors.append("layer_b.suspicion_triggers must be a non-empty map")
    thresh = lb.get("suspicion_threshold", None)
    if not isinstance(thresh, int) or thresh <= 0:
        errors.append("layer_b.suspicion_threshold must be a positive int")

    # Decoys
    decoys = bundle.get("decoy_endpoints") or []
    seen_paths: set[tuple] = set()
    for i, d in enumerate(decoys):
        if not isinstance(d, dict):
            errors.append(f"decoy_endpoints[{i}] not a mapping")
            continue
        path = d.get("path")
        method = (d.get("method") or "GET").upper()
        resp = d.get("response") or {}
        if not isinstance(path, str) or not path.startswith("/"):
            errors.append(f"decoy_endpoints[{i}].path invalid")
        key = (method, path)
        if key in seen_paths:
            errors.append(f"decoy_endpoints: duplicate {method} {path}")
        seen_paths.add(key)
        if not isinstance(resp, dict) or "status" not in resp or "body" not in resp:
            errors.append(f"decoy_endpoints[{i}].response missing status/body")

    # Identity leak check + UTF-8 round-trip
    for s in _iter_strings(bundle):
        for bad in FORBIDDEN_IDENTITIES:
            if bad and bad in s:
                errors.append(f"Forbidden identity '{bad}' found in a payload string")
        try:
            s.encode("utf-8").decode("utf-8")
        except Exception:
            errors.append("Non-UTF-8 payload string present")

    return errors


# ── Cached singleton ──────────────────────────────────────────────────────────

_bundle: Optional[dict] = None
_bundle_lock = Lock()


def get_payloads(force_reload: bool = False, path: Path = DEFAULT_PATH) -> dict:
    """Return the cached bundle, loading + validating on first call."""
    global _bundle
    with _bundle_lock:
        if _bundle is None or force_reload:
            bundle = load_payloads(path)
            errs = validate_loaded(bundle)
            if errs:
                raise PayloadValidationError(
                    "Payload validation failed:\n  - " + "\n  - ".join(errs)
                )
            _bundle = bundle
    return _bundle


def payloads_sha256(path: Path = DEFAULT_PATH) -> str:
    """SHA-256 of the raw payload file bytes (for startup log + provenance)."""
    try:
        return get_payloads(path=path).get("_sha256", "")
    except Exception:
        if path.exists():
            return hashlib.sha256(path.read_bytes()).hexdigest()
        return ""


# ── Layer A pickers ───────────────────────────────────────────────────────────

def pick_layer_a_model_description(model_id: str) -> Optional[dict]:
    """Return {visible, hidden} for the given model_id, or None if not found."""
    try:
        bundle = get_payloads()
    except Exception:
        return None
    if not bundle.get("layer_a", {}).get("enabled", True):
        return None
    for entry in bundle.get("layer_a", {}).get("model_descriptions") or []:
        if entry.get("model_id") == model_id:
            return {"visible": entry.get("visible", ""), "hidden": entry.get("hidden", "")}
    return None


def pick_layer_a_error(kind: str) -> Optional[dict]:
    """Return {visible, hidden_ansi} for the given error kind."""
    try:
        bundle = get_payloads()
    except Exception:
        return None
    if not bundle.get("layer_a", {}).get("enabled", True):
        return None
    errs = bundle.get("layer_a", {}).get("error_messages") or {}
    e = errs.get(kind)
    if not isinstance(e, dict):
        return None
    return {"visible": e.get("visible", ""), "hidden_ansi": e.get("hidden_ansi", "")}


# ── Layer B suspicion heuristic ───────────────────────────────────────────────

_SDK_UA_RE = re.compile(
    r"(openai-python|anthropic|langchain|llamaindex|litellm|"
    r"instructor|autogen|crewai|dspy|openai/[0-9])",
    re.I,
)


def _load_bad_asns() -> set[int]:
    asns: set[int] = set()
    if not BAD_ASNS_PATH.exists():
        return asns
    try:
        for line in BAD_ASNS_PATH.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r"(?:AS)?(\d+)", s, re.I)
            if m:
                asns.add(int(m.group(1)))
    except Exception:
        pass
    return asns


_bad_asns_cache: Optional[set[int]] = None


def bad_asns() -> set[int]:
    global _bad_asns_cache
    if _bad_asns_cache is None:
        _bad_asns_cache = _load_bad_asns()
    return _bad_asns_cache


def score_suspicion(
    *,
    user_agent: str = "",
    auth_header: str = "",
    asn: Optional[int] = None,
    residential_proxy: bool = False,
    first_request_in_session: bool = False,
) -> dict:
    """
    Score a request against Layer B heuristics.
    Returns {score, triggered (bool), trigger_hits (dict of weight contributions)}.
    """
    try:
        bundle = get_payloads()
    except Exception:
        return {"score": 0, "triggered": False, "trigger_hits": {}}

    lb = bundle.get("layer_b") or {}
    weights = lb.get("suspicion_triggers") or {}
    threshold = int(lb.get("suspicion_threshold") or 5)

    hits: dict = {}
    score = 0

    if not user_agent:
        w = int(weights.get("missing_user_agent") or 0)
        if w:
            score += w
            hits["missing_user_agent"] = w

    # Malformed auth header: missing "Bearer " prefix OR non-ASCII OR too short
    if auth_header:
        bad_auth = False
        if not auth_header.lower().startswith(("bearer ", "basic ", "token ")):
            bad_auth = True
        elif len(auth_header) < 10:
            bad_auth = True
        if bad_auth:
            w = int(weights.get("malformed_auth_header") or 0)
            if w:
                score += w
                hits["malformed_auth_header"] = w

    if asn is not None and asn in bad_asns():
        w = int(weights.get("known_bad_asn") or 0)
        if w:
            score += w
            hits["known_bad_asn"] = w

    if residential_proxy:
        w = int(weights.get("residential_proxy_hit") or 0)
        if w:
            score += w
            hits["residential_proxy_hit"] = w

    if user_agent and not _SDK_UA_RE.search(user_agent):
        w = int(weights.get("non_sdk_client") or 0)
        if w:
            score += w
            hits["non_sdk_client"] = w

    if first_request_in_session:
        w = int(weights.get("first_request_in_session") or 0)
        if w:
            score += w
            hits["first_request_in_session"] = w

    return {
        "score": score,
        "triggered": score >= threshold,
        "trigger_hits": hits,
        "threshold": threshold,
    }


# ── Layer B / C template pickers ──────────────────────────────────────────────

def pick_layer_b_template() -> Optional[str]:
    try:
        bundle = get_payloads()
    except Exception:
        return None
    lb = bundle.get("layer_b") or {}
    if not lb.get("enabled", True):
        return None
    templates = lb.get("templates") or []
    return random.choice(templates) if templates else None


def pick_layer_c_template() -> Optional[str]:
    try:
        bundle = get_payloads()
    except Exception:
        return None
    lc = bundle.get("layer_c") or {}
    if not lc.get("enabled", True):
        return None
    templates = lc.get("templates") or []
    return random.choice(templates) if templates else None


def decoy_endpoints() -> list[dict]:
    try:
        bundle = get_payloads()
    except Exception:
        return []
    return list(bundle.get("decoy_endpoints") or [])
