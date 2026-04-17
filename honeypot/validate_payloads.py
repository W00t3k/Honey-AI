"""
Standalone validator for config/injection_payloads.yaml.

Exit codes:
    0 — valid
    1 — file missing / parse failure
    2 — validation errors
    3 — forbidden identity leaked into a payload

Run:
    python -m honeypot.validate_payloads [path]
    python -m honeypot                     [path]     # alias

Prints:
    - Post-load SHA-256 of the raw file bytes
    - Byte-level presence checks (ZW code points + literal 0x1B)
    - Layered structural checks
    - Forbidden-identity guard
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="honeypot.validate_payloads",
        description="Lint config/injection_payloads.yaml — byte-level, structural, leak checks.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to injection_payloads.yaml (default: config/injection_payloads.yaml)",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Only print errors.",
    )
    args = parser.parse_args(argv)

    # Defer heavy imports until after arg parse so --help is fast.
    from services.injection_payloads import (
        DEFAULT_PATH,
        FORBIDDEN_IDENTITIES,
        _contains_any_zw,
        _iter_strings,
        load_payloads,
        validate_loaded,
    )

    path = Path(args.path).expanduser() if args.path else DEFAULT_PATH

    if not path.exists():
        print(f"ERROR: {path} does not exist", file=sys.stderr)
        return 1

    try:
        bundle = load_payloads(path)
    except Exception as e:
        print(f"ERROR: load failed — {e}", file=sys.stderr)
        return 1

    errors = validate_loaded(bundle)

    # Additional byte-level echo (for human review)
    la = bundle.get("layer_a") or {}

    if not args.quiet:
        print(f"Payloads:       {path}")
        print(f"SHA-256:        {bundle.get('_sha256', '')}")
        print(f"Layer A enabled: {la.get('enabled', False)}")
        print(f"Layer B enabled: {(bundle.get('layer_b') or {}).get('enabled', False)}")
        print(f"Layer C enabled: {(bundle.get('layer_c') or {}).get('enabled', False)}")
        print(f"Decoys:         {len(bundle.get('decoy_endpoints') or [])}")
        print(
            "Model descriptions: "
            f"{len(la.get('model_descriptions') or [])} entries"
        )
        for entry in la.get("model_descriptions") or []:
            hidden = entry.get("hidden", "")
            print(
                f"  - {entry.get('model_id'):<20} "
                f"hidden_len={len(hidden)} zw={'y' if _contains_any_zw(hidden) else 'n'}"
            )
        for kind, body in (la.get("error_messages") or {}).items():
            if isinstance(body, dict):
                ansi = body.get("hidden_ansi", "")
                print(
                    f"  error:{kind:<18} "
                    f"ansi_len={len(ansi)} has_0x1B={'y' if chr(0x1B) in ansi else 'n'}"
                )

    # Identity-leak scan (validate_loaded already reports, but surface loudly)
    leaked = []
    for s in _iter_strings(bundle):
        for bad in FORBIDDEN_IDENTITIES:
            if bad and bad in s:
                leaked.append(bad)
    if leaked:
        print(f"FORBIDDEN IDENTITIES FOUND: {sorted(set(leaked))}", file=sys.stderr)
        return 3

    if errors:
        print("\nVALIDATION ERRORS:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 2

    if not args.quiet:
        print("\nOK — payloads validated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
