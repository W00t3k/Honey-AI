"""
`python -m honeypot` → runs the payload validator.

For discoverability we also accept the explicit form
`python -m honeypot.validate_payloads`.
"""

from honeypot.validate_payloads import main

if __name__ == "__main__":
    raise SystemExit(main())
