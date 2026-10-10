#!/usr/bin/env python3
"""Require matching dependency locks for standalone and Supervisor builds."""

from pathlib import Path

root = Path(__file__).resolve().parent.parent
runtime = (root / "requirements.lock").read_bytes()
for relative in ("family_vpn/requirements.lock", "family_vpn/requirements.txt"):
    if (root / relative).read_bytes() != runtime:
        raise SystemExit(f"Runtime locks differ; synchronize requirements.lock and {relative}")
print("Runtime locks and add-on dependency manifest match")
