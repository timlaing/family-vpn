#!/usr/bin/env python3
"""Require matching dependency locks for standalone and Supervisor builds."""

from pathlib import Path

root = Path(__file__).resolve().parent.parent
if (root / "requirements.lock").read_bytes() != (
    root / "family_vpn/requirements.lock"
).read_bytes():
    raise SystemExit(
        "Runtime locks differ; synchronize requirements.lock and family_vpn/requirements.lock"
    )
print("Runtime locks match")
