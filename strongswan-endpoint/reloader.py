"""Apply credential changes inside the gateway and revoke only affected sessions."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time

from authentication import atomic
from reload_requests import requests


ALLOWED_ACTIONS = {"add", "enable", "disable", "delete", "password"}
REVOKE_ACTIONS = {"disable", "delete", "password"}


def text(value):
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def target_sessions(events, username):
    identifiers = []
    for event in events:
        for name, session in event.items():
            if text(name) != "family-vpn":
                continue
            identity = session.get("remote-eap-id", session.get("remote-id", b""))
            # Abort unidentified in-flight authentication using old credentials too.
            authenticating = text(session.get("state", b"")) != "ESTABLISHED" and not session.get("remote-eap-id")
            if text(identity) == username or authenticating:
                identifier = text(session["uniqueid"])
                if not identifier.isdecimal():
                    raise ValueError("Invalid gateway session identifier")
                identifiers.append(identifier)
    return identifiers


def terminate_account(username):
    import vici
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect("/var/run/charon.vici")
        session = vici.Session(connection)
        identifiers = target_sessions(list(session.list_sas()), username)
        for identifier in identifiers:
            # Consuming the generator confirms the VICI command completed.
            list(session.terminate({"ike-id": identifier, "force": "yes", "loglevel": "-1"}))
    return len(identifiers)


def apply_request(data, request, run=subprocess.run, terminate=terminate_account, radius=False):
    username = request.get("username", "")
    action = request.get("action", "")
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", username) or action not in ALLOWED_ACTIONS:
        raise ValueError("Invalid account reload request")
    if radius:
        return {"status": "applied", "message": "Local accounts retained; authentication is managed by RADIUS.",
                "disconnected": 0, "updated_at": time.time()}
    # --clear is essential: removed credentials must not remain in daemon memory.
    run(["swanctl", "--load-creds", "--clear", "--noprompt"], check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    disconnected = terminate(username) if action in REVOKE_ACTIONS else 0
    return {"status": "applied", "message": "Account changes applied to the VPN gateway.",
            "disconnected": disconnected, "updated_at": time.time()}


def process_pending(data, control, apply=apply_request, now=time.time):
    control = Path(control)
    control.mkdir(mode=0o700, parents=True, exist_ok=True)
    owner = 10001 if os.geteuid() == 0 else None
    if owner is not None:
        os.chown(control, owner, owner)
    paths = requests(data)
    active = {path.name for path in paths}
    for obsolete in control.glob("*.json"):
        if owner is not None:
            os.chown(obsolete, owner, owner)
        if obsolete.name not in active:
            obsolete.unlink()
    for path in paths:
        result = control / path.name
        previous = json.loads(result.read_text()) if result.exists() else {}
        if previous.get("status") == "applied":
            continue
        if now() - previous.get("updated_at", 0) < 5:
            continue
        try:
            if path.stat().st_size > 4096:
                raise ValueError("Reload request too large")
            status = apply(data, json.loads(path.read_text()))
        except Exception:
            # Retry transient daemon failures; do not expose CLI output or credentials.
            status = {"status": "error", "message": "Account changes saved, but the gateway could not apply them. Retrying automatically.",
                      "updated_at": now()}
        atomic(result, json.dumps(status), owner=owner)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True)
    parser.add_argument("--control", required=True)
    options = parser.parse_args()
    os.umask(0o077)
    # The running daemon uses the startup snapshot, not a pending backend edit.
    radius = Path("/run/family-vpn-auth.conf").stat().st_size > 0
    def apply(data, request):
        return apply_request(data, request, radius=radius)
    while True:
        process_pending(options.data, options.control, apply=apply)
        time.sleep(1)


if __name__ == "__main__":
    main()
