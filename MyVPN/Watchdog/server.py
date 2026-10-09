"""Optional APNs watchdog. Run behind an HTTPS reverse proxy; never logs tokens."""
import base64
import hmac
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = re.compile(r"^(?:[0-9a-f]{2})+$")  # APNs tokens are opaque and variable-length.

@contextmanager
def database():
    connection = sqlite3.connect(os.environ.get("WATCHDOG_DATABASE", "watchdog.sqlite"))
    connection.execute("CREATE TABLE IF NOT EXISTS installations (id TEXT PRIMARY KEY, token TEXT NOT NULL)")
    try:
        with connection:
            yield connection
    finally:
        connection.close()

def validate_registration(value):
    if not isinstance(value, dict) or set(value) != {"id", "token"}:
        raise ValueError("Registration accepts only an installation ID and APNs token")
    identifier, token = value.get("id"), value.get("token")
    if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
        raise ValueError("Invalid identifier")
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise ValueError("Invalid token")
    return identifier, token

def push_headers(jwt, topic):
    return {"authorization": "bearer " + jwt, "apns-topic": topic,
            "apns-push-type": "background", "apns-priority": "5",
            "apns-collapse-id": "policy-check", "apns-expiration": str(int(time.time()) + 3600)}

def provider_jwt():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=")
    header = encode(json.dumps({"alg": "ES256", "kid": os.environ["APNS_KEY_ID"]}).encode())
    claims = encode(json.dumps({"iss": os.environ["APNS_TEAM_ID"], "iat": int(time.time())}).encode())
    message = header + b"." + claims
    key = serialization.load_pem_private_key(Path(os.environ["APNS_KEY_FILE"]).read_bytes(), password=None)
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return (message + b"." + encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))).decode()

def send_checks():
    import httpx
    host = "api.sandbox.push.apple.com" if os.environ.get("APNS_ENVIRONMENT") == "sandbox" else "api.push.apple.com"
    jwt = provider_jwt()
    with database() as connection, httpx.Client(http2=True, timeout=15) as client:
        rows = connection.execute("SELECT id, token FROM installations").fetchall()
        for identifier, token in rows:
            try:
                response = client.post(f"https://{host}/3/device/{token}", headers=push_headers(jwt, os.environ["APNS_TOPIC"]), json={"aps": {"content-available": 1}})
            except httpx.RequestError:
                print("APNs request unavailable; continuing remaining checks", flush=True)
                continue
            try:
                body = response.json() if response.content else {}
                reason = body.get("reason") if isinstance(body, dict) else None
            except ValueError:
                reason = None
            if response.status_code == 410 or reason in ("BadDeviceToken", "DeviceTokenNotForTopic"):
                connection.execute("DELETE FROM installations WHERE id = ? AND token = ?", (identifier, token))
            elif response.status_code not in (200, 429, 500, 503):
                print("APNs provider configuration requires attention", flush=True)

def validated_interval():
    interval = int(os.environ.get("WATCHDOG_INTERVAL_SECONDS", "2700"))
    if not 1800 <= interval <= 3600:
        raise ValueError("Interval must be 30–60 minutes")
    return interval

def watchdog():
    interval = validated_interval()
    while True:
        try:
            send_checks()
        except Exception:
            print("Watchdog check failed; retrying next interval", flush=True)
        time.sleep(interval)

class RegistrationHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        # Suppress HTTP request logging to avoid retaining device identifiers.
        pass
    def do_POST(self):
        if self.path != "/registrations":
            self.send_error(404); return
        expected = "Bearer " + os.environ["REGISTRATION_BEARER"]
        if not hmac.compare_digest(self.headers.get("Authorization", "").encode("utf-8"), expected.encode("utf-8")):
            self.send_error(401); return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 1024: raise ValueError("Invalid length")
            identifier, token = validate_registration(json.loads(self.rfile.read(size)))
            with database() as connection:
                connection.execute("INSERT INTO installations VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET token=excluded.token", (identifier, token))
        except (ValueError, TypeError, AttributeError):
            self.send_error(400); return
        self.send_response(204); self.end_headers()

if __name__ == "__main__":
    os.umask(0o077)
    if len(os.environ.get("REGISTRATION_BEARER", "")) < 32:
        raise RuntimeError("Provision a strong registration bearer secret")
    for required in ("APNS_KEY_ID", "APNS_TEAM_ID", "APNS_TOPIC", "APNS_KEY_FILE"):
        if not os.environ.get(required): raise RuntimeError("Missing server configuration")
    validated_interval()  # Fail startup rather than silently losing the watchdog thread.
    threading.Thread(target=watchdog, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PORT", "8080"))), RegistrationHandler).serve_forever()
