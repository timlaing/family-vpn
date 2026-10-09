"""Family VPN control dashboard. Run one worker behind an HTTPS reverse proxy."""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from .commands import Commands, ACTIONS
from .provisioning import VPNProvisioning
from .administrator import AdministratorProvisioning
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for

CONNECTIONS = {"connected", "connecting", "reasserting", "disconnecting", "disconnected", "invalid"}
INGRESS_FLAG = "vpnweb.ingress"
TOKEN = re.compile(r"^(?:[0-9a-f]{2})+$")

@dataclass
class Settings:
    database: str = "data/vpnweb.sqlite"
    admin_secret: str = field(default="", repr=False)
    enrollment_secret: str = field(default="", repr=False)
    session_secret: str = field(default="", repr=False)
    apns_key_file: str = ""
    apns_key_id: str = ""
    apns_team_id: str = ""
    apns_topic: str = "uk.co.laingcorp.myvpn"
    apns_environment: str = "sandbox"
    push_mode: str = "direct"
    relay_url: str = "https://push.family-vpn.workers.dev"
    relay_callback: str = ""
    relay_server: str = ""
    relay_registered_server: str = ""
    relay_secret: str = field(default="", repr=False)
    relay_enrollment: str = field(default="", repr=False)
    relay_limit: int = 10
    interval: int = 2700
    automatic: bool = True
    secure_cookie: bool = True
    demo: bool = False

    @classmethod
    def from_environment(cls):
        return cls(database=os.getenv("VPNWEB_DATABASE", "data/vpnweb.sqlite"),
                   admin_secret=os.getenv("ADMIN_BEARER", ""),
                   enrollment_secret=os.getenv("REGISTRATION_BEARER", ""),
                   session_secret=os.getenv("SESSION_SECRET", ""),
                   apns_key_file=os.getenv("APNS_KEY_FILE", ""),
                   apns_key_id=os.getenv("APNS_KEY_ID", ""),
                   apns_team_id=os.getenv("APNS_TEAM_ID", ""),
                   apns_topic=os.getenv("APNS_TOPIC", "uk.co.laingcorp.myvpn"),
                   apns_environment=os.getenv("APNS_ENVIRONMENT", "sandbox"),
                   push_mode=os.getenv("PUSH_MODE", "direct"), relay_url=os.getenv("RELAY_URL", "https://push.family-vpn.workers.dev"),
                   relay_callback=os.getenv("RELAY_CALLBACK", ""), relay_secret=os.getenv("RELAY_TOKEN", ""),
                   relay_enrollment=os.getenv("RELAY_ENROLLMENT_BEARER", ""),
                   relay_registered_server=os.getenv("RELAY_REGISTERED_SERVER", ""),
                   relay_limit=int(os.getenv("RELAY_PER_MINUTE", "10")),
                   interval=int(os.getenv("WATCHDOG_INTERVAL_SECONDS", "2700")),
                   automatic=os.getenv("AUTO_PUSH", "true").lower() == "true",
                   secure_cookie=os.getenv("LOCAL_HTTP", "false").lower() != "true")

    def validate(self):
        from .relay_protocol import https_url
        from urllib.parse import urlsplit
        for value in (self.relay_url, self.relay_callback):
            if value: https_url(value)
        if self.relay_url and urlsplit(self.relay_url).path not in ("", "/"):
            raise ValueError("Host the relay at the HTTPS origin root")
        if self.push_mode not in {"direct", "relay"} or type(self.relay_limit) is not int or not 1 <= self.relay_limit <= 100:
            raise ValueError("Use direct/relay push mode and a limit between 1 and 100")
        if self.apns_environment not in ("sandbox", "production") or not 1800 <= self.interval <= 3600:
            raise ValueError("Use sandbox/production APNs and a 30–60 minute interval")
        if not self.demo and any(len(value) < 32 for value in (self.admin_secret, self.enrollment_secret, self.session_secret)):
            raise ValueError("Provision ADMIN_BEARER, REGISTRATION_BEARER and SESSION_SECRET (32+ characters)")

    @property
    def apns_ready(self):
        if self.push_mode == "relay":
            return bool(self.relay_url and self.relay_callback and len(self.relay_secret) >= 32 and self.relay_server and self.relay_server == self.relay_registered_server)
        return bool(self.apns_key_file and self.apns_key_id and self.apns_team_id)


class Database:
    def __init__(self, path):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY, token TEXT, status_hash TEXT NOT NULL,
                registered REAL NOT NULL, seen REAL, connection TEXT,
                policy_ok INTEGER, pushed REAL, push_result TEXT);
                CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
                device TEXT, kind TEXT NOT NULL, result TEXT NOT NULL);''')
        os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db: yield db
        finally: db.close()

    @staticmethod
    def event(db, identifier, kind, result):
        db.execute("INSERT INTO events(at,device,kind,result) VALUES(?,?,?,?)", (time.time(), identifier, kind, result))
        db.execute("DELETE FROM events WHERE seq NOT IN (SELECT seq FROM events ORDER BY seq DESC LIMIT 200)")

    def public_devices(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT id,registered,seen,connection,policy_ok,pushed,push_result,token IS NOT NULL AS registered_token,command_epoch IS NOT NULL AS command_capable,tunnel_seen,administrator_capable,vpn_capable FROM devices ORDER BY registered")]


class APNsSender:
    def __init__(self, settings):
        self.settings = settings
        self.jwt = None
        self.jwt_at = 0

    def provider_jwt(self):
        if self.jwt and time.time() - self.jwt_at < 3000: return self.jwt
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=")
        header = encode(json.dumps({"alg": "ES256", "kid": self.settings.apns_key_id}).encode())
        claims = encode(json.dumps({"iss": self.settings.apns_team_id, "iat": int(time.time())}).encode())
        message = header + b"." + claims
        key = serialization.load_pem_private_key(Path(self.settings.apns_key_file).read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("APNs requires a P-256 provider key")
        r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
        self.jwt = (message + b"." + encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))).decode()
        self.jwt_at = time.time()
        return self.jwt

    def send(self, token, command=None):
        if not self.settings.apns_ready: return "not_configured"
        try:
            jwt = self.provider_jwt()
            host = "api.sandbox.push.apple.com" if self.settings.apns_environment == "sandbox" else "api.push.apple.com"
            collapse = "policy-check"
            if command:
                action = json.loads(base64.b64decode(command["body"]))["action"]
                collapse = {"refresh_status":"remote-refresh", "reprovision_admin":"remote-admin", "reprovision_vpn":"remote-vpn"}.get(action,"remote-control")
            headers = {"authorization": "bearer " + jwt, "apns-topic": self.settings.apns_topic,
                       "apns-push-type": "background", "apns-priority": "5", "apns-collapse-id": collapse,
                       "apns-expiration": str(int(time.time()) + 3600)}
            with httpx.Client(http2=True, timeout=10) as client:
                response = client.post(f"https://{host}/3/device/{token}", headers=headers, json={"aps": {"content-available": 1}, **({"command": command} if command else {})})
            if response.status_code == 200: return "accepted"
            try:
                body = response.json()
                reason = body.get("reason") if isinstance(body, dict) else None
            except ValueError: reason = None
            if response.status_code == 410 or reason in {"BadDeviceToken", "DeviceTokenNotForTopic"}: return "invalid_token"
            if response.status_code in {429, 500, 503}: return "retry_later"
            return "provider_error"
        except httpx.RequestError: return "network_error"
        except (ValueError, OSError, TypeError, KeyError): return "provider_error"


class Dispatcher:
    def __init__(self, database, sender, settings, commands):
        self.database, self.sender, self.settings = database, sender, settings
        self.commands = commands
        self.lock = threading.Lock()
        self.running = False
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="apns")
        self.stop_event = threading.Event()
        self.future = None

    def trigger(self, identifier=None, commands_only=False):
        if self.settings.demo: return False
        with self.lock:
            if self.running: return False
            self.running = True
            self.future = self.executor.submit(self.run, identifier, commands_only)
        return True

    def run(self, identifier=None, commands_only=False):
        try:
            with self.database.connect() as db:
                rows = db.execute("SELECT id,token FROM devices WHERE token IS NOT NULL" + (" AND id=?" if identifier else ""), (identifier,) if identifier else ()).fetchall()
            for row in rows:
                command = self.commands.next_delivery(row["id"])
                if command is None and commands_only: continue
                try:
                    from .relay_client import PushSender
                    if isinstance(self.sender, PushSender):
                        result = self.sender.send(row["token"], command=self.commands.envelope(command) if command else None, device=row["id"])
                    else:
                        result = self.sender.send(row["token"], command=self.commands.envelope(command)) if command else self.sender.send(row["token"])
                    if command: self.commands.delivered(command["sequence"], result)
                except Exception: result = "provider_error"  # Never log request objects, tokens or key material.
                with self.database.connect() as db:
                    updated = db.execute("UPDATE devices SET pushed=?,push_result=?,token=CASE WHEN ?='invalid_token' THEN NULL ELSE token END WHERE id=? AND token=?",
                                         (time.time(), result, result, row["id"], row["token"]))
                    if updated.rowcount: self.database.event(db, row["id"], "push", result)
        finally:
            with self.lock: self.running = False

    def schedule(self):
        next_policy = time.monotonic() + self.settings.interval
        while not self.stop_event.wait(60):
            policy_due = time.monotonic() >= next_policy
            if policy_due: next_policy = time.monotonic() + self.settings.interval
            if self.settings.apns_ready: self.trigger(commands_only=not (policy_due and self.settings.automatic))

    def close(self):
        self.stop_event.set()
        self.executor.shutdown(wait=True)


def identifier(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value: raise ValueError("Invalid installation ID")
    return value

def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def equal(a, b): return hmac.compare_digest(a.encode(), b.encode())


class DashboardViews:
    """Per-app routes and security state, isolated from other app instances."""

    def __init__(self, app):
        self.app = app
        for name in ("settings", "database", "commands", "administrator", "vpn_provisioning", "dispatcher"):
            setattr(self, name, app.extensions[name])
        self.login_failures = {}
        self.login_lock = threading.Lock()
        self.report_lock = threading.Lock()
        self.report_buckets = {}
        app.before_request(self.security)
        app.after_request(self.headers)
        app.add_url_rule('/login', endpoint='login', view_func=self.login, methods=['GET', 'POST'])
        app.add_url_rule('/logout', endpoint='logout', view_func=self.logout, methods=['POST'])
        app.add_url_rule('/', endpoint='dashboard', view_func=self.dashboard, methods=['GET'])
        for page in ("provisioning", "administration", "activity"):
            app.add_url_rule('/'+page, endpoint=page, view_func=self.dashboard, methods=['GET'])
        app.add_url_rule('/vpn-provisioning', endpoint='configure_vpn_provisioning', view_func=self.configure_vpn_provisioning, methods=['POST'])
        app.add_url_rule('/administrator-password', endpoint='administrator_password', view_func=self.administrator_password, methods=['POST'])
        app.add_url_rule('/registrations', endpoint='register', view_func=self.register, methods=['POST'])
        app.add_url_rule('/status', endpoint='status', view_func=self.status, methods=['POST'])
        app.add_url_rule('/vpn-configuration', endpoint='device_vpn_configuration', view_func=self.device_vpn_configuration, methods=['GET'])
        app.add_url_rule('/commands', endpoint='pending_commands', view_func=self.pending_commands, methods=['GET'])
        app.add_url_rule('/command-results', endpoint='command_results', view_func=self.command_results, methods=['POST'])
        app.add_url_rule('/api/commands', endpoint='create_command', view_func=self.create_command, methods=['POST'])
        app.add_url_rule('/api/commands', endpoint='command_history', view_func=self.command_history, methods=['GET'])
        app.add_url_rule('/command', endpoint='command_form', view_func=self.command_form, methods=['POST'])
        app.add_url_rule('/api/devices', endpoint='devices', view_func=self.devices, methods=['GET'])
        app.add_url_rule('/api/push', endpoint='push', view_func=self.push, methods=['POST'])
        app.add_url_rule('/push', endpoint='push_form', view_func=self.push_form, methods=['POST'])
        app.add_url_rule('/configuration', endpoint='configuration', view_func=self.configuration, methods=['GET', 'POST'])
        app.add_url_rule('/advanced', endpoint='advanced', view_func=self.configuration, methods=['GET', 'POST'])
        app.add_url_rule('/relay-register', endpoint='relay_register', view_func=self.relay_register, methods=['POST'])
        app.add_url_rule('/relay-results', endpoint='relay_results', view_func=self.relay_results, methods=['POST'])
        app.add_url_rule('/health', endpoint='health', view_func=self.health, methods=['GET'])
        app.add_template_filter(self.when, 'when')
        app.context_processor(self.navigation_state)

    def limit_public_report(self):
        now = time.monotonic()
        keys = [("ip:" + (request.remote_addr or "unknown"),120), ("credential:" + digest(request.headers.get("Authorization", "")),20)]
        with self.report_lock:
            expired = [key for key, bucket in self.report_buckets.items() if bucket[0] <= now]
            for key in expired:
                del self.report_buckets[key]
            for key, maximum in keys:
                if key not in self.report_buckets:
                    if len(self.report_buckets) >= 2000: abort(429)
                    self.report_buckets[key] = [now+60,0]
                if self.report_buckets[key][1] >= maximum: abort(429)
            for key, _ in keys: self.report_buckets[key][1] += 1


    def bearer(self):
        value = request.headers.get("Authorization", "")
        return value[7:] if value.startswith("Bearer ") else ""


    def admin(self):
        return (not self.settings.demo and bool(self.bearer()) and equal(self.bearer(), self.settings.admin_secret)) or (not request.environ.get("vpnweb.home_assistant") and session.get("admin") is True)


    def security(self):
        if request.path == "/vpn-provisioning": request.max_content_length = 32768
        if request.content_length is not None and request.content_length > (request.max_content_length or self.app.config["MAX_CONTENT_LENGTH"]): abort(413)
        if self.settings.demo and request.method != "GET": abort(403)
        if request.path in {"/status", "/command-results"}: self.limit_public_report()
        if request.environ.get(INGRESS_FLAG):
            session["admin"] = True


    def headers(self, response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if not request.environ.get(INGRESS_FLAG): response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; frame-ancestors 'none'; form-action 'self'"
        if request.environ.get(INGRESS_FLAG):
            response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; frame-ancestors 'self'; form-action 'self'"
        return response


    def login(self):
        failed = False
        if request.method == "POST":
            address = request.remote_addr or "unknown"
            now = time.monotonic()
            with self.login_lock:
                attempts = [at for at in self.login_failures.get(address, []) if now - at < 60]
                if len(attempts) >= 5: abort(429)
                valid = equal(request.form.get("password", ""), self.settings.admin_secret)
                if valid: self.login_failures.pop(address, None)
                else:
                    if len(self.login_failures) >= 1000: self.login_failures.clear()
                    self.login_failures[address] = attempts + [now]
            if valid:
                session.clear(); session.update(admin=True)
                return redirect(url_for("dashboard"))
            failed = True
        return render_template("login.html", failed=failed)


    def logout(self):
        session.clear(); return redirect(url_for("login"))


    def navigation_state(self):
        provisioned = self.settings.demo or bool(self.vpn_provisioning.enrollment())
        administered = self.settings.demo or self.administrator.configured()
        ready = provisioned and administered
        devices = self.settings.demo or bool(self.database.public_devices())
        return {"available_pages": {"provisioning": True, "configuration": True, "advanced": True,
            "administration": provisioned, "dashboard": ready, "activity": ready and devices}}

    def dashboard(self):
        if not self.settings.demo and not session.get("admin"): return redirect(url_for("login"))
        available = self.navigation_state()["available_pages"]
        page = request.endpoint
        if page == "dashboard" and not available[page]:
            page = "administration" if available["administration"] else "provisioning"
        elif not available[page]:
            return redirect(url_for("dashboard"))
        with self.database.connect() as db:
            events = [dict(row) for row in db.execute("SELECT at,device,kind,result FROM events ORDER BY seq DESC LIMIT 30")]
        return render_template("dashboard.html", page=page, devices=self.database.public_devices(), events=events, demo=self.settings.demo,
                               configured=self.settings.apns_ready, environment=self.settings.apns_environment,
                               interval=self.settings.interval // 60, automatic=self.settings.automatic, running=self.dispatcher.running, commands=self.commands.public(), administrator_configured=self.administrator.configured(), vpn_provision=self.vpn_provisioning.enrollment())


    def configure_vpn_provisioning(self):
        if not session.get("admin"): abort(401)
        ssids = [ssid for ssid in request.form.getlist("trusted_ssid") if ssid != ""] if "trusted_ssid" in request.form else request.form.get("trusted_ssids", "").splitlines()
        try:
            ca = self.vpn_provisioning.certificate_pem(request.files.get("ca_file"), request.form.get("ca_pem", ""), request.form.get("remove_ca") == "true")
            value = self.vpn_provisioning.save(request.form.get("server"), request.form.get("remote_identifier"), ssids, ca)
            from .relay_protocol import server_key
            self.settings.relay_server = server_key(value["server"])
        except ValueError as exc: return str(exc), 400
        return redirect(url_for("provisioning"))


    def administrator_password(self):
        if not session.get("admin"): abort(401)
        try: self.administrator.set_password(request.form.get("password"),request.form.get("confirmation"))
        except ValueError: return "Use matching administrator passwords of at least 12 characters (maximum 1024 UTF-8 bytes).",400
        return redirect(url_for("administration"))


    def registration_payload(self):
        value = request.get_json(silent=True)
        try:
            if not isinstance(value, dict) or set(value) != {"id", "token"}: raise ValueError()
            device = identifier(value["id"])
            token = value["token"]
            administrator_only = token is None and request.headers.get("X-FamilyVPN-Administrator-Protocol") == "1"
            if not administrator_only and (not isinstance(token, str) or not TOKEN.fullmatch(token)): raise ValueError()
        except (ValueError, TypeError, KeyError): abort(400)
        return device, token

    def register(self):
        if not equal(self.bearer(), self.settings.enrollment_secret): abort(401)
        device, token = self.registration_payload()
        provision = self.administrator.enrollment() if request.headers.get("X-FamilyVPN-Administrator-Protocol") == "1" else None
        if request.headers.get("X-FamilyVPN-Administrator-Protocol") == "1" and provision is None:
            return jsonify(error="Set the device administrator password in the dashboard before enrollment"),409
        vpn = self.vpn_provisioning.enrollment() if request.headers.get("X-FamilyVPN-VPN-Protocol") in {"1", "2"} else None
        if request.headers.get("X-FamilyVPN-VPN-Protocol") in {"1", "2"} and vpn is None:
            return jsonify(error="Configure the VPN gateway and trusted Wi-Fi in the dashboard before enrollment"),409
        status_token = secrets.token_urlsafe(32)
        with self.database.connect() as db:
            db.execute("INSERT INTO devices(id,token,status_hash,registered) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET token=COALESCE(excluded.token,devices.token),status_hash=excluded.status_hash,registered=excluded.registered",
                       (device, token, digest(status_token), time.time()))
            epoch = str(uuid.uuid4()) if request.headers.get("X-FamilyVPN-Command-Protocol") == "1" else None
            db.execute("UPDATE devices SET command_epoch=?,administrator_capable=?,vpn_capable=? WHERE id=?", (epoch,int(provision is not None),int(request.headers.get("X-FamilyVPN-VPN-Protocol") == "2"),device))
            db.execute("UPDATE commands SET state='superseded' WHERE device=? AND state='pending'",(device,))
            self.database.event(db, device, "registration", "registered")
        return jsonify(status_token=status_token, **({"command_key": self.commands.public_key, "command_epoch": epoch} if epoch else {}), **({"administrator":provision} if provision else {}), **({"vpn":vpn} if vpn else {})), 201


    def status(self):
        value = request.get_json(silent=True)
        try:
            if not isinstance(value, dict) or set(value) != {"id", "connection", "policy_ok"}: raise ValueError()
            device = identifier(value["id"])
            if value["connection"] not in CONNECTIONS or type(value["policy_ok"]) is not bool: raise ValueError()
        except (ValueError, TypeError, KeyError): abort(400)
        with self.database.connect() as db:
            row = db.execute("SELECT status_hash FROM devices WHERE id=?", (device,)).fetchone()
            if row is None or not self.bearer() or not equal(digest(self.bearer()), row["status_hash"]): abort(401)
            db.execute("UPDATE devices SET seen=?,connection=?,policy_ok=? WHERE id=?", (time.time(), value["connection"], value["policy_ok"], device))
            self.database.event(db, device, "status", "policy_ok" if value["policy_ok"] else "policy_failed")
        return "", 204


    def scoped(self, device):
        with self.database.connect() as db:
            row=db.execute("SELECT status_hash FROM devices WHERE id=?",(device,)).fetchone()
            if row is None or not self.bearer() or not equal(digest(self.bearer()),row["status_hash"]): abort(401)


    def device_vpn_configuration(self):
        try:
            if set(request.args) != {"id", "request_id"}: raise ValueError()
            device = identifier(request.args["id"])
            request_id = identifier(request.args["request_id"])
        except (ValueError, KeyError): abort(400)
        self.scoped(device)
        with self.database.connect() as db:
            row = db.execute("SELECT c.vpn_json FROM commands c JOIN devices d ON c.device=d.id WHERE c.device=? AND c.request_id=? AND c.epoch=d.command_epoch AND c.action='reprovision_vpn' AND c.state='pending' AND c.expires_at>?", (device, request_id, int(time.time()))).fetchone()
        if row is None: abort(404)
        return self.app.response_class(row['vpn_json'], mimetype='application/json')


    def pending_commands(self):
        try:
            if set(request.args) != {"id"}: raise ValueError()
            device=identifier(request.args["id"])
        except (ValueError,KeyError): abort(400)
        self.scoped(device)
        with self.database.connect() as db: db.execute("UPDATE devices SET tunnel_seen=? WHERE id=?",(time.time(),device))
        return jsonify(commands=self.commands.pending(device))


    def command_results(self):
        value=request.get_json(silent=True)
        try:
            if not isinstance(value,dict) or set(value)!={"id","request_id","result"}: raise ValueError()
            device=identifier(value["id"]); request_id=identifier(value["request_id"])
            if value["result"] not in {"executed","failed"}: raise ValueError()
        except (ValueError,KeyError,TypeError): abort(400)
        self.scoped(device)
        try: self.commands.acknowledge(device,request_id,value["result"])
        except LookupError: abort(404)
        except RuntimeError: abort(409)
        return "",204


    def queue_command(self, device, action, duration):
        if not self.settings.apns_ready: return jsonify(error="APNs is not configured"),503
        try: request_id=self.commands.queue(device,action,duration)
        except ValueError: abort(400)
        except LookupError: abort(404)
        except RuntimeError: return jsonify(error="Update and re-enroll this installation"),409
        self.dispatcher.trigger(device,commands_only=True)
        return jsonify(result="pending",request_id=request_id),202


    def create_command(self):
        if not self.bearer() or not equal(self.bearer(),self.settings.admin_secret): abort(401)
        value=request.get_json(silent=True)
        try:
            if not isinstance(value,dict) or not {"id","action"} <= set(value) or set(value)-{"id","action","duration_seconds"}: raise ValueError()
            device=identifier(value["id"])
            action=value["action"]
            if not isinstance(action,str) or action not in ACTIONS: raise ValueError()
            duration=value.get("duration_seconds")
            if action=="suspend" and "duration_seconds" not in value: duration=3600
        except (ValueError,KeyError,TypeError): abort(400)
        return self.queue_command(device,action,duration)


    def command_history(self):
        if not self.admin(): abort(401)
        return jsonify(commands=self.commands.public())


    def command_form(self):
        if not session.get("admin"): abort(401)
        try:
            device=identifier(request.form.get("id"))
            action=request.form.get("action")
            raw=request.form.get("duration_seconds","3600")
            duration = None
            if action == "suspend" and raw != "manual":
                duration = int(raw)
        except (ValueError,TypeError): abort(400)
        response=self.queue_command(device,action,duration)
        if response[1]!=202: return response
        return redirect(url_for("dashboard"))


    def devices(self):
        if not self.admin(): abort(401)
        return jsonify(devices=self.database.public_devices())


    def push(self):
        if not self.bearer() or not equal(self.bearer(), self.settings.admin_secret): abort(401)
        value = request.get_json(silent=True)
        try:
            if not isinstance(value, dict) or set(value) - {"id"}: raise ValueError()
            device = identifier(value["id"]) if "id" in value else None
        except (ValueError, KeyError, TypeError): abort(400)
        return self.queue_push(device)


    def queue_push(self, device):
        if not self.settings.apns_ready: return jsonify(error="APNs is not configured"), 503
        if device and not any(row["id"] == device for row in self.database.public_devices()): abort(404)
        if not self.dispatcher.trigger(device): return jsonify(error="A check is already running"), 409
        return jsonify(result="queued"), 202


    def push_form(self):
        if not session.get("admin"): abort(401)
        device = request.form.get("id") or None
        try:
            if device: identifier(device)
        except ValueError: abort(400)
        response = self.queue_push(device)
        if response[1] != 202: return response
        return redirect(url_for("dashboard"))


    def configuration(self):
        manager = self.app.extensions.get("addon_configuration")
        if manager is None or not request.environ.get(INGRESS_FLAG): abort(404)
        error = None
        if request.method == "POST":
            try:
                with self.dispatcher.lock:
                    if self.dispatcher.running: abort(409)
                    manager.update(request.form, self.settings)
                    from .relay_client import PushSender
                    if isinstance(self.dispatcher.sender, PushSender): self.dispatcher.sender.direct.jwt = None
                    elif isinstance(self.dispatcher.sender, APNsSender): self.dispatcher.sender.jwt = None
                return redirect(url_for("advanced"))
            except ValueError:
                error = "Use valid push settings, HTTPS relay/callback URLs, a 30–60 minute interval and a provider key under /share or /data."
        from .relay_client import PushSender
        relay = self.dispatcher.sender.relay if isinstance(self.dispatcher.sender, PushSender) else None
        return render_template("configuration.html", settings=self.settings, error=error, relay_result=relay.last_result if relay else "not_contacted")


    def relay_register(self):
        from .relay_client import PushSender
        manager = self.app.extensions.get("addon_configuration")
        if manager is None or not request.environ.get(INGRESS_FLAG): abort(404)
        if not self.settings.relay_server or not self.settings.relay_enrollment: return "Save VPN provisioning and relay enrollment credentials first",400
        with self.dispatcher.lock:
            if self.dispatcher.running: abort(409)
            sender = self.dispatcher.sender
            if not isinstance(sender, PushSender): abort(409)
            try: result = sender.relay.register()
            except ValueError: return "Save valid HTTPS relay and callback addresses first",400
            if result != "registered": return "Relay registration failed; check the address, credentials and public callback route",502
            self.settings.relay_registered_server = self.settings.relay_server
            manager.save_settings(self.settings)
        return redirect(url_for("advanced"))

    def relay_results(self):
        from .relay_protocol import verify, server_key
        from urllib.parse import urlsplit
        if not self.settings.relay_secret or not self.settings.relay_callback: abort(401)
        value = request.get_json(silent=True)
        if not isinstance(value,dict) or value.get("server") != self.settings.relay_server: abort(400)
        nonce = verify(self.settings.relay_secret, urlsplit(self.settings.relay_callback).path, request.get_data(), request.headers)
        if nonce is None: abort(401)
        if value == {"server":server_key(self.settings.relay_server), "kind":"registration"}:
            pass
        else:
            try:
                if set(value) != {"server","kind","device","token","result"} or value["kind"] != "push_result": raise ValueError()
                identifier(value["device"])
                if value["result"] not in {"accepted","invalid_token","retry_later","network_error","provider_error","not_configured"}: raise ValueError()
                if not isinstance(value["token"],str) or not TOKEN.fullmatch(value["token"]): raise ValueError()
            except (ValueError,TypeError): abort(400)
        with self.database.connect() as db:
            db.execute("DELETE FROM relay_callbacks WHERE at<?",(time.time()-600,))
            try: db.execute("INSERT INTO relay_callbacks VALUES(?,?)",(nonce,time.time()))
            except sqlite3.IntegrityError: abort(409)
            if value["kind"] == "push_result":
                updated = db.execute("UPDATE devices SET pushed=?,push_result=?,token=CASE WHEN ?='invalid_token' THEN NULL ELSE token END WHERE id=? AND token=?",
                    (time.time(),value["result"],value["result"],value["device"],value["token"]))
                if updated.rowcount: self.database.event(db,value["device"],"relay_push",value["result"])
        return "",204

    def health(self): return jsonify(status="ok")


    def when(self, value):
        if value is None: return "Not received"
        from datetime import datetime, timezone
        return datetime.fromtimestamp(value, timezone.utc).strftime("%d %b %H:%M UTC")


def create_app(settings=None, sender=None):
    settings = settings or Settings.from_environment()
    settings.validate()
    os.umask(0o077)
    app = Flask(__name__)
    app.config.update(SECRET_KEY=settings.session_secret or secrets.token_hex(32), MAX_CONTENT_LENGTH=2048,
                      WTF_CSRF_FIELD_NAME="csrf",
                      SESSION_COOKIE_SECURE=settings.secure_cookie, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
    database = Database(settings.database)
    commands = Commands(database)
    administrator = AdministratorProvisioning(database)
    vpn_provisioning = VPNProvisioning(database)
    app.extensions["vpn_provisioning"] = vpn_provisioning
    from .relay_protocol import server_key
    from .relay_client import PushSender
    provision = vpn_provisioning.enrollment()
    settings.relay_server = server_key(provision["server"]) if provision else ""
    with database.connect() as db:
        db.execute("CREATE TABLE IF NOT EXISTS relay_callbacks (nonce TEXT PRIMARY KEY, at REAL NOT NULL)")
    dispatcher = Dispatcher(database, sender or PushSender(settings), settings, commands)
    app.extensions.update(database=database, dispatcher=dispatcher, settings=settings, commands=commands, administrator=administrator)
    DashboardViews(app)
    csrf = CSRFProtect(app)
    # Bearer/HMAC-authenticated REST writes are exempt; browser forms remain protected.
    for endpoint in ("register", "status", "command_results", "create_command", "push", "relay_results"):
        csrf.exempt(app.view_functions[endpoint])  # noqa: S4502
    app.register_error_handler(CSRFError, lambda error: ("CSRF validation failed", 403))
    if not settings.demo:
        threading.Thread(target=dispatcher.schedule, daemon=True, name="watchdog").start()
    return app


def seed_demo(app):
    db = app.extensions["database"]
    with db.connect() as connection:
        for index, state in enumerate(("connected", "disconnected", "connecting")):
            device = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"family-vpn-preview-{index}"))
            connection.execute("INSERT OR REPLACE INTO devices(id,token,status_hash,registered,seen,connection,policy_ok,pushed,push_result) VALUES(?,?,?,?,?,?,?,?,?)",
                               (device, "ab" * 32, "demo", time.time(), time.time() - index * 90, state, 1, time.time() - 180, "accepted"))
        db.event(connection, None, "preview", "Sample data; no push sent")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--port", type=int, default=8500)
    args = parser.parse_args()
    if args.demo:
        import tempfile
        settings = Settings(database=tempfile.mkdtemp(prefix="vpnweb-demo-") + "/demo.sqlite", demo=True, automatic=False, secure_cookie=False)
        app = create_app(settings); seed_demo(app)
    else: app = create_app()
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
