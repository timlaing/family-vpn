"""Local administration for the standalone VPN endpoint."""
import json
from datetime import timedelta
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
import time

from flask import Flask, abort, redirect, render_template, request, send_file, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from configure import create


def atomic(path, contents):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(contents)
    temporary.chmod(0o600)
    temporary.replace(path)


def create_app(data=None, authority=None):
    os.umask(0o077)
    data = Path(data or os.environ.get("VPN_DATA", "/data"))
    authority = Path(authority or os.environ.get("VPN_AUTHORITY", "/authority"))
    data.mkdir(parents=True, exist_ok=True)
    authority.mkdir(parents=True, exist_ok=True)
    admin = authority / "administrator.json"
    # Persist CSRF/session signing before the administrator has been created.
    session_key = authority / "session-key"
    if not session_key.exists():
        key = json.loads(admin.read_text())["session_key"] if admin.exists() else secrets.token_hex(32)
        atomic(session_key, key)
    app = Flask(__name__)
    app.config.update(SECRET_KEY=session_key.read_text(), MAX_CONTENT_LENGTH=16384,
                      PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      SESSION_COOKIE_SECURE=os.environ.get("VPN_COOKIE_SECURE") == "1")
    CSRFProtect(app)
    failures = {}

    @app.after_request
    def private_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.before_request
    def authenticate():
        if request.endpoint == "static":
            return None
        if not admin.exists() and request.endpoint != "initialize":
            return redirect(url_for("initialize"))
        if admin.exists() and request.endpoint == "initialize":
            if request.method == "POST":
                abort(409)
            return redirect(url_for("index") if session.get("administrator") else url_for("login"))
        if request.endpoint not in {"login", "initialize"} and not session.get("administrator"):
            return redirect(url_for("login"))

    @app.route("/initialize", methods=["GET", "POST"])
    def initialize():
        error = None
        if request.method == "POST":
            password = request.form.get("password", "")
            if not 16 <= len(password) <= 256:
                error = "Choose an administrator password of 16–256 characters."
            elif password != request.form.get("confirmation"):
                error = "The passwords do not match."
            else:
                # Exclusive creation prevents a second setup from replacing credentials.
                try:
                    with admin.open("x") as stream:
                        json.dump({"password": generate_password_hash(password),
                                   "session_key": app.config["SECRET_KEY"]}, stream)
                except FileExistsError:
                    abort(409)
                session.clear()
                session.permanent = True
                session["administrator"] = True
                return redirect(url_for("index"))
        return render_template("endpoint.html", page="initialize", error=error)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            # Bounded per-source login attempts; do not trust forwarded headers.
            now = time.monotonic()
            for source in list(failures):
                if now - failures[source][0] > 300:
                    del failures[source]
            attempts = failures.get(request.remote_addr, (now, 0))
            if attempts[1] >= 10:
                abort(429)
            if check_password_hash(json.loads(admin.read_text())["password"], request.form.get("password", "")):
                failures.pop(request.remote_addr, None)
                session.clear()
                session.permanent = True
                session["administrator"] = True
                return redirect(url_for("index"))
            if len(failures) >= 1024:
                abort(429)
            failures[request.remote_addr] = (attempts[0], attempts[1] + 1)
            error = "Incorrect administrator password"
        return render_template("endpoint.html", page="login", error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/", methods=["GET", "POST"])
    def index():
        settings_file = data / "settings.json"
        settings = json.loads(settings_file.read_text()) if settings_file.exists() else None
        error = None
        if request.method == "POST":
            if settings:
                abort(409)
            values = {key: request.form.get(key, "").strip() for key in ("server", "pool", "dns", "lan", "allowed")}
            try:
                # Generate away from live files; publish readiness only after all writes.
                with tempfile.TemporaryDirectory(dir=authority) as temporary:
                    generated = Path(temporary) / "generated"
                    create(generated, username=None, password=None, **values)
                    shutil.copytree(generated / "ca", authority / "ca")
                    shutil.copytree(generated / "swanctl", data / "swanctl")
                    shutil.copyfile(generated / "gateway.env", data / "gateway.env")
                atomic(settings_file, json.dumps(values))
                atomic(data / "accounts.json", json.dumps({}))
                atomic(data / "ready", "ready")
                return redirect(url_for("accounts"))
            except (ValueError, OSError) as exc:
                if not (data / "ready").exists():
                    shutil.rmtree(data / "swanctl", ignore_errors=True)
                    shutil.rmtree(authority / "ca", ignore_errors=True)
                    for path in (data / "gateway.env", settings_file, data / "accounts.json"):
                        path.unlink(missing_ok=True)
                error = str(exc)
        accounts = json.loads((data / "accounts.json").read_text()) if settings else {}
        return render_template("endpoint.html", page="endpoint", settings=settings, account_count=len(accounts), error=error)

    @app.route("/accounts", methods=["GET", "POST"])
    def accounts():
        if not (data / "ready").exists():
            return redirect(url_for("index"))
        account_file = data / "accounts.json"
        stored = json.loads(account_file.read_text())
        # Preserve installations created before account state was introduced.
        values = {name: {"password": value, "enabled": True} if isinstance(value, str) else value
                  for name, value in stored.items()}
        if request.method == "GET":
            return render_template("endpoint.html", page="accounts", accounts=values, settings=True)
        username = request.form.get("username", "")
        action = request.form.get("action", "add")
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", username):
            abort(400, "Use a simple account name")
        if action not in {"add", "password", "delete", "enable", "disable"}:
            abort(400, "Unknown account action")
        if action != "add" and username not in values:
            abort(404, "Account not found")
        if action == "add" and username in values:
            abort(409, "Account already exists; use Change password")
        if action == "delete":
            del values[username]
        elif action in {"enable", "disable"}:
            values[username]["enabled"] = action == "enable"
        else:
            password = request.form.get("password", "")
            if not 16 <= len(password) <= 256 or any(ord(c) < 33 or ord(c) > 126 or c in {'"', chr(92)} for c in password):
                abort(400, "Use a 16-256 character printable password without quotes or backslashes")
            if action == "add":
                values[username] = {"password": password, "enabled": True}
            else:
                values[username]["password"] = password
        contents = "secrets {\n" + "".join(
            f'    eap-{index} {{\n        id = "{name}"\n        secret = "{account["password"]}"\n    }}\n'
            for index, (name, account) in enumerate(sorted(values.items())) if account["enabled"]) + "}\n"
        atomic(data / "swanctl/conf.d/family-vpn-secrets.conf", contents)
        atomic(account_file, json.dumps(values))
        return redirect(url_for("accounts", changed="1"))

    @app.get("/ca.pem")
    def certificate():
        path = data / "swanctl/x509ca/family-vpn-ca.pem"
        if not path.exists():
            abort(404)
        return send_file(path, as_attachment=True, download_name="family-vpn-ca.pem")

    return app
