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
    if not admin.exists():
        password = os.environ.get("VPN_ADMIN_PASSWORD", "")
        if len(password) < 16:
            raise ValueError("Set VPN_ADMIN_PASSWORD to at least 16 characters")
        atomic(admin, json.dumps({"password": generate_password_hash(password), "session_key": secrets.token_hex(32)}))
    credentials = json.loads(admin.read_text())
    app = Flask(__name__)
    app.config.update(SECRET_KEY=credentials["session_key"], MAX_CONTENT_LENGTH=16384,
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
        if request.endpoint != "login" and not session.get("administrator"):
            return redirect(url_for("login"))

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
            if check_password_hash(credentials["password"], request.form.get("password", "")):
                failures.pop(request.remote_addr, None)
                session.clear()
                session.permanent = True
                session["administrator"] = True
                return redirect(url_for("index"))
            if len(failures) >= 1024:
                abort(429)
            failures[request.remote_addr] = (attempts[0], attempts[1] + 1)
            error = "Incorrect administrator password"
        return render_template("endpoint.html", login=True, error=error)

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
            values = {key: request.form.get(key, "").strip() for key in ("server", "pool", "dns", "username", "lan", "allowed")}
            try:
                # Generate away from live files; publish readiness only after all writes.
                with tempfile.TemporaryDirectory(dir=authority) as temporary:
                    generated = Path(temporary) / "generated"
                    create(generated, password=request.form.get("password", ""), **values)
                    shutil.copytree(generated / "ca", authority / "ca")
                    shutil.copytree(generated / "swanctl", data / "swanctl")
                    shutil.copyfile(generated / "gateway.env", data / "gateway.env")
                atomic(settings_file, json.dumps(values))
                atomic(data / "accounts.json", json.dumps({values["username"]: request.form["password"]}))
                atomic(data / "ready", "ready")
                return redirect(url_for("index"))
            except (ValueError, OSError) as exc:
                if not (data / "ready").exists():
                    shutil.rmtree(data / "swanctl", ignore_errors=True)
                    shutil.rmtree(authority / "ca", ignore_errors=True)
                    for path in (data / "gateway.env", settings_file, data / "accounts.json"):
                        path.unlink(missing_ok=True)
                error = str(exc)
        accounts = json.loads((data / "accounts.json").read_text()) if settings else {}
        return render_template("endpoint.html", settings=settings, accounts=sorted(accounts), error=error)

    @app.post("/accounts")
    def accounts():
        if not (data / "ready").exists():
            abort(409)
        account_file = data / "accounts.json"
        values = json.loads(account_file.read_text())
        username = request.form.get("username", "")
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", username):
            abort(400, "Use a simple account name")
        if request.form.get("action") == "delete":
            if username not in values or len(values) == 1:
                abort(400, "Keep at least one account")
            del values[username]
        else:
            password = request.form.get("password", "")
            if not 16 <= len(password) <= 256 or any(ord(c) < 33 or ord(c) > 126 or c in {'"', chr(92)} for c in password):
                abort(400, "Use a 16-256 character printable password without quotes or backslashes")
            values[username] = password
        contents = "secrets {\n" + "".join(
            f'    eap-{index} {{\n        id = "{name}"\n        secret = "{password}"\n    }}\n'
            for index, (name, password) in enumerate(sorted(values.items()))) + "}\n"
        atomic(data / "swanctl/conf.d/family-vpn-secrets.conf", contents)
        atomic(account_file, json.dumps(values))
        return redirect(url_for("index", changed="1"))

    @app.get("/ca.pem")
    def certificate():
        path = data / "swanctl/x509ca/family-vpn-ca.pem"
        if not path.exists():
            abort(404)
        return send_file(path, as_attachment=True, download_name="family-vpn-ca.pem")

    return app


if os.environ.get("VPN_ADMIN_PASSWORD") or os.environ.get("VPN_DATA"):
    app = create_app()
