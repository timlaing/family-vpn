"""Authenticated setup persists secrets without exposing them through the UI."""
import importlib.util
import json
from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent / "strongswan-endpoint"
spec = importlib.util.spec_from_file_location("configure", ROOT / "configure.py")
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)
sys.modules["configure"] = configure
spec = importlib.util.spec_from_file_location("endpoint_web", ROOT / "web.py")
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)


@pytest.fixture
def management(tmp_path, monkeypatch):
    monkeypatch.setenv("VPN_ADMIN_PASSWORD", "synthetic-administrator-password")
    app = web.create_app(tmp_path / "data", tmp_path / "authority")
    app.config["TESTING"] = True
    # importlib does not give Flask the source root for template discovery.
    app.template_folder = str(ROOT / "templates")
    return app, tmp_path


def token(client, path="/"):
    response = client.get(path)
    return re.search(r'name="csrf_token" value="([^"]+)"', response.text)[1]


def sign_in(client):
    return client.post("/login", data={"csrf_token": token(client, "/login"),
                                     "password": "synthetic-administrator-password"})


def test_login_csrf_rate_limit_and_secret_redaction(management):
    app, _ = management
    client = app.test_client()
    assert client.get("/ca.pem").status_code == 302
    assert client.post("/login", data={"password": "wrong"}).status_code == 400
    csrf = token(client, "/login")
    for _ in range(10):
        assert client.post("/login", data={"csrf_token": csrf, "password": "wrong"}).status_code == 200
    assert client.post("/login", data={"csrf_token": csrf, "password": "wrong"}).status_code == 429


def test_setup_accounts_certificate_and_restart_persistence(management):
    app, directory = management
    client = app.test_client()
    assert sign_in(client).status_code == 302
    payload = dict(csrf_token=token(client), server="vpn.example.org", pool="10.20.30.0/24",
                   dns="192.168.10.53", username="device-one", password="synthetic-vpn-password",
                   lan="192.168.10.0/24", allowed="192.168.10.53/32")
    assert client.post("/", data=payload).status_code == 302
    assert (directory / "authority/ca/ca-key.pem").exists()
    assert not (directory / "data/ca").exists()
    assert (directory / "data/ready").exists()
    assert "synthetic-vpn-password" not in client.get("/").text
    assert client.get("/ca.pem").data.startswith(b"-----BEGIN CERTIFICATE-----")
    assert client.post("/", data=payload).status_code == 409
    assert client.post("/accounts", data=dict(csrf_token=token(client), username='bad"name', password="synthetic-vpn-password")).status_code == 400
    assert client.post("/accounts", data=dict(csrf_token=token(client), username="device-two", password="second-synthetic-password")).status_code == 302
    assert client.post("/accounts", data=dict(csrf_token=token(client), username="device-one", action="delete")).status_code == 302
    accounts = json.loads((directory / "data/accounts.json").read_text())
    assert list(accounts) == ["device-two"]
    assert (directory / "data/accounts.json").stat().st_mode & 0o777 == 0o600
    again = web.create_app(directory / "data", directory / "authority")
    again.template_folder = str(ROOT / "templates")
    fresh = again.test_client()
    sign_in(fresh)
    assert "device-two" in fresh.get("/").text
    assert fresh.post("/accounts", data=dict(csrf_token=token(fresh), username="device-two", action="delete")).status_code == 400
