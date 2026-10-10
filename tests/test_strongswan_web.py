"""Authenticated setup persists secrets without exposing them through the UI."""
import importlib.util
import json
from pathlib import Path
import re
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent / "strongswan-endpoint"
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("configure", ROOT / "configure.py")
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)
sys.modules["configure"] = configure
spec = importlib.util.spec_from_file_location("endpoint_web", ROOT / "web.py")
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)


@pytest.fixture
def management(tmp_path):
    app = web.create_app(tmp_path / "data", tmp_path / "authority", tmp_path / "control")
    app.config["TESTING"] = True
    # importlib does not give Flask the source root for template discovery.
    app.template_folder = str(ROOT / "templates")
    return app, tmp_path


def token(client, path="/"):
    response = client.get(path, follow_redirects=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', response.text)[1]


def sign_in(client):
    if client.get("/login").location == "/initialize":
        return client.post("/initialize", data={"csrf_token": token(client, "/initialize"),
                                              "password": "synthetic-administrator-password",
                                              "confirmation": "synthetic-administrator-password"})
    return client.post("/login", data={"csrf_token": token(client, "/login"),
                                     "password": "synthetic-administrator-password"})


def test_login_csrf_rate_limit_and_secret_redaction(management):
    app, _ = management
    client = app.test_client()
    assert client.get("/ca.pem").location == "/initialize"
    sign_in(client)
    client.post("/logout", data={"csrf_token": token(client)})
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
                   dns="192.168.10.53",
                   lan="192.168.10.0/24", allowed="192.168.10.53/32")
    assert client.post("/", data=payload).location == "/accounts"
    assert client.post("/accounts", data=dict(csrf_token=token(client, "/accounts"), username="device-one", password="synthetic-vpn-password")).status_code == 302
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
    again = web.create_app(directory / "data", directory / "authority", directory / "control")
    again.template_folder = str(ROOT / "templates")
    fresh = again.test_client()
    sign_in(fresh)
    assert "device-two" in fresh.get("/accounts").text
    assert "device-two" not in fresh.get("/").text
    assert fresh.post("/accounts", data=dict(csrf_token=token(fresh), username="device-two", action="delete")).status_code == 302


def test_first_launch_password_is_required_confirmed_and_cannot_be_replaced(management):
    app, directory = management
    client = app.test_client()
    assert not (directory / "authority/administrator.json").exists()
    assert client.get("/accounts").location == "/initialize"
    assert client.post("/initialize", data={"password": "short"}).status_code == 400
    csrf = token(client, "/initialize")
    assert "16–256" in client.post("/initialize", data=dict(csrf_token=csrf, password="short", confirmation="short")).text
    assert "do not match" in client.post("/initialize", data=dict(csrf_token=csrf, password="synthetic-administrator-password", confirmation="different")).text
    sign_in(client)
    admin = directory / "authority/administrator.json"
    original = admin.read_bytes()
    assert b"synthetic-administrator-password" not in original
    assert admin.stat().st_mode & 0o777 == 0o600
    assert client.post("/initialize", data=dict(csrf_token=token(client), password="replacement-password", confirmation="replacement-password")).status_code == 409
    assert admin.read_bytes() == original
    assert client.get("/accounts").location == "/"
    assert 'name="username"' not in client.get("/").text


def test_account_actions_exclude_disabled_accounts_and_preserve_state(management):
    app, directory = management
    client = app.test_client()
    sign_in(client)
    client.post("/", data=dict(csrf_token=token(client), server="vpn.example.org", pool="10.20.30.0/24",
                              dns="192.168.10.53", lan="192.168.10.0/24", allowed="192.168.10.53/32"))
    def action(name, operation, password="synthetic-vpn-password"):
        return client.post("/accounts", data=dict(csrf_token=token(client, "/accounts"), username=name, action=operation, password=password))
    assert action("device", "add").status_code == 302
    assert action("device", "add").status_code == 409
    secrets_file = directory / "data/swanctl/conf.d/family-vpn-secrets.conf"
    assert 'id = "device"' in secrets_file.read_text()
    assert action("device", "disable").status_code == 302
    assert 'id = "device"' not in secrets_file.read_text()
    assert action("device", "password", "replacement-vpn-password").status_code == 302
    account = json.loads((directory / "data/accounts.json").read_text())["device"]
    assert account == {"enabled": False, "password": "replacement-vpn-password"}
    assert "replacement-vpn-password" not in client.get("/accounts").text
    assert action("device", "enable").status_code == 302
    assert "replacement-vpn-password" in secrets_file.read_text()
    assert action("device", "password", "short").status_code == 400
    assert action("missing", "disable").status_code == 404
    assert action("device", "unknown").status_code == 400
    assert action("device", "delete").status_code == 302
    assert json.loads((directory / "data/accounts.json").read_text()) == {}
    assert 'id = "device"' not in secrets_file.read_text()


def test_legacy_credentials_and_accounts_are_preserved(management):
    app, directory = management
    client = app.test_client()
    sign_in(client)
    client.post("/", data=dict(csrf_token=token(client), server="vpn.example.org", pool="10.20.30.0/24",
                              dns="192.168.10.53", lan="192.168.10.0/24", allowed="192.168.10.53/32"))
    account_file = directory / "data/accounts.json"
    account_file.write_text(json.dumps({"legacy": "legacy-account-password"}))
    assert "legacy" in client.get("/accounts").text
    assert client.post("/accounts", data=dict(csrf_token=token(client, "/accounts"), username="legacy", action="disable")).status_code == 302
    assert json.loads(account_file.read_text())["legacy"] == {"enabled": False, "password": "legacy-account-password"}
    # Legacy installations did not have a separate session-key file.
    (directory / "authority/session-key").unlink()
    restarted = web.create_app(directory / "data", directory / "authority", directory / "control")
    assert restarted.config["SECRET_KEY"] == app.config["SECRET_KEY"]


def test_radius_configuration_secret_privacy_and_local_account_gating(management):
    app, directory = management
    client = app.test_client()
    sign_in(client)
    assert client.get("/authentication").location == "/"
    client.post("/", data=dict(csrf_token=token(client), server="vpn.example.org", pool="10.20.30.0/24",
                              dns="192.168.10.53", lan="192.168.10.0/24", allowed="192.168.10.53/32"))
    client.post("/accounts", data=dict(csrf_token=token(client, "/accounts"), username="local-device", password="synthetic-vpn-password"))
    config = directory / "data/swanctl/swanctl.conf"
    radius = directory / "data/authentication/radius.conf"
    def update(**values):
        return client.post("/authentication", data=dict(csrf_token=token(client, "/authentication"), **values))
    assert update(mode="radius", server="192.168.10.54", secret="short").status_code == 200
    assert not radius.exists()
    assert "auth = eap-mschapv2" in config.read_text()
    assert update(mode="radius", server="192.168.10.54", secret="synthetic-radius-secret", auth_port="18120", acct_port="18130", nas_identifier="family-vpn", accounting="on").status_code == 302
    assert "auth = eap-radius" in config.read_text()
    assert "auth_port = 18120" in radius.read_text() and "accounting = yes" in radius.read_text()
    assert radius.stat().st_mode & 0o777 == 0o600
    for path in ("/", "/authentication", "/accounts"):
        assert "synthetic-radius-secret" not in client.get(path).text
    assert "Managed by your RADIUS server" in client.get("/accounts").text
    assert 'name="username"' not in client.get("/accounts").text
    assert client.post("/accounts", data=dict(csrf_token=token(client, "/accounts"), username="local-device", action="disable")).status_code == 409
    assert update(mode="radius", server="192.168.10.54", secret="", nas_identifier="family-vpn").status_code == 302
    assert "synthetic-radius-secret" in radius.read_text()
    old = radius.read_bytes()
    assert update(mode="radius", server='radius.example.org"injection', secret="new-radius-secret").status_code == 200
    assert radius.read_bytes() == old
    assert update(mode="local").status_code == 302
    assert "auth = eap-mschapv2" in config.read_text() and not radius.exists()
    assert "local-device" in client.get("/accounts").text


def test_account_reload_queue_status_and_noop_edits(management):
    app, directory = management
    client = app.test_client()
    sign_in(client)
    client.post("/", data=dict(csrf_token=token(client), server="vpn.example.org", pool="10.20.30.0/24",
                              dns="192.168.10.53", lan="192.168.10.0/24", allowed="192.168.10.53/32"))
    def change(action, password="synthetic-vpn-password"):
        return client.post("/accounts", data=dict(csrf_token=token(client, "/accounts"), username="device", action=action, password=password))
    assert change("add").location.endswith("changed=1")
    pending = sorted((directory / "data/reloads").glob("*.json"))
    assert len(pending) == 1 and json.loads(pending[0].read_text()) == {"username": "device", "action": "add"}
    assert client.get("/reload-status").json["status"] == "pending"
    assert change("enable").location.endswith("changed=not-needed")
    assert change("password").location.endswith("changed=not-needed")
    assert len(list((directory / "data/reloads").glob("*.json"))) == 1
    assert change("disable").location.endswith("changed=1")
    assert change("password", "changed-inactive-password").location.endswith("changed=not-needed")
    assert change("delete").location.endswith("changed=not-needed")
    assert len(list((directory / "data/reloads").glob("*.json"))) == 2
    assert "synthetic-vpn-password" not in client.get("/reload-status").text
    assert 'restart vpn' not in client.get("/accounts").text
