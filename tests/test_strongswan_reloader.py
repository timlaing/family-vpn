"""Credential reload failures stay visible, and revocations target EAP accounts."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent / "strongswan-endpoint"
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("reloader", ROOT / "reloader.py")
reloader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reloader)
from reload_requests import queue_reload, reload_status


def test_targeted_eap_sessions_preserve_other_established_tunnels():
    events = [
        {"family-vpn": {"uniqueid": b"1", "remote-eap-id": b"alice", "state": b"ESTABLISHED"}},
        {"family-vpn": {"uniqueid": b"2", "remote-eap-id": b"bob", "remote-id": b"alice", "state": b"ESTABLISHED"}},
        {"different-vpn": {"uniqueid": b"3", "remote-eap-id": b"alice", "state": b"ESTABLISHED"}},
        {"family-vpn": {"uniqueid": b"4", "state": b"CONNECTING"}},
        {"family-vpn": {"uniqueid": b"5", "remote-id": b"alice", "state": b"ESTABLISHED"}},
    ]
    assert reloader.target_sessions(events, "alice") == ["1", "4", "5"]


@pytest.mark.parametrize("action", ["add", "enable", "disable", "delete", "password"])
def test_reload_clears_stale_credentials_and_only_revokes_when_needed(tmp_path, action):
    calls, revoked = [], []
    def run(command, **options):
        calls.append((command, options))
    def terminate(username):
        revoked.append(username)
        return 2
    result = reloader.apply_request(tmp_path, {"username": "alice", "action": action}, run=run, terminate=terminate)
    assert calls[0][0] == ["swanctl", "--load-creds", "--clear", "--noprompt"]
    assert calls[0][1]["check"] is True
    assert revoked == (["alice"] if action in reloader.REVOKE_ACTIONS else [])
    assert result["status"] == "applied"
    assert result["disconnected"] == (2 if revoked else 0)


def test_failed_reloads_are_retried_without_false_success_or_secret_disclosure(tmp_path):
    data, control = tmp_path / "data", tmp_path / "control"
    queue_reload(data, control, "alice", "disable")
    calls = []
    def fails(data, request):
        calls.append(request)
        raise subprocess.CalledProcessError(1, "synthetic", stderr="sensitive output")
    reloader.process_pending(data, control, apply=fails, now=lambda: 100)
    assert reload_status(data, control)["status"] == "error"
    assert "sensitive output" not in json.dumps(reload_status(data, control))
    reloader.process_pending(data, control, apply=fails, now=lambda: 101)
    assert len(calls) == 1
    reloader.process_pending(data, control, apply=lambda data, request: {"status": "applied", "message": "Applied", "updated_at": 106}, now=lambda: 106)
    assert reload_status(data, control)["status"] == "applied"
    reloader.process_pending(data, control, apply=fails, now=lambda: 200)
    assert len(calls) == 1


def test_earlier_pending_revocation_is_not_hidden_by_later_success(tmp_path):
    data, control = tmp_path / "data", tmp_path / "control"
    first = queue_reload(data, control, "alice", "disable")
    second = queue_reload(data, control, "bob", "add")
    control.mkdir()
    (control / second).write_text(json.dumps({"status": "applied", "message": "Applied"}))
    assert reload_status(data, control)["status"] == "pending"
    assert (data / "reloads" / first).exists()


def test_invalid_requests_and_inactive_local_backend_do_not_control_sessions(tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("Gateway commands must not run")
    with pytest.raises(ValueError):
        reloader.apply_request(tmp_path, {"username": "alice;unsafe", "action": "disable"}, run=forbidden)
    result = reloader.apply_request(tmp_path, {"username": "alice", "action": "disable"}, run=forbidden, terminate=forbidden, radius=True)
    assert result["status"] == "applied"
    assert result["disconnected"] == 0
