"""Private file-based requests; the web container never receives a VICI socket."""
import json
from pathlib import Path
import re
import time
import uuid

from authentication import atomic

REQUEST_NAME = re.compile(r"[0-9]{1,24}_[a-f0-9]{32}\.json")


def requests(data):
    return sorted(path for path in (Path(data) / "reloads").glob("*.json")
                  if REQUEST_NAME.fullmatch(path.name))


def queue_reload(data, control, username, action):
    folder = Path(data) / "reloads"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Keep pending work across outages; retain only a small applied history.
    completed = [path for path in requests(data) if (Path(control) / path.name).exists()
                 and json.loads((Path(control) / path.name).read_text()).get("status") == "applied"]
    for path in completed[:-32]:
        path.unlink()
    path = folder / f"{time.time_ns()}_{uuid.uuid4().hex}.json"
    atomic(path, json.dumps({"username": username, "action": action}))
    return path.name


def reload_status(data, control):
    pending = requests(data)
    if not pending:
        return {"status": "none", "message": "No account reload pending."}
    # Surface an earlier outstanding revocation even if a later addition succeeded.
    latest = None
    for path in pending:
        result = Path(control) / path.name
        status = json.loads(result.read_text()) if result.exists() else {
            "status": "pending", "message": "Account changes saved. Waiting for the VPN gateway to apply them."}
        if status["status"] != "applied":
            return status
        latest = status
    return latest
