"""Read Supervisor options and persist only non-secret ingress overrides."""
import json
import os
import secrets
from pathlib import Path
from .app import Settings

FIELDS = {"apns_key_id", "apns_team_id", "apns_topic", "apns_key_file", "apns_environment", "interval", "automatic"}

class AddonConfiguration:
    def __init__(self, data="/data"):
        self.data = Path(data)
        self.data.mkdir(parents=True, exist_ok=True)
        self.path = self.data / "runtime-settings.json"
    def load(self):
        options = json.loads((self.data / "options.json").read_text())
        session_path = self.data / "session-secret"
        try:
            with session_path.open("x") as output:
                os.chmod(session_path, 0o600)
                output.write(secrets.token_urlsafe(32))
        except FileExistsError: pass
        settings = Settings(database=str(self.data / "vpnweb.sqlite"),
            admin_secret=options["admin_bearer"], enrollment_secret=options["registration_bearer"],
            session_secret=session_path.read_text(), secure_cookie=True,
            apns_key_file=options.get("apns_key_file", ""), apns_key_id=options.get("apns_key_id", ""),
            apns_team_id=options.get("apns_team_id", ""), apns_topic=options.get("apns_topic", "uk.co.laingcorp.myvpn"),
            apns_environment=options.get("apns_environment", "sandbox"), interval=options.get("interval", 2700),
            automatic=options.get("automatic", False))
        if self.path.exists():
            overrides=json.loads(self.path.read_text())
            self.validate(overrides)
            for field, value in overrides.items(): setattr(settings, field, value)
        self.validate({field: getattr(settings, field) for field in FIELDS})
        settings.validate()
        return settings
    @staticmethod
    def validate(values):
        if set(values) != FIELDS: raise ValueError("Invalid configuration fields")
        if values["apns_environment"] not in {"sandbox", "production"}: raise ValueError("Invalid environment")
        if type(values["interval"]) is not int or not 1800 <= values["interval"] <= 3600: raise ValueError("Invalid interval")
        if type(values["automatic"]) is not bool: raise ValueError("Invalid automatic option")
        for field in ("apns_key_id", "apns_team_id", "apns_topic", "apns_key_file"):
            value = values[field]
            if not isinstance(value, str) or len(value) > 256 or any(ord(char) < 32 or ord(char) > 126 for char in value): raise ValueError("Invalid field")
        key = values["apns_key_file"]
        if key and (not key.startswith(("/share/", "/data/")) or ".." in Path(key).parts): raise ValueError("Invalid key path")
    def update(self, form, settings):
        if form.get("reset") == "true":
            self.path.unlink(missing_ok=True)
            return
        values = {field: form.get(field, "").strip() for field in FIELDS - {"interval", "automatic"}}
        values.update(interval=int(form.get("interval", "0")), automatic=form.get("automatic") == "true")
        self.validate(values)
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w") as output:
            os.chmod(temporary, 0o600)
            json.dump(values, output)
        temporary.replace(self.path)
        for field, value in values.items(): setattr(settings, field, value)
