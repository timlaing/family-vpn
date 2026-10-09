"""Persist dashboard settings and optional Supervisor bearer credentials."""
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
        settings = Settings(database=str(self.data / "vpnweb.sqlite"),
            admin_secret=self.secret("admin-bearer", options.get("admin_bearer", "")),
            enrollment_secret=self.secret("registration-bearer", options.get("registration_bearer", "")),
            session_secret=self.secret("session-secret"), secure_cookie=True,
            automatic=False, apns_key_file="/share/family-vpn/apns.p8")
        if self.path.exists():
            values = json.loads(self.path.read_text())
        else:
            # Import legacy Supervisor settings once; subsequent edits belong to Ingress.
            values = {field: options.get(field, getattr(settings, field)) for field in FIELDS}
        self.validate(values)
        self.persist(values)
        for field, value in values.items(): setattr(settings, field, value)
        self.validate({field: getattr(settings, field) for field in FIELDS})
        settings.validate()
        return settings
    def secret(self, name, supplied=""):
        path = self.data / name
        if supplied:
            if not isinstance(supplied, str) or len(supplied) < 32:
                raise ValueError("Bearer credentials require at least 32 characters")
            temporary = path.with_suffix(".tmp")
            with temporary.open("w") as output:
                os.chmod(temporary, 0o600)
                output.write(supplied)
            temporary.replace(path)
        else:
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w") as output:
                    output.write(secrets.token_urlsafe(32))
            except FileExistsError:
                pass
        os.chmod(path, 0o600)
        return path.read_text()

    def persist(self, values):
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w") as output:
            os.chmod(temporary, 0o600)
            json.dump(values, output)
        temporary.replace(self.path)

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
            defaults = Settings(automatic=False, apns_key_file="/share/family-vpn/apns.p8")
            values = {field: getattr(defaults, field) for field in FIELDS}
            self.persist(values)
            for field, value in values.items(): setattr(settings, field, value)
            return
        values = {field: form.get(field, "").strip() for field in FIELDS - {"interval", "automatic"}}
        values.update(interval=int(form.get("interval", "0")), automatic=form.get("automatic") == "true")
        self.validate(values)
        self.persist(values)
        for field, value in values.items(): setattr(settings, field, value)
