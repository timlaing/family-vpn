"""Persist dashboard settings and optional Supervisor bearer credentials."""
import json
import os
import secrets
from pathlib import Path
from .app import Settings

RELAY_RESULTS_PATH = "/relay-results"
HOST_CREDENTIALS_FILE = "host-credentials.json"
HOST_KEY_FILE = "host-apns.p8"

FIELDS = {"apns_key_id", "apns_team_id", "apns_topic", "apns_key_file", "apns_environment", "interval", "automatic", "push_mode", "relay_url", "relay_callback", "relay_limit", "relay_registered_server", "rest_url", "push_choice", "relay_rotated_at", "host_enabled", "host_topic", "host_url", "host_push_url", "host_limit"}

class AddonConfiguration:
    def __init__(self, data="/data"):
        self.data = Path(data)
        self.data.mkdir(parents=True, exist_ok=True)
        self.path = self.data / "runtime-settings.json"
    def saved_values(self, settings, options):
        saved = None
        if self.path.exists():
            saved = json.loads(self.path.read_text())
            values = {field: saved.get(field, getattr(settings, field)) for field in FIELDS}
            if "push_mode" not in saved: values["push_mode"] = "direct"
        else:
            # Import legacy Supervisor settings once; subsequent edits belong to Ingress.
            values = {field: options.get(field, getattr(settings, field)) for field in FIELDS}
        if not values["relay_url"]: values["relay_url"] = settings.relay_url
        for callback in (settings.relay_callback, values.get("relay_callback", "")):
            if not values["rest_url"] and callback.endswith(RELAY_RESULTS_PATH):
                values["rest_url"] = callback[:-len(RELAY_RESULTS_PATH)]
        if saved is not None and "push_choice" not in saved:
            values["push_choice"] = "primary" if values["push_mode"] == "relay" and values["relay_url"] == settings.relay_url else "custom"
        return values

    def load(self):
        options = json.loads((self.data / "options.json").read_text())
        enrollment_path = self.data / "relay-enrollment"
        proxy_path = self.data / 'relay-proxy-token'
        settings = Settings(database=str(self.data / "vpnweb.sqlite"),
            admin_secret=self.secret("admin-bearer", options.get("admin_bearer", "")),
            enrollment_secret=self.secret("registration-bearer", options.get("registration_bearer", "")),
            session_secret=self.secret("session-secret"), secure_cookie=True,
            automatic=True, push_mode="relay", relay_secret=self.secret("relay-token"),
            relay_enrollment=enrollment_path.read_text() if enrollment_path.exists() else "", apns_key_file="/share/family-vpn/apns.p8")
        values = self.saved_values(settings, options)
        settings.host_proxy_token = os.getenv("RELAY_PROXY_TOKEN", "") or (proxy_path.read_text() if proxy_path.exists() else "")
        self.validate(values)
        self.persist(values)
        for field, value in values.items(): setattr(settings, field, value)
        self.validate({field: getattr(settings, field) for field in FIELDS})
        settings.validate()
        return settings
    def secret(self, name, supplied=""):
        path = self.data / name
        if supplied:
            if not isinstance(supplied, str) or not 32 <= len(supplied) <= 256 or any(ord(char) < 33 or ord(char) > 126 for char in supplied):
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

    def validate_urls(self, values):
        from .relay_protocol import https_url
        from urllib.parse import urlsplit
        for field in ("relay_url", "relay_callback", "rest_url", "host_url", "host_push_url"):
            if not values[field]: continue
            https_url(values[field])
            if field in {"relay_url", "host_url"} and urlsplit(values[field]).path not in ("", "/"):
                raise ValueError("Host the relay at the HTTPS origin root")

    def validate_push(self, values):
        if values["push_mode"] not in {"direct", "relay"}: raise ValueError("Invalid push mode")
        if type(values["relay_limit"]) is not int or not 1 <= values["relay_limit"] <= 100: raise ValueError("Invalid relay limit")
        if values['push_choice'] not in {'primary','custom'} or type(values['host_enabled']) is not bool:
            raise ValueError('Invalid push selection')
        if type(values['host_limit']) is not int or not 1 <= values['host_limit'] <= 100: raise ValueError('Invalid hosted rate limit')
        if not isinstance(values['relay_rotated_at'], (int,float)) or values['relay_rotated_at'] < 0: raise ValueError('Invalid rotation time')
        if values["apns_environment"] not in {"sandbox", "production"}: raise ValueError("Invalid environment")

    def validate_apns_fields(self, values):
        for field in ("apns_key_id", "apns_team_id", "apns_topic", "apns_key_file"):
            value = values[field]
            if not isinstance(value, str) or len(value) > 256 or any(ord(char) < 32 or ord(char) > 126 for char in value): raise ValueError("Invalid field")
        key = values["apns_key_file"]
        if key and (not key.startswith(("/share/", "/data/",str(self.data)+"/")) or ".." in Path(key).parts): raise ValueError("Invalid key path")

    def validate(self, values):
        if set(values) != FIELDS: raise ValueError("Invalid configuration fields")
        self.validate_urls(values)
        self.validate_push(values)
        self.validate_apns_fields(values)
        if type(values["interval"]) is not int or not 1800 <= values["interval"] <= 3600: raise ValueError("Invalid interval")
        if type(values["automatic"]) is not bool: raise ValueError("Invalid automatic option")
    def save_settings(self, settings):
        self.persist({field:getattr(settings,field) for field in FIELDS})

    def update(self, form, settings):
        if form.get("reset") == "true":
            defaults = Settings(automatic=True, push_mode=settings.push_mode, relay_url=settings.relay_url,
                relay_callback=settings.relay_callback, relay_limit=settings.relay_limit,
                relay_registered_server=settings.relay_registered_server, apns_key_file="/share/family-vpn/apns.p8")
            values = {field:getattr(settings,field) for field in FIELDS}
            for field in ('apns_key_id','apns_team_id','apns_topic','apns_key_file','apns_environment','interval','automatic'):
                values[field] = getattr(defaults,field)
            self.persist(values)
            for field, value in values.items(): setattr(settings, field, value)
            return
        values = {field: form.get(field, getattr(settings, field)).strip() for field in FIELDS - {"interval", "automatic", "relay_limit", "relay_registered_server", "relay_rotated_at", "host_limit", "host_enabled"}}
        values.update(interval=int(form.get("interval", "0")), automatic=form.get("automatic") == "true",
            relay_limit=int(form.get("relay_limit", settings.relay_limit)), relay_registered_server=settings.relay_registered_server, relay_rotated_at=settings.relay_rotated_at,
            host_limit=settings.host_limit, host_enabled=settings.host_enabled)
        if any(values[field] != getattr(settings,field) for field in ("relay_url", "relay_callback", "relay_limit")):
            values["relay_registered_server"] = ""
        self.validate(values)
        for field in ("relay_token", "relay_enrollment"):
            supplied = form.get(field, "").strip()
            if supplied and (not 32 <= len(supplied) <= 256 or any(ord(char) < 33 or ord(char) > 126 for char in supplied)):
                raise ValueError("Relay credentials require 32–256 printable ASCII characters without spaces")
        if form.get("relay_token", "").strip():
            settings.relay_secret = self.secret("relay-token", form["relay_token"].strip())
            values["relay_registered_server"] = ""
        if form.get("relay_enrollment", "").strip():
            settings.relay_enrollment = self.secret("relay-enrollment", form["relay_enrollment"].strip())
        self.persist(values)
        for field, value in values.items(): setattr(settings, field, value)

    def custom_push(self, candidate, form, settings, upload):
        import re
        topic = form.get('bundle_id',settings.apns_topic).strip()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,255}',topic): raise ValueError('Provide a valid bundle ID')
        candidate['apns_topic'] = topic
        candidate['apns_environment'] = 'sandbox' if 'sandbox.push.apple.com' in candidate['relay_url'] else 'production'
        self.validate(candidate)
        if upload and upload.filename:
            credentials = self.read_credentials(upload,team_id=settings.apns_team_id)
            candidate.update(apns_key_file=str(self.data/'custom-apns.p8'),apns_key_id=credentials['key_id'],apns_team_id=credentials['team_id'])
            self.validate(candidate)
            self.private_file('custom-apns.p8',credentials['private_key'])

    def update_push(self, form, settings, upload=None):
        from .relay_protocol import https_url
        choice = form.get('push_choice', settings.push_choice)
        if choice not in {'primary','custom'}: raise ValueError('Select Primary or Custom')
        url = 'https://push.family-vpn.workers.dev' if choice == 'primary' else https_url(form.get('push_url',settings.relay_url))
        direct = url in {'https://api.push.apple.com','https://api.sandbox.push.apple.com'}
        if choice == 'custom' and not direct: raise ValueError('Custom push supports direct Apple APNs URLs only')
        candidate = {field:getattr(settings,field) for field in FIELDS}
        candidate.update(push_choice=choice, push_mode='direct' if direct else 'relay',relay_url=url)
        if url != settings.relay_url or choice != settings.push_choice:
            candidate['relay_registered_server'] = ''
            candidate['relay_rotated_at'] = 0
        if choice == 'custom': self.custom_push(candidate, form, settings, upload)
        self.validate(candidate)
        self.persist(candidate)
        for field,value in candidate.items(): setattr(settings,field,value)

    def private_file(self, name, value):
        temporary = (self.data/name).with_suffix('.tmp')
        with temporary.open('w') as output:
            os.chmod(temporary,0o600)
            output.write(value)
        temporary.replace(self.data/name)

    @staticmethod
    def apns_credentials(text, filename, team_id, key_id=""):
        import re
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        if text.startswith('{'):
            value = json.loads(text)
            if set(value) != {'key_id','team_id','private_key'}: raise ValueError()
        else:
            if not key_id:
                match = re.fullmatch(r'AuthKey_([A-Z0-9]{10})\.p8',Path(filename).name)
                if not match: raise ValueError()
                key_id = match[1]
            value = {'key_id':key_id,'team_id':team_id,'private_key':text}
        if not all(isinstance(value[field],str) and re.fullmatch(r'[A-Z0-9]{10}',value[field]) for field in ('key_id','team_id')): raise ValueError()
        if not isinstance(value['private_key'], str): raise ValueError()
        key = serialization.load_pem_private_key(value['private_key'].encode(),password=None)
        if not isinstance(key,ec.EllipticCurvePrivateKey) or not isinstance(key.curve,ec.SECP256R1): raise ValueError()
        return value

    @staticmethod
    def read_credentials(upload, direct=True, team_id='', key_id=''):
        from .relay_service import valid_token
        raw = upload.read(16385)
        if len(raw) > 16384: raise ValueError('Key file must be at most 16 KB')
        try:
            text = raw.decode('utf-8').strip()
            if direct: return AddonConfiguration.apns_credentials(text, upload.filename, team_id, key_id)
            if not valid_token(text): raise ValueError()
            return text
        except (ValueError,TypeError,KeyError):
            raise ValueError('Provide a P-256 APNs private key with a 10-character Key ID and Team ID, or a valid APNs JSON credential') from None

    def host_metadata(self):
        path = self.data / HOST_CREDENTIALS_FILE
        return json.loads(path.read_text()) if path.exists() else {}

    def has_host_credentials(self):
        return (self.data / HOST_CREDENTIALS_FILE).exists() and (self.data / HOST_KEY_FILE).exists()

    @staticmethod
    def host_private_key_input(form, upload):
        pasted = form.get('host_private_key', '').strip()
        if len(pasted.encode()) > 16384: raise ValueError('Private key must be at most 16 KB')
        if pasted and upload and upload.filename: raise ValueError('Upload or paste the private key, not both')
        return pasted

    @staticmethod
    def parse_host_key(text, team_id, key_id):
        try:
            return AddonConfiguration.apns_credentials(text, HOST_KEY_FILE, team_id, key_id)
        except (ValueError, TypeError, KeyError):
            raise ValueError('Provide a P-256 APNs private key with a 10-character Key ID and Team ID') from None

    def host_credentials(self, form, upload):
        saved = self.host_metadata()
        key_id = form.get('host_key_id', saved.get('key_id', '')).strip()
        team_id = form.get('host_team_id', saved.get('team_id', '')).strip()
        pasted = self.host_private_key_input(form, upload)
        if upload and upload.filename:
            return self.read_credentials(upload, team_id=team_id, key_id=key_id)
        if pasted: return self.parse_host_key(pasted, team_id, key_id)
        if not saved: return None
        if (key_id, team_id) == (saved['key_id'], saved['team_id']): return None
        if not self.has_host_credentials(): raise ValueError('Upload or paste the APNs private key first')
        return self.parse_host_key((self.data / HOST_KEY_FILE).read_text(), team_id, key_id)

    def update_host(self, form, settings, upload=None):
        from .relay_protocol import https_url
        from .relay_service import valid_token
        import re
        url = https_url(form.get('host_push_url',settings.host_push_url))
        if url not in {'https://api.push.apple.com','https://api.sandbox.push.apple.com'}: raise ValueError('Select an Apple APNs HTTPS URL')
        topic = form.get('host_topic',settings.host_topic).strip()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,255}',topic): raise ValueError('Invalid bundle ID')
        proxy = form.get('proxy_token','').strip()
        if proxy and not valid_token(proxy): raise ValueError('Worker credential requires 32–256 printable characters')
        credentials = self.host_credentials(form, upload)
        enabled = form.get('host_enabled') == 'true'
        if enabled and not (credentials or self.has_host_credentials()): raise ValueError('Upload publisher APNs credentials first')
        values = {field:getattr(settings,field) for field in FIELDS}
        values.update(host_enabled=enabled,host_topic=topic,host_url=form.get('host_url',settings.host_url).strip().rstrip('/'),host_push_url=url,host_limit=int(form.get('host_limit',settings.host_limit)))
        self.validate(values)
        if credentials:
            self.private_file(HOST_CREDENTIALS_FILE,json.dumps({field:credentials[field] for field in ('key_id','team_id')}))
            self.private_file(HOST_KEY_FILE,credentials['private_key'])
        if proxy:
            settings.host_proxy_token = self.secret('relay-proxy-token',proxy)
        self.persist(values)
        for field,value in values.items(): setattr(settings,field,value)

    def host_settings(self, settings):
        values = self.host_metadata()
        return Settings(apns_key_file=str(self.data/HOST_KEY_FILE) if values else '',
            apns_key_id=values.get('key_id',''),apns_team_id=values.get('team_id',''),apns_topic=settings.host_topic,
            apns_environment='sandbox' if 'sandbox.push.apple.com' in settings.host_push_url else 'production')
