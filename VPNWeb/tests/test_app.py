import json
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import httpx
from family_vpn.app import APNsSender, Settings, create_app, seed_demo


class Sender:
    def __init__(self): self.tokens = []; self.result = "accepted"; self.callback = None
    def send(self, token):
        self.tokens.append(token)
        if self.callback: self.callback()
        return self.result


class AppTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.settings = Settings(database=self.directory.name + "/test.sqlite", admin_secret="a" * 32,
                                 enrollment_secret="e" * 32, session_secret="s" * 32,
                                 automatic=False, secure_cookie=False,
                                 apns_key_file="synthetic", apns_key_id="test", apns_team_id="test")
        self.sender = Sender()
        self.app = create_app(self.settings, self.sender)
        self.app.testing = True
        self.client = self.app.test_client()
        self.device = str(uuid.uuid4())
        self.database = self.app.extensions["database"]
        self.dispatcher = self.app.extensions["dispatcher"]

    def tearDown(self):
        self.dispatcher.close()
        self.directory.cleanup()

    def register(self, token="ab" * 32, device=None):
        response = self.client.post("/registrations", headers={"Authorization": "Bearer " + self.settings.enrollment_secret},
                                    json={"id": device or self.device, "token": token})
        self.assertEqual(response.status_code, 201)
        return response.json["status_token"]

    def report(self, secret, device=None, **extra):
        return self.client.post("/status", headers={"Authorization": "Bearer " + secret},
                                json={"id": device or self.device, "connection": "connected", "policy_ok": True, **extra})

    def login(self):
        self.client.get("/login")
        with self.client.session_transaction() as session: csrf = session["csrf"]
        return self.client.post("/login", data={"csrf": csrf, "password": self.settings.admin_secret})

    def test_registration_and_device_scoped_status(self):
        secret = self.register()
        self.assertEqual(self.report(secret).status_code, 204)
        other = str(uuid.uuid4()); self.register(device=other)
        self.assertEqual(self.report(secret, device=other).status_code, 401)
        self.assertEqual(self.report(self.settings.enrollment_secret).status_code, 401)
        row = self.database.public_devices()[0]
        self.assertEqual(row["connection"], "connected"); self.assertEqual(row["policy_ok"], 1)
        self.assertIsNotNone(row["seen"])

    def test_rotated_registration_revokes_old_status_key(self):
        old = self.register(); new = self.register("cd" * 48)
        self.assertNotEqual(old, new)
        self.assertEqual(self.report(old).status_code, 401)
        self.assertEqual(self.report(new).status_code, 204)

    def test_registration_authentication_and_input_validation(self):
        for auth in ({}, {"Authorization": "Bearer wrong"}):
            self.assertEqual(self.client.post("/registrations", headers=auth, json={}).status_code, 401)
        auth = {"Authorization": "Bearer " + self.settings.enrollment_secret}
        for payload in ({}, [], {"id": "bad", "token": "ab"}, {"id": self.device, "token": "abc"},
                        {"id": self.device, "token": "ab", "username": "not-accepted"}):
            self.assertEqual(self.client.post("/registrations", headers=auth, json=payload).status_code, 400)
        for size in (16, 32, 64): self.register("ab" * size)
        self.assertEqual(self.client.post("/registrations", headers=auth, data="x" * 2049).status_code, 413)

    def test_private_status_fields_and_wrong_types_rejected(self):
        secret = self.register()
        for extra in ({"ssid": "never-accept"}, {"connection": "invented"}, {"connection": []}, {"policy_ok": 1}):
            self.assertEqual(self.report(secret, **extra).status_code, 400)
        self.assertIsNone(self.database.public_devices()[0]["seen"])

    def test_tokens_and_status_keys_never_appear_in_admin_responses(self):
        secret = self.register()
        self.report(secret)
        response = self.client.get("/api/devices", headers={"Authorization": "Bearer " + self.settings.admin_secret})
        self.assertEqual(response.status_code, 200)
        for private in (secret, "ab" * 32, "status_hash", '"token"'):
            self.assertNotIn(private, response.text)
        self.assertEqual(self.client.get("/api/devices").status_code, 401)
        self.assertEqual(self.login().status_code, 302)
        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Only a subsequent device report", dashboard.text)
        self.assertNotIn(secret, dashboard.text)

    def test_login_csrf_rate_limit_and_logout(self):
        self.client.get("/login")
        with self.client.session_transaction() as session: csrf = session["csrf"]
        self.assertEqual(self.client.post("/login", data={"password": self.settings.admin_secret}).status_code, 403)
        for _ in range(5):
            self.assertEqual(self.client.post("/login", data={"csrf": csrf, "password": "wrong"}).status_code, 200)
        self.assertEqual(self.client.post("/login", data={"csrf": csrf, "password": "wrong"}).status_code, 429)
        self.assertEqual(self.client.post("/logout").status_code, 403)
        self.assertEqual(self.client.post("/logout", data={"csrf": csrf}).status_code, 302)

    def test_manual_push_requires_admin_bearer_and_returns_queued(self):
        self.register()
        self.assertEqual(self.client.post("/api/push", json={}).status_code, 401)
        self.assertEqual(self.client.post("/api/push", headers={"Authorization": "Bearer " + self.settings.enrollment_secret}, json={}).status_code, 401)
        response = self.client.post("/api/push", headers={"Authorization": "Bearer " + self.settings.admin_secret}, json={"id": self.device})
        self.assertEqual(response.status_code, 202)
        self.dispatcher.future.result(timeout=2)
        self.assertEqual(self.sender.tokens, ["ab" * 32])
        self.assertEqual(self.database.public_devices()[0]["push_result"], "accepted")
        self.assertIsNone(self.database.public_devices()[0]["seen"])

    def test_dashboard_push_requires_csrf(self):
        self.register(); self.login()
        self.assertEqual(self.client.post("/push", data={}).status_code, 403)
        with self.client.session_transaction() as session: csrf = session["csrf"]
        self.assertEqual(self.client.post("/push", data={"csrf": csrf}).status_code, 302)
        self.dispatcher.future.result(timeout=2)

    def test_invalid_token_retains_device_and_allows_registration(self):
        self.register(); self.sender.result = "invalid_token"
        self.dispatcher.run()
        self.assertFalse(self.database.public_devices()[0]["registered_token"])
        self.register("cd" * 32)
        self.assertTrue(self.database.public_devices()[0]["registered_token"])

    def test_rotation_during_delivery_is_not_pruned(self):
        self.register()
        def rotate():
            with self.database.connect() as db: db.execute("UPDATE devices SET token=? WHERE id=?", ("cd" * 32, self.device))
        self.sender.callback = rotate; self.sender.result = "invalid_token"
        self.dispatcher.run()
        self.assertTrue(self.database.public_devices()[0]["registered_token"])
        self.assertIsNone(self.database.public_devices()[0]["push_result"])

    def test_overlapping_triggers_are_coalesced(self):
        self.register()
        entered, release = threading.Event(), threading.Event()
        self.sender.callback = lambda: (entered.set(), release.wait(timeout=2))
        self.assertTrue(self.dispatcher.trigger())
        self.assertTrue(entered.wait(timeout=2))
        self.assertFalse(self.dispatcher.trigger())
        release.set(); self.dispatcher.future.result(timeout=2)
        self.assertEqual(len(self.sender.tokens), 1)

    def test_events_are_bounded_and_database_is_private(self):
        with self.database.connect() as db:
            for _ in range(205): self.database.event(db, self.device, "status", "policy_ok")
            self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 200)
        self.assertEqual(Path(self.settings.database).stat().st_mode & 0o777, 0o600)

    def test_unconfigured_provider_and_unknown_device(self):
        auth = {"Authorization": "Bearer " + self.settings.admin_secret}
        self.assertEqual(self.client.post("/api/push", headers=auth, json={"id": str(uuid.uuid4())}).status_code, 404)
        self.settings.apns_key_file = ""
        self.assertEqual(self.client.post("/api/push", headers=auth, json={}).status_code, 503)

    def test_security_headers(self):
        response = self.client.get("/health")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])


class ProviderTests(unittest.TestCase):
    def test_provider_jwt_signature_and_cache(self):
        import base64
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        key = ec.generate_private_key(ec.SECP256R1())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.p8"
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            sender = APNsSender(Settings(apns_key_file=str(path), apns_key_id="synthetic", apns_team_id="synthetic"))
            token = sender.provider_jwt()
            header, claims, signature = token.split(".")
            decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            self.assertEqual(json.loads(decode(header)), {"alg": "ES256", "kid": "synthetic"})
            self.assertEqual(json.loads(decode(claims))["iss"], "synthetic")
            raw = decode(signature)
            self.assertEqual(len(raw), 64)
            key.public_key().verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")), (header + "." + claims).encode(), ec.ECDSA(hashes.SHA256()))
            path.unlink()
            self.assertEqual(sender.provider_jwt(), token)

    def test_provider_payload_and_errors(self):
        settings = Settings(apns_key_file="synthetic", apns_key_id="synthetic", apns_team_id="synthetic", automatic=False)
        sender = APNsSender(settings)
        with patch.object(sender, "provider_jwt", return_value="synthetic"), patch("family_vpn.app.httpx.Client") as factory:
            client = factory.return_value.__enter__.return_value
            for code, body, expected in ((200, {}, "accepted"), (410, {}, "invalid_token"), (429, {}, "retry_later"), (403, {}, "provider_error"), (400, {"reason": "BadDeviceToken"}, "invalid_token")):
                client.post.return_value = httpx.Response(code, json=body)
                self.assertEqual(sender.send("ab" * 32), expected)
            args = client.post.call_args
            self.assertEqual(args.kwargs["json"], {"aps": {"content-available": 1}})
            self.assertEqual(args.kwargs["headers"]["apns-priority"], "5")
            self.assertIn("api.sandbox.push.apple.com", args.args[0])
            client.post.side_effect = httpx.ConnectError("synthetic")
            self.assertEqual(sender.send("ab" * 32), "network_error")

    def test_demo_is_read_only_and_configuration_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(Settings(database=directory + "/demo.sqlite", demo=True, automatic=False, secure_cookie=False))
            seed_demo(app)
            client = app.test_client()
            self.assertEqual(client.get("/").status_code, 200)
            self.assertIn("READ-ONLY PREVIEW", client.get("/").text)
            for path in ("/registrations", "/status", "/push", "/api/push"):
                self.assertEqual(client.post(path, json={}).status_code, 403)
            app.extensions["dispatcher"].close()
        with self.assertRaises(ValueError): Settings().validate()
        with self.assertRaises(ValueError): Settings(demo=True, interval=5).validate()

if __name__ == "__main__": unittest.main()
