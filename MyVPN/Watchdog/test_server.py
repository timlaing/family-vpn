import unittest
import uuid
from server import validate_registration, push_headers
class ServerTests(unittest.TestCase):
    def test_registration(self):
        identifier = str(uuid.uuid4())
        self.assertEqual(validate_registration({"id": identifier, "token": "a" * 64}), (identifier, "a" * 64))
        for length in (32, 64, 128):
            self.assertEqual(validate_registration({"id": identifier, "token": "a" * length}), (identifier, "a" * length))
        for value in ({"id": identifier, "token": "abc"}, {"id": "bad", "token": "a" * 64}, {"id": identifier, "token": "secret"}, {}):
            with self.assertRaises((ValueError, TypeError, AttributeError)): validate_registration(value)
    def test_background_headers(self):
        headers = push_headers("test", "test.bundle")
        self.assertEqual(headers["apns-push-type"], "background")
        self.assertEqual(headers["apns-priority"], "5")
        self.assertEqual(headers["apns-collapse-id"], "policy-check")

class DeliveryTests(unittest.TestCase):
    def test_invalid_interval_and_private_fields_rejected(self):
        from unittest.mock import patch
        import server
        for interval in ("1799", "3601", "bad"):
            with patch.dict("os.environ", {"WATCHDOG_INTERVAL_SECONDS": interval}):
                with self.assertRaises(ValueError): server.validated_interval()
        with patch.dict("os.environ", {"WATCHDOG_INTERVAL_SECONDS": "2700"}):
            self.assertEqual(server.validated_interval(), 2700)
        with self.assertRaises(ValueError):
            server.validate_registration({"id": str(uuid.uuid4()), "token": "a" * 64, "password": "never-store"})

    def test_delivery_continues_after_network_error_and_prunes_invalid_tokens(self):
        import os
        import tempfile
        import httpx
        import server
        from unittest.mock import patch
        identifiers = [str(uuid.uuid4()) for _ in range(4)]
        tokens = [letter * 64 for letter in "abcd"]
        class Client:
            def __init__(self, **kwargs): self.calls = 0
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def post(self, url, headers, json):
                self.calls += 1
                assert json == {"aps": {"content-available": 1}}
                assert headers["apns-priority"] == "5"
                if self.calls == 1: raise httpx.ConnectError("synthetic network failure")
                if self.calls == 2: return httpx.Response(410, json={"reason": "Unregistered"})
                if self.calls == 3: return httpx.Response(503, content=b"not-json")
                return httpx.Response(200)
        client = Client()
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "WATCHDOG_DATABASE": directory + "/test.sqlite", "APNS_TOPIC": "test.bundle", "APNS_ENVIRONMENT": "sandbox"
        }), patch.object(server, "provider_jwt", return_value="synthetic-jwt"), patch.object(httpx, "Client", return_value=client):
            with server.database() as connection:
                connection.executemany("INSERT INTO installations VALUES (?, ?)", zip(identifiers, tokens))
            server.send_checks()
            self.assertEqual(client.calls, 4)
            with server.database() as connection:
                remaining = {row[0] for row in connection.execute("SELECT id FROM installations")}
            self.assertEqual(remaining, {identifiers[0], identifiers[2], identifiers[3]})

    def test_rotated_token_is_not_deleted_by_old_delivery_response(self):
        import os
        import tempfile
        import httpx
        import server
        from unittest.mock import patch
        identifier = str(uuid.uuid4())
        old, new = "a" * 64, "b" * 64
        class Client:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def post(self, *args, **kwargs):
                with server.database() as connection:
                    connection.execute("UPDATE installations SET token=? WHERE id=?", (new, identifier))
                return httpx.Response(410)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "WATCHDOG_DATABASE": directory + "/test.sqlite", "APNS_TOPIC": "test.bundle"
        }), patch.object(server, "provider_jwt", return_value="synthetic-jwt"), patch.object(httpx, "Client", Client):
            with server.database() as connection:
                connection.execute("INSERT INTO installations VALUES (?, ?)", (identifier, old))
            server.send_checks()
            with server.database() as connection:
                self.assertEqual(connection.execute("SELECT token FROM installations").fetchone()[0], new)


class RegistrationHTTPTests(unittest.TestCase):
    def test_authentication_input_limits_and_token_rotation(self):
        import json
        import os
        import tempfile
        import threading
        import http.client
        from unittest.mock import patch
        from http.server import ThreadingHTTPServer
        import server
        identifier = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "WATCHDOG_DATABASE": directory + "/test.sqlite", "REGISTRATION_BEARER": "x" * 32
        }):
            service = ThreadingHTTPServer(("127.0.0.1", 0), server.RegistrationHandler)
            thread = threading.Thread(target=service.serve_forever, daemon=True)
            thread.start()
            def request(body, authorized=True, path="/registrations"):
                connection = http.client.HTTPConnection(*service.server_address, timeout=3)
                headers = {"Content-Type": "application/json"}
                if authorized: headers["Authorization"] = "Bearer " + "x" * 32
                try:
                    connection.request("POST", path, body, headers)
                    response = connection.getresponse(); response.read()
                    return response.status
                finally: connection.close()
            try:
                payload = json.dumps({"id": identifier, "token": "a" * 64})
                self.assertEqual(request(payload, authorized=False), 401)
                self.assertEqual(request(payload, path="/other"), 404)
                self.assertEqual(request("bad-json"), 400)
                self.assertEqual(request("x" * 1025), 400)
                self.assertEqual(request(payload), 204)
                self.assertEqual(request(json.dumps({"id": identifier, "token": "b" * 64})), 204)
                with server.database() as connection:
                    self.assertEqual(connection.execute("SELECT id, token FROM installations").fetchall(), [(identifier, "b" * 64)])
            finally:
                service.shutdown(); service.server_close(); thread.join(timeout=3)

if __name__ == "__main__": unittest.main()
