"""Validated deployment settings delivered over authenticated LAN enrollment."""
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import ipaddress
import json
import re
import uuid

class VPNProvisioning:
    def __init__(self, database):
        self.database = database
        with database.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS vpn_configuration (singleton INTEGER PRIMARY KEY CHECK(singleton=1), payload TEXT NOT NULL)")
    @staticmethod
    def hostname(value):
        if not isinstance(value, str) or value != value.strip() or not value or len(value) > 253:
            raise ValueError('Invalid VPN gateway or server identity')
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            if value.endswith('.invalid') or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in value.split('.')):
                raise ValueError('Use a hostname or IP address without a URL scheme or port')
        return value
    def save(self, server, remote_identifier, ssids, ca_pem=""):
        ca = None
        if ca_pem:
            try:
                if len(ca_pem.encode()) > 16384: raise ValueError()
                certificate = x509.load_pem_x509_certificate(ca_pem.encode())
                if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca: raise ValueError()
                ca = base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()
            except (ValueError, x509.ExtensionNotFound):
                raise ValueError("Supply a PEM CA certificate, without a private key")
            if "PRIVATE KEY" in ca_pem or ca_pem.count("BEGIN CERTIFICATE") != 1: raise ValueError("Supply one CA certificate only")
        server = self.hostname(server)
        remote_identifier = self.hostname(remote_identifier or server)
        if not isinstance(ssids, list) or len(ssids) > 32 or any(not isinstance(v, str) or v != v.strip() or not v or len(v.encode()) > 32 for v in ssids) or len(set(ssids)) != len(ssids):
            raise ValueError('Use at most 32 unique SSIDs, each at most 32 UTF-8 bytes')
        payload = {"server": server, "remoteIdentifier": remote_identifier, "trustedSSIDs": ssids, "revision": str(uuid.uuid4()), "caCertificate": ca}
        with self.database.connect() as db:
            db.execute('INSERT INTO vpn_configuration VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET payload=excluded.payload', (json.dumps(payload),))
        return payload
    def certificate_pem(self, uploaded, pasted, remove=False):
        current = self.enrollment()
        data = uploaded.read(16385) if uploaded and uploaded.filename else b""
        if len(data) > 16384: raise ValueError("CA certificate must be at most 16 KB")
        if sum((bool(data), bool(pasted), remove)) > 1:
            raise ValueError("Choose one certificate action: upload, paste or remove")
        if remove: return ""
        if data:
            try:
                if b"-----BEGIN" in data:
                    return data.decode("ascii")
                return x509.load_der_x509_certificate(data).public_bytes(serialization.Encoding.PEM).decode("ascii")
            except (ValueError, UnicodeDecodeError):
                raise ValueError("Upload a PEM or DER CA certificate") from None
        if pasted: return pasted
        if current and current["caCertificate"]:
            return x509.load_der_x509_certificate(base64.b64decode(current["caCertificate"])).public_bytes(serialization.Encoding.PEM).decode("ascii")
        return ""

    def enrollment(self):
        with self.database.connect() as db:
            row = db.execute('SELECT payload FROM vpn_configuration WHERE singleton=1').fetchone()
        return json.loads(row['payload']) if row else None
