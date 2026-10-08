"""Validated deployment settings delivered over authenticated LAN enrollment."""
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
    def save(self, server, remote_identifier, ssids):
        server = self.hostname(server)
        remote_identifier = self.hostname(remote_identifier or server)
        if not isinstance(ssids, list) or len(ssids) > 32 or any(not isinstance(v, str) or v != v.strip() or not v or len(v.encode()) > 32 for v in ssids) or len(set(ssids)) != len(ssids):
            raise ValueError('Use at most 32 unique SSIDs, each at most 32 UTF-8 bytes')
        payload = dict(server=server, remoteIdentifier=remote_identifier, trustedSSIDs=ssids, revision=str(uuid.uuid4()))
        with self.database.connect() as db:
            db.execute('INSERT INTO vpn_configuration VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET payload=excluded.payload', (json.dumps(payload),))
        return payload
    def enrollment(self):
        with self.database.connect() as db:
            row = db.execute('SELECT payload FROM vpn_configuration WHERE singleton=1').fetchone()
        return json.loads(row['payload']) if row else None
