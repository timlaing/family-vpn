"""Endpoint-scoped HMAC requests shared by dashboards and the push relay."""
import hashlib
import hmac
import ipaddress
import json
import time
import uuid
from urllib.parse import urlsplit
from .provisioning import VPNProvisioning


def server_key(value):
    value = VPNProvisioning.hostname(value)
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return value.lower()


def https_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443):
        raise ValueError('Use an HTTPS address on port 443 without credentials, query or fragment')
    return value.rstrip('/')


def body_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def signature(secret, method, path, body, timestamp, nonce):
    message = '\n'.join((method, path, timestamp, nonce, hashlib.sha256(body).hexdigest())).encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def signed_headers(secret, path, body):
    timestamp, nonce = str(int(time.time())), str(uuid.uuid4())
    return {'Content-Type':'application/json', 'X-Relay-Time':timestamp, 'X-Relay-Nonce':nonce,
            'X-Relay-Signature':signature(secret, 'POST', path, body, timestamp, nonce)}


def verify(secret, path, body, headers):
    try:
        timestamp, nonce = headers['X-Relay-Time'], headers['X-Relay-Nonce']
        if abs(time.time()-int(timestamp)) > 300 or str(uuid.UUID(nonce)) != nonce: return None
        expected = signature(secret, 'POST', path, body, timestamp, nonce)
        return nonce if hmac.compare_digest(expected, headers.get('X-Relay-Signature', '')) else None
    except (KeyError, ValueError, TypeError):
        return None
