"""Portable relay: endpoint registrations only; never persist device information."""
import base64
import hashlib
import http.client
import ipaddress
import os
import socket
import sqlite3
import ssl
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from cryptography.fernet import Fernet
from flask import Flask, abort, jsonify, request
from .relay_protocol import body_bytes, https_url, server_key, signed_headers, verify


class PublicHTTPS(http.client.HTTPSConnection):
    """Resolve once, reject internal addresses and pin TLS to the original host."""
    def connect(self):
        addresses = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
            raise ValueError('Dashboard callback must resolve only to public addresses')
        self.sock = socket.create_connection((addresses[0][4][0], 443), timeout=self.timeout)
        self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)


def callback(url, secret, payload):
    parsed = urlsplit(https_url(url))
    body = body_bytes(payload)
    connection = PublicHTTPS(parsed.hostname, timeout=10)
    try:
        connection.request('POST', parsed.path or '/', body, signed_headers(secret, parsed.path or '/', body))
        response = connection.getresponse()
        return response.status == 204
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        connection.close()


class RelayStore:
    def __init__(self, path, master):
        self.path = path
        self.cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master.encode()).digest()))
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS endpoints(server TEXT PRIMARY KEY, callback TEXT NOT NULL, secret BLOB NOT NULL, quota INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS requests(server TEXT NOT NULL, nonce TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY(server,nonce));''')
        os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        with sqlite3.connect(self.path, timeout=10) as db:
            db.row_factory = sqlite3.Row
            yield db

    def endpoint(self, server):
        with self.connect() as db:
            row = db.execute('SELECT * FROM endpoints WHERE server=?',(server,)).fetchone()
        if not row: return None
        return {**dict(row), 'secret':self.cipher.decrypt(row['secret']).decode()}

    def register(self, server, url, token, limit):
        import hmac
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT secret FROM endpoints WHERE server=?',(server,)).fetchone()
            if existing and not hmac.compare_digest(self.cipher.decrypt(existing['secret']).decode(),token): return False
            db.execute('INSERT INTO endpoints VALUES(?,?,?,?) ON CONFLICT(server) DO UPDATE SET callback=excluded.callback,quota=excluded.quota',
                       (server,url,self.cipher.encrypt(token.encode()),limit))
        return True

    def claim(self, server, nonce, limit):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            now = time.time()
            db.execute('DELETE FROM requests WHERE at<?',(now-600,))
            if db.execute('SELECT 1 FROM requests WHERE server=? AND nonce=?',(server,nonce)).fetchone(): return 409
            count = db.execute('SELECT COUNT(*) FROM requests WHERE server=? AND at>?',(server,now-60)).fetchone()[0]
            if count >= limit: return 429
            db.execute('INSERT INTO requests VALUES(?,?,?)',(server,nonce,now))
        return None


def create_relay(path, enrollment, master, sender, max_limit=100, callback_sender=callback):
    if len(enrollment) < 32 or len(master) < 32: raise ValueError('Provide separate 32+ character enrollment and storage secrets')
    if type(max_limit) is not int or not 1 <= max_limit <= 100: raise ValueError('Use a maximum rate between 1 and 100')
    store = RelayStore(path, master)
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 8192
    app.extensions['relay_store'] = store

    @app.after_request
    def private_response(response):
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.post('/endpoints')
    def enroll():
        import hmac
        if not hmac.compare_digest(request.headers.get('Authorization','').encode(), ('Bearer '+enrollment).encode()): abort(401)
        value = request.get_json(silent=True)
        try:
            if not isinstance(value, dict) or set(value) != {'server','callback','token','limit'}: raise ValueError()
            server = server_key(value['server'])
            url = https_url(value['callback'])
            token, limit = value['token'], value['limit']
            if not isinstance(token,str) or not 32 <= len(token) <= 256 or any(ord(char) < 33 or ord(char) > 126 for char in token) or type(limit) is not int or not 1 <= limit <= max_limit: raise ValueError()
        except (ValueError, TypeError): abort(400)
        existing = store.endpoint(server)
        if existing:
            if not hmac.compare_digest(existing['secret'],token): abort(409)
            nonce = verify(existing['secret'], request.path, request.get_data(), request.headers)
            if nonce is None: abort(401)
            blocked = store.claim(server, nonce, existing['quota'])
            if blocked: abort(blocked)
        # Prove callback ownership before retaining registration or sending device data.
        if not callback_sender(url, token, {'server':server,'kind':'registration'}): return jsonify(error='callback_verification_failed'),400
        if not store.register(server,url,token,limit): abort(409)
        return jsonify(server=server,limit=limit),201

    @app.post('/push')
    def push():
        from .app import TOKEN, identifier
        value = request.get_json(silent=True)
        try:
            if not isinstance(value,dict) or set(value) != {'server','device','token','command'}: raise ValueError()
            server = server_key(value['server'])
            identifier(value['device'])
            if not isinstance(value['token'],str) or not TOKEN.fullmatch(value['token']) or len(value['token']) > 512: raise ValueError()
            if value['command'] is not None and not isinstance(value['command'],dict): raise ValueError()
        except (ValueError,TypeError): abort(400)
        endpoint = store.endpoint(server)
        if endpoint is None: abort(401)
        nonce = verify(endpoint['secret'], request.path, request.get_data(), request.headers)
        if nonce is None: abort(401)
        blocked = store.claim(server,nonce,endpoint['quota'])
        if blocked: return jsonify(error='rate_limit' if blocked == 429 else 'replay'),blocked
        result = sender.send(value['token'],command=value['command'])
        delivered = callback_sender(endpoint['callback'],endpoint['secret'],
            {'server':server,'kind':'push_result','device':value['device'],'token':value['token'],'result':result})
        return jsonify(result=result, callback='delivered' if delivered else 'failed')

    @app.get('/health')
    def health(): return jsonify(status='ok')
    return app
