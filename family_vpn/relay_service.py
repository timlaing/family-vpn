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
            columns = {row['name'] for row in db.execute('PRAGMA table_info(endpoints)')}
            for column in ('last_push', 'rotated_at'):
                if column not in columns:
                    db.execute(f'ALTER TABLE endpoints ADD COLUMN {column} REAL NOT NULL DEFAULT 0')
                    db.execute(f'UPDATE endpoints SET {column}=?',(time.time(),))
        os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection: yield connection
        finally: connection.close()

    def prune(self):
        with self.connect() as db:
            db.execute('DELETE FROM endpoints WHERE last_push<?', (time.time()-30*86400,))
            db.execute('DELETE FROM requests WHERE at<? OR server NOT IN (SELECT server FROM endpoints)', (time.time()-600,))

    def endpoint(self, server):
        self.prune()
        with self.connect() as db:
            row = db.execute('SELECT * FROM endpoints WHERE server=?',(server,)).fetchone()
        if not row: return None
        return {**dict(row), 'secret':self.cipher.decrypt(row['secret']).decode()}

    def register(self, server, url, token, limit):
        self.prune()
        with self.connect() as db:
            try:
                db.execute('INSERT INTO endpoints(server,callback,secret,quota,last_push,rotated_at) VALUES(?,?,?,?,?,?)',
                    (server,url,self.cipher.encrypt(token.encode()),limit,time.time(),time.time()))
            except sqlite3.IntegrityError: return False
        return True

    def rotate(self, server, existing, token, callback_url):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT secret,rotated_at FROM endpoints WHERE server=?',(server,)).fetchone()
            if not row or self.cipher.decrypt(row['secret']).decode() != existing: return None
            # Retrying with the newly installed key is safe after a lost response.
            if existing == token: return row['rotated_at']
            now = time.time()
            db.execute('UPDATE endpoints SET secret=?,rotated_at=?,callback=? WHERE server=?',
                (self.cipher.encrypt(token.encode()),now,callback_url,server))
        return now

    def touched(self, server):
        with self.connect() as db:
            db.execute('UPDATE endpoints SET last_push=? WHERE server=?',(time.time(),server))

    def summary(self):
        self.prune()
        with self.connect() as db:
            return [dict(row) for row in db.execute('SELECT server,last_push,rotated_at,quota FROM endpoints ORDER BY server')]

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


def valid_token(token):
    return isinstance(token,str) and 32 <= len(token) <= 256 and all(33 <= ord(char) <= 126 for char in token)


class RelayViews:
    """Authenticate and validate each relay operation independently."""
    def __init__(self, app, store, enrollment, sender, max_limit, callback_sender, authorize):
        self.store, self.enrollment, self.sender = store, enrollment, sender
        self.max_limit, self.callback_sender, self.authorize = max_limit, callback_sender, authorize
        app.before_request(self.trusted_proxy)
        app.after_request(self.private_response)
        app.add_url_rule('/endpoints', endpoint='enroll', view_func=self.enroll, methods=['POST'])
        app.add_url_rule('/rotate', endpoint='rotate', view_func=self.rotate, methods=['POST'])
        app.add_url_rule('/push', endpoint='push', view_func=self.push, methods=['POST'])
        app.add_url_rule('/health', endpoint='health', view_func=self.health, methods=['GET'])

    def trusted_proxy(self):
        if self.authorize is not None and request.path != '/health': self.authorize()

    def private_response(self, response):
        response.headers['Cache-Control'] = 'no-store'
        return response

    @staticmethod
    def payload(fields):
        value = request.get_json(silent=True)
        if not isinstance(value, dict) or set(value) != fields: abort(400)
        return value

    def enrollment_payload(self):
        value = self.payload({'server','callback','token','limit'})
        try:
            server = server_key(value['server'])
            url = https_url(value['callback'])
            token, limit = value['token'], value['limit']
            cap = self.max_limit() if callable(self.max_limit) else self.max_limit
            if not valid_token(token) or type(limit) is not int or not 1 <= limit <= cap: raise ValueError()
        except (ValueError, TypeError): abort(400)
        return server, url, token, limit

    def enroll(self):
        import hmac
        if self.authorize is None and not hmac.compare_digest(request.headers.get('Authorization','').encode(), ('Bearer '+self.enrollment).encode()): abort(401)
        server, url, token, limit = self.enrollment_payload()
        if self.store.endpoint(server): return jsonify(error='endpoint_exists'),409
        # Prove callback ownership before retaining registration or sending device data.
        if not self.callback_sender(url, token, {'server':server,'kind':'registration'}): return jsonify(error='callback_verification_failed'),400
        if not self.store.register(server,url,token,limit): abort(409)
        return jsonify(server=server,limit=limit,rotated_at=self.store.endpoint(server)['rotated_at']),201

    def rotation_payload(self):
        value = self.payload({'server','token','callback'})
        try:
            server = server_key(value['server'])
            url = https_url(value['callback'])
            if not valid_token(value['token']): raise ValueError()
        except (ValueError,TypeError): abort(400)
        return value, server, url

    @staticmethod
    def authenticate(endpoint):
        nonce = verify(endpoint['secret'],request.path,request.get_data(),request.headers)
        if nonce is None: abort(401)
        return nonce

    def rotate(self):
        value, server, url = self.rotation_payload()
        endpoint = self.store.endpoint(server)
        if endpoint is None: return jsonify(error='endpoint_missing'),404
        nonce = self.authenticate(endpoint)
        blocked = self.store.claim(server,nonce,endpoint['quota'])
        if blocked: abort(blocked)
        if url != endpoint['callback'] and not self.callback_sender(url,endpoint['secret'],{'server':server,'kind':'registration'}):
            return jsonify(error='callback_verification_failed'),400
        rotated_at = self.store.rotate(server,endpoint['secret'],value['token'],url)
        if rotated_at is None: abort(409)
        return jsonify(rotated_at=rotated_at)

    def push_payload(self):
        from .app import TOKEN, identifier
        value = self.payload({'server','device','token','command'})
        try:
            server = server_key(value['server'])
            identifier(value['device'])
            if not isinstance(value['token'],str) or not TOKEN.fullmatch(value['token']) or len(value['token']) > 512: raise ValueError()
            if value['command'] is not None and not isinstance(value['command'],dict): raise ValueError()
        except (ValueError,TypeError): abort(400)
        return value, server

    def push(self):
        value, server = self.push_payload()
        endpoint = self.store.endpoint(server)
        if endpoint is None: abort(401)
        nonce = self.authenticate(endpoint)
        if time.time()-endpoint['rotated_at'] >= 86400: return jsonify(error='rotation_required'),409
        blocked = self.store.claim(server,nonce,endpoint['quota'])
        if blocked: return jsonify(error='rate_limit' if blocked == 429 else 'replay'),blocked
        result = self.sender.send(value['token'],command=value['command'])
        self.store.touched(server)
        delivered = self.callback_sender(endpoint['callback'],endpoint['secret'],
            {'server':server,'kind':'push_result','device':value['device'],'token':value['token'],'result':result})
        return jsonify(result=result, callback='delivered' if delivered else 'failed')

    def health(self): return jsonify(status='ok')


def create_relay(path, enrollment, master, sender, max_limit=100, callback_sender=callback, authorize=None):
    if len(enrollment) < 32 or len(master) < 32: raise ValueError('Provide separate 32+ character enrollment and storage secrets')
    if not callable(max_limit) and (type(max_limit) is not int or not 1 <= max_limit <= 100): raise ValueError('Use a maximum rate between 1 and 100')
    store = RelayStore(path, master)
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 8192
    app.extensions['relay_store'] = store
    RelayViews(app, store, enrollment, sender, max_limit, callback_sender, authorize)
    return app
