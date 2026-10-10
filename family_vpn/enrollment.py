"""Short-lived single-use invitations and device-scoped registration credentials."""
import base64
import hashlib
import json
import secrets
import time
import qrcode
from qrcode.image.svg import SvgPathFillImage
from markupsafe import Markup


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


class Enrollment:
    def __init__(self, database):
        self.database = database
        with database.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS enrollment_invites (hash TEXT PRIMARY KEY, expires REAL NOT NULL)")
            if 'enrollment_hash' not in {row['name'] for row in db.execute('PRAGMA table_info(devices)')}:
                db.execute("ALTER TABLE devices ADD COLUMN enrollment_hash TEXT")

    def issue(self, endpoint):
        token = 'invite_' + secrets.token_urlsafe(32)
        expires = time.time() + 600
        with self.database.connect() as db:
            db.execute('DELETE FROM enrollment_invites WHERE expires<=?', (time.time(),))
            # Issuing a new invitation revokes previous unused invitations.
            db.execute('DELETE FROM enrollment_invites')
            db.execute('INSERT INTO enrollment_invites VALUES(?,?)', (token_hash(token), expires))
        payload = base64.urlsafe_b64encode(json.dumps({'endpoint':endpoint,'token':token},separators=(',',':')).encode()).decode().rstrip('=')
        link = 'familyvpn://enroll#' + payload
        image = qrcode.make(link, image_factory=SvgPathFillImage)
        return {'link':link,'qr':Markup(image.to_string(encoding='unicode')),'expires':expires}

    def authorize(self, db, bearer, device, master):
        # Called inside the registration transaction: no two devices can consume a code.
        if secrets.compare_digest(bearer.encode(), master.encode()):
            return None
        if bearer.startswith('invite_'):
            result = db.execute('DELETE FROM enrollment_invites WHERE hash=? AND expires>?', (token_hash(bearer),time.time()))
            if not result.rowcount: raise ValueError('Invalid or expired invitation')
            credential = 'device_' + secrets.token_urlsafe(32)
            return credential
        row = db.execute('SELECT enrollment_hash FROM devices WHERE id=?', (device,)).fetchone()
        if not bearer.startswith('device_') or not row or not row['enrollment_hash'] or not secrets.compare_digest(row['enrollment_hash'],token_hash(bearer)):
            raise ValueError('Invalid device enrollment credential')
        return None
