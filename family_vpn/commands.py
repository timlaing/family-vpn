"""Durable, device-scoped Ed25519 commands. Never trust APNs delivery as execution."""
import base64
import json
import os
import time
import uuid
from pathlib import Path
from .administrator import AdministratorProvisioning
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ACTIONS = {'refresh_status', 'suspend', 'enable', 'reprovision_admin'}

def encode(value): return base64.b64encode(value).decode()

class Commands:
    def __init__(self, database):
        self.database = database
        self.administrator = AdministratorProvisioning(database)
        path = Path(database.path).parent / 'command-signing.key'
        try:
            with path.open('xb') as output:
                os.chmod(path, 0o600)
                output.write(Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        except FileExistsError: pass
        os.chmod(path, 0o600)
        self.key = Ed25519PrivateKey.from_private_bytes(path.read_bytes())
        self.public_key = encode(self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        with database.connect() as db:
            columns = {row['name'] for row in db.execute('PRAGMA table_info(devices)')}
            if 'administrator_capable' not in columns: db.execute('ALTER TABLE devices ADD COLUMN administrator_capable INTEGER NOT NULL DEFAULT 0')
            if 'tunnel_seen' not in columns: db.execute('ALTER TABLE devices ADD COLUMN tunnel_seen REAL')
            if 'command_epoch' not in columns: db.execute('ALTER TABLE devices ADD COLUMN command_epoch TEXT')
            db.executescript('''CREATE TABLE IF NOT EXISTS commands(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT UNIQUE NOT NULL,
                device TEXT NOT NULL, epoch TEXT NOT NULL, action TEXT NOT NULL,
                issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, suspend_until INTEGER,
                state TEXT NOT NULL, last_attempt REAL, delivery TEXT, acknowledged REAL);
                CREATE INDEX IF NOT EXISTS commands_pending ON commands(device,state,sequence);''')
            command_columns = {row['name'] for row in db.execute('PRAGMA table_info(commands)')}
            if 'administrator_json' not in command_columns: db.execute('ALTER TABLE commands ADD COLUMN administrator_json TEXT')
    def expire(self, db):
        db.execute("UPDATE commands SET state='expired' WHERE state='pending' AND expires_at<=?",(int(time.time()),))
    def queue(self, device, action, duration=None):
        if action not in ACTIONS or (action!='suspend' and duration is not None): raise ValueError('Invalid command')
        if duration is not None and (type(duration) is not int or not 900<=duration<=86400): raise ValueError('Use 15 minutes to 24 hours')
        now=int(time.time()); until=now+duration if duration is not None else None
        expiry=min(now+86400,until) if until else now+(3600 if action=='refresh_status' else 86400)
        request_id=str(uuid.uuid4())
        with self.database.connect() as db:
            self.expire(db)
            row=db.execute('SELECT command_epoch,administrator_capable FROM devices WHERE id=?',(device,)).fetchone()
            if row is None: raise LookupError('Unknown installation')
            if not row['command_epoch']: raise RuntimeError('Update and re-enroll this installation')
            provision = None
            if action=='reprovision_admin':
                if not row['administrator_capable']: raise RuntimeError('Update and re-enroll this installation')
                # Snapshot the exact dashboard verifier at queue time.
                provision = self.administrator.enrollment()
                if provision is None: raise RuntimeError('Set the administrator password before reprovisioning')
                db.execute("UPDATE commands SET state='superseded' WHERE device=? AND action='reprovision_admin' AND state='pending'",(device,))
            elif action=='refresh_status':
                db.execute("UPDATE commands SET state='superseded' WHERE device=? AND action='refresh_status' AND state='pending'",(device,))
            else:
                db.execute("UPDATE commands SET state='superseded' WHERE device=? AND action IN ('suspend','enable') AND state='pending'",(device,))
            db.execute('INSERT INTO commands(request_id,device,epoch,action,issued_at,expires_at,suspend_until,state,administrator_json) VALUES(?,?,?,?,?,?,?,?,?)',
                (request_id,device,row['command_epoch'],action,now,expiry,until,'pending',json.dumps(provision,separators=(',',':')) if provision else None))
            db.execute("DELETE FROM commands WHERE device=? AND state!='pending' AND sequence NOT IN (SELECT sequence FROM commands WHERE device=? ORDER BY sequence DESC LIMIT 200)",(device,device))
            self.database.event(db,device,'command',action)
        return request_id
    def envelope(self, row):
        body={field:row[field] for field in ('request_id','device','epoch','sequence','action','issued_at','expires_at','suspend_until')}
        if row["administrator_json"]: body["administrator"]=json.loads(row["administrator_json"])
        raw=json.dumps(body,separators=(',',':'),sort_keys=True).encode()
        return {'body':encode(raw),'signature':encode(self.key.sign(raw))}
    def pending(self, device):
        with self.database.connect() as db:
            self.expire(db)
            return [self.envelope(row) for row in db.execute("SELECT * FROM commands WHERE device=? AND state='pending' ORDER BY sequence",(device,))]
    def next_delivery(self, device):
        with self.database.connect() as db:
            self.expire(db)
            row=db.execute("SELECT * FROM commands WHERE device=? AND state='pending' AND (last_attempt IS NULL OR last_attempt<?) ORDER BY (action='refresh_status'),sequence DESC LIMIT 1",(device,time.time()-900)).fetchone()
            return dict(row) if row else None
    def delivered(self, sequence, result):
        with self.database.connect() as db:
            db.execute('UPDATE commands SET last_attempt=?,delivery=? WHERE sequence=?',(time.time(),result,sequence))
    def acknowledge(self, device, request_id, result):
        if result not in {'executed','failed'}: raise ValueError('Invalid result')
        with self.database.connect() as db:
            row=db.execute('SELECT c.state,c.epoch,d.command_epoch FROM commands c JOIN devices d ON c.device=d.id WHERE c.device=? AND c.request_id=?',(device,request_id)).fetchone()
            if row is None: raise LookupError('Unknown command')
            if row['epoch']!=row['command_epoch']: raise RuntimeError('Enrollment changed')
            if row['state'] in {'executed','failed'}:
                if row['state']!=result: raise RuntimeError('Result already acknowledged')
                return
            db.execute('UPDATE commands SET state=?,acknowledged=? WHERE device=? AND request_id=?',(result,time.time(),device,request_id))
            self.database.event(db,device,'command_result',result)
    def public(self):
        with self.database.connect() as db:
            self.expire(db)
            return [dict(row) for row in db.execute('SELECT request_id,device,sequence,action,issued_at,expires_at,suspend_until,state,delivery,acknowledged FROM commands ORDER BY sequence DESC LIMIT 100')]
