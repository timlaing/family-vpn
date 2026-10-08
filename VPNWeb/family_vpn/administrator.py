"""Dashboard-owned administrator verifier, provisioned only during enrollment."""
import base64
import hashlib
import secrets
import uuid

class AdministratorProvisioning:
    def __init__(self, database):
        self.database = database
        with database.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS administrator_configuration (singleton INTEGER PRIMARY KEY CHECK(singleton=1), salt BLOB NOT NULL, verifier BLOB NOT NULL, revision TEXT NOT NULL)')
    def configured(self):
        with self.database.connect() as db:
            return db.execute('SELECT 1 FROM administrator_configuration WHERE singleton=1').fetchone() is not None
    def set_password(self, password, confirmation):
        if not isinstance(password,str) or password != confirmation or len(password)<12 or len(password.encode('utf-8'))>1024:
            raise ValueError('Use matching administrator passwords of at least 12 characters (maximum 1024 UTF-8 bytes).')
        salt=secrets.token_bytes(32)
        verifier=hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt,600_000,32)
        with self.database.connect() as db:
            db.execute('INSERT INTO administrator_configuration VALUES(1,?,?,?) ON CONFLICT(singleton) DO UPDATE SET salt=excluded.salt,verifier=excluded.verifier,revision=excluded.revision',(salt,verifier,str(uuid.uuid4())))
            self.database.event(db,None,'administrator_password','updated_reenrollment_required')
    def enrollment(self):
        with self.database.connect() as db:
            row=db.execute('SELECT salt,verifier,revision FROM administrator_configuration WHERE singleton=1').fetchone()
        if row is None: return None
        return {'algorithm':'pbkdf2-sha256','iterations':600_000,'salt':base64.b64encode(row['salt']).decode(),'verifier':base64.b64encode(row['verifier']).decode(),'revision':row['revision']}
