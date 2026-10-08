"""Generate local development secrets directly into .env, never stdout."""
import os
import secrets
from pathlib import Path
path = Path('.env')
with path.open('x') as output:
    os.chmod(path, 0o600)
    for name in ('ADMIN_BEARER', 'REGISTRATION_BEARER', 'SESSION_SECRET'):
        output.write(f'{name}={secrets.token_urlsafe(32)}\n')
    output.write('LOCAL_HTTP=true\nAUTO_PUSH=false\nAPNS_ENVIRONMENT=sandbox\nAPNS_TOPIC=uk.co.laingcorp.myvpn\n')
print('Created private .env. Review locally; do not commit or share it.')
