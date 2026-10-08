#!/usr/bin/env bash
# Synthetic credentials only; no Apple configuration or external pushes.
set -euo pipefail
image="${1:-vpnweb:test}"
name="vpnweb-smoke-${RANDOM}"
env_file=$(mktemp)
cleanup() { docker rm -fv "$name" >/dev/null 2>&1 || true; rm -f "$env_file"; }
trap cleanup EXIT
python3 - <<'PYTHON' > "$env_file"
import secrets
for name in ('ADMIN_BEARER', 'REGISTRATION_BEARER', 'SESSION_SECRET'):
    print(f'{name}={secrets.token_urlsafe(32)}')
print('AUTO_PUSH=false\nLOCAL_HTTP=true')
PYTHON
docker run -d --name "$name" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges --env-file "$env_file" \
  -p 127.0.0.1::8081 "$image" >/dev/null
port=$(docker port "$name" 8081/tcp | sed 's/.*://')
VPNWEB_SMOKE_PORT="$port" python3 - <<'PYTHON'
import json, os, time, urllib.error, urllib.request
url = 'http://127.0.0.1:' + os.environ['VPNWEB_SMOKE_PORT']
for attempt in range(30):
    try:
        with urllib.request.urlopen(url + '/health', timeout=2) as response:
            assert json.load(response) == {'status': 'ok'}
        break
    except (OSError, urllib.error.URLError): time.sleep(1)
else: raise SystemExit('Container did not become ready')
with urllib.request.urlopen(url + '/login', timeout=2) as response:
    assert b'access key' in response.read().lower()
    assert response.headers['X-Frame-Options'] == 'DENY'
try: urllib.request.urlopen(url + '/api/devices', timeout=2)
except urllib.error.HTTPError as error: assert error.code == 401
else: raise AssertionError('Admin API unexpectedly accessible')
print('Container liveness, login and authentication smoke checks passed')
PYTHON
