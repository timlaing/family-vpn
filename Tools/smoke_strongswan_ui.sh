#!/usr/bin/env bash
set -euo pipefail
ui_image="${1:-family-vpn-configuration:test}"
vpn_image="${2:-family-vpn-strongswan:test}"
name="familyvpn-configuration-smoke-${RANDOM}"
cleanup() {
  docker rm -f "$name" "$name-vpn" >/dev/null 2>&1 || true
  docker volume rm "$name-data" "$name-ca" "$name-control" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker volume create "$name-data" >/dev/null
docker volume create "$name-ca" >/dev/null
docker volume create "$name-control" >/dev/null
docker run -d --name "$name" \
  -v "$name-data:/data" -v "$name-ca:/authority" -v "$name-control:/control:ro" "$ui_image" >/dev/null
for attempt in {1..30}; do
  if docker exec "$name" /opt/venv/bin/python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8080/login")' >/dev/null 2>&1; then break; fi
  if [[ "$attempt" == 30 ]]; then docker logs "$name"; exit 1; fi
  sleep 1
done
docker exec -i "$name" /opt/venv/bin/python - <<'PYTHON'
from http.cookiejar import CookieJar
import re
from urllib.request import build_opener, HTTPCookieProcessor
from urllib.parse import urlencode
client=build_opener(HTTPCookieProcessor(CookieJar()))
base='http://127.0.0.1:8080'
def csrf(path):
    return re.search(r'name="csrf_token" value="([^"]+)"',client.open(base+path).read().decode())[1]
def post(path,values):
    return client.open(base+path,urlencode(values).encode()).read().decode()
post('/initialize',dict(csrf_token=csrf('/initialize'),password='synthetic-administrator-password',confirmation='synthetic-administrator-password'))
page=post('/',dict(csrf_token=csrf('/'),server='vpn.example.org',pool='10.20.30.0/24',dns='192.168.10.53',lan='192.168.10.0/24',allowed='192.168.10.53/32'))
assert 'Device access' in page
assert 'No device accounts yet' in page
page=post('/accounts',dict(csrf_token=csrf('/accounts'),username='smoke-device',password='synthetic-vpn-password',action='add'))
assert 'Enabled' in page
assert 'smoke-device' in page
assert 'synthetic-vpn-password' not in page
assert client.open(base+'/ca.pem').read().startswith(b'-----BEGIN CERTIFICATE-----')
page=post('/advanced',dict(csrf_token=csrf('/advanced'),mode='radius',server='192.0.2.54',secret='synthetic-radius-secret',auth_port='1812',acct_port='1813',nas_identifier='family-vpn'))
assert 'synthetic-radius-secret' not in page
assert 'Managed by your RADIUS server' in client.open(base+'/accounts').read().decode()
post('/advanced',dict(csrf_token=csrf('/advanced'),mode='local'))
assert 'smoke-device' in client.open(base+'/accounts').read().decode()
PYTHON
# Simulate and migrate private volumes from the older root-running UI.
docker exec --user root "$name" chown -R 0:0 /data /authority
docker run --rm --user root --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE \
  -v "$name-data:/data" -v "$name-ca:/authority" --entrypoint chown \
  "$ui_image" -R 10001:10001 /data /authority
docker restart "$name" >/dev/null
docker exec "$name" /opt/venv/bin/python -c 'import os; assert os.geteuid() == 10001'
docker run -d --name "$name-vpn" --cap-add NET_ADMIN --cap-add NET_RAW \
  --sysctl net.ipv4.ip_forward=1 -e VPN_CONFIGURATION_DIR=/data -e VPN_CONTROL_DIR=/control \
  -v "$name-data:/data:ro" -v "$name-control:/control" "$vpn_image" >/dev/null
for attempt in {1..30}; do
  if docker exec "$name-vpn" swanctl --list-conns 2>/dev/null | grep -q 'family-vpn:'; then break; fi
  if [[ "$attempt" == 30 ]]; then docker logs "$name-vpn"; exit 1; fi
  sleep 1
done
docker exec "$name-vpn" sh -c 'test -f /data/ready && test ! -d /data/ca && test ! -d /authority'
docker exec "$name" /opt/venv/bin/python -c 'from pathlib import Path; import json; assert "smoke-device" in json.loads(Path("/data/accounts.json").read_text()); assert Path("/authority/ca/ca-key.pem").exists()'
daemon_pid=$(docker exec "$name-vpn" /opt/control/bin/python -c 'from pathlib import Path; print(next(p.parent.name for p in Path("/proc").glob("[0-9]*/comm") if p.read_text().strip() == "charon"))' )
docker exec -i "$name" /opt/venv/bin/python - <<'PYTHON'
from http.cookiejar import CookieJar
import json
import re
import time
from urllib.request import build_opener, HTTPCookieProcessor
from urllib.parse import urlencode
client = build_opener(HTTPCookieProcessor(CookieJar()))
base = 'http://127.0.0.1:8080'
def csrf(path):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.open(base+path).read().decode())[1]
def post(path, values):
    return client.open(base+path, urlencode(values).encode()).read().decode()
def applied():
    for _ in range(30):
        status = json.load(client.open(base+'/reload-status'))
        if status['status'] == 'applied':
            return
        time.sleep(1)
    raise AssertionError(status)
post('/login', dict(csrf_token=csrf('/login'), password='synthetic-administrator-password'))
applied()
for action in ('disable', 'enable', 'password', 'delete'):
    post('/accounts', dict(csrf_token=csrf('/accounts'), username='smoke-device',
                          action=action, password='synthetic-replacement-password'))
    applied()
assert 'No device accounts yet' in client.open(base+'/accounts').read().decode()
PYTHON
[[ "$daemon_pid" = "$(docker exec "$name-vpn" /opt/control/bin/python -c 'from pathlib import Path; print(next(p.parent.name for p in Path("/proc").glob("[0-9]*/comm") if p.read_text().strip() == "charon"))' )" ]]
docker exec "$name-vpn" /opt/control/bin/python -c 'import vici; assert not vici.Session().get_shared()["keys"]'
echo 'Browser setup, persistence, automatic account reloads and stale credential removal verified'
