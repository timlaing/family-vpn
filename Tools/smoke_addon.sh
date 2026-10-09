#!/usr/bin/env bash
set -euo pipefail
image="${1:-vpnweb-addon:test}"
name="vpnweb-addon-smoke-${RANDOM}"
volume="${name}-data"
cleanup() {
  result=$?
  if [[ "$result" != 0 ]]; then docker logs --tail 100 "$name" >&2 || true; fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker volume create "$volume" >/dev/null
# Supervisor mounts root-owned data. A runner-owned mktemp bind directory fails
# on Linux when the app runs as root with all capabilities dropped.
docker run --rm --mount "type=volume,source=$volume,target=/data" --entrypoint python "$image" -c '
import json,os,secrets
os.chown("/data",0,0)
os.chmod("/data",0o700)
with open("/data/options.json","w") as output:
    json.dump({"admin_bearer":secrets.token_urlsafe(32),"registration_bearer":secrets.token_urlsafe(32),"automatic":False},output)
os.chmod("/data/options.json",0o600)
'
docker run -d --name "$name" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges --mount "type=volume,source=$volume,target=/data" \
  -p 127.0.0.1::8500 -p 127.0.0.1::8099 "$image" >/dev/null
rest=$(docker port "$name" 8500/tcp | sed 's/.*://')
ingress=$(docker port "$name" 8099/tcp | sed 's/.*://')
VPNWEB_REST_PORT="$rest" VPNWEB_INGRESS_PORT="$ingress" python3 - <<'PY'
import json,os,time,urllib.error,urllib.request
rest='http://127.0.0.1:'+os.environ['VPNWEB_REST_PORT']
ingress='http://127.0.0.1:'+os.environ['VPNWEB_INGRESS_PORT']
for attempt in range(30):
    try:
        with urllib.request.urlopen(rest+'/health',timeout=2) as response: assert json.load(response)=={'status':'ok'}
        break
    except (OSError,urllib.error.URLError): time.sleep(1)
else: raise SystemExit('Home Assistant image failed to start')
for path,status in [('/',404),('/configuration',404),('/api/devices',401)]:
    try: urllib.request.urlopen(rest+path,timeout=2)
    except urllib.error.HTTPError as error: assert error.code==status
    else: raise AssertionError('External listener isolation failed')
request=urllib.request.Request(ingress+'/',headers={'X-Ingress-Path':'/api/hassio_ingress/synthetic','X-Forwarded-For':'172.30.32.2'})
try: urllib.request.urlopen(request,timeout=2)
except urllib.error.HTTPError as error: assert error.code==403
else: raise AssertionError('Ingress gateway restriction failed')
print('Home Assistant container listener isolation checks passed')
PY
