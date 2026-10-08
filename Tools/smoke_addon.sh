#!/usr/bin/env bash
set -euo pipefail
image="${1:-vpnweb-addon:test}"
name="vpnweb-addon-smoke-${RANDOM}"
data=$(mktemp -d)
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$data"; }
trap cleanup EXIT
python3 - <<'PY' > "$data/options.json"
import json,secrets
print(json.dumps({'admin_bearer':secrets.token_urlsafe(32),'registration_bearer':secrets.token_urlsafe(32),'automatic':False}))
PY
docker run -d --name "$name" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges --mount "type=bind,source=$data,target=/data" \
  -p 127.0.0.1::8081 -p 127.0.0.1::8099 "$image" >/dev/null
rest=$(docker port "$name" 8081/tcp | sed 's/.*://')
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
