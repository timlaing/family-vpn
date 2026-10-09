#!/usr/bin/env bash
# Exercise a synthetic Supervisor gateway; this does not install Home Assistant.
# Sonar shell:S5332 is suppressed for this file in sonar-project.properties:
# HTTP stays inside the disposable Docker fixture or loopback, using synthetic credentials.
set -euo pipefail
image="${1:-vpnweb-addon:test}"
suffix="${RANDOM}"
network="vpnweb-ingress-${suffix}"
backend="vpnweb-backend-${suffix}"
gateway="vpnweb-gateway-${suffix}"
data=$(mktemp -d)
cleanup() {
  docker rm -f "$gateway" "$backend" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$data"
}
trap cleanup EXIT
mkdir "$data/state"
python3 - <<'PY' > "$data/state/options.json"
import json,secrets
print(json.dumps({'admin_bearer':secrets.token_urlsafe(32),'registration_bearer':secrets.token_urlsafe(32),'automatic':False}))
PY
cat > "$data/nginx.conf" <<'NGINX'
events {}
http {
  access_log off;
  server {
    listen 8080;
    location = /family-vpn/status {
      limit_except POST { deny all; }
      proxy_pass http://172.30.32.3:8081/status;
      proxy_set_header Authorization $http_authorization;
    }
    location = /family-vpn/command-results {
      limit_except POST { deny all; }
      proxy_pass http://172.30.32.3:8081/command-results;
      proxy_set_header Authorization $http_authorization;
    }
    location = /family-vpn/registrations {
      allow 172.30.32.12;
      deny all;
      limit_except POST { deny all; }
      proxy_pass http://172.30.32.3:8081/registrations;
      proxy_set_header Authorization $http_authorization;
      proxy_set_header X-FamilyVPN-Command-Protocol $http_x_familyvpn_command_protocol;
      proxy_set_header X-FamilyVPN-Administrator-Protocol $http_x_familyvpn_administrator_protocol;
    }
    location /family-vpn/ {
      allow 172.30.32.10;
      deny all;
      proxy_pass http://172.30.32.3:8081/;
      proxy_set_header Authorization $http_authorization;
      proxy_set_header Host vpn-control.test;
    }
    location /api/hassio_ingress/synthetic/ {
      proxy_pass http://172.30.32.3:8099/;
      proxy_set_header X-Ingress-Path /api/hassio_ingress/synthetic;
      proxy_set_header X-Forwarded-Proto http;
      proxy_set_header Host homeassistant.test;
    }
  }
}
NGINX
docker network create --subnet 172.30.32.0/24 "$network" >/dev/null
docker run -d --name "$backend" --network "$network" --ip 172.30.32.3 \
  --mount "type=bind,source=$data/state,target=/data" "$image" >/dev/null
docker run -d --name "$gateway" --network "$network" --ip 172.30.32.2 \
  --mount "type=bind,source=$data/nginx.conf,target=/etc/nginx/nginx.conf,readonly" \
  -p 127.0.0.1::8080 nginx:1.28-alpine >/dev/null
port=$(docker port "$gateway" 8080/tcp | sed 's/.*://')
VPNWEB_GATEWAY_PORT="$port" python3 - <<'PY'
import http.cookiejar,os,re,time,urllib.error,urllib.parse,urllib.request
prefix='/api/hassio_ingress/synthetic'
base='http://127.0.0.1:'+os.environ['VPNWEB_GATEWAY_PORT']
client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
for attempt in range(30):
    try:
        with client.open(base+prefix+'/',timeout=2) as response:
            assert response.status==200
            html=response.read().decode()
            assert prefix+'/configuration' in html
            assert response.headers.get('X-Frame-Options') is None
        break
    except (OSError,urllib.error.URLError): time.sleep(1)
else: raise SystemExit('Synthetic ingress gateway failed to start')
with client.open(base+prefix+'/static/style.css',timeout=2) as response: assert response.status==200
with client.open(base+prefix+'/configuration',timeout=2) as response:
    csrf=re.search(r'name="csrf" value="([^"]+)"',response.read().decode()).group(1)
form={'csrf':csrf,'apns_key_id':'','apns_team_id':'','apns_topic':'uk.co.laingcorp.myvpn','apns_key_file':'','apns_environment':'sandbox','interval':'1800'}
with client.open(base+prefix+'/configuration',data=urllib.parse.urlencode(form).encode(),timeout=2) as response:
    assert prefix+'/configuration' in response.url
    assert b'value="1800"' in response.read()
with client.open(base+prefix+'/',timeout=2) as response:
    csrf=re.search(r'name="csrf" value="([^"]+)"',response.read().decode()).group(1)
form={'csrf':csrf,'password':'synthetic-test-password','confirmation':'synthetic-test-password'}
with client.open(base+prefix+'/administrator-password',data=urllib.parse.urlencode(form).encode(),timeout=2) as response:
    assert b'Configured.' in response.read()
print('Synthetic Supervisor gateway, prefixed assets/cookies, configuration and administrator setup passed')
PY

# These peer addresses simulate allowed/denied network paths, not a live VPN.
python3 - <<'PYTHON' "$data/state/options.json" | docker run --rm -i --network "$network" --ip 172.30.32.12 --mount "type=bind,source=$data/state,target=/fixture" python:3.14-slim python -
import json,sys
options=json.load(open(sys.argv[1]))
print("options="+repr(options))
print(r'''
import json,urllib.error,urllib.request,uuid
base='http://172.30.32.2:8080/family-vpn'
def post(path,body,credential):
    request=urllib.request.Request(base+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+credential,'X-FamilyVPN-Administrator-Protocol':'1','X-FamilyVPN-Command-Protocol':'1'})
    return urllib.request.urlopen(request,timeout=5)

identifier=str(uuid.uuid4())
with post('/registrations',{'id':identifier,'token':'ab'*32},options['registration_bearer']) as response:
    assert response.status==201
    registered=json.load(response)
    assert registered['administrator']['algorithm']=='pbkdf2-sha256'
    assert registered['administrator']['iterations']==600000
    assert 'synthetic-test-password' not in json.dumps(registered)
    credential=registered['status_token']
    with open('/fixture/report.json','w') as fixture: json.dump({'id':identifier,'credential':credential},fixture)
with post('/status',{'id':identifier,'connection':'connected','policy_ok':True},credential) as response: assert response.status==204
for path in ('/health','/api/devices','/commands'):
    try: urllib.request.urlopen(base+path,timeout=5)
    except urllib.error.HTTPError as error: assert error.code==403
    else: raise AssertionError('Registration LAN gained VPN-only access')
print('Registration LAN: enrollment and scoped report passed; VPN-only routes denied')
''')
PYTHON
docker run --rm --network "$network" --ip 172.30.32.10 python:3.14-slim python -c '
import urllib.request,urllib.error
base="http://172.30.32.2:8080/family-vpn"
with urllib.request.urlopen(base+"/health",timeout=5) as response: assert response.status==200
request=urllib.request.Request(base+"/registrations",data=b"{}",headers={"Content-Type":"application/json"})
try: urllib.request.urlopen(request,timeout=5)
except urllib.error.HTTPError as error: assert error.code==403
else: raise AssertionError("VPN peer was allowed to enroll")
print("VPN source: protected health allowed; enrollment denied")
'
docker run --rm --network "$network" --ip 172.30.32.11 --mount "type=bind,source=$data/state,target=/fixture,readonly" python:3.14-slim python -c '
import urllib.request,urllib.error
for path in ("/health","/registrations","/status","/api/devices","/commands","/command-results"):
    try: urllib.request.urlopen("http://172.30.32.2:8080/family-vpn"+path,timeout=5)
    except urllib.error.HTTPError as error: assert error.code==403
    else: raise AssertionError("Source outside VPN ACL was allowed")
import json,uuid
fixture=json.load(open("/fixture/report.json"))
for path,body,expected in (("/status",{"id":fixture["id"],"connection":"disconnected","policy_ok":True},204),("/command-results",{"id":fixture["id"],"request_id":str(uuid.uuid4()),"result":"executed"},404)):
    request=urllib.request.Request("http://172.30.32.2:8080/family-vpn"+path,data=json.dumps(body).encode(),headers={"Content-Type":"application/json","Authorization":"Bearer "+fixture["credential"]})
    try:
        with urllib.request.urlopen(request,timeout=5) as response: assert response.status==expected
    except urllib.error.HTTPError as error: assert error.code==expected
    request.remove_header("Authorization")
    try: urllib.request.urlopen(request,timeout=5)
    except urllib.error.HTTPError as error: assert error.code==401
    else: raise AssertionError("Public reporting accepted unauthenticated input")
print("Public authenticated reporting passed; protected routes and non-POST requests denied")
'
