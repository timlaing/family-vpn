#!/usr/bin/env bash
set -euo pipefail
image="${1:-family-vpn-strongswan:test}"
root=$(cd "$(dirname "$0")/.." && pwd)
data=$(mktemp -d)
name="familyvpn-radius-smoke-${RANDOM}"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$data"; }
trap cleanup EXIT
python3 - "$root" "$data" <<'PYTHON'
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1])/'strongswan-endpoint'))
from configure import create
from authentication import configure_authentication
output=Path(sys.argv[2])/'runtime'
create(output,'vpn.example.org','10.20.30.0/24','192.168.10.53',None,None,'192.168.10.0/24','192.168.10.53/32')
configure_authentication(output,'radius','192.0.2.54','synthetic-radius-secret',18120,18130,'synthetic-gateway',True)
PYTHON
docker run -d --name "$name" --cap-add NET_ADMIN --cap-add NET_RAW --sysctl net.ipv4.ip_forward=1 \
  --env-file "$data/runtime/gateway.env" \
  --mount "type=bind,source=$data/runtime/swanctl,target=/etc/swanctl,readonly" \
  --mount "type=bind,source=$data/runtime/authentication,target=/etc/family-vpn-auth,readonly" "$image" >/dev/null
for attempt in {1..30}; do
  if docker exec "$name" swanctl --list-conns 2>/dev/null | grep -q 'EAP_RADIUS'; then break; fi
  if [[ "$attempt" == 30 ]]; then docker logs "$name"; exit 1; fi
  sleep 1
done
docker exec "$name" swanctl --stats | grep -q 'eap-radius'
docker logs "$name" 2>&1 | grep -q 'loaded 1 RADIUS server configuration'
# Container restart must reload the same backend without duplicating includes.
docker restart "$name" >/dev/null
for attempt in {1..30}; do
  if docker exec "$name" swanctl --list-conns 2>/dev/null | grep -q 'EAP_RADIUS'; then break; fi
  if [[ "$attempt" == 30 ]]; then docker logs "$name"; exit 1; fi
  sleep 1
done
echo 'External RADIUS connection, plugin/server configuration and restart loaded; no live RADIUS authentication tested'
