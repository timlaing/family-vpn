#!/usr/bin/env bash
set -euo pipefail
image="${1:-family-vpn-strongswan:test}"
root=$(cd "$(dirname "$0")/.." && pwd)
data=$(mktemp -d)
name="familyvpn-strongswan-smoke-${RANDOM}"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$data"; }
trap cleanup EXIT
python3 - "$root" "$data" <<'PYTHON'
import importlib.util,sys
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[1])/'strongswan-endpoint'))
spec=importlib.util.spec_from_file_location('endpoint',Path(sys.argv[1])/'strongswan-endpoint/configure.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.create(Path(sys.argv[2])/'runtime','vpn.example.org','10.20.30.0/24','192.168.10.53','synthetic-device','synthetic-vpn-password','192.168.10.0/24','192.168.10.53/32 192.168.10.20/32')
PYTHON
docker compose -f "$root/strongswan-endpoint/compose.yaml" --project-directory "$data" config --quiet
docker run -d --name "$name" --cap-add NET_ADMIN --cap-add NET_RAW --sysctl net.ipv4.ip_forward=1 \
  --env-file "$data/runtime/gateway.env" --mount "type=bind,source=$data/runtime/swanctl,target=/etc/swanctl,readonly" "$image" >/dev/null
for attempt in {1..30}; do
  if docker exec "$name" swanctl --list-conns 2>/dev/null | grep -q 'family-vpn:'; then break; fi
  if [[ "$attempt" == 30 ]]; then docker logs "$name"; exit 1; fi
  sleep 1
done
docker exec "$name" swanctl --stats | grep -q 'eap-mschapv2'
docker exec "$name" swanctl --list-algs | grep -q 'HASH_MD4'
docker exec "$name" swanctl --list-pools | grep -q 'family-vpn-pool'
docker exec "$name" iptables -C FAMILY_VPN -s 10.20.30.0/24 -d 192.168.10.20/32 -m policy --dir in --pol ipsec -j ACCEPT
echo 'strongSwan config, EAP plugin, pool, crypto and firewall loaded; no live tunnel tested'
