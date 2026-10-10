#!/bin/sh
set -eu
# All rules stay in this container's network namespace.
if [ -n "${VPN_CONFIGURATION_DIR:-}" ]; then
    while [ ! -f "$VPN_CONFIGURATION_DIR/ready" ]; do sleep 2; done
    . "$VPN_CONFIGURATION_DIR/gateway.env"
    rm -rf /etc/swanctl
    ln -s "$VPN_CONFIGURATION_DIR/swanctl" /etc/swanctl
    rm -rf /etc/family-vpn-auth
    ln -s "$VPN_CONFIGURATION_DIR/authentication" /etc/family-vpn-auth
fi
: "${VPN_POOL_CIDR:?Run configure.py first}"
: "${VPN_LAN_CIDRS:?Set explicit private destination networks}"
: "${VPN_ALLOWED_LAN_CIDRS:?Set private networks devices may access}"
test -f /etc/swanctl/swanctl.conf
test -f /etc/swanctl/private/vpn-server-key.pem
iptables -N FAMILY_VPN 2>/dev/null || iptables -F FAMILY_VPN
iptables -C FORWARD -j FAMILY_VPN 2>/dev/null || iptables -A FORWARD -j FAMILY_VPN
iptables -t nat -N FAMILY_VPN_NAT 2>/dev/null || iptables -t nat -F FAMILY_VPN_NAT
iptables -t nat -C POSTROUTING -j FAMILY_VPN_NAT 2>/dev/null || iptables -t nat -A POSTROUTING -j FAMILY_VPN_NAT
iptables -A FAMILY_VPN -d "$VPN_POOL_CIDR" -m conntrack --ctstate ESTABLISHED,RELATED -m policy --dir out --pol ipsec -j ACCEPT
for network in $VPN_ALLOWED_LAN_CIDRS; do
    iptables -A FAMILY_VPN -s "$VPN_POOL_CIDR" -d "$network" -m policy --dir in --pol ipsec -j ACCEPT
done
for network in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 $VPN_LAN_CIDRS; do
    iptables -A FAMILY_VPN -s "$VPN_POOL_CIDR" -d "$network" -j DROP
    iptables -t nat -A FAMILY_VPN_NAT -s "$VPN_POOL_CIDR" -d "$network" -j ACCEPT
done
iptables -A FAMILY_VPN -s "$VPN_POOL_CIDR" -m policy --dir in --pol ipsec -j ACCEPT
iptables -A FAMILY_VPN -s "$VPN_POOL_CIDR" -j DROP
iptables -A FAMILY_VPN -d "$VPN_POOL_CIDR" -j DROP
iptables -t nat -A FAMILY_VPN_NAT -s "$VPN_POOL_CIDR" -m policy --dir out --pol none -j MASQUERADE
# Snapshot authentication for this process; apply changes by restarting.
umask 077
: > /run/family-vpn-auth.conf
if [ -f /etc/family-vpn-auth/radius.conf ]; then
    cat /etc/family-vpn-auth/radius.conf > /run/family-vpn-auth.conf
fi
/usr/lib/ipsec/charon &
daemon=$!
reloader=
cleanup() {
    if [ -n "$reloader" ]; then
        kill "$reloader" 2>/dev/null || true
        wait "$reloader" 2>/dev/null || true
    fi
    kill "$daemon" 2>/dev/null || true
    wait "$daemon" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 0' TERM INT
ready=false
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if swanctl --stats >/dev/null 2>&1; then ready=true; break; fi
    kill -0 "$daemon" 2>/dev/null || exit 1
    sleep 1
done
[ "$ready" = true ] || exit 1
swanctl --load-all
if [ -n "${VPN_CONTROL_DIR:-}" ]; then
    /opt/control/bin/python /usr/local/bin/reloader.py --data "$VPN_CONFIGURATION_DIR" --control "$VPN_CONTROL_DIR" &
    reloader=$!
fi
while kill -0 "$daemon" 2>/dev/null; do
    if [ -n "$reloader" ] && ! kill -0 "$reloader" 2>/dev/null; then exit 1; fi
    sleep 1
done
wait "$daemon"
