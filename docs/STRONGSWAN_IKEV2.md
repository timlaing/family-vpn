# strongSwan IKEv2 endpoint

Start with the [shared endpoint checklist](VPN_ENDPOINT_SETUP.md). This guide translates the inspected RouterOS VPN profile to a Linux IKEv2 responder; it has not been deployed or tested against a live strongSwan endpoint in this task.

## Install and choose the daemon

Use your distribution's strongSwan **charon + VICI/swanctl** packages. Enable `kernel-netlink`, a socket backend, X.509/public-key crypto, `eap-identity` and `eap-mschapv2`; the latter also needs an MD4 provider. For RADIUS, enable `eap-radius` instead. Check distribution plugin packaging rather than assuming every plugin is installed with the base daemon. Use one daemon/configuration frontend: do not run an `ipsec.conf` starter alongside charon-systemd with the same sockets.

Use `swanctl --stats`, `swanctl --list-algs` and daemon startup logs to inspect the installed version, crypto and loaded plugins. Service names vary by distribution; the commands below use `strongswan.service` for a charon-systemd installation.

## Certificates and accounts

Install your server leaf at `/etc/swanctl/x509/vpn-server.pem`, its private key under `/etc/swanctl/private/`, and CA/intermediates under `/etc/swanctl/x509ca/`. Restrict private-key and credential files to root (`0600`). Create certificates following the shared guide; distribute only the public root CA to the dashboard.

Copy [swanctl.conf.example](examples/swanctl.conf.example) to `/etc/swanctl/swanctl.conf` after replacing example values. `send_cert = always` matters because the app does not pin an issuer common name. The remote EAP identity is requested independently from the client's IKE identity. Strict MODP2048 PFS follows the app profile; keep it initially and verify Apple child-SA rekeys. Generic/manual macOS profiles may need a different PFS policy. See [Apple interoperability](https://docs.strongswan.org/docs/latest/interop/ios.html).

Create `/etc/swanctl/conf.d/family-vpn-secrets.conf` **on the gateway**, with a dedicated device account. Unencrypted private keys in the private directory load automatically:

```conf
secrets {
    eap-device-one {
        id = device-one
        secret = REPLACE_WITH_DEVICE_PASSWORD
    }
}
```

For an encrypted key, add a `private-family-vpn` section with `file = vpn-server-key.pem` and `secret = REPLACE_WITH_KEY_PASSPHRASE`, or supply the passphrase interactively. Keep that file root-only.

The local EAP example uses one address pool. Additional accounts can use that pool. Separate authorization groups need explicit identity-specific connection/pool selection or a RADIUS address-allocation design; adding a second pool alone does not enforce group separation.

## Optional RADIUS backend

To retain the MikroTik-style EAP backend, change `remote.auth` to `eap-radius`, remove local EAP secrets, and merge [strongswan-radius.conf.example](examples/strongswan-radius.conf.example) into `strongswan.conf`. Install the plugin and register the Linux gateway as a RADIUS client with the same shared secret. Limit UDP 1812/1813 to the gateway/backend pair. The RADIUS server must implement an Apple-compatible EAP method, such as EAP-MSCHAPv2.

RouterOS `Framed-Pool` names do not automatically create equivalent Linux pools. For backend address assignment, strongSwan supports `Framed-IP-Address`; otherwise verify allocation from the configured local pool. Avoid conflicting local and backend allocations and enforce the resulting IPs in firewall/proxy policy. [RADIUS plugin reference](https://docs.strongswan.org/docs/latest/plugins/eap-radius.html).

## Forwarding and firewall

Enable IPv4 forwarding persistently:

```ini
# /etc/sysctl.d/90-family-vpn.conf
net.ipv4.ip_forward = 1
```

Apply with `sudo sysctl --system`. At the perimeter, allow UDP 500 and 4500 to the gateway and ESP (IP protocol 50) for unencapsulated traffic. If behind NAT, forward UDP 500/4500 to it. Use the existing host firewall manager to persist equivalent rules.

This IPv4 iptables fragment illustrates ordering; substitute `eth0`, addresses and destinations and insert rules before existing drops/NAT. It is not a complete firewall. Restrict private service access rather than permitting every LAN destination:

```sh
sudo iptables -I INPUT -p udp -m multiport --dports 500,4500 -j ACCEPT
sudo iptables -I INPUT -p esp -j ACCEPT
sudo iptables -I FORWARD -s 10.20.30.0/24 -d 192.168.10.53 -p udp --dport 53 -m policy --dir in --pol ipsec -j ACCEPT
sudo iptables -I FORWARD -s 10.20.30.0/24 -d 192.168.10.53 -p tcp --dport 53 -m policy --dir in --pol ipsec -j ACCEPT
sudo iptables -I FORWARD -s 10.20.30.0/24 -d 192.168.10.20 -p tcp --dport 443 -m policy --dir in --pol ipsec -j ACCEPT
sudo iptables -I FORWARD -s 10.20.30.0/24 -o eth0 -m policy --dir in --pol ipsec -j ACCEPT
sudo iptables -I FORWARD -d 10.20.30.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -m policy --dir out --pol ipsec -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 10.20.30.0/24 -o eth0 -m policy --dir out --pol none -j MASQUERADE
```

If `eth0` also reaches private networks, restrict the internet-egress rule further; an interface match alone is not LAN isolation. Add destination-deny/allow policies before that broad egress rule. Exempt outbound IPsec traffic from any existing general masquerade before it runs. Add a return route for the VPN pool on LAN routers via the Linux gateway. Preserving VPN source addresses to the dashboard lets NPM verify pool membership; LAN-wide masquerade would defeat this distinction. [Forwarding reference](https://docs.strongswan.org/docs/latest/howtos/forwarding.html).

Do not publish an IPv6 gateway record or claim IPv6 tunneling from this IPv4-only example. Configure IPv6 pools/selectors/firewall separately and verify the native app profile before enabling dual-stack VPN traffic.

## Load and verify

```sh
sudo systemctl status strongswan.service
sudo swanctl --load-all
sudo swanctl --list-conns
sudo swanctl --list-pools
sudo swanctl --list-sas
sudo ip xfrm policy
sudo ip xfrm state
sudo journalctl -u strongswan.service --since '10 minutes ago'
```

The responder waits for the app; do not initiate a road-warrior connection from the server. Verify server identity, EAP success, virtual IP, traffic counters, DNS and protected REST access, then the full acceptance checklist. Sanitize logs before sharing them: usernames and IPs may appear. `swanctl --load-all` validates/loading configuration; it does not prove Apple interoperability. Configuration option details: [swanctl reference](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html).
