# MikroTik RouterOS IKEv2 endpoint

Start with the [shared endpoint checklist](VPN_ENDPOINT_SETUP.md). This guide is based on a read-only inspection of RouterOS **7.24.5** on 8 October 2026. It preserves the VPN's IKE/ESP proposals, EAP-RADIUS authentication, responder mode, generated policies, full-tunnel selector, internal DNS and RADIUS-selected authorization pools. The inspected router was not changed.

## Mapping from the inspected configuration

| Component | Observed setting | Generic setup below |
| --- | --- | --- |
| IKE profile | AES-256, SHA-256 hash/PRF, MODP2048, 1 day, NAT-T, DPD 10 seconds / 5 failures | `family-vpn-ike` |
| ESP proposal | AES-256-GCM, no separate integrity algorithm, MODP2048 PFS, 2 hours | `family-vpn-child` |
| Peer | Passive IKEv2 responder; no initial contact | `family-vpn` |
| Mode config | Responder, explicit internal DNS, IPv4 full-tunnel | `family-vpn-mode` |
| Identity | EAP-RADIUS, server certificate, FQDN server ID, generated port-strict policies | `family-vpn` identity |
| Policy | Dedicated group and wildcard template, child proposal above | `family-vpn-policies` |
| Authentication | External and loopback RADIUS entries; User Manager enabled | Choose one deliberate backend initially |
| Address allocation | User Manager group returns `Framed-Pool` | Generic `vpn-standard` / `vpn-restricted` pools |
| Firewall | Dedicated VPN input chain; UDP 500/4500 and ESP; group-based forwarding and NAT exemptions | Integrate equivalent rules in your firewall |

### Differences to address before enrolling updated apps

The existing identity pins one `user-fqdn` client IKE identity. The current app clears its configured local IKE identity during provisioning; its EAP username is a separate value. Do not assume the old fixed identity filter will match new clients. The generic example uses `remote-id=ignore` and relies on EAP-RADIUS to authenticate each account. This does not bypass EAP authentication. If maintaining a fixed identity policy, first verify the actual client ID and implement compatible client provisioning.

One inspected User Manager group has empty `outer-auths` and `inner-auths`. Verify its EAP method permissions before assigning users; the examples explicitly enable `eap-mschap2`. This is a configuration finding, not proof that a live login failed. The current assigned pools also differ from the earlier dashboard documentation's assumptions: derive reverse-proxy ACLs from the actual RADIUS assignments.

The server certificate has a DNS SAN and an available private key, but the printed key-usage field is empty. Check the actual public certificate with OpenSSL before reusing it. The old bundled certificate has no extensions and fails the dashboard's new explicit `CA:TRUE` requirement. The [certificate section](VPN_ENDPOINT_SETUP.md#certificates) explains the replacement requirements. Do not upload a leaf or private key as the CA.

## Prepare DNS and certificates

Point your public gateway name at the WAN endpoint and make UDP 500/4500 reachable. RouterOS hosts the VPN directly in this example; an HTTP reverse proxy does not terminate IKEv2.

Use WinBox **System → Certificates → Import**, or `/certificate import file-name=...`, to import your CA/chain, server leaf and its private key or protected PKCS#12 bundle. Inspect `/certificate print detail` and ensure the leaf has the private-key flag. Rename it to `vpn-server` for the example. Its DNS SAN must cover `vpn.example.org`, which must match `my-id` and dashboard certificate identity. Import intermediates as well when your issuer uses them. Mark the intended CA trusted. Do not export a private key to the dashboard.

For an existing endpoint, preserve its old certificate/identity until replacement clients have approved the new CA. The dashboard CA upload accepts one public PEM or DER root with explicit CA basic constraints.

## IKEv2 responder

These commands create uniquely named objects for a **new installation**. Existing routers need a reviewed change to their current objects; repeated `add` commands are not idempotent. Do not create another wildcard responder alongside an existing IKEv2 responder without considering peer matching. Save a private backup and use RouterOS Safe Mode when changing firewall/access settings.

```routeros
/ip ipsec profile
add name=family-vpn-ike enc-algorithm=aes-256 hash-algorithm=sha256 prf-algorithm=sha256 dh-group=modp2048 lifetime=1d proposal-check=obey nat-traversal=yes dpd-interval=10s dpd-maximum-failures=5
/ip ipsec proposal
add name=family-vpn-child enc-algorithms=aes-256-gcm auth-algorithms="" pfs-group=modp2048 lifetime=2h
/ip ipsec policy group
add name=family-vpn-policies
/ip ipsec policy
add group=family-vpn-policies template=yes src-address=0.0.0.0/0 dst-address=0.0.0.0/0 protocol=all proposal=family-vpn-child
/ip ipsec mode-config
add name=family-vpn-mode responder=yes system-dns=no static-dns=192.168.10.53 split-include=0.0.0.0/0
/ip ipsec peer
add name=family-vpn exchange-mode=ike2 passive=yes profile=family-vpn-ike send-initial-contact=no
/ip ipsec identity
add peer=family-vpn auth-method=eap-radius certificate=vpn-server my-id=fqdn:vpn.example.org remote-id=ignore generate-policy=port-strict policy-template-group=family-vpn-policies mode-config=family-vpn-mode
```

The inspected policy template was `::/0` in both directions. The example limits the template to IPv4 to match this guide's pool and full-tunnel selector; it does not claim IPv6 coverage. Configure an IPv6 policy/pool and validate the app before extending it.

## RADIUS authentication and address pools

Create address pools that do not overlap other routed networks:

```routeros
/ip pool
add name=vpn-standard ranges=10.20.30.100-10.20.30.200
add name=vpn-restricted ranges=10.20.40.100-10.20.40.200
```

For an external EAP-capable RADIUS server, configure an IPsec client entry. Enter your real shared secret privately on the router and backend; the text below is deliberately a placeholder:

```routeros
/radius
add service=ipsec address=192.168.10.54 authentication-port=1812 accounting-port=1813 timeout=1100ms secret="REPLACE_WITH_RADIUS_SHARED_SECRET"
```

Configure the backend to authenticate EAP-MSCHAPv2 and return `Framed-Pool = vpn-standard` or `vpn-restricted` in Access-Accept. The pool must exist on this RouterOS device. Alternatively, use backend-assigned individual `Framed-IP-Address` values. The inspected mode-config does not specify an address pool; it relies on the authentication backend. For a single-pool installation, you may explicitly set `address-pool=vpn-standard` on mode-config instead; verify precedence if also returning RADIUS address attributes.

### Local User Manager alternative

If using RouterOS User Manager, install the matching RouterOS-version package if it is not already present. Use the loopback RADIUS entry **instead of adding the external backend above** for your initial setup:

```routeros
/user-manager
set enabled=yes
/user-manager router
add name=family-vpn-local address=127.0.0.1 shared-secret="REPLACE_WITH_RADIUS_SHARED_SECRET"
/radius
add service=ipsec address=127.0.0.1 authentication-port=1812 accounting-port=1813 timeout=1100ms secret="REPLACE_WITH_RADIUS_SHARED_SECRET"
/user-manager user group
add name=family-vpn-standard outer-auths=eap-mschap2 inner-auths="" attributes=Framed-Pool:vpn-standard
add name=family-vpn-restricted outer-auths=eap-mschap2 inner-auths="" attributes=Framed-Pool:vpn-restricted
/user-manager user
add name=device-one password="REPLACE_WITH_DEVICE_PASSWORD" group=family-vpn-standard
```

Add distinct accounts to the appropriate group and configure profile/session limits if your User Manager policy requires them. Permit loopback RADIUS traffic in the input firewall if your ruleset filters it. Keep external RADIUS services reachable only from authorized gateway clients. Group authentication and address attributes are described in [User Manager documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/2555940/User%2BManager).

The inspected router contains both an external and a local entry. Do not reproduce that ordering as an assumed redundancy design: verify which backend answers, how rejection/timeout is handled and whether both maintain consistent accounts and pool assignments.

## Firewall and NAT

Your firewall structure and rule order matter. The inspected router uses jump chains for VPN input and group-based forwarding; preserve your existing architecture when integrating these equivalents. `WAN` below is an example interface-list name, not a discovered interface.

Allow IKE and transport to the router **before the final input drop**:

```routeros
/ip firewall filter
add chain=input action=accept in-interface-list=WAN protocol=udp dst-port=500,4500 comment="Family VPN IKE and NAT-T"
add chain=input action=accept in-interface-list=WAN protocol=ipsec-esp comment="Family VPN ESP"
```

`add` appends: move these to the intended position before the drop. The live router also permits IPsec AH; this AES-GCM ESP deployment does not need an additional AH allowance.

Use decrypted IPsec policy matches with VPN source ranges. This example permits DNS and dashboard HTTPS for one pool; apply an explicit policy for the second pool:

```routeros
/ip firewall address-list
add list=family-vpn-clients address=10.20.30.0/24
add list=family-vpn-clients address=10.20.40.0/24
/ip firewall filter
add chain=forward action=accept ipsec-policy=in,ipsec src-address-list=family-vpn-clients dst-address=192.168.10.53 protocol=udp dst-port=53 comment="VPN DNS"
add chain=forward action=accept ipsec-policy=in,ipsec src-address-list=family-vpn-clients dst-address=192.168.10.53 protocol=tcp dst-port=53 comment="VPN DNS TCP"
add chain=forward action=accept ipsec-policy=in,ipsec src-address-list=family-vpn-clients dst-address=192.168.10.20 protocol=tcp dst-port=443 comment="VPN dashboard HTTPS"
add chain=forward action=accept ipsec-policy=in,ipsec src-address-list=family-vpn-clients out-interface-list=WAN comment="VPN internet egress"
```

Place these before the final forward drop, and retain appropriate established/related return rules. Apply explicit group-specific destination restrictions before broad internet rules if the WAN path also routes private sites. Allow DNS in `input` rather than `forward` if the router itself is the resolver. Exclude VPN/IPsec flows from FastTrack; use source/destination VPN lists in your FastTrack exclusions without introducing unconditional accepts that bypass group policy.

The live router has NAT exemptions before its WAN masquerade. Preserve that ordering:

```routeros
/ip firewall nat
add chain=srcnat action=accept ipsec-policy=out,ipsec comment="Do not NAT traffic entering IPsec"
add chain=dstnat action=accept ipsec-policy=in,ipsec comment="Preserve decrypted VPN destinations"
```

Move these before applicable general NAT rules. Retain/add a WAN masquerade for VPN clients' internet egress. Do not masquerade VPN-to-dashboard LAN traffic: NPM needs the actual client pool IP for its VPN-only ACL. The inspected router has DNS redirect rules *before* its decrypted-traffic exemption; review that placement deliberately if keeping DNS interception. Add return routes for VPN pools on any downstream LAN routers.

## Readback and connection checks

```routeros
/ip ipsec profile print detail where name=family-vpn-ike
/ip ipsec proposal print detail where name=family-vpn-child
/ip ipsec peer print detail where name=family-vpn
/ip ipsec mode-config print detail where name=family-vpn-mode
/ip ipsec policy print detail where group=family-vpn-policies
/ip ipsec active-peers print detail
/ip ipsec installed-sa print detail
/radius monitor [find where service=ipsec] once
```

Use WinBox to inspect identity/certificate selection and RADIUS results without exporting secrets. During a physical-device connection, check EAP acceptance, assigned address, generated policy, negotiated AES-256/SHA-256 IKE and AES-256-GCM ESP, and increasing SA byte counters. Then complete the [acceptance checks](VPN_ENDPOINT_SETUP.md#acceptance-checks), including rekey and dashboard source-address verification. Avoid publishing raw diagnostic output.

MikroTik's [IPsec reference](https://help.mikrotik.com/docs/spaces/ROS/pages/11993097/IPsec) explains responder identities, policies and mode-config. These documented settings and readback from the existing router support the guide; no fresh end-to-end client connection was performed for this documentation change.
