# VPN endpoint setup

Family VPN connects to an IKEv2 endpoint with a server certificate and EAP username/password authentication. The dashboard provisions the gateway, certificate identity, trusted Wi-Fi list and optional CA. It does not create VPN accounts or configure the gateway.

Choose [MikroTik RouterOS](MIKROTIK_IKEV2.md) or [strongSwan](STRONGSWAN_IKEV2.md). Both guides use the live RouterOS settings inspected read-only on 8 October 2026 as the protocol baseline. Router commands and Linux templates are examples for a new installation, not scripts applied to the inspected router. No passwords, RADIUS shared secrets, private keys, raw exports or personal network topology are included.

## Choose deployment values

| Setting | Illustrative value | Where to configure it |
| --- | --- | --- |
| Public gateway / DNS name | `vpn.example.org` | Public DNS, endpoint certificate, dashboard gateway |
| Server IKE identity | `vpn.example.org` | Certificate DNS SAN, endpoint identity, dashboard certificate identity |
| VPN address pool | `10.20.30.100–10.20.30.200` | RouterOS pool or strongSwan pool |
| Optional second VPN group | `10.20.40.100–10.20.40.200` | Separate pool and authorization policy |
| Registration LAN | `192.168.10.0/24` | Reverse-proxy registration ACL |
| DNS resolver | `192.168.10.53` | Endpoint configuration payload; reachable through VPN |
| Protected dashboard/proxy | `192.168.10.20` | Routing, firewall and reverse proxy |
| Trusted Wi-Fi | Your exact SSIDs | Dashboard; empty list means no Wi-Fi bypass |
| VPN credentials | A separate account per device/person | EAP/RADIUS backend and native app |

Every address, subnet, interface and account in these guides is an example. Replace them consistently and avoid overlap with local client networks. The registration subnet and VPN pool are different access zones. Include **every pool actually assigned by authentication** in the VPN-only proxy ACL.

## Match the application profile

The repository's `MyVPN/MyVPN/Resources/VPNConfiguration.json` supplies these fixed cryptographic settings; dashboard provisioning currently changes endpoint, identity, CA and Wi-Fi, not cipher suites.

| Parameter | Application and inspected RouterOS baseline |
| --- | --- |
| IKE | IKEv2, AES-256-CBC, SHA-256 integrity/PRF, MODP2048 (DH14) |
| IKE lifetime | 24 hours |
| ESP / child SA | AES-256-GCM, MODP2048 PFS |
| Child lifetime | 2 hours |
| Authentication | Server certificate, client EAP username/password |
| Routing | IPv4 full-tunnel selector `0.0.0.0/0` |

GCM provides authenticated encryption: do not add a separate ESP SHA-512 requirement simply because the Apple configuration also contains an integrity enum. The observed RouterOS child proposal has an empty separate integrity list. Negotiated SAs and rekey tests are the final compatibility check.

The app allows MOBIKE and uses high DPD, but gateway implementations determine the negotiated behavior. `includeAllNetworks` is currently false. An IPv4 full-tunnel selector does not establish IPv6 protection or an operating-system kill switch. IPv6 and uninterrupted enforcement need a separate verified design; inspect for bypass on dual-stack access networks.

## Certificates

[Create and install CA/server certificates](VPN_CERTIFICATES.md) includes OpenSSL commands, endpoint import and rotation steps.

Use a leaf server certificate containing the gateway DNS SAN and an identity matching the dashboard. Prefer a publicly trusted certificate, or a dedicated private CA with `BasicConstraints: CA:TRUE`; the leaf should have `CA:FALSE`, appropriate signing usage and server authentication EKU. For an IP-based endpoint, use a matching IP SAN rather than a DNS SAN. The certificate chain and private key belong on the endpoint.

The dashboard accepts **one public CA certificate in PEM or DER**, not a server leaf, bundle or private key. It rejects certificates without an explicit CA basic constraint. The legacy certificate bundled in this repository has no X.509 extensions and is not suitable for this new CA upload validation. Generate a proper CA and leaf for a new deployment; changing trust on an existing deployment requires a staged rollout.

With a private CA, upload its public PEM or DER certificate in dashboard VPN provisioning before registration. The app receives it during enrollment and exports a CA-only profile. Install and approve system trust before installing the VPN. The app cannot silently grant certificate trust. See [Apple's certificate trust instructions](https://support.apple.com/en-gb/102390) and [dashboard provisioning](PROVISIONING.md).

## Enrollment and endpoint changes

1. Establish gateway DNS, certificate, EAP authentication, routing and firewall rules.
2. Configure dashboard gateway, certificate identity, optional CA, trusted SSIDs and administrator password.
3. Register the updated app from the configured registration LAN and approve certificate trust if needed.
4. Enter the VPN account in the app and install Personal VPN. Test using cellular or an untrusted Wi-Fi network.
5. Confirm policy, DNS, protected REST access and public status/acknowledgements. Verify the actual assigned source subnet at the proxy.

To change endpoints, save settings and send **Push VPN / Wi-Fi / CA** while the old endpoint still works. APNs carries a signed snapshot digest; the device fetches the payload through the VPN-only REST interface. Keep the old gateway reachable until receipt, trust approval and successful policy application are verified. CA changes display a notification and badge, subject to permission. An executed command receipt means settings were stored, not that the new tunnel connected. Use the policy report and gateway SA state as additional evidence. Offline recovery requires registration on the registration LAN. See [remote provisioning details](PROVISIONING.md).

## Acceptance checks

- An incorrect VPN password fails; another account cannot reuse device dashboard credentials.
- The gateway certificate identity and chain validate without disabling validation.
- The assigned VPN IP is in the intended authorization pool; DNS and return routing work.
- Internet egress, intended private services and dashboard VPN-only routes work through the tunnel; unrelated private services remain blocked.
- Registration is denied outside its LAN; configuration retrieval is denied outside VPN source ranges; public status and ACKs still require device authentication.
- Trusted Wi-Fi disconnects VPN as configured, and cellular/untrusted Wi-Fi reconnects it. Test sleep/wake and Wi-Fi-to-cellular movement.
- Test child rekey beyond two hours, IKE rekey beyond one day and simultaneous devices behind one NAT. A successful initial connection alone does not verify rekey/PFS.
- Test a CA update on a physical device: notification/badge, profile export, trust approval and eventual new tunnel. Silent APNs execution is best effort.
