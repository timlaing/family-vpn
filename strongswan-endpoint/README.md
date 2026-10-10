# Family VPN strongSwan endpoint

A separate **Linux Docker Engine** IKEv2/EAP-MSCHAPv2 endpoint for Family VPN. It uses the existing application's AES-256/SHA-256/MODP2048 IKE and AES-256-GCM/MODP2048 ESP profile. The dashboard and push relay remain separate services. Docker Desktop is suitable for image/configuration checks, not the documented production gateway: use a reachable Linux host with kernel XFRM/IPsec, UDP 500/4500 and Docker bridge forwarding enabled.

## Published container images

The **Publish strongSwan containers** GitHub Actions workflow publishes both images to GHCR after CI, lint, SonarQube and container smoke tests pass:

| Image | Purpose |
| --- | --- |
| `ghcr.io/timlaing/family-vpn-strongswan` | IKEv2 gateway |
| `ghcr.io/timlaing/family-vpn-strongswan-configuration` | Standalone configuration dashboard |

Both support `linux/amd64` and `linux/arm64`. Publishing a `vMAJOR.MINOR.PATCH` repository tag creates the corresponding version tag and updates `latest`; prerelease tags do not update `latest`. Running the workflow manually on **main** publishes `edge`. Every publication also creates a `sha-<full commit SHA>` tag. No personal access token is needed; publishing uses GitHub's scoped workflow token. For public anonymous downloads, ensure both GHCR packages have public visibility in their GitHub package settings.

To use published images, put these lines in a local `.env` beside the Compose file. Replace `edge` with a published release version or commit tag when deploying production:

```dotenv
VPN_ENDPOINT_IMAGE=ghcr.io/timlaing/family-vpn-strongswan:edge
VPN_CONFIGURATION_IMAGE=ghcr.io/timlaing/family-vpn-strongswan-configuration:edge
```

```bash
docker compose -f compose.dashboard.yaml pull
docker compose -f compose.dashboard.yaml up -d --no-build
```

The first publication must complete before these tags can be pulled. Follow the browser setup below; existing installations retain their named volumes. Apply the one-time ownership migration below if upgrading from the older root-running dashboard image.

## Browser configuration with persistent Docker volumes

For a new installation, use the standalone management Compose file instead of the CLI/bind-mount instructions below. This remains a separate Docker package, not a Home Assistant app.

1. Start both containers; no administrator password environment variable or `.env` file is required:

   ```sh
   docker compose -f compose.dashboard.yaml up -d --build
   ```

2. Open `http://localhost:8080`. For a remote Linux host, use `ssh -L 8080:127.0.0.1:8080 user@docker-host` and open the same URL locally. The interface binds to localhost by default; do not forward port 8080 from your router.
3. On first launch, create and confirm an administrator password of at least 16 characters. Its hash is persisted in the authority volume; existing installations keep their password. The first-launch page cannot replace an existing administrator.
4. Enter the gateway hostname, VPN pool, DNS resolver, LAN networks and permitted private destinations. The VPN container waits until gateway setup completes, then starts automatically. The interface takes you to the separate **Device accounts** page to add your first account.
5. Download the **public CA certificate** from the interface and upload it to the Family VPN dashboard. Complete the routing and device checks below.
6. Use **Device accounts** to add an account, disable/enable access, change its password or delete it. Disabled accounts retain their password but are excluded from the gateway authentication file. Changing a disabled account’s password does not enable it. All accounts may be disabled/deleted; in that case no new device can authenticate. Account changes reload credentials automatically within a few seconds. The page reports pending, applied or retrying status. Disabling/deleting an active account or changing its password also terminates that account’s sessions; unrelated established tunnels remain connected. Editing an inactive account or saving unchanged credentials does not trigger a reload.

The management image runs as the unprivileged `endpoint` user (UID/GID 10001). Fresh named volumes receive the correct ownership automatically. If upgrading an installation created by an older root-running management image, stop the management service and migrate only its two private volumes before starting the rebuilt image:

```bash
docker compose -f compose.dashboard.yaml stop configuration
docker compose -f compose.dashboard.yaml build
docker compose -f compose.dashboard.yaml run --rm --user root --cap-add CHOWN --cap-add DAC_OVERRIDE --entrypoint chown configuration -R 10001:10001 /data /authority
docker compose -f compose.dashboard.yaml up -d
```

This preserves passwords and keys. The gateway stays root because it manages kernel IPsec policies and firewall rules; its private CA signing key is never mounted. Reload acknowledgements are readable by UID 10001 without granting the management container access to the VICI socket.

Three named volumes survive container replacement: `vpn_configuration` holds gateway settings, VPN credentials and certificates; `vpn_authority` holds the CA signing key and hashed administrator credential/session key. `vpn_control` stores reload acknowledgements; it is writable only by the VPN container and read-only in the management container. The configuration volume is read-only in the VPN container. Reload requests contain account names/actions, never passwords. The gateway clears and reloads credentials through `swanctl`, then uses its private VICI socket to terminate matching EAP sessions. Neither the Docker socket nor the VICI socket is shared with the web container. Failed reloads stay visible and retry automatically; queued changes survive container outages. No Docker socket is mounted. Back up the configuration and authority volumes securely; VPN account passwords must be retained in private files for EAP authentication. Never use `docker compose down -v` unless deliberately deleting all configuration and keys.

The UI uses the Family VPN shield and network graphics, with separate Endpoint, Device accounts and Advanced pages. It supports initial gateway provisioning and account management. Gateway address/network changes and certificate renewal remain manual operations; it refuses to recreate an existing CA. Existing CLI installations are not automatically migrated into the named volumes: keep using the original Compose file until a deliberate backup and migration is completed. The browser workflow retains the CA key in its separate volume for later manual renewal, rather than moving it offline.

If deliberately exposing management on a private interface, set `VPN_MANAGEMENT_BIND` to that interface's IP and use an authenticated HTTPS proxy/network restriction. Set `VPN_COOKIE_SECURE=1` in the configuration service environment when accessing exclusively through HTTPS. The administrator session uses HttpOnly/SameSite cookies and Flask-WTF CSRF protection; failed logins are limited. Never publish this interface directly to the internet.

## External RADIUS authentication

After configuring the gateway, open **Advanced** and select **External RADIUS server**. Supply:

| Setting | Required value |
| --- | --- |
| Server address | Reachable RADIUS IPv4 address or DNS hostname |
| Authentication port | UDP 1812 by default |
| Shared secret | Same strong secret configured for the gateway's RADIUS client entry; at least 16 printable characters, no quotes/backslashes |
| NAS identifier | `family-vpn` by default; use the identifier expected by your policy |
| Accounting | Optional; enable only if the server accepts accounting packets |
| Accounting port | UDP 1813 by default; used when accounting is enabled |

Save, then run `docker compose -f compose.dashboard.yaml restart vpn`. The shared secret is stored in private configuration files on the configuration volume, never displayed or logged by the interface. Leave the secret field blank to retain it; enter a new value to replace it.

Configure the external server (for example FreeRADIUS or Windows NPS) to accept **EAP-MSCHAPv2 over RADIUS**, including `EAP-Message`, `Message-Authenticator` and the MS-MPPE send/receive key attributes in Access-Accept. A server that only accepts PAP, CHAP or a bare MS-CHAP request is insufficient: strongSwan forwards the EAP exchange. The server must have compatible password material for MSCHAPv2 (for example a cleartext password, NT hash or supported directory backend); an ordinary one-way password hash is not sufficient.

Register the gateway as a RADIUS client using its **observed source IP** and matching shared secret. Under Docker bridge networking, an external server generally sees the Docker host's egress address, not the VPN client's pool address; confirm from your server logs. Permit outbound UDP authentication/accounting traffic and its replies between gateway and server. Do not publish UDP 1812/1813 on the VPN container or router: this gateway is the RADIUS client, not the server. Protect this traffic on a trusted private network or a separate encrypted transport tunnel; the configured UDP RADIUS transport is not RadSec/TLS.

In RADIUS mode, the **Device accounts** page explains that accounts, disable/enable actions, password changes and deletion are handled on the external server. The interface does not administer remote accounts. Existing local accounts remain stored but are inactive. There is **no automatic local fallback** on RADIUS errors or rejection. Switching back to Local accounts restores the previous local account states after restarting the VPN container.

The endpoint's configured VPN pool, DNS and destination allowlist still apply. Do not issue RADIUS address or DNS overrides that conflict with these routes and firewall rules. Disabling/deleting a RADIUS account may leave an already connected tunnel active: terminate the session on the gateway or restart it. Dynamic authorization/CoA and RadSec are not configured by this interface.

Test a valid RADIUS account, incorrect password, disabled account and an unavailable RADIUS server. Confirm rejection never falls back to a local account. If accounting is enabled, verify Start/Stop packets on the server. Configuration/plugin smoke tests do not prove your external server's EAP policy or an Apple device's tunnel works.

The CLI alternative supports the same backend and prompts privately for the shared secret:

```sh
python3 configure.py --auth radius --radius-server radius.example.org \
  --server vpn.example.org --dns 192.168.10.53 \
  --lan '192.168.10.0/24' --allow-lan '192.168.10.53/32 192.168.10.20/32'
```

Optional CLI flags: `--radius-auth-port`, `--radius-acct-port`, `--radius-nas-identifier`, and `--radius-accounting`. No `--username` is required in RADIUS mode. The original Compose file mounts `runtime/authentication` read-only alongside `runtime/swanctl`; the CA signing key remains outside the VPN container.

References: [strongSwan EAP-RADIUS](https://docs.strongswan.org/docs/latest/plugins/eap-radius.html) and [plugin configuration options](https://docs.strongswan.org/docs/latest/config/strongswanConf.html#charon-plugins-eap-radius), and [FreeRADIUS MS-CHAP password requirements](https://www.freeradius.org/documentation/freeradius-server/4.0.0/howto/modules/mschap/index.html).

## 1. Create the endpoint configuration (CLI alternative)

Choose a DNS hostname resolving to the Linux gateway's public address. Choose a VPN pool that overlaps neither your LAN nor Docker networks, a reachable DNS resolver, and explicit private destinations devices may access. Start with only the DNS resolver and dashboard/proxy addresses.

From this folder, with Python 3 and OpenSSL installed:

```sh
python3 configure.py --server vpn.example.org --pool 10.20.30.0/24 \
  --dns 192.168.10.53 --username device-one \
  --lan '192.168.10.0/24' --allow-lan '192.168.10.53/32 192.168.10.20/32'
```

The script prompts twice for a dedicated VPN account password, creates a private CA and server certificate with DNS SAN/serverAuth, and writes root-private runtime configuration. No password appears in command arguments. It refuses to overwrite existing runtime data. The sample pool and LAN addresses are generic examples; replace them.

Alternatively build the image first and generate configuration using its Python/OpenSSL tools:

```sh
docker build -t family-vpn-strongswan:local .
mkdir -m 700 runtime
docker run --rm -it --entrypoint configure-vpn \
  --mount type=bind,source="$PWD/runtime",target=/output \
  family-vpn-strongswan:local --output /output \
  --server vpn.example.org --dns 192.168.10.53 --username device-one \
  --lan '192.168.10.0/24' --allow-lan '192.168.10.53/32 192.168.10.20/32'
```

Only `runtime/swanctl` is mounted into the gateway. Back up `runtime/ca` securely and move the CA private key offline after issuing the server certificate. Never upload the CA private key, server key or VPN password to the dashboard. The runtime folder is ignored by Git and excluded from the Docker build context.

## 2. Start the gateway

```sh
docker compose build
docker compose up -d
docker compose logs --tail 80 vpn
docker compose exec vpn swanctl --list-conns
docker compose exec vpn swanctl --list-pools
```

The Compose bridge defaults to `10.88.0.0/24`, with gateway container `10.88.0.2`. Override `VPN_DOCKER_SUBNET` and `VPN_CONTAINER_ADDRESS` in a local `.env` if those conflict. Docker publishes UDP 500/4500; forward those ports from your perimeter router to the Linux host. Kernel IPsec requires NET_ADMIN; no privileged container or Docker socket mount is used. Keep management access and the Docker API private.

This is an IPv4-only endpoint. Do not advertise an IPv6 gateway or claim dual-stack protection without separate IPv6 configuration and client verification. The container firewall permits configured private destinations, blocks other RFC1918/link-local destinations, and masquerades internet traffic. Private traffic keeps its VPN source address so dashboard access restrictions can distinguish VPN clients from enrollment LAN clients.

## 3. Configure return routing

Private access needs a route for the VPN pool through this gateway. On the LAN router, route `10.20.30.0/24` via the Linux Docker host's LAN IP. On the Docker host, route the pool via the container address on the Compose bridge:

```sh
sudo ip route replace 10.20.30.0/24 via 10.88.0.2
```

Persist the host route using your distribution's network configuration. Allow the corresponding forwarded traffic through the host's firewall/Docker forwarding policy. If NPM is another Docker container, verify its actual route and source addresses. Do **not** masquerade private VPN traffic to make it work: that erases the VPN source address relied upon by the dashboard's VPN-only ACLs. Restrict permitted ports further with your host/network firewall; the container's private allowlist works at destination-CIDR level.

## 4. Connect the dashboard and device

1. Open the dashboard's Setup guide and enter the gateway hostname.
2. Upload **only** `runtime/swanctl/x509ca/family-vpn-ca.pem` as the CA certificate.
3. Configure public HTTPS dashboard access and its enrollment/VPN source boundaries using the generated proxy locations.
4. Complete administrator setup and enable notifications using Primary relay.
5. Add a device with its one-time setup code while on the enrollment network.
6. In the native app, enter the username and VPN password created above. Install/approve the private CA and VPN configuration when prompted.
7. Test using cellular or an untrusted Wi-Fi network. Verify the assigned VPN address, DNS, private dashboard routes and reported status.

The device administrator password, VPN account password and dashboard enrollment credentials are separate credentials.

## Accounts, certificate renewal and verification

Add one account per device to `runtime/swanctl/conf.d/family-vpn-secrets.conf`, using separate `eap-<name>` sections with `id` and `secret`. For this CLI/bind-mount alternative, keep the file mode 0600, then reload with `docker compose exec vpn swanctl --load-creds --clear --noprompt`. The browser/volume deployment performs this automatically. Revoke an account by removing it, reloading credentials and terminating its active SA; removing the password alone does not terminate an established tunnel. Secrets are cleartext inside this root-private file, so protect backups.

The generated server certificate lasts **365 days**; the private CA lasts ten years. Renew the leaf before expiry with your retained CA, or replace it with a certificate/chain from your certificate management system. Preserve hostname/SAN and private-key protection; reload credentials and verify new connections. For a CA change, stage dashboard provisioning and device trust approval before switching gateways. Certificate issuance/renewal is not automated by Compose.

```sh
docker compose exec vpn swanctl --list-sas
docker compose exec vpn ip xfrm policy
docker compose exec vpn ip xfrm state
```

An image build, configuration load or healthy container does not prove a real Apple tunnel works. Run the [endpoint acceptance checks](../docs/VPN_ENDPOINT_SETUP.md#acceptance-checks), including wrong passwords, multiple devices behind NAT, cellular/Wi-Fi switching and CHILD/IKE rekeys. Logs can contain device usernames and addresses; redact them before sharing.

References: [strongSwan Apple interoperability](https://docs.strongswan.org/docs/latest/interop/ios.html), [swanctl configuration](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html), [forwarding and NAT](https://docs.strongswan.org/docs/latest/howtos/forwarding.html), and the [existing strongSwan guide](../docs/STRONGSWAN_IKEV2.md).
