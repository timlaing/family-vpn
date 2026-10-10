# Family VPN strongSwan endpoint

A separate **Linux Docker Engine** IKEv2/EAP-MSCHAPv2 endpoint for Family VPN. It uses the existing application's AES-256/SHA-256/MODP2048 IKE and AES-256-GCM/MODP2048 ESP profile. The dashboard and push relay remain separate services. Docker Desktop is suitable for image/configuration checks, not the documented production gateway: use a reachable Linux host with kernel XFRM/IPsec, UDP 500/4500 and Docker bridge forwarding enabled.

## Browser configuration with persistent Docker volumes

For a new installation, use the standalone management Compose file instead of the CLI/bind-mount instructions below. This remains a separate Docker package, not a Home Assistant app.

1. Create a private `.env` file (`chmod 600 .env`) with `VPN_ADMIN_PASSWORD=` followed by a unique password of at least 16 characters. This bootstraps the administrator credential on first startup; subsequent starts use its persisted password hash. Do not commit this file.
2. Start both containers:

   ```sh
   docker compose -f compose.dashboard.yaml up -d --build
   ```

3. Open `http://localhost:8080`. For a remote Linux host, use `ssh -L 8080:127.0.0.1:8080 user@docker-host` and open the same URL locally. The interface binds to localhost by default; do not forward port 8080 from your router.
4. Sign in and enter the gateway hostname, VPN pool, DNS resolver, LAN networks, permitted private destinations and first device account. The VPN container waits until setup completes, then starts automatically.
5. Download the **public CA certificate** from the interface and upload it to the Family VPN dashboard. Complete the routing and device checks below.
6. Add, change or remove device accounts through the interface. Apply account changes with `docker compose -f compose.dashboard.yaml restart vpn`. This disconnects existing tunnels, including revoked accounts.

Two named volumes survive container replacement: `vpn_configuration` holds gateway settings, VPN credentials and certificates; `vpn_authority` holds the CA signing key and hashed administrator credential/session key. Only the configuration volume is mounted, read-only, into the VPN container. No Docker socket is mounted. Back up both volumes securely; VPN account passwords must be retained in private files for EAP authentication. Never use `docker compose down -v` unless deliberately deleting all configuration and keys.

The UI supports initial gateway provisioning and account management. Gateway address/network changes and certificate renewal remain manual operations; it refuses to recreate an existing CA. Existing CLI installations are not automatically migrated into the named volumes: keep using the original Compose file until a deliberate backup and migration is completed. The browser workflow retains the CA key in its separate volume for later manual renewal, rather than moving it offline.

If deliberately exposing management on a private interface, set `VPN_MANAGEMENT_BIND` to that interface's IP and use an authenticated HTTPS proxy/network restriction. Set `VPN_COOKIE_SECURE=1` in the configuration service environment when accessing exclusively through HTTPS. The administrator session uses HttpOnly/SameSite cookies and Flask-WTF CSRF protection; failed logins are limited. Never publish this interface directly to the internet.

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

Add one account per device to `runtime/swanctl/conf.d/family-vpn-secrets.conf`, using separate `eap-<name>` sections with `id` and `secret`. Keep the file mode 0600, then reload with `docker compose exec vpn swanctl --load-creds`. Revoke an account by removing it, reloading credentials and terminating its active SA; removing the password alone does not terminate an established tunnel. Secrets are cleartext inside this root-private file, so protect backups.

The generated server certificate lasts **365 days**; the private CA lasts ten years. Renew the leaf before expiry with your retained CA, or replace it with a certificate/chain from your certificate management system. Preserve hostname/SAN and private-key protection; reload credentials and verify new connections. For a CA change, stage dashboard provisioning and device trust approval before switching gateways. Certificate issuance/renewal is not automated by Compose.

```sh
docker compose exec vpn swanctl --list-sas
docker compose exec vpn ip xfrm policy
docker compose exec vpn ip xfrm state
```

An image build, configuration load or healthy container does not prove a real Apple tunnel works. Run the [endpoint acceptance checks](../docs/VPN_ENDPOINT_SETUP.md#acceptance-checks), including wrong passwords, multiple devices behind NAT, cellular/Wi-Fi switching and CHILD/IKE rekeys. Logs can contain device usernames and addresses; redact them before sharing.

References: [strongSwan Apple interoperability](https://docs.strongswan.org/docs/latest/interop/ios.html), [swanctl configuration](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html), [forwarding and NAT](https://docs.strongswan.org/docs/latest/howtos/forwarding.html), and the [existing strongSwan guide](../docs/STRONGSWAN_IKEV2.md).
