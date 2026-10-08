> Device administrator setup and signed reprovisioning: [ADMINISTRATION.md](ADMINISTRATION.md).

> Version 0.3.0: authenticated POST status and command acknowledgements may be public; registration is restricted to 192.168.150.0/24; remaining REST routes stay VPN-only. See the repository `docs/REMOTE_COMMANDS.md` for complete setup instructions.

# Home Assistant app and Nginx Proxy Manager

## Install

This repository is an app/add-on repository: `repository.yaml` identifies it and `family_vpn/config.yaml` defines the app. No Home Assistant configuration has been changed by implementation.

For local installation, copy the entire **family_vpn** folder to Home Assistant's local apps/add-ons directory (`/addons/family_vpn` on installations using that path), reload the app store and install **Family VPN** from Local apps. The folder includes its own Dockerfile and runtime dependencies. For repository installation, push this repository to a Git host, add its clone URL under the Home Assistant app store's repository menu, then install. The repository URL is `https://github.com/timlaing/family-vpn`.

Set two separate random credentials of at least 32 characters in the app's **Configuration** tab:

- `admin_bearer`: administrative REST access.
- `registration_bearer`: native device enrollment.

Defaults are deliberately empty, and startup fails until valid credentials are provided. Configure APNs identity/topic/environment; keep `automatic: false` until manual delivery is verified. Put the P-256 provider key at `/share/family-vpn/apns.p8` and restrict its host permissions. The app maps `/share` read-only; it reads no Home Assistant configuration/API and requests no host-network or privileged capabilities. The Supervisor-mounted `/data` contains the SQLite database, persisted session secret and Ingress setting overrides. Protect app backups like the live credentials/database. Cold backups stop the app while copying persistent data.

The Home Assistant app image runs within the Supervisor's protected container as root so it can read Supervisor-owned options and private provider files. The standalone image runs UID 10001. Do not disable protection mode or grant host access.

## Dashboard and configuration

Start the app and choose **Open Web UI**, or enable its Family VPN sidebar panel. The dashboard is available through Home Assistant Ingress, without a second app login. Only the Supervisor gateway peer `172.30.32.2` can enter port 8099; forwarded IP headers do not authorize access. Never map port 8099 externally.

The Ingress **Configuration** page edits APNs key ID, team, topic, key path, environment, interval and automatic checks. It never displays bearer/session credentials or provider key contents. Saves apply immediately and persist as overrides in `/data/runtime-settings.json`. Changes are rejected while dispatch is active. The scheduler adopts an interval after the current wait completes. Reset removes overrides; restart the app to reload Home Assistant options. The native Home Assistant Configuration tab remains authoritative for bearer credentials; changing options requires an app restart.

The sidebar entry is marked administrator-only. Ingress trusts Home Assistant's existing authorization; review who can open app Ingress in your installation. Session cookies are scoped to the Ingress prefix and follow the gateway's forwarded HTTPS indicator. Use HTTPS for Home Assistant remote access.

## External REST interface

Port **8081** exposes `/registrations`, `/status`, `/commands`, `/command-results`, `/api/devices`, `/api/push`, `/api/commands` and `/health`. All operational REST routes use bearer authentication; `/health` is generic liveness. Dashboard, login, static assets and configuration are rejected on this port. The container serves plain HTTP here; terminate trusted TLS at Nginx Proxy Manager.

Select the host mapping under the app's **Network** settings (8081 by default). Keep this host port accessible only from the reverse proxy/trusted network; do not forward it directly from your router. If NPM runs in a separate container, `127.0.0.1` means that container, so use the Home Assistant host's reachable LAN address and the selected mapped port. If NPM shares the Supervisor network, a tested app DNS name can be used instead, but do not guess the repository-prefixed container name.

## Nginx Proxy Manager custom location

On an existing HTTPS Proxy Host, add a custom location:

| NPM field | Value |
| --- | --- |
| Location | `/family-vpn/` |
| Scheme | `http` |
| Forward Hostname / IP | Home Assistant host LAN IP reachable from NPM |
| Forward Port | App's mapped REST port, usually `8081` |
| Forward Path (if offered) | `/` |

NPM versions differ in how Forward Path is exposed. The essential routing is **strip `/family-vpn/` before forwarding**. Inspect the generated location and ensure its upstream ends with a slash, equivalent to this complete Nginx location:

```nginx
location /family-vpn/ {
    proxy_pass http://HOME_ASSISTANT_HOST:8081/;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 2k;
    proxy_connect_timeout 5s;
    proxy_read_timeout 15s;
}
```

Replace HOME_ASSISTANT_HOST with the real address. This is a **complete location example**, not text to paste as a nested `location` inside NPM's location-specific Advanced box. If NPM does not expose Forward Path, add `rewrite ^/family-vpn/(.*)$ /$1 break;` in that custom location's Advanced field and keep the generated upstream without a URI suffix. Use either the trailing-slash upstream or this rewrite; inspect the generated config and verify the mapping below. Nginx's official proxy-pass URI replacement rules are linked below.

Avoid a second Basic Auth/access-list authentication layer that overwrites Authorization: native enrollment/status uses that header. Preserve bearer values. Do not log headers/bodies or add the Ingress port to this location. Enable a trusted certificate and Force SSL on the Proxy Host. Rate-limit at ingress if supported by your NPM deployment.

| Public HTTPS route | Internal REST route |
| --- | --- |
| `/family-vpn/registrations` | `/registrations` |
| `/family-vpn/status` | `/status` |
| `/family-vpn/api/devices` | `/api/devices` |
| `/family-vpn/api/push` | `/api/push` |
| `/family-vpn/health` | `/health` |

Verify public `/family-vpn/health` returns `{"status":"ok"}`; `/family-vpn/` and `/family-vpn/configuration` must return 404, and unauthenticated `/family-vpn/api/devices` must return 401. Then set the native registration endpoint to `https://YOUR_HOST/family-vpn/registrations` with the enrollment bearer. The native client derives the sibling `/family-vpn/status` endpoint automatically.

After one manual APNs request, verify a new report from a physical device. Synthetic/unit/container checks do not establish Supervisor installation, your NPM routing, APNs delivery or physical-device recovery.

## References

- [Home Assistant app configuration](https://developers.home-assistant.io/docs/apps/configuration/)
- [Home Assistant Ingress requirements](https://developers.home-assistant.io/docs/apps/presentation/#ingress)
- [Nginx proxy_pass URI replacement](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass)

## Public reporting and protected REST access

Expose only authenticated POST status and command acknowledgements publicly. Restrict enrollment to 192.168.150.0/24. Restrict pending-command retrieval and administrator REST APIs to the VPN source subnets. Keep the dashboard and configuration in Home Assistant Ingress. Firewall direct port 8081 access and preserve bearer headers at NPM.

The repository `docs/REMOTE_COMMANDS.md` provides the complete location generator, command API, key backup requirements and physical-device acceptance checks. Use its `--public-reports` configuration for this deployment. A public connected report is a device assertion; the separate last VPN-only contact relies on the protected route and correct proxy/firewall configuration.

## Generate the complete proxy location

`Tools/generate_npm_location.py` validates the private upstream address, mapped port, location path and explicit source networks. It rejects default-route allowlists and config injection characters, and only writes the example to stdout; it never changes NPM. Use your actual addresses, not the illustrative values below:

```sh
python3 Tools/generate_npm_location.py --upstream 192.168.1.20 \
  --prefix /family-vpn/ --allow 10.20.30.0/24
```

Repeat `--allow` for multiple client networks or a VPN NAT gateway address. The output is a complete Nginx location, not a nested location for NPM's Advanced box. Apply its allow/deny lines to the existing custom location and use the path-rewrite instructions above. Firewall the direct mapped port separately. If a proxy precedes NPM, establish the trusted real-IP chain before treating its peer address as a VPN source.

The proxy smoke test now also simulates an allowed and denied source on an isolated network: enrollment and scoped reporting succeed through `/family-vpn/` for the allowed peer, while all REST paths return 403 for the denied peer. It also checks forwarded Host headers and bearer preservation. This establishes the example proxy behaviour, not your real VPN routing or NPM configuration.
