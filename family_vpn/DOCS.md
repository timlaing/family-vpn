# Home Assistant app and Nginx Proxy Manager

## Install

[![Add Family VPN to Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Ftimlaing%2Ffamily-vpn)

Home Assistant OS or another installation with **Supervisor** is required; Home Assistant Container/Core alone cannot install Supervisor apps. Supported architectures are AMD64 and ARM64/aarch64.

1. Use the button above, or open Home Assistant's app store (called the add-on store on older versions), select **⋮ → Repositories**, and add `https://github.com/timlaing/family-vpn`.
2. Refresh the store, find **Family VPN apps → Family VPN**, open it and choose **Install**. The `experimental` stage may require advanced mode in your Home Assistant user profile.
3. Configure the two bearer credentials and APNs options below before starting it. Keep protection mode enabled; no host access or privileged capabilities are needed.
4. Choose **Start**, inspect the app log, then **Open Web UI** for the Ingress dashboard. Enable the sidebar panel if desired.
5. Configure gateway, trusted Wi-Fi, optional CA and administrator password. Complete [native provisioning](https://github.com/timlaing/family-vpn/blob/main/docs/PROVISIONING.md) and [VPN endpoint setup](https://github.com/timlaing/family-vpn/blob/main/docs/VPN_ENDPOINT_SETUP.md), then set up the protected REST proxy below.

`repository.yaml` identifies the repository and `family_vpn/config.yaml` defines the app. Supervisor currently builds the self-contained `family_vpn/` Docker context locally; a prebuilt image is not selected in the manifest. The tagged publication workflow also produces architecture-specific GHCR images for explicit deployments. Home Assistant installation does not require a GitHub token for this public repository. No live Home Assistant configuration is changed by these instructions.

For local development, copy the complete **family_vpn** folder to `/addons/family_vpn` on installations using that directory, reload the store and install it under Local apps. For updates, back up the app's private data and signing key, refresh the store and apply an offered version update. The manifest version must increase for Supervisor to offer a new app version; code-only pushes at the same version do not constitute an update release.

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

Port **8081** exposes `/registrations`, `/status`, `/commands`, `/command-results`, `/vpn-configuration`, `/api/devices`, `/api/push`, `/api/commands` and `/health`. All operational REST routes use bearer authentication; `/health` is generic liveness. Dashboard, login, static assets and configuration are rejected on this port. The container serves plain HTTP here; terminate trusted TLS at Nginx Proxy Manager.

Select the host mapping under the app's **Network** settings (8081 by default). Keep this host port accessible only from the reverse proxy/trusted network; do not forward it directly from your router. If NPM runs in a separate container, `127.0.0.1` means that container, so use the Home Assistant host's reachable LAN address and the selected mapped port. If NPM shares the Supervisor network, a tested app DNS name can be used instead, but do not guess the repository-prefixed container name.

## Nginx Proxy Manager routing and access restrictions

Use a trusted HTTPS Proxy Host and strip `/family-vpn/` before forwarding to the mapped REST port. Preserve the Authorization header. Keep port 8099 private to Supervisor Ingress and firewall direct access to port 8081 so clients cannot bypass the proxy ACLs.

Generate complete locations from the repository root, replacing these illustrative addresses with your actual Home Assistant host, registration LAN and VPN client networks:

```sh
python3 Tools/generate_npm_location.py --upstream 192.168.1.20 \
  --prefix /family-vpn/ --allow 10.20.30.0/24 --allow 10.20.40.0/24 \
  --public-reports --registration-allow 192.168.10.0/24
```

The generator writes configuration to stdout and does not modify NPM. It creates separate public POST status/acknowledgement locations, a LAN-only registration location, and VPN-only locations for remaining REST routes. Apply the complete location definitions where your NPM deployment supports server-level custom locations; do not nest them inside an existing location's Advanced box. Inspect the generated configuration, validate Nginx syntax and reload it using your deployment's normal process. See [remote commands and network boundaries](https://github.com/timlaing/family-vpn/blob/main/docs/REMOTE_COMMANDS.md).

NPM must see the real registration/VPN source addresses. If another proxy or NAT sits in front of it, configure a trusted real-IP chain or deliberate source mapping before relying on ACLs. Do not add Basic Auth that overwrites the bearer Authorization header. Do not log headers or request bodies.

| HTTPS route under `/family-vpn/` | Allowed source | Upstream route |
| --- | --- | --- |
| POST registrations | Registration LAN | /registrations |
| POST status | Public; device bearer required | /status |
| POST command-results | Public; device bearer required | /command-results |
| GET commands | VPN clients | /commands |
| GET vpn-configuration | VPN clients | /vpn-configuration |
| api/devices, api/push, api/commands | VPN clients; admin authentication required | Matching /api route |
| GET health | VPN clients; no bearer | /health |

Verify allowed and denied source paths before enrolling a real device: registration works only from the registration LAN; public POST reports require valid scoped credentials; pending-command/configuration and administrator routes reject non-VPN sources. From an allowed VPN source, `/health` returns `{"status":"ok"}`. The REST listener rejects dashboard and configuration routes. Set the native registration endpoint to `https://YOUR_HOST/family-vpn/registrations`; the app derives sibling endpoints on the same origin and prefix.

After a manual APNs command, verify its acknowledgement and a subsequent report from a physical device. Synthetic/unit/container checks do not establish your Supervisor installation, NPM routing, APNs delivery or real tunnel recovery.

## References

- [Home Assistant app configuration](https://developers.home-assistant.io/docs/apps/configuration/)
- [Home Assistant Ingress requirements](https://developers.home-assistant.io/docs/apps/presentation/#ingress)
- [Nginx proxy_pass URI replacement](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass)

## VPN endpoint setup

See the [endpoint setup guide](https://github.com/timlaing/family-vpn/blob/main/docs/VPN_ENDPOINT_SETUP.md), with MikroTik RouterOS and strongSwan settings based on the inspected IKEv2/EAP deployment. Configure your gateway and authentication backend before enrolling devices.
