> Device administrator setup and signed reprovisioning: [ADMINISTRATION.md](docs/ADMINISTRATION.md).

> Version 0.3.0: authenticated POST status and command acknowledgements may be public; registration is restricted to 192.168.150.0/24; remaining REST routes stay VPN-only. See [remote command and proxy configuration](docs/REMOTE_COMMANDS.md).

# Security policy

## Supported versions

Security fixes are maintained on `main`. Deploy a tested release built from current maintained code; older tags are not promised separate backports.

## Private reporting

Report suspected vulnerabilities to **tim@laingcorp.co.uk** with the affected version, reproduction using synthetic data, and impact. Do not open a public issue containing an exploit against a live installation, credentials, device tokens or private reports. There is no guaranteed response deadline.

If a credential has leaked, revoke or rotate it in the affected system immediately. Removing it from Git history alone does not revoke it.

## Data and trust boundaries

The database contains APNs tokens, installation UUIDs, report times, connection/policy results, salted device administrator verifiers and signed-command snapshots. Status credentials are hashed; APNs tokens must remain available to send pushes. Neither the dashboard nor the admin API returns token or credential hashes. Server administrators and anyone with access to the database can read operational data.

The service receives no VPN credentials, SSIDs or browsing data. It stores remotely requested actions and suspension durations. A device report is an authenticated claim from that installation, not independent verification of traffic routing. APNs acceptance does not establish delivery or execution.

Use HTTPS, separate random admin/enrollment/session credentials, private database backups and a read-only APNs key mount. Keep the dashboard restricted to intended administrators. Add ingress rate limits at the reverse proxy: the application throttles dashboard login attempts and public reporting, and a proxy may cause users to share a single limiter address. Do not expose Gunicorn directly to the internet or enable LOCAL_HTTP in production.

Run one application process: scheduling and dispatch locks are process-local. This service is designed for small installations, not multi-tenant use or multiple replicas. Public `/health` only confirms that the web process responds; it does not test Apple connectivity, key validity or device availability.

CI uses synthetic data and no APNs credentials. Registry publication uses only the workflow-scoped GitHub token. Review dependency and action updates before merging.

## Home Assistant mode

The Supervisor gateway peer exclusively authorizes Ingress, including APNs configuration writes. The REST listener exposes no dashboard/configuration and requires bearer credentials for operational routes; it does not accept Ingress sessions. `panel_admin` controls the sidebar entry; review Home Assistant Ingress access separately. The app needs no Supervisor/Core API privileges. See [installation and proxy boundaries](docs/HOME_ASSISTANT.md).

The intended deployment exposes only authenticated POST status and command acknowledgements publicly. NPM restricts all other REST routes to VPN sources, and the direct app port is firewalled. Disconnected installations can report; reported status and last protected contact are separate signals, neither independently audits traffic routing.
