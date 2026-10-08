> Device administrator setup and signed reprovisioning: [ADMINISTRATION.md](docs/ADMINISTRATION.md).

> Version 0.3.0: authenticated POST status and command acknowledgements may be public; registration is restricted to 192.168.150.0/24; remaining REST routes stay VPN-only. See [remote command and proxy configuration](docs/REMOTE_COMMANDS.md).

# Family VPN

Family VPN combines native iOS/iPadOS/macOS apps in `MyVPN/` with a Python/Flask dashboard and Home Assistant add-on in `family_vpn/`. The dashboard provisions administrator access, sends signed VPN commands and receives authenticated status updates. The native app remains authoritative for VPN policy.

Open `MyVPN/MyVPN.xcodeproj` for Apple development. See the [implementation plan](MyVPN/Docs/PLAN.md), [device setup and acceptance checks](MyVPN/Docs/NEXT_STEPS.md), and [Xcode Cloud setup](MyVPN/Docs/XCODE_CLOUD.md). GitHub Actions tests and publishes the web service; Xcode Cloud handles the Apple project.

## Home Assistant installation

This repository includes a Home Assistant app/add-on in `family_vpn/`. The dashboard and APNs settings use Ingress on port 8099; a separate bearer-authenticated REST listener on port 8081 sits behind your Nginx Proxy Manager custom location. Only authenticated POST status and command acknowledgements are publicly reachable; registration requires 192.168.150.0/24 and remaining REST routes require VPN source addresses. Follow [Home Assistant and NPM setup](docs/HOME_ASSISTANT.md). The root entry points retain standalone preview compatibility.

## Documentation

- [Contributing](CONTRIBUTING.md), [security policy](SECURITY.md) and [privacy policy](PRIVACY.md).
- [API contract](docs/API.md), [architecture](docs/ARCHITECTURE.md) and [deployment/releases](docs/DEPLOYMENT.md).
- [Changelog](CHANGELOG.md) and [MIT licence](LICENSE).

Requires Python 3.12–3.14 on macOS/Linux, or Docker for Linux containers. CI tests all three Python versions and the production container. Version tags publish tested images to GHCR; deployment instructions are in the release guide.

## Features

- Authenticated dashboard, per-installation and all-device check requests, and automatic 30–60 minute checks (default 45).
- APNs HTTP/2 background hints: priority 5, content-available 1, collapse ID policy-check. Provider JWTs are reused for up to 50 minutes.
- Enrollment token rotation and invalid-token pruning; a rotated token cannot be pruned by an old response.
- Device-scoped status credentials stored as SHA-256 hashes. Browser/admin APIs never expose APNs tokens or device credentials.
- Connection-state and policy-check reports, with server receipt timestamps and a bounded 200-event operational history.
- Separate enrollment/admin credentials, session authentication, CSRF protection, login throttling, restricted response headers and private SQLite permissions.
- Dashboard distinguishes APNs acceptance from actual device execution. Device reports describe their last execution opportunity, not live coverage. Silent pushes are discretionary, particularly after force-quit.

## Local preview (no secrets or real pushes)

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/python app.py --demo --port 8081
```

Open http://127.0.0.1:8081. Preview data is synthetic; every POST is blocked and no APNs key is accessed. Stop with Control-C.

## Configure a local service

```sh
.venv/bin/python setup_local.py
set -a
source .env
set +a
.venv/bin/python app.py --port 8081
```

Open `/login`. Read your private `.env` locally and enter ADMIN_BEARER as the dashboard access key. Do not paste secrets into chat or Git. This generated configuration disables automatic pushes and enables loopback HTTP cookies. Without APNs configuration, enrollment/status work but push requests return 503.

The native app requires HTTPS. For a real device, deploy behind your trusted HTTPS reverse proxy and set LOCAL_HTTP=false. Use certificates trusted by the device, not an unapproved TLS bypass.

## Production

1. Keep ADMIN_BEARER, REGISTRATION_BEARER, SESSION_SECRET and the APNs .p8 key in private environment/secret storage. Use separate strong random values. Mount the provider key read-only. Keep the database persistent with restrictive file permissions.
2. Set APNS_KEY_FILE, APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC and APNS_ENVIRONMENT. Use sandbox for development builds and production for release-testing/ad hoc builds. Check your actual team ID.
3. Set AUTO_PUSH=true for scheduled checks. WATCHDOG_INTERVAL_SECONDS must be 1800–3600. Checks start after the first interval, not immediately on startup.
4. Run exactly **one worker** so the scheduler and dispatch lock are unique:

```sh
.venv/bin/gunicorn --workers 1 --threads 4 --bind 127.0.0.1:8081 \
  --access-logfile /dev/null --error-logfile - wsgi:application
```

5. Put an HTTPS reverse proxy in front of this loopback listener. Apply request-body limits and ingress rate limits; never log Authorization headers, cookies or request bodies. Keep registration and status under the same deployment prefix. Do not expose the development Flask server publicly.

The server does not contact APNs until configured and triggered or its scheduled interval arrives. No real pushes or key reads occurred during implementation tests.

## Connect the native app

Use the updated MyVPN build from the sibling directory. Set the device administrator password in the dashboard, then on the native main page set the HTTPS registration endpoint (for example `https://vpn-control.example.com/registrations`) and REGISTRATION_BEARER, then register. Registration returns a device-specific status credential; the app stores it in device-only Keychain. APNs token changes re-register and rotate this credential.

After foreground/timer/push recovery checks, the app posts only `{id, connection, policy_ok}` to `/status` on the same origin/prefix. It never sends VPN usernames/passwords, administrator passwords, SSIDs or browsing information. The server stores the suspension duration selected in its dashboard. Reporting failure does not disable local VPN policy. The updated app requires administrator provisioning from the 0.3.0 service; legacy 204 watchdog replies cannot provision it.

If endpoint/enrollment changes, re-register. If you replace the database or rotate enrollment credentials, re-enroll devices. Status reporting is best effort; offline reports are not queued. Dashboard reports can be stale, and connected status is not an independent traffic audit.

## API

| Endpoint | Authentication | Behaviour |
| --- | --- | --- |
| GET /health | None | Generic readiness only |
| POST /registrations | Bearer REGISTRATION_BEARER | `{id, token}`; returns 201 `{status_token}`; rotates report credential |
| POST /status | Per-device status_token | `{id, connection, policy_ok}`; returns 204 |
| GET /api/devices | Bearer ADMIN_BEARER or admin session | Sanitized latest reports; no tokens/hashes |
| POST /api/push | Bearer ADMIN_BEARER | `{}` for all or `{id}` for one; returns 202 queued, 409 busy or 503 unconfigured |

IDs are canonical UUIDs. Connection values: connected, connecting, reasserting, disconnecting, disconnected, invalid. policy_ok is a JSON Boolean. Private/extra fields are rejected. APNs tokens are variable-length lowercase byte-pair hexadecimal. Requests are limited to 2048 bytes. A queued request is asynchronous; refresh the dashboard for its APNs result and wait for a separate device report.

## Test

Install the separate test dependencies; production images do not include pytest.

```sh
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python -m pytest -v
```

Tests use temporary SQLite files, synthetic tokens/provider responses and a fake sender. Coverage includes enrollment/authentication, scoped reports, credential rotation, CSRF, login throttling, payload limits, privacy, queue coalescing, token rotation during delivery, pruning, bounded history and read-only preview. These do not prove real APNs delivery, device scheduling or production deployment.

## Licence

Copyright 2026 Tim Laing. Released under the [MIT licence](LICENSE). Third-party dependencies retain their own licences.
