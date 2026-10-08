# Verification evidence

Local verification for the initial Home Assistant package:

- 25 isolated tests pass under Python 3.12, 3.13 and 3.14.
- Locked dependencies pass pip check.
- Standalone and Home Assistant production containers build and pass HTTP smoke checks.
- A synthetic Supervisor gateway on a disposable Docker network passes Ingress dashboard, prefixed static assets, cookie/CSRF and APNs configuration-save checks. No provider credentials are configured and automatic pushes stay disabled.
- Direct Ingress peer/header spoofing is rejected; the external REST port rejects dashboard/configuration and preserves bearer authentication.
- actionlint validates both GitHub workflows; bash syntax checks pass for all smoke scripts.

Tests create synthetic data and temporary storage; smoke scripts clean up their containers/networks. The initial local container checks use the local Docker architecture; native amd64/aarch64 jobs are configured in CI. GitHub runs, Supervisor installation, actual NPM VPN-source restrictions, Apple delivery and physical-device execution remain unverified.

Follow REMOTE_COMMANDS.md to verify public authenticated reporting and registration-LAN enrollment and VPN-only pending-command retrieval/admin APIs from connected and disconnected devices before distribution.

Additional source-ACL verification: allowed peers enroll, report and read sanitized administrative results through a stripped custom-location prefix. Denied peers receive 403 on health/enrollment/status/admin routes. Forwarded Host headers cannot change socket isolation. The configuration generator rejects open default routes, invalid ports, public/loopback upstreams and injection characters.
