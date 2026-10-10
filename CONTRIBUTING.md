# Contributing to Family VPN

Use the issue forms to suggest improvements or report bugs. Include your app/service version, operating system, steps to reproduce, and expected and actual behaviour. Remove passwords, tokens, private network details and device identifiers from attachments.

Report security vulnerabilities privately following [SECURITY.md](SECURITY.md).

For pull requests, describe the problem, resulting behaviour and validation. Keep changes focused, sign commits with your own key and ensure required CI checks pass. Maintain compatibility with the [API contract](docs/API.md) and dashboard provisioning protocol.

Keep runtime dependency versions and hashes identical in `requirements.lock`, `family_vpn/requirements.lock` and `family_vpn/requirements.txt`. The add-on manifest exposes the pinned dependencies to Dependabot; CI checks the three copies stay synchronized.

Do not commit credentials, local provisioning profiles, databases, build outputs or private development documents. Development plans, roadmaps, test procedures and results belong in the ignored local `.private-docs/` folder.

See the [setup and usage documentation](README.md#documentation) for supported deployment and device configuration.

## Local preview (no secrets or real pushes)

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/python app.py --demo --port 8500
```

Open http://127.0.0.1:8500. Preview data is synthetic; every POST is blocked and no APNs key is accessed. Stop with Control-C.

## Configure a local service

```sh
.venv/bin/python setup_local.py
set -a
source .env
set +a
.venv/bin/python app.py --port 8500
```

Open `/login`. Read your private `.env` locally and enter ADMIN_BEARER as the dashboard access key. Do not paste secrets into chat or Git. This generated configuration disables automatic pushes and enables loopback HTTP cookies. Without APNs configuration, enrollment/status work but push requests return 503.

The native app requires HTTPS. For a real device, deploy behind your trusted HTTPS reverse proxy and set LOCAL_HTTP=false. Use certificates trusted by the device, not an unapproved TLS bypass.

## Test

Install the separate test dependencies; production images do not include pytest.

```sh
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python -m pytest -v
```

Tests use temporary SQLite files, synthetic tokens/provider responses and a fake sender. Coverage includes enrollment/authentication, scoped reports, credential rotation, CSRF, login throttling, payload limits, privacy, queue coalescing, token rotation during delivery, pruning, bounded history and read-only preview. These do not prove real APNs delivery, device scheduling or production deployment.
