# Contributing to Family VPN

## Apple apps

Open `MyVPN/MyVPN.xcodeproj` and use the shared MyVPN scheme. Run its XCTest suite on macOS and iPhone/iPad simulators. See [native verification](MyVPN/Docs/TEST_REPORT.md) and [Xcode Cloud](MyVPN/Docs/XCODE_CLOUD.md). Tests must not install VPN settings or use real credentials. Keep native policy and the dashboard command protocol compatible.

## Web development

Use Python 3.12–3.14 on macOS or Linux. Clone this repository, then run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
.venv/bin/python -m pip check
.venv/bin/python -m pytest -v
.venv/bin/python app.py --demo --port 8081
```

The preview uses synthetic devices and blocks writes. To exercise enrollment and status locally, run `setup_local.py` and follow the [README](README.md). Never use production secrets or real APNs requests in automated tests.

## Changes and pull requests

Keep changes focused. Explain the problem, resulting behaviour and validation in the pull request. Include tests for changes to authentication, registration, dispatch races, request validation or status reporting. For dashboard changes, inspect desktop and narrow layouts and include screenshots containing synthetic data only.

Use pytest with plain assertions and pytest.raises and standard-library utilities where practical. Keep provider responses and failures as bounded, non-sensitive result codes. Do not add credentials, SSIDs, browsing information or free-form device logs to status reports. Review the [architecture](docs/ARCHITECTURE.md) and [API contract](docs/API.md) before changing client compatibility.

Sign commits with your own signing key. Do not amend another contributor's history or commit generated `.env`, databases, provider keys, virtual environments or build output. Use the pull request template and ensure CI passes before merging.

## Dependencies and releases

`requirements.txt` defines direct dependency ranges; `requirements.lock` pins the complete tested runtime environment. Update both where applicable in a clean virtual environment, regenerate the lock with `python -m pip freeze`, and rerun tests on every supported Python version. Do not freeze an unrelated developer environment. Dependabot proposes GitHub Action and Docker base updates; Python lock updates are maintained explicitly because this file is a pip freeze lock rather than a resolver-managed lock.

See [deployment and releases](docs/DEPLOYMENT.md). Changes are listed under Unreleased in [CHANGELOG.md](CHANGELOG.md) until a version is selected. Tags publish container images after tests; they do not install anything on a live server.

## Reporting issues

For bugs, provide OS/Python version, steps, expected and actual behaviour, and sanitized test output. Use synthetic installation IDs and tokens. Report vulnerabilities privately using [SECURITY.md](SECURITY.md).

## Home Assistant changes

Runtime source is in `family_vpn/`; the folder must remain a self-contained Supervisor build context. Keep its requirements.lock identical to the root lock. Test both container contexts and the gateway/REST separation. Do not add Supervisor API access or host-network privileges without a concrete need. Version tags must match `family_vpn/config.yaml`.
