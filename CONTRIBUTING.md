# Contributing to Family VPN

Use the issue forms to suggest improvements or report bugs. Include your app/service version, operating system, steps to reproduce, and expected and actual behaviour. Remove passwords, tokens, private network details and device identifiers from attachments.

Report security vulnerabilities privately following [SECURITY.md](SECURITY.md).

For pull requests, describe the problem, resulting behaviour and validation. Keep changes focused, sign commits with your own key and ensure required CI checks pass. Maintain compatibility with the [API contract](docs/API.md) and dashboard provisioning protocol.

Keep runtime dependency versions and hashes identical in `requirements.lock`, `family_vpn/requirements.lock` and `family_vpn/requirements.txt`. The add-on manifest exposes the pinned dependencies to Dependabot; CI checks the three copies stay synchronized.

Do not commit credentials, local provisioning profiles, databases, build outputs or private development documents. Development plans, roadmaps, test procedures and results belong in the ignored local `.private-docs/` folder.

See the [setup and usage documentation](README.md#documentation) for supported deployment and device configuration.
