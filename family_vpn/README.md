# Family VPN — Home Assistant app

[![Add Family VPN to Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Ftimlaing%2Ffamily-vpn)

Supports AMD64 and ARM64/aarch64. Requires a Home Assistant installation with Supervisor. Add the repository URL, install Family VPN, configure its bearer secrets and APNs identity, start it, then open its Ingress dashboard.

Open Web UI for the Ingress dashboard and APNs settings. Use the separate mapped REST port behind Nginx Proxy Manager for native enrollment/status.

See [DOCS.md](DOCS.md) for configuration and installation. Licensed under [MIT](LICENSE).
