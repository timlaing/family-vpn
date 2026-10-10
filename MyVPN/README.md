# Family VPN Apple apps

Native iOS, iPadOS and macOS clients for Family VPN. Register with your own dashboard to receive VPN, trusted Wi-Fi, certificate and administrator settings. The apps enforce local VPN policy and report status to the dashboard.

- [Apple device setup and use](../docs/APPLE_APPS.md)
- [Dashboard provisioning](../docs/PROVISIONING.md)
- [Remote commands](../docs/REMOTE_COMMANDS.md)
- [Contributing and local development](../CONTRIBUTING.md)

Open `FamilyVPN.xcodeproj` in Xcode and select the `FamilyVPN` scheme. Configure signing for your Apple Developer team when building your own app. Push credentials must match the app’s bundle identifier and APNs environment.

See the [repository README](../README.md) for the dashboard, Home Assistant app, push proxy and VPN endpoint components.
