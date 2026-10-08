# Family VPN Privacy Policy

Effective date: 8 October 2026

Family VPN is open-source software for iOS, iPadOS and macOS that connects to a configured IKEv2 VPN and an administrator-managed dashboard. The software does not include a VPN subscription or a hosted dashboard service. Your deployment's administrator is responsible for the VPN server, dashboard and their configuration.

## Information stored on your device

The app stores VPN credentials, dashboard enrollment credentials, device-scoped reporting credentials, administrator password verification data and command verification keys in the Apple Keychain. Local policy includes trusted Wi-Fi names, suspension settings and expiry times. The app also retains bounded command-processing records so it can reject replayed commands and acknowledge execution. VPN passwords are supplied to Apple's system VPN through Keychain references.

Device authentication uses Apple's authentication facilities. The app does not receive or store fingerprint or face templates. Wi-Fi identity, when the operating system makes it available, is used locally to explain connection status.

## Information sent to the dashboard

Registration sends an installation identifier and an Apple push-notification token when available. Status messages contain the installation identifier, VPN connection state and whether the local policy check succeeded. Command acknowledgements identify the command and its execution result. The dashboard records receipt times, command requests, suspension durations and bounded operational history. It stores push tokens, administrator verification data and hashed device reporting credentials.

The dashboard stores administrator-configured VPN gateway, trusted Wi-Fi names and optional public CA certificates and supplies them to devices during registration. Device status reports do not send VPN usernames or passwords, trusted Wi-Fi names, browsing history, visited URLs or biometric information. The network service and reverse proxy may see source IP addresses and maintain their own access logs; those logs depend on the operator's configuration.

## Why this information is processed

Installation identifiers and push tokens enable device registration and remote commands. Connection reports and acknowledgements help administrators understand whether a device has checked its policy or executed a command. Verification data protects administrator access and authenticates commands. These features do not independently audit browsing traffic or guarantee continuous VPN connectivity.

## Apple and your VPN operator

Apple provides system VPN, Keychain, device authentication and Apple Push Notification service. Push notifications may carry a signed command, including a requested suspension expiry or administrator verification update. They do not carry the plaintext administrator password or VPN password. Apple's processing is governed by its own privacy terms.

Your VPN operator processes traffic routed through the VPN and authentication information required by the VPN server. Its visibility and logging practices depend on that deployment. This policy describes Family VPN's app/dashboard software and does not replace the operator's privacy policy.

## Advertising and tracking

The app includes no advertising or third-party analytics SDKs. Its reporting protocol is used for VPN administration and does not implement advertising tracking.

## Retention and removal

The device retains settings and Keychain records needed for continued operation. Removing the app does not necessarily remove Keychain items or the system VPN configuration. Ask your administrator for help removing these records and any installed VPN or certificate profile.

Dashboard data is held in the operator's database and backups. Operational history is bounded, but device records, commands and backups may persist until the operator removes them. Contact your deployment administrator for retention details and requests to access or remove deployment data.

## Contact and changes

For questions about the software or this policy, contact **tim@laingcorp.co.uk**. For questions about your VPN traffic, dashboard records or deployment access, contact the administrator who enrolled your device.

This policy may be updated as the software changes. The effective date above identifies the current version. Source code and policy history are available at https://github.com/timlaing/family-vpn.
