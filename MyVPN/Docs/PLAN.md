> Current dashboard provisioning and command protocol: [ADMINISTRATION.md](ADMINISTRATION.md) and [REMOTE_COMMANDS.md](REMOTE_COMMANDS.md).

# Family VPN App — Design and Implementation Plan

## 1. Purpose

Build a native SwiftUI application for iOS, iPadOS, and macOS that installs and manages an IKEv2 Personal VPN configuration.

The application replaces the practical role of a fixed Apple configuration profile while allowing the VPN username and password to be changed. It also provides parental-control-oriented, best-effort policy enforcement:

- Do not connect the VPN on administrator-approved trusted Wi-Fi networks.
- Connect automatically on cellular, Ethernet, and all untrusted Wi-Fi networks.
- Allow an administrator to suspend the VPN for a selected period or indefinitely.
- Detect and repair unauthorized changes to the app-owned VPN configuration whenever iOS, iPadOS, or macOS gives the app an execution opportunity.

This is not a substitute for supervised-device MDM. On an unsupervised device, the owner can still force-quit or remove the app, delete the VPN configuration, disable background execution, or change VPN settings. The design provides best-effort recovery rather than non-bypassable enforcement.

## 2. Target Platforms and Distribution

- Use one shared SwiftUI codebase for iOS, iPadOS, and macOS.
- Support the current shipping Apple OS releases and the immediately preceding major releases at implementation time.
- Distribute iOS and iPadOS builds through ad hoc provisioning to registered device UDIDs.
- Sign the macOS build with Developer ID and notarize it.
- Enable the Personal VPN entitlement (`com.apple.developer.networking.vpn.api`).
- Enable Keychain access, Background App Refresh, Remote Notifications, and local notifications.
- Do not add background audio, PushKit/VoIP, location, or other unrelated background modes as keep-alive mechanisms.

## 3. VPN Architecture

Use Apple's built-in IKEv2 implementation through `NEVPNManager` and `NEVPNProtocolIKEv2`. Do not build a custom packet-tunnel extension unless later server requirements prove incompatible with the built-in client.

The application owns one Personal VPN configuration and is responsible for installing, validating, updating, and removing it. It cannot modify a VPN owned by a configuration profile.

### Fixed configuration

Import the non-secret settings from a sanitized existing `.mobileconfig` into a bundled, read-only configuration resource. It must include:

- VPN server address.
- Remote and local identifiers.
- IKEv2 authentication method and EAP settings.
- Server-certificate validation constraints.
- IKE and child security-association algorithms and lifetimes.
- Routing, MTU, sleep, MOBIKE, and related protocol settings used by the existing profile.

It must not contain usernames, passwords, private keys, shared secrets, tokens, or administrator credentials.

### User-editable credentials

- Ordinary users may edit only the VPN username and password.
- Protect entry into the credential editor with Face ID, Touch ID, or device authentication.
- Never display the saved password; changing it requires a complete replacement value.
- Store the VPN password in a non-synchronizing, device-only Keychain item that is available to the system VPN service after the device's first unlock.
- Set `NEVPNProtocolIKEv2.passwordReference` to the Keychain item's persistent reference.
- Store the username in the VPN protocol configuration.
- Never log credentials or include them in diagnostics, notification payloads, or server requests.

Credential changes must be transactional: disconnect if necessary, update the Keychain and VPN configuration, save and reload preferences, and restore the previous working state if any step fails.

## 4. Trusted Wi-Fi Policy

Ship a default trusted-SSID list and allow an authenticated administrator to add, rename, and remove entries.

SSID matching is exact and case-sensitive. Trim surrounding whitespace, reject empty values, and prevent duplicates. SSID-only trust does not protect against another access point imitating the same SSID; this limitation must be disclosed in the administrator UI.

Configure ordered VPN On Demand rules:

1. An `NEOnDemandRuleDisconnect` matching the trusted SSID list on Wi-Fi.
2. A catch-all `NEOnDemandRuleConnect` for every other available network.

The system VPN service evaluates these rules even when the application UI is not running:

- Joining trusted Wi-Fi disconnects or bypasses the VPN.
- Leaving trusted Wi-Fi allows the VPN to connect automatically.
- Cellular, Ethernet, and untrusted Wi-Fi use the VPN.
- No network means no connection attempt.

After an administrator changes the trusted list, rebuild the rules, save them to Network Extension preferences, reload them, and verify that the stored state matches the requested state.

## 5. Local Administration

Require creation and confirmation of the device administrator password in the dashboard. Before installing the VPN, register from 192.168.150.0/24 to retrieve its verifier. Manage password changes centrally and deliver them through registration or signed reprovision commands.

- Store a salted, computationally expensive verifier rather than plaintext.
- Use constant-time verifier comparison.
- Apply persistent exponential retry delays after repeated failures.
- Never place the administrator password in logs, backups, notifications, or server payloads.
- Require the administrator password for local changes to trusted SSIDs, suspension, repair or removal. Dashboard administrator access manages password changes and authorizes enrolled signed commands.
- Provide dashboard-managed recovery through authenticated re-registration or a signed reprovision request. Keychain records may survive uninstall; reinstallation alone is not a password reset.

The password gate is an application control, not a system security boundary. Reinstalling the app or changing settings outside it remains possible on an unsupervised device.

## 6. Administrator Suspension

Offer these suspension choices:

- 15 minutes.
- 1 hour.
- 8 hours.
- Until tomorrow at a clearly displayed local time.
- A custom date and time.
- Until manually re-enabled.

Persist a suspension record containing its creation time, optional expiry, and whether it is indefinite. Do not require or store a reason.

When suspension begins:

1. Verify the administrator password.
2. Persist the suspension record.
3. Set `isOnDemandEnabled` to `false`.
4. Disconnect an active tunnel.
5. Save and reload Network Extension preferences.
6. Display the suspension and expiry prominently.

Require the administrator password to end a suspension early or to end an indefinite suspension.

When a timed suspension expires, restore the standard On Demand rules and allow the system to reconnect only when the current network is not trusted. Re-evaluate expiry on every available execution opportunity, including app launch, foreground transition, background refresh, background push, configuration notification, and network event received while the app is active.

Exact automatic expiry cannot be guaranteed on iOS or iPadOS if the application is suspended or terminated. Schedule a local notification at the deadline and restore enforcement as soon as the system next runs the app. On macOS, use a signed login/background helper for prompt expiry handling.

## 7. Best-Effort Self-Repair

The desired policy is authoritative unless an authenticated administrator suspension is active.

At every repair opportunity, load the configuration from preferences and verify:

- The app-owned VPN configuration still exists.
- `isEnabled` is true.
- `isOnDemandEnabled` is true when no suspension is active.
- The protocol settings match the bundled fixed configuration.
- The username and password reference are present.
- The trusted-network and catch-all rules are present and ordered correctly.

If the state differs, restore it, save preferences, reload, and verify the effective state. Do not repair On Demand while a valid administrator suspension is active.

Observe `NEVPNConfigurationChangeNotification` and `NEVPNStatusDidChange` while the process is running. These notifications can detect changes but do not reliably launch a suspended or terminated iOS application.

If another Personal VPN becomes enabled, avoid a rapid enable/disable loop. Record the conflict, attempt one policy repair per execution opportunity, and present a visible warning to the administrator.

### Background push watchdog

Provide a small server-side APNs service as an optional but recommended component.

- Register each installation with an opaque device identifier and its APNs token.
- Send a silent background notification approximately every 30–60 minutes.
- Use `apns-push-type: background`, `apns-priority: 5`, `content-available: 1`, and a collapse identifier so obsolete checks are coalesced.
- Never include plaintext VPN or administrator passwords, trusted SSIDs or browsing data in pushes. Signed reprovision commands may contain the salted administrator verifier; treat it as sensitive credential material.
- On receipt, run the repair evaluation and finish within Apple's background execution allowance.
- Rotate changed APNs tokens and remove invalid tokens reported by APNs.
- Authenticate device registration and protect the APNs provider key in server-side secret storage.

Silent push delivery is discretionary. Apple may delay, throttle, coalesce, or discard pushes, and force-quitting the app prevents background pushes from relaunching it until it is opened again. The server watchdog is therefore one recovery path, not the sole control mechanism.

### Other recovery opportunities

- Submit `BGAppRefreshTask` requests as a secondary best-effort mechanism.
- Recheck policy whenever the app launches or becomes active.
- Recheck after protected data becomes available following the first device unlock.
- Recheck on network-path changes while the process is running.
- Use a signed macOS login/background helper for continuous desktop monitoring.
- Send a visible local notification if automatic repair repeatedly fails or user interaction is required.

Do not use PushKit/VoIP pushes. They are reserved for real incoming calls, must be reported to CallKit, and misuse can terminate the app or stop future VoIP delivery. Do not play silent audio to retain background execution; the audio background mode is restricted to genuine audio functionality and is not a reliable watchdog.

## 8. User Experience

### First-run flow

1. Explain what the application controls and the limitations of an unsupervised device.
2. Set the password in the dashboard and retrieve its verifier through authenticated LAN registration.
3. Enter the initial VPN username and password.
4. Review the shipped trusted Wi-Fi list.
5. Request permission to add the Personal VPN configuration.
6. Install, reload, and verify the configuration.

### Main screen

Display:

- Connected, connecting, disconnected, reasserting, or failed state.
- “Not connected on trusted Wi-Fi” when a trusted-network rule applies.
- “Suspended by administrator” with the expiry or “Until manually enabled.”
- Read-only server identity.
- Credential-change action.
- Last successful policy check and last repair result.

Use status language that distinguishes an intentional trusted-network bypass or suspension from a connection failure.

### Administrator screen

After the password challenge, provide:

- Trusted SSID management.
- Suspension duration selection.
- Early re-enable control.
- Guidance to change the password in the dashboard and reprovision the device.
- Configuration validation and repair.
- Configuration removal with an additional confirmation.

## 9. Internal Components

- `VPNConfiguration`: immutable fixed IKEv2 settings decoded from the bundled resource.
- `VPNCredentials`: transient username and replacement-password input.
- `CredentialStore`: Keychain creation, persistent-reference updates, and deletion.
- `AdminAuthenticator`: dashboard verifier validation/provisioning, local password validation and persistent throttling.
- `TrustedNetworkStore`: bundled defaults plus authenticated local overrides.
- `SuspensionPolicy`: active state, creation time, optional expiry, and indefinite state.
- `VPNPolicyEngine`: constructs the ordered On Demand rules and determines desired state.
- `VPNManager`: installs, loads, validates, repairs, connects, disconnects, and removes the Personal VPN.
- `RecoveryCoordinator`: serializes foreground, push, refresh, network, and configuration repair triggers.
- `PushRegistrationService`: registers and rotates APNs device tokens without transmitting private VPN data.
- `DeviceAuthentication`: wraps Local Authentication for the ordinary credential editor.

All VPN preference operations must be serialized to prevent overlapping load/save/repair operations.

## 10. Security and Privacy Requirements

- Keep plaintext VPN and administrator passwords out of service payloads; provision only the administrator verifier to the device.
- Use TLS for all communication with the watchdog service.
- Store an opaque device identifier and APNs token; when enrolled in the web service, also store only the latest connection state, policy-check success and server receipt times. Native status reports must not transmit trusted SSIDs, suspension details or credential data. The service may send its administrator verifier in authorized provisioning replies/commands.
- Do not collect browsing activity, DNS requests, visited domains, locations, SSID history, or VPN traffic.
- Redact all Keychain references, usernames, tokens, and identifiers from diagnostics.
- Make local operational logs bounded and non-sensitive.
- Validate every persisted policy object before applying it.
- Accept only the enrolled service’s signed, device-scoped, expiring refresh_status, suspend, enable and reprovision_admin requests. Enrollment authorizes remote policy changes; verify pinned Ed25519 key, enrollment epoch and persistent sequence before applying. Unauthenticated payloads remain wake hints.

## 11. Verification Plan

### Unit tests

- Decode and validate the fixed VPN configuration.
- Construct trusted-SSID disconnect and catch-all connect rules in the correct order.
- Validate SSID editing, whitespace normalization, and duplicate rejection.
- Test suspension presets, custom expiry, indefinite suspension, time-zone changes, and clock changes.
- Test administrator-password verification, retry throttling, and password changes.
- Test Keychain insertion, persistent references, replacement, rollback, and deletion.
- Test repair decisions for every combination of VPN enabled state, On Demand state, suspension state, and network classification.
- Test recovery-trigger coalescing and preference-operation serialization.

### Physical-device integration tests

- First installation and system permission denial.
- Correct credentials, incorrect credentials, unreachable gateway, and invalid server certificate.
- Trusted Wi-Fi to cellular and cellular to trusted Wi-Fi transitions.
- Trusted Wi-Fi to untrusted Wi-Fi transitions.
- Sleep/wake, reboot, first unlock, and temporary loss of connectivity.
- Credential rotation while connected, bypassed, and suspended.
- Manual disabling of On Demand in Settings while the app is active, suspended, terminated, and later relaunched.
- Enabling another Personal VPN and resolving the conflict.
- Each suspension duration and expiry while foregrounded, backgrounded, and force-quit.
- Silent push delivery, delayed delivery, coalescing, invalid tokens, and unavailable APNs.
- Disabled Background App Refresh and denied notification permission.
- macOS background-helper startup, repair, update, and removal.

VPN behavior must be tested on physical iPhone, iPad, and Mac hardware; simulators do not provide representative system VPN behavior.

### Acceptance criteria

- The app-owned configuration appears in Apple system VPN settings.
- Users can change VPN credentials without reinstalling a profile.
- The VPN disconnects on every configured trusted SSID.
- The VPN connects automatically on cellular, Ethernet, and untrusted Wi-Fi while enforcement is active.
- Administrator suspension persists across app and device restarts.
- Expired suspensions restore enforcement at the first available execution opportunity.
- Unauthorized changes are detected and repaired whenever the application or macOS helper can execute.
- No credentials or browsing information leave the device.
- The product clearly communicates that enforcement is best effort on unsupervised iOS and iPadOS devices.

## 12. Required Inputs Before Implementation

- A sanitized copy of the current `.mobileconfig` containing all non-secret IKEv2 settings.
- The initial trusted Wi-Fi SSID list.
- Apple Developer team and bundle identifiers.
- Registered iOS/iPadOS device UDIDs for ad hoc provisioning.
- VPN server test credentials and access to a test account.
- Decision on the hosting environment for the optional APNs watchdog service.

## 13. Apple References

- [NEVPNManager](https://developer.apple.com/documentation/networkextension/nevpnmanager)
- [VPN On Demand rules](https://developer.apple.com/documentation/networkextension/vpn-on-demand-rules)
- [Personal VPN entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.vpn.api)
- [Background notifications](https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app)
- [PushKit VoIP restrictions](https://developer.apple.com/documentation/pushkit/pkpushtype/voip)
- [App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/)
