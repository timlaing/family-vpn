> Administrator password setup is dashboard-owned; see [ADMINISTRATION.md](ADMINISTRATION.md) for migration and reprovisioning.

> Remote commands and public reporting boundaries are documented in [REMOTE_COMMANDS.md](REMOTE_COMMANDS.md). Re-enroll the updated iPhone/iPad app from 192.168.150.0/24 to authorize signed commands.

# Implementation and deployment

The starter is preserved as the first Git commit. The shared SwiftUI app now uses Apple's Personal VPN API, ordered trusted-Wi-Fi disconnect / catch-all connect rules, device-only Keychain passwords and persistent references, a PBKDF2-SHA256 administrator verifier (600,000 rounds), persistent retry delays, suspension records, verified preference readback, device authentication for credentials, and serialized recovery. A cross-process lock and policy reload coordinate the main app with the macOS login monitor.

## Initial VPN configuration

The supplied signed `VPN-EAP.mobileconfig` is the source for `MyVPN/Resources/VPNConfiguration.json`. The importer verifies its CMS content signature without asserting signer trust, extracts non-secret VPN settings, and exports the public root CA separately. Re-import after deliberate source changes with:

```sh
python3 Tools/import_profile.py VPN-EAP.mobileconfig
```

The app preserves the profile's Certificate authentication method with extended EAP enabled, server and identifiers, issuer common name, High dead-peer detection, MOBIKE/redirect/revocation flags, PFS and internal-subnet configuration. IKE uses AES-256 / SHA2-256 / DH14 / 1440 minutes; the child association uses AES-256-GCM / SHA2-512 / DH14 / 120 minutes. HTTP and HTTPS proxies remain disabled. No MTU override is introduced because the source does not specify one. Missing routing options retain native defaults. [Apple's authenticationMethod documentation](https://developer.apple.com/documentation/networkextension/nevpnprotocolipsec/authenticationmethod) describes how IKEv2 extended authentication uses this setting for server authentication validation.

The initial trusted SSIDs are `Laing's Wi-Fi Network` and `Laing's Wi-Fi Network 5GHz`. They seed new local policy; existing authenticated policy overrides are retained. The redundant Wi-Fi connect rule in the source is covered by the app's catch-all connect rule. SSID matching is exact and case-sensitive; an attacker can imitate an SSID. Native On Demand decides bypass; the app does not claim to know the current SSID without Wi-Fi information permission.

### Root certificate prerequisite

The source includes a self-signed public root CA with common name `vpn`, valid until 17 October 2035. The app bundles its DER certificate as `VPNRootCA.cer` and an unsigned CA-only `VPNRootCA.mobileconfig`; neither contains VPN credentials, a client identity or a VPN payload. First-run setup provides an export action. Transfer the CA-only profile to the target device through a profile-capable system flow such as Safari, Mail or AirDrop, and install/approve it through system Settings. On macOS, approve the profile and certificate trust through system administration. Follow Apple's certificate-trust instructions for the target platform if further trust approval is required.

The app checks the bundled root against system trust before first VPN installation, with network fetching disabled. It does not silently add a global trust anchor, bypass certificate validation, or claim that an app-local Keychain certificate is sufficient for the system VPN. The trust check and actual server-certificate handshake still need physical-device validation. If the original profile already installed the same root, a second root profile may be unnecessary. Do not install the original full VPN profile merely to provision the app's VPN: the app cannot edit a profile-owned configuration.

The importer rejects credentials, identity references, non-root certificate payloads, enabled proxies and unknown protocol options. No identity certificates or credentials should be committed.

The project retains developer team `4C8FWEBR8F` and bundle identifier `uk.co.laingcorp.myvpn`. Deployment targets are iOS/iPadOS 26 and macOS 26; builds use Xcode 27. Enable Personal VPN and Push Notifications for the App ID, regenerate provisioning profiles, and register ad hoc device UDIDs. The iOS entitlement uses the development APNs environment; production/ad hoc export must use the environment in the distribution profile. The macOS app needs Developer ID signing and notarization. Unsigned builds verify compilation only.

## Desktop monitor

The macOS bundle embeds `Contents/Library/LaunchAgents/uk.co.laingcorp.myvpn.monitor.plist`. An authenticated administrator enables it with SMAppService from the app. It launches the same signed executable with `--policy-helper`, suppresses the UI, and checks every minute plus network/configuration events. This shares the app identity, Keychain and policy implementation. macOS may require user approval in Login Items. Removing the VPN unregisters the monitor. Test launch, logout/login, termination/restart, app relocation and update on a signed Mac build before distribution. Timed suspension checks resume after sleep/wake; the desktop timer is not a hard real-time deadline.

## Dashboard enrollment and optional APNs

The sibling VPNWeb 0.3.0 Home Assistant add-on is the supported enrollment service. Its dashboard creates the administrator password verifier; the native main-page registration retrieves that verifier and command trust from the registration LAN before first installation. Enrolled signed commands refresh status, suspend, enable and reprovision the administrator verifier after signature, scope, expiry and replay checks. See ADMINISTRATION.md and REMOTE_COMMANDS.md for credentials, migration and access boundaries.

`Watchdog/server.py` remains a legacy wake-only reference and test fixture. Its 204 registration protocol cannot provision the updated native app. No live server or APNs credentials were configured by these repository changes. APNs token registration and signed command handling support iOS/iPadOS and macOS; the running Mac background helper handles remote commands with the UI closed. VPN-connected pending-command polling remains a fallback. Notification denial does not disable native On Demand.

## Validation

```sh
xcodebuild -project MyVPN.xcodeproj -scheme MyVPN -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO test
xcodebuild -project MyVPN.xcodeproj -scheme MyVPN -destination 'generic/platform=iOS' CODE_SIGNING_ALLOWED=NO build
python3 -m unittest discover -s Watchdog -v
```

Xcode XCTest is the verified test path. A SwiftPM harness is also included, but this Xcode 27 environment produces conflicting Darwin SDK modules with SwiftPM.

Physical VPN acceptance remains pending system CA trust, signing/provisioning and a test account. Execute the physical-device matrix in PLAN.md: installation/permission denial, actual gateway authentication/certificate rejection, network transitions, preference tampering, expiry across force-quit/reboot, APNs delivery, disabled refresh, and signed helper operation. Test simulated failures of preference save/readback and rollback with the actual entitlement. Unit Keychain tests use isolated random service names and never touch production credentials.

## Known limits and reset semantics

On unsupervised devices the app can be removed, force-quit, or denied background execution. Exact iOS expiry is unavailable; a local reminder accompanies timed suspension. Another Personal VPN causes a visible conflict and one repair attempt per opportunity. The app never intentionally replaces another owner's configuration.

Keychain items may survive uninstall. Existing local administrator verifiers continue protecting an installed VPN until dashboard registration or a signed reprovision request replaces them. First installation requires a dashboard-provisioned record; reinstalling alone is not password recovery.

Repeated failures are visible in the app, with a generic local notification after three consecutive failures when notification permission allows. Notification delivery remains to be validated on physical devices. Last check/result are process-local and contain no credentials. No browsing, DNS, traffic, location or SSID history is collected.

### Verified on 7 October 2026

- macOS unsigned build and XCTest: passed, 9 tests and 0 failures.
- Generic iOS unsigned build: passed.
- Python importer tests: passed, 4 tests, including signed-source-to-bundle equivalence and CA-only export.
- Python watchdog tests: passed, 2 tests.
- macOS monitor plist verified at the expected bundle path.
- No real VPN was installed or connected; no APNs provider key was accessed and no server was deployed.

## Application identity and macOS menus

The displayed application name is Family VPN on all platforms; the executable and bundle identifier remain unchanged for the desktop helper. AppIcon supplies an opaque 1024-pixel iOS master and macOS icon sizes. Artwork provenance and prompt are in APP_ICON_PROMPT.txt.

macOS uses a single connection window rather than creating independent policy windows. The VPN menu provides Show Connection (Command-1), Check Connection (Command-R), Change VPN Credentials (Command-Shift-K) and Administrator Controls (Command-Shift-A). Credential and administrator requests use the existing authentication gates. Unavailable and preview-state actions are disabled. Native editing/window commands remain available, while generic New Window actions are removed. Help presents local guidance without transmitting data.

Verification: signed iOS simulator build passed; macOS build and all nine existing tests passed. Both bundle names and compiled icon entries were checked. All desktop preview instances were closed. Native menu interaction remains unverified where Computer Use access is unavailable.

### Expanded verification and hardening

See TEST_REPORT.md for current results and NEXT_STEPS.md for the ordered device/distribution checklist. Recovery hints now share one in-flight result; queued preference work observes cancellation without corrupting the queue. Background refresh reports the actual repair result and completes once on expiration or worker completion. Cancelled work does not generate false repair-failure alerts. Credential replacement checks ownership, and install/credential rollback preserves protocol, enabled state, On Demand rules and metadata. Administrator-policy rollback failures are explicit. Secure-storage read errors cannot masquerade as a missing administrator record. Persisted dates, retry counters and association lifetimes are bounded before native use.

The watchdog accepts variable-length opaque APNs tokens, closes SQLite connections, continues remaining sends after a network failure and preserves token rotation during invalid-token pruning. Local HTTP tests cover enrollment authentication, invalid input and rotation. No provider key or real APNs request was used.

ExportOptions templates use Xcode’s current release-testing and developer-id methods. The macOS target enables hardened runtime. Real Developer ID signing and notarization remain pending the required signing identity and successful physical acceptance.

## Home Assistant control service

The sibling `../VPNWeb` app is the primary packaged control service; the Watchdog directory remains the earlier minimal baseline. Home Assistant Ingress provides dashboard/APNs configuration, while a separate REST port is routed through Nginx Proxy Manager and restricted to connected VPN clients. Follow `../VPNWeb/docs/HOME_ASSISTANT.md` rather than publicly exposing the baseline watchdog. The updated native client derives the status endpoint from its HTTPS registration URL and stores the device-scoped report credential in Keychain. Offline enrollment/reporting has no public fallback; stale report times are expected while disconnected.
