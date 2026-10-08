> Remote commands and public reporting boundaries are documented in [REMOTE_COMMANDS.md](REMOTE_COMMANDS.md). Set the device administrator password in the dashboard, then register updated iOS/macOS apps from 192.168.10.0/24. Use signed reprovision requests after later password changes.

# Next steps — Family VPN

## What is ready

The app, imported IKEv2 settings, local authentication, trusted-network policy, suspension, recovery paths, desktop helper, optional watchdog, icons and menus are implemented. Automated tests exercise logic, isolated Keychain records and synthetic failures. Simulator tests do not establish real system VPN operation.

The project uses team `4C8FWEBR8F` and bundle ID `uk.co.laingcorp.myvpn`. Verify that this is the team you intend to use. The local machine currently has an Apple Development signing identity; no Apple Distribution or Developer ID identity was found. No real VPN, root trust, APNs service or distribution profile was installed during this work.

## 1. Configure Xcode and connect one test device

1. Open `MyVPN.xcodeproj` in Xcode. Add your Apple Developer account under Xcode Settings → Accounts.
2. Select the MyVPN target → Signing & Capabilities. Choose the intended team and automatic signing. Enable Personal VPN for the App ID. Enable Push Notifications if testing the optional watchdog; the project already declares background fetch/remote-notification modes.
3. Connect an iPhone by USB, approve the device's Trust prompt yourself, and enable Developer Mode if Xcode requests it. Select the physical device as the run destination.
4. For eventual ad hoc distribution, register each iPhone/iPad UDID with the Developer team and obtain an Apple Distribution certificate plus a profile including those devices and the required capabilities. Xcode Organizer's release-testing distribution is the current equivalent of ad hoc export.
5. Build and run. Keep VPN test credentials and the administrator password out of chat, files and Git; enter the VPN credentials in the app and set the device administrator password in the dashboard.

Start with one iPhone. Repeat the acceptance checks on an iPad and a signed Mac before distributing to family devices.

## 2. Approve the public root CA and install the app-owned VPN

1. In first-run setup, choose **Export VPN root CA profile**. Transfer it through a profile-capable system flow such as AirDrop, Safari or Mail and approve it in system Settings.
2. On iPhone/iPad, review the installed profile under Settings → General → VPN & Device Management. If required for the manually installed root, enable its trust under Settings → General → About → Certificate Trust Settings. Review the `vpn` certificate and verify it is the bundled certificate before approving it. [Apple's certificate-trust instructions](https://support.apple.com/en-gb/102390).
3. On Mac, approve the CA/profile and required trust through system administration. The app's root-trust gate and the real gateway handshake must both pass.
4. Avoid installing the original **full** VPN-EAP profile alongside this app-owned configuration: a profile-owned VPN cannot be edited by the app. If one is already installed, review and resolve that conflict yourself before the test. Removing an existing profile may also remove its CA, so check root trust afterwards.
5. Set and confirm the device administrator password in the dashboard, register the app from 192.168.10.0/24, then enter the VPN test username/password, review trusted SSIDs and approve **Install Personal VPN** when Apple prompts.
6. Confirm Family VPN appears in system VPN settings. On an untrusted network or cellular, verify actual connection and traffic through your VPN server. A verified policy check alone is not proof of a working tunnel.

## 3. Run the physical acceptance checks

Record OS version, app build, scenario and pass/fail in a local copy of the checklist below. Never include passwords, tokens, persistent references, browsing data or private identifiers in results.

| Scenario | Expected result | Result |
| --- | --- | --- |
| Installation consent denied, then retried | Clear error; retry installs without corrupting credentials | Pending |
| Correct credentials on untrusted Wi-Fi/cellular | Tunnel connects and traffic uses the gateway | Pending |
| Incorrect credentials / gateway unavailable | Failure is visible; no misleading connected state | Pending |
| Invalid/untrusted server certificate | Connection is rejected | Pending |
| Each trusted SSID → cellular/untrusted Wi-Fi, and back | VPN connects away from trusted networks and bypasses them on return | Pending |
| Mac Ethernet | VPN connects when enforcement is active | Pending |
| Credential replacement while connected/bypassed/suspended | Authentication required; replacement works; policy is retained | Pending |
| Timed and indefinite suspension | Persist across restart; expiry resumes at next execution opportunity; early re-enable requires admin password | Pending |
| Disable On Demand or change settings while app is active, backgrounded or force-quit | Repair occurs when execution resumes; no promise of force-quit recovery | Pending |
| Another Personal VPN becomes active | Conflict is visible and competing configuration is not replaced | Pending |
| Reboot, first unlock, sleep/wake and temporary connectivity loss | Policy persists; available recovery paths resume | Pending |
| Notification denial / Background App Refresh disabled | Foreground recovery and native On Demand remain usable | Pending |
| Mac login monitor enabled, app closed, logout/login and sleep/wake | Helper checks policy and handles expiry; Login Items approval may be required | Pending |
| Mac update, relocation and administrator removal | Monitor registration remains valid or exposes a clear error; removal unregisters it | Pending |

There is no in-app administrator password recovery. Keychain data may survive uninstall; a complete reset requires platform administration, not merely reinstalling the app.

## 4. Package distribution builds

The export templates in `Config/ExportOptions` use the project's team ID. Review it before use. Provisioning and signing certificates must already be configured in Xcode. Commands below do not automatically modify your Developer account.

```sh
xcodebuild -project MyVPN.xcodeproj -scheme MyVPN -configuration Release \
  -destination 'generic/platform=iOS' -archivePath /tmp/FamilyVPN-iOS.xcarchive archive
xcodebuild -exportArchive -archivePath /tmp/FamilyVPN-iOS.xcarchive \
  -exportPath /tmp/FamilyVPN-iOS \
  -exportOptionsPlist Config/ExportOptions/iOS-AdHoc.plist
```

Inspect the exported app's signing/provisioning entitlements: Personal VPN must include `allow-vpn`; when distributing with APNs, the exported environment must match the production distribution profile and watchdog server. The development build currently declares development APNs.

For macOS, obtain a Developer ID Application certificate, then archive and export:

```sh
xcodebuild -project MyVPN.xcodeproj -scheme MyVPN -configuration Release \
  -destination 'platform=macOS' -archivePath /tmp/FamilyVPN-macOS.xcarchive archive
xcodebuild -exportArchive -archivePath /tmp/FamilyVPN-macOS.xcarchive \
  -exportPath /tmp/FamilyVPN-macOS \
  -exportOptionsPlist Config/ExportOptions/macOS-DeveloperID.plist
codesign --verify --deep --strict /tmp/FamilyVPN-macOS/MyVPN.app
```

Use Xcode Organizer to submit the exported Mac build for notarization and staple the accepted result before distribution. Preserve the registered installation location when testing the login monitor. A GPG-signed Git commit is separate from Apple app signing and notarization.

## 5. Dashboard enrollment and remote command acceptance

Install the sibling VPNWeb 0.3.0 Home Assistant add-on and configure its dashboard administrator password before initial native VPN setup. See ADMINISTRATION.md and REMOTE_COMMANDS.md. Registration is limited to 192.168.10.0/24; status and acknowledgements are public authenticated POST routes; pending-command retrieval and admin APIs remain VPN-only. Apply and test NPM ACLs and direct-port firewall restrictions.

Use sandbox APNs for development builds and production APNs for distribution. Register each updated device from the native main page on the registration LAN. Test refresh, suspend, enable and administrator reprovision on a physical iPhone/iPad, including delayed delivery, expiry, force quit, changed tokens and offline acknowledgements. Change the password in the dashboard and confirm an executed reprovision acknowledgement before relying on the changed local unlock password. macOS can register before receiving its APNs token; signed APNs commands can reach the running app/background helper while disconnected, with VPN-connected polling as fallback. Delivery timing is best effort.

## Re-run local verification

```sh
python3 -m venv .venv
.venv/bin/pip install -r Watchdog/requirements.txt
Tools/verify.sh
```

The script runs importer/watchdog tests, macOS XCTest, a signed simulator build and unsigned iOS/macOS Release builds, writing logs into a unique `/tmp/FamilyVPN-verification.*` directory. To include iOS XCTest, supply a simulator UUID shown by `xcrun simctl list devices available`:

```sh
SIMULATOR_TEST_DEVICE_ID='<simulator UUID>' Tools/verify.sh
```

Xcode's Product → Test also runs the shared test suite for the selected supported device. Unit-test hosts disable automatic recovery and all preference mutations; Keychain tests use random test-only service names. Release builds exclude the test-host and screenshot overrides. These tests cannot verify Apple's real network transitions, provisioning consent, helper registration, CA approval, APNs delivery or native menu interactions.

## Python control dashboard

The repository-root web service adds authenticated APNs triggers and device-scoped status reports. Follow `../../README.md` for installation, private secrets, APNs provider configuration and HTTPS deployment. Enroll with the `/registrations` URL and enrollment bearer in the native administrator controls. The dashboard displays the last reported connection and policy result; APNs acceptance alone does not establish execution or connectivity.

VPN-only REST access means disconnected devices retain their last report until reconnecting. Treat the report timestamp as part of the status; historical connected reports are not live connection proof. Reconnect and repeat registration if enrollment/token rotation failed while VPN was disconnected. The web repository includes a validated NPM location generator; supply the real Home Assistant private address and VPN source subnet or NAT gateway address before applying its configuration.

## Xcode Cloud and network status

Use [XCODE_CLOUD.md](XCODE_CLOUD.md) to activate native CI/CD after publishing the Git repository. macOS now registers for APNs and handles signed commands in the app/background helper. Enable Push Notifications in the macOS App ID and refresh its signing profile; validate delivery with the helper running while the VPN is suspended. APNs is still best effort and cannot guarantee execution while the Mac is asleep or the helper is stopped.

The disconnected status now distinguishes an observed exact trusted SSID, an untrusted SSID, unavailable network, unavailable network identity, and the last system VPN disconnect error. iOS requires Access Wi-Fi Information and an eligible installed VPN configuration; macOS CoreWLAN may withhold SSID without OS privacy permission. Missing identity is explicitly shown, never assumed trusted. SSIDs remain local and are not reported to the dashboard.

## VPN endpoint setup

See the [endpoint setup guide](https://github.com/timlaing/family-vpn/blob/main/docs/VPN_ENDPOINT_SETUP.md), with MikroTik RouterOS and strongSwan settings based on the inspected IKEv2/EAP deployment. Configure your gateway and authentication backend before enrolling devices.
