# Simulator smoke tests — 7 October 2026

## Results

| Simulator | Runtime | Install | Launch | Setup screenshot |
| --- | --- | --- | --- | --- |
| iPhone 17 Pro | iOS 26.5 | Passed | Passed | Reviewed |
| iPhone 18 Pro | iOS 27.0 | Passed | Passed | Reviewed |
| iPad Pro 13-inch (M5) | iOS 27.0 | Passed | Passed | Reviewed |

The ad hoc signed simulator build renders the server identity, first-run fields, best-effort protection explanation, and both bundled trusted SSIDs. The iPad screenshot also shows the CA prerequisite, export action and install action without layout clipping. No credentials were entered and no VPN configuration, CA trust or watchdog enrollment was installed.

Screenshot artifacts are saved locally under `Documents/ChatGPT/iOS-VPN/SimulatorTesting/2026-10-07` as `iPhone-iOS26.png`, `iPhone-iOS27.png`, and `iPad-iOS27.png`.

## Bugs found and corrected

The desktop monitor copy phase placed a macOS `Contents/Library/LaunchAgents` directory inside the iOS app. CoreSimulator then failed to discover the iOS bundle identifier, reporting `IXErrorDomain code 13: Missing bundle ID`, despite a valid root Info.plist. Replaced that copy phase with a declared-input/output build phase that copies the monitor only when `PLATFORM_NAME` is `macosx`. A clean simulator build has no `Contents` directory or embedded desktop monitor. Actual installation succeeds on both iOS runtime versions. The macOS bundle still contains its monitor at the expected path.

Unsigned simulator launch also exposed that a Keychain-read failure occurred before the app seeded trusted-network defaults. Initialization now loads bundled defaults before reading the persisted override. The final signed simulator screenshots display both trusted networks correctly.

## Reproduce

```sh
xcodebuild -project MyVPN.xcodeproj -scheme MyVPN \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath /tmp/MyVPN-simulator \
  CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- build

xcrun simctl boot <device-uuid>
xcrun simctl bootstatus <device-uuid> -b
xcrun simctl install <device-uuid> Build/Products/Debug-iphonesimulator/MyVPN.app
xcrun simctl launch <device-uuid> uk.co.laingcorp.myvpn
xcrun simctl io <device-uuid> screenshot /tmp/MyVPN-setup.png
```

If an earlier build contains the incorrectly embedded macOS folder, perform a clean build before installation. Inspect screenshots after the launch animation settles.

## Coverage limits

These are build, installation, launch and visual setup smoke tests, not a full interactive UI suite. The Simulator GUI application is absent from this tool environment, so tests use CoreSimulator CLI launch and screenshots. Credential entry, administrator screens, CA export interaction, suspension controls, system installation consent and end-to-end Keychain transactions were not exercised through the simulator UI. The existing nine XCTest unit tests passed on macOS after the fixes; they were not run as iOS simulator unit tests.

Real IKEv2 authentication, server certificate trust, On Demand network transitions, background push delivery, expiry during suspension/force-quit, and system policy repair remain physical-device acceptance tests. Simulator launch does not establish those behaviors.

## Expanded unit coverage

The shared XCTest target now supports macOS, iOS and iPadOS. All 22 Swift tests passed on iPhone 17 Pro Max / iOS 26.5 and iPad Pro 13-inch (M5) / iOS 27.0, including isolated Keychain insertion/replacement/deletion and administrator authentication/throttling tests. Test-host recovery and preference mutations are disabled through a Debug-only scheme environment flag. Release builds exclude this flag and screenshot overrides. These are native unit tests, not interactive UI or real VPN integration tests; the earlier coverage limits still apply to those behaviours.

Use Product → Test in Xcode with the selected simulator, or `Tools/verify.sh` with `SIMULATOR_TEST_DEVICE_ID`. The reproducible workflow also builds both platforms in Release configuration. See NEXT_STEPS.md for physical acceptance and distribution instructions.
