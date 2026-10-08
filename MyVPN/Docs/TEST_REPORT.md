# Verification report — current update 8 October 2026

The initial table records earlier platform runs; current provisioning verification appears below.

| Check | Result |
| --- | --- |
| macOS 27.0.1 XCTest | 22 tests passed, zero failures |
| iPhone 17 Pro Max / iOS 26.5 XCTest | 22 tests passed, zero failures |
| iPad Pro 13-inch (M5) / iOS 27.0 XCTest | 22 tests passed, zero failures |
| Signed iOS simulator build | Passed (ad hoc local signing, not distribution provisioning) |
| iOS Release build | Passed, Apple signing disabled |
| macOS Release build | Passed, Apple signing disabled |
| Profile importer | 4 tests passed, including source-to-bundle equivalence |
| Watchdog | 6 tests passed, local HTTP and synthetic APNs responses |
| Desktop test/preview processes | None left running |

Initial run logs: `/tmp/FamilyVPN-verification.6xHzDB`. Separate iPad unit log: `/tmp/MyVPN-ipad-unit.log`. Logs are local temporary evidence and may be removed by system cleanup. Reproduce with Tools/verify.sh; it prints a fresh evidence directory for each run. Native VPN state is not modified by the unit-test host. Keychain tests create and delete isolated random test-only service records.

## What the tests establish

- Ordered Wi-Fi disconnect/catch-all connect rules, exact SSID normalization and UTF-8 limits.
- Fixed protocol import and placeholders/overflow rejection.
- Suspension expiry boundaries, backward/forward clock evaluation, indefinite suspension, invalid-date rejection and local-midnight calculation across DST/time-zone changes.
- Administrator verifier, password replacement, persistent retry delay, exact retry boundary and corrupt-record rejection.
- Isolated Keychain insertion, persistent reference stability, replacement, restoration and deletion.
- Preference queue ordering across awaits, queued cancellation and continued operation after failure.
- Recovery coalescing, cancellation and retry after failure; background completion is single-use.
- Synthetic transaction failures after credential/protocol/metadata stages and explicit rollback failure.
- Competing-owner decisions prevent claiming another Personal VPN.
- Watchdog registration authentication, payload limits, variable-length tokens, token rotation and invalid-token pruning without losing a newly rotated token.
- APNs headers/payload, continuation after a network error and tolerance of a malformed service response.

## What remains unverified

Synthetic transaction tests verify the shared rollback control flow, not actual NEVPNManager save/readback failures on an entitled device. Real preference snapshots, authentication prompts, consent denial, CA trust, server authentication, traffic routing, On Demand transitions, notifications, background scheduling, physical clock/time-zone transitions and macOS helper registration/update/removal require the checklist in NEXT_STEPS.md.

No actual APNs provider key was read; delivery tests use a synthetic JWT and mock HTTP responses. No watchdog was deployed. No Apple Distribution or Developer ID signing identity was found locally, so export, notarization and physical-device provisioning are pending. Native menu interaction was not exercised through Computer Use. GPG commit signatures do not provide Apple application signing.

The app must not be treated as non-bypassable parental enforcement. Unsupervised device owners can remove the app/configuration or prevent recovery execution.

## Current dashboard provisioning verification — 8 October 2026

- Native macOS and iPhone 17 Pro Max simulator: 36 XCTest cases each passed, zero failures. Logs: `/tmp/FamilyVPN-verification.kHTrw1`.
- Native importer (4 tests), legacy watchdog (6 tests), simulator build and unsigned iOS/macOS release builds passed.
- VPNWeb: 44 tests passed on Python 3.12, 3.13 and 3.14, including verifier interoperability, dashboard-only setup, registration migration, command snapshots, independent replay/supersession and protected/public route boundaries.
- Standalone and Home Assistant Docker builds and smoke tests passed. Synthetic Supervisor/NPM tests exercise password setup through prefixed Ingress and verifier retrieval through registration-LAN enrollment.
- Workflows pass actionlint; patch whitespace checks pass. Local synthetic results do not establish live GitHub Actions execution, APNs delivery or entitled VPN behavior.

Administrator reprovisioning must still be validated on enrolled physical iOS/iPadOS devices, including background delivery while VPN is suspended. At the 0.3.0 baseline macOS had REST polling only; the subsequent gap implementation adds macOS APNs registration and command handling, which still requires signed-device delivery verification. Actual password setup, device authentication prompts, NPM deployment and Home Assistant installation are user deployment steps.

## Gap implementation verification — 8 October 2026

- 39 XCTest cases passed with zero failures on macOS, iPhone 17 Pro Max (iOS 26.5 simulator), and iPad Pro 13-inch M5 (iOS 27 simulator).
- New classification tests cover exact trusted SSID matching, unavailable identity, offline networks, and historical disconnect errors.
- Unsigned iOS and macOS Release compilation passed; signed APNs delivery and privacy-controlled SSID access remain physical-device checks.
- Six legacy watchdog tests passed using the prepared dependency environment.
- Xcode Cloud post-clone hook passed all four importer tests locally. Cloud workflows cannot be activated until a hosted repository and Apple account authorization exist.
- Release script syntax validated. Actual archive/export/notarization requires signing assets and a configured notary credential profile and has not been performed.

Evidence: `/tmp/FamilyVPN-gap-mac.log`, `/tmp/FamilyVPN-gap-ios.log`, `/tmp/FamilyVPN-gap-ipad.log`, `/tmp/FamilyVPN-gap-release.log`.
