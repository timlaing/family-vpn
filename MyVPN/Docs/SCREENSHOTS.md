> Native screenshots below are historical previews from before dashboard-owned administrator setup. The 0.3.0 setup flow is documented in [ADMINISTRATION.md](ADMINISTRATION.md). The current dashboard preview is saved in the Documents deployment artifacts.

# Application screenshots — 7 October 2026

Captured iPhone 17 Pro Max / iOS 26.5 and macOS app views: setup, dashboard, VPN credentials, administrator password challenge, trusted Wi-Fi, suspension controls, platform monitoring and maintenance, and the suspended dashboard.

The source PNGs, side-by-side `gallery.html` and portable `Family-VPN-screenshots.zip` are saved locally under `Documents/ChatGPT/iOS-VPN/Screenshots/2026-10-07`.

The screenshots are real native SwiftUI renders with clearly labelled read-only sample states. They do not demonstrate a real connected VPN, completed authentication, policy validation, successful suspension, or enabled monitoring. The long administrator page is split into network/suspension and security/maintenance sections for screenshot coverage. Lower iPhone sections are captured at explicit scroll positions.

Debug launches accept `--screenshot-page` followed by `setup`, `setup-bottom`, `dashboard`, `credentials`, `admin-gate`, `administrator`, `administrator-bottom`, `admin-security`, `admin-security-bottom`, or `suspended`. Screenshot initialization does not read persisted policy or credentials, create observers or start recovery. Preference mutations reject screenshot sessions; screenshot action handlers do not authenticate or submit changes. Remote registration and refresh scheduling are skipped. The option is disabled in Release builds. macOS captures used a separate preview app bundle identity.

Validation: signed iOS simulator build passed, nine macOS XCTest tests passed, and a generic iOS Release build passed with fixture state overrides excluded. The previous simulator and physical-device coverage limits remain unchanged.

## Updated styling

The shared SwiftUI design now uses adaptive grouped cards, rounded headings, a navy/teal header, scalable shield artwork and subtle background graphics. macOS starts at 460 × 860 points with a 400–540-point width range; iOS uses compact navigation titles to preserve form space. All editors use the same design, with light/dark appearance selected by the system. Decorative artwork is hidden from accessibility and makes no connection-state claim.

Updated previews are in `Documents/ChatGPT/iOS-VPN/Screenshots/Restyled/gallery.html`. Signed iOS simulator and macOS builds passed. Dashboard layouts were visually inspected on iPhone 17 Pro Max, iPad Pro 13-inch and macOS; setup and administrator layouts were also inspected on macOS. These remain sample-state captures, not VPN connection tests.

Portrait macOS follow-up: compact vector artwork, 15-point form text and content-based window resizing now preserve a narrow, stacked layout. The macOS build passed. A fresh preview was launched, but screenshot capture was unavailable because Computer Use did not approve access to the application. Visual verification of this follow-up remains outstanding.

Network artwork follow-up: a shared SwiftUI Canvas draws a globe grid, curved routes and mint nodes in page headers, with a faint continuation behind the cards. A horizontal fade preserves text readability. The illustration is static, ignores pointer input and is hidden from accessibility; it represents no real endpoint geography or live VPN state. macOS and signed iOS simulator builds passed.
