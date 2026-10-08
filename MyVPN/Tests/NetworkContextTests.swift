import XCTest
@testable import MyVPN

@MainActor final class NetworkContextTests: XCTestCase {
    func testTrustedSSIDRequiresAnExactObservedMatch() {
        XCTAssertEqual(NetworkContext.disconnectedStatus(ssid: "Home", trusted: ["Home"], online: true, failure: nil), "Not connected on trusted Wi-Fi")
        XCTAssertEqual(NetworkContext.disconnectedStatus(ssid: "home", trusted: ["Home"], online: true, failure: nil), "Disconnected on untrusted Wi-Fi")
    }
    func testUnavailableIdentityNeverClaimsTrustedBypass() {
        XCTAssertEqual(NetworkContext.disconnectedStatus(ssid: nil, trusted: ["Home"], online: true, failure: nil), "Disconnected — network identity unavailable")
    }
    func testOfflineAndHistoricalErrorsAreDistinguished() {
        XCTAssertEqual(NetworkContext.disconnectedStatus(ssid: nil, trusted: [], online: false, failure: "Authentication"), "Disconnected — network unavailable")
        XCTAssertEqual(NetworkContext.disconnectedStatus(ssid: nil, trusted: [], online: true, failure: "Authentication"), "Disconnected — last VPN failure: Authentication")
        XCTAssertEqual(NetworkContext.disconnectedStatus(ssid: "Home", trusted: ["Home"], online: true, failure: "Old error"), "Not connected on trusted Wi-Fi")
    }
}
