import XCTest
import NetworkExtension
@testable import FamilyVPN

@MainActor final class NetworkContextTests: XCTestCase {
    func testConnectionIndicatorUsesObservedSystemAndNetworkState() {
        XCTAssertEqual(NetworkContext.indicator(status: .connected, ssid: nil, trusted: [], online: true, suspended: false), .connected)
        XCTAssertEqual(NetworkContext.indicator(status: .disconnected, ssid: "Home", trusted: ["Home"], online: true, suspended: false), .trusted)
        for status in [NEVPNStatus.invalid, .connecting, .reasserting, .disconnecting] {
            XCTAssertEqual(NetworkContext.indicator(status: status, ssid: "Home", trusted: ["Home"], online: true, suspended: false), .disconnected)
        }
        XCTAssertEqual(NetworkContext.indicator(status: .disconnected, ssid: nil, trusted: ["Home"], online: true, suspended: false), .disconnected)
        XCTAssertEqual(NetworkContext.indicator(status: .disconnected, ssid: "home", trusted: ["Home"], online: true, suspended: false), .disconnected)
        XCTAssertEqual(NetworkContext.indicator(status: .disconnected, ssid: "Home", trusted: ["Home"], online: false, suspended: false), .disconnected)
        XCTAssertEqual(NetworkContext.indicator(status: .connected, ssid: "Home", trusted: ["Home"], online: true, suspended: true), .disconnected)
    }
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
