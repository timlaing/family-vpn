import XCTest
#if canImport(VPNCore)
@testable import VPNCore
#else
@testable import FamilyVPN
#endif

final class EnrollmentLinkTests: XCTestCase {
    private func link(endpoint: String = "https://dashboard.example.org/family-vpn/registrations", token: String = "invite_" + String(repeating: "a", count: 43)) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: ["endpoint": endpoint, "token": token])
        return "familyvpn://enroll#" + data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    func testSetupLinkPreservesEndpointAndRequiresInvitation() throws {
        let offer = try EnrollmentLink.parse(link())
        XCTAssertEqual(offer.dashboard, "dashboard.example.org")
        XCTAssertEqual(offer.token.count, 50)
        XCTAssertThrowsError(try EnrollmentLink.parse(link(token: "reusable-dashboard-secret")))
        XCTAssertThrowsError(try EnrollmentLink.parse(link(token: "invite_" + String(repeating: "!", count: 43))))
    }
    func testRejectsUnsafeLinksAndWrongRegistrationPaths() throws {
        for endpoint in ["http://dashboard.example.org/registrations", "https://user:password@dashboard.example.org/registrations", "https://dashboard.example.org/status", "https://dashboard.example.org/registrations?token=private", "https://dashboard.example.org:8443/registrations"] {
            XCTAssertThrowsError(try EnrollmentLink.parse(link(endpoint: endpoint)))
        }
        for value in ["familyvpn://enroll#invalid", "https://example.org/", "familyvpn://enroll?anything#invalid", String(repeating: "x", count: 4097)] {
            XCTAssertThrowsError(try EnrollmentLink.parse(value))
        }
    }
}
