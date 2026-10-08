import XCTest
import NetworkExtension
#if canImport(VPNCore)
@testable import VPNCore
#else
@testable import MyVPN
#endif

final class PolicyTests: XCTestCase {
    func testOrderedRulesAndEmptyTrustList() {
        let rules = VPNPolicyEngine.rules(trustedSSIDs: ["Home", "Office"])
        XCTAssertEqual(rules.count, 2)
        XCTAssertTrue(rules[0] is NEOnDemandRuleDisconnect)
        XCTAssertEqual(rules[0].interfaceTypeMatch, .wiFi)
        XCTAssertEqual(rules[0].ssidMatch, ["Home", "Office"])
        XCTAssertTrue(rules[1] is NEOnDemandRuleConnect)
        XCTAssertEqual(rules[1].interfaceTypeMatch, .any)
        let empty = VPNPolicyEngine.rules(trustedSSIDs: [])
        XCTAssertEqual(empty.count, 1)
        XCTAssertTrue(empty[0] is NEOnDemandRuleConnect)
    }
    func testEnforcementAcrossSuspensionStates() {
        let now = Date()
        XCTAssertTrue(VPNPolicyEngine.onDemandEnabled(policy: LocalPolicy(), at: now))
        XCTAssertFalse(VPNPolicyEngine.onDemandEnabled(policy: LocalPolicy(suspension: SuspensionPolicy(created: now, expiry: nil)), at: now))
        XCTAssertFalse(VPNPolicyEngine.onDemandEnabled(policy: LocalPolicy(suspension: SuspensionPolicy(created: now, expiry: now.addingTimeInterval(900))), at: now))
        XCTAssertTrue(VPNPolicyEngine.onDemandEnabled(policy: LocalPolicy(suspension: SuspensionPolicy(created: now.addingTimeInterval(-1000), expiry: now)), at: now))
    }
    func testExactSSIDNormalization() throws {
        XCTAssertEqual(try LocalPolicy.normalize([" Home ", "home"]), ["Home", "home"])
        XCTAssertThrowsError(try LocalPolicy.normalize([" Home", "Home "]))
        XCTAssertThrowsError(try LocalPolicy.normalize(["   "]))
        XCTAssertThrowsError(try LocalPolicy.normalize([String(repeating: "é", count: 17)]))
    }
    func testSuspensionBoundaryAndClockChanges() throws {
        let start = Date(timeIntervalSince1970: 1000)
        let end = start.addingTimeInterval(900)
        let timed = SuspensionPolicy(created: start, expiry: end)
        try timed.validate()
        XCTAssertTrue(timed.active(at: start))
        XCTAssertTrue(timed.active(at: start.addingTimeInterval(-100)))
        XCTAssertFalse(timed.active(at: end))
        XCTAssertFalse(timed.active(at: end.addingTimeInterval(1000)))
        XCTAssertTrue(SuspensionPolicy(created: start, expiry: nil).active(at: .distantFuture))
        XCTAssertThrowsError(try SuspensionPolicy(created: start, expiry: start).validate())
    }
    func testPersistedPolicyValidation() throws {
        let policy = LocalPolicy(trustedSSIDs: ["Home"], suspension: SuspensionPolicy(created: Date(), expiry: nil), installed: true)
        let copy = try JSONDecoder().decode(LocalPolicy.self, from: JSONEncoder().encode(policy))
        XCTAssertEqual(policy, copy)
        XCTAssertThrowsError(try LocalPolicy(trustedSSIDs: [" Home "]).validate())
    }
    private func bundledConfiguration() throws -> VPNConfiguration {
        #if canImport(VPNCore)
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        return try JSONDecoder().decode(VPNConfiguration.self, from: Data(contentsOf: root.appendingPathComponent("MyVPN/Resources/VPNConfiguration.json")))
        #else
        return try VPNConfiguration.load()
        #endif
    }
    func testDashboardProvisioningValidation() throws {
        let configuration = try VPNProvision(server: "vpn.example.org", remoteIdentifier: "vpn.example.org", trustedSSIDs: ["Home"], revision: UUID().uuidString).configuration()
        XCTAssertEqual(configuration.server, "vpn.example.org")
        XCTAssertEqual(configuration.defaultTrustedSSIDs, ["Home"])
        XCTAssertNil(configuration.rootCertificateResource)
        for host in ["https://vpn.example.org", "a..org", "gateway.invalid", "vpn.example.org:443"] {
            XCTAssertThrowsError(try VPNProvision(server: host, remoteIdentifier: host, trustedSSIDs: [], revision: UUID().uuidString).configuration())
        }
    }
    func testImportedProfileProtocolSettings() throws {
        var configuration = try bundledConfiguration()
        XCTAssertThrowsError(try configuration.validate())
        configuration.server = "vpn.example.org"
        configuration.remoteIdentifier = "vpn.example.org"
        try configuration.validate()
        let proto = try configuration.makeProtocol(username: "test-only", reference: Data([1, 2, 3]))
        XCTAssertEqual(proto.authenticationMethod, .certificate)
        XCTAssertTrue(proto.useExtendedAuthentication)
        XCTAssertEqual(proto.deadPeerDetectionRate, .high)
        XCTAssertTrue(proto.useConfigurationAttributeInternalIPSubnet)
        XCTAssertFalse(proto.disableMOBIKE)
        XCTAssertFalse(proto.disableRedirect)
        XCTAssertFalse(proto.enableRevocationCheck)
        XCTAssertTrue(proto.enablePFS)
        XCTAssertNil(proto.serverCertificateIssuerCommonName)
        XCTAssertNil(proto.serverCertificateCommonName)
        XCTAssertNil(proto.proxySettings)
        XCTAssertEqual(proto.ikeSecurityAssociationParameters.encryptionAlgorithm, .algorithmAES256)
        XCTAssertEqual(proto.ikeSecurityAssociationParameters.integrityAlgorithm, .SHA256)
        XCTAssertEqual(proto.ikeSecurityAssociationParameters.lifetimeMinutes, 1440)
        XCTAssertEqual(proto.childSecurityAssociationParameters.encryptionAlgorithm, .algorithmAES256GCM)
        XCTAssertEqual(proto.childSecurityAssociationParameters.integrityAlgorithm, .SHA512)
        XCTAssertEqual(proto.childSecurityAssociationParameters.lifetimeMinutes, 120)
        XCTAssertNil(configuration.mtu)
        XCTAssertEqual(proto.mtu, NEVPNProtocolIKEv2().mtu)
        XCTAssertEqual(configuration.defaultTrustedSSIDs, [])
        XCTAssertNil(configuration.rootCertificateResource)
    }
    func testPlaceholderCannotInstall() throws {
        var values = try JSONSerialization.jsonObject(with: JSONEncoder().encode(bundledConfiguration())) as! [String: Any]
        values["server"] = "configuration-required.invalid"
        let placeholder = try JSONDecoder().decode(VPNConfiguration.self, from: JSONSerialization.data(withJSONObject: values))
        XCTAssertThrowsError(try placeholder.validate())
    }
    func testKeychainReplacementAndRollback() throws {
        let store = CredentialStore(service: "uk.co.laingcorp.myvpn.tests." + UUID().uuidString)
        defer { try? store.delete("vpn") }
        let old = try store.put("vpn", data: Data("old-value".utf8))
        let replacement = try store.put("vpn", data: Data("new-value".utf8))
        XCTAssertEqual(old, replacement)
        XCTAssertEqual(try store.read("vpn"), Data("new-value".utf8))
        try store.put("vpn", data: Data("old-value".utf8))
        XCTAssertEqual(try store.read("vpn"), Data("old-value".utf8))
        try store.delete("vpn")
        XCTAssertNil(try store.read("vpn"))
    }
    func testAdministratorThrottleSurvivesRecreation() throws {
        let store = CredentialStore(service: "uk.co.laingcorp.myvpn.tests." + UUID().uuidString)
        defer { try? store.delete("administrator") }
        let admin = AdminAuthenticator(store: store)
        XCTAssertThrowsError(try admin.create("short", confirmation: "short"))
        try admin.create("long-test-password", confirmation: "long-test-password")
        try admin.verify("long-test-password")
        for _ in 0..<3 { XCTAssertThrowsError(try admin.verify("wrong")) }
        XCTAssertThrowsError(try AdminAuthenticator(store: store).verify("long-test-password"))
    }
    func testAdministratorRetryBoundaryPasswordChangeAndCorruptRecord() throws {
        let store = CredentialStore(service: "uk.co.laingcorp.myvpn.tests." + UUID().uuidString)
        defer { try? store.delete("administrator") }
        let admin = AdminAuthenticator(store: store)
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        try admin.create("original-test-password", confirmation: "original-test-password")
        for _ in 0..<3 { XCTAssertThrowsError(try admin.verify("wrong", at: now)) }
        XCTAssertThrowsError(try admin.verify("original-test-password", at: now.addingTimeInterval(4)))
        try admin.verify("original-test-password", at: now.addingTimeInterval(5))
        try admin.create("replacement-test-password", confirmation: "replacement-test-password")
        XCTAssertThrowsError(try admin.verify("original-test-password", at: now))
        try admin.verify("replacement-test-password", at: now)
        var record = try JSONDecoder().decode(AdminAuthenticator.Record.self, from: XCTUnwrap(store.read("administrator")))
        record.failures = Int.max
        try store.put("administrator", data: JSONEncoder().encode(record))
        XCTAssertThrowsError(try admin.verify("replacement-test-password", at: now))
    }
    func testInvalidAssociationLifetimeCannotOverflowNativeProtocol() throws {
        var values = try JSONSerialization.jsonObject(with: JSONEncoder().encode(bundledConfiguration())) as! [String: Any]
        var association = values["ike"] as! [String: Any]
        association["lifetimeMinutes"] = Int(Int32.max) + 1
        values["ike"] = association
        let invalid = try JSONDecoder().decode(VPNConfiguration.self, from: JSONSerialization.data(withJSONObject: values))
        XCTAssertThrowsError(try invalid.makeProtocol(username: "test", reference: Data([1])))
    }
    func testSuspensionDatesMustBeFiniteAndSSIDByteBoundary() throws {
        XCTAssertThrowsError(try SuspensionPolicy(created: Date(timeIntervalSince1970: .infinity), expiry: nil).validate())
        XCTAssertThrowsError(try SuspensionPolicy(created: Date(), expiry: Date(timeIntervalSince1970: .nan)).validate())
        XCTAssertEqual(try LocalPolicy.normalize([String(repeating: "é", count: 16)]).count, 1)
        XCTAssertEqual(try LocalPolicy.normalize([]), [])
    }

    func testCompetingVPNIsNeverOwnedByThisApplication() {
        let owner = "Family VPN"
        XCTAssertTrue(VPNPolicyEngine.mayModify(hasProtocol: false, description: nil, owner: owner))
        XCTAssertTrue(VPNPolicyEngine.mayModify(hasProtocol: true, description: owner, owner: owner))
        XCTAssertFalse(VPNPolicyEngine.mayModify(hasProtocol: true, description: "Other VPN", owner: owner))
        XCTAssertFalse(VPNPolicyEngine.mayModify(hasProtocol: true, description: nil, owner: owner))
    }

    func testTomorrowUsesLocalMidnightAcrossDSTAndTimezoneChanges() throws {
        var london = Calendar(identifier: .gregorian)
        london.timeZone = try XCTUnwrap(TimeZone(identifier: "Europe/London"))
        let start = try XCTUnwrap(london.date(from: DateComponents(year: 2026, month: 3, day: 29, hour: 0)))
        let expiry = try SuspensionPolicy.tomorrow(at: start, calendar: london)
        XCTAssertEqual(expiry.timeIntervalSince(start), 23 * 3600)
        XCTAssertEqual(london.component(.hour, from: expiry), 0)
        var losAngeles = london
        losAngeles.timeZone = try XCTUnwrap(TimeZone(identifier: "America/Los_Angeles"))
        XCTAssertNotEqual(try SuspensionPolicy.tomorrow(at: start, calendar: losAngeles), expiry)
        let record = SuspensionPolicy(created: start, expiry: expiry)
        let restored = try JSONDecoder().decode(SuspensionPolicy.self, from: JSONEncoder().encode(record))
        XCTAssertEqual(restored.expiry, expiry)
        XCTAssertTrue(restored.active(at: expiry.addingTimeInterval(-1)))
        XCTAssertFalse(restored.active(at: expiry))
    }

    func testStatusPayloadContainsOnlyApprovedOperationalFields() throws {
        let payload = WatchdogStatus(id: "test-installation", connection: "connected", policyOK: false)
        let values = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(payload)) as? [String: Any])
        XCTAssertEqual(Set(values.keys), ["id", "connection", "policy_ok"])
        XCTAssertEqual(values["policy_ok"] as? Bool, false)
    }
    func testStatusEndpointRemainsOnRegistrationOriginAndRejectsUnsafeURLs() throws {
        XCTAssertEqual(try WatchdogStatus.endpoint(from: XCTUnwrap(URL(string: "https://example.com/vpn/registrations"))).absoluteString, "https://example.com/vpn/status")
        for value in ["http://example.com/registrations", "https://user:password@example.com/registrations", "https://example.com/registrations?redirect=other", "https://example.com/arbitrary"] {
            XCTAssertThrowsError(try WatchdogStatus.endpoint(from: XCTUnwrap(URL(string: value))))
        }
    }

}
