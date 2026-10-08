import XCTest
import CryptoKit
#if canImport(VPNCore)
@testable import VPNCore
#else
@testable import FamilyVPN
#endif

final class AdministratorProvisionTests: XCTestCase {
    private func fixture() -> AdministratorProvision {
        AdministratorProvision(algorithm: "pbkdf2-sha256", iterations: 600_000, salt: Data(base64Encoded: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")!, verifier: Data(base64Encoded: "X/2X92Gpi34yt3t0EczhAkmsiNKT9zxaMqPxtu6Y60Q=")!, revision: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    }
    func testPythonVerifierUnlocksAndProvisionedRecordSurvivesRecreation() throws {
        let store = CredentialStore(service: "uk.co.laingcorp.myvpn.tests." + UUID().uuidString)
        defer { try? store.delete("administrator") }
        let admin = AdminAuthenticator(store: store)
        XCTAssertFalse(try admin.hasProvisionedRecord())
        try admin.provision(fixture())
        XCTAssertTrue(try AdminAuthenticator(store: store).hasProvisionedRecord())
        try admin.verify("dashboard-test-password")
        XCTAssertThrowsError(try admin.verify("wrong-password"))
    }
    func testProvisioningSameVerifierPreservesRetryDelay() throws {
        let store = CredentialStore(service: "uk.co.laingcorp.myvpn.tests." + UUID().uuidString)
        defer { try? store.delete("administrator") }
        let admin = AdminAuthenticator(store: store)
        try admin.provision(fixture())
        for _ in 0..<3 { XCTAssertThrowsError(try admin.verify("wrong-password")) }
        try admin.provision(fixture())
        XCTAssertThrowsError(try admin.verify("dashboard-test-password"))
    }
    func testInvalidProvisionCannotOverwriteExistingAdministrator() throws {
        let store = CredentialStore(service: "uk.co.laingcorp.myvpn.tests." + UUID().uuidString)
        defer { try? store.delete("administrator") }
        let admin = AdminAuthenticator(store: store)
        try admin.provision(fixture())
        let original = try store.read("administrator")
        for value in [AdministratorProvision(algorithm: "sha256", iterations: 600_000, salt: fixture().salt, verifier: fixture().verifier, revision: fixture().revision), AdministratorProvision(algorithm: "pbkdf2-sha256", iterations: 1, salt: fixture().salt, verifier: fixture().verifier, revision: fixture().revision), AdministratorProvision(algorithm: "pbkdf2-sha256", iterations: 600_000, salt: Data(), verifier: fixture().verifier, revision: fixture().revision), AdministratorProvision(algorithm: "pbkdf2-sha256", iterations: 600_000, salt: fixture().salt, verifier: Data(), revision: "invalid")] {
            XCTAssertThrowsError(try admin.provision(value))
            XCTAssertEqual(try store.read("administrator"), original)
        }
    }
    func testLegacyRecordRequiresEnrollmentAndNewVerifierReplacesPassword() throws {
        let store = CredentialStore(service: "uk.co.laingcorp.myvpn.tests." + UUID().uuidString)
        defer { try? store.delete("administrator") }
        let admin = AdminAuthenticator(store: store)
        try admin.create("legacy-test-password", confirmation: "legacy-test-password")
        XCTAssertFalse(try admin.hasProvisionedRecord())
        try admin.provision(fixture())
        XCTAssertTrue(try admin.hasProvisionedRecord())
        XCTAssertThrowsError(try admin.verify("legacy-test-password"))
        try admin.verify("dashboard-test-password")
    }
    func testSignedReprovisionHasIndependentReplayTrackingAndPreservesPolicy() throws {
        let key = Curve25519.Signing.PrivateKey()
        func signed(sequence: Int64, administrator: AdministratorProvision?) throws -> RemoteCommand {
            var value: [String: Any] = ["request_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "device": "device", "epoch": "epoch", "sequence": sequence, "action": "reprovision_admin", "issued_at": 1000, "expires_at": 1900, "suspend_until": NSNull()]
            if let administrator { value["administrator"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(administrator)) }
            let raw = try JSONSerialization.data(withJSONObject: value)
            let envelope = RemoteCommandEnvelope(body: raw.base64EncodedString(), signature: try key.signature(for: raw).base64EncodedString())
            return try RemoteCommand.verify(envelope, key: key.publicKey.rawRepresentation, device: "device", epoch: "epoch", now: Date(timeIntervalSince1970: 1100))
        }
        let command = try signed(sequence: 8, administrator: fixture())
        let policy = LocalPolicy(trustedSSIDs: ["Home"], installed: true)
        XCTAssertEqual(try command.applying(to: policy), policy)
        var ledger = RemoteCommandLedger()
        ledger.highWater = 100
        ledger.refreshHighWater = 100
        XCTAssertTrue(ledger.accepts(command))
        ledger.record(command, success: true)
        let restored = try JSONDecoder().decode(RemoteCommandLedger.self, from: JSONEncoder().encode(ledger))
        XCTAssertFalse(restored.accepts(command))
        XCTAssertFalse(restored.accepts(try signed(sequence: 7, administrator: fixture())))
        XCTAssertThrowsError(try signed(sequence: 9, administrator: nil))
        let oldLedger = Data(#"{"highWater":7,"refreshHighWater":9,"receipts":[]}"#.utf8)
        XCTAssertTrue(try JSONDecoder().decode(RemoteCommandLedger.self, from: oldLedger).accepts(command))
    }

}
