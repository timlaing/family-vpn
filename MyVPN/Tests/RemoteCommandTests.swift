import XCTest
import CryptoKit
#if canImport(VPNCore)
@testable import VPNCore
#else
@testable import MyVPN
#endif

final class RemoteCommandTests: XCTestCase {
    private let device = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    private let epoch = "cccccccc-cccc-cccc-cccc-cccccccccccc"
    private let now = Date(timeIntervalSince1970: 1100)
    private func envelope(action: String = "suspend", sequence: Int64 = 7, until: Int? = 1900, expiry: Int = 1900, key: Curve25519.Signing.PrivateKey) throws -> RemoteCommandEnvelope {
        let body: [String: Any] = ["request_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "device": device, "epoch": epoch, "sequence": sequence, "action": action, "issued_at": 1000, "expires_at": expiry, "suspend_until": until.map { $0 as Any } ?? NSNull()]
        let data = try JSONSerialization.data(withJSONObject: body)
        return RemoteCommandEnvelope(body: data.base64EncodedString(), signature: try key.signature(for: data).base64EncodedString())
    }
    func testVPNProvisioningDigestAndIndependentReplayLedger() throws {
        let key = Curve25519.Signing.PrivateKey()
        let body: [String: Any] = ["request_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "device": device, "epoch": epoch, "sequence": 7, "action": "reprovision_vpn", "issued_at": 1000, "expires_at": 1900, "vpn_digest": String(repeating: "a", count: 64)]
        let data = try JSONSerialization.data(withJSONObject: body)
        let signed = RemoteCommandEnvelope(body: data.base64EncodedString(), signature: try key.signature(for: data).base64EncodedString())
        let command = try RemoteCommand.verify(signed, key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: now)
        XCTAssertEqual(command.action, .reprovisionVPN)
        var ledger = RemoteCommandLedger(highWater: 100)
        XCTAssertTrue(ledger.accepts(command))
        ledger.record(command, success: true)
        XCTAssertFalse(ledger.accepts(command))
        XCTAssertEqual(ledger.highWater, 100)
    }
    func testPythonSignatureInteroperabilityAndPolicyPreservation() throws {
        let key = Data(base64Encoded: "8nJYdcpV128yFYsBHzN9wlFQOmCeIB8b6xz5KeLFg4g=")!
        let envelope = RemoteCommandEnvelope(body: "eyJhY3Rpb24iOiJzdXNwZW5kIiwiZGV2aWNlIjoiYmJiYmJiYmItYmJiYi1iYmJiLWJiYmItYmJiYmJiYmJiYmJiIiwiZXBvY2giOiJjY2NjY2NjYy1jY2NjLWNjY2MtY2NjYy1jY2NjY2NjY2NjY2MiLCJleHBpcmVzX2F0IjoxOTAwLCJpc3N1ZWRfYXQiOjEwMDAsInJlcXVlc3RfaWQiOiJhYWFhYWFhYS1hYWFhLWFhYWEtYWFhYS1hYWFhYWFhYWFhYWEiLCJzZXF1ZW5jZSI6Nywic3VzcGVuZF91bnRpbCI6MTkwMH0=", signature: "y/AaqxUMPuXNnCEDlk93q2fV8tk6maHkmPzHFk3s4ncFdcirJfqI/P9qyKgPsKKjq0uZ4MJgTHEPivJ1dmEiDA==")
        let command = try RemoteCommand.verify(envelope, key: key, device: device, epoch: epoch, now: now)
        let original = LocalPolicy(trustedSSIDs: ["Home"], installed: true)
        let next = try command.applying(to: original)
        XCTAssertEqual(next.trustedSSIDs, original.trustedSSIDs)
        XCTAssertTrue(next.installed)
        XCTAssertEqual(next.suspension?.expiry, Date(timeIntervalSince1970: 1900))
    }
    func testSignatureScopeExpiryAndTamperingRejected() throws {
        let key = Curve25519.Signing.PrivateKey()
        let signed = try envelope(key: key)
        XCTAssertThrowsError(try RemoteCommand.verify(signed, key: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation, device: device, epoch: epoch, now: now))
        XCTAssertThrowsError(try RemoteCommand.verify(signed, key: key.publicKey.rawRepresentation, device: "other", epoch: epoch, now: now))
        XCTAssertThrowsError(try RemoteCommand.verify(signed, key: key.publicKey.rawRepresentation, device: device, epoch: "other", now: now))
        XCTAssertThrowsError(try RemoteCommand.verify(signed, key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: Date(timeIntervalSince1970: 1900)))
        let altered = RemoteCommandEnvelope(body: Data("{}".utf8).base64EncodedString(), signature: signed.signature)
        XCTAssertThrowsError(try RemoteCommand.verify(altered, key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: now))
    }
    func testUnsupportedActionsParametersAndExcessiveLifetimesRejected() throws {
        let key = Curve25519.Signing.PrivateKey()
        for signed in [try envelope(action: "remove_vpn", key: key), try envelope(action: "enable", until: 1900, key: key), try envelope(until: 1001, key: key), try envelope(expiry: 200000, key: key), try envelope(sequence: 0, key: key)] {
            XCTAssertThrowsError(try RemoteCommand.verify(signed, key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: now))
        }
    }
    func testEnableAndRefreshRespectLocalTrustPolicy() throws {
        let key = Curve25519.Signing.PrivateKey()
        let suspended = LocalPolicy(trustedSSIDs: ["Home"], suspension: SuspensionPolicy(created: now, expiry: nil), installed: true)
        let enable = try RemoteCommand.verify(envelope(action: "enable", until: nil, key: key), key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: now)
        let enabled = try enable.applying(to: suspended)
        XCTAssertNil(enabled.suspension)
        XCTAssertEqual(enabled.trustedSSIDs, suspended.trustedSSIDs)
        let refresh = try RemoteCommand.verify(envelope(action: "refresh_status", until: nil, key: key), key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: now)
        XCTAssertEqual(try refresh.applying(to: suspended), suspended)
    }
    func testDuplicateAndOutOfOrderRejectionSurvivesLedgerRoundTrip() throws {
        let key = Curve25519.Signing.PrivateKey()
        let command = try RemoteCommand.verify(envelope(key: key), key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: now)
        var ledger = RemoteCommandLedger()
        XCTAssertTrue(ledger.accepts(command))
        ledger.record(command, success: true)
        let restored = try JSONDecoder().decode(RemoteCommandLedger.self, from: JSONEncoder().encode(ledger))
        XCTAssertFalse(restored.accepts(command))
        let older = try RemoteCommand.verify(envelope(sequence: 6, key: key), key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: now)
        XCTAssertFalse(restored.accepts(older))
        XCTAssertEqual(restored.receipts.first?.result, "executed")
    }
    func testIndefiniteSuspensionAndDeferredAcknowledgementBound() throws {
        let key = Curve25519.Signing.PrivateKey()
        let command = try RemoteCommand.verify(envelope(until: nil, key: key), key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: now)
        XCTAssertNil(try command.applying(to: LocalPolicy(installed: true)).suspension?.expiry)
        var ledger = RemoteCommandLedger()
        for _ in 0..<40 { ledger.record(command, success: false) }
        XCTAssertEqual(ledger.receipts.count, 32)
        XCTAssertEqual(ledger.receipts.last?.result, "failed")
    }
    func testNewerPingDoesNotDiscardPendingPolicyChange() throws {
        let key = Curve25519.Signing.PrivateKey()
        let ping = try RemoteCommand.verify(envelope(action: "refresh_status", sequence: 9, until: nil, key: key), key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: now)
        let control = try RemoteCommand.verify(envelope(sequence: 8, key: key), key: key.publicKey.rawRepresentation, device: device, epoch: epoch, now: now)
        var ledger = RemoteCommandLedger()
        ledger.record(ping, success: true)
        XCTAssertTrue(ledger.accepts(control))
        XCTAssertFalse(ledger.accepts(ping))
        ledger.record(control, success: true)
        XCTAssertFalse(ledger.accepts(control))
    }

}
