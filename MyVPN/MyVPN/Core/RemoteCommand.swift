import Foundation
import CryptoKit

struct RemoteCommandEnvelope: Codable {
    let body: String
    let signature: String
}

struct RemoteCommand: Decodable {
    enum Action: String, Decodable { case refreshStatus = "refresh_status", suspend, enable, reprovisionAdmin = "reprovision_admin", reprovisionVPN = "reprovision_vpn" }
    let requestID: String
    let device: String
    let epoch: String
    let sequence: Int64
    let action: Action
    let issuedAt: Int64
    let expiresAt: Int64
    let suspendUntil: Int64?
    let administrator: AdministratorProvision?
    let vpnDigest: String?
    enum CodingKeys: String, CodingKey {
        case requestID = "request_id", device, epoch, sequence, action
        case vpnDigest = "vpn_digest", administrator, issuedAt = "issued_at", expiresAt = "expires_at", suspendUntil = "suspend_until"
    }
    static func verify(_ envelope: RemoteCommandEnvelope, key: Data, device: String, epoch: String, now: Date = Date()) throws -> RemoteCommand {
        guard envelope.body.utf8.count <= 2048, envelope.signature.utf8.count <= 128,
              let body = Data(base64Encoded: envelope.body), let signature = Data(base64Encoded: envelope.signature),
              try Curve25519.Signing.PublicKey(rawRepresentation: key).isValidSignature(signature, for: body) else {
            throw AppError.message("Remote command signature rejected.")
        }
        let command = try JSONDecoder().decode(Self.self, from: body)
        let time = now.timeIntervalSince1970
        guard command.device == device, command.epoch == epoch,
              UUID(uuidString: command.requestID)?.uuidString.lowercased() == command.requestID,
              command.sequence > 0, command.issuedAt > 0,
              Double(command.issuedAt) <= time + 300,
              command.expiresAt > command.issuedAt,
              Double(command.expiresAt) - Double(command.issuedAt) <= 86400,
              Double(command.expiresAt) > time else { throw AppError.message("Remote command scope or expiry rejected.") }
        if command.action == .suspend {
            if let until = command.suspendUntil {
                guard until > command.issuedAt, Double(until) > time,
                      Double(until) - Double(command.issuedAt) <= 86400 else { throw AppError.message("Invalid remote suspension expiry.") }
            }
        } else if command.suspendUntil != nil { throw AppError.message("Unexpected remote suspension data.") }
        if command.action == .reprovisionAdmin {
            guard let administrator = command.administrator else { throw AppError.message("Administrator provisioning is missing.") }
            try administrator.validate()
        } else if command.administrator != nil { throw AppError.message("Unexpected administrator provisioning data.") }
        if command.action == .reprovisionVPN {
            guard let digest = command.vpnDigest, digest.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw AppError.message("Invalid VPN provisioning digest.") }
        } else if command.vpnDigest != nil { throw AppError.message("Unexpected VPN provisioning digest.") }
        return command
    }
    func applying(to policy: LocalPolicy) throws -> LocalPolicy {
        var next = policy
        switch action {
        case .refreshStatus, .reprovisionAdmin, .reprovisionVPN: break
        case .enable: next.suspension = nil
        case .suspend:
            next.suspension = SuspensionPolicy(created: Date(timeIntervalSince1970: Double(issuedAt)), expiry: suspendUntil.map { Date(timeIntervalSince1970: Double($0)) })
        }
        try next.validate()
        return next
    }
}

struct RemoteCommandReceipt: Codable {
    let requestID: String
    let result: String
    enum CodingKeys: String, CodingKey { case requestID = "request_id", result }
}
struct RemoteCommandLedger: Codable {
    var highWater: Int64 = 0
    var refreshHighWater: Int64 = 0
    var administratorHighWater: Int64?
    var vpnHighWater: Int64?
    var receipts: [RemoteCommandReceipt] = []
    func accepts(_ command: RemoteCommand) -> Bool {
        let previous: Int64
        switch command.action {
        case .reprovisionVPN: previous = vpnHighWater ?? 0
        case .reprovisionAdmin: previous = administratorHighWater ?? 0
        case .refreshStatus: previous = refreshHighWater
        case .suspend, .enable: previous = highWater
        }
        return command.sequence > previous
    }
    mutating func record(_ command: RemoteCommand, success: Bool) {
        if command.action == .reprovisionVPN { vpnHighWater = max(vpnHighWater ?? 0, command.sequence) }
        else if command.action == .reprovisionAdmin { administratorHighWater = max(administratorHighWater ?? 0, command.sequence) }
        else if command.action == .refreshStatus { refreshHighWater = max(refreshHighWater, command.sequence) }
        else { highWater = max(highWater, command.sequence) }
        receipts.append(RemoteCommandReceipt(requestID: command.requestID, result: success ? "executed" : "failed"))
        receipts = Array(receipts.suffix(32))
    }
}
