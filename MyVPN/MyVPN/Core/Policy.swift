import Foundation
import Network
import Security

struct VPNConfiguration: Codable {
    var provisionRevision: String?
    var caCertificate: String?
    let authenticationMethod: String
    let useExtendedAuthentication: Bool
    let deadPeerDetectionRate: Int
    let disableRedirect: Bool
    let enableRevocationCheck: Bool
    let useConfigurationAttributeInternalIPSubnet: Bool
    var defaultTrustedSSIDs: [String]
    var rootCertificateResource: String?
    var server: String
    var remoteIdentifier: String
    var localIdentifier: String
    let certificateCommonName: String
    var certificateIssuerCommonName: String
    let disconnectOnSleep: Bool
    let disableMOBIKE: Bool
    let enablePFS: Bool
    let includeAllNetworks: Bool
    let mtu: Int?
    let ike: SecurityAssociation
    let child: SecurityAssociation
    struct SecurityAssociation: Codable {
        let encryption: Int
        let integrity: Int
        let diffieHellman: Int
        let lifetimeMinutes: Int
    }
    func validate() throws {
        guard ["None", "Certificate"].contains(authenticationMethod), useExtendedAuthentication,
              (0...3).contains(deadPeerDetectionRate),
              try LocalPolicy.normalize(defaultTrustedSSIDs) == defaultTrustedSSIDs,
              rootCertificateResource == nil || rootCertificateResource == "VPNRootCA",
              !server.isEmpty, !server.hasSuffix(".invalid"), !remoteIdentifier.isEmpty,
              mtu.map({ (1280...1500).contains($0) }) ?? true,
              [ike, child].allSatisfy({ [3, 4, 5, 6, 7].contains($0.encryption) && [3, 4, 5].contains($0.integrity) && [14, 15, 16, 17, 18, 19, 20, 21, 31, 32].contains($0.diffieHellman) && $0.lifetimeMinutes > 0 && $0.lifetimeMinutes <= Int(Int32.max) }) else {
            throw AppError.message("Supply and validate the real sanitized VPN configuration before installation.")
        }
    }
    static func load() throws -> Self {
        guard let url = Bundle.main.url(forResource: "VPNConfiguration", withExtension: "json") else { throw AppError.message("Bundled VPN configuration is missing.") }
        if let cached = try CredentialStore().read("vpn-provision") { return try JSONDecoder().decode(Self.self, from: cached) }
        return try JSONDecoder().decode(Self.self, from: Data(contentsOf: url))
    }
}
enum AppError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case let .message(text) = self { return text }; return nil }
}
struct SuspensionPolicy: Codable, Equatable {
    let created: Date
    let expiry: Date?
    static func tomorrow(at date: Date = Date(), calendar: Calendar = .current) throws -> Date {
        guard date.timeIntervalSince1970.isFinite, let next = calendar.date(byAdding: .day, value: 1, to: date) else {
            throw AppError.message("Cannot determine tomorrow’s suspension expiry.")
        }
        return calendar.startOfDay(for: next)
    }
    var isActive: Bool { active(at: Date()) }
    func active(at date: Date) -> Bool { expiry.map { date < $0 } ?? true }
    func validate() throws {
        guard created.timeIntervalSince1970.isFinite, expiry?.timeIntervalSince1970.isFinite ?? true else { throw AppError.message("Invalid suspension date.") }
        if let expiry, expiry <= created { throw AppError.message("Suspension expiry must follow its creation.") }
    }
}
struct LocalPolicy: Codable, Equatable {
    var provisionRevision: String?
    var trustedSSIDs: [String] = []
    var suspension: SuspensionPolicy?
    var installed = false
    static func normalize(_ entries: [String]) throws -> [String] {
        let values = entries.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 32 }), Set(values).count == values.count else {
            throw AppError.message("SSID values must be unique, nonempty, and at most 32 UTF-8 bytes.")
        }
        return values
    }
    func validate() throws {
        guard try Self.normalize(trustedSSIDs) == trustedSSIDs else { throw AppError.message("Invalid stored trusted networks.") }
        try suspension?.validate()
    }
}

struct VPNProvision: Decodable {
    let server: String
    let remoteIdentifier: String
    let trustedSSIDs: [String]
    let revision: String
    let caCertificate: String?
    init(server: String, remoteIdentifier: String, trustedSSIDs: [String], revision: String, caCertificate: String? = nil) {
        self.server = server; self.remoteIdentifier = remoteIdentifier; self.trustedSSIDs = trustedSSIDs; self.revision = revision; self.caCertificate = caCertificate
    }
    func configuration() throws -> VPNConfiguration {
        func validHost(_ host: String) -> Bool {
            guard !host.isEmpty, host.utf8.count <= 253, !host.hasSuffix(".invalid") else { return false }
            return IPv6Address(host) != nil || host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
                label.range(of: "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", options: .regularExpression) != nil
            }
        }
        guard validHost(server), validHost(remoteIdentifier), UUID(uuidString: revision) != nil,
              trustedSSIDs.count <= 32, try LocalPolicy.normalize(trustedSSIDs) == trustedSSIDs else { throw AppError.message("Invalid dashboard VPN provisioning.") }
        var config = try VPNConfiguration.load()
        config.server = server; config.remoteIdentifier = remoteIdentifier
        config.localIdentifier = ""; config.certificateIssuerCommonName = ""
        config.defaultTrustedSSIDs = trustedSSIDs; config.rootCertificateResource = nil
        config.provisionRevision = revision
        if let caCertificate {
            guard let data = Data(base64Encoded: caCertificate), data.count <= 12288, SecCertificateCreateWithData(nil, data as CFData) != nil else { throw AppError.message("Invalid provisioned CA certificate.") }
        }
        config.caCertificate = caCertificate
        try config.validate()
        return config
    }
}
