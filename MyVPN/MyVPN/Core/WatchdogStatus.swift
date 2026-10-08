import Foundation

/// Explicit allowlist: no username, SSID, credential, suspension details or diagnostic text.
struct WatchdogStatus: Encodable {
    let id: String
    let connection: String
    let policyOK: Bool
    enum CodingKeys: String, CodingKey { case id, connection; case policyOK = "policy_ok" }
    static func endpoint(from registrationURL: URL) throws -> URL {
        guard registrationURL.scheme == "https", registrationURL.host != nil,
              registrationURL.user == nil, registrationURL.password == nil,
              registrationURL.query == nil, registrationURL.fragment == nil,
              registrationURL.lastPathComponent == "registrations" else {
            throw AppError.message("Status reporting requires an HTTPS /registrations endpoint.")
        }
        return registrationURL.deletingLastPathComponent().appendingPathComponent("status")
    }
}
