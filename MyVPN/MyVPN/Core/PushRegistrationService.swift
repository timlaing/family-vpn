import Foundation

private final class RegistrationSessionDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        // Enrollment credentials must never be forwarded to a redirect target.
        completionHandler(nil)
    }
}

@MainActor enum PushRegistrationService {
    static let store = CredentialStore()
    static func configure(endpoint: String, secret: String) throws {
        guard let url = URL(string: endpoint), url.scheme == "https", url.host != nil, url.user == nil, url.password == nil, url.query == nil, url.fragment == nil, secret.count >= 32 else { throw AppError.message("Use an HTTPS registration URL and a strong enrollment secret.") }
        _ = try WatchdogStatus.endpoint(from: url)
        // A changed deployment must never receive the old server's device credential.
        let previousEndpoint = try store.read("watchdog-endpoint")
        if previousEndpoint != Data(endpoint.utf8) {
            for name in ["watchdog-status-secret", "watchdog-command-key", "watchdog-command-epoch", "watchdog-command-ledger", "watchdog-registered-token", "vpn-provision"] { try store.delete(name) }
        }
        try store.put("watchdog-endpoint", data: Data(endpoint.utf8))
        try store.put("watchdog-secret", data: Data(secret.utf8))
        if try store.read("watchdog-id") == nil { try store.put("watchdog-id", data: Data(UUID().uuidString.lowercased().utf8)) }
    }
    static func enroll(endpoint: String, secret: String) async throws {
        let accounts = ["watchdog-endpoint", "watchdog-secret", "watchdog-id", "watchdog-status-secret", "watchdog-command-key", "watchdog-command-epoch", "watchdog-command-ledger", "watchdog-registered-token", "administrator", "vpn-provision"]
        var previous: [String: Data] = [:]
        for account in accounts { if let value = try store.read(account) { previous[account] = value } }
        do { try configure(endpoint: endpoint, secret: secret); try await register() }
        catch {
            let original = error
            do {
                for account in accounts {
                    if let value = previous[account] { try store.put(account, data: value) }
                    else { try store.delete(account) }
                }
            } catch { throw AppError.message("Enrollment rollback failed. Register this device again before using remote controls.") }
            throw original
        }
    }
    static func receivedAPNsToken(_ token: Data) async throws {
        try store.put("watchdog-apns-token", data: token)
        if try store.read("watchdog-registered-token") == token, try store.read("watchdog-status-secret") != nil { return }
        try await register(token: token)
    }
    static func register(token suppliedToken: Data? = nil) async throws {
        let token = try suppliedToken ?? store.read("watchdog-apns-token")
        guard let endpointData = try store.read("watchdog-endpoint"), let endpoint = String(data: endpointData, encoding: .utf8), let url = URL(string: endpoint), url.scheme == "https",
              let secretData = try store.read("watchdog-secret"), let secret = String(data: secretData, encoding: .utf8),
              let idData = try store.read("watchdog-id"), let identifier = String(data: idData, encoding: .utf8) else { return }
        var request = URLRequest(url: url); request.httpMethod = "POST"
        request.setValue("Bearer " + secret, forHTTPHeaderField: "Authorization")
        request.setValue("1", forHTTPHeaderField: "X-FamilyVPN-Command-Protocol")
        request.setValue("1", forHTTPHeaderField: "X-FamilyVPN-Administrator-Protocol")
        request.setValue("1", forHTTPHeaderField: "X-FamilyVPN-VPN-Protocol")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let tokenString = token.map { $0.map { String(format: "%02x", $0) }.joined() }
        request.httpBody = try JSONSerialization.data(withJSONObject: ["id": identifier, "token": tokenString.map { $0 as Any } ?? NSNull()])
        let session = URLSession(configuration: .ephemeral, delegate: RegistrationSessionDelegate(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        request.timeoutInterval = 10
        let (data, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse, (200..<300).contains(response.statusCode) else { throw AppError.message("Watchdog registration failed.") }
        guard response.statusCode == 201, data.count <= 8192 else { throw AppError.message("The dashboard must support administrator provisioning.") }
        let registration = try JSONDecoder().decode(RegistrationReply.self, from: data)
        guard (32...256).contains(registration.statusToken.utf8.count), registration.statusToken.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else { throw AppError.message("Invalid status registration response.") }
        guard let provision = registration.administrator else { throw AppError.message("Set the administrator password in the dashboard before registering.") }
        try provision.validate()
        guard let vpn = registration.vpn else { throw AppError.message("Configure VPN provisioning in the dashboard and register again.") }
        let config = try vpn.configuration()
        guard let publicKey = registration.commandKey, let key = Data(base64Encoded: publicKey), key.count == 32,
           let epoch = registration.commandEpoch, UUID(uuidString: epoch)?.uuidString.lowercased() == epoch else { throw AppError.message("Invalid dashboard command enrollment.") }
        guard try store.read("watchdog-endpoint") == endpointData,
              try store.read("watchdog-secret") == secretData,
              try store.read("watchdog-id") == idData else { throw AppError.message("Enrollment changed while registration was in progress. Register again.") }
        // Remove the previous trust first; incomplete enrollment never authorizes remote actions.
        try store.delete("watchdog-command-key")
        try store.put("watchdog-command-epoch", data: Data(epoch.utf8))
        try store.put("watchdog-command-ledger", data: JSONEncoder().encode(RemoteCommandLedger()))
        try store.put("watchdog-command-key", data: key)
        try store.put("watchdog-status-secret", data: Data(registration.statusToken.utf8))
        try AdminAuthenticator().provision(provision)
        try store.put("vpn-provision", data: JSONEncoder().encode(config))
        if let token { try store.put("watchdog-registered-token", data: token) }
    }
    private struct RegistrationReply: Decodable {
        let vpn: VPNProvision?
        let statusToken: String
        let commandKey: String?
        let commandEpoch: String?
        let administrator: AdministratorProvision?
        enum CodingKeys: String, CodingKey { case vpn, administrator, statusToken = "status_token", commandKey = "command_key", commandEpoch = "command_epoch" }
    }
    static func trustedCommand(_ envelope: RemoteCommandEnvelope) throws -> RemoteCommand {
        guard let key = try store.read("watchdog-command-key"),
              let id = try store.read("watchdog-id"), let device = String(data: id, encoding: .utf8),
              let data = try store.read("watchdog-command-epoch"), let epoch = String(data: data, encoding: .utf8) else {
            throw AppError.message("Remote command enrollment is absent.")
        }
        return try RemoteCommand.verify(envelope, key: key, device: device, epoch: epoch)
    }
    static func ledger() throws -> RemoteCommandLedger {
        guard let data = try store.read("watchdog-command-ledger") else { throw AppError.message("Remote command ledger unavailable.") }
        return try JSONDecoder().decode(RemoteCommandLedger.self, from: data)
    }
    static func saveLedger(_ value: RemoteCommandLedger) throws {
        try store.put("watchdog-command-ledger", data: JSONEncoder().encode(value))
    }
    private static func commandRequest(path: String) throws -> URLRequest? {
        guard let endpointData = try store.read("watchdog-endpoint"), let endpoint = String(data: endpointData, encoding: .utf8), let registrationURL = URL(string: endpoint),
              let credentialData = try store.read("watchdog-status-secret"), let credential = String(data: credentialData, encoding: .utf8),
              try store.read("watchdog-command-key") != nil else { return nil }
        let base = try WatchdogStatus.endpoint(from: registrationURL).deletingLastPathComponent()
        var request = URLRequest(url: base.appendingPathComponent(path)); request.timeoutInterval = 5
        request.setValue("Bearer " + credential, forHTTPHeaderField: "Authorization")
        return request
    }
    private static func commandData(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForResource = 8
        let session = URLSession(configuration: configuration, delegate: RegistrationSessionDelegate(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse else { throw AppError.message("Remote service unavailable.") }
        return (data, response)
    }
    static func pendingCommands() async throws -> [RemoteCommandEnvelope] {
        guard var request = try commandRequest(path: "commands"), let idData = try store.read("watchdog-id"), let id = String(data: idData, encoding: .utf8) else { return [] }
        var url = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
        url.queryItems = [URLQueryItem(name: "id", value: id)]
        request.url = url.url
        let (data, response) = try await commandData(request)
        guard response.statusCode == 200, data.count <= 8192 else { throw AppError.message("Pending commands unavailable.") }
        struct Reply: Decodable { let commands: [RemoteCommandEnvelope] }
        return Array(try JSONDecoder().decode(Reply.self, from: data).commands.prefix(3))
    }
    static func acknowledge(_ receipt: RemoteCommandReceipt) async throws -> Bool {
        guard var request = try commandRequest(path: "command-results"), let idData = try store.read("watchdog-id"), let id = String(data: idData, encoding: .utf8) else { return false }
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(["id": id, "request_id": receipt.requestID, "result": receipt.result])
        let (_, response) = try await commandData(request)
        // Gone history or rotated enrollment is terminal; transient/network failures retain the outbox.
        if [204, 404, 409].contains(response.statusCode) { return true }
        throw AppError.message("Command acknowledgement deferred.")
    }
    static func report(connection: String, policyOK: Bool) async throws {
        guard let endpointData = try store.read("watchdog-endpoint"), let endpoint = String(data: endpointData, encoding: .utf8), let registrationURL = URL(string: endpoint),
              let secretData = try store.read("watchdog-status-secret"), let secret = String(data: secretData, encoding: .utf8),
              let idData = try store.read("watchdog-id"), let identifier = String(data: idData, encoding: .utf8) else { return }
        let url = try WatchdogStatus.endpoint(from: registrationURL)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"; request.timeoutInterval = 5
        request.setValue("Bearer " + secret, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(WatchdogStatus(id: identifier, connection: connection, policyOK: policyOK))
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForResource = 8
        let session = URLSession(configuration: configuration, delegate: RegistrationSessionDelegate(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (_, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse, response.statusCode == 204 else { throw AppError.message("Status report unavailable.") }
    }
}
