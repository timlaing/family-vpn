import Foundation
import Security
import CommonCrypto
import LocalAuthentication

struct CredentialStore {
    let service: String
    init(service: String = "uk.co.laingcorp.myvpn.local") { self.service = service }
    func read(_ account: String) throws -> Data? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching([kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account, kSecReturnData: true, kSecMatchLimit: kSecMatchLimitOne] as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw AppError.message("Secure storage is unavailable (\(status)).") }
        return result as? Data
    }
    @discardableResult func put(_ account: String, data: Data) throws -> Data {
        let query = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account] as [CFString: Any]
        let attributes: [CFString: Any] = [kSecValueData: data, kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecAttrSynchronizable: false]
        let update = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if update == errSecItemNotFound {
            var insertion = query.merging(attributes) { _, new in new }
            insertion[kSecReturnPersistentRef] = true
            var result: CFTypeRef?
            let status = SecItemAdd(insertion as CFDictionary, &result)
            guard status == errSecSuccess, let reference = result as? Data else { throw AppError.message("Could not create secure storage (\(status)).") }
            return reference
        }
        guard update == errSecSuccess else { throw AppError.message("Could not update secure storage (\(update)).") }
        return try reference(account)
    }
    func reference(_ account: String) throws -> Data {
        var result: CFTypeRef?
        let status = SecItemCopyMatching([kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account, kSecReturnPersistentRef: true] as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { throw AppError.message("VPN password reference is missing.") }
        return data
    }
    func delete(_ account: String) throws {
        let status = SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: account] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw AppError.message("Secure storage deletion failed.") }
    }
}
struct AdministratorProvision: Codable {
    let algorithm: String
    let iterations: Int
    let salt: Data
    let verifier: Data
    let revision: String
    func validate() throws {
        guard algorithm == "pbkdf2-sha256", iterations == 600_000, salt.count == 32, verifier.count == 32,
              UUID(uuidString: revision)?.uuidString.lowercased() == revision else {
            throw AppError.message("Invalid dashboard administrator configuration.")
        }
    }
}

struct AdminAuthenticator {
    struct Record: Codable {
        var salt: Data
        var verifier: Data
        var serverRevision: String?
        var failures: Int = 0
        var retryAfter: Date = .distantPast
    }
    let store: CredentialStore
    init(store: CredentialStore = CredentialStore()) { self.store = store }
    func hasRecord() throws -> Bool { try store.read("administrator") != nil }
    func hasProvisionedRecord() throws -> Bool {
        guard let data = try store.read("administrator") else { return false }
        let record = try JSONDecoder().decode(Record.self, from: data)
        return record.serverRevision != nil && record.salt.count == 32 && record.verifier.count == 32
    }
    func provision(_ value: AdministratorProvision) throws {
        try value.validate()
        var record = Record(salt: value.salt, verifier: value.verifier, serverRevision: value.revision)
        if let data = try store.read("administrator"), let previous = try? JSONDecoder().decode(Record.self, from: data),
           previous.salt == value.salt, previous.verifier == value.verifier {
            record.failures = previous.failures
            record.retryAfter = previous.retryAfter
        }
        try store.put("administrator", data: JSONEncoder().encode(record))
    }
    private func derive(_ password: String, salt: Data) throws -> Data {
        let bytes = Array(password.utf8)
        var output = [UInt8](repeating: 0, count: 32)
        let status = bytes.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passwordBytes.baseAddress!.assumingMemoryBound(to: Int8.self), bytes.count, saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600_000, &output, output.count)
            }
        }
        guard status == kCCSuccess else { throw AppError.message("Password verification failed.") }
        return Data(output)
    }
    #if DEBUG
    func create(_ password: String, confirmation: String) throws {
        guard password == confirmation, password.count >= 12 else { throw AppError.message("Use a matching administrator password of at least 12 characters.") }
        var salt = Data(count: 32)
        let result = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard result == errSecSuccess else { throw AppError.message("Secure randomness unavailable.") }
        let record = Record(salt: salt, verifier: try derive(password, salt: salt))
        try store.put("administrator", data: JSONEncoder().encode(record))
    }
    #endif
    func verify(_ password: String, at now: Date = Date()) throws {
        guard !password.isEmpty, let data = try store.read("administrator") else { throw AppError.message("Enter the administrator password.") }
        var record = try JSONDecoder().decode(Record.self, from: data)
        guard record.salt.count == 32, record.verifier.count == 32, (0...20).contains(record.failures), record.retryAfter.timeIntervalSince1970.isFinite else { throw AppError.message("Invalid administrator record.") }
        guard now >= record.retryAfter else { throw AppError.message("Try again after \(record.retryAfter.formatted()).") }
        let candidate = try derive(password, salt: record.salt)
        var difference: UInt8 = 0
        for (a, b) in zip(candidate, record.verifier) { difference |= a ^ b }
        if difference != 0 {
            record.failures = min(record.failures + 1, 20)
            record.retryAfter = now.addingTimeInterval(record.failures < 3 ? 0 : min(3600, pow(2, Double(record.failures - 3)) * 5))
            try store.put("administrator", data: JSONEncoder().encode(record))
            throw AppError.message("Incorrect administrator password.")
        }
        record.failures = 0
        record.retryAfter = .distantPast
        try store.put("administrator", data: JSONEncoder().encode(record))
    }
}
enum DeviceAuthentication {
    static func authorize() async throws {
        let context = LAContext()
        guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authorize Family VPN setup or credential changes") else { throw AppError.message("Device authentication was cancelled.") }
    }
}
