import Foundation
import Security

enum RootCertificate {
    static var profileURL: URL? {
        guard let configuration = try? VPNConfiguration.load(), let encoded = configuration.caCertificate, let data = Data(base64Encoded: encoded) else { return nil }
        let identifier = "org.familyvpn.ca." + (configuration.provisionRevision ?? UUID().uuidString)
        let profile: [String: Any] = ["PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": identifier, "PayloadUUID": UUID().uuidString, "PayloadDisplayName": "Family VPN Certificate Authority", "PayloadContent": [["PayloadType": "com.apple.security.root", "PayloadVersion": 1, "PayloadIdentifier": identifier + ".certificate", "PayloadUUID": UUID().uuidString, "PayloadDisplayName": "VPN Certificate Authority", "PayloadContent": data]]]
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("FamilyVPN-CA.mobileconfig")
        guard let bytes = try? PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0), (try? bytes.write(to: url, options: .atomic)) != nil else { return nil }
        return url
    }
    static func checkSystemTrust(configuration: VPNConfiguration) throws {
        guard let encoded = configuration.caCertificate else { return }
        guard let data = Data(base64Encoded: encoded), let certificate = SecCertificateCreateWithData(nil, data as CFData) else { throw AppError.message("Provisioned CA is invalid.") }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, let trust else { throw AppError.message("Cannot check VPN certificate trust.") }
        SecTrustSetNetworkFetchAllowed(trust, false)
        // Never set custom anchors here: that would only trust this app's evaluation,
        // not the system VPN service. Trust must be installed through system Settings.
        guard SecTrustEvaluateWithError(trust, nil) else { throw AppError.message("Install and trust the exported VPN root CA through system Settings, then retry. The app cannot establish system certificate trust itself.") }
    }
}
