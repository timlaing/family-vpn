import Foundation
import Security

enum RootCertificate {
    static var profileURL: URL? { Bundle.main.url(forResource: "VPNRootCA", withExtension: "mobileconfig") }
    static func checkSystemTrust(configuration: VPNConfiguration) throws {
        guard let resource = configuration.rootCertificateResource else { return }
        guard let url = Bundle.main.url(forResource: resource, withExtension: "cer"),
              let certificate = SecCertificateCreateWithData(nil, try Data(contentsOf: url) as CFData) else { throw AppError.message("Bundled root CA is missing or invalid.") }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess, let trust else { throw AppError.message("Cannot check VPN certificate trust.") }
        SecTrustSetNetworkFetchAllowed(trust, false)
        // Never set custom anchors here: that would only trust this app's evaluation,
        // not the system VPN service. Trust must be installed through system Settings.
        guard SecTrustEvaluateWithError(trust, nil) else { throw AppError.message("Install and trust the exported VPN root CA through system Settings, then retry. The app cannot establish system certificate trust itself.") }
    }
}
