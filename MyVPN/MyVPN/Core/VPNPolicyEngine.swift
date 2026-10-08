import NetworkExtension
import Foundation

enum VPNPolicyEngine {
    static func mayModify(hasProtocol: Bool, description: String?, owner: String) -> Bool {
        !hasProtocol || description == owner
    }
    static func onDemandEnabled(policy: LocalPolicy, at date: Date = Date()) -> Bool {
        !(policy.suspension?.active(at: date) ?? false)
    }
    static func rules(trustedSSIDs: [String]) -> [NEOnDemandRule] {
        var rules: [NEOnDemandRule] = []
        if !trustedSSIDs.isEmpty {
            let trusted = NEOnDemandRuleDisconnect()
            trusted.interfaceTypeMatch = .wiFi
            trusted.ssidMatch = trustedSSIDs
            rules.append(trusted)
        }
        rules.append(NEOnDemandRuleConnect())
        return rules
    }
}

extension VPNConfiguration {
    func makeProtocol(username: String, reference: Data) throws -> NEVPNProtocolIKEv2 {
        try validate()
        let configuration = self
        let proto = NEVPNProtocolIKEv2()
        proto.serverAddress = configuration.server
        proto.remoteIdentifier = configuration.remoteIdentifier
        proto.localIdentifier = configuration.localIdentifier
        proto.authenticationMethod = configuration.authenticationMethod == "Certificate" ? .certificate : .none
        proto.useExtendedAuthentication = configuration.useExtendedAuthentication
        guard let rate = NEVPNIKEv2DeadPeerDetectionRate(rawValue: configuration.deadPeerDetectionRate) else { throw AppError.message("Invalid dead peer detection rate.") }
        proto.deadPeerDetectionRate = rate
        proto.disableRedirect = configuration.disableRedirect
        proto.enableRevocationCheck = configuration.enableRevocationCheck
        proto.useConfigurationAttributeInternalIPSubnet = configuration.useConfigurationAttributeInternalIPSubnet
        proto.username = username
        proto.passwordReference = reference
        proto.serverCertificateCommonName = configuration.certificateCommonName.isEmpty ? nil : configuration.certificateCommonName
        proto.serverCertificateIssuerCommonName = configuration.certificateIssuerCommonName.isEmpty ? nil : configuration.certificateIssuerCommonName
        proto.disconnectOnSleep = configuration.disconnectOnSleep
        proto.disableMOBIKE = configuration.disableMOBIKE
        proto.enablePFS = configuration.enablePFS
        proto.includeAllNetworks = configuration.includeAllNetworks
        if let mtu = configuration.mtu { proto.mtu = mtu }
        for (settings, value) in [(proto.ikeSecurityAssociationParameters, configuration.ike), (proto.childSecurityAssociationParameters, configuration.child)] {
            guard let encryption = NEVPNIKEv2EncryptionAlgorithm(rawValue: value.encryption), let integrity = NEVPNIKEv2IntegrityAlgorithm(rawValue: value.integrity), let group = NEVPNIKEv2DiffieHellmanGroup(rawValue: value.diffieHellman) else { throw AppError.message("Unsupported security association.") }
            settings.encryptionAlgorithm = encryption
            settings.integrityAlgorithm = integrity
            settings.diffieHellmanGroup = group
            settings.lifetimeMinutes = Int32(value.lifetimeMinutes)
        }
        return proto
    }
}
