import Foundation
import NetworkExtension
import Combine
import UserNotifications
import Darwin
#if os(iOS)
import UIKit
#else
import AppKit
#endif

@MainActor final class VPNManager: ObservableObject {
    @Published var status = "Not installed"
    @Published var result = "No policy check yet"
    @Published var lastCheck: Date?
    @Published var policy = LocalPolicy()
    @Published var configuration: VPNConfiguration?
    @Published var busy = false
    @Published var error: String?
    @Published var administratorReady = false
    let screenshotPage = ScreenshotMode.page
    let isUnitTestHost = ScreenshotMode.isUnitTestHost
    let store = CredentialStore()
    let admin = AdminAuthenticator()
    private let system = NEVPNManager.shared()
    private let operations = PreferenceOperationQueue()
    private var observers: [NSObjectProtocol] = []
    private var loaded = false
    private let recovery = RecoveryWork()
    var networkAvailable: Bool?
    private var currentSSID: String?
    private var lastDisconnectFailure: String?
    private var statusRefresh: Task<Void, Never>?
    private var consecutiveFailures = 0
    private let repairFailureMessage = "Policy repair failed; administrator attention required. Another Personal VPN or missing credentials may require intervention."
    private let owner = "Family VPN · uk.co.laingcorp.myvpn"

    init() {
        #if DEBUG
        if isUnitTestHost { configuration = try? VPNConfiguration.load(); return }
        if let page = screenshotPage {
            configuration = try? VPNConfiguration.load()
            policy.trustedSSIDs = configuration?.defaultTrustedSSIDs ?? []
            policy.installed = !["setup", "setup-bottom"].contains(page)
            status = !policy.installed ? "Not installed" : "Disconnected — preview state"
            result = "Policy verified — preview data"
            lastCheck = Date()
            if page == "suspended" {
                policy.suspension = SuspensionPolicy(created: Date(), expiry: Date().addingTimeInterval(3600))
                status = "Suspended by administrator — " + policy.suspension!.expiry!.formatted()
            }
            return
        }
        #endif
        do {
            configuration = try VPNConfiguration.load()
            policy.trustedSSIDs = configuration?.defaultTrustedSSIDs ?? []
            if let data = try store.read("policy") { policy = try JSONDecoder().decode(LocalPolicy.self, from: data); try policy.validate() }
            administratorReady = try admin.hasProvisionedRecord()
            loaded = true
        } catch { self.error = "Local configuration could not be loaded. Recovery is paused." }
        for name in [Notification.Name.NEVPNConfigurationChange, Notification.Name.NEVPNStatusDidChange] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.refreshNetworkStatus(); await self?.recover() }
            })
        }
    }
    private func serialized(_ body: @escaping @MainActor () async throws -> Void) async throws {
        guard screenshotPage == nil, !isUnitTestHost else { throw AppError.message("Screenshot previews cannot change credentials or VPN policy.") }
        try await operations.run {
            self.busy = true
            defer { self.busy = false }
            // Main UI and login monitor share the same app container and preferences.
            let directory = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("FamilyVPN", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let descriptor = open(directory.appendingPathComponent("preferences.lock").path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
            guard descriptor >= 0 else { throw AppError.message("Cannot acquire policy operation lock.") }
            defer { flock(descriptor, LOCK_UN); close(descriptor) }
            while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
                guard errno == EWOULDBLOCK else { throw AppError.message("Policy operation lock failed.") }
                try await Task.sleep(for: .milliseconds(100))
            }
            try Task.checkCancellation()
            if let data = try self.store.read("policy") {
                let current = try JSONDecoder().decode(LocalPolicy.self, from: data)
                try current.validate()
                self.policy = current
            }
            try self.reloadVPNProvisioning()
            self.loaded = self.configuration != nil
            try await body()
        }

    }
    private struct PreferenceSnapshot {
        let proto: NEVPNProtocol?
        let description: String?
        let enabled: Bool
        let onDemand: Bool
        let rules: [NEOnDemandRule]?
        init(_ system: NEVPNManager) {
            proto = system.protocolConfiguration?.copy() as? NEVPNProtocol
            description = system.localizedDescription
            enabled = system.isEnabled
            onDemand = system.isOnDemandEnabled
            rules = system.onDemandRules?.compactMap { $0.copy() as? NEOnDemandRule }
        }
        func restore(_ system: NEVPNManager) {
            system.protocolConfiguration = proto
            system.localizedDescription = description
            system.isEnabled = enabled
            system.isOnDemandEnabled = onDemand
            system.onDemandRules = rules
        }
    }
    private func load() async throws { try await system.loadFromPreferences() }
    private func save() async throws { try await system.saveToPreferences(); try await load() }
    private func persist(_ value: LocalPolicy) throws {
        try value.validate()
        try store.put("policy", data: JSONEncoder().encode(value))
        policy = value
    }
    private func rules() -> [NEOnDemandRule] { VPNPolicyEngine.rules(trustedSSIDs: policy.trustedSSIDs) }
    private func expected(username: String, reference: Data) throws -> NEVPNProtocolIKEv2 {
        guard let configuration else { throw AppError.message("VPN resource is missing.") }
        return try configuration.makeProtocol(username: username, reference: reference)
    }
    private func associationsMatch(_ a: NEVPNIKEv2SecurityAssociationParameters, _ b: NEVPNIKEv2SecurityAssociationParameters) -> Bool {
        a.encryptionAlgorithm == b.encryptionAlgorithm && a.integrityAlgorithm == b.integrityAlgorithm && a.diffieHellmanGroup == b.diffieHellmanGroup && a.lifetimeMinutes == b.lifetimeMinutes
    }
    private func matches(_ wanted: NEVPNProtocolIKEv2) -> Bool {
        guard let current = system.protocolConfiguration as? NEVPNProtocolIKEv2,
              current.serverAddress == wanted.serverAddress,
              current.remoteIdentifier == wanted.remoteIdentifier, current.localIdentifier == wanted.localIdentifier,
              current.authenticationMethod == wanted.authenticationMethod, current.useExtendedAuthentication == wanted.useExtendedAuthentication,
              current.username == wanted.username, current.passwordReference == wanted.passwordReference,
              current.identityReference == wanted.identityReference, current.sharedSecretReference == wanted.sharedSecretReference,
              current.proxySettings == nil,
              current.serverCertificateCommonName == wanted.serverCertificateCommonName,
              current.serverCertificateIssuerCommonName == wanted.serverCertificateIssuerCommonName,
              current.disconnectOnSleep == wanted.disconnectOnSleep, current.disableMOBIKE == wanted.disableMOBIKE,
              current.deadPeerDetectionRate == wanted.deadPeerDetectionRate,
              current.disableRedirect == wanted.disableRedirect, current.enableRevocationCheck == wanted.enableRevocationCheck,
              current.useConfigurationAttributeInternalIPSubnet == wanted.useConfigurationAttributeInternalIPSubnet,
              current.enablePFS == wanted.enablePFS, current.includeAllNetworks == wanted.includeAllNetworks, current.mtu == wanted.mtu,
              associationsMatch(current.ikeSecurityAssociationParameters, wanted.ikeSecurityAssociationParameters),
              associationsMatch(current.childSecurityAssociationParameters, wanted.childSecurityAssociationParameters), system.localizedDescription == owner, system.isEnabled,
              system.isOnDemandEnabled == !(policy.suspension?.isActive ?? false) else { return false }
        let actual = system.onDemandRules ?? []
        let desired = rules()
        guard actual.count == desired.count else { return false }
        for (a, b) in zip(actual, desired) {
            guard type(of: a) == type(of: b), a.interfaceTypeMatch == b.interfaceTypeMatch,
                  a.ssidMatch == b.ssidMatch, a.dnsSearchDomainMatch == b.dnsSearchDomainMatch,
                  a.dnsServerAddressMatch == b.dnsServerAddressMatch, a.probeURL == b.probeURL else { return false }
        }
        return true
    }
    private func apply(_ proto: NEVPNProtocolIKEv2) {
        system.localizedDescription = owner
        system.protocolConfiguration = proto
        system.isEnabled = true
        system.onDemandRules = rules()
        system.isOnDemandEnabled = !(policy.suspension?.isActive ?? false)
    }
    func install(username: String, password: String) async throws {
        try await serialized {
            guard self.loaded, !self.policy.installed else { throw AppError.message("Setup is unavailable.") }
            try self.configuration?.validate()
            if let configuration = self.configuration { try RootCertificate.checkSystemTrust(configuration: configuration) }
            guard !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !password.isEmpty else { throw AppError.message("Enter VPN credentials.") }
            guard try self.admin.hasProvisionedRecord() else { throw AppError.message("Register with the dashboard to retrieve the administrator configuration first.") }
            try await self.load()
            guard VPNPolicyEngine.mayModify(hasProtocol: self.system.protocolConfiguration != nil, description: self.system.localizedDescription, owner: self.owner) else { throw AppError.message("Another Personal VPN exists. Resolve it in system settings before installing.") }
            let account = "vpn-" + UUID().uuidString
            let previous = PreferenceSnapshot(self.system)
            let previousAccount = try self.store.read("vpn-account")
            let previousUsername = try self.store.read("vpn-username")
            try await PreferenceTransaction.run(operation: {
                let reference = try self.store.put(account, data: Data(password.utf8))
                let proto = try self.expected(username: username, reference: reference)
                self.apply(proto)
                try await self.save()
                guard self.matches(proto) else { throw AppError.message("Saved VPN verification failed.") }
                try self.store.put("vpn-account", data: Data(account.utf8))
                try self.store.put("vpn-username", data: Data(username.utf8))
                var policy = self.policy; policy.installed = true; try self.persist(policy)
            }, rollback: {
                    try await self.load()
                    guard VPNPolicyEngine.mayModify(hasProtocol: self.system.protocolConfiguration != nil, description: self.system.localizedDescription, owner: self.owner) else {
                        throw AppError.message("Another VPN appeared during installation rollback; it was not replaced.")
                    }
                    if self.system.localizedDescription == self.owner {
                        if previous.proto != nil {
                            previous.restore(self.system)
                            try await self.save()
                        } else { try await self.system.removeFromPreferences() }
                    }
                    try self.store.delete(account)
                    if let previousAccount { try self.store.put("vpn-account", data: previousAccount) }
                    else { try self.store.delete("vpn-account") }
                    if let previousUsername { try self.store.put("vpn-username", data: previousUsername) }
                    else { try self.store.delete("vpn-username") }
            }, rollbackFailure: "Installation rollback failed. Reopen the app and use administrator repair.")
            _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
            self.updateStatus()
        }
    }
    func changeCredentials(username: String, password: String) async throws {
        try await DeviceAuthentication.authorize()
        try await serialized {
            guard !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !password.isEmpty, self.policy.installed else { throw AppError.message("Enter replacement VPN credentials.") }
            try await self.load()
            guard self.system.localizedDescription == self.owner else { throw AppError.message("Another Personal VPN conflicts with credential replacement. Resolve it in system settings first.") }
            let old = PreferenceSnapshot(self.system)
            let oldAccountData = try self.store.read("vpn-account")
            let oldUsername = try self.store.read("vpn-username")
            let connected = self.system.connection.status == .connected
            self.system.connection.stopVPNTunnel()
            let deadline = Date().addingTimeInterval(20)
            while [.connected, .connecting, .reasserting, .disconnecting].contains(self.system.connection.status) {
                guard Date() < deadline else { throw AppError.message("VPN did not disconnect in time; credentials were not changed.") }
                try await Task.sleep(for: .milliseconds(200))
            }
            let account = "vpn-" + UUID().uuidString
            try await PreferenceTransaction.run(operation: {
                let reference = try self.store.put(account, data: Data(password.utf8))
                let proto = try self.expected(username: username, reference: reference)
                self.apply(proto); try await self.save()
                guard self.matches(proto) else { throw AppError.message("Credential verification failed.") }
                try self.store.put("vpn-account", data: Data(account.utf8))
                try self.store.put("vpn-username", data: Data(username.utf8))
            }, rollback: {
                    try await self.load()
                    guard VPNPolicyEngine.mayModify(hasProtocol: self.system.protocolConfiguration != nil, description: self.system.localizedDescription, owner: self.owner) else {
                        throw AppError.message("Another VPN appeared during rollback; it was not replaced.")
                    }
                    old.restore(self.system)
                    try await self.save()
                    if let oldAccountData { try self.store.put("vpn-account", data: oldAccountData) }
                    if let oldUsername { try self.store.put("vpn-username", data: oldUsername) }
                    try self.store.delete(account)
                    if connected && !(self.policy.suspension?.isActive ?? false) { try self.system.connection.startVPNTunnel() }
            }, rollbackFailure: "Credential update and rollback failed. Administrator repair is required.")
            if let oldAccountData, let oldAccount = String(data: oldAccountData, encoding: .utf8) { try? self.store.delete(oldAccount) }
            // On Demand decides whether the current network should reconnect.
        }
    }
    func enroll(endpoint: String, secret: String) async throws {
        try await DeviceAuthentication.authorize()
        try await serialized {
            try await PushRegistrationService.enroll(endpoint: endpoint, secret: secret)
            try self.reloadVPNProvisioning()
            self.administratorReady = try self.admin.hasProvisionedRecord()
            #if os(iOS)
            UIApplication.shared.registerForRemoteNotifications()
            #else
            NSApplication.shared.registerForRemoteNotifications()
            #endif
        }
    }
    private func reloadVPNProvisioning() throws {
        let latest = try VPNConfiguration.load()
        if latest.provisionRevision != policy.provisionRevision {
            var updated = policy
            updated.trustedSSIDs = latest.defaultTrustedSSIDs
            updated.provisionRevision = latest.provisionRevision
            try persist(updated)
        }
        configuration = latest
    }
    func refreshEnrollmentState() {
        administratorReady = (try? admin.hasProvisionedRecord()) == true
        Task { await recover() }
    }
    func authenticateAdmin(_ password: String) async throws {
        try await serialized { try self.admin.verify(password) }
    }
    func administer(password: String, change: @escaping (inout LocalPolicy) throws -> Void) async throws {
        try await serialized {
            try self.admin.verify(password)
            var value = self.policy; try change(&value); try value.validate()
            let old = self.policy
            try await PreferenceTransaction.run(operation: {
                try self.persist(value)
                try await self.evaluate()
            }, rollback: {
                try self.persist(old)
                try await self.evaluate()
            }, rollbackFailure: "Policy change and rollback failed. Administrator repair is required.")
            await self.scheduleNotification()
        }
    }
    #if os(macOS)
    func desktopMonitoring(password: String, enabled: Bool) async throws {
        try await serialized {
            try self.admin.verify(password)
            if enabled { try DesktopMonitor.enable() } else { try DesktopMonitor.disable() }
        }
    }
    #endif
    func remove(password: String) async throws {
        try await serialized {
            try self.admin.verify(password); try await self.load()
            guard self.system.localizedDescription == self.owner else { throw AppError.message("App-owned configuration is absent; no other VPN will be removed.") }
            #if os(macOS)
            try DesktopMonitor.disable()
            #endif
            self.system.connection.stopVPNTunnel()
            try await self.system.removeFromPreferences()
            var policy = self.policy; policy.installed = false; policy.suspension = nil; try self.persist(policy)
            if let data = try self.store.read("vpn-account"), let account = String(data: data, encoding: .utf8) { try self.store.delete(account) }
            try self.store.delete("vpn-account"); try self.store.delete("vpn-username")
            UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: ["suspension"])
            self.status = "Not installed"
        }
    }
    @discardableResult func recover() async -> Bool {
        guard screenshotPage == nil, !isUnitTestHost, configuration != nil else { return false }
        return await recovery.run { await self.performRecovery() }
    }
    private func performRecovery() async -> Bool {
        // REST reconciliation is opportunistic; disconnected devices rely on signed APNs data.
        if system.connection.status == .connected, let pending = try? await PushRegistrationService.pendingCommands() {
            for envelope in pending { _ = await executeRemoteCommand(envelope) }
        }
        await flushCommandReceipts()
        do {
            try await serialized { if self.policy.installed { try await self.evaluate() } }
            if error == repairFailureMessage { error = nil }
            await reportStatus(policyOK: true)
            return true
        }
        catch {
            guard !Task.isCancelled, !(error is CancellationError) else { return false }
            result = repairFailureMessage
            self.error = result
            consecutiveFailures += 1
            if consecutiveFailures == 3 {
                let content = UNMutableNotificationContent()
                content.title = "VPN policy needs attention"
                content.body = "Open Family VPN and authenticate as administrator to review protection."
                try? await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "repair-failed", content: content, trigger: nil))
            }
            await reportStatus(policyOK: false)
            return false
        }
    }
    func receiveRemoteCommand(_ envelope: RemoteCommandEnvelope) async -> Bool {
        guard screenshotPage == nil, !isUnitTestHost else { return false }
        let success = await executeRemoteCommand(envelope)
        _ = await recover()
        return success
    }
    private func executeRemoteCommand(_ envelope: RemoteCommandEnvelope) async -> Bool {
        var success = false
        do {
            try await serialized {
                let command = try PushRegistrationService.trustedCommand(envelope)
                guard self.policy.installed || command.action == .reprovisionAdmin else { return }
                var ledger = try PushRegistrationService.ledger()
                guard ledger.accepts(command) else { success = true; return }
                let old = self.policy
                do {
                    if command.action == .reprovisionAdmin {
                        guard let provision = command.administrator else { throw AppError.message("Administrator configuration missing.") }
                        try self.admin.provision(provision)
                        self.refreshEnrollmentState()
                    } else {
                    let next = try command.applying(to: old)
                    try await PreferenceTransaction.run(operation: {
                        try self.persist(next)
                        try await self.evaluate()
                    }, rollback: {
                        try self.persist(old)
                        try await self.evaluate()
                    }, rollbackFailure: "Remote policy change and rollback failed. Administrator repair is required.")
                    await self.scheduleNotification()
                    }
                    success = true
                } catch {
                    self.error = "Remote policy request failed; administrator review is required."
                }
                ledger.record(command, success: success)
                try PushRegistrationService.saveLedger(ledger)
            }
        } catch { return false }
        return success
    }
    private func flushCommandReceipts() async {
        // Never hold the preference lock across reporting: suspension can remove REST reachability.
        guard let pending = try? PushRegistrationService.ledger().receipts else { return }
        for receipt in pending.prefix(2) {
            guard (try? await PushRegistrationService.acknowledge(receipt)) == true else { break }
            try? await serialized {
                var ledger = try PushRegistrationService.ledger()
                ledger.receipts.removeAll { $0.requestID == receipt.requestID }
                try PushRegistrationService.saveLedger(ledger)
            }
        }
    }
    private func reportStatus(policyOK: Bool) async {
        guard policy.installed, !Task.isCancelled, !isUnitTestHost, screenshotPage == nil else { return }
        let connection: String
        if system.localizedDescription != owner { connection = "invalid" }
        else {
            switch system.connection.status {
            case .connected: connection = "connected"
            case .connecting: connection = "connecting"
            case .reasserting: connection = "reasserting"
            case .disconnecting: connection = "disconnecting"
            case .disconnected: connection = "disconnected"
            default: connection = "invalid"
            }
        }
        // Reporting is optional; a network/service failure cannot turn local repair into failure.
        try? await PushRegistrationService.report(connection: connection, policyOK: policyOK)
    }
    private func evaluate() async throws {
        if let suspension = policy.suspension, !suspension.isActive { var value = policy; value.suspension = nil; try persist(value) }
        try await load()
        guard VPNPolicyEngine.mayModify(hasProtocol: system.protocolConfiguration != nil, description: system.localizedDescription, owner: owner) else { throw AppError.message("Another Personal VPN conflicts with this policy.") }
        guard let accountData = try store.read("vpn-account"), let account = String(data: accountData, encoding: .utf8), let nameData = try store.read("vpn-username"), let username = String(data: nameData, encoding: .utf8) else { throw AppError.message("Saved VPN credentials are missing.") }
        let proto = try expected(username: username, reference: store.reference(account))
        if policy.suspension?.isActive == true { system.connection.stopVPNTunnel() }
        if !matches(proto) {
            apply(proto)
            if policy.suspension?.isActive == true { system.connection.stopVPNTunnel() }
            try await save()
            guard matches(proto) else { throw AppError.message("Policy readback verification failed.") }
            result = "Policy restored and verified"
        } else { result = "Policy verified" }
        consecutiveFailures = 0
        lastCheck = Date(); updateStatus()
    }
    func refreshNetworkStatus(online: Bool? = nil) {
        if let online { networkAvailable = online }
        currentSSID = nil
        updateStatus()
        statusRefresh?.cancel()
        statusRefresh = Task {
            let ssid = await NetworkContext.currentSSID()
            guard !Task.isCancelled else { return }
            currentSSID = ssid
            if system.connection.status == .disconnected {
                let failure: Error? = await withCheckedContinuation { continuation in
                    system.connection.fetchLastDisconnectError { continuation.resume(returning: $0) }
                }
                guard !Task.isCancelled else { return }
                lastDisconnectFailure = failure?.localizedDescription
            } else { lastDisconnectFailure = nil }
            updateStatus()
        }
    }
    func updateStatus() {
        if let suspension = policy.suspension, suspension.isActive {
            status = "Suspended by administrator — " + (suspension.expiry.map { $0.formatted() } ?? "Until manually enabled")
            return
        }
        switch system.connection.status {
        case .connected: status = "Connected"
        case .connecting: status = "Connecting"
        case .reasserting: status = "Reasserting"
        case .disconnecting: status = "Disconnecting"
        case .invalid: status = "Not installed"
        default: status = NetworkContext.disconnectedStatus(ssid: currentSSID, trusted: policy.trustedSSIDs, online: networkAvailable, failure: lastDisconnectFailure)
        }
    }
    private func scheduleNotification() async {
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: ["suspension"])
        guard let expiry = policy.suspension?.expiry, expiry > Date() else { return }
        guard (try? await center.requestAuthorization(options: [.alert, .sound])) == true else { return }
        let content = UNMutableNotificationContent(); content.title = "VPN suspension expired"; content.body = "Open Family VPN to restore enforcement if it has not resumed."
        try? await center.add(UNNotificationRequest(identifier: "suspension", content: content, trigger: UNTimeIntervalNotificationTrigger(timeInterval: max(1, expiry.timeIntervalSinceNow), repeats: false)))
    }
}
