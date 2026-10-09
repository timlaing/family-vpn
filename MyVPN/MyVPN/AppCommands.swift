import SwiftUI

extension Notification.Name {
    static let vpnCredentialsRequested = Notification.Name("FamilyVPN.credentialsRequested")
    static let vpnAdministratorRequested = Notification.Name("FamilyVPN.administratorRequested")
    static let vpnHelpRequested = Notification.Name("FamilyVPN.helpRequested")
}

#if os(macOS)
struct VPNCommands: Commands {
    @ObservedObject var vpn: VPNManager
    @Environment(\.openWindow) private var openWindow
    private var unavailable: Bool { vpn.busy || vpn.screenshotPage != nil }
    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            // A single VPN configuration has no New Document action.
        }
        CommandMenu("VPN") {
            Button("Show Connection") { openWindow(id: "main") }
                .keyboardShortcut("1")
            Divider()
            Button("Check Connection") { Task { await vpn.recover() } }
                .keyboardShortcut("r").disabled(unavailable || !vpn.policy.installed)
            Button("Change VPN Credentials…") {
                NotificationCenter.default.post(name: .vpnCredentialsRequested, object: nil)
            }.keyboardShortcut("k", modifiers: [.command, .shift])
                .disabled(unavailable || !vpn.policy.installed)
            Button("Administrator Controls…") {
                NotificationCenter.default.post(name: .vpnAdministratorRequested, object: nil)
            }.keyboardShortcut("a", modifiers: [.command, .shift])
                .disabled(unavailable || !vpn.policy.installed)
        }
        CommandGroup(replacing: .help) {
            Button("Family VPN Help") {
                NotificationCenter.default.post(name: .vpnHelpRequested, object: nil)
            }
        }
    }
}
#endif

struct VPNHelpView: View {
    var showsDone = true
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            Form {
                Section("Getting started") {
                    Text("Configure the VPN gateway, trusted Wi-Fi and device administrator password in your dashboard, register from your configured registration network, and enter your VPN account credentials in the app. Install your own certificate authority in system Settings if your gateway requires it.")
                }
                Section("Automatic protection") {
                    Text("The VPN connects on untrusted networks and bypasses administrator-approved Wi-Fi. The connection screen reports the system VPN status and latest policy check.")
                }
                Section("Credentials and administration") {
                    Text("Changing VPN credentials requires device authentication. Local trusted-network, suspension and policy changes require the dashboard-managed administrator password. Password changes are delivered by registration or a signed dashboard reprovision request.")
                }
                Section("Best-effort recovery") {
                    Text("Open the app to retry a failed policy check. On macOS, enable the login monitor in Administrator Controls to check policy while the window is closed. Device owners can remove the VPN or app; background execution and precise suspension expiry are not guaranteed.")
                }
                Section("Support") {
                    Text("For account or connection problems, contact the administrator of your VPN environment.")
                    Link("Setup documentation", destination: URL(string: "https://github.com/timlaing/family-vpn#readme")!)
                    Link("Report an application issue", destination: URL(string: "https://github.com/timlaing/family-vpn/issues")!)
                    Text("Do not include passwords, enrollment secrets or private network details in public reports.").font(.footnote)
                }
                if showsDone { Button("Done") { dismiss() }.buttonStyle(.borderedProminent) }
            }
            .vpnPage(title: "How Family VPN works", subtitle: "Connection, protection and local administration.", icon: "questionmark.circle")
            .navigationTitle("Family VPN Help")
        }
    }
}
