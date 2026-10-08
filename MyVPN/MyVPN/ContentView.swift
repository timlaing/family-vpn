import SwiftUI

struct ContentView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var username = ""
    @State private var password = ""
    @State private var administrator = ""
    @State private var endpoint = ""
    @State private var enrollmentSecret = ""
    @State private var trusted = ""
    @State private var customExpiry = Date().addingTimeInterval(3600)
    @State private var adminOpen = false
    @State private var adminUnlocked = false
    @State private var credentialsOpen = false
    @State private var confirmRemoval = false
    @State private var helpOpen = false
    var body: some View {
        Group {
        #if DEBUG
        if vpn.screenshotPage == "credentials" {
            credentialEditor
        } else if ["admin-gate", "administrator", "admin-security", "administrator-bottom", "admin-security-bottom"].contains(vpn.screenshotPage ?? "") {
            administratorEditor
        } else {
            mainScreen
        }
        #else
        mainScreen
        #endif
        }
        .onReceive(NotificationCenter.default.publisher(for: .vpnCredentialsRequested)) { _ in
            guard vpn.policy.installed, !vpn.busy, !adminOpen, !credentialsOpen, vpn.screenshotPage == nil else { return }
            run { try await DeviceAuthentication.authorize(); credentialsOpen = true }
        }
        .onReceive(NotificationCenter.default.publisher(for: .vpnAdministratorRequested)) { _ in
            guard vpn.policy.installed, !vpn.busy, !adminOpen, !credentialsOpen, vpn.screenshotPage == nil else { return }
            adminUnlocked = false; administrator = ""; adminOpen = true
        }
        .onReceive(NotificationCenter.default.publisher(for: .vpnHelpRequested)) { _ in helpOpen = true }
        .sheet(isPresented: $helpOpen) {
            VPNHelpView()
        }
    }
    private var mainScreen: some View {
        NavigationStack {
            ScrollViewReader { proxy in
            Form {
                screenshotLabel
                Section("Connection") {
                    Label(vpn.status, systemImage: "shield.lefthalf.filled")
                    LabeledContent("Server", value: vpn.configuration?.server ?? "Unavailable")
                    Text("On unsupervised devices, protection is best effort. Device owners can remove the app or VPN and prevent background recovery.").font(.footnote)
                }
                Section("Dashboard registration") {
                    Text(vpn.administratorReady ? "Administrator configuration received. To change the password, update it in the dashboard and send a reprovision request or register again." : "Registration is required before installing the VPN.")
                    TextField("HTTPS registration endpoint", text: $endpoint)
                    SecureField("Enrollment secret", text: $enrollmentSecret)
                    Button("Register this installation") { run { try await vpn.enroll(endpoint: endpoint, secret: enrollmentSecret); enrollmentSecret = "" } }
                    Text("Registration requires device authentication and the dashboard enrollment secret. Only the configured registration network can enroll. Public reports use device credentials; pending commands require VPN connectivity. Enrollment authorizes signed refresh, suspend and enable requests.").font(.footnote)
                }
                if vpn.configuration?.caCertificate != nil, let url = RootCertificate.profileURL {
                    Section("VPN certificate authority") {
                        Text("A CA profile was provided by your dashboard. Export and install it through system Settings, then approve trust. The notification badge clears after a successful system trust check.")
                        ShareLink("Export VPN CA profile", item: url)
                        Button("Check certificate trust and apply provisioning") { run { _ = await vpn.recover() } }
                    }
                }
                if !vpn.policy.installed {
                    Section("First-run setup") {
                        Text("Set the device administrator password in the dashboard, then register this device from the configured registration LAN. The app retrieves a password verifier over HTTPS.")
                        TextField("VPN username", text: $username)
                        SecureField("VPN password", text: $password)
                        Text("Initial trusted Wi-Fi: " + (vpn.policy.trustedSSIDs.isEmpty ? "None" : vpn.policy.trustedSSIDs.joined(separator: ", ")))
                        Button("Install Personal VPN") { run { try await vpn.install(username: username, password: password) } }.buttonStyle(.borderedProminent).controlSize(.large).disabled(!vpn.administratorReady).id("setupEnd")
                    }
                } else {
                    Section("Policy checks") {
                        if let check = vpn.lastCheck { LabeledContent("Last successful check", value: check.formatted()) }
                        Text(vpn.result)
                        Button("Change VPN credentials") { run { try await DeviceAuthentication.authorize(); credentialsOpen = true } }
                        Button("Administrator controls") { adminUnlocked = false; adminOpen = true }
                    }
                }
                if let error = vpn.error { Section { Text(error).foregroundStyle(.red) } }
            }
            .vpnPage(title: vpn.policy.installed ? "Your connection" : "Welcome home", subtitle: vpn.policy.installed ? "Connection status and protection policy, in one place." : "Set up your family’s private connection.", icon: "network")
            .task {
                if vpn.screenshotPage == "setup-bottom" {
                    try? await Task.sleep(for: .milliseconds(400))
                    proxy.scrollTo("setupEnd", anchor: .bottom)
                }
            }
            }
            .navigationTitle("Family VPN")
            .frame(minWidth: 320)
            .disabled(vpn.busy)
            .sheet(isPresented: $credentialsOpen) { credentialEditor }
            .sheet(isPresented: $adminOpen) { administratorEditor }
            .safeAreaInset(edge: .bottom) { bottomPreviewLabel }
        }
    }
    private var credentialEditor: some View {
        NavigationStack {
            Form {
                screenshotLabel
                Text("Device authentication is required when saving. The stored password is never displayed.")
                TextField("Replacement username", text: $username)
                SecureField("Complete replacement password", text: $password)
                Button("Save credentials") { run { try await vpn.changeCredentials(username: username, password: password); credentialsOpen = false } }.buttonStyle(.borderedProminent).controlSize(.large)
                Button("Cancel") { credentialsOpen = false; password = "" }
            }
            .vpnPage(title: "VPN credentials", subtitle: "Update your account securely on this device.", icon: "key.fill")
            .navigationTitle("VPN credentials")
        }.frame(minWidth: 320, minHeight: 300)
    }
    private var administratorEditor: some View {
        NavigationStack {
            ScrollViewReader { proxy in
            Form {
                screenshotLabel
                Section("Administrator authentication") {
                    SecureField("Administrator password", text: $administrator)
                    Text("Every change requires this password; repeated failures incur persistent retry delays.").font(.footnote)
                }
                if !adminUnlocked {
                    Button("Unlock administrator controls") {
                        Task {
                            do { try await vpn.authenticateAdmin(administrator); adminUnlocked = true }
                            catch { vpn.error = error.localizedDescription; administrator = "" }
                        }
                    }
                    if let error = vpn.error { Text(error).foregroundStyle(.red) }
                } else {
                if !["admin-security", "admin-security-bottom"].contains(vpn.screenshotPage ?? "") {
                Section("Trusted Wi-Fi") {
                    Text("Managed by your dashboard. Re-register on the registration network to retrieve gateway and Wi-Fi changes. An access point can imitate a trusted SSID.")
                    ForEach(vpn.policy.trustedSSIDs, id: \.self) { Text($0) }
                    if vpn.policy.trustedSSIDs.isEmpty { Text("No trusted networks configured.") }
                }
                Section("Suspend enforcement") {
                    ForEach([15, 60, 480], id: \.self) { minutes in
                        Button(minutes == 15 ? "15 minutes" : minutes == 60 ? "1 hour" : "8 hours") { suspend(until: Date().addingTimeInterval(Double(minutes) * 60)) }
                    }
                    if let tomorrow = try? SuspensionPolicy.tomorrow() {
                        Button("Until tomorrow at \(tomorrow.formatted())") { suspend(until: tomorrow) }
                    }
                    DatePicker("Custom expiry", selection: $customExpiry, in: Date()...)
                    Button("Suspend until selected time") { suspend(until: customExpiry) }
                    Button("Until manually re-enabled") { suspend(until: nil) }
                    Button("Re-enable enforcement") { run { try await vpn.administer(password: administrator) { $0.suspension = nil } } }
                    Text("iOS may delay automatic expiry until the next execution opportunity. Enable desktop monitoring on macOS for checks while the main app is closed.").font(.footnote).id("suspensionEnd")
                }
                }
                if !["administrator", "administrator-bottom"].contains(vpn.screenshotPage ?? "") {
                #if os(macOS)
                Section("Desktop background monitor") {
                    Button("Enable login monitor") { run { try await vpn.desktopMonitoring(password: administrator, enabled: true) } }
                    Button("Disable login monitor") { run { try await vpn.desktopMonitoring(password: administrator, enabled: false) } }
                    Text("macOS may require approval under System Settings → General → Login Items. The signed app must remain installed at its registered location.").font(.footnote)
                }
                #endif
                Section("Administrator password") {
                    Text("Manage the password in the dashboard. Send a reprovision request from the dashboard, or register again from the main page, to retrieve a changed administrator configuration.")
                }
                Section {
                    Button("Validate and repair") { run { try await vpn.administer(password: administrator) { _ in } } }
                    Button("Remove VPN configuration", role: .destructive) { confirmRemoval = true }
                    Button("Done") { adminOpen = false; administrator = "" }.id("securityEnd")
                }
                }
                }
            }
            .vpnPage(title: "Administrator", subtitle: "Manage trusted networks, protection and device settings.", icon: "slider.horizontal.3")
            .task {
                if ["administrator-bottom", "admin-security-bottom"].contains(vpn.screenshotPage ?? "") {
                    try? await Task.sleep(for: .milliseconds(400))
                    proxy.scrollTo(vpn.screenshotPage == "administrator-bottom" ? "suspensionEnd" : "securityEnd", anchor: .bottom)
                }
            }
            }.navigationTitle("Administrator")
                .onAppear {
                    trusted = vpn.policy.trustedSSIDs.joined(separator: "\n")
                    #if DEBUG
                    adminUnlocked = ["administrator", "admin-security", "administrator-bottom", "admin-security-bottom"].contains(vpn.screenshotPage ?? "")
                    #endif
                }
                .confirmationDialog("Remove the app-owned VPN?", isPresented: $confirmRemoval) {
                    Button("Remove VPN", role: .destructive) { run { try await vpn.remove(password: administrator); adminOpen = false } }
                }
        }.frame(minWidth: 350, minHeight: 600)
            .safeAreaInset(edge: .bottom) { bottomPreviewLabel }
    }
    @ViewBuilder private var bottomPreviewLabel: some View {
        if vpn.screenshotPage?.hasSuffix("-bottom") == true {
            Text("SCREENSHOT PREVIEW · Sample state").font(.caption).padding(6)
        }
    }
    @ViewBuilder private var screenshotLabel: some View {
        if vpn.screenshotPage != nil {
            Text("SCREENSHOT PREVIEW · Sample state · Actions do not change policy")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
    private func suspend(until date: Date?) {
        run { try await vpn.administer(password: administrator) { $0.suspension = SuspensionPolicy(created: Date(), expiry: date) } }
    }
    private func run(_ action: @escaping () async throws -> Void) {
        guard vpn.screenshotPage == nil else { return }
        Task { do { vpn.error = nil; try await action() } catch { vpn.error = error.localizedDescription }; password = ""; administrator = "" }
    }
}
