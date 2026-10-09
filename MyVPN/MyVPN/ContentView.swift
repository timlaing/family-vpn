import SwiftUI

private func suspensionLabel(_ minutes: Int) -> String {
    switch minutes {
    case 15: return "15 minutes"
    case 60: return "1 hour"
    default: return "8 hours"
    }
}


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
    @State private var registrationOpen = false
    @State private var page: HomePage = .status
    private enum HomePage: String, CaseIterable {
        case status = "Status", details = "Details", settings = "Settings", help = "Help"
        var icon: String {
            switch self {
            case .status: return "shield.fill"
            case .settings: return "gearshape"
            case .details: return "info.circle"
            case .help: return "questionmark.circle"
            }
        }
    }
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
        Group {
            if vpn.policy.installed, page == .help {
                VPNHelpView(showsDone: false)
            } else {
                mainForm
            }
        }
        .onAppear {
            #if DEBUG
            if vpn.screenshotPage == "settings" { page = .settings }
            if vpn.screenshotPage == "help" { page = .help }
            #endif
        }
        .sheet(isPresented: $credentialsOpen) { credentialEditor }
        .sheet(isPresented: $adminOpen) { administratorEditor }
        .sheet(isPresented: $registrationOpen) {
            NavigationStack {
                Form {
                    registration
                    if let error = vpn.error { Text(error).foregroundStyle(.red) }
                    Button("Done") { registrationOpen = false }
                }.vpnPage(title: "Dashboard registration", subtitle: "Retrieve your dashboard configuration again.", icon: "network")
                    .disabled(vpn.busy)
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if vpn.policy.installed { navigationBar }
            bottomPreviewLabel
        }
    }
    private var mainForm: some View {
        NavigationStack {
            Form {
                screenshotLabel
                if !vpn.policy.installed {
                    if vpn.administratorReady {
                        initialAccount
                    } else {
                        registration
                    }
                } else {
                    switch page {
                    case .status: connectionHome
                    case .settings: userPage
                    case .help: EmptyView()
                    case .details: detailsPage
                    }
                }
                if let error = vpn.error { Section { Text(error).foregroundStyle(.red) } }
            }
            .vpnPage(title: homeTitle, subtitle: homeSubtitle, icon: vpn.policy.installed ? page.icon : "network")
            .navigationTitle("Family VPN")
            .onAppear {
                #if DEBUG
                switch vpn.screenshotPage {
                case "settings": page = .settings
                case "user": page = .settings
                case "details", "details-suspended": page = .details
                default: break
                }
                #endif
            }
            .frame(minWidth: 320)
            .disabled(vpn.busy)
        }
    }
    private var homeTitle: String {
        if vpn.policy.installed { return page == .status ? "Your connection" : page.rawValue }
        return vpn.administratorReady ? "Your VPN account" : "Welcome home"
    }
    private var homeSubtitle: String {
        if vpn.policy.installed { return "Your family’s private connection." }
        return vpn.administratorReady ? "Registration complete. Add your VPN account to finish setup." : "Register with your dashboard to get started."
    }
    private var registration: some View {
        Section("Dashboard registration") {
            Text("Set up your environment and device administrator password in the dashboard, then register from its allowed registration network.")
            TextField("HTTPS registration endpoint", text: $endpoint)
            SecureField("Enrollment secret", text: $enrollmentSecret)
            Button("Register this installation") {
                run { try await vpn.enroll(endpoint: endpoint, secret: enrollmentSecret); enrollmentSecret = "" }
            }.buttonStyle(.borderedProminent).controlSize(.large)
            Text("Device authentication is required. Registration securely retrieves your VPN gateway, trusted Wi-Fi and administrator configuration.").font(.footnote)
        }
    }
    private var initialAccount: some View {
        Group {
            Section("Registration complete") {
                Label("Dashboard configuration received", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                LabeledContent("VPN gateway", value: vpn.configuration?.server ?? "Unavailable")
            }
            certificateSection
            Section("VPN account") {
                Text("Enter the account provided by your VPN administrator. The password is stored securely on this device.")
                TextField("VPN username", text: $username)
                SecureField("VPN password", text: $password)
                Button("Install Personal VPN") {
                    run { try await vpn.install(username: username, password: password); page = .status }
                }.buttonStyle(.borderedProminent).controlSize(.large)
            }
        }
    }
    private var connectionHome: some View {
        Section {
            VStack(spacing: 18) {
                ZStack {
                    VPNArtwork(shieldSize: 124, shieldColor: .teal.opacity(0.35), accentColor: .teal.opacity(0.85))
                    Image(systemName: connectionSymbol)
                        .font(.system(size: 64, weight: .medium)).foregroundStyle(connectionColor)
                        .padding(4).background(.background, in: Circle())
                        .offset(x: 42, y: 44)
                }.frame(width: 190, height: 190).accessibilityHidden(true)
                Text(connectionTitle).font(.title2.bold())
                Text(vpn.status).font(.subheadline).foregroundStyle(.secondary)
                if vpn.connectionIndicator == .trusted {
                    Text("VPN bypass is allowed on this trusted Wi-Fi network.").font(.footnote)
                }
            }.multilineTextAlignment(.center).frame(maxWidth: .infinity).padding(.vertical, 38)
                .background {
                    ZStack {
                        LinearGradient(colors: [.teal.opacity(0.20), .cyan.opacity(0.08), .clear], startPoint: .topLeading, endPoint: .bottomTrailing)
                        VPNNetworkBackdrop(color: .teal, emphasis: 2, centered: true)
                    }.clipShape(RoundedRectangle(cornerRadius: 24))
                }
            LabeledContent("VPN gateway", value: vpn.configuration?.server ?? "Unavailable")
            if vpn.busy { ProgressView("Checking connection…") }
        }
    }
    private var connectionSymbol: String {
        switch vpn.connectionIndicator {
        case .connected: return "checkmark.circle.fill"
        case .trusted: return "wifi.circle.fill"
        case .disconnected: return "xmark.circle.fill"
        }
    }
    private var connectionColor: Color {
        switch vpn.connectionIndicator {
        case .connected: return .green
        case .trusted: return .yellow
        case .disconnected: return .red
        }
    }
    private var connectionTitle: String {
        switch vpn.connectionIndicator {
        case .connected: return "VPN connected"
        case .trusted: return "On a trusted network"
        case .disconnected: return "VPN not connected"
        }
    }
    private var userPage: some View {
        Group {
            Section("VPN account") {
                LabeledContent("Username", value: vpn.accountUsername ?? "Unavailable")
                Text("Your password is stored securely and is never displayed.").font(.footnote)
                Button("Change VPN credentials") {
                    run { try await DeviceAuthentication.authorize(); credentialsOpen = true }
                }
            }
            Section("Administration") {
                Button {
                    adminUnlocked = false; administrator = ""; adminOpen = true
                } label: {
                    Label("Administrator controls", systemImage: "lock.shield")
                }
            }
        }
    }
    private var suspensionEnd: String {
        guard let suspension = vpn.policy.suspension else { return "Not suspended" }
        return suspension.expiry?.formatted() ?? "Until manually re-enabled"
    }
    private var detailsPage: some View {
        Group {
            certificateSection
            Section("Policy checks") {
                LabeledContent("Suspension end", value: suspensionEnd)
                if let check = vpn.lastCheck { LabeledContent("Last successful check", value: check.formatted()) }
                Text(vpn.result)
            }
            Section("Trusted Wi-Fi") {
                ForEach(vpn.policy.trustedSSIDs, id: \.self) { Text($0) }
                if vpn.policy.trustedSSIDs.isEmpty { Text("No trusted networks configured.") }
            }
            Section("Protection limits") {
                Text("On unsupervised devices, protection is best effort. Device owners can remove the app or VPN and prevent background recovery.").font(.footnote)
            }
        }
    }
    @ViewBuilder private var certificateSection: some View {
        if vpn.configuration?.caCertificate != nil, let url = RootCertificate.profileURL {
            Section("VPN certificate authority") {
                Text("Export and install the dashboard’s CA profile through system Settings, then approve trust.")
                ShareLink("Export VPN CA profile", item: url)
                Button("Check certificate trust and apply provisioning") { run { _ = await vpn.recover() } }
            }
        }
    }
    private var navigationBar: some View {
        HStack(spacing: 0) {
            ForEach(HomePage.allCases, id: \.self) { item in
                Button {
                    if page == .settings || item == .settings { adminUnlocked = false; administrator = "" }
                    page = item
                } label: {
                    VStack(spacing: 5) {
                        Image(systemName: item.icon).font(.title3)
                        Text(item.rawValue).font(.caption2).lineLimit(1).minimumScaleFactor(0.8)
                    }.frame(maxWidth: .infinity).padding(.vertical, 12)
                }
                .buttonStyle(.plain)
                .foregroundStyle(page == item ? Color.teal : Color.secondary)
                .accessibilityAddTraits(page == item ? .isSelected : [])
            }
        }.padding(.horizontal, 8).background(.regularMaterial)
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
                        Button(suspensionLabel(minutes)) { suspend(until: Date().addingTimeInterval(Double(minutes) * 60)) }
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
                    Button("Register with dashboard again") { registrationOpen = true }
                    Text("Manage the password in the dashboard. Send a reprovision request from the dashboard, or register again through administrator controls, to retrieve a changed administrator configuration.")
                }
                Section {
                    Button("Validate and repair") {
                        run {
                            try await vpn.administer(password: administrator) { policy in
                                try policy.validate()
                            }
                        }
                    }
                    Button("Remove VPN configuration", role: .destructive) { confirmRemoval = true }
                    Button("Done") { adminOpen = false; administrator = ""; adminUnlocked = false }.id("securityEnd")
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
