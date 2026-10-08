import SwiftUI

@main struct MyApp: App {
    @StateObject private var vpn = VPNManager()
    @Environment(\.scenePhase) private var phase
    #if os(iOS)
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    #else
    @NSApplicationDelegateAdaptor(DesktopAppDelegate.self) private var delegate
    #endif
    init() {
        #if os(macOS)
        if ProcessInfo.processInfo.arguments.contains("--policy-helper") {
            NSApplication.shared.setActivationPolicy(.prohibited)
            let manager = VPNManager()
            _vpn = StateObject(wrappedValue: manager)
            RecoveryCoordinator.shared.start(manager)
        }
        #endif
    }
    var body: some Scene {
        #if os(macOS)
        mainWindow.defaultSize(width: 460, height: 860).windowResizability(.contentSize).defaultLaunchBehavior(ProcessInfo.processInfo.arguments.contains("--policy-helper") ? .suppressed : .automatic)
            .commands { VPNCommands(vpn: vpn) }
        #else
        mainWindow
        #endif
    }
    private var mainWindow: some Scene {
        #if os(macOS)
        Window("Family VPN", id: "main") { appContent }
        #else
        WindowGroup { appContent }
        #endif
    }
    private var appContent: some View {
            ContentView().environmentObject(vpn)
                .task { RecoveryCoordinator.shared.start(vpn) }
                .onChange(of: phase) { _, value in
                    if value == .active { Task { vpn.refreshNetworkStatus(); await vpn.recover() } }
                    #if os(iOS)
                    if value == .background { RecoveryCoordinator.shared.scheduleRefresh() }
                    #endif
                }
    }
}
