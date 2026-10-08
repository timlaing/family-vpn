#if os(macOS)
import ServiceManagement

@MainActor enum DesktopMonitor {
    static let service = SMAppService.agent(plistName: "uk.co.laingcorp.myvpn.monitor.plist")
    static func enable() throws { if service.status != .enabled { try service.register() } }
    static func disable() throws { if service.status == .enabled { try service.unregister() } }
}
#endif
