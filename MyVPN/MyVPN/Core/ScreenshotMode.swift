import Foundation

/// Debug-only, read-only UI fixtures. Never represents an installed or connected VPN.
enum ScreenshotMode {
    static var isUnitTestHost: Bool {
        #if DEBUG
        return ProcessInfo.processInfo.environment["FAMILY_VPN_UNIT_TESTS"] == "1"
        #else
        return false
        #endif
    }
    static var page: String? {
        #if DEBUG
        let arguments = ProcessInfo.processInfo.arguments
        guard let index = arguments.firstIndex(of: "--screenshot-page"), arguments.indices.contains(index + 1) else { return nil }
        let page = arguments[index + 1]
        return ["setup", "registered", "settings", "help", "user", "details", "status-connected", "status-trusted", "dashboard", "suspended", "credentials", "admin-gate", "administrator", "admin-security", "setup-bottom", "administrator-bottom", "admin-security-bottom"].contains(page) ? page : nil
        #else
        return nil
        #endif
    }
}
