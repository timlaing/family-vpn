import Foundation
import Network
import NetworkExtension
#if os(macOS)
import CoreWLAN
#endif

/// SSIDs are used locally for display only and are never included in dashboard reports.
@MainActor enum NetworkContext {
    static func currentSSID() async -> String? {
        #if os(iOS)
        return await withCheckedContinuation { continuation in
            NEHotspotNetwork.fetchCurrent { continuation.resume(returning: $0?.ssid) }
        }
        #else
        return CWWiFiClient.shared().interface()?.ssid()
        #endif
    }
    static func disconnectedStatus(ssid: String?, trusted: [String], online: Bool?, failure: String?) -> String {
        if online == false { return "Disconnected — network unavailable" }
        if let ssid, trusted.contains(ssid) { return "Not connected on trusted Wi-Fi" }
        if let failure { return "Disconnected — last VPN failure: " + failure }
        if ssid != nil { return "Disconnected on untrusted Wi-Fi" }
        return "Disconnected — network identity unavailable"
    }
}
