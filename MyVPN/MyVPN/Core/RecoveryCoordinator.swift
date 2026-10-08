import Foundation
import UserNotifications
import Network
#if os(iOS)
import UIKit
import BackgroundTasks
#endif

@MainActor final class RecoveryCoordinator {
    static let shared = RecoveryCoordinator()
    weak var vpn: VPNManager?
    private let monitor = NWPathMonitor()
    private var timer: Timer?
    func start(_ vpn: VPNManager) {
        guard vpn.screenshotPage == nil, !vpn.isUnitTestHost, self.vpn == nil else { return }
        self.vpn = vpn
        monitor.pathUpdateHandler = { path in Task { @MainActor in
            RecoveryCoordinator.shared.vpn?.refreshNetworkStatus(online: path.status == .satisfied)
            await RecoveryCoordinator.shared.vpn?.recover()
        } }
        monitor.start(queue: DispatchQueue(label: "vpn.network"))
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { _ in Task { @MainActor in
            RecoveryCoordinator.shared.vpn?.refreshNetworkStatus()
            await RecoveryCoordinator.shared.vpn?.recover()
        } }
        Task { vpn.refreshNetworkStatus(); await vpn.recover() }
    }
    #if os(iOS)
    func scheduleRefresh() {
        guard ScreenshotMode.page == nil, !ScreenshotMode.isUnitTestHost else { return }
        let request = BGAppRefreshTaskRequest(identifier: "uk.co.laingcorp.myvpn.refresh")
        request.earliestBeginDate = Date().addingTimeInterval(1800)
        try? BGTaskScheduler.shared.submit(request)
    }
    #endif
}
#if os(iOS)
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        guard ScreenshotMode.page == nil, !ScreenshotMode.isUnitTestHost else { return true }
        UNUserNotificationCenter.current().delegate = VPNNotificationDelegate.shared
        BGTaskScheduler.shared.register(forTaskWithIdentifier: "uk.co.laingcorp.myvpn.refresh", using: nil) { task in
            Task { @MainActor in
                let completion = CompletionOnce { task.setTaskCompleted(success: $0) }
                let work = Task { await RecoveryCoordinator.shared.vpn?.recover() }
                task.expirationHandler = { work.cancel(); completion.finish(success: false) }
                let success = await work.value ?? false
                RecoveryCoordinator.shared.scheduleRefresh()
                completion.finish(success: success && !work.isCancelled)
            }
        }
        if (try? CredentialStore().read("watchdog-endpoint")) != nil { application.registerForRemoteNotifications() }
        return true
    }
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in
            do { try await PushRegistrationService.receivedAPNsToken(deviceToken); RecoveryCoordinator.shared.vpn?.refreshEnrollmentState() }
            catch { RecoveryCoordinator.shared.vpn?.error = "Watchdog registration failed; local recovery remains available." }
        }
    }
    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        Task { @MainActor in RecoveryCoordinator.shared.vpn?.error = "APNs registration unavailable." }
    }
    func applicationProtectedDataDidBecomeAvailable(_ application: UIApplication) { Task { @MainActor in await RecoveryCoordinator.shared.vpn?.recover() } }
    func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any], fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        Task { @MainActor in
            guard let vpn = RecoveryCoordinator.shared.vpn else { completionHandler(.noData); return }
            let success: Bool
            if let value = userInfo["command"], let data = try? JSONSerialization.data(withJSONObject: value),
               let envelope = try? JSONDecoder().decode(RemoteCommandEnvelope.self, from: data) {
                success = await vpn.receiveRemoteCommand(envelope)
            } else { success = await vpn.recover() }
            completionHandler(success ? .newData : .failed)
        }
    }
}
#endif

#if os(macOS)
import AppKit

final class DesktopAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        guard ScreenshotMode.page == nil, !ScreenshotMode.isUnitTestHost else { return }
        UNUserNotificationCenter.current().delegate = VPNNotificationDelegate.shared
        if (try? CredentialStore().read("watchdog-endpoint")) != nil {
            NSApplication.shared.registerForRemoteNotifications()
        }
    }
    func application(_ application: NSApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in
            do {
                try await PushRegistrationService.receivedAPNsToken(deviceToken)
                RecoveryCoordinator.shared.vpn?.refreshEnrollmentState()
            } catch { RecoveryCoordinator.shared.vpn?.error = "Watchdog registration failed; register again on the enrollment network." }
        }
    }
    func application(_ application: NSApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        Task { @MainActor in RecoveryCoordinator.shared.vpn?.error = "APNs registration unavailable." }
    }
    func application(_ application: NSApplication, didReceiveRemoteNotification userInfo: [String: Any]) {
        Task { @MainActor in
            guard let vpn = RecoveryCoordinator.shared.vpn else { return }
            if let value = userInfo["command"], let data = try? JSONSerialization.data(withJSONObject: value),
               let envelope = try? JSONDecoder().decode(RemoteCommandEnvelope.self, from: data) {
                _ = await vpn.receiveRemoteCommand(envelope)
            } else { _ = await vpn.recover() }
        }
    }
}
#endif

final class VPNNotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    static let shared = VPNNotificationDelegate()
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .badge])
    }
}
