// swift-tools-version: 6.0
import PackageDescription
let package = Package(name: "VPNCore", platforms: [.macOS(.v15)], products: [.library(name: "VPNCore", targets: ["VPNCore"])], targets: [
    .target(name: "VPNCore", path: "MyVPN/Core", exclude: ["VPNManager.swift", "RecoveryCoordinator.swift", "DesktopMonitor.swift", "PushRegistrationService.swift", "RootCertificate.swift", "ScreenshotMode.swift"], sources: ["Policy.swift", "Security.swift", "VPNPolicyEngine.swift", "AsyncOperations.swift", "WatchdogStatus.swift", "RemoteCommand.swift", "EnrollmentLink.swift"]),
    .testTarget(name: "VPNCoreTests", dependencies: ["VPNCore"], path: "Tests")
], swiftLanguageModes: [.v5])
