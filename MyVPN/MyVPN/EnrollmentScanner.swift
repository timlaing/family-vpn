#if os(iOS)
import SwiftUI
import VisionKit
import Vision

struct EnrollmentScanner: UIViewControllerRepresentable {
    let scanned: (String) -> Void
    let unavailable: () -> Void
    func makeCoordinator() -> Coordinator { Coordinator(scanned: scanned, unavailable: unavailable) }
    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .balanced,
            recognizesMultipleItems: false, isHighFrameRateTrackingEnabled: false, isPinchToZoomEnabled: true,
            isGuidanceEnabled: true, isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        do { try scanner.startScanning() }
        catch { DispatchQueue.main.async { context.coordinator.unavailable() } }
        return scanner
    }
    func updateUIViewController(_: DataScannerViewController, context _: Context) {
        // Scanning configuration is fixed when the controller is created.
    }
    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator _: Coordinator) { controller.stopScanning() }
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let scanned: (String) -> Void
        let unavailable: () -> Void
        var completed = false
        init(scanned: @escaping (String) -> Void, unavailable: @escaping () -> Void) { self.scanned = scanned; self.unavailable = unavailable }
        func dataScanner(_: DataScannerViewController, becameUnavailableWithError _: DataScannerViewController.ScanningUnavailable) { unavailable() }
        func dataScanner(_ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems _: [RecognizedItem]) {
            guard !completed else { return }
            for item in addedItems {
                if case .barcode(let barcode) = item, let value = barcode.payloadStringValue {
                    completed = true; scanner.stopScanning(); scanned(value); return
                }
            }
        }
    }
}
#endif
