import Foundation

/// Serializes preference work even when actors yield during asynchronous system calls.
@MainActor final class PreferenceOperationQueue {
    private var tail: Task<Void, Never>?
    private(set) var pendingCount = 0

    func run(_ body: @escaping @MainActor () async throws -> Void) async throws {
        let previous = tail
        pendingCount += 1
        let work = Task { @MainActor in
            defer { self.pendingCount -= 1 }
            await previous?.value
            try Task.checkCancellation()
            try await body()
        }
        tail = Task { _ = try? await work.value }
        try await withTaskCancellationHandler(operation: { try await work.value }, onCancel: { work.cancel() })
    }
}

/// Overlapping wake hints share the same result instead of becoming spurious failures.
@MainActor final class RecoveryWork {
    private var current: Task<Bool, Never>?
    func run(_ body: @escaping @MainActor () async -> Bool) async -> Bool {
        if let current { return await current.value }
        let work = Task { @MainActor in await body() }
        current = work
        defer { current = nil }
        return await withTaskCancellationHandler(operation: { await work.value }, onCancel: { work.cancel() })
    }
}

/// Preserve the operation's error only after rollback has actually completed.
@MainActor enum PreferenceTransaction {
    static func run(operation: () async throws -> Void, rollback: () async throws -> Void,
                    rollbackFailure: String) async throws {
        do { try await operation() }
        catch {
            let original = error
            do { try await rollback() }
            catch { throw AppError.message(rollbackFailure) }
            throw original
        }
    }
}

/// A background expiration callback and its worker may race to finish the same task.
final class CompletionOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var finished = false
    private let completion: (Bool) -> Void
    init(_ completion: @escaping (Bool) -> Void) { self.completion = completion }
    func finish(success: Bool) {
        lock.lock()
        guard !finished else { lock.unlock(); return }
        finished = true
        lock.unlock()
        completion(success)
    }
}
