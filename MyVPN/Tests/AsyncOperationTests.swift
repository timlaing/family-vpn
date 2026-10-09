import XCTest
#if canImport(VPNCore)
@testable import VPNCore
#else
@testable import FamilyVPN
#endif

@MainActor private final class TestGate {
    var continuation: CheckedContinuation<Void, Never>?
    let entered: XCTestExpectation
    init(_ entered: XCTestExpectation) { self.entered = entered }
    func wait() async {
        await withCheckedContinuation { continuation in
            self.continuation = continuation
            entered.fulfill()
        }
    }
    func open() { continuation?.resume(); continuation = nil }
}

final class AsyncOperationTests: XCTestCase {
    @MainActor func testOperationsCannotOverlapAcrossAwait() async throws {
        let queue = PreferenceOperationQueue()
        let entered = expectation(description: "First operation holds queue")
        let gate = TestGate(entered)
        var events: [String] = []
        let first = Task { try await queue.run { events.append("first-start"); await gate.wait(); events.append("first-end") } }
        await fulfillment(of: [entered], timeout: 2)
        let enqueued = expectation(description: "Second operation enqueued")
        let second = Task { enqueued.fulfill(); try await queue.run { events.append("second") } }
        await fulfillment(of: [enqueued], timeout: 2)
        XCTAssertEqual(queue.pendingCount, 2)
        XCTAssertEqual(events, ["first-start"])
        gate.open()
        try await first.value; try await second.value
        XCTAssertEqual(events, ["first-start", "first-end", "second"])
        XCTAssertEqual(queue.pendingCount, 0)
    }
    @MainActor func testCancelledQueuedMutationIsSkippedAndQueueRecovers() async throws {
        let queue = PreferenceOperationQueue()
        let entered = expectation(description: "Block queue")
        let gate = TestGate(entered)
        let first = Task { try await queue.run { await gate.wait() } }
        await fulfillment(of: [entered], timeout: 2)
        var mutated = false
        let enqueued = expectation(description: "Queued mutation")
        let second = Task { enqueued.fulfill(); try await queue.run { mutated = true } }
        await fulfillment(of: [enqueued], timeout: 2)
        second.cancel(); gate.open()
        try await first.value
        do { try await second.value; XCTFail("Cancelled operation succeeded") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertFalse(mutated)
        try await queue.run { mutated = true }
        XCTAssertTrue(mutated)
    }
    @MainActor func testFailedOperationDoesNotPoisonQueue() async throws {
        let queue = PreferenceOperationQueue()
        do { try await queue.run { throw AppError.message("Injected save failure") }; XCTFail() }
        catch { XCTAssertEqual(error.localizedDescription, "Injected save failure") }
        var completed = false
        try await queue.run { completed = true }
        XCTAssertTrue(completed)
    }
    @MainActor func testRecoveryHintsShareFailureAndPermitRetry() async {
        let recovery = RecoveryWork()
        let entered = expectation(description: "Repair started")
        let gate = TestGate(entered)
        var attempts = 0
        let first = Task { await recovery.run { attempts += 1; await gate.wait(); return false } }
        await fulfillment(of: [entered], timeout: 2)
        let joined = expectation(description: "Second hint joined")
        let second = Task { joined.fulfill(); return await recovery.run { attempts += 1; return true } }
        await fulfillment(of: [joined], timeout: 2)
        gate.open()
        let firstResult = await first.value
        let secondResult = await second.value
        XCTAssertFalse(firstResult); XCTAssertFalse(secondResult)
        XCTAssertEqual(attempts, 1)
        let retried = await recovery.run { attempts += 1; return true }
        XCTAssertTrue(retried); XCTAssertEqual(attempts, 2)
    }
    @MainActor func testCancellationReachesActiveRecovery() async {
        let recovery = RecoveryWork()
        let entered = expectation(description: "Repair started")
        let task = Task { await recovery.run {
            entered.fulfill()
            do { try await Task.sleep(for: .seconds(30)); return true }
            catch { return false }
        } }
        await fulfillment(of: [entered], timeout: 2)
        task.cancel()
        let result = await task.value
        XCTAssertFalse(result)
        let next = await recovery.run { true }
        XCTAssertTrue(next)
    }
    @MainActor func testTransactionRestoresStateAtEveryFailureStage() async {
        for stage in 1...3 {
            var state = ["password": "old", "protocol": "old", "metadata": "old"]
            do {
                try await PreferenceTransaction.run(operation: {
                    state["password"] = "new"
                    if stage == 1 { throw AppError.message("Injected failure") }
                    state["protocol"] = "new"
                    if stage == 2 { throw AppError.message("Injected failure") }
                    state["metadata"] = "new"
                    throw AppError.message("Injected failure")
                }, rollback: {
                    state = ["password": "old", "protocol": "old", "metadata": "old"]
                }, rollbackFailure: "Rollback failed")
                XCTFail()
            } catch { XCTAssertEqual(error.localizedDescription, "Injected failure") }
            XCTAssertEqual(Set(state.values), ["old"])
        }
    }
    @MainActor func testRollbackFailureIsExplicitAndSuccessDoesNotRollback() async throws {
        do {
            try await PreferenceTransaction.run(operation: { throw AppError.message("Save failed") },
                                                rollback: { throw AppError.message("Storage failed") }, rollbackFailure: "Administrator repair required")
            XCTFail()
        } catch { XCTAssertEqual(error.localizedDescription, "Administrator repair required") }
        var rollbackCalled = false
        try await PreferenceTransaction.run(operation: { /* Successful no-op verifies rollback is not invoked. */ }, rollback: { rollbackCalled = true }, rollbackFailure: "Unexpected")
        XCTAssertFalse(rollbackCalled)
    }
    func testExpirationAndWorkerCanCompleteOnlyOnce() {
        var results: [Bool] = []
        let completion = CompletionOnce { results.append($0) }
        completion.finish(success: false)
        completion.finish(success: true)
        XCTAssertEqual(results, [false])
        let workerFirst = CompletionOnce { results.append($0) }
        workerFirst.finish(success: true)
        workerFirst.finish(success: false)
        XCTAssertEqual(results, [false, true])
    }

}
