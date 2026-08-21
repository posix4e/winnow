@testable import WinnowApp
import BitcoinP2P
import WalletCore
import XCTest

/// Double-submit protection for the operations that move money
/// (epic #100, invariant S2).
///
/// `send` and `bumpFee` are `@MainActor`, which serializes their *entry* but
/// not their execution: each releases the main actor at every await — device
/// authentication, build, broadcast, commit — so a second entry can begin in
/// any of those gaps. The send screen disables its button while a send is in
/// flight, but that is presentation, not a guarantee, and it protects only
/// the one path that happens to render that button.
///
/// These tests drive the guarantee itself.
@MainActor
final class SpendExclusionTests: XCTestCase {
    private final class SilentAuthenticator: DeviceAuthenticating {
        func authenticate(reason: String) async throws {}
    }

    /// A suspension point the test controls. Everything is main-actor
    /// isolated, so `open()` racing `wait()` is ordered rather than a race.
    @MainActor
    private final class Gate {
        private var continuation: CheckedContinuation<Void, Never>?
        private var opened = false

        func wait() async {
            if opened { return }
            await withCheckedContinuation { continuation = $0 }
        }

        func open() {
            opened = true
            continuation?.resume()
            continuation = nil
        }
    }

    private func makeModel() -> AppModel {
        AppModel(deviceAuthenticator: SilentAuthenticator())
    }

    private func samplePreview() -> AppModel.SendPreview {
        AppModel.SendPreview(
            destination: "tb1p-recipient",
            payments: [Payment(amount: 1000, scriptPubKey: Data([0x51, 0x20] + repeatElement(0xAA, count: 32)))],
            silentPayments: [],
            feeRateSatPerVByte: 2,
            fee: 100,
            changeAmount: nil,
            inputCount: 1,
            selectedOutpoints: [.init(txid: Data(repeating: 0x11, count: 32), vout: 0)],
            change: nil)
    }

    private func sampleFeeBump() -> FeeBumpPreview {
        FeeBumpPreview(
            originalTxid: Data(repeating: 0x11, count: 32),
            currentFeeRateSatPerVByte: 1,
            feeRateSatPerVByte: 5,
            fee: 500,
            changeAmount: nil,
            replacementTransaction: Transaction(version: 2, inputs: [], outputs: [], locktime: 0))
    }

    // MARK: - The gate itself

    func testASecondSpendIsRefusedWhileOneIsInFlight() async throws {
        let model = makeModel()
        let gate = Gate()
        let entered = expectation(description: "first spend entered the gate")

        let first = Task { @MainActor in
            try await model.exclusively(.spending) {
                entered.fulfill()
                await gate.wait()
                return 1
            }
        }
        await fulfillment(of: [entered], timeout: 5)

        do {
            _ = try await model.exclusively(.spending) { 2 }
            XCTFail("a second spend was allowed while one was in flight")
        } catch AppModel.AppError.spendAlreadyInFlight {
            // expected
        }

        gate.open()
        let result = try await first.value
        XCTAssertEqual(result, 1)
    }

    /// The gate must not latch: once the first operation finishes, the next
    /// one proceeds normally.
    func testTheGateIsReleasedAfterSuccess() async throws {
        let model = makeModel()
        _ = try await model.exclusively(.spending) { 1 }
        let second = try await model.exclusively(.spending) { 2 }
        XCTAssertEqual(second, 2)
    }

    /// A failed payment must not wedge the wallet. The claim is released on
    /// the throwing path too, so the user can retry.
    func testTheGateIsReleasedWhenTheOperationThrows() async throws {
        struct Boom: Error {}
        let model = makeModel()
        do {
            _ = try await model.exclusively(.spending) { throw Boom() }
            XCTFail("the operation should have thrown")
        } catch is Boom {}

        let after = try await model.exclusively(.spending) { 7 }
        XCTAssertEqual(after, 7, "a failed spend must not permanently block later spends")
    }

    // MARK: - The spending paths actually use it

    /// Proof of wiring, not just of the mechanism. With the gate held, `send`
    /// reports the in-flight refusal rather than reaching its wallet check —
    /// which it could only do by passing through the gate first.
    func testSendGoesThroughTheGate() async throws {
        let model = makeModel()
        let gate = Gate()
        let entered = expectation(description: "gate held")

        let holder = Task { @MainActor in
            try await model.exclusively(.spending) {
                entered.fulfill()
                await gate.wait()
                return 0
            }
        }
        await fulfillment(of: [entered], timeout: 5)

        do {
            _ = try await model.send(preview: samplePreview())
            XCTFail("send ran while another spend was in flight")
        } catch AppModel.AppError.spendAlreadyInFlight {
            // expected
        } catch AppModel.AppError.noWallet {
            XCTFail("send reached its wallet check, so it did not consult the gate")
        }

        gate.open()
        _ = try await holder.value
    }

    /// A fee bump races a send just as dangerously as two sends race each
    /// other: both spend from the same UTXO set and both commit wallet state.
    /// They share one gate, and this proves `bumpFee` observes it.
    func testFeeBumpSharesTheGateWithSend() async throws {
        let model = makeModel()
        let gate = Gate()
        let entered = expectation(description: "gate held")

        let holder = Task { @MainActor in
            try await model.exclusively(.spending) {
                entered.fulfill()
                await gate.wait()
                return 0
            }
        }
        await fulfillment(of: [entered], timeout: 5)

        do {
            _ = try await model.bumpFee(preview: sampleFeeBump())
            XCTFail("a fee bump ran while a spend was in flight")
        } catch AppModel.AppError.spendAlreadyInFlight {
            // expected
        } catch AppModel.AppError.noWallet {
            XCTFail("bumpFee reached its wallet check, so it did not consult the gate")
        }

        gate.open()
        _ = try await holder.value
    }
}
