@testable import WinnowApp
import TestSupport
import WalletCore
import XCTest

/// A Ledger as the second signer, through the app model and the device
/// simulator: Advanced mode only, the stored registration, the address check
/// on the device, a spend both sign, and a refusal on the device.
@MainActor
final class LedgerPairingTests: XCTestCase {
    struct SimulatorConnector: LedgerConnector {
        let simulator: LedgerSimulator
        /// Rewrites the leaf hash in every signature the device yields, as a
        /// faulty or tampered device or link would.
        var relabelsLeaves = false
        func connect() async throws -> any LedgerSession {
            SimulatorSession(simulator: simulator, relabelsLeaves: relabelsLeaves)
        }
    }

    struct SimulatorSession: LedgerSession {
        let simulator: LedgerSimulator
        let relabelsLeaves: Bool
        func exchange(_ apdu: Data) async throws -> Data {
            var reply = try await simulator.exchange(apdu)
            let bytes = Array(reply)
            // A yielded script-path signature: tag, input, key length 64, x-only key, leaf hash, signature.
            if relabelsLeaves, bytes.count > 70, bytes.first == 0x10, bytes[2] == 64, bytes.suffix(2) == [0xE0, 0x00] {
                reply.replaceSubrange(reply.startIndex + 35 ..< reply.startIndex + 67, with: Data(repeating: 0xEE, count: 32))
            }
            return reply
        }
        func close() async {}
    }

    func testLedgerSigningIsAdvancedModeOnly() async throws {
        let model = try await readyMultisigModel(advanced: false)
        model.ledgerConnector = SimulatorConnector(simulator: LedgerSimulator(master: try TestKeys.masters()[1]))
        do {
            try await model.pairLedger(name: "Phone and Ledger")
            XCTFail("paired a Ledger in Simple mode")
        } catch {
            XCTAssertEqual(error as? AppModel.LedgerActionError, .advancedModeOnly)
        }
        XCTAssertTrue(model.multisigAccounts.isEmpty)
    }

    func testPairVerifyAndSpendWithBothSigners() async throws {
        let model = try await readyMultisigModel(advanced: true)
        let simulator = LedgerSimulator(master: try TestKeys.masters()[1])
        model.ledgerConnector = SimulatorConnector(simulator: simulator)

        var record = try await model.pairLedger(name: "Phone and Ledger")
        let account = try model.multisigAccount(for: record)
        XCTAssertEqual(account.threshold, 2)
        XCTAssertEqual(account.signers.count, 2)
        let registration = try XCTUnwrap(record.ledger)
        XCTAssertEqual(registration.masterFingerprint, try TestKeys.masters()[1].fingerprint)
        XCTAssertEqual(registration.keyPath, LedgerMultisig.keyPath(network: .signet))
        let names = await simulator.registeredNames
        XCTAssertEqual(names, ["Phone and Ledger"])

        // Pairing again refiles the same account rather than adding a copy.
        let again = try await model.pairLedger(name: "Phone and Ledger")
        XCTAssertEqual(again.id, record.id)
        XCTAssertEqual(model.multisigAccounts.count, 1)

        let shown = try await model.verifyLedgerAddress(record: record, index: 0)
        XCTAssertEqual(shown, try account.address(index: 0))
        let displayed = await simulator.displayedAddresses
        XCTAssertEqual(displayed, [shown])

        // Fund the account, then spend: the phone and the Ledger each sign.
        let height = record.createdAtHeight + 1
        let coinbase = Transaction(version: 1, inputs: [coinbaseInput()],
                                   outputs: [.init(value: 50, scriptPubKey: Data([0x51]))], locktime: height)
        let funding = Transaction(
            version: 2,
            inputs: [.init(previousOutput: Transaction.Outpoint(txid: Data(repeating: 0x33, count: 32), vout: 0),
                           scriptSig: Data(), sequence: 0xFFFF_FFFD)],
            outputs: [.init(value: 60_000, scriptPubKey: try account.scriptPubKey(index: 0))], locktime: 0)
        try await model.multisigStore.apply(match: fakeMatch(height: height, transactions: [coinbase, funding]),
                                            network: .signet)
        await model.refresh()
        record = try XCTUnwrap(model.multisigAccounts.first { $0.id == record.id })
        XCTAssertEqual(record.balance, 60_000)

        let destination = try Descriptor("tr(\(try TestKeys.keyExpression(master: TestKeys.masters()[2])))")
            .derived(index: 0, bitcoinNetwork: .signet)[0].address
        var psbt = try await model.createMultisigSpend(record: record, address: destination, amount: 40_000,
                                                       feeRateSatPerVByte: 2)
        // What the signing screen shows at each step.
        var screen = try model.multisigSigningScreen(psbt, record: record)
        XCTAssertEqual(screen.paths, [.signers])
        XCTAssertEqual(screen.progress, MultisigSigningProgress(phoneHolds: true, phoneUnsigned: true, ledgerHolds: true,
                                                                ledgerUnsigned: true))
        XCTAssertTrue(screen.progress.nextStep.hasPrefix("Add this phone's signature and the Ledger's"))
        psbt = try await model.signMultisigSpendWithLedger(psbt, record: record)
        screen = try model.multisigSigningScreen(psbt, record: record)
        XCTAssertEqual(screen.approvals[.signers]?.count, 1)
        XCTAssertFalse(screen.progress.ledgerUnsigned || screen.progress.complete)

        // A device whose signatures name a leaf they were not made for is refused,
        // though its key already holds a valid one (SEC-036), and nothing is added.
        model.ledgerConnector = SimulatorConnector(simulator: simulator, relabelsLeaves: true)
        do {
            _ = try await model.signMultisigSpendWithLedger(psbt, record: record)
            XCTFail("a relabelled Ledger signature was accepted")
        } catch {
            XCTAssertEqual(error as? LedgerError, .mismatch("a Ledger signature does not verify"))
        }
        model.ledgerConnector = SimulatorConnector(simulator: simulator)

        psbt = try await model.signMultisigSpend(psbt, record: record)
        screen = try model.multisigSigningScreen(psbt, record: record)
        XCTAssertEqual(screen.approvals[.signers]?.count, 2)
        XCTAssertTrue(screen.progress.complete)
        XCTAssertEqual(screen.progress.nextStep, "Enough signatures verify. Finalize and broadcast.")
        var finalized = psbt
        let transaction = try account.finalizeSpend(&finalized, knownUTXOs: record.utxos,
                                                    ownedOutputCoordinates: model.multisigOwnedCoordinates(for: record),
                                                    chainTip: height)
        XCTAssertEqual(transaction.inputs.count, 1)

        // A refusal on the Ledger reaches the user as that, and signs nothing.
        await simulator.setDecision(.reject)
        let unsigned = try await model.createMultisigSpend(record: record, address: destination, amount: 40_000,
                                                           feeRateSatPerVByte: 2)
        do {
            _ = try await model.signMultisigSpendWithLedger(unsigned, record: record)
            XCTFail("a refused signature was accepted")
        } catch {
            XCTAssertEqual(error as? LedgerError, .rejectedOnDevice)
        }
    }

    func testBuilderMakesTwoOfThreeWithAnotherWinnowALedgerAndRecovery() async throws {
        let model = try await readyMultisigModel(advanced: true)
        let masters = try TestKeys.masters()
        let simulator = LedgerSimulator(master: masters[1])
        model.ledgerConnector = SimulatorConnector(simulator: simulator)
        let otherWinnow = try TestKeys.keyExpression(master: masters[2])

        let record = try await model.createMultisigAccount(
            name: "Family 2-of-3", threshold: 2, otherKeys: [" \(otherWinnow) "], includeLedger: true,
            recovery: .fewerSigners(threshold: 1, blocks: 4320))
        let account = try model.multisigAccount(for: record)
        XCTAssertEqual(account.threshold, 2)
        XCTAssertEqual(account.signers.count, 3)
        XCTAssertEqual(account.recovery?.blocks, 4320)
        XCTAssertEqual(account.recovery?.threshold, 1)
        XCTAssertNotNil(record.ledger)
        let names = await simulator.registeredNames
        XCTAssertEqual(names, ["Family 2-of-3"])
        // The other Winnow joins with the same descriptor: its key is a signer.
        let joined = try MultisigAccount(record.descriptor, network: .signet)
        XCTAssertTrue(joined.includes(accountKey: try masters[2].derived(path: "m/86'/1'/0'").neutered))
        XCTAssertEqual(try joined.address(index: 0), try account.address(index: 0))
        XCTAssertEqual(model.multisigAccounts.count, 1)
    }

    func testStoreRefusesARegistrationForAnotherAccount() async throws {
        let model = try await readyMultisigModel(advanced: true)
        model.ledgerConnector = SimulatorConnector(simulator: LedgerSimulator(master: try TestKeys.masters()[1]))
        let record = try await model.pairLedger(name: "Phone and Ledger")
        var forged = try XCTUnwrap(record.ledger)
        forged.policyID = Data(repeating: 0x11, count: 32)
        do {
            try await model.multisigStore.setLedger(id: record.id, registration: forged)
            XCTFail("a registration for another policy was filed")
        } catch {}
        var tampered = record
        tampered.ledger = forged
        XCTAssertThrowsError(try MultisigStore.validate([tampered], network: .signet))
        XCTAssertNoThrow(try MultisigStore.validate([record], network: .signet))
    }
}
