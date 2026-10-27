@testable import WinnowApp
import TestSupport
import WalletCore
import XCTest

extension XCTestCase {
    /// A ready phone in an isolated wallet fixture; `entropyByte` picks its
    /// seed, `TestKeys.master(entropyByte:)`'s.
    @MainActor
    func readyMultisigModel(advanced: Bool, entropyByte: UInt8 = 0xA1) async throws -> AppModel {
        let environment = [
            "WINNOW_E2E": "1",
            "WINNOW_E2E_RUN": "multisig-\(UUID().uuidString)",
            "WINNOW_E2E_ENTROPY": String(repeating: String(format: "%02x", entropyByte), count: 16),
            "WINNOW_E2E_PEER": "127.0.0.1:1",
            "WINNOW_E2E_CHALLENGE": "51",
            "WINNOW_E2E_ADVANCED": advanced ? "1" : "0",
        ]
        guard case let .active(mode) = E2EMode.resolve(environment: environment),
              case let .active(cleanup) = E2EMode.resolve(
                environment: environment.merging(["WINNOW_E2E_RESET": "1"]) { _, reset in reset })
        else {
            XCTFail("could not create an isolated wallet fixture")
            throw CancellationError()
        }
        let model = AppModel(deviceAuthenticator: SilentAuthenticator(), e2e: mode, storeKeys: InMemoryStoreKeyVault(),
                             keyStore: InMemoryKeyStore())
        addTeardownBlock {
            await model.scenePhaseChanged(.background)
            cleanup.wipeIfRequested()
        }
        let directory = try XCTUnwrap(model.storageDirectory())
        _ = try Wallet.create(network: .signet, keyStore: model.keyStore,
                              storageURL: directory.appending(path: "wallet.json"), entropy: mode.entropy)
        await model.boot()
        XCTAssertEqual(model.stage, .ready)
        XCTAssertEqual(model.advancedMode, advanced)
        return model
    }
}

/// Multisig accounts through the app model with no hardware signer: the
/// builder, a co-signer's spend signed on two phones, and the recovery path's
/// age check. Advanced mode only.
@MainActor
final class MultisigAccountFlowTests: XCTestCase {
    func testBuilderMakesAccountWithAnotherWinnowAndRecovery() async throws {
        let model = try await readyMultisigModel(advanced: true)
        let masters = try TestKeys.masters()
        let otherWinnow = try TestKeys.keyExpression(master: masters[2])

        let record = try await model.createMultisigAccount(
            name: "Family 2-of-2", threshold: 2, otherKeys: [" \(otherWinnow) "], includeLedger: false,
            recovery: .fewerSigners(threshold: 1, blocks: 4320))
        let account = try model.multisigAccount(for: record)
        XCTAssertEqual(account.threshold, 2)
        XCTAssertEqual(account.signers.count, 2)
        XCTAssertEqual(account.recovery?.blocks, 4320)
        XCTAssertEqual(account.recovery?.threshold, 1)
        // The other Winnow joins with the same descriptor: its key is a signer.
        let joined = try MultisigAccount(record.descriptor, network: .signet)
        XCTAssertTrue(joined.includes(accountKey: try masters[2].derived(path: "m/86'/1'/0'").neutered))
        XCTAssertEqual(try joined.address(index: 0), try account.address(index: 0))
        // The same account with this phone's recovery copy under another fingerprint
        // would leave a signer unable to find its key: joining refuses it (SEC-037).
        let phoneKey = try model.multisigKeyExpression()
        let bare = String(phoneKey.dropLast("/<0;1>/*".count))
        let body = String(record.descriptor.split(separator: "#")[0])
        let relabelled = body.replacingOccurrences(of: bare + "/<2;3>/*", with: "[deadbeef" + bare.dropFirst(9) + "/<2;3>/*")
        XCTAssertNotEqual(relabelled, body)
        do {
            _ = try await model.addMultisigAccount(name: "Relabelled", descriptor: relabelled)
            XCTFail("joined an account whose recovery leaf relabels a signer")
        } catch {
            XCTAssertEqual(error as? MultisigAccountError,
                           .invalidDescriptor("a signer reused for recovery must keep its own fingerprint and path there"))
        }
        XCTAssertEqual(model.multisigAccounts.count, 1)

        // Phone and another Winnow with a separate recovery key.
        let recoveryKey = try TestKeys.keyExpression(master: TestKeys.master(entropyByte: 0xD4))
        let pair = try await model.createMultisigAccount(
            name: "Two phones", threshold: 2, otherKeys: [otherWinnow], includeLedger: false,
            recovery: .separateKeys(threshold: 1, keys: [recoveryKey], blocks: 144))
        XCTAssertEqual(try model.multisigAccount(for: pair).recovery?.keys.count, 1)
        XCTAssertEqual(model.multisigAccounts.count, 2)
    }

    func testTwoPhonesSignACoSignersSpendWithBIP326Sequences() async throws {
        let phone = try await readyMultisigModel(advanced: true)
        let otherPhone = try await readyMultisigModel(advanced: true, entropyByte: 0xC3)
        let recoveryKey = try TestKeys.keyExpression(master: TestKeys.master(entropyByte: 0xD4))
        let created = try await phone.createMultisigAccount(
            name: "Two phones", threshold: 2, otherKeys: [try otherPhone.multisigKeyExpression()], includeLedger: false,
            recovery: .separateKeys(threshold: 1, keys: [recoveryKey], blocks: 144))
        _ = try await otherPhone.addMultisigAccount(name: "Two phones", descriptor: created.descriptor)
        let account = try phone.multisigAccount(for: created)

        // Two coins 300 blocks apart reach both phones.
        let height = created.createdAtHeight + 1
        var coins: [Transaction] = []
        for (offset, index) in [(UInt32(0), UInt32(0)), (300, 1)] {
            let funding = Transaction(
                version: 2,
                inputs: [.init(previousOutput: Transaction.Outpoint(txid: Data(repeating: 0x35 + UInt8(index), count: 32),
                                                                    vout: 0), scriptSig: Data(), sequence: 0xFFFF_FFFD)],
                outputs: [.init(value: 60_000, scriptPubKey: try account.scriptPubKey(index: index))], locktime: 0)
            let coinbase = Transaction(version: 1, inputs: [coinbaseInput()],
                                       outputs: [.init(value: 50, scriptPubKey: Data([0x51]))], locktime: height + offset)
            coins.append(funding)
            for model in [phone, otherPhone] {
                try await model.multisigStore.apply(match: fakeMatch(height: height + offset, transactions: [coinbase, funding]),
                                                    network: .signet)
            }
        }
        await phone.refresh()
        await otherPhone.refresh()
        let record = try XCTUnwrap(phone.multisigAccounts.first { $0.id == created.id })
        let otherRecord = try XCTUnwrap(otherPhone.multisigAccounts.first { $0.id == created.id })
        XCTAssertEqual(record.balance, 120_000)

        // A co-signer's wallet builds the spend and, following BIP326, sets each
        // Taproot input's sequence to its coin's confirmations: one meets the
        // 144-block recovery lock, one does not. Both phones take it as the
        // signers' path, sign their own copies and combine them (SEC-035).
        let destination = try Descriptor("tr(\(try TestKeys.keyExpression(master: TestKeys.masters()[1])))")
            .derived(index: 0, bitcoinNetwork: .signet)[0].address
        var proposal = try await phone.createMultisigSpend(record: record, address: destination, amount: 100_000,
                                                           feeRateSatPerVByte: 2)
        for (index, input) in try proposal.unsignedTransaction().inputs.enumerated() {
            proposal.inputs[index].sequence = input.previousOutput.txid == coins[0].txid ? 305 : 5
        }
        for (model, copy) in [(phone, record), (otherPhone, otherRecord)] {
            let screen = try model.multisigSigningScreen(proposal, record: copy)
            XCTAssertEqual(screen.paths, [.signers])
            XCTAssertTrue(screen.progress.phoneUnsigned)
        }
        let mine = try await phone.signMultisigSpend(proposal, record: record)
        let theirs = try await otherPhone.signMultisigSpend(proposal, record: otherRecord)
        var combined = try phone.combineMultisigSpend(mine, with: theirs, record: record)
        XCTAssertTrue(try phone.multisigSigningScreen(combined, record: record).progress.complete)
        let transaction = try account.finalizeSpend(&combined, knownUTXOs: record.utxos,
                                                    ownedOutputCoordinates: phone.multisigOwnedCoordinates(for: record),
                                                    chainTip: height + 304)
        XCTAssertEqual(transaction.inputs.map(\.sequence).sorted(), [5, 305])
    }

    func testRecoveryPathRefusesCoinsThatAreTooYoung() async throws {
        let model = try await readyMultisigModel(advanced: true)
        let record = try await model.createMultisigAccount(
            name: "Two phones", threshold: 2, otherKeys: [try TestKeys.keyExpression(master: TestKeys.masters()[2])],
            includeLedger: false, recovery: .fewerSigners(threshold: 1, blocks: 1000))
        let account = try model.multisigAccount(for: record)
        let height = record.createdAtHeight + 1
        let coinbase = Transaction(version: 1, inputs: [coinbaseInput()],
                                   outputs: [.init(value: 50, scriptPubKey: Data([0x51]))], locktime: height)
        let funding = Transaction(
            version: 2,
            inputs: [.init(previousOutput: Transaction.Outpoint(txid: Data(repeating: 0x34, count: 32), vout: 0),
                           scriptSig: Data(), sequence: 0xFFFF_FFFD)],
            outputs: [.init(value: 60_000, scriptPubKey: try account.scriptPubKey(index: 0))], locktime: 0)
        try await model.multisigStore.apply(match: fakeMatch(height: height, transactions: [coinbase, funding]),
                                            network: .signet)
        await model.refresh()
        let funded = try XCTUnwrap(model.multisigAccounts.first { $0.id == record.id })
        let destination = try Descriptor("tr(\(try TestKeys.keyExpression(master: TestKeys.masters()[0])))")
            .derived(index: 5, bitcoinNetwork: .signet)[0].address
        do {
            _ = try await model.createMultisigSpend(record: funded, address: destination, amount: 20_000,
                                                    feeRateSatPerVByte: 2, path: .recovery)
            XCTFail("a coin younger than the recovery delay was offered to the recovery path")
        } catch {
            guard case MultisigAccountError.invalidSpend = error else { return XCTFail("unexpected \(error)") }
        }
        // The signers' path spends it at once.
        _ = try await model.createMultisigSpend(record: funded, address: destination, amount: 20_000,
                                                feeRateSatPerVByte: 2)
    }

    func testBuilderIsAdvancedModeOnly() async throws {
        let model = try await readyMultisigModel(advanced: false)
        do {
            _ = try await model.createMultisigAccount(
                name: "Two phones", threshold: 2, otherKeys: [try TestKeys.keyExpression(master: TestKeys.masters()[2])],
                includeLedger: false, recovery: nil)
            XCTFail("built a multisig account in Simple mode")
        } catch {
            XCTAssertEqual(error as? AppModel.LedgerActionError, .advancedModeOnly)
        }
    }
}
