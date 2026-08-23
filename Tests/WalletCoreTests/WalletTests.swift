import BitcoinCore
import BitcoinP2P
import Foundation
import P256K
import Testing
@testable import WalletCore

@Suite("Wallet")
struct WalletTests {
    private func makeWallet(network: BitcoinNetwork = .signet,
                            storageURL: URL? = nil,
                            keyStore: KeyStore = InMemoryKeyStore()) async throws -> Wallet {
        try await Wallet.create(network: network, keyStore: keyStore, storageURL: storageURL,
                                entropy: testEntropy, creationHeight: 100)
    }

    @Test("create: mnemonic stored, descriptor shape, wallet ID = master fingerprint")
    func create() async throws {
        let keyStore = InMemoryKeyStore()
        let wallet = try await makeWallet(keyStore: keyStore)
        // The all-zero entropy mnemonic's master fingerprint (BIP32/BIP86 vectors).
        let id = await wallet.id
        #expect(id == "73c5da0a")
        #expect(try keyStore.load(walletID: "73c5da0a") == .mnemonic(testMnemonic))

        let text = await wallet.descriptor.serialized()
        #expect(text.hasPrefix("tr([73c5da0a/86'/1'/0']tpub"))
        #expect(text.contains("/<0;1>/*)#"))
        // The descriptor round-trips through the BIP380 parser.
        let descriptor = await wallet.descriptor
        #expect(try Descriptor(text) == descriptor)
    }

    @Test("failed wallet persistence rolls back the protected key")
    func createPersistenceRollback() throws {
        let keyStore = InMemoryKeyStore()
        let root = FileManager.default.temporaryDirectory
            .appending(path: "wallet-create-rollback-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let invalidFile = root.appending(path: "wallet.json", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: invalidFile, withIntermediateDirectories: false)

        #expect(throws: (any Error).self) {
            _ = try Wallet.create(network: .signet, keyStore: keyStore,
                                  storageURL: invalidFile, entropy: testEntropy)
        }
        #expect(throws: KeyStoreError.notFound(walletID: "73c5da0a")) {
            _ = try keyStore.load(walletID: "73c5da0a")
        }
    }

    @Test("address derivation matches BIP86 (incl. the official mainnet vector)")
    func addresses() async throws {
        let master = try testMaster()
        let wallet = try await makeWallet()
        // Signet: coin type 1 — cross-checked against BitcoinCore's BIP86.
        for index: UInt32 in [0, 1, 7] {
            let internalKey = try BIP86.internalKey(from: master, coinType: 1, change: 0, index: index)
            #expect(try await wallet.address(chain: .receive, index: index)
                == BIP86.address(internalKey: internalKey, hrp: "tb"))
            let changeInternal = try BIP86.internalKey(from: master, coinType: 1, change: 1, index: index)
            #expect(try await wallet.address(chain: .change, index: index)
                == BIP86.address(internalKey: changeInternal, hrp: "tb"))
        }
        // Mainnet: the official BIP86 vector for m/86'/0'/0'/0/0.
        let mainnet = try await makeWallet(network: .mainnet)
        #expect(try await mainnet.address(chain: .receive, index: 0)
            == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
    }

    @Test("freshReceiveAddress advances the index; watch list covers the gap window")
    func gapLimit() async throws {
        let wallet = try await makeWallet()
        #expect(await wallet.nextReceiveIndex == 0)
        let first = try await wallet.freshReceiveAddress()
        #expect(first == (try await wallet.address(chain: .receive, index: 0)))
        #expect(await wallet.nextReceiveIndex == 1)
        // (1 used + 20 lookahead) receive + (0 used + 20 lookahead) change.
        #expect(try await wallet.watchScripts().count == 21 + 20)
    }

    @Test("apply: a matched payment becomes a UTXO + history; a spend shrinks the set")
    func applyMatches() async throws {
        let wallet = try await makeWallet()
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 200_000, scriptPubKey: script),
        ], locktime: 0)
        let effect = try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        #expect(effect.received.count == 1 && effect.spent.isEmpty)
        #expect(await wallet.balance == 200_000)
        #expect(await wallet.utxos.count == 1)
        #expect(await wallet.history.count == 1)
        #expect(await wallet.history[0].received == 200_000)

        // Spending tx: one of our inputs + payment elsewhere; fee observable.
        let utxo = try #require(await wallet.utxos.first)
        var spend = Transaction(version: 2, inputs: [
            Transaction.Input(previousOutput: utxo.outpoint, scriptSig: Data(), sequence: 0xFFFF_FFFD),
        ], outputs: [
            Transaction.Output(value: 199_000, scriptPubKey: Data([0x51, 0x20] + repeatElement(0x55, count: 32))),
        ], locktime: 0)
        spend.inputs[0].witness = [Data(repeating: 0, count: 64)] // fake sig for vsize math
        let spendEffect = try await wallet.apply(match: fakeMatch(height: 101, transactions: [spend]))
        #expect(spendEffect.spent.count == 1)
        #expect(await wallet.balance == 0)
        #expect(await wallet.utxos.isEmpty)
        #expect(await wallet.history.count == 2)
        #expect(await wallet.history[1].spent == 200_000)
        #expect(await wallet.history[1].fee == 1_000) // all inputs ours → fee known
        #expect(await wallet.observedFeeRates.count == 1)
    }

    @Test("block application rejects wallet-wide monetary overflow atomically")
    func applyRejectsAggregateOverflow() async throws {
        let wallet = try await makeWallet()
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let first = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            .init(value: BitcoinAmount.maximum, scriptPubKey: script),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [first]))
        #expect(await wallet.balance == BitcoinAmount.maximum)

        let second = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            .init(value: BitcoinAmount.maximum, scriptPubKey: script),
        ], locktime: 1)
        do {
            _ = try await wallet.apply(match: fakeMatch(height: 101, transactions: [second]))
            Issue.record("a wallet total above Bitcoin's monetary range was accepted")
        } catch let error as WalletError {
            #expect(error == .invalidTransactionAmounts)
        }

        #expect(await wallet.balance == BitcoinAmount.maximum)
        #expect(await wallet.utxos.count == 1)
        #expect(await wallet.history.count == 1)
    }

    @Test("payments beyond the gap-limit window are not detected; inside it, indices advance")
    func gapWindow() async throws {
        let wallet = try await makeWallet()
        // Index 25 is outside the initial window (0 used + 20 lookahead).
        let outside = try await wallet.scriptPubKey(chain: .receive, index: 25)
        let txOutside = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 5_000, scriptPubKey: outside),
        ], locktime: 0)
        let effect1 = try await wallet.apply(match: fakeMatch(height: 100, transactions: [txOutside]))
        #expect(effect1.received.isEmpty)
        #expect(await wallet.balance == 0)

        // Index 3 is inside the window; the receive index advances past it.
        let inside = try await wallet.scriptPubKey(chain: .receive, index: 3)
        let txInside = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 7_000, scriptPubKey: inside),
        ], locktime: 0)
        let effect2 = try await wallet.apply(match: fakeMatch(height: 101, transactions: [txInside]))
        #expect(effect2.received.count == 1)
        #expect(await wallet.nextReceiveIndex == 4)
        #expect(await wallet.balance == 7_000)
    }

    @Test("send: coin selection → PSBT → signed tx whose witnesses verify")
    func send() async throws {
        let wallet = try await makeWallet()
        // Two funding outputs: receive 0 and change 0 (received as change).
        for (chain, index, amount) in [(AddressChain.receive, UInt32(0), Int64(150_000)),
                                       (AddressChain.change, UInt32(0), Int64(80_000))] {
            let script = try await wallet.scriptPubKey(chain: chain, index: index)
            let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
                Transaction.Output(value: amount, scriptPubKey: script),
            ], locktime: 0)
            try await wallet.apply(match: fakeMatch(height: 100 + index, transactions: [funding]))
        }
        #expect(await wallet.balance == 230_000)
        #expect(await wallet.nextChangeIndex == 1) // funding to change 0 advanced it
        try await matureCoinbase(wallet, height: 101)

        let destination = Data([0x51, 0x20] + repeatElement(0x99, count: 32))
        let built = try await wallet.send(payments: [Payment(amount: 100_000, scriptPubKey: destination)],
                                          feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        let tx = built.transaction
        #expect(tx.isSegwit)
        #expect(built.changeAmount != nil) // largest-first picks the 150k UTXO
        #expect(tx.inputs.count == 1)
        #expect(built.fee == 150_000 - 100_000 - built.changeAmount!)

        // Every witness verifies cryptographically against the spent scriptPubKey.
        let spentScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let spent = [SighashBIP341.SpentOutput(amount: 150_000, scriptPubKey: spentScript)]
        for index in tx.inputs.indices {
            let sighash = try SighashBIP341.sighash(tx: tx, inputIndex: index, spentOutputs: spent)
            let outputKey = P256K.Schnorr.XonlyKey(dataRepresentation: spentScript.suffix(32))
            let signature = try P256K.Schnorr.SchnorrSignature(dataRepresentation: tx.inputs[index].witness[0])
            var message = [UInt8](sighash)
            #expect(outputKey.isValid(signature, for: &message), "input \(index) must verify")
        }

        // The selection is committed locally: the spent UTXO is gone, the
        // change output is pending (height 0), the send is in history.
        let changeScript = try await wallet.scriptPubKey(chain: .change, index: 1)
        #expect(tx.outputs.contains { $0.scriptPubKey == changeScript })
        #expect(await wallet.utxos.count == 2) // 80k untouched + pending change
        #expect(await wallet.balance == 80_000 + built.changeAmount!)
        let sendEntry = try await #require(wallet.history.first { $0.txid == tx.txid })
        #expect(sendEntry.fee == built.fee)
        #expect(sendEntry.height == 0) // unconfirmed

        // When the send confirms in a matched block, heights update in place.
        let confirmation = try await wallet.apply(match: fakeMatch(height: 150, transactions: [tx]))
        #expect(confirmation.received.isEmpty) // change was already counted
        let history = await wallet.history
        #expect(history.count == 3) // two funding entries + the send
        #expect(history.first { $0.txid == tx.txid }?.height == 150)
        #expect(await wallet.utxos.allSatisfy { $0.height > 0 })
    }

    @Test("coinbase outputs are credited immediately but not spendable until 100 confirmations")
    func coinbaseMaturity() async throws {
        let wallet = try await makeWallet()
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 150_000, scriptPubKey: script),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        #expect(await wallet.utxos.first?.isCoinbase == true)
        #expect(await wallet.spendableUtxos.isEmpty)
        #expect(await wallet.balance == 150_000)

        let destination = Data([0x51, 0x20] + repeatElement(0x99, count: 32))
        await #expect(throws: CoinSelectionError.noUTXOs) {
            try await wallet.buildSend(
                payments: [Payment(amount: 100_000, scriptPubKey: destination)],
                feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        }

        // 99 confirmations: still immature (tip 198 → 198-100+1 = 99).
        try await wallet.recordScanHeight(199)
        #expect(await wallet.spendableUtxos.isEmpty)
        await #expect(throws: CoinSelectionError.noUTXOs) {
            try await wallet.buildSend(
                payments: [Payment(amount: 100_000, scriptPubKey: destination)],
                feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        }

        try await matureCoinbase(wallet, height: 100)
        #expect(await wallet.spendableUtxos.count == 1)
        let built = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)], feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        #expect(built.built.transaction.inputs.count == 1)
    }

    @Test("buildSend leaves wallet state untouched until commit (rollback safety)")
    func buildSendDefersCommit() async throws {
        let wallet = try await makeWallet()
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 150_000, scriptPubKey: script),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        let utxosBefore = await wallet.utxos.count
        let changeIndexBefore = await wallet.nextChangeIndex

        let destination = Data([0x51, 0x20] + repeatElement(0x99, count: 32))
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)], feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })

        // Nothing moved: had broadcast thrown here, no UTXO is stranded.
        #expect(await wallet.balance == 150_000)
        #expect(await wallet.utxos.count == utxosBefore)
        #expect(await wallet.nextChangeIndex == changeIndexBefore)
        #expect(await wallet.history.first { $0.txid == prepared.built.transaction.txid } == nil)

        // commit applies exactly the selection the old send() did.
        try await wallet.commit(prepared)
        #expect(await wallet.utxos.count == 1) // 150k spent, pending change in
        #expect(await wallet.balance == prepared.built.changeAmount!)
        #expect(await wallet.history.contains { $0.txid == prepared.built.transaction.txid })
    }

    @Test("fee bump keeps inputs/payments, satisfies BIP125 fees, signs, and persists")
    func feeBump() async throws {
        let url = tempFileURL("wallet.json")
        let keyStore = InMemoryKeyStore()
        let wallet = try await makeWallet(storageURL: url, keyStore: keyStore)
        let fundingScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 150_000, scriptPubKey: fundingScript),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)

        let destination = Data([0x51, 0x20] + repeatElement(0x99, count: 32))
        let original = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)], feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(original)
        let originalTx = original.built.transaction
        let originalBalance = await wallet.balance
        let currentRate = try await wallet.pendingFeeRate(txid: originalTx.txid)

        do {
            _ = try await wallet.previewFeeBump(txid: originalTx.txid,
                                                feeRateSatPerVByte: currentRate)
            Issue.record("an equal feerate must not build a replacement")
        } catch let error as FeeBumpError {
            guard case .feeRateNotHigher = error else {
                Issue.record("unexpected fee-bump error: \(error)")
                return
            }
        }

        // A tiny requested increase is intentionally below BIP125 rule 4;
        // the builder must raise the actual fee by one replacement vbyte.
        let preview = try await wallet.previewFeeBump(
            txid: originalTx.txid, feeRateSatPerVByte: currentRate + 0.000_1)
        let replacement = try await wallet.buildFeeBump(
            txid: originalTx.txid, feeRateSatPerVByte: currentRate + 0.000_1)
        let replacementTx = replacement.built.transaction
        let replacementVSize = TransactionBuilder.vsize(of: replacementTx)
        #expect(replacement.built.fee >= original.built.fee + Int64(replacementVSize))
        #expect(preview.fee == replacement.built.fee)
        #expect(preview.feeRateSatPerVByte > currentRate)
        #expect(preview.authorizes(replacement.built))

        var changedFee = replacement.built
        changedFee.fee += 1
        #expect(!preview.authorizes(changedFee))

        var changedOutput = replacement.built
        changedOutput.transaction.outputs[0].value -= 1
        #expect(!preview.authorizes(changedOutput))

        var changedInput = replacement.built
        changedInput.transaction.inputs[0].previousOutput.vout += 1
        #expect(!preview.authorizes(changedInput))

        var changedSequence = replacement.built
        changedSequence.transaction.inputs[0].sequence -= 1
        #expect(!preview.authorizes(changedSequence))
        #expect(replacementTx.inputs.map(\.previousOutput) == originalTx.inputs.map(\.previousOutput))
        #expect(replacementTx.outputs.contains { $0.value == 100_000 && $0.scriptPubKey == destination })
        #expect(replacement.built.changeAmount! < original.built.changeAmount!)

        // PSBT signing uses the exact original prevout metadata.
        let sighash = try SighashBIP341.sighash(
            tx: replacementTx, inputIndex: 0,
            spentOutputs: [SighashBIP341.SpentOutput(amount: 150_000, scriptPubKey: fundingScript)])
        let outputKey = P256K.Schnorr.XonlyKey(dataRepresentation: fundingScript.suffix(32))
        let signature = try P256K.Schnorr.SchnorrSignature(
            dataRepresentation: replacementTx.inputs[0].witness[0])
        var message = [UInt8](sighash)
        #expect(outputKey.isValid(signature, for: &message))

        // Build is rollback-safe; commit swaps pending change and history.
        #expect(await wallet.history.first { $0.txid == originalTx.txid }?.replacedBy == nil)
        try await wallet.commitFeeBump(replacement)
        #expect(await wallet.history.first { $0.txid == originalTx.txid }?.replacedBy == replacementTx.txid)
        #expect(await wallet.history.first { $0.txid == replacementTx.txid }?.height == 0)
        #expect(await wallet.balance == originalBalance - (replacement.built.fee - original.built.fee))
        #expect(await wallet.nextChangeIndex == 1)

        // Exact prevouts/raw tx survive relaunch, so a second bump can be built.
        let reopened = try Wallet.open(storageURL: url, keyStore: keyStore)
        #expect(await reopened.feeBumpableTxids == [replacementTx.txid])
        let reopenedRate = try await reopened.pendingFeeRate(txid: replacementTx.txid)
        _ = try await reopened.buildFeeBump(txid: replacementTx.txid,
                                            feeRateSatPerVByte: reopenedRate + 1)
    }

    @Test("same-input bump refuses a changeless send")
    func feeBumpNeedsChange() async throws {
        let wallet = try await makeWallet()
        let fundingScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 100_000, scriptPubKey: fundingScript),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        let destination = Data([0x51, 0x20] + repeatElement(0x88, count: 32))
        let original = try await wallet.buildSend(
            payments: [Payment(amount: 99_778, scriptPubKey: destination)], feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        #expect(original.built.changeAmount == nil)
        try await wallet.commit(original)
        #expect(await wallet.feeBumpableTxids.isEmpty)
        do {
            _ = try await wallet.buildFeeBump(txid: original.built.transaction.txid,
                                              feeRateSatPerVByte: 5)
            Issue.record("a changeless same-input spend cannot be bumped")
        } catch let error as FeeBumpError {
            #expect(error == .noChangeOutput)
        }
    }

    @Test("a parent whose pending change was spent by a child refuses a bump")
    func feeBumpRefusesSpentChange() async throws {
        let wallet = try await makeWallet()
        let fundingScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 150_000, scriptPubKey: fundingScript),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        let destination = Data([0x51, 0x20] + repeatElement(0x55, count: 32))
        let parent = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)], feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(parent)

        // The only spendable UTXO is now the parent's height-0 change, so the
        // child spend is forced onto it.
        let child = try await wallet.buildSend(
            payments: [Payment(amount: 20_000, scriptPubKey: destination)], feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        #expect(child.built.transaction.inputs.contains {
            $0.previousOutput.txid == parent.built.transaction.txid
        })
        try await wallet.commit(child)

        // The parent's change has left the UTXO set; a same-input replacement
        // of the parent would orphan the committed child.
        #expect(!(await wallet.feeBumpableTxids).contains(parent.built.transaction.txid))
        do {
            _ = try await wallet.buildFeeBump(txid: parent.built.transaction.txid,
                                              feeRateSatPerVByte: 5)
            Issue.record("bumping the parent would orphan the committed child spend")
        } catch let error as FeeBumpError {
            #expect(error == .changeAlreadySpent)
        }
    }

    @Test("fee bump removes change when the higher-fee remainder becomes dust")
    func feeBumpDropsDustChange() async throws {
        let wallet = try await makeWallet()
        let fundingScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 101_000, scriptPubKey: fundingScript),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        let destination = Data([0x51, 0x20] + repeatElement(0x66, count: 32))
        let original = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        let originalChange = try #require(original.built.changeAmount)
        let changeScript = try await wallet.scriptPubKey(chain: .change, index: 0)
        #expect(originalChange >= CoinSelection.dustThreshold(scriptPubKey: changeScript))
        try await wallet.commit(original)

        let replacement = try await wallet.buildFeeBump(
            txid: original.built.transaction.txid, feeRateSatPerVByte: 7)
        #expect(replacement.built.changeAmount == nil)
        #expect(replacement.built.transaction.outputs.count == 1)
        #expect(replacement.built.transaction.outputs[0].value == 100_000)
        #expect(replacement.built.fee == 1_000)
        try await wallet.commitFeeBump(replacement)
        #expect(await wallet.balance == 0)
        #expect(await wallet.feeBumpableTxids.isEmpty)
    }

    @Test("confirmation chooses one replacement-chain member without double-counting change")
    func feeBumpConfirmationRace() async throws {
        let wallet = try await makeWallet()
        let fundingScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 150_000, scriptPubKey: fundingScript),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        let destination = Data([0x51, 0x20] + repeatElement(0x77, count: 32))
        let original = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)], feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(original)
        let replacement = try await wallet.buildFeeBump(
            txid: original.built.transaction.txid, feeRateSatPerVByte: 5)
        try await wallet.commitFeeBump(replacement)

        // The original can still win before the replacement propagates. Its
        // confirmation discards the descendant row/change and restores only
        // the original change as confirmed.
        let effect = try await wallet.apply(match: fakeMatch(
            height: 150, transactions: [original.built.transaction]))
        #expect(effect.discardedReplacements == [replacement.built.transaction.txid])
        let history = await wallet.history
        #expect(history.first { $0.txid == original.built.transaction.txid }?.height == 150)
        #expect(history.first { $0.txid == original.built.transaction.txid }?.replacedBy == nil)
        #expect(history.first { $0.txid == replacement.built.transaction.txid } == nil)
        #expect(await wallet.utxos.contains {
            $0.txid == original.built.transaction.txid && $0.height == 150
        })
        #expect(!(await wallet.utxos).contains { $0.txid == replacement.built.transaction.txid })
    }

    @Test("a middle replacement confirming discards only its later descendants")
    func feeBumpMiddleConfirmation() async throws {
        let wallet = try await makeWallet()
        let fundingScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 150_000, scriptPubKey: fundingScript),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        let destination = Data([0x51, 0x20] + repeatElement(0x66, count: 32))
        let original = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)], feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(original)
        let first = try await wallet.buildFeeBump(
            txid: original.built.transaction.txid, feeRateSatPerVByte: 5)
        try await wallet.commitFeeBump(first)
        let second = try await wallet.buildFeeBump(
            txid: first.built.transaction.txid, feeRateSatPerVByte: 8)
        try await wallet.commitFeeBump(second)

        let effect = try await wallet.apply(match: fakeMatch(
            height: 150, transactions: [first.built.transaction]))
        #expect(effect.discardedReplacements == [second.built.transaction.txid])
        let history = await wallet.history
        #expect(history.first { $0.txid == original.built.transaction.txid }?.replacedBy
                == first.built.transaction.txid)
        #expect(history.first { $0.txid == first.built.transaction.txid }?.height == 150)
        #expect(history.first { $0.txid == first.built.transaction.txid }?.replacedBy == nil)
        #expect(history.first { $0.txid == second.built.transaction.txid } == nil)
        #expect(await wallet.utxos.contains {
            $0.txid == first.built.transaction.txid && $0.height == 150
        })
        #expect(!(await wallet.utxos).contains { $0.txid == second.built.transaction.txid })
        #expect(await wallet.feeBumpableTxids.isEmpty)
    }

    @Test("an already-relayed replacement confirms safely if its state commit failed")
    func uncommittedFeeBumpConfirmation() async throws {
        let wallet = try await makeWallet()
        let fundingScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 150_000, scriptPubKey: fundingScript),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        let destination = Data([0x51, 0x20] + repeatElement(0x44, count: 32))
        let original = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(original)
        let replacement = try await wallet.buildFeeBump(
            txid: original.built.transaction.txid, feeRateSatPerVByte: 5)

        // Model the broadcast-success / persistence-failure boundary by
        // confirming the built replacement without committing its state swap.
        let effect = try await wallet.apply(match: fakeMatch(
            height: 150, transactions: [replacement.built.transaction]))
        #expect(effect.discardedReplacements == [original.built.transaction.txid])
        #expect(await wallet.history.first {
            $0.txid == original.built.transaction.txid
        }?.replacedBy == replacement.built.transaction.txid)
        let replacementEntry = try await #require(wallet.history.first {
            $0.txid == replacement.built.transaction.txid
        })
        #expect(replacementEntry.height == 150)
        #expect(replacementEntry.spent == 150_000)
        #expect(replacementEntry.fee == replacement.built.fee)
        let replacementChange = try #require(replacement.built.changeAmount)
        #expect(await wallet.balance == replacementChange)
        #expect(await wallet.feeBumpableTxids.isEmpty)
        #expect(!(await wallet.utxos).contains { $0.txid == original.built.transaction.txid })
    }

    @Test("a reordered-input replacement reconciles the losing pending send")
    func reorderedInputReplacementConfirmation() async throws {
        let wallet = try await makeWallet()
        let fundingScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 80_000, scriptPubKey: fundingScript),
            Transaction.Output(value: 80_000, scriptPubKey: fundingScript),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        let destination = Data([0x51, 0x20] + repeatElement(0x33, count: 32))
        let original = try await wallet.buildSend(
            payments: [Payment(amount: 120_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        #expect(original.built.transaction.inputs.count == 2)
        try await wallet.commit(original)

        let prepared = try await wallet.buildFeeBump(
            txid: original.built.transaction.txid, feeRateSatPerVByte: 5)
        let built = prepared.built.transaction
        let reordered = Transaction(version: built.version, inputs: Array(built.inputs.reversed()),
                                    outputs: built.outputs, locktime: built.locktime)
        let effect = try await wallet.apply(match: fakeMatch(
            height: 150, transactions: [reordered]))

        #expect(effect.discardedReplacements == [original.built.transaction.txid])
        #expect(await wallet.history.first {
            $0.txid == original.built.transaction.txid
        }?.replacedBy == reordered.txid)
        #expect(await wallet.history.first { $0.txid == reordered.txid }?.height == 150)
        #expect(!(await wallet.utxos).contains { $0.txid == original.built.transaction.txid })
        #expect(await wallet.utxos.contains { $0.txid == reordered.txid && $0.height == 150 })
        #expect(await wallet.feeBumpableTxids.isEmpty)
    }

    @Test("persistence: state round-trips through Wallet.open")
    func persistence() async throws {
        let url = tempFileURL("wallet.json")
        let keyStore = InMemoryKeyStore()
        let wallet = try await makeWallet(storageURL: url, keyStore: keyStore)
        _ = try await wallet.freshReceiveAddress()
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 42_000, scriptPubKey: script),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))

        let reopened = try await Wallet.open(storageURL: url, keyStore: keyStore)
        let reopenedID = await reopened.id
        #expect(reopenedID == "73c5da0a")
        #expect(await reopened.balance == 42_000)
        #expect(await reopened.nextReceiveIndex == 1)
        #expect(await reopened.history.count == 1)
        let reopenedDescriptor = await reopened.descriptor
        let originalDescriptor = await wallet.descriptor
        #expect(reopenedDescriptor == originalDescriptor)
    }

    @Test("corrupt persisted coin totals fail closed instead of trapping balance")
    func corruptPersistedAmounts() async throws {
        let url = tempFileURL("corrupt-amount-wallet.json")
        let keyStore = InMemoryKeyStore()
        let wallet = try await makeWallet(storageURL: url, keyStore: keyStore)
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 42_000, scriptPubKey: script),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))

        let data = try Data(contentsOf: url)
        var json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        var coins = try #require(json["utxos"] as? [[String: Any]])
        coins[0]["amount"] = BitcoinAmount.maximum
        var second = coins[0]
        second["vout"] = 1
        coins.append(second)
        json["utxos"] = coins
        try JSONSerialization.data(withJSONObject: json).write(to: url, options: .atomic)

        #expect(throws: (any Error).self) {
            _ = try Wallet.open(storageURL: url, keyStore: keyStore)
        }
    }

    @Test("invalid block amounts are rejected atomically before wallet mutation")
    func invalidBlockAmounts() async throws {
        let wallet = try await makeWallet()
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let valid = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 42_000, scriptPubKey: script),
        ], locktime: 0)
        let invalid = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: BitcoinAmount.maximum, scriptPubKey: script),
            Transaction.Output(value: 1, scriptPubKey: Data([0x51])),
        ], locktime: 0)

        await #expect(throws: WalletError.invalidTransactionAmounts) {
            _ = try await wallet.apply(match: fakeMatch(
                height: 100, transactions: [valid, invalid]))
        }
        #expect(await wallet.balance == 0)
        #expect(await wallet.history.isEmpty)
    }

    @Test("zero-value watched outputs are ignored without wedging later blocks")
    func zeroValueWatchedOutputDoesNotWedgeScan() async throws {
        let wallet = try await makeWallet()
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let zero = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 0, scriptPubKey: script),
        ], locktime: 0)

        let effect = try await wallet.apply(match: fakeMatch(height: 100, transactions: [zero]))
        #expect(effect.received.isEmpty)
        #expect(await wallet.balance == 0)
        #expect(await wallet.utxos.isEmpty)
        #expect(await wallet.history.isEmpty)
        #expect(await wallet.nextReceiveIndex == 0)

        let positive = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 42_000, scriptPubKey: script),
        ], locktime: 0)
        _ = try await wallet.apply(match: fakeMatch(height: 101, transactions: [positive]))
        #expect(await wallet.balance == 42_000)
        #expect(await wallet.nextReceiveIndex == 1)
    }

    @Test("wallet state from before fee-bump metadata remains readable")
    func legacyPersistence() async throws {
        let url = tempFileURL("legacy-wallet.json")
        let keyStore = InMemoryKeyStore()
        let wallet = try await makeWallet(storageURL: url, keyStore: keyStore)
        _ = try await wallet.freshReceiveAddress()

        let data = try Data(contentsOf: url)
        var json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        json.removeValue(forKey: "pendingSends")
        json.removeValue(forKey: "observedFeeRates")
        try JSONSerialization.data(withJSONObject: json).write(to: url, options: .atomic)

        let reopened = try Wallet.open(storageURL: url, keyStore: keyStore)
        #expect(await reopened.nextReceiveIndex == 1)
        #expect(await reopened.feeBumpableTxids.isEmpty)
        #expect(await reopened.observedFeeRates.isEmpty)
    }
}
