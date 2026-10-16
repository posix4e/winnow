import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// Tombstones and rollback: what the wallet keeps, hides and rebuilds when a
/// chain reorg takes a block back (#127, #157, SEC-016).
///
/// Two suites merged here, each a section below. They are one subject: the
/// rollback re-derives rather than journalling an undo — chain-derived state is
/// a pure function of chain and keys, so it is rebuilt by rewinding the
/// frontier and rescanning — and that is only possible *because* spent coins
/// are tombstoned rather than deleted. A coin created below the fork and spent
/// above it could never be recovered by a rescan that starts above the fork.
@Suite("Wallet reorg")
struct WalletReorgTests {
    // MARK: - Spent coin tombstones
    //
    // Spent coins are marked rather than deleted (#127, groundwork).
    //
    // The wallet scans forward and never revisits a height it has passed, so
    // after a reorg it cannot rebuild a coin whose *creating* transaction is
    // below the fork -- the rescan range does not reach it. `HistoryEntry`
    // cannot help either: it stores aggregates, with no outpoints, scripts, or
    // derivation indices, so from "this transaction spent 50,000 sats of ours"
    // there is no way back to which coins.
    //
    // So the one fact that was being thrown away is kept. That is deliberately
    // not a general undo journal: it retains a single field at the sites that
    // destroyed it and leaves everything else to be re-derived.
    //
    // What these pin is the part that makes it safe to keep spent rows at all
    // -- that a tombstone can never be mistaken for money.

    /// A matured coin at receive 0, and the txid that funded it.
    private func fundedWalletAndTxid(amount: Int64 = 500_000) async throws -> (Wallet, Data) {
        let funded = try await TestSupport.fundedWallet(coins: [(.receive, 0, amount, 100)])
        return (funded.wallet, funded.fundings[0].txid)
    }

    private var destination: Data { TestScripts.p2trDestination }

    /// A spend seen in a block. The coin leaves the wallet's view entirely --
    /// balance, the coin list, and the spendable set -- while the row survives.
    @Test("a confirmed spend hides the coin but keeps the row")
    func confirmedSpendTombstones() async throws {
        let (wallet, fundingTxid) = try await fundedWalletAndTxid()
        #expect(await wallet.balance == 500_000)

        let spend = Transaction(
            version: 2,
            inputs: [Transaction.Input(previousOutput: .init(txid: fundingTxid, vout: 0),
                                       scriptSig: Data(), sequence: 0xFFFF_FFFD)],
            outputs: [Transaction.Output(value: 400_000, scriptPubKey: destination)],
            locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 150, transactions: [spend]))

        #expect(await wallet.balance == 0, "a spent coin is not money")
        #expect(await wallet.utxos.isEmpty)
        #expect(await wallet.spendableUtxos.isEmpty)

        // …but the row is still there, carrying who spent it and when.
        let rows = await wallet.allUtxos
        let row = try #require(rows.first { $0.txid == fundingTxid })
        #expect(row.spent?.spentBy == spend.txid)
        #expect(row.spent?.height == 150)
    }

    /// Our own send, before any block confirms it. The height is absent, and
    /// that absence is the thing a rollback has to respect: the broadcaster
    /// keeps re-relaying this transaction, so restoring the coin while it is
    /// still in flight would make the wallet double-spend itself.
    @Test("committing our own send tombstones with no height")
    func ownSendTombstonesWithoutHeight() async throws {
        let (wallet, fundingTxid) = try await fundedWalletAndTxid()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: { 0.5 })
        try await wallet.commit(prepared)

        let rows = await wallet.allUtxos
        let row = try #require(rows.first { $0.txid == fundingTxid })
        #expect(row.spent?.spentBy == prepared.built.transaction.txid)
        #expect(row.spent?.height == nil, "an unconfirmed spend has no depth to record")
        #expect(await wallet.utxos.contains { $0.txid == fundingTxid } == false)
    }

    /// The tightest constraint: a tombstone must never be selectable. If it
    /// could reach coin selection the wallet would build a transaction
    /// spending a coin it has already spent.
    @Test("a tombstoned coin cannot be selected for a send")
    func tombstonedCoinIsNotSelectable() async throws {
        let (wallet, _) = try await fundedWalletAndTxid()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: { 0.5 })
        try await wallet.commit(prepared)

        // Only the change output remains, so a send larger than it must fail
        // for want of coins rather than quietly re-spending the input.
        await #expect(throws: CoinSelectionError.self) {
            try await wallet.buildSend(
                payments: [Payment(amount: 450_000, scriptPubKey: self.destination)],
                feeRateSatPerVByte: 2, chainTip: 840_000, randomness: { 0.5 })
        }
    }

    /// The transition between the two states, which the other tests skip by
    /// only ever looking at one end of it.
    ///
    /// A coin spent by our own send is tombstoned at commit with no height,
    /// and the block that confirms that send is the only place the height can
    /// be learned. Miss it and the row is never prunable -- pruning measures
    /// depth and a nil height has none -- and a rollback cannot tell an
    /// in-flight spend from a buried one.
    @Test("a pending tombstone gains its height when the spend confirms")
    func pendingTombstoneIsUpgradedOnConfirmation() async throws {
        let (wallet, fundingTxid) = try await fundedWalletAndTxid()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: { 0.5 })
        try await wallet.commit(prepared)
        #expect(await wallet.allUtxos.first { $0.txid == fundingTxid }?.spent?.height == nil)

        try await wallet.apply(match: fakeMatch(height: 200,
                                                transactions: [prepared.built.transaction]))

        let row = try #require(await wallet.allUtxos.first { $0.txid == fundingTxid })
        #expect(row.spent?.height == 200, "the confirming block is where the height comes from")
        #expect(row.spent?.spentBy == prepared.built.transaction.txid)
    }

    /// …and once it has a height it can finally be pruned. Without the upgrade
    /// every own spend leaves a row that pruning can never reach, so the
    /// bounded-storage claim is false for the case that dominates.
    @Test("an own spend becomes prunable once it confirms")
    func ownSpendBecomesPrunable() async throws {
        let (wallet, fundingTxid) = try await fundedWalletAndTxid()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: { 0.5 })
        try await wallet.commit(prepared)
        try await wallet.apply(match: fakeMatch(height: 200,
                                                transactions: [prepared.built.transaction]))

        try await wallet.recordScanHeight(200 + Wallet.spentCoinHorizon + 1)
        #expect(await wallet.allUtxos.contains { $0.txid == fundingTxid } == false,
                "a confirmed own spend must not leave a permanent row")
    }

    // MARK: The file format

    /// A state file written before this change has no `spent` key anywhere.
    /// Every row in it is a coin, because that build deleted the others.
    @Test("a state file without the field loads with every row live")
    func legacyStateFileLoads() throws {
        let json = """
        {"descriptor":"tr(tpub)","network":"signet","creationHeight":100,
         "nextReceiveIndex":1,"nextChangeIndex":0,"nextScanHeight":200,
         "utxos":[{"txid":"\(String(repeating: "ab", count: 32))","vout":0,"amount":150000,
                   "scriptPubKey":"5120\(String(repeating: "cd", count: 32))",
                   "chain":0,"index":0,"height":101}],
         "history":[],"observedFeeRates":[]}
        """
        let state = try JSONDecoder().decode(WalletState.self, from: Data(json.utf8))
        #expect(state.allUtxos.count == 1)
        #expect(state.utxos.count == 1, "an old row is a live coin")
        #expect(state.allUtxos[0].isSpent == false)
    }

    /// A live coin still encodes exactly as before, so the format only changes
    /// once there is something new to say.
    @Test("an unspent row emits no spent key")
    func unspentRowIsByteIdentical() throws {
        let coin = WalletUTXO(txid: Data(repeating: 0xAB, count: 32), vout: 0, amount: 1_000,
                              scriptPubKey: Data([0x51, 0x20] + repeatElement(0xCD, count: 32)),
                              chain: .receive, index: 0, height: 101)
        let encoded = try JSONEncoder().encode(coin)
        let text = String(decoding: encoded, as: UTF8.self)
        #expect(!text.contains("spent"))

        var spentCoin = coin
        spentCoin.spent = WalletUTXO.SpentMarker(spentBy: Data(repeating: 0x01, count: 32),
                                                 height: 150)
        let roundTripped = try JSONDecoder().decode(
            WalletUTXO.self, from: try JSONEncoder().encode(spentCoin))
        #expect(roundTripped == spentCoin, "the marker survives a round trip")
    }

    /// Moved here from the "Wallet" suite: what it pins is the tombstone, not
    /// the wallet's ordinary persistence. A corrupted spent row is dangerous
    /// precisely because a rollback past the spend would turn it back into a
    /// live coin carrying that amount.
    @Test("a tampered tombstone fails closed on load instead of waiting to be resurrected")
    func corruptPersistedTombstone() async throws {
        let url = tempFileURL("corrupt-tombstone-wallet.json")
        let keyStore = InMemoryKeyStore()
        let (wallet, _) = try await fundedWallet(storageURL: url, keyStore: keyStore,
                                                coins: [(.receive, 0, 150_000, 100)])
        let destination = TestScripts.p2trDestination
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)], feeRateSatPerVByte: 2,
            chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(prepared)
        _ = try Wallet.open(storageURL: url, keyStore: keyStore) // the untouched file loads

        // The spent row's amount is corrupted. A rollback past the spend
        // would have turned it into a live coin with that amount.
        let data = try Data(contentsOf: url)
        var json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        var coins = try #require(json["utxos"] as? [[String: Any]])
        let spentIndex = try #require(coins.firstIndex { $0["spent"] != nil })
        coins[spentIndex]["amount"] = 0
        json["utxos"] = coins
        try JSONSerialization.data(withJSONObject: json).write(to: url, options: .atomic)

        #expect(throws: (any Error).self) {
            _ = try Wallet.open(storageURL: url, keyStore: keyStore)
        }
    }

    // MARK: Bounded storage

    /// Tombstones are not kept forever, or a wallet that spends often grows a
    /// state file without bound.
    @Test("confirmed tombstones are pruned past the horizon")
    func prunedPastTheHorizon() async throws {
        let (wallet, fundingTxid) = try await fundedWalletAndTxid()
        let spend = Transaction(
            version: 2,
            inputs: [Transaction.Input(previousOutput: .init(txid: fundingTxid, vout: 0),
                                       scriptSig: Data(), sequence: 0xFFFF_FFFD)],
            outputs: [Transaction.Output(value: 400_000, scriptPubKey: destination)],
            locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 150, transactions: [spend]))
        #expect(await wallet.allUtxos.contains { $0.txid == fundingTxid })

        // Exactly at the horizon it must still be there: a reorg this deep is
        // the case the row exists for.
        try await wallet.recordScanHeight(150 + Wallet.spentCoinHorizon)
        #expect(await wallet.allUtxos.contains { $0.txid == fundingTxid },
                "the row must survive to the full horizon depth")

        try await wallet.recordScanHeight(150 + Wallet.spentCoinHorizon + 1)
        #expect(await wallet.allUtxos.contains { $0.txid == fundingTxid } == false)
    }

    /// A spend still in flight has no depth, so it cannot be buried. Pruning it
    /// would lose the coin with no block having decided anything.
    @Test("an in-flight spend is never pruned")
    func inFlightSpendSurvivesPruning() async throws {
        let (wallet, fundingTxid) = try await fundedWalletAndTxid()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: { 0.5 })
        try await wallet.commit(prepared)

        try await wallet.recordScanHeight(100_000)
        #expect(await wallet.allUtxos.contains { $0.txid == fundingTxid },
                "an unconfirmed spend has no depth and must not be pruned")
    }

    // MARK: What still sees every row

    /// The filter watch set keeps a spent coin's script, so a rescan after a
    /// reorg can find the coin again.
    @Test("watch scripts still cover a spent coin")
    func watchScriptsCoverSpentCoins() async throws {
        let (wallet, fundingTxid) = try await fundedWalletAndTxid()
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let spend = Transaction(
            version: 2,
            inputs: [Transaction.Input(previousOutput: .init(txid: fundingTxid, vout: 0),
                                       scriptSig: Data(), sequence: 0xFFFF_FFFD)],
            outputs: [Transaction.Output(value: 400_000, scriptPubKey: destination)],
            locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 150, transactions: [spend]))

        #expect(try await wallet.watchScripts().contains(script),
                "a rescan must still be able to re-find the coin")
    }

    // MARK: - Reorg rollback
    //
    // The wallet rolls back after a chain reorg (#127, SEC-016).
    //
    // `HeaderChain` handled reorgs correctly and the wallet never heard about
    // it. Meanwhile the wallet scans forward and never revisits a height it has
    // passed, so after a reorg removed a block it had credited: a payment
    // stayed recorded as confirmed when it no longer existed, a coin stayed
    // spendable when it was never mined into the surviving branch, and a send
    // built on that coin was assembled locally and rejected by the network.
    //
    // Short reorgs are ordinary on mainnet. This is a routine condition, not an
    // attack.

    /// A coin confirmed above the fork and reserved by our own in-flight send:
    /// funded at 220 and matured, spent by a committed send, then rolled back
    /// to 200. Returns the funding transaction too, so a test can re-find it.
    private func reservedCoinAboveFork() async throws
        -> (wallet: Wallet, funding: Transaction, prepared: Wallet.PreparedSend) {
        let (wallet, fundings) = try await fundedWallet(coins: [(.receive, 0, 500_000, 220)])
        let funding = fundings[0]

        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 319, randomness: { 0.5 })
        try await wallet.commit(prepared)

        try await wallet.rollBack(to: 200)
        return (wallet, funding, prepared)
    }

    // MARK: Block hashes

    /// A payment remembers the block it confirmed in, so a restore can check
    /// it against headers instead of fetching the block again. A rewind that
    /// sends it back to pending forgets the block it left.
    @Test("a confirmed payment keeps its block hash until a rewind re-pends it")
    func blockHashFollowsConfirmation() async throws {
        let (wallet, fundingTxid) = try await fundedWalletAndTxid()
        let spend = Transaction(
            version: 2,
            inputs: [Transaction.Input(previousOutput: .init(txid: fundingTxid, vout: 0),
                                       scriptSig: Data(), sequence: 0xFFFF_FFFD)],
            outputs: [Transaction.Output(value: 400_000, scriptPubKey: destination)],
            locktime: 0)
        let match = fakeMatch(height: 250, transactions: [spend])
        try await wallet.apply(match: match)
        let funding = try #require(await wallet.history.first { $0.txid == fundingTxid })
        #expect(funding.blockHash != nil)
        #expect(await wallet.history.first { $0.txid == spend.txid }?.blockHash == match.blockHash)

        try await wallet.rollBack(to: 200)

        let repended = try #require(await wallet.history.first { $0.txid == spend.txid })
        #expect(repended.height == 0)
        #expect(repended.blockHash == nil, "a pending payment is in no block")
        #expect(await wallet.history.first { $0.txid == fundingTxid }?.blockHash == funding.blockHash,
                "below the fork, nothing changes")
    }

    @Test("our own send gains its block hash when a block confirms it")
    func ownSendGainsBlockHash() async throws {
        let (wallet, _) = try await fundedWalletAndTxid()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: { 0.5 })
        try await wallet.commit(prepared)
        let txid = prepared.built.transaction.txid
        #expect(await wallet.history.first { $0.txid == txid }?.blockHash == nil)

        let match = fakeMatch(height: 840_001, transactions: [prepared.built.transaction])
        try await wallet.apply(match: match)
        #expect(await wallet.history.first { $0.txid == txid }?.blockHash == match.blockHash)
    }

    @Test("the scan frontier keeps its block hash, and a rewind behind it clears it")
    func frontierHash() async throws {
        let url = tempFileURL("frontier-hash-wallet.json")
        let keyStore = InMemoryKeyStore()
        let wallet = try makeTestWallet(storageURL: url, keyStore: keyStore)
        let hash = Data(repeating: 0xAB, count: 32)
        try await wallet.recordScanHeight(301, scannedThroughHash: hash)
        #expect(await wallet.scannedThroughHash == hash)
        #expect(try await Wallet.open(storageURL: url, keyStore: keyStore).scannedThroughHash == hash)

        try await wallet.rollBack(to: 200)
        #expect(await wallet.nextScanHeight == 201)
        #expect(await wallet.scannedThroughHash == nil, "block 300 is no longer known to be on the chain")

        try await wallet.recordScanHeight(301, scannedThroughHash: hash)
        try await wallet.recordScanHeight(302)
        #expect(await wallet.scannedThroughHash == nil, "a hash is never left describing another height")
    }

    // MARK: What a reorg takes away

    /// A payment that only existed on the orphaned branch.
    @Test("a receive confirmed above the fork is dropped")
    func orphanedReceiveIsDropped() async throws {
        let wallet = try makeTestWallet()
        try await fund(wallet, amount: 150_000, height: 100)
        try await fund(wallet, amount: 250_000, height: 220, index: 1)
        try await wallet.recordScanHeight(221)
        #expect(await wallet.balance == 400_000)

        try await wallet.rollBack(to: 200)

        #expect(await wallet.balance == 150_000, "only the pre-fork coin survives")
        #expect(await wallet.utxos.count == 1)
        #expect(await wallet.nextScanHeight == 201, "those heights must be read again")
        #expect(await wallet.history.contains { $0.height > 200 } == false)
    }

    /// A disconnected spend of our coin is not undone — it is re-pended
    /// (#157). The reorg removed it from the chain, but every node that saw
    /// it put it back in its mempool, so the transaction is *in flight*:
    /// restoring the coin as selectable built conflicting sends the network
    /// rejected, which is the exact symptom #127 exists to eliminate. The coin
    /// row survives (the reason coins are tombstoned at all — nothing above
    /// the fork can recreate a coin created below it), reserved by a now
    /// heightless marker; the payment survives as pending instead of
    /// vanishing mid-flight.
    @Test("a coin spent above the fork stays reserved for the still-live spend")
    func spendAboveForkStaysReserved() async throws {
        let wallet = try makeTestWallet()
        let fundingTxid = try await fund(wallet, amount: 150_000, height: 100).txid

        let spend = Transaction(
            version: 2,
            inputs: [Transaction.Input(previousOutput: .init(txid: fundingTxid, vout: 0),
                                       scriptSig: Data(), sequence: 0xFFFF_FFFD)],
            outputs: [Transaction.Output(value: 100_000, scriptPubKey: destination)],
            locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 220, transactions: [spend]))
        try await wallet.recordScanHeight(221)
        #expect(await wallet.balance == 0)

        try await wallet.rollBack(to: 200)

        let coin = try #require(await wallet.allUtxos.first)
        let marker = try #require(coin.spent, "the reservation must survive the rollback")
        #expect(marker.height == nil, "in flight again, not confirmed")
        #expect(marker.spentBy == spend.txid)
        #expect(await wallet.utxos.isEmpty, "a reserved coin is not selectable")
        let entry = try #require(await wallet.history.first { $0.txid == spend.txid },
                                 "the payment must stay visible")
        #expect(entry.height == 0, "pending again, exactly like a fresh own send")
    }

    /// The acceptance case #157 names: after the reorg, a send cannot be built
    /// from the coin the still-live transaction is spending.
    @Test("a send built after the reorg cannot conflict with the live spend")
    func noConflictingSendAfterReorg() async throws {
        let wallet = try makeTestWallet()
        let fundingTxid = try await fund(wallet, amount: 150_000, height: 100).txid
        let spend = Transaction(
            version: 2,
            inputs: [Transaction.Input(previousOutput: .init(txid: fundingTxid, vout: 0),
                                       scriptSig: Data(), sequence: 0xFFFF_FFFD)],
            outputs: [Transaction.Output(value: 100_000, scriptPubKey: destination)],
            locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 220, transactions: [spend]))
        try await wallet.recordScanHeight(221)
        try await wallet.rollBack(to: 200)

        await #expect(throws: (any Error).self,
                      "the only coin is reserved by a live transaction; selecting it builds a conflict") {
            _ = try await wallet.buildSend(
                payments: [Payment(amount: 50_000, scriptPubKey: self.destination)],
                feeRateSatPerVByte: 2, chainTip: 200, randomness: { 0.5 })
        }
    }

    /// The healing path: when the re-pended spend confirms again on the new
    /// branch, the existing tombstone upgrade re-heights the marker and the
    /// history entry — the same machinery a fresh pending send uses.
    @Test("the re-pended spend heals when it confirms on the new branch")
    func rependedSpendReconfirms() async throws {
        let wallet = try makeTestWallet()
        let fundingTxid = try await fund(wallet, amount: 150_000, height: 100).txid
        let spend = Transaction(
            version: 2,
            inputs: [Transaction.Input(previousOutput: .init(txid: fundingTxid, vout: 0),
                                       scriptSig: Data(), sequence: 0xFFFF_FFFD)],
            outputs: [Transaction.Output(value: 100_000, scriptPubKey: destination)],
            locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 220, transactions: [spend]))
        try await wallet.recordScanHeight(221)
        try await wallet.rollBack(to: 200)

        try await wallet.apply(match: fakeMatch(height: 205, transactions: [spend]))

        let coin = try #require(await wallet.allUtxos.first)
        #expect(coin.spent?.height == 205, "the marker re-heights at the new confirmation")
        let entry = try #require(await wallet.history.first { $0.txid == spend.txid })
        #expect(entry.height == 205, "the payment is confirmed again, at its new height")
    }

    /// The exemption that stops the rollback double-spending the wallet against
    /// itself. Our own transaction is still being relayed by the broadcaster,
    /// so its inputs must stay reserved even though the rollback is restoring
    /// other spends.
    @Test("a spend still in flight is not restored")
    func inFlightSpendStaysReserved() async throws {
        let wallet = try makeTestWallet()
        try await fund(wallet, amount: 500_000, height: 100)
        try await wallet.recordScanHeight(221)

        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 220, randomness: { 0.5 })
        try await wallet.commit(prepared)
        let selected = prepared.selected.map(\.outpoint)

        try await wallet.rollBack(to: 200)

        let restored = await wallet.utxos.map(\.outpoint)
        for outpoint in selected {
            #expect(restored.contains(outpoint) == false,
                    "our own transaction is still in flight; its inputs stay spent")
        }
    }

    /// The same exemption when the reserved coin was itself confirmed above
    /// the fork. Dropping its row with the block that carried it, like any
    /// other orphaned receive, forgets the reservation: the rescan re-finds
    /// the funding and admits a fresh, unspent, selectable coin while the
    /// broadcaster is still relaying the send that spends it -- the wallet
    /// double-spending itself. The row stays instead, reserved at height 0,
    /// until the rescan re-heights it and the send confirms on top.
    @Test("an in-flight spend of a coin above the fork stays reserved")
    func inFlightSpendOfACoinAboveTheForkStaysReserved() async throws {
        let (wallet, funding, prepared) = try await reservedCoinAboveFork()
        let sendTxid = prepared.built.transaction.txid
        let change = try #require(prepared.built.changeAmount)

        let reserved = try #require(await wallet.allUtxos.first { $0.txid == funding.txid },
                                    "the row must survive the rollback")
        #expect(reserved.height == 0, "not in a block yet, until the rescan finds it again")
        #expect(reserved.spent?.height == nil, "still in flight")
        #expect(reserved.spent?.spentBy == sendTxid)
        #expect(await wallet.utxos.contains { $0.txid == funding.txid } == false,
                "a reserved coin is not selectable")

        // The rescan re-finds the funding on the new branch: the row is
        // re-heighted, not duplicated, and the receive returns to history.
        try await wallet.apply(match: fakeMatch(height: 205, transactions: [funding]))
        let refound = try #require(await wallet.allUtxos.first { $0.txid == funding.txid })
        #expect(refound.height == 205)
        #expect(await wallet.utxos.contains { $0.txid == funding.txid } == false,
                "re-found, and still reserved")
        let receive = try #require(await wallet.history.first { $0.txid == funding.txid },
                                   "the receive the rollback dropped is back")
        #expect(receive.height == 205)
        #expect(receive.received == 500_000)

        // Then the send confirms, through the same tombstone upgrade a fresh
        // pending send uses.
        try await wallet.apply(match: fakeMatch(height: 206,
                                                transactions: [prepared.built.transaction]))
        let spentRow = try #require(await wallet.allUtxos.first { $0.txid == funding.txid })
        #expect(spentRow.spent?.height == 206, "the marker heights at the confirmation")
        let entry = try #require(await wallet.history.first { $0.txid == sendTxid })
        #expect(entry.height == 206)
        #expect(await wallet.balance == change, "only the change is ours to spend")
    }

    // MARK: What a reorg must never take away

    /// The highest-consequence invariant here. Rewinding the address indices
    /// would hand out an address that has already been given to someone, which
    /// is a privacy regression in a wallet whose whole argument is that it
    /// discloses nothing. A reorg must never cost the user their address gap.
    @Test("address indices and identity survive a rollback")
    func intentStateIsUntouched() async throws {
        let wallet = try makeTestWallet()
        try await fund(wallet, amount: 150_000, height: 210)
        _ = try await wallet.scriptPubKey(chain: .receive, index: 4)
        try await wallet.recordScanHeight(230)

        let descriptor = await wallet.descriptor.serialized()
        let receiveIndex = await wallet.nextReceiveIndex
        let changeIndex = await wallet.nextChangeIndex
        let creationHeight = await wallet.creationHeight

        try await wallet.rollBack(to: 200)

        #expect(await wallet.nextReceiveIndex == receiveIndex,
                "an address already handed out must never be handed out again")
        #expect(await wallet.nextChangeIndex == changeIndex)
        #expect(await wallet.creationHeight == creationHeight)
        #expect(await wallet.descriptor.serialized() == descriptor)
    }

    /// Height 0 means "not in a block yet", not "in block zero", so pending
    /// state is not above any fork and must survive.
    @Test("pending change and pending history survive")
    func pendingStateSurvives() async throws {
        let wallet = try makeTestWallet()
        try await fund(wallet, amount: 500_000, height: 100)
        try await wallet.recordScanHeight(221)
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 220, randomness: { 0.5 })
        try await wallet.commit(prepared)

        let pendingBefore = await wallet.utxos.filter { $0.height == 0 }.count
        #expect(pendingBefore > 0, "the change output is pending")

        try await wallet.rollBack(to: 200)

        #expect(await wallet.utxos.filter { $0.height == 0 }.count == pendingBefore,
                "a pending coin is not above the fork; it is not in a block at all")
    }

    // MARK: Properties the crash marker relies on

    /// Idempotence is what turns crash recovery into a redo rather than a
    /// repair: the marker names a height, and running the rollback again is
    /// indistinguishable from having run it once.
    @Test("rolling back twice is the same as once")
    func rollbackIsIdempotent() async throws {
        let wallet = try makeTestWallet()
        try await fund(wallet, amount: 150_000, height: 100)
        try await fund(wallet, amount: 250_000, height: 220, index: 1)
        try await wallet.recordScanHeight(221)

        try await wallet.rollBack(to: 200)
        let once = await wallet.allUtxos
        let frontier = await wallet.nextScanHeight

        try await wallet.rollBack(to: 200)
        #expect(await wallet.allUtxos == once)
        #expect(await wallet.nextScanHeight == frontier)
    }

    /// A reserved row the rollback kept is re-heighted to 0, and height 0 is
    /// not above any fork: a second run finds nothing left to do.
    @Test("rolling back twice is the same as once with a reserved, re-heighted row")
    func rollbackIsIdempotentWithAReservedRelinkedRow() async throws {
        let (wallet, funding, _) = try await reservedCoinAboveFork()
        let once = await wallet.allUtxos
        #expect(once.contains { $0.txid == funding.txid && $0.height == 0 },
                "the fixture holds a reserved, re-heighted row")

        try await wallet.rollBack(to: 200)
        #expect(await wallet.allUtxos == once)
    }

    /// A fork at or above the frontier leaves nothing that was scanned in
    /// doubt. Advancing here would skip blocks that have never been read.
    @Test("a rollback never moves the frontier forward")
    func frontierNeverAdvances() async throws {
        let wallet = try makeTestWallet()
        try await fund(wallet, amount: 150_000, height: 100)
        try await wallet.recordScanHeight(150)

        try await wallet.rollBack(to: 900)

        #expect(await wallet.nextScanHeight == 150,
                "unread blocks must not be skipped by a rollback above the frontier")
        #expect(await wallet.balance == 150_000)
    }
}
