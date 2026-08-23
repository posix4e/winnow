import BitcoinCore
import BitcoinP2P
import Foundation
import Testing
@testable import WalletCore

/// Spent coins are marked rather than deleted (#127, groundwork).
///
/// The wallet scans forward and never revisits a height it has passed, so after
/// a reorg it cannot rebuild a coin whose *creating* transaction is below the
/// fork -- the rescan range does not reach it. `HistoryEntry` cannot help
/// either: it stores aggregates, with no outpoints, scripts, or derivation
/// indices, so from "this transaction spent 50,000 sats of ours" there is no
/// way back to which coins.
///
/// So the one fact that was being thrown away is kept. That is deliberately
/// not a general undo journal: it retains a single field at the sites that
/// destroyed it and leaves everything else to be re-derived.
///
/// What these pin is the part that makes it safe to keep spent rows at all --
/// that a tombstone can never be mistaken for money.
@Suite("Spent coin tombstones")
struct SpentCoinTombstoneTests {
    private func fundedWallet(amount: Int64 = 500_000) async throws -> (Wallet, Data) {
        let wallet = try await Wallet.create(network: .signet, keyStore: InMemoryKeyStore(),
                                             storageURL: nil, entropy: testEntropy,
                                             creationHeight: 100)
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: amount, scriptPubKey: script),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        return (wallet, funding.txid)
    }

    private var destination: Data { Data([0x51, 0x20] + repeatElement(0x99, count: 32)) }

    /// A spend seen in a block. The coin leaves the wallet's view entirely --
    /// balance, the coin list, and the spendable set -- while the row survives.
    @Test("a confirmed spend hides the coin but keeps the row")
    func confirmedSpendTombstones() async throws {
        let (wallet, fundingTxid) = try await fundedWallet()
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
        let (wallet, fundingTxid) = try await fundedWallet()
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
        let (wallet, _) = try await fundedWallet()
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
        let (wallet, fundingTxid) = try await fundedWallet()
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
        let (wallet, fundingTxid) = try await fundedWallet()
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

    // MARK: - The file format

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

    // MARK: - Bounded storage

    /// Tombstones are not kept forever, or a wallet that spends often grows a
    /// state file without bound.
    @Test("confirmed tombstones are pruned past the horizon")
    func prunedPastTheHorizon() async throws {
        let (wallet, fundingTxid) = try await fundedWallet()
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
        let (wallet, fundingTxid) = try await fundedWallet()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: { 0.5 })
        try await wallet.commit(prepared)

        try await wallet.recordScanHeight(100_000)
        #expect(await wallet.allUtxos.contains { $0.txid == fundingTxid },
                "an unconfirmed spend has no depth and must not be pruned")
    }

    // MARK: - What still sees every row

    /// The filter watch set keeps a spent coin's script, so a rescan after a
    /// reorg can find the coin again.
    @Test("watch scripts still cover a spent coin")
    func watchScriptsCoverSpentCoins() async throws {
        let (wallet, fundingTxid) = try await fundedWallet()
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
}
