import BitcoinCore
import BitcoinP2P
import Foundation
import Testing
@testable import WalletCore

/// The wallet rolls back after a chain reorg (#127, SEC-016).
///
/// `HeaderChain` handled reorgs correctly and the wallet never heard about it.
/// Meanwhile the wallet scans forward and never revisits a height it has
/// passed, so after a reorg removed a block it had credited: a payment stayed
/// recorded as confirmed when it no longer existed, a coin stayed spendable
/// when it was never mined into the surviving branch, and a send built on that
/// coin was assembled locally and rejected by the network.
///
/// Short reorgs are ordinary on mainnet. This is a routine condition, not an
/// attack.
///
/// The rollback re-derives rather than journalling an undo: chain-derived
/// state is a pure function of chain and keys, so it is rebuilt by rewinding
/// the frontier and rescanning. That is only possible because spent coins are
/// tombstoned rather than deleted -- a coin created below the fork and spent
/// above it could never be recovered by a rescan that starts above the fork.
@Suite("Reorg rollback")
struct ReorgRollbackTests {
    private var destination: Data { Data([0x51, 0x20] + repeatElement(0x99, count: 32)) }

    private func wallet() async throws -> Wallet {
        try await Wallet.create(network: .signet, keyStore: InMemoryKeyStore(),
                                storageURL: nil, entropy: testEntropy, creationHeight: 100)
    }

    /// Funds the wallet at `height` and returns the funding txid.
    @discardableResult
    private func fund(_ wallet: Wallet, amount: Int64, height: UInt32,
                      index: UInt32 = 0) async throws -> Data {
        let script = try await wallet.scriptPubKey(chain: .receive, index: index)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: amount, scriptPubKey: script),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: height, transactions: [funding]))
        return funding.txid
    }

    // MARK: - What a reorg takes away

    /// A payment that only existed on the orphaned branch.
    @Test("a receive confirmed above the fork is dropped")
    func orphanedReceiveIsDropped() async throws {
        let wallet = try await wallet()
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
        let wallet = try await wallet()
        let fundingTxid = try await fund(wallet, amount: 150_000, height: 100)

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
        let wallet = try await wallet()
        let fundingTxid = try await fund(wallet, amount: 150_000, height: 100)
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
        let wallet = try await wallet()
        let fundingTxid = try await fund(wallet, amount: 150_000, height: 100)
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
        let wallet = try await wallet()
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

    // MARK: - What a reorg must never take away

    /// The highest-consequence invariant here. Rewinding the address indices
    /// would hand out an address that has already been given to someone, which
    /// is a privacy regression in a wallet whose whole argument is that it
    /// discloses nothing. A reorg must never cost the user their address gap.
    @Test("address indices and identity survive a rollback")
    func intentStateIsUntouched() async throws {
        let wallet = try await wallet()
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
        let wallet = try await wallet()
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

    // MARK: - Properties the crash marker relies on

    /// Idempotence is what turns crash recovery into a redo rather than a
    /// repair: the marker names a height, and running the rollback again is
    /// indistinguishable from having run it once.
    @Test("rolling back twice is the same as once")
    func rollbackIsIdempotent() async throws {
        let wallet = try await wallet()
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

    /// A fork at or above the frontier leaves nothing that was scanned in
    /// doubt. Advancing here would skip blocks that have never been read.
    @Test("a rollback never moves the frontier forward")
    func frontierNeverAdvances() async throws {
        let wallet = try await wallet()
        try await fund(wallet, amount: 150_000, height: 100)
        try await wallet.recordScanHeight(150)

        try await wallet.rollBack(to: 900)

        #expect(await wallet.nextScanHeight == 150,
                "unread blocks must not be skipped by a rollback above the frontier")
        #expect(await wallet.balance == 150_000)
    }
}
