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

    /// The case a rescan alone cannot fix, and the reason coins are tombstoned:
    /// the coin was created below the fork, so nothing above the fork can
    /// recreate it. Only the retained row can give it back.
    @Test("a coin spent above the fork comes back")
    func spendAboveForkIsUndone() async throws {
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

        #expect(await wallet.balance == 150_000, "the spend was never mined on this branch")
        #expect(await wallet.utxos.first?.txid == fundingTxid)
        #expect(await wallet.allUtxos.first?.spent == nil, "the tombstone is cleared")
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
