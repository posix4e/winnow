import BitcoinCore
import BitcoinP2P
import Foundation
import Testing
@testable import WalletCore

/// A draw sequence the test controls, so both randomness branches can be
/// exercised without sampling a live RNG.
///
/// `antiFeeSnipingLocktime` draws twice -- once to choose the branch, once for
/// the size of the lookback -- and those have to be set independently, which a
/// closure returning a constant cannot do. The last value repeats once the
/// sequence runs out, so a caller only has to supply the draws it cares about.
final class DrawSequence: @unchecked Sendable {
    private let lock = NSLock()
    private let values: [Double]
    private var index = 0

    init(_ values: Double...) { self.values = values }

    /// Passed as `randomness:`.
    var next: @Sendable () -> Double {
        { [self] in
            lock.lock(); defer { lock.unlock() }
            let value = values[min(index, values.count - 1)]
            index += 1
            return value
        }
    }
}

/// Anti-fee-sniping locktimes (#139).
///
/// Bitcoin Core stamps every transaction it builds with the current block
/// height, so a transaction cannot be mined into an *earlier* block and a miner
/// gains nothing by re-mining the previous one to take its fees. Most wallets
/// copy it, and that is the point here: a transaction carrying `nLockTime = 0`
/// is trivially distinguishable from a Core-built one, so it discloses which
/// software made it to anyone reading the chain.
///
/// For a wallet whose whole argument is that it discloses nothing, that is a
/// poor trade for no benefit. What these pin is that a send now sits inside the
/// existing crowd, and that it never lands in the future -- a locktime above
/// the tip is not final and would not relay.
@Suite("Anti-fee-sniping locktime")
struct AntiFeeSnipingTests {
    private func makeFundedWallet() async throws -> Wallet {
        let wallet = try await Wallet.create(network: .signet, keyStore: InMemoryKeyStore(),
                                             storageURL: nil, entropy: testEntropy,
                                             creationHeight: 100)
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 500_000, scriptPubKey: script),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        return wallet
    }

    private var destination: Data { Data([0x51, 0x20] + repeatElement(0x99, count: 32)) }

    // MARK: - The rule itself

    /// Nine times in ten, exactly the tip.
    @Test("the common branch stamps the tip exactly")
    func commonBranchIsTheTip() {
        for draw in [0.1, 0.5, 0.9, 0.999] {
            #expect(TransactionBuilder.antiFeeSnipingLocktime(tip: 840_000,
                                                              randomness: DrawSequence(draw).next)
                    == 840_000, "draw \(draw) must not take the lookback branch")
        }
    }

    /// One time in ten, a height from the previous hundred blocks. Both draws
    /// are pinned, so this asserts the arithmetic and not a coin flip.
    @Test("the lookback branch reaches back by the second draw")
    func lookbackBranchUsesSecondDraw() {
        // 0.05 < 0.1 selects the branch; 0.42 scales to a 42-block lookback.
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 840_000, randomness: DrawSequence(0.05, 0.42).next) == 839_958)
        // The boundary draws: no lookback at all, and the deepest one.
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 840_000, randomness: DrawSequence(0.0, 0.0).next) == 840_000)
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 840_000, randomness: DrawSequence(0.0, 0.99).next) == 839_901)
    }

    /// 0.1 is the branch boundary and must be excluded, or the wallet reaches
    /// back more often than Core does and becomes distinguishable that way.
    @Test("the branch boundary is exclusive")
    func branchBoundaryExclusive() {
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 500, randomness: DrawSequence(0.099_999, 0.5).next) != 500)
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 500, randomness: DrawSequence(0.1, 0.5).next) == 500)
    }

    /// A young chain must not wrap around. `UInt32` subtraction below zero
    /// traps, so this is a crash on the money path, not merely a wrong height.
    @Test("a tip shallower than the lookback clamps to zero")
    func shallowTipDoesNotUnderflow() {
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 10, randomness: DrawSequence(0.0, 0.99).next) == 0)
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 0, randomness: DrawSequence(0.0, 0.99).next) == 0)
    }

    /// Draws outside `0 ..< 1` are not reachable from the default source, but
    /// the parameter is public: a negative draw would trap in the `UInt32`
    /// initialiser and 1.0 would give a 100-block lookback, one deeper than
    /// Core ever uses.
    @Test("an out-of-range draw is confined rather than trusted")
    func outOfRangeDrawsConfined() {
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 840_000, randomness: DrawSequence(0.0, 1.0).next) == 840_000 - 99)
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 840_000, randomness: DrawSequence(0.0, 7.5).next) == 840_000 - 99)
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 840_000, randomness: DrawSequence(-1.0, -1.0).next) == 840_000)
        #expect(TransactionBuilder.antiFeeSnipingLocktime(
            tip: 840_000, randomness: DrawSequence(.nan, .nan).next) == 840_000)
    }

    /// The default source, sampled. The bound is what matters and holds for
    /// every draw; the "both branches occur" check is safe because missing the
    /// lookback branch 20,000 times running has probability 0.9^20000.
    @Test("the live source stays within the previous hundred blocks")
    func liveSourceStaysInRange() {
        let tip: UInt32 = 840_000
        var sawLookback = false
        var sawTip = false
        for _ in 0 ..< 20_000 {
            let locktime = TransactionBuilder.antiFeeSnipingLocktime(tip: tip)
            #expect(locktime <= tip, "a locktime above the tip is not final and will not relay")
            #expect(locktime >= tip - 99)
            if locktime == tip { sawTip = true } else { sawLookback = true }
        }
        #expect(sawTip)
        #expect(sawLookback, "the lookback branch must actually be reachable")
    }

    // MARK: - The money path

    /// The regression the issue asks for, observed failing against the builder
    /// before the locktime was threaded through.
    @Test("a freshly built send does not ship nLockTime = 0")
    func buildSendStampsALocktime() async throws {
        let wallet = try await makeFundedWallet()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: DrawSequence(0.5).next)
        #expect(prepared.built.transaction.locktime == 840_000,
                "a zero locktime fingerprints the wallet on chain")
    }

    /// The lookback branch reaches the money path too, not only the helper.
    @Test("a send can carry a recent height instead of the tip")
    func buildSendCanReachBack() async throws {
        let wallet = try await makeFundedWallet()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: DrawSequence(0.05, 0.42).next)
        #expect(prepared.built.transaction.locktime == 839_958)
    }

    /// The locktime is only enforced if at least one input is non-final, so
    /// this pins the pair rather than the locktime alone. 0xFFFFFFFD is also
    /// what opts the transaction into BIP125 replacement.
    @Test("inputs stay non-final so the locktime is actually enforced")
    func inputsRemainNonFinal() async throws {
        let wallet = try await makeFundedWallet()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: DrawSequence(0.5).next)
        #expect(prepared.built.transaction.inputs.allSatisfy { $0.sequence == 0xFFFF_FFFD })
        #expect(prepared.built.transaction.inputs.allSatisfy { $0.sequence != 0xFFFF_FFFF },
                "a final input would make the locktime a no-op")
    }

    /// An unsynced wallet has no validated tip to stamp. It also has nothing to
    /// spend, so this documents the boundary rather than endorsing it.
    @Test("a wallet with no validated tip stamps zero")
    func unsyncedWalletStampsZero() async throws {
        let wallet = try await makeFundedWallet()
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 0)
        #expect(prepared.built.transaction.locktime == 0)
    }

    /// A replacement must reuse the original's locktime. Choosing a fresh one
    /// would both leak that the two transactions came from the same wallet at
    /// different heights and trip the reviewer in `Wallet.swift`, which
    /// requires a replacement to preserve it.
    @Test("a fee bump keeps the original locktime")
    func feeBumpPreservesLocktime() async throws {
        let wallet = try await makeFundedWallet()
        let original = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: DrawSequence(0.05, 0.42).next)
        try await wallet.commit(original)
        #expect(original.built.transaction.locktime == 839_958)

        let rate = try await wallet.pendingFeeRate(txid: original.built.transaction.txid)
        let replacement = try await wallet.buildFeeBump(
            txid: original.built.transaction.txid, feeRateSatPerVByte: rate + 1)
        #expect(replacement.built.transaction.locktime == 839_958,
                "a replacement must not pick a new locktime")
    }

    /// The vault is the second build site. Fixing only the wallet would move
    /// the fingerprint onto vault spends rather than remove it.
    @Test("a vault spend is stamped too")
    func vaultSpendStampsALocktime() throws {
        let masters = try (0 ..< 3).map { try HDKey(seed: Data(repeating: UInt8($0 + 1), count: 32)) }
        let descriptor = try Vault.multiADescriptor(
            threshold: 2, cosigners: masters.map { try VaultFlowTests.keyExpression(master: $0) })
        let vault = try Vault(descriptor: descriptor, network: .signet)
        let utxo = try VaultFlowTests.funding(vault: vault, amount: 100_000)

        let psbt = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: 840_000,
            randomness: DrawSequence(0.5).next)
        // PSBT v2 carries it as the fallback locktime global, which is what the
        // finalizer rebuilds the transaction from.
        #expect(psbt.fallbackLocktime == 840_000)
    }
}
