import Foundation
import Testing
import TestSupport
@testable import WalletCore

@Suite("Address decoding + transaction building")
struct TransactionBuilderTests {
    // MARK: Address decoding

    @Test("P2TR bech32m address → scriptPubKey (mainnet and signet HRPs)")
    func p2tr() throws {
        let address = TestScripts.bip86FirstMainnetAddress
        let script = try AddressDecoder.scriptPubKey(for: address, network: .mainnet)
        #expect(script.count == 34 && script.starts(with: [0x51, 0x20]))
        #expect(AddressDecoder.isP2TR(script))
        #expect(AddressDecoder.address(for: script, network: .mainnet) == address)
        // Same output key on the signet HRP.
        let signetAddress = try SegwitAddress.encode(hrp: "tb", version: 1, program: script.suffix(32))
        #expect(try AddressDecoder.scriptPubKey(for: signetAddress, network: .signet) == script)
        #expect(AddressDecoder.address(for: script, network: .signet) == signetAddress)
        // Wrong network is rejected.
        #expect(throws: AddressError.self) {
            _ = try AddressDecoder.scriptPubKey(for: address, network: .signet)
        }
    }

    @Test("P2WPKH bech32, base58 P2PKH and P2SH → scriptPubKey")
    func legacyAndV0() throws {
        // BIP173 reference P2WPKH address.
        let p2wpkh = try AddressDecoder.scriptPubKey(for: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                                                     network: .mainnet)
        #expect(p2wpkh == Data(hex: "0014751e76e8199196d454941c45d1b3a323f1433bd6"))
        // P2PKH for the same hash160 (base58 prefix 0x00).
        let p2pkh = try AddressDecoder.scriptPubKey(for: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", network: .mainnet)
        #expect(p2pkh == Data(hex: "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"))
        // Signet/testnet P2PKH (prefix 0x6F).
        let testnetP2pkh = try AddressDecoder.scriptPubKey(for: "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r",
                                                           network: .signet)
        #expect(testnetP2pkh == Data(hex: "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"))
        // P2SH (prefix 0x05): hash160 0x89ABCDEFABCDABCDABCDABCDABCDABCDABCDABCD.
        let p2sh = try AddressDecoder.scriptPubKey(for: "3EExK1K1WioG5caKFqP724ymoEXJNsTjnK", network: .mainnet)
        #expect(p2sh == Data(hex: "a91489abcdefabcdabcdabcdabcdabcdabcdabcdabcd87"))
        #expect(AddressDecoder.address(for: p2wpkh, network: .mainnet) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        #expect(AddressDecoder.address(for: p2pkh, network: .mainnet) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        #expect(AddressDecoder.address(for: p2pkh, network: .signet) == "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r")
        #expect(AddressDecoder.address(for: p2sh, network: .mainnet) == "3EExK1K1WioG5caKFqP724ymoEXJNsTjnK")
        #expect(AddressDecoder.address(for: Data([0x6a, 0x01, 0x01]), network: .mainnet) == nil)
        // Wrong network is rejected for base58 too: mainnet P2PKH on signet.
        #expect(throws: AddressError.self) {
            _ = try AddressDecoder.scriptPubKey(for: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", network: .signet)
        }
    }

    @Test("unactivated witness versions cannot be funded")
    func futureWitnessVersionsRejected() throws {
        let p2mrShape = try SegwitAddress.encode(
            hrp: "bc", version: 2, program: Data(repeating: 0x42, count: 32))
        #expect(p2mrShape.hasPrefix("bc1z"))
        #expect(AddressDecoder.address(for: Data([0x52, 0x20]) + Data(repeating: 0x42, count: 32), network: .mainnet) == nil)
        #expect(throws: AddressError.unsupportedWitnessVersion(2)) {
            _ = try AddressDecoder.scriptPubKey(for: p2mrShape, network: .mainnet)
        }

        let signet = try SegwitAddress.encode(
            hrp: "tb", version: 2, program: Data(repeating: 0x42, count: 32))
        #expect(throws: AddressError.unsupportedWitnessVersion(2)) {
            _ = try AddressDecoder.scriptPubKey(for: signet, network: .signet)
        }

        // v1 is only activated as the 32-byte P2TR program. A different v1
        // length is another unknown witness program, not a safe Taproot output.
        let unknownV1 = try SegwitAddress.encode(
            hrp: "bc", version: 1, program: Data(repeating: 0x24, count: 20))
        #expect(throws: AddressError.unsupportedWitnessProgram(version: 1, length: 20)) {
            _ = try AddressDecoder.scriptPubKey(for: unknownV1, network: .mainnet)
        }
    }

    // MARK: Building

    @Test("unsigned tx shape: version 2, empty scriptSigs, RBF sequence, change position")
    func build() throws {
        let inputs = [Transaction.Outpoint(txid: Data(repeating: 0x11, count: 32), vout: 1)]
        let payments = [Payment(amount: 50_000, scriptPubKey: Data([0x51, 0x20] + repeatElement(0x22, count: 32)))]
        let change = Payment(amount: 10_000, scriptPubKey: Data([0x51, 0x20] + repeatElement(0x33, count: 32)))
        let tx = try TransactionBuilder.build(inputs: inputs, payments: payments, change: change,
                                              changePosition: 0)
        #expect(tx.version == 2)
        #expect(tx.inputs.count == 1)
        #expect(tx.inputs[0].scriptSig.isEmpty)
        #expect(tx.inputs[0].sequence == 0xFFFF_FFFD) // BIP125 opt-in
        #expect(tx.outputs.count == 2)
        #expect(tx.outputs[0].value == 10_000) // change inserted first
        #expect(tx.outputs[1].value == 50_000)
        #expect(!tx.isSegwit) // unsigned

        #expect(throws: TxBuildError.noInputs) {
            _ = try TransactionBuilder.build(inputs: [], payments: payments)
        }
        #expect(throws: TxBuildError.invalidAmount(0)) {
            _ = try TransactionBuilder.build(inputs: inputs, payments: [Payment(amount: 0, scriptPubKey: Data([0x51]))])
        }
    }

    @Test("signedVSize estimate matches the actual signed transaction's vsize")
    func vsizeMath() throws {
        // 2 P2TR inputs, one P2TR payment + P2TR change.
        let script = Data([0x51, 0x20] + repeatElement(0x44, count: 32))
        let outputs = [Transaction.Output(value: 100_000, scriptPubKey: script),
                       Transaction.Output(value: 50_000, scriptPubKey: script)]
        let estimate = TransactionBuilder.signedVSize(inputCount: 2, outputs: outputs)

        var tx = try TransactionBuilder.build(
            inputs: [Transaction.Outpoint(txid: Data(repeating: 0x11, count: 32), vout: 0),
                     Transaction.Outpoint(txid: Data(repeating: 0x22, count: 32), vout: 3)],
            payments: outputs.map { Payment(amount: $0.value, scriptPubKey: $0.scriptPubKey) })
        for index in tx.inputs.indices {
            tx.inputs[index].witness = [Data(repeating: 0xAB, count: 64)] // SIGHASH_DEFAULT sig slot
        }
        #expect(TransactionBuilder.vsize(of: tx) == estimate)
    }

    @Test("builder rejects malformed inputs, positions, scripts, and monetary overflow")
    func hostileBuilderInputs() {
        let input = Transaction.Outpoint(txid: Data(repeating: 0x11, count: 32), vout: 0)
        let script = Data([0x51, 0x20] + repeatElement(0x22, count: 32))
        let payment = Payment(amount: 50_000, scriptPubKey: script)

        #expect(throws: TxBuildError.duplicateInput) {
            _ = try TransactionBuilder.build(inputs: [input, input], payments: [payment])
        }
        #expect(throws: TxBuildError.invalidOutpoint) {
            _ = try TransactionBuilder.build(
                inputs: [Transaction.Outpoint(txid: Data(repeating: 0x11, count: 31), vout: 0)],
                payments: [payment])
        }
        #expect(throws: TxBuildError.invalidChangePosition(2)) {
            _ = try TransactionBuilder.build(
                inputs: [input], payments: [payment],
                change: Payment(amount: 10_000, scriptPubKey: script), changePosition: 2)
        }
        #expect(throws: TxBuildError.emptyScript) {
            _ = try TransactionBuilder.build(
                inputs: [input], payments: [Payment(amount: 50_000, scriptPubKey: Data())])
        }
        #expect(throws: TxBuildError.invalidAmount(Int64.max)) {
            _ = try TransactionBuilder.build(
                inputs: [input], payments: [Payment(amount: Int64.max, scriptPubKey: script)])
        }
        #expect(throws: TxBuildError.amountOverflow) {
            _ = try TransactionBuilder.build(inputs: [input], payments: [
                Payment(amount: BitcoinAmount.maximum, scriptPubKey: script),
                Payment(amount: 1, scriptPubKey: script),
            ])
        }
    }

    // MARK: - Anti fee sniping
    //
    // Anti-fee-sniping locktimes (#139).
    //
    // Bitcoin Core stamps every transaction it builds with the current block
    // height, so a transaction cannot be mined into an *earlier* block and a
    // miner gains nothing by re-mining the previous one to take its fees. Most
    // wallets copy it, and that is the point here: a transaction carrying
    // `nLockTime = 0` is trivially distinguishable from a Core-built one, so it
    // discloses which software made it to anyone reading the chain.
    //
    // For a wallet whose whole argument is that it discloses nothing, that is a
    // poor trade for no benefit. What these pin is that a send now sits inside
    // the existing crowd, and that it never lands in the future -- a locktime
    // above the tip is not final and would not relay.

    private var destination: Data { TestScripts.p2trDestination }

    // MARK: The rule itself

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

    // MARK: The money path

    /// The regression the issue asks for, observed failing against the builder
    /// before the locktime was threaded through.
    @Test("a freshly built send does not ship nLockTime = 0")
    func buildSendStampsALocktime() async throws {
        let wallet = try await fundedWallet().wallet
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: 840_000, randomness: DrawSequence(0.5).next)
        #expect(prepared.built.transaction.locktime == 840_000,
                "a zero locktime fingerprints the wallet on chain")
    }

    /// The lookback branch reaches the money path too, not only the helper.
    @Test("a send can carry a recent height instead of the tip")
    func buildSendCanReachBack() async throws {
        let wallet = try await fundedWallet().wallet
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
        let wallet = try await fundedWallet().wallet
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
        let wallet = try await fundedWallet().wallet
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
        let wallet = try await fundedWallet().wallet
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
}

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
