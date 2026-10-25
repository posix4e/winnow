import Foundation
import TestSupport
import WalletCore

/// `winnow-fixture multisig-differential`: Winnow's Taproot script-path
/// multisig held to Bitcoin Core on a disposable regtest node, which
/// `scripts/check-multisig-core` starts and stops.
///
/// Seeded cases vary the threshold, the number of signers (two to five),
/// which signers are Bitcoin Core wallets (keys Core generated, signing with
/// its own libsecp256k1), the order the signers are listed in, and the
/// recovery leaf (none, fewer of the same signers, or separate keys, after a
/// delay). For every case Core must agree with Winnow on:
///
/// - the descriptor checksum and the first four receive and change addresses,
///   and that listing the signers, or a recovery leaf's separate keys, in
///   another order builds the very same descriptor;
/// - which signers a PSBT carries valid signatures from, Core's included
///   (both sides compute the same script-path sighash);
/// - every subset of exactly k signers, each signing in a shuffled order:
///   Winnow finalizes, Core's mempool accepts the transaction, and Core's own
///   finalizer produces the same bytes; with k + 1 signers both still finish
///   and Core accepts Winnow's k-signature witness; with k − 1 neither
///   finishes; one spend is mined;
/// - the recovery leaf, for delays of one to four blocks: every subset of its
///   threshold, refused by Core and by Winnow's unlock rule one block before
///   the lock opens and accepted by both in the block it opens; one key fewer
///   finishing on neither side unless the same people also complete the
///   signers' leaf; the signers' leaf finishing a spend that carries the
///   recovery sequence (BIP326); and one recovery spend is mined.
///
/// A disagreement is recorded with its seed and case and the run continues,
/// so one run reports every mismatch; the command exits non-zero if any.
enum MultisigDifferential {
    struct Options {
        var seed: UInt64 = 0x5441_5052_4F4F_5453
        var cases = 24
    }

    /// Agreement checks by kind, and every disagreement.
    final class Tally {
        private(set) var agreed: [String: Int] = [:]
        private(set) var disagreements: [String] = []

        func check(_ agrees: Bool, _ kind: String, _ detail: @autoclosure () -> String) {
            if agrees {
                agreed[kind, default: 0] += 1
            } else {
                disagreements.append("\(kind): \(detail())")
            }
        }
    }

    struct Failure: Error, CustomStringConvertible {
        let description: String
    }

    /// One signer: a Winnow master, or a Core wallet with a key Core made.
    enum Signer {
        case winnow(HDKey)
        case core(CoreSigner)

        var expression: String {
            get throws {
                switch self {
                case let .winnow(master): try TestKeys.keyExpression(master: master)
                case let .core(core): core.signerExpression
                }
            }
        }

        var label: String {
            if case .core = self { return "Core" }
            return "Winnow"
        }

        /// The account xpub, which identifies the signer inside the account.
        var accountKey: String {
            get throws { try MultisigDifferential.extendedKey(in: expression) }
        }
    }

    /// One generated account.
    struct Case {
        let number: Int
        let threshold: Int
        /// In the order the descriptor lists them.
        let signers: [Signer]
        let recovery: MultisigAccount.RecoveryPlan?
        /// The keys of a `separateKeys` recovery leaf, all Winnow masters.
        let recoveryMasters: [HDKey]

        var summary: String {
            let who = signers.map(\.label).joined(separator: ",")
            let leaf = switch recovery {
            case nil: "no recovery"
            case let .fewerSigners(m, blocks): "recovery \(m) of the signers after \(blocks)"
            case let .separateKeys(m, keys, blocks): "recovery \(m) of \(keys.count) other keys after \(blocks)"
            }
            return "\(threshold)-of-\(signers.count) [\(who)], \(leaf)"
        }
    }

    static let bank = "bank"
    /// Delays up to this many blocks are spent on the recovery path; longer
    /// ones are checked for addresses only.
    static let spendableDelay: UInt32 = 4

    static func run(_ options: Options) throws -> Tally {
        let tally = Tally()
        let chain = try BitcoinCLI.string(BitcoinCLI.runObject(["getblockchaininfo"]), "chain")
        guard chain == "regtest" else {
            throw Failure(description: "the node reports \(chain); this command mines and needs a disposable regtest node")
        }
        try prepareBank()
        for number in 0 ..< options.cases {
            var rng = SeededRandom(state: options.seed &+ UInt64(number) &* 0x9E37_79B9)
            do {
                let generated = try generate(number: number, rng: &rng)
                print("case \(number): \(generated.summary)")
                try check(generated, rng: &rng, tally: tally,
                          tag: "seed \(String(options.seed, radix: 16)) case \(number)")
            } catch {
                tally.check(false, "case completed", "seed \(String(options.seed, radix: 16)) case \(number): \(error)")
            }
        }
        return tally
    }

    // MARK: - Cases

    static func generate(number: Int, rng: inout SeededRandom) throws -> Case {
        let count = 2 + rng.count(4)
        let threshold = 1 + rng.count(count)
        let coreCount = min(rng.count(3), count)
        var signers: [Signer] = try (0 ..< coreCount).map { .core(try CoreSigner(wallet: "case\(number)-core\($0)")) }
        signers += try (coreCount ..< count).map { _ in .winnow(try master(&rng)) }
        shuffle(&signers, &rng)
        let blocks: UInt32 = rng.count(10) < 7 ? UInt32(1 + rng.count(Int(spendableDelay)))
            : [16, 144, 4_032, 65_535][rng.count(4)]
        var recoveryMasters: [HDKey] = []
        let recovery: MultisigAccount.RecoveryPlan?
        switch rng.count(3) {
        case 0:
            recovery = nil
        case 1:
            recovery = .fewerSigners(threshold: 1 + rng.count(count), blocks: blocks)
        default:
            recoveryMasters = try (0 ..< 1 + rng.count(3)).map { _ in try master(&rng) }
            recovery = .separateKeys(threshold: 1 + rng.count(recoveryMasters.count),
                                     keys: try recoveryMasters.map { try TestKeys.keyExpression(master: $0) },
                                     blocks: blocks)
        }
        return Case(number: number, threshold: threshold, signers: signers, recovery: recovery,
                    recoveryMasters: recoveryMasters)
    }

    static func check(_ generated: Case, rng: inout SeededRandom, tally: Tally, tag: String) throws {
        let expressions = try generated.signers.map { try $0.expression }
        let descriptor = try MultisigAccount.descriptor(threshold: generated.threshold, signers: expressions,
                                                        recovery: generated.recovery, network: .regtest)
        let account = try MultisigAccount(descriptor: descriptor, network: .regtest)
        try checkAddresses(account, generated: generated, expressions: expressions, tally: tally, tag: tag)
        for signer in generated.signers {
            if case let .core(core) = signer { try core.importMultisigAccount(account) }
        }
        try checkSignersPath(account, generated: generated, rng: &rng, tally: tally, tag: tag)
        if let recovery = account.recovery, recovery.blocks <= spendableDelay {
            try checkRecoveryPath(account, generated: generated, rng: &rng, tally: tally, tag: tag)
        }
    }

    // MARK: - Descriptor and addresses

    static func checkAddresses(_ account: MultisigAccount, generated: Case, expressions: [String],
                               tally: Tally, tag: String) throws {
        let text = account.descriptor.serialized()
        let body = String(text.split(separator: "#")[0])
        let coreChecksum = try BitcoinCLI.string(BitcoinCLI.runObject(["getdescriptorinfo", body]), "checksum")
        tally.check(coreChecksum == account.id, "descriptor checksum", "\(tag): Core \(coreChecksum), Winnow \(account.id)")
        let derived = try BitcoinCLI.runJSON(["deriveaddresses", text, "[0,3]"])
        let lists: [[String]] = (derived as? [[String]]) ?? [(derived as? [String]) ?? []]
        for choice in 0 ... 1 {
            for index in 0 ... 3 {
                let ours = try account.address(index: UInt32(index), choice: choice)
                let theirs = lists.indices.contains(choice) && lists[choice].indices.contains(index)
                    ? lists[choice][index] : "none"
                tally.check(ours == theirs, "address", "\(tag) \(choice)/\(index): Core \(theirs), Winnow \(ours)")
            }
        }
        // The builder writes keys in one canonical order, so listing the
        // signers, or a recovery leaf's separate keys, in another order must
        // give the very same descriptor, internal key included.
        let reversedRecovery = generated.recovery.map { plan -> MultisigAccount.RecoveryPlan in
            guard case let .separateKeys(m, keys, blocks) = plan else { return plan }
            return .separateKeys(threshold: m, keys: keys.reversed(), blocks: blocks)
        }
        let reordered = try MultisigAccount.descriptor(threshold: generated.threshold, signers: expressions.reversed(),
                                                       recovery: reversedRecovery, network: .regtest)
        tally.check(reordered.serialized() == text, "signer order",
                    "\(tag): listing the keys in reverse gives \(reordered.serialized().suffix(8)), not \(account.id)")
    }

    // MARK: - The signers' leaf

    static func checkSignersPath(_ account: MultisigAccount, generated: Case, rng: inout SeededRandom,
                                 tally: Tally, tag: String) throws {
        let coins = try fund(account, indices: [0, 1], rng: &rng)
        let tip = try height()
        let destination = try newScript()
        let psbt = try account.createSpend(utxos: coins, payments: [Payment(amount: 60_000, scriptPubKey: destination)],
                                           changeIndex: 0, feeRateSatPerVByte: 2, chainTip: tip)
        let owned = [MultisigAccount.OutputCoordinate(choice: 1, index: 0)]
        let positions = try signerPositions(account.signers, of: generated.signers)
        let k = generated.threshold
        var trials = combinations(of: Array(generated.signers.indices), size: k)
        if k > 1 { trials.append(Array(generated.signers.indices.prefix(k - 1))) }
        if k < generated.signers.count { trials.append(Array(generated.signers.indices.prefix(k + 1))) }
        var first: (label: String, hex: String)?
        for var subset in trials {
            shuffle(&subset, &rng)
            let label = "\(tag) signers \(subset.map { generated.signers[$0].label + "\($0)" })"
            var signed = psbt
            for member in subset {
                try sign(&signed, as: generated.signers[member], account: account, coins: coins, owned: owned, tip: tip)
            }
            let approved = try account.approvals(of: signed, knownUTXOs: coins)
            let expected = Set(subset.map { positions[$0] })
            tally.check(approved == expected, "verified signers",
                        "\(label): Winnow verifies \(approved.sorted()), signed by \(expected.sorted())")
            let outcome = try finalizeBoth(account, signed, coins: coins, owned: owned, tip: tip)
            guard subset.count >= k else {
                tally.check(outcome.winnow == nil && outcome.core == nil, "below threshold refused",
                            "\(label): Winnow finished \(outcome.winnow != nil), Core finished \(outcome.core != nil)")
                continue
            }
            guard let ours = outcome.winnow else {
                tally.check(false, "threshold finalizes", "\(label): Winnow refused \(k) signatures")
                continue
            }
            tally.check(outcome.core != nil, "threshold finalizes", "\(label): Core's finalizer did not complete")
            if subset.count == k, let theirs = outcome.core {
                tally.check(ours == theirs, "finalizers agree", "\(label): Winnow \(ours), Core \(theirs)")
            }
            let verdict = try mempoolVerdict(ours)
            tally.check(verdict.allowed, "Core accepts", "\(label): \(verdict.reason ?? "")")
            if verdict.allowed, first == nil { first = (label, ours) }
        }
        // Mined only after every subset was tried against the unspent coins.
        if let first { try broadcastAndMine(first.hex, tally: tally, label: first.label) }
    }

    // MARK: - The recovery leaf

    static func checkRecoveryPath(_ account: MultisigAccount, generated: Case, rng: inout SeededRandom,
                                  tally: Tally, tag: String) throws {
        guard let recovery = account.recovery else { return }
        let coin = try fund(account, indices: [2], rng: &rng)[0]
        let unlock = coin.height + recovery.blocks
        let openTip = unlock - 1
        let destination = try newScript()
        let lookback = Lookback()
        let psbt = try account.createSpend(utxos: [coin], payments: [Payment(amount: 40_000, scriptPubKey: destination)],
                                           changeIndex: 1, feeRateSatPerVByte: 2, chainTip: openTip,
                                           path: .recovery, randomness: { lookback.next() })
        let owned = [MultisigAccount.OutputCoordinate(choice: 1, index: 1)]
        let keyHolders = try recoveryHolders(account, generated: generated)
        let m = recovery.threshold
        var trials = combinations(of: Array(keyHolders.indices), size: m)
        if m > 1 { trials.append(Array(keyHolders.indices.prefix(m - 1))) }
        var ready: [(label: String, hex: String)] = []
        for var subset in trials {
            shuffle(&subset, &rng)
            let label = "\(tag) recovery keys \(subset)"
            var signed = psbt
            for member in subset {
                try sign(&signed, as: keyHolders[member], account: account, coins: [coin], owned: owned, tip: openTip)
            }
            let approved = try account.approvals(of: signed, knownUTXOs: [coin], path: .recovery)
            tally.check(approved == Set(subset), "verified recovery signers",
                        "\(label): Winnow verifies \(approved.sorted()), signed by \(subset.sorted())")
            let outcome = try finalizeBoth(account, signed, coins: [coin], owned: owned, tip: openTip)
            // A signer reused for recovery signs both leaves, so when its
            // signatures meet the signers' threshold that leaf can finish.
            let signersCanFinish = try account.approvals(of: signed, knownUTXOs: [coin]).count >= generated.threshold
            guard subset.count >= m else {
                let finished = (outcome.winnow != nil, outcome.core != nil)
                tally.check(finished == (signersCanFinish, signersCanFinish), "below recovery threshold",
                            "\(label): Winnow finished \(finished.0), Core finished \(finished.1), "
                                + "signers' leaf complete \(signersCanFinish)")
                continue
            }
            guard let ours = outcome.winnow else {
                tally.check(false, "recovery finalizes", "\(label): Winnow refused \(m) recovery signatures")
                continue
            }
            tally.check(outcome.core != nil, "recovery finalizes", "\(label): Core's finalizer did not complete")
            // When the signers' leaf can finish too, each finalizer may pick
            // either leaf, so only a recovery-only spend must match byte for byte.
            if let theirs = outcome.core, !signersCanFinish {
                tally.check(ours == theirs, "recovery finalizers agree", "\(label): Winnow \(ours), Core \(theirs)")
            }
            ready.append((label, ours))
        }
        // BIP326: the signers' leaf may finish a spend that carries the
        // recovery sequence; such a spend obeys the same relative lock.
        var bySigners = psbt
        for member in generated.signers.indices.prefix(generated.threshold) {
            try sign(&bySigners, as: generated.signers[member], account: account, coins: [coin], owned: owned,
                     tip: openTip)
        }
        if let ours = try finalizeBoth(account, bySigners, coins: [coin], owned: owned, tip: openTip).winnow {
            ready.append(("\(tag) signers' leaf with the recovery sequence", ours))
        } else {
            tally.check(false, "signers' leaf under the recovery sequence", "\(tag): Winnow refused it")
        }

        // One block before the lock opens: Core and Winnow both refuse.
        if openTip >= 1, openTip - 1 >= (try height()) {
            try mine(to: openTip - 1)
            tally.check(!account.isUnlockedForRecovery(coin, chainTip: openTip - 1), "locked a block early",
                        "\(tag): Winnow calls the coin unlocked at tip \(openTip - 1), coin at \(coin.height)")
            for (label, hex) in ready {
                let verdict = try mempoolVerdict(hex)
                tally.check(!verdict.allowed && (verdict.reason ?? "").contains("non-BIP68-final"),
                            "Core refuses a block early", "\(label): allowed \(verdict.allowed) \(verdict.reason ?? "")")
            }
        }
        // The block the lock opens in: both accept.
        try mine(to: openTip)
        tally.check(account.isUnlockedForRecovery(coin, chainTip: openTip), "unlocked on time",
                    "\(tag): Winnow calls the coin locked at tip \(openTip), coin at \(coin.height)")
        tally.check(account.recoveryUnlockHeight(of: coin) == unlock, "unlock height",
                    "\(tag): Winnow \(String(describing: account.recoveryUnlockHeight(of: coin))), expected \(unlock)")
        for (label, hex) in ready {
            let verdict = try mempoolVerdict(hex)
            tally.check(verdict.allowed, "Core accepts on time", "\(label): \(verdict.reason ?? "")")
        }
        if let first = ready.first, try mempoolVerdict(first.hex).allowed {
            try broadcastAndMine(first.hex, tally: tally, label: first.label)
        }
    }

    /// Who holds each recovery key, in the leaf's order.
    static func recoveryHolders(_ account: MultisigAccount, generated: Case) throws -> [Signer] {
        let holders: [Signer] = generated.recoveryMasters.isEmpty ? generated.signers
            : generated.recoveryMasters.map { .winnow($0) }
        let keys = try holders.map { try $0.accountKey }
        return try account.keys(on: .recovery).map { key in
            guard case let .extended(xpub, _) = key.base,
                  let position = keys.firstIndex(of: xpub.serialized(network: .testnet)) else {
                throw Failure(description: "a recovery key has no holder")
            }
            return holders[position]
        }
    }

    // MARK: - Signing and finalizing

    static func sign(_ psbt: inout PSBT, as signer: Signer, account: MultisigAccount, coins: [WalletUTXO],
                     owned: [MultisigAccount.OutputCoordinate], tip: UInt32) throws {
        switch signer {
        case let .winnow(master):
            try account.sign(&psbt, signingKey: master, knownUTXOs: coins, ownedOutputCoordinates: owned, chainTip: tip)
        case let .core(core):
            psbt = try core.process(psbt)
        }
    }

    /// Both finalizers on the same signed PSBT: the raw transactions in hex,
    /// nil where a side does not complete.
    static func finalizeBoth(_ account: MultisigAccount, _ psbt: PSBT, coins: [WalletUTXO],
                             owned: [MultisigAccount.OutputCoordinate],
                             tip: UInt32) throws -> (winnow: String?, core: String?) {
        var copy = psbt
        let winnow = (try? account.finalizeSpend(&copy, knownUTXOs: coins, ownedOutputCoordinates: owned,
                                                 chainTip: tip))?.serialized(includeWitness: true).hex
        let result = try BitcoinCLI.runObject(["finalizepsbt", psbt.base64V0()])
        let core = (result["complete"] as? Bool) == true ? result["hex"] as? String : nil
        return (winnow, core)
    }

    /// Positions in the account's signer list, by generated signer.
    static func signerPositions(_ keys: [Descriptor.SingleKey], of signers: [Signer]) throws -> [Int] {
        let listed = try keys.map { key -> String in
            guard case let .extended(xpub, _) = key.base else { throw Failure(description: "a signer is not an xpub") }
            return xpub.serialized(network: .testnet)
        }
        return try signers.map { signer in
            guard let position = listed.firstIndex(of: try signer.accountKey) else {
                throw Failure(description: "a signer is missing from the account")
            }
            return position
        }
    }

    // MARK: - The node

    static func prepareBank() throws {
        try BitcoinCLI.ensureWallet(bank)
        if try BitcoinCLI.trustedBalanceSats(wallet: bank) < 100_000_000 {
            try BitcoinCLI.run(["generatetoaddress", "110", BitcoinCLI.newAddress(wallet: bank)])
        }
    }

    /// Pays each receive index of `account` from the bank, mines the
    /// payments and returns them as coins of the account.
    static func fund(_ account: MultisigAccount, indices: [UInt32], rng: inout SeededRandom) throws -> [WalletUTXO] {
        for index in indices {
            try BitcoinCLI.sendToAddress(wallet: bank, address: account.address(index: index),
                                         sats: 80_000 + rng.int(0 ... 120_000), feeRate: 2)
        }
        try mine(blocks: 1)
        return try indices.flatMap { index in
            let script = try account.scriptPubKey(index: index)
            return try BitcoinCLI.unspents(scriptHex: script.hex).map {
                WalletUTXO(txid: Data(Data(hex: $0.txid)!.reversed()), vout: $0.vout, amount: $0.amount,
                           scriptPubKey: script, chain: .receive, index: index, height: $0.height)
            }
        }
    }

    static func newScript() throws -> Data {
        let address = try BitcoinCLI.newAddress(wallet: bank)
        let info = try BitcoinCLI.runObject(["getaddressinfo", address], wallet: bank)
        return Data(hex: try BitcoinCLI.string(info, "scriptPubKey"))!
    }

    static func height() throws -> UInt32 {
        UInt32(try BitcoinCLI.run(["getblockcount"]))!
    }

    static func mine(blocks: Int) throws {
        guard blocks > 0 else { return }
        try BitcoinCLI.run(["generatetoaddress", "\(blocks)", BitcoinCLI.newAddress(wallet: bank)])
    }

    static func mine(to target: UInt32) throws {
        let current = try height()
        if target > current { try mine(blocks: Int(target - current)) }
    }

    static func mempoolVerdict(_ hex: String) throws -> (allowed: Bool, reason: String?) {
        let results = try BitcoinCLI.runJSON(["testmempoolaccept", "[\"\(hex)\"]"]) as? [[String: Any]]
        let first = results?.first ?? [:]
        return ((first["allowed"] as? Bool) == true, first["reject-reason"] as? String)
    }

    static func broadcastAndMine(_ hex: String, tally: Tally, label: String) throws {
        let txid = try BitcoinCLI.run(["sendrawtransaction", hex])
        try mine(blocks: 1)
        let block = try BitcoinCLI.runObject(["getblock", BitcoinCLI.bestBlockHash(), "1"])
        let mined = (block["tx"] as? [String])?.contains(txid) == true
        tally.check(mined, "mined", "\(label): \(txid) is not in the next block")
    }

    // MARK: - Helpers

    static func master(_ rng: inout SeededRandom) throws -> HDKey {
        try HDKey(seed: Data((0 ..< 32).map { _ in UInt8(truncatingIfNeeded: rng.next()) }))
    }

    /// The xpub inside a key expression `[origin]xpub/…`.
    static func extendedKey(in expression: String) throws -> String {
        guard let close = expression.firstIndex(of: "]") else { throw Failure(description: "no origin in \(expression)") }
        let rest = expression[expression.index(after: close)...]
        return String(rest.prefix { $0 != "/" })
    }

    static func shuffle<T>(_ values: inout [T], _ rng: inout SeededRandom) {
        guard values.count > 1 else { return }
        for index in stride(from: values.count - 1, to: 0, by: -1) {
            values.swapAt(index, rng.count(index + 1))
        }
    }

    static func combinations(of values: [Int], size: Int) -> [[Int]] {
        guard size > 0 else { return [[]] }
        guard values.count >= size else { return [] }
        var result: [[Int]] = []
        for (offset, value) in values.enumerated() {
            for rest in combinations(of: Array(values[(offset + 1)...]), size: size - 1) {
                result.append([value] + rest)
            }
        }
        return result
    }

    /// Randomness for `createSpend` that always takes Core's anti-fee-sniping
    /// lookback of 50 blocks, so a spend built for the block a lock opens in
    /// is final by locktime a block earlier and only BIP68 can refuse it.
    final class Lookback: @unchecked Sendable {
        private var draws = 0
        func next() -> Double {
            draws += 1
            return draws % 2 == 1 ? 0 : 0.5
        }
    }
}
