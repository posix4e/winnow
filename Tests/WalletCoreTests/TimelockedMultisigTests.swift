import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// Multisig accounts with a timelocked recovery leaf: descriptors checked
/// against Bitcoin Core, the leaf scripts and BIP68 rule, spends on each
/// path, and what admission and review refuse.
@Suite("Timelocked multisig")
struct TimelockedMultisigTests {
    struct CoreVectors: Decodable {
        struct Case: Decodable {
            var name: String
            var descriptor: String
            var checksum: String
            var addresses: [String: [String]]
        }

        var source: String
        var cases: [Case]
    }

    let destination = Data([0x51, 0x20] + repeatElement(0x77, count: 32))
    let owned = [MultisigAccount.OutputCoordinate(choice: 1, index: 0)]

    // MARK: - Bitcoin Core and scripts

    @Test("descriptors with a recovery leaf match Bitcoin Core's checksums and addresses")
    func coreVectors() throws {
        let vectors = try Vectors.decode(CoreVectors.self, "core-timelocked-multisig.json", in: .module)
        #expect(vectors.cases.count == 4)
        for vector in vectors.cases {
            let descriptor = try Descriptor(vector.descriptor)
            #expect(descriptor.serialized() == vector.descriptor + "#" + vector.checksum, "\(vector.name)")
            for choice in 0 ... 1 {
                let expected = try #require(vector.addresses[String(choice)])
                for (index, address) in expected.enumerated() {
                    let derived = try descriptor.derived(index: UInt32(index), bitcoinNetwork: .regtest)[choice]
                    #expect(derived.address == address, "\(vector.name) \(choice)/\(index)")
                }
            }
        }
    }

    @Test("timelocked leaves parse back to their keys, threshold and lock; look-alikes do not")
    func leafPolicies() throws {
        let keys = (1 ... 3).map { Data(repeating: UInt8($0), count: 32) }
        for blocks: UInt32 in [1, 16, 17, 144, 4320, 65535, 0x7FFF_FFFF] {
            let multi = try Multisig.timelockedScript(threshold: 2, xonlyKeys: keys, blocks: blocks)
            #expect(Multisig.parsePolicy(multi) == LeafPolicy(threshold: 2, keys: keys, relativeLock: blocks))
            #expect(Multisig.parse(multi) == nil)
            let single = try Multisig.timelockedScript(xonlyKey: keys[0], blocks: blocks)
            #expect(Multisig.parsePolicy(single) == LeafPolicy(threshold: 1, keys: [keys[0]], relativeLock: blocks))
        }
        #expect(throws: MultisigError.invalidTimelock) { _ = try Multisig.timelockedScript(xonlyKey: keys[0], blocks: 0) }
        // A non-minimal lock push and a trailing opcode are not this module's leaves.
        var nonMinimal = try Multisig.timelockedScript(xonlyKey: keys[0], blocks: 5).bytes
        nonMinimal.replaceSubrange(34 ..< 35, with: [0x01, 0x05])
        #expect(Multisig.parsePolicy(Script(nonMinimal)) == nil)
        let trailing = try Multisig.timelockedScript(xonlyKey: keys[0], blocks: 5).bytes + [Script.Op.checkSig]
        #expect(Multisig.parsePolicy(Script(trailing)) == nil)

        #expect(RelativeLock.isSatisfied(blocks: 10, sequence: 10, txVersion: 2))
        #expect(RelativeLock.isSatisfied(blocks: 10, sequence: 11, txVersion: 2))
        #expect(!RelativeLock.isSatisfied(blocks: 10, sequence: 9, txVersion: 2))
        #expect(!RelativeLock.isSatisfied(blocks: 10, sequence: 10, txVersion: 1))
        #expect(!RelativeLock.isSatisfied(blocks: 10, sequence: 0xFFFF_FFFD, txVersion: 2))
        #expect(!RelativeLock.isSatisfied(blocks: 10, sequence: 10 | (1 << 22), txVersion: 2))
    }

    // MARK: - Spends

    static func funding(_ account: MultisigAccount, amount: Int64, index: UInt32 = 0, height: UInt32) throws -> WalletUTXO {
        try WalletUTXO(txid: Data(repeating: 0x5B + UInt8(index), count: 32), vout: 0, amount: amount,
                       scriptPubKey: account.scriptPubKey(index: index), chain: .receive, index: index, height: height)
    }

    func spend(_ account: MultisigAccount, _ utxo: WalletUTXO, tip: UInt32,
               path: MultisigAccount.SpendPath) throws -> PSBT {
        try account.createSpend(utxos: [utxo], payments: [Payment(amount: 40_000, scriptPubKey: destination)],
                                changeIndex: 0, feeRateSatPerVByte: 2, chainTip: tip, path: path, randomness: { 0.5 })
    }

    static func witnessSize(_ witness: [Data]) -> Int {
        func compact(_ value: Int) -> Int { value < 0xFD ? 1 : 3 }
        return compact(witness.count) + witness.reduce(0) { $0 + compact($1.count) + $1.count }
    }

    /// The builder's canonical order covers the recovery leaf: separate
    /// recovery keys in any order, and the signers reused for recovery in
    /// any order, give one descriptor.
    @Test("recovery keys in any order, and signers in any order, give one descriptor")
    func recoveryKeyOrderDoesNotMatter() throws {
        let signers = try TestKeys.masters().map { try TestKeys.keyExpression(master: $0) }
        let others = try [0xD4, 0xD5, 0xD6].map { try TestKeys.keyExpression(master: TestKeys.master(entropyByte: $0)) }
        let separate = try [others, Array(others.reversed()), [others[1], others[2], others[0]]].map {
            try MultisigAccount.descriptor(threshold: 2, signers: Array(signers.prefix(2)),
                                           recovery: .separateKeys(threshold: 2, keys: $0, blocks: 144),
                                           network: .signet).serialized()
        }
        #expect(Set(separate).count == 1)
        let reused = try [signers, Array(signers.reversed())].map {
            try MultisigAccount.descriptor(threshold: 2, signers: $0, recovery: .fewerSigners(threshold: 1, blocks: 10),
                                           network: .signet).serialized()
        }
        #expect(Set(reused).count == 1)
    }

    @Test("2-of-3 now, or any 1 of the same 3 once a coin is 10 blocks old")
    func fewerSigners() throws {
        let unordered = try TestKeys.masters()
        let descriptor = try MultisigAccount.descriptor(
            threshold: 2, signers: try unordered.map { try TestKeys.keyExpression(master: $0) },
            recovery: .fewerSigners(threshold: 1, blocks: 10), network: .signet)
        let account = try MultisigAccount(descriptor: descriptor, network: .signet)
        let masters = try TestKeys.inSignerOrder(unordered, of: account)
        let recovery = try #require(account.recovery)
        #expect(recovery.threshold == 1 && recovery.blocks == 10 && recovery.keys.count == 3)
        #expect(try MultisigAccount(descriptor.serialized(), network: .signet).address(index: 2) == account.address(index: 2))

        let coin = try Self.funding(account, amount: 100_000, height: 100)
        // The signers' path: two of three, at once.
        var now = try spend(account, coin, tip: 101, path: .signers)
        #expect(now.inputs[0].tapLeafScripts.count == 2)
        // The change's tree lists the right leaf first, the bytes Core's walletprocesspsbt writes.
        let changeTree = try #require(now.outputs.compactMap { $0.tapTree }.first)
        let changeLeaves = try account.leaves(choice: 1, index: 0).map { $0.script.bytes }
        #expect(changeTree.map { $0.script } == changeLeaves.reversed())
        #expect(changeTree.allSatisfy { $0.depth == 1 && $0.leafVersion == 0xC0 })
        try account.sign(&now, signingKey: masters[0], knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: 101)
        #expect(throws: (any Error).self) { var copy = now; _ = try copy.finalize() }
        try account.sign(&now, signingKey: masters[2], knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: 101)
        #expect(try account.approvals(of: now, knownUTXOs: [coin]) == [0, 2])
        #expect(try account.approvals(of: now, knownUTXOs: [coin], path: .recovery).isEmpty)
        let fast = try account.finalizeSpend(&now, knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: 101)
        #expect(fast.inputs[0].sequence == TransactionBuilder.defaultSequence)
        #expect(fast.inputs[0].witness.count == 5)
        #expect(Self.witnessSize(fast.inputs[0].witness) <= (try account.witnessBytesPerInput(path: .signers)))

        // The recovery path: refused while the coin is young, then one key.
        // A coin from block 100 under a 10-block lock opens in block 110,
        // the first block Core's BIP68 check accepts its spend in: the
        // account screen's "recovery path from block 110" and the rule agree.
        #expect(account.recoveryUnlockHeight(of: coin) == 110)
        #expect(!account.isUnlockedForRecovery(coin, chainTip: 108) && account.isUnlockedForRecovery(coin, chainTip: 109))
        #expect(throws: MultisigAccountError.self) { _ = try spend(account, coin, tip: 108, path: .recovery) }
        var later = try spend(account, coin, tip: 109, path: .recovery)
        #expect(try account.reviewSpend(later, knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: 109).path
            == .recovery)
        #expect(throws: MultisigAccountError.self) {
            _ = try account.reviewSpend(later, knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: 108)
        }
        try account.sign(&later, signingKey: masters[1], knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: 109)
        #expect(try account.approvals(of: later, knownUTXOs: [coin], path: .recovery) == [1])
        let slow = try account.finalizeSpend(&later, knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: 109)
        #expect(slow.inputs[0].sequence == 10)
        let leaves = try account.leaves(choice: 0, index: 0)
        let recoveryScript = try #require(leaves.first { $0.isRecovery }).script.bytes
        #expect(slow.inputs[0].witness[slow.inputs[0].witness.count - 2] == recoveryScript)
        #expect(Self.witnessSize(slow.inputs[0].witness) <= (try account.witnessBytesPerInput(path: .recovery)))
    }

    @Test("2-of-2 with a separate recovery key after 144 blocks")
    func separateKey() throws {
        let masters = try TestKeys.masters()
        let recoveryMaster = try TestKeys.master(entropyByte: 0xD4)
        let descriptor = try MultisigAccount.descriptor(
            threshold: 2, signers: try masters.prefix(2).map { try TestKeys.keyExpression(master: $0) },
            recovery: .separateKeys(threshold: 1, keys: [try TestKeys.keyExpression(master: recoveryMaster)], blocks: 144),
            network: .signet)
        #expect(descriptor.serialized().contains("and_v(v:pk("))
        let account = try MultisigAccount(descriptor: descriptor, network: .signet)
        #expect(account.hasSigner(for: recoveryMaster))
        let coin = try Self.funding(account, amount: 80_000, height: 500)

        // On the signers' path the recovery key signs nothing.
        var now = try spend(account, coin, tip: 600, path: .signers)
        #expect(throws: (any Error).self) {
            try account.sign(&now, signingKey: recoveryMaster, knownUTXOs: [coin], ownedOutputCoordinates: owned,
                             chainTip: 600)
        }
        // After 144 blocks it spends alone.
        var later = try spend(account, coin, tip: 643, path: .recovery)
        try account.sign(&later, signingKey: recoveryMaster, knownUTXOs: [coin], ownedOutputCoordinates: owned,
                         chainTip: 643)
        let transaction = try account.finalizeSpend(&later, knownUTXOs: [coin], ownedOutputCoordinates: owned,
                                                    chainTip: 643)
        #expect(transaction.inputs[0].sequence == 144)
        #expect(transaction.inputs[0].witness.count == 3) // signature, leaf script, control block
    }

    // No user path reaches this one: the signet journey's signers' leaf
    // completes first. The journey's 2-of-3, where all three sign, covers a
    // surplus on the signers' leaf with Core mining the result.
    @Test("two holders sign a 1-of-3 recovery leaf: the witness carries exactly one signature")
    func surplusRecoverySignatureLeftOut() throws {
        let masters = try TestKeys.masters()
        let account = try MultisigAccount(descriptor: MultisigAccount.descriptor(
            threshold: 3, signers: try masters.map { try TestKeys.keyExpression(master: $0) },
            recovery: .fewerSigners(threshold: 1, blocks: 10), network: .signet), network: .signet)
        let coin = try Self.funding(account, amount: 100_000, height: 100)
        var later = try spend(account, coin, tip: 109, path: .recovery)
        for master in masters.prefix(2) {
            try account.sign(&later, signingKey: master, knownUTXOs: [coin], ownedOutputCoordinates: owned,
                             chainTip: 109)
        }
        #expect(try account.approvals(of: later, knownUTXOs: [coin], path: .recovery) == [0, 1])
        let transaction = try account.finalizeSpend(&later, knownUTXOs: [coin], ownedOutputCoordinates: owned,
                                                    chainTip: 109)
        // Two of three on the signers' leaf is too few, so the recovery leaf finishes it, with one signature.
        let witness = transaction.inputs[0].witness
        let recoveryScript = try #require(account.leaves(choice: 0, index: 0).first { $0.isRecovery }).script.bytes
        #expect(witness[witness.count - 2] == recoveryScript)
        #expect(witness.prefix(3).filter { !$0.isEmpty }.count == 1)
    }

    // The app tests cannot age coins against a chain tip, so this case stays
    // here; a mix of sequences is walked across two phones in
    // AppTests/MultisigAccountFlowTests.testTwoPhonesSignACoSignersSpendWithBIP326Sequences.
    @Test("a co-signer's BIP326 sequences on old coins: either leaf could finish it, the signers still do")
    func bip326OldCoins() throws {
        let masters = try TestKeys.masters()
        let recoveryMaster = try TestKeys.master(entropyByte: 0xD4)
        let account = try MultisigAccount(descriptor: MultisigAccount.descriptor(
            threshold: 2, signers: try masters.prefix(2).map { try TestKeys.keyExpression(master: $0) },
            recovery: .separateKeys(threshold: 1, keys: [try TestKeys.keyExpression(master: recoveryMaster)],
                                    blocks: 144),
            network: .signet), network: .signet)
        let coins = try [Self.funding(account, amount: 60_000, index: 1, height: 1),
                         Self.funding(account, amount: 60_000, index: 2, height: 2)]
        var psbt = try account.createSpend(utxos: coins, payments: [Payment(amount: 100_000, scriptPubKey: destination)],
                                           changeIndex: 0, feeRateSatPerVByte: 2, chainTip: 200, randomness: { 0.5 })
        // BIP326: each Taproot input's sequence is its coin's confirmations, both past the 144-block lock.
        for (index, input) in try psbt.unsignedTransaction().inputs.enumerated() {
            let coin = try #require(coins.first { $0.outpoint == input.previousOutput })
            psbt.inputs[index].sequence = 200 - coin.height + 1
        }
        #expect(try account.reviewSpend(psbt, knownUTXOs: coins, ownedOutputCoordinates: owned, chainTip: 200).path
            == .recovery)
        for master in masters.prefix(2) {
            try account.sign(&psbt, signingKey: master, knownUTXOs: coins, ownedOutputCoordinates: owned, chainTip: 200)
        }
        let finished = try account.finalizeSpend(&psbt, knownUTXOs: coins, ownedOutputCoordinates: owned, chainTip: 200)
        for input in finished.inputs {
            #expect(Multisig.parsePolicy(Script(input.witness[input.witness.count - 2]))?.relativeLock == nil)
        }
    }

    @Test("review takes a mix of sequences as the signers' path and refuses a missing leaf")
    func reviewRefusals() throws {
        let masters = try TestKeys.masters()
        let account = try MultisigAccount(descriptor: MultisigAccount.descriptor(
            threshold: 2, signers: try masters.map { try TestKeys.keyExpression(master: $0) },
            recovery: .fewerSigners(threshold: 1, blocks: 10), network: .signet), network: .signet)
        let first = try Self.funding(account, amount: 60_000, index: 0, height: 100)
        let second = try Self.funding(account, amount: 60_000, index: 1, height: 100)
        let mixed = try account.createSpend(utxos: [first, second],
                                            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
                                            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: 200, path: .recovery,
                                            randomness: { 0.5 })
        // The second input back on the signers' sequence.
        var rebuilt = mixed
        rebuilt.inputs[1].pairs.removeAll { $0.type == PSBT.InType.sequence }
        rebuilt.inputs[1].pairs.append(PSBT.KeyValue(type: PSBT.InType.sequence,
                                                     value: Data([0xFD, 0xFF, 0xFF, 0xFF])))
        #expect(try account.reviewSpend(rebuilt, knownUTXOs: [first, second], ownedOutputCoordinates: owned,
                                        chainTip: 200).path == .signers)
        var stripped = try spend(account, first, tip: 200, path: .signers)
        stripped.inputs[0].tapLeafScripts = Array(stripped.inputs[0].tapLeafScripts.prefix(1))
        #expect(throws: MultisigAccountError.self) {
            _ = try account.reviewSpend(stripped, knownUTXOs: [first], ownedOutputCoordinates: owned, chainTip: 200)
        }
    }

    @Test("review refuses, rather than traps on, a coin stored at the top of the height range")
    func topOfHeightRange() throws {
        let masters = try TestKeys.masters()
        let account = try MultisigAccount(descriptor: MultisigAccount.descriptor(
            threshold: 2, signers: try masters.map { try TestKeys.keyExpression(master: $0) },
            recovery: .fewerSigners(threshold: 1, blocks: 10), network: .signet), network: .signet)
        var coin = try Self.funding(account, amount: 60_000, height: .max - 4)
        #expect(account.recoveryUnlockHeight(of: coin) == nil)
        var psbt = try spend(account, coin, tip: 200, path: .signers)
        psbt.inputs[0].sequence = 10
        #expect(throws: MultisigAccountError.invalidSpend("input 1 unlocks for recovery only past the last block height")) {
            _ = try account.reviewSpend(psbt, knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: .max)
        }
        coin.isCoinbase = true
        psbt.inputs[0].sequence = TransactionBuilder.defaultSequence
        #expect(throws: MultisigAccountError.invalidSpend("input 1 spends a coinbase that matures in 95 blocks")) {
            _ = try account.reviewSpend(psbt, knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: .max)
        }
    }

    @Test("admission refuses look-alike recovery leaves")
    func admissionRefusals() throws {
        let masters = try TestKeys.masters()
        let signers = try masters.map { try TestKeys.keyExpression(master: $0) }
        let bare = try masters.map { try TestKeys.bareKeyExpression(master: $0) }
        let other = try TestKeys.keyExpression(master: TestKeys.master(entropyByte: 0xD4))
        let primary = "sortedmulti_a(2,\(signers.joined(separator: ",")))"
        let nums = Taproot.unspendableInternalKey.hex
        let refused = [
            "and_v(v:pk(\(other)),older(65536))", // longer than BIP68's 16 bits
            "and_v(v:pk(\(other)),older(4194314))", // the time-based flag
            "and_v(v:pk(\(signers[0])),older(10))", // a signer on its first path again
            "and_v(v:pk(\(other.dropLast(8))/<2;3>/*),older(10))", // a stranger on the reused path
            "and_v(v:multi_a(1,\(bare[0])/<2;3>/*,\(bare[0])/<2;3>/*),older(10))", // a repeated recovery key
            "and_v(v:pk([deadbeef\(bare[0].dropFirst(9))/<2;3>/*),older(10))", // a signer under another fingerprint
            "and_v(v:pk(\(bare[0].replacingOccurrences(of: "/86'/", with: "/87'/"))/<2;3>/*),older(10))", // another path
            "multi_a(1,\(other))", // a second leaf without a lock
        ]
        _ = try MultisigAccount("tr(\(nums),{\(primary),and_v(v:pk(\(other)),older(10))})", network: .signet)
        for leaf in refused {
            #expect(throws: (any Error).self, "accepted \(leaf.prefix(40))") {
                _ = try MultisigAccount("tr(\(nums),{\(primary),\(leaf)})", network: .signet)
            }
        }
        #expect(throws: MultisigAccountError.invalidDescriptor("every recovery key must be an extended public key")) {
            _ = try MultisigAccount("tr(\(nums),{\(primary),and_v(v:pk(\(Taproot.unspendableInternalKey.hex)),older(10))})",
                                    network: .signet)
        }
        // A timelocked leaf alone has no signers' path, and older(0) does not parse.
        #expect(throws: (any Error).self) {
            _ = try MultisigAccount("tr(\(nums),and_v(v:pk(\(other)),older(10)))", network: .signet)
        }
        #expect(throws: DescriptorError.invalidTimelock) {
            _ = try Descriptor("tr(\(nums),{\(primary),and_v(v:pk(\(other)),older(0))})")
        }
        #expect(throws: (any Error).self) {
            _ = try MultisigAccount.descriptor(threshold: 2, signers: signers,
                                               recovery: .fewerSigners(threshold: 4, blocks: 10), network: .signet)
        }
    }
}
