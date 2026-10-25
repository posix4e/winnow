import CryptoKit
import Foundation
import P256K
import Testing
import TestSupport
@testable import WalletCore

/// Raw k-of-n script-path accounts, `tr(NUMS, sortedmulti_a(k, …))`: building,
/// signing in any order, thresholds, review and admission (signet-format
/// fixtures, fully offline). Ported from the shared-account Winnow's vault
/// suites onto the native curve module.
@Suite("Multisig accounts")
struct MultisigAccountTests {
    /// An external P2TR destination.
    let destination = Data([0x51, 0x20] + repeatElement(0x77, count: 32))

    /// The account and its signers' masters, `masters[i]` holding signer `i`.
    static func account(threshold: Int = 2, count: Int = 3) throws -> (MultisigAccount, [HDKey]) {
        let masters = Array(try TestKeys.masters().prefix(count))
        let descriptor = try MultisigAccount.descriptor(
            threshold: threshold, signers: try masters.map { try TestKeys.keyExpression(master: $0) }, network: .signet)
        let account = try MultisigAccount(descriptor: descriptor, network: .signet)
        return (account, try TestKeys.inSignerOrder(masters, of: account))
    }

    static func funding(_ account: MultisigAccount, amount: Int64, choice: AddressChain = .receive,
                        index: UInt32 = 0, height: UInt32 = 100, txidByte: UInt8 = 0x5A) throws -> WalletUTXO {
        try WalletUTXO(txid: Data(repeating: txidByte, count: 32), vout: 0, amount: amount,
                       scriptPubKey: account.scriptPubKey(index: index, choice: choice.rawValue),
                       chain: choice, index: index, height: height)
    }

    let owned = [MultisigAccount.OutputCoordinate(choice: 1, index: 0)]

    func spend(_ account: MultisigAccount, _ utxo: WalletUTXO) throws -> PSBT {
        try account.createSpend(utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
                                changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
    }

    // MARK: - End to end

    @Test("2-of-3: derive, fund, build, two signers in any order, combine, finalize, verify")
    func twoOfThree() throws {
        let (account, masters) = try Self.account()
        #expect(account.threshold == 2)
        #expect(account.signers.count == 3)
        let address = try account.address(index: 0)
        #expect(address.hasPrefix("tb1p"))
        #expect(try account.watchScripts(upTo: 2).count == 4)
        #expect(try MultisigAccount(account.descriptor.serialized(), network: .signet).address(index: 0) == address)

        let utxo = try Self.funding(account, amount: 100_000)
        let created = try spend(account, utxo)
        let input = created.inputs[0]
        #expect(input.tapInternalKey == (try account.descriptor.resolvedTaproot(index: 0, choice: 0)).internalKey)
        #expect(input.tapLeafScripts.count == 1)
        #expect(input.tapScriptSignatures.isEmpty)
        #expect(input.tapBIP32Derivation.count == 3)
        #expect(input.tapBIP32Derivation.values.allSatisfy { $0.leafHashes.count == 1 })
        let change = created.outputs.first { $0.script == (try? account.scriptPubKey(index: 0, choice: 1)) }
        #expect(change?.tapTree?.count == 1)
        #expect(change?.tapInternalKey == (try account.descriptor.resolvedTaproot(index: 0, choice: 1)).internalKey)
        #expect(change?.tapBIP32Derivation.count == 3)

        let base64 = created.base64
        #expect(try PSBT(base64: base64) == created)

        // A review that fails leaves the document untouched.
        var wrongCoin = utxo
        wrongCoin.amount += 1
        var rejected = try PSBT(base64: base64)
        let before = rejected
        #expect(throws: MultisigAccountError.self) {
            try account.sign(&rejected, signingKey: masters[0], knownUTXOs: [wrongCoin],
                             ownedOutputCoordinates: owned, chainTip: testChainTip)
        }
        #expect(rejected == before)

        var partialC = try PSBT(base64: base64)
        try account.sign(&partialC, signingKey: masters[2], knownUTXOs: [utxo],
                         ownedOutputCoordinates: owned, chainTip: testChainTip)
        var partialA = try PSBT(base64: base64)
        try account.sign(&partialA, signingKey: masters[0], knownUTXOs: [utxo],
                         ownedOutputCoordinates: owned, chainTip: testChainTip)
        #expect(partialA.inputs[0].tapScriptSignatures.count == 1)
        #expect(try account.approvals(of: partialA, knownUTXOs: [utxo]) == [0])

        var combined = try partialC.combined(with: [partialA])
        #expect(try account.approvals(of: combined, knownUTXOs: [utxo]) == [0, 2])

        // A hostile combiner appends an unrelated leaf: the account's review
        // refuses the policy change and leaves the document as it was.
        let realLeaf = try #require(combined.inputs[0].tapLeafScripts.first)
        let bogus = PSBT.TapLeafScript(
            controlBlock: Taproot.ControlBlock(leafVersion: realLeaf.leafVersion, outputKeyParity: false,
                                               internalKey: Data(repeating: 0, count: 32), path: []),
            script: realLeaf.script, leafVersion: realLeaf.leafVersion)
        var hostile = combined
        hostile.inputs[0].tapLeafScripts = [bogus, realLeaf]
        let hostileBefore = hostile
        #expect(throws: MultisigAccountError.self) {
            _ = try account.finalizeSpend(&hostile, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                                          chainTip: testChainTip)
        }
        #expect(hostile == hostileBefore)
        // The generic finalizer proves self-consistency only: the leaf that
        // commits to the spent output wins over the one that does not.
        var generic = hostile
        try generic.finalize()
        #expect(try verifiedSignatures(generic.extractedTransaction(), spentOutput: utxo.spentOutput) == 2)

        let signed = try account.finalizeSpend(&combined, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                                               chainTip: testChainTip)
        #expect(try verifiedSignatures(signed, spentOutput: utxo.spentOutput) == 2)
        // The fee estimate covered the real witness: n slots, script, control block.
        let witness = signed.inputs[0].witness
        #expect(witness.count == 3 + 2)
        #expect(try account.witnessBytesPerInput() >= 1 + witness.reduce(0) { $0 + 1 + $1.count })
    }

    @Test("every pair of signers can spend a 2-of-3; no single signer can finalize")
    func everyPairCanSpend() throws {
        let (account, masters) = try Self.account()
        let utxo = try Self.funding(account, amount: 100_000)
        for pair in [(0, 1), (0, 2), (1, 2)] {
            var psbt = try spend(account, utxo)
            try account.sign(&psbt, signingKey: masters[pair.0], knownUTXOs: [utxo],
                             ownedOutputCoordinates: owned, chainTip: testChainTip)
            var alone = psbt
            #expect(throws: (any Error).self, "signer \(pair.0) alone finalized") {
                _ = try account.finalizeSpend(&alone, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                                              chainTip: testChainTip)
            }
            try account.sign(&psbt, signingKey: masters[pair.1], knownUTXOs: [utxo],
                             ownedOutputCoordinates: owned, chainTip: testChainTip)
            let signed = try account.finalizeSpend(&psbt, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                                                   chainTip: testChainTip)
            #expect(try verifiedSignatures(signed, spentOutput: utxo.spentOutput) == 2, "pair \(pair)")
        }
    }

    @Test("a 3-of-3 refuses two signatures and accepts three")
    func threeOfThree() throws {
        let (account, masters) = try Self.account(threshold: 3)
        let utxo = try Self.funding(account, amount: 100_000)
        var psbt = try spend(account, utxo)
        for master in masters.prefix(2) {
            try account.sign(&psbt, signingKey: master, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                             chainTip: testChainTip)
        }
        var twoOnly = psbt
        #expect(throws: (any Error).self) {
            _ = try account.finalizeSpend(&twoOnly, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                                          chainTip: testChainTip)
        }
        try account.sign(&psbt, signingKey: masters[2], knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                         chainTip: testChainTip)
        let signed = try account.finalizeSpend(&psbt, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                                               chainTip: testChainTip)
        #expect(try verifiedSignatures(signed, spentOutput: utxo.spentOutput) == 3)
    }

    @Test("an account-key-only wallet signs with its BIP86 account key; a stranger's key cannot")
    func accountKeySigning() throws {
        let (account, masters) = try Self.account()
        let accountKey = try masters[1].derived(path: "m/86'/1'/0'")
        #expect(account.hasSigner(for: accountKey))
        #expect(account.includes(accountKey: accountKey.neutered))
        let stranger = try TestKeys.master(entropyByte: 0x0D)
        #expect(!account.hasSigner(for: stranger))

        let utxo = try Self.funding(account, amount: 100_000, choice: .change, index: 7)
        var psbt = try spend(account, utxo)
        try account.sign(&psbt, signingKey: accountKey, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                         chainTip: testChainTip)
        #expect(try account.approvals(of: psbt, knownUTXOs: [utxo]) == [1])
        #expect(throws: MultisigAccountError.noSignerKey(input: 0)) {
            try account.sign(&psbt, signingKey: stranger, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                             chainTip: testChainTip)
        }
    }

    @Test("an approval is counted by verification, not by a signature entry naming the key")
    func forgedApprovalNotCounted() throws {
        let (account, masters) = try Self.account()
        let utxo = try Self.funding(account, amount: 100_000)
        var psbt = try spend(account, utxo)
        try account.sign(&psbt, signingKey: masters[0], knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                         chainTip: testChainTip)
        let leafHash = try #require(psbt.inputs[0].tapLeafScripts.first).leafHash
        let signerTwo = try account.descriptor.publicKey(of: account.signers[2], index: 0, choice: 0).dropFirst()
        psbt.inputs[0].tapScriptSignatures[PSBT.TapScriptSignatureID(publicKey: Data(signerTwo), leafHash: leafHash)]
            = Data(repeating: 0x42, count: 64)
        #expect(try account.approvals(of: psbt, knownUTXOs: [utxo]) == [0])
        #expect(throws: (any Error).self) {
            _ = try account.finalizeSpend(&psbt, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                                          chainTip: testChainTip)
        }
    }

    // MARK: - Canonical order

    /// Two phones that each list the same signers in their own order, this
    /// phone first as the builder does, must make the same account; and an
    /// account written in another order before the builder sorted keys
    /// still parses, keeps its own internal key and its own addresses.
    @Test("the same signers in any order make the same account; an older account keeps its addresses")
    func signerOrderDoesNotMatter() throws {
        let expressions = try TestKeys.masters().map { try TestKeys.keyExpression(master: $0) }
        let orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]
        let built = try orders.map { order in
            try MultisigAccount.descriptor(threshold: 2, signers: order.map { expressions[$0] }, network: .signet)
        }
        #expect(Set(built.map { $0.serialized() }).count == 1)
        let account = try MultisigAccount(descriptor: built[0], network: .signet)

        // The descriptor the builder wrote before sorting, for signers listed
        // in reverse: the same leaf, another chain code on the NUMS xpub.
        let reversed = Array(expressions.reversed())
        let leaf = "sortedmulti_a(2,\(reversed.joined(separator: ",")))"
        let draft = try Descriptor("tr(\(Taproot.unspendableInternalKey.hex),\(leaf))")
        let olderKey = try MultisigAccount.unspendableKeyExpression(leafKeys: Array(draft.allKeys.dropFirst()),
                                                                     network: .signet)
        let older = try MultisigAccount("tr(\(olderKey),\(leaf))", network: .signet)
        #expect(older.descriptor.serialized() != account.descriptor.serialized())
        #expect(try older.address(index: 0) != account.address(index: 0))
        #expect(try MultisigAccount(older.descriptor.serialized(), network: .signet).address(index: 0)
            == older.address(index: 0))
    }

    // MARK: - Review (SEC-004)

    @Test("review decides change by derived script, never by the PSBT's own derivation labels")
    func changeByScriptOnly() throws {
        let (account, _) = try Self.account()
        let utxo = try Self.funding(account, amount: 100_000)
        var psbt = try spend(account, utxo)
        let review = try account.reviewSpend(psbt, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                                             chainTip: testChainTip)
        #expect(review.outputs.filter(\.isAccountOwned).count == 1)
        #expect(review.fee == review.inputTotal - review.outputTotal)
        // The same change output, without the coordinates that own it, is not ours,
        // whatever its BIP32 labels say.
        let unowned = try account.reviewSpend(psbt, knownUTXOs: [utxo], ownedOutputCoordinates: [],
                                              chainTip: testChainTip)
        #expect(unowned.outputs.allSatisfy { !$0.isAccountOwned })
        // A label copied onto the payment output does not make it change.
        let changeIndex = try #require(psbt.outputs.firstIndex { $0.script == (try? account.scriptPubKey(index: 0, choice: 1)) })
        let paymentIndex = 1 - changeIndex
        psbt.outputs[paymentIndex].tapBIP32Derivation = psbt.outputs[changeIndex].tapBIP32Derivation
        let relabelled = try account.reviewSpend(psbt, knownUTXOs: [utxo], ownedOutputCoordinates: owned,
                                                 chainTip: testChainTip)
        #expect(!relabelled.outputs[paymentIndex].isAccountOwned)
    }

    @Test("review refuses unknown coins, wrong amounts, open sighash types, immature coinbase and big fees")
    func reviewRefusals() throws {
        let (account, _) = try Self.account()
        let utxo = try Self.funding(account, amount: 100_000)
        let psbt = try spend(account, utxo)
        #expect(throws: MultisigAccountError.self) {
            _ = try account.reviewSpend(psbt, knownUTXOs: [], ownedOutputCoordinates: owned, chainTip: testChainTip)
        }
        var none = psbt
        none.inputs[0].sighashType = 2
        #expect(throws: MultisigAccountError.self) {
            _ = try account.reviewSpend(none, knownUTXOs: [utxo], ownedOutputCoordinates: owned, chainTip: testChainTip)
        }
        var coinbase = utxo
        coinbase.isCoinbase = true
        coinbase.height = testChainTip - 10
        #expect(throws: MultisigAccountError.self) {
            _ = try account.reviewSpend(psbt, knownUTXOs: [coinbase], ownedOutputCoordinates: owned,
                                        chainTip: testChainTip)
        }
        coinbase.height = testChainTip - Wallet.coinbaseMaturity
        _ = try account.reviewSpend(psbt, knownUTXOs: [coinbase], ownedOutputCoordinates: owned, chainTip: testChainTip)
        // A creator refuses to propose a fee over 10% of the inputs.
        #expect(throws: (any Error).self) {
            _ = try account.createSpend(utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
                                        changeIndex: 0, feeRateSatPerVByte: 100, chainTip: testChainTip)
        }
    }

    // MARK: - Admission (SEC-009, SEC-019, SEC-020)

    @Test("an internal key someone holds is refused: it could spend alone (SEC-020)")
    func realInternalKeyRefused() throws {
        let masters = try TestKeys.masters()
        let signers = try masters.map { try TestKeys.keyExpression(master: $0) }
        let internalKey = try masters[0].derived(path: "m/86'/1'/0'/0/0").publicKey.hex
        #expect(throws: MultisigAccountError.self) {
            _ = try MultisigAccount("tr(\(internalKey),sortedmulti_a(2,\(signers.joined(separator: ","))))", network: .signet)
        }
        #expect(throws: MultisigAccountError.self) {
            _ = try MultisigAccount("tr(\(signers[0]),sortedmulti_a(2,\(signers[1]),\(signers[2])))", network: .signet)
        }
    }

    @Test("new accounts name the internal key as Liana's unspendable xpub on H, which a Ledger can register")
    func unspendableXpubInternalKey() throws {
        let (account, _) = try Self.account()
        guard case let .trTree(internalKey, _) = account.descriptor.expression,
              case let .extended(xpub, keyNetwork) = internalKey.base else {
            Issue.record("expected an extended internal key")
            return
        }
        #expect(internalKey.origin == nil)
        #expect(internalKey.derivation.elements == MultisigAccount.signerSuffix)
        #expect(keyNetwork == .testnet)
        #expect(xpub.publicKey == Data([0x02]) + Taproot.unspendableInternalKey)
        #expect(xpub.depth == 0 && xpub.parentFingerprint == 0 && xpub.childIndex == 0)
        var concatenated = Data()
        for signer in account.signers {
            guard case let .extended(key, _) = signer.base else { continue }
            concatenated.append(key.publicKey)
        }
        #expect(xpub.chainCode == Data(SHA256.hash(data: concatenated)))
        // Each address commits to a child of H, never H itself, and the
        // descriptor round-trips through its text form.
        let first = try account.descriptor.resolvedTaproot(index: 0, choice: 0).internalKey
        #expect(first != Taproot.unspendableInternalKey)
        #expect(first != (try account.descriptor.resolvedTaproot(index: 1, choice: 0)).internalKey)
        let reparsed = try MultisigAccount(account.descriptor.serialized(), network: .signet)
        #expect(try reparsed.address(index: 3, choice: 1) == account.address(index: 3, choice: 1))
    }

    @Test("look-alike internal xpubs are refused: a real key, an origin, another suffix, another network (SEC-020)")
    func unspendableXpubLookAlikesRefused() throws {
        let masters = try TestKeys.masters()
        let signers = try masters.map { try TestKeys.keyExpression(master: $0) }
        let leaf = "sortedmulti_a(2,\(signers.joined(separator: ",")))"
        let chainCode = Data(repeating: 0x42, count: 32)
        let nums = HDKey(depth: 0, parentFingerprint: 0, childIndex: 0, chainCode: chainCode, privateKey: nil,
                         publicKey: Data([0x02]) + Taproot.unspendableInternalKey)
        let held = try masters[0].derived(path: "m/86'/1'/0'")
        let realKey = HDKey(depth: 0, parentFingerprint: 0, childIndex: 0, chainCode: chainCode, privateKey: nil,
                            publicKey: held.publicKey)
        // Positive control: any chain code on H is accepted.
        _ = try MultisigAccount("tr(\(nums.serialized(network: .testnet))/<0;1>/*,\(leaf))", network: .signet)
        let refused = [
            "\(realKey.serialized(network: .testnet))/<0;1>/*",
            "[00000000]\(nums.serialized(network: .testnet))/<0;1>/*",
            "\(nums.serialized(network: .testnet))/0/*",
            "\(nums.serialized(network: .testnet))",
            "\(nums.serialized(network: .mainnet))/<0;1>/*",
        ]
        for internalKey in refused {
            #expect(throws: MultisigAccountError.self, "accepted \(internalKey.prefix(12))") {
                _ = try MultisigAccount("tr(\(internalKey),\(leaf))", network: .signet)
            }
        }
    }

    @Test("a repeated signer is refused, however its origin is labelled (SEC-009)")
    func repeatedSignerRefused() throws {
        let masters = try TestKeys.masters()
        let first = try TestKeys.keyExpression(master: masters[0])
        let second = try TestKeys.keyExpression(master: masters[1])
        #expect(throws: MultisigAccountError.self) {
            _ = try MultisigAccount.descriptor(threshold: 2, signers: [first, first, second], network: .signet)
        }
        let relabelled = "[00000001" + first.drop { $0 != "/" }
        #expect(throws: MultisigAccountError.self) {
            _ = try MultisigAccount.descriptor(threshold: 2, signers: [first, relabelled, second], network: .signet)
        }
        // Positive control: the three distinct keys are accepted.
        _ = try MultisigAccount.descriptor(threshold: 2, signers: try masters.map { try TestKeys.keyExpression(master: $0) },
                                           network: .signet)
    }

    @Test("signers must share the /<0;1>/* suffix, so independence is provable (SEC-019)")
    func suffixPinned() throws {
        let masters = try TestKeys.masters()
        let bare = try masters.map { try TestKeys.bareKeyExpression(master: $0) }
        for suffix in ["/0/*", "/<0;1>/0", "/*", "", "/<1;0>/*", "/<0;1>/*'"] {
            #expect(throws: (any Error).self, "accepted suffix \(suffix)") {
                _ = try MultisigAccount.descriptor(threshold: 2,
                                                   signers: [bare[0] + "/<0;1>/*", bare[1] + "/<0;1>/*", bare[2] + suffix],
                                                   network: .signet)
            }
        }
    }

    @Test("signers must be origin-bearing public keys of this network")
    func signerKeyShape() throws {
        let master = try TestKeys.masters()[0]
        let other = try TestKeys.keyExpression(master: TestKeys.masters()[1])
        let account = try master.derived(path: "m/86'/1'/0'")
        let fingerprint = String(format: "%08x", master.fingerprint)
        let privateExpression = "[\(fingerprint)/86'/1'/0']\(account.serialized(network: .testnet))/<0;1>/*"
        let noOrigin = "\(account.neutered.serialized(network: .testnet))/<0;1>/*"
        let wrongDepth = "[\(fingerprint)/86'/1']\(account.neutered.serialized(network: .testnet))/<0;1>/*"
        for bad in [privateExpression, noOrigin, wrongDepth] {
            #expect(throws: (any Error).self) {
                _ = try MultisigAccount.descriptor(threshold: 1, signers: [bad, other], network: .signet)
            }
        }
        #expect(throws: MultisigAccountError.self) {
            _ = try MultisigAccount.descriptor(threshold: 1, signers: [try TestKeys.keyExpression(master: master), other],
                                               network: .mainnet)
        }
    }

    @Test("thresholds outside 1...n, one signer, and trees with more than one leaf are refused")
    func shapeRefusals() throws {
        let signers = try TestKeys.masters().map { try TestKeys.keyExpression(master: $0) }
        let nums = Taproot.unspendableInternalKey.hex
        #expect(throws: (any Error).self) {
            _ = try MultisigAccount.descriptor(threshold: 0, signers: signers, network: .signet)
        }
        #expect(throws: (any Error).self) {
            _ = try MultisigAccount.descriptor(threshold: 4, signers: signers, network: .signet)
        }
        #expect(throws: MultisigAccountError.self) {
            _ = try MultisigAccount.descriptor(threshold: 1, signers: [signers[0]], network: .signet)
        }
        #expect(throws: MultisigAccountError.self) {
            _ = try MultisigAccount("tr(\(nums),{sortedmulti_a(1,\(signers[0]),\(signers[1])),pk(\(signers[2]))})",
                                    network: .signet)
        }
        // multi_a (unsorted) is accepted as well as sortedmulti_a.
        let unsorted = try MultisigAccount("tr(\(nums),multi_a(2,\(signers.joined(separator: ","))))", network: .signet)
        #expect(!unsorted.isSorted)
    }

    @Test("records keep the shared-account Winnow's JSON keys")
    func recordCoding() throws {
        let (account, _) = try Self.account()
        let record = MultisigAccountRecord(id: account.id, name: "Household", descriptor: account.descriptor.serialized(),
                                           createdAtHeight: 100, nextReceiveIndex: 3,
                                           allUtxos: [try Self.funding(account, amount: 5_000)])
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(record)) as? [String: Any]
        #expect(Set(json?.keys.map { $0 } ?? []) ==
            ["id", "name", "descriptor", "createdAtHeight", "nextReceiveIndex", "nextChangeIndex", "utxos"])
        #expect(try JSONDecoder().decode(MultisigAccountRecord.self, from: JSONEncoder().encode(record)) == record)
        #expect(record.balance == 5_000)
    }

    /// Bundles written by the shared-account Winnow keep every account under
    /// `vaults`. A script-path multisig account restores; anything else, such
    /// as a MuSig2 account, refuses the bundle, so its coins never vanish
    /// from a restore.
    @Test("bundles carry multisig accounts and refuse any other kind of account")
    func bundleAccounts() throws {
        let (account, masters) = try Self.account()
        let record = MultisigAccountRecord(id: account.id, name: "Household", descriptor: account.descriptor.serialized(),
                                           createdAtHeight: 90, nextReceiveIndex: 1,
                                           allUtxos: [try Self.funding(account, amount: 5_000)])
        var bundle = ImportBundle(network: "signet", lastKnownHeight: 200)
        #expect(!(try bundle.serialized()).contains("vaults"), "a bundle without accounts is unchanged")
        bundle.vaults = [record]
        #expect(try ImportBundle.decode(json: bundle.serialized()).vaults == [record])

        let keys = try masters.map { try TestKeys.bareKeyExpression(master: $0) }
        var muSig2 = record
        // Main's MuSig2 account shape; this build cannot even parse it.
        muSig2.descriptor = "tr(musig(\(keys[0]),\(keys[1]))/<0;1>/*)"
        for refused in [[muSig2], [record, muSig2]] {
            bundle.vaults = refused
            #expect(throws: WalletError.unsupportedWalletData) { _ = try ImportBundle.decode(json: bundle.serialized()) }
        }
        var mainnet = bundle
        mainnet.network = "mainnet"
        mainnet.vaults = [record]
        #expect(throws: WalletError.unsupportedWalletData) { _ = try ImportBundle.decode(json: mainnet.serialized()) }
        bundle.vaults = Array(repeating: record, count: ImportBundle.maximumVaults + 1)
        #expect(throws: WalletError.self) { _ = try ImportBundle.decode(json: bundle.serialized()) }
    }
}

/// Replays BIP342 multi_a validation for a finalized input with the native
/// module: the control block must commit the leaf to the spent output key,
/// then each witness item is matched to its script key (reversed, BIP387)
/// and verified against the script-path sighash. Returns the valid count.
private func verifiedSignatures(_ tx: Transaction, spentOutput: SighashBIP341.SpentOutput) throws -> Int {
    let witness = tx.inputs[0].witness
    let leafScript = Script(witness[witness.count - 2])
    let controlBlock = try Taproot.ControlBlock(serialized: witness[witness.count - 1])
    var root = Taproot.leafHash(version: controlBlock.leafVersion, script: leafScript)
    for sibling in controlBlock.path { root = Taproot.branchHash(root, sibling) }
    let (outputKey, parity) = try Taproot.tweakedOutputKey(internalKey: controlBlock.internalKey, merkleRoot: root)
    #expect(outputKey == spentOutput.scriptPubKey.suffix(32))
    #expect(controlBlock.outputKeyParity == parity)
    let (_, keys) = try #require(Multisig.parse(leafScript))
    let sighash = try SighashBIP341.sighash(tx: tx, inputIndex: 0, spentOutputs: [spentOutput], hashType: .default,
                                            scriptPath: .init(leafScript: leafScript))
    var valid = 0
    for (position, key) in keys.enumerated() {
        let item = witness[keys.count - 1 - position]
        var message = [UInt8](sighash)
        if !item.isEmpty, let parsed = try? P256K.Schnorr.SchnorrSignature(dataRepresentation: item.prefix(64)),
           P256K.Schnorr.XonlyKey(dataRepresentation: key).isValid(parsed, for: &message) {
            valid += 1
        }
    }
    return valid
}
