import BitcoinCore
import BitcoinP2P
import Foundation
import P256K
import Testing
@testable import WalletCore

/// End-to-end vault flows (signet-format fixtures, fully offline): a 2-of-3
/// `sortedmulti_a` script-path vault and a 2-of-2 MuSig2 key-path vault, each
/// funded with a fabricated UTXO, spent via the PSBT workflow between
/// cosigners, with the final witnesses verified cryptographically.
@Suite("Vault end-to-end flows")
struct VaultFlowTests {
    /// Three cosigner HD masters (fixed entropy — deterministic fixtures).
    static func masters() throws -> [HDKey] {
        try [Data(repeating: 0xA1, count: 16), Data(repeating: 0xB2, count: 16),
             Data(repeating: 0xC3, count: 16)]
            .map { try HDKey(seed: BIP39.seed(mnemonic: BIP39.mnemonic(entropy: $0))) }
    }

    /// `[fp/86'/1'/0']tpub…/<0;1>/*` cosigner key expression text.
    static func keyExpression(master: HDKey) throws -> String {
        let account = try master.derived(path: "m/86'/1'/0'")
        let fingerprint = String(format: "%08x", master.fingerprint)
        return "[\(fingerprint)/86'/1'/0']\(account.neutered.serialized(network: .testnet))/<0;1>/*"
    }

    /// Bare `[fp/86'/1'/0']tpub…` — musig() participants carry no own
    /// derivation when the musig has a suffix (BIP390).
    static func bareKeyExpression(master: HDKey) throws -> String {
        let account = try master.derived(path: "m/86'/1'/0'")
        let fingerprint = String(format: "%08x", master.fingerprint)
        return "[\(fingerprint)/86'/1'/0']\(account.neutered.serialized(network: .testnet))"
    }

    /// A fabricated funding UTXO paying the vault at (choice, index).
    static func funding(vault: Vault, amount: Int64, choice: AddressChain = .receive,
                        index: UInt32 = 0, height: UInt32 = 100) throws -> WalletUTXO {
        try WalletUTXO(txid: Data(repeating: 0x5A, count: 32), vout: 0, amount: amount,
                       scriptPubKey: vault.scriptPubKey(index: index, choice: choice.rawValue),
                       chain: choice, index: index, height: height)
    }

    let destination = Data([0x51, 0x20] + repeatElement(0x77, count: 32)) // external P2TR

    // MARK: - Vault setup validation

    @Test("vault draft stays valid as keys, thresholds, and policies change")
    func draftTransitions() throws {
        let masters = try Self.masters()
        let keys = try masters.map { try Self.keyExpression(master: $0) }
        var draft = VaultDraft()
        #expect(draft.threshold == 1)
        #expect(!draft.canBuild)

        try draft.add(keys[0], network: .signet)
        #expect(draft.threshold == 1)
        #expect(!draft.canBuild)
        try draft.add(keys[1], network: .signet)
        #expect(draft.threshold == 2) // the second key defaults the draft to 2-of-2
        #expect(draft.canBuild)

        try draft.add(keys[2], network: .signet)
        #expect(draft.threshold == 2)
        draft.setThreshold(1)
        #expect(draft.threshold == 1) // decrement works
        draft.setThreshold(3)
        #expect(draft.threshold == 3) // increment works
        draft.setThreshold(99)
        #expect(draft.threshold == 3) // never exceeds the number of keys

        draft.remove(at: IndexSet(integer: 2))
        #expect(draft.threshold == 2)
        draft.remove(at: IndexSet(integer: 1))
        #expect(draft.threshold == 1)
        #expect(!draft.canBuild)

        let changedWithKey = draft.setRole(.muSig2)
        #expect(!changedWithKey) // an incompatible policy cannot replace live keys
        draft.remove(at: IndexSet(integer: 0))
        let changedWhenEmpty = draft.setRole(.muSig2)
        #expect(changedWhenEmpty)
        #expect(draft.role == .muSig2)
        #expect(draft.threshold == 1)

        let unchanged = draft
        #expect(throws: VaultCosignerKeyError.malformed) {
            try draft.add("not a signer key", network: .signet)
        }
        #expect(draft == unchanged) // invalid text is not admitted to the draft
    }

    @Test("signer keys are public, complete, and match the selected policy")
    func signerKeyValidation() throws {
        let master = try Self.masters()[0]
        let account = try master.derived(path: "m/86'/1'/0'")
        let scriptPath = try Self.keyExpression(master: master)
        let muSig2 = try Self.bareKeyExpression(master: master)

        #expect(try VaultCosignerKey(scriptPath, role: .scriptPath,
                                    network: .signet).expression == scriptPath)
        #expect(try VaultCosignerKey(muSig2, role: .muSig2,
                                    network: .signet).expression == muSig2)

        let fingerprint = String(format: "%08x", master.fingerprint)
        let privateExpression = "[\(fingerprint)/86'/1'/0']\(account.serialized(network: .testnet))/<0;1>/*"
        #expect(throws: VaultCosignerKeyError.privateKey) {
            _ = try VaultCosignerKey(privateExpression, role: .scriptPath, network: .signet)
        }
        #expect(throws: VaultCosignerKeyError.privateKey) {
            _ = try VaultCosignerKey(account.serialized(network: .testnet),
                                     role: .scriptPath, network: .signet)
        }
        #expect(VaultCosignerKeyError.privateKey.localizedDescription.contains("private key"))

        let wrongNetwork = "[\(fingerprint)/86'/1'/0']\(account.neutered.serialized(network: .mainnet))/<0;1>/*"
        #expect(throws: VaultCosignerKeyError.wrongNetwork(expectedPrefix: "tpub")) {
            _ = try VaultCosignerKey(wrongNetwork, role: .scriptPath, network: .signet)
        }
        #expect(throws: VaultCosignerKeyError.missingOrigin) {
            _ = try VaultCosignerKey("\(account.neutered.serialized(network: .testnet))/<0;1>/*",
                                     role: .scriptPath, network: .signet)
        }
        #expect(throws: VaultCosignerKeyError.muSig2DerivationForbidden) {
            _ = try VaultCosignerKey(scriptPath, role: .muSig2, network: .signet)
        }
        #expect(throws: VaultCosignerKeyError.scriptPathDerivationRequired) {
            _ = try VaultCosignerKey(muSig2, role: .scriptPath, network: .signet)
        }
        #expect(throws: VaultCosignerKeyError.malformed) {
            _ = try VaultCosignerKey("definitely not a signer key", role: .scriptPath, network: .signet)
        }
        let mismatchedOrigin = "[deadbeef/86'/1']\(account.neutered.serialized(network: .testnet))/<0;1>/*"
        #expect(throws: VaultCosignerKeyError.originPathMismatch) {
            _ = try VaultCosignerKey(mismatchedOrigin, role: .scriptPath, network: .signet)
        }

        let relabeled = "[deadbeef/86'/1'/0']\(account.neutered.serialized(network: .testnet))/<0;1>/*"
        #expect(try VaultCosignerKey(scriptPath, role: .scriptPath, network: .signet).identity ==
            VaultCosignerKey(relabeled, role: .scriptPath, network: .signet).identity)
        var duplicateDraft = VaultDraft()
        try duplicateDraft.add(scriptPath, network: .signet)
        #expect(throws: VaultCosignerKeyError.duplicateKey) {
            try duplicateDraft.add(relabeled, network: .signet)
        }
        #expect(throws: VaultCosignerKeyError.duplicateKey) {
            _ = try Vault.multiADescriptor(threshold: 2, cosigners: [scriptPath, relabeled])
        }

        #expect(throws: VaultCosignerKeyError.privateKey) {
            _ = try Vault.multiADescriptor(threshold: 1, cosigners: [privateExpression])
        }
    }

    // MARK: - 2-of-3 multi_a script-path vault

    @Test("2-of-3 multi_a vault: derive, fund, build, 2 cosigners, combine, finalize, verify")
    func multiAVault() throws {
        let masters = try Self.masters()
        let descriptor = try Vault.multiADescriptor(threshold: 2,
                                                    cosigners: masters.map { try Self.keyExpression(master: $0) })
        let vault = try Vault(descriptor: descriptor, network: .signet)

        // The vault commits to the NUMS internal key; addresses are bech32m.
        #expect(vault.usesUnspendableInternalKey)
        let address = try vault.address(index: 0)
        #expect(address.hasPrefix("tb1p"))
        #expect(try vault.watchScripts(upTo: 2).count == 4)
        // Deterministic across constructions from the same text.
        #expect(try Vault(descriptor.serialized(), network: .signet).address(index: 0) == address)

        // Fund the vault and build the spend PSBT (creator role).
        let utxo = try Self.funding(vault: vault, amount: 100_000)
        let created = try vault.createSpend(utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
                                            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        let input = created.inputs[0]
        #expect(input.tapInternalKey == Taproot.unspendableInternalKey)
        #expect(input.tapLeafScripts.count == 1)
        #expect(input.tapScriptSignatures.isEmpty)
        // BIP371 derivation entries carry the tapleaf hash for every cosigner.
        #expect(input.tapBIP32Derivation.count == 3)
        #expect(input.tapBIP32Derivation.values.allSatisfy { $0.leafHashes.count == 1 })
        // Change output carries the vault's tap tree (receiving-side check).
        let changeScript = try vault.scriptPubKey(index: 0, choice: 1)
        let changeOutput = created.outputs.first { $0.script == changeScript }
        #expect(changeOutput?.tapTree?.count == 1)
        #expect(changeOutput?.tapInternalKey == Taproot.unspendableInternalKey)

        // The PSBT travels between cosigners as Base64 (BIP174 interchange).
        let base64 = created.base64
        #expect(try PSBT(base64: base64) == created)

        // Cosigners 0 and 2 each partial-sign their own copy (signer role).
        var partialA = try PSBT(base64: base64)
        let ownedCoordinates = [Vault.OutputCoordinate(choice: 1, index: 0)]
        var wrongCoin = utxo
        wrongCoin.amount += 1
        var rejected = partialA
        #expect(throws: VaultError.self) {
            try vault.partialSign(&rejected, master: masters[0], knownUTXOs: [wrongCoin],
                                  ownedOutputCoordinates: ownedCoordinates)
        }
        #expect(rejected == partialA)

        try vault.partialSign(&partialA, master: masters[0], knownUTXOs: [utxo],
                              ownedOutputCoordinates: ownedCoordinates)
        var partialC = try PSBT(base64: base64)
        try vault.partialSign(&partialC, master: masters[2], knownUTXOs: [utxo],
                              ownedOutputCoordinates: ownedCoordinates)
        #expect(partialA.inputs[0].tapScriptSignatures.count == 1)
        #expect(partialC.inputs[0].tapScriptSignatures.count == 1)

        // One partial alone is below threshold and cannot finalize.
        var alone = partialA
        #expect(throws: PSBTError.self) { try alone.finalize() }

        // Combine (combiner role) → finalize → raw transaction.
        var combined = try partialA.combined(with: [partialC])
        #expect(combined.inputs[0].tapScriptSignatures.count == 2)
        // A hostile combiner may append an unrelated but structurally parsed
        // leaf. The vault boundary rejects that policy mutation atomically.
        let realLeaf = try #require(combined.inputs[0].tapLeafScripts.first)
        let bogusControl = Taproot.ControlBlock(
            leafVersion: realLeaf.leafVersion,
            outputKeyParity: false,
            internalKey: Data(repeating: 0, count: 32),
            path: [])
        let bogusLeaf = PSBT.TapLeafScript(controlBlock: bogusControl,
                                           script: realLeaf.script,
                                           leafVersion: realLeaf.leafVersion)
        var hostile = combined
        hostile.inputs[0].tapLeafScripts = [bogusLeaf, realLeaf]
        #expect(hostile.inputs[0].tapLeafScripts.first?.controlBlock.internalKey
            == Data(repeating: 0, count: 32))
        let hostileBeforeReview = hostile
        #expect(throws: VaultError.self) {
            _ = try vault.finalizeSpend(&hostile, knownUTXOs: [utxo],
                                        ownedOutputCoordinates: ownedCoordinates)
        }
        #expect(hostile == hostileBeforeReview)

        // The generic PSBT finalizer has a different boundary: it proves the
        // document is self-consistent, so an unrelated leaf must not shadow a
        // later leaf that actually commits to the declared witness UTXO.
        var generic = hostile
        try generic.finalize()
        let genericSigned = try generic.extractedTransaction()
        #expect(try verifyMultisigSpend(
            tx: genericSigned, inputIndex: 0,
            spentOutputs: [utxo.spentOutput]).validSignatures == 2)

        let signed = try vault.finalizeSpend(&combined, knownUTXOs: [utxo],
                                             ownedOutputCoordinates: ownedCoordinates)

        // Verify the witness cryptographically (see the helper below).
        let result = try verifyMultisigSpend(tx: signed, inputIndex: 0,
                                             spentOutputs: [utxo.spentOutput])
        #expect(result.validSignatures == 2)
        #expect(result.threshold == 2)
        #expect(result.keyCount == 3)
    }

    @Test("vault review trusts known coins and descriptor scripts, not PSBT labels")
    func vaultSpendReview() throws {
        let masters = try Self.masters()
        let descriptor = try Vault.multiADescriptor(
            threshold: 2, cosigners: masters.map { try Self.keyExpression(master: $0) })
        let vault = try Vault(descriptor: descriptor, network: .signet)
        let utxo = try Self.funding(vault: vault, amount: 100_000)
        let changeCoordinate = Vault.OutputCoordinate(choice: AddressChain.change.rawValue, index: 0)
        let created = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })

        let review = try vault.reviewSpend(
            created, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate])
        #expect(review.inputTotal == 100_000)
        #expect(review.outputTotal + review.fee == review.inputTotal)
        #expect(review.sighashTypes == [0])
        #expect(review.transactionVersion == 2)
        // The review surfaces the anti-fee-sniping locktime the creator chose,
        // so a signer sees the height it is committing to (#139). It used to
        // read zero here, which was the fingerprint, not an invariant.
        #expect(review.fallbackLocktime == testChainTip)
        #expect(review.sequences == [0xFFFF_FFFD])
        #expect(review.outputs.first { $0.scriptPubKey == destination }?.isVaultOwned == false)
        #expect(review.outputs.first { $0.scriptPubKey != destination }?.isVaultOwned == true)

        // Forge the attacker's output metadata to look exactly like the real
        // change metadata. Ownership still comes from its actual script.
        var forgedLabel = created
        let externalIndex = try #require(forgedLabel.outputs.firstIndex { $0.script == destination })
        let changeIndex = try #require(forgedLabel.outputs.firstIndex { $0.script != destination })
        forgedLabel.outputs[externalIndex].tapBIP32Derivation =
            forgedLabel.outputs[changeIndex].tapBIP32Derivation
        let forgedReview = try vault.reviewSpend(
            forgedLabel, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate])
        #expect(forgedReview.outputs[externalIndex].isVaultOwned == false)

        var wrongAmount = created
        wrongAmount.inputs[0].witnessUTXO = SighashBIP341.SpentOutput(
            amount: utxo.amount + 1, scriptPubKey: utxo.scriptPubKey)
        #expect(throws: VaultError.self) {
            _ = try vault.reviewSpend(
                wrongAmount, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate])
        }

        var unsafeSighash = created
        unsafeSighash.inputs[0].sighashType = 2 // SIGHASH_NONE
        #expect(throws: VaultError.self) {
            _ = try vault.reviewSpend(
                unsafeSighash, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate])
        }

        var changedPolicy = created
        changedPolicy.inputs[0].tapInternalKey = Data(repeating: 0x44, count: 32)
        #expect(throws: VaultError.self) {
            _ = try vault.reviewSpend(
                changedPolicy, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate])
        }

        var absurdFee = created
        let paymentIndex = try #require(absurdFee.outputs.firstIndex { $0.script == destination })
        absurdFee.outputs[paymentIndex].amount = 1
        let vaultOutputIndex = try #require(absurdFee.outputs.firstIndex { $0.script != destination })
        absurdFee.outputs[vaultOutputIndex].amount = 1
        #expect(throws: VaultError.self) {
            _ = try vault.reviewSpend(
                absurdFee, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate])
        }

        var unsupportedVersion = created
        unsupportedVersion.globals.removeAll { $0.type == PSBT.GlobalType.txVersion }
        unsupportedVersion.globals.append(PSBT.KeyValue(
            type: PSBT.GlobalType.txVersion,
            value: Data([3, 0, 0, 0])))
        #expect(throws: VaultError.self) {
            _ = try vault.reviewSpend(
                unsupportedVersion, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate])
        }
    }

    // MARK: - 2-of-2 MuSig2 key-path vault

    @Test("2-of-2 musig vault: nonce round, partial sigs, aggregate, BIP340-verifiable")
    func muSigVault() throws {
        let masters = try Self.masters().prefix(2).map { $0 }
        let keys = try masters.map { try Self.bareKeyExpression(master: $0) }
        let text = "tr(musig(\(keys[0]),\(keys[1]))/<0;1>/*)"
        let vault = try Vault(text, network: .signet)

        let utxo = try Self.funding(vault: vault, amount: 80_000)
        let created = try vault.createSpend(utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
                                            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        let context = try vault.muSig2Context(choice: 0, index: 0)
        #expect(context.participants.count == 2)
        // The BIP373 participant field and the BIP328-derived internal key.
        #expect(created.inputs[0].musig2ParticipantPubKeys[context.aggregate] == context.participants)
        #expect(created.inputs[0].tapInternalKey == context.internalKey)
        // The tweaked aggregate key is exactly the vault's output program.
        #expect(utxo.scriptPubKey == Data([0x51, 0x20]) + context.outputKey)
        // MuSig2 outputs do not carry per-key derivation labels. Descriptor
        // script matching still recognizes the real change output.
        let ownedCoordinates = [Vault.OutputCoordinate(choice: 1, index: 0)]
        let review = try vault.reviewSpend(
            created, knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates)
        let changeScript = try vault.scriptPubKey(index: 0, choice: AddressChain.change.rawValue)
        #expect(review.outputs.first { $0.scriptPubKey == changeScript }?.isVaultOwned == true)

        var tooManyOutputs = created
        tooManyOutputs.outputs = Array(repeating: created.outputs[0], count: 1_001)
        #expect(throws: VaultError.self) {
            try vault.reviewSpend(tooManyOutputs, knownUTXOs: [utxo],
                                  ownedOutputCoordinates: ownedCoordinates)
        }

        // Round 1: each cosigner attaches its public nonce to its own copy.
        let base64 = created.base64
        var noncePSBT_A = try PSBT(base64: base64)
        var secnoncesA = try vault.muSig2AttachNonce(
            &noncePSBT_A, input: 0, context: context, master: masters[0],
            knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates)
        var noncePSBT_B = try PSBT(base64: base64)
        var secnoncesB = try vault.muSig2AttachNonce(
            &noncePSBT_B, input: 0, context: context, master: masters[1],
            knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates)
        #expect(noncePSBT_A.inputs[0].musig2PubNonces.count == 1)
        #expect(secnoncesA.count == 1 && secnoncesB.count == 1)

        // Combine nonces, then round 2: each cosigner partial-signs the
        // combined PSBT.
        let withNonces = try noncePSBT_A.combined(with: [noncePSBT_B])
        #expect(withNonces.inputs[0].musig2PubNonces.count == 2)
        var signedA = withNonces
        try vault.muSig2Sign(&signedA, input: 0, context: context, master: masters[0],
                             secretNonces: &secnoncesA, knownUTXOs: [utxo],
                             ownedOutputCoordinates: ownedCoordinates)
        var signedB = withNonces
        try vault.muSig2Sign(&signedB, input: 0, context: context, master: masters[1],
                             secretNonces: &secnoncesB, knownUTXOs: [utxo],
                             ownedOutputCoordinates: ownedCoordinates)
        // The secnonce was zeroed — reuse is rejected.
        #expect(secnoncesA.values.first?.allSatisfy { $0 == 0 } == true)
        #expect(signedA.inputs[0].musig2PartialSigs.count == 1)

        // Combine partials, aggregate into the key-path signature, finalize.
        var combined = try signedA.combined(with: [signedB])
        try vault.muSig2Aggregate(&combined, input: 0, context: context,
                                  knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates)
        #expect(combined.inputs[0].tapKeySignature?.count == 64)
        let signed = try vault.finalizeSpend(&combined, knownUTXOs: [utxo],
                                             ownedOutputCoordinates: ownedCoordinates)

        // The witness is a single 64-byte BIP340 signature over the key-path
        // sighash, valid for the tweaked aggregate key.
        #expect(signed.inputs[0].witness.count == 1)
        let signature = signed.inputs[0].witness[0]
        let sighash = try SighashBIP341.sighash(tx: signed, inputIndex: 0,
                                                spentOutputs: [utxo.spentOutput], hashType: .default)
        var message = [UInt8](sighash)
        let parsed = try P256K.Schnorr.SchnorrSignature(dataRepresentation: signature)
        #expect(P256K.Schnorr.XonlyKey(dataRepresentation: context.outputKey).isValid(parsed, for: &message))
    }

    @Test("musig vault rejects a partial signed with the wrong key")
    func muSigWrongKey() throws {
        let masters = try Self.masters().prefix(2).map { $0 }
        let keys = try masters.map { try Self.bareKeyExpression(master: $0) }
        let vault = try Vault("tr(musig(\(keys[0]),\(keys[1]))/<0;1>/*)", network: .signet)
        let utxo = try Self.funding(vault: vault, amount: 80_000)
        var psbt = try vault.createSpend(utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
                                         changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        let context = try vault.muSig2Context(choice: 0, index: 0)
        // The third master is not a participant: no nonce, no signature.
        let outsider = try Self.masters()[2]
        #expect(throws: VaultError.noCosignerKey(input: 0)) {
            _ = try vault.muSig2AttachNonce(
                &psbt, input: 0, context: context, master: outsider,
                knownUTXOs: [utxo],
                ownedOutputCoordinates: [.init(choice: 1, index: 0)])
        }
    }

    // MARK: - Verification helper

    struct MultisigVerification {
        var threshold: Int
        var keyCount: Int
        var validSignatures: Int
    }

    /// Replays BIP342 multi_a validation for a finalized input: the control
    /// block must commit the leaf to the spent output key, then every witness
    /// stack item is matched to its script key (reversed order, BIP387) and
    /// each signature verified against the script-path sighash.
    func verifyMultisigSpend(tx: Transaction, inputIndex: Int,
                             spentOutputs: [SighashBIP341.SpentOutput]) throws -> MultisigVerification {
        let witness = tx.inputs[inputIndex].witness
        let leafScript = Script(witness[witness.count - 2])
        let controlBlock = try Taproot.ControlBlock(serialized: witness[witness.count - 1])

        // Control block: walk the path to the root, recompute the output key.
        var root = Taproot.leafHash(version: controlBlock.leafVersion, script: leafScript)
        for sibling in controlBlock.path { root = Taproot.branchHash(root, sibling) }
        let (outputKey, parity) = try Taproot.tweakedOutputKey(internalKey: controlBlock.internalKey,
                                                               merkleRoot: root)
        #expect(outputKey == spentOutputs[inputIndex].scriptPubKey.suffix(32))
        #expect(controlBlock.outputKeyParity == parity)

        let (threshold, keys) = try #require(Multisig.parse(leafScript))
        let sighash = try SighashBIP341.sighash(tx: tx, inputIndex: inputIndex,
                                                spentOutputs: spentOutputs, hashType: .default,
                                                scriptPath: .init(leafScript: leafScript))
        var valid = 0
        for (position, key) in keys.enumerated() {
            let item = witness[keys.count - 1 - position] // reversed onto the stack
            if item.isEmpty { continue } // placeholder for a non-signing key
            var message = [UInt8](sighash)
            let signature = try P256K.Schnorr.SchnorrSignature(dataRepresentation: item.prefix(64))
            if P256K.Schnorr.XonlyKey(dataRepresentation: key).isValid(signature, for: &message) {
                valid += 1
            }
        }
        return MultisigVerification(threshold: threshold, keyCount: keys.count, validSignatures: valid)
    }
}
