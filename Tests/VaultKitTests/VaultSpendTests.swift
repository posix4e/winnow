import Foundation
import P256K
import Testing
import TestSupport
@testable import VaultKit
@testable import WalletCore

/// Building, signing, thresholds and finalization for a vault spend
/// (signet-format fixtures, fully offline).
///
/// Three suites merged here, each a section below: the end-to-end flows over a
/// 2-of-3 `sortedmulti_a` script-path vault and a 2-of-2 MuSig2 key-path vault;
/// the k-of-n threshold and signing-coverage enumeration; and the PSBT leaf,
/// MuSig2, combiner and finalizer fields those flows travel on. They shared the
/// BIP342 verifier below, which used to be reached by constructing the flow
/// suite from the threshold suite.
@Suite("Vault spend")
struct VaultSpendTests {
    /// An external P2TR destination. `TestScripts.p2trDestination` is a
    /// different stranger (0x99); these suites always paid this one.
    let destination = Data([0x51, 0x20] + repeatElement(0x77, count: 32))

    // MARK: - Vault end-to-end flows

    // MARK: Vault setup validation

    /// Threshold and role transitions of a draft are enumerated in
    /// the threshold section below and in `VaultAdmissionTests`; this pins the
    /// empty draft's defaults and that malformed text never enters it.
    @Test("an empty draft is 1-of-0, cannot build, and refuses malformed text unchanged")
    func emptyDraft() throws {
        var draft = VaultDraft()
        #expect(draft.threshold == 1)
        #expect(!draft.canBuild)

        let unchanged = draft
        #expect(throws: VaultCosignerKeyError.malformed) {
            try draft.add("not a signer key", network: .signet)
        }
        #expect(draft == unchanged) // invalid text is not admitted to the draft
    }

    /// Each refusal a signer key can earn is pinned with its positive control
    /// in `VaultAdmissionTests`; this keeps the signet-format fixtures
    /// accepted for their own policy, and private material out of a descriptor.
    @Test("signet signer keys are accepted for their policy; a private key never reaches a descriptor")
    func signerKeyValidation() throws {
        let master = try TestVaults.masters()[0]
        let account = try master.derived(path: "m/86'/1'/0'")
        let scriptPath = try TestVaults.keyExpression(master: master)
        let muSig2 = try TestVaults.bareKeyExpression(master: master)

        #expect(try VaultCosignerKey(scriptPath, role: .scriptPath,
                                    network: .signet).expression == scriptPath)
        #expect(try VaultCosignerKey(muSig2, role: .muSig2,
                                    network: .signet).expression == muSig2)

        let fingerprint = String(format: "%08x", master.fingerprint)
        let privateExpression = "[\(fingerprint)/86'/1'/0']\(account.serialized(network: .testnet))/<0;1>/*"
        #expect(throws: VaultCosignerKeyError.privateKey) {
            _ = try Vault.multiADescriptor(threshold: 1, cosigners: [privateExpression])
        }
    }

    // MARK: 2-of-3 multi_a script-path vault

    @Test("2-of-3 multi_a vault: derive, fund, build, 2 cosigners, combine, finalize, verify")
    func multiAVault() throws {
        let masters = try TestVaults.masters()
        let descriptor = try Vault.multiADescriptor(threshold: 2,
                                                    cosigners: masters.map { try TestVaults.keyExpression(master: $0) })
        let vault = try Vault(descriptor: descriptor, network: .signet)

        // The vault commits to the NUMS internal key; addresses are bech32m.
        #expect(vault.usesUnspendableInternalKey)
        let address = try vault.address(index: 0)
        #expect(address.hasPrefix("tb1p"))
        #expect(try vault.watchScripts(upTo: 2).count == 4)
        // Deterministic across constructions from the same text.
        #expect(try Vault(descriptor.serialized(), network: .signet).address(index: 0) == address)

        // Fund the vault and build the spend PSBT (creator role).
        let utxo = try TestVaults.funding(vault: vault, amount: 100_000)
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
                                  ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
        }
        #expect(rejected == partialA)

        try vault.partialSign(&partialA, master: masters[0], knownUTXOs: [utxo],
                              ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
        var partialC = try PSBT(base64: base64)
        try vault.partialSign(&partialC, master: masters[2], knownUTXOs: [utxo],
                              ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
        #expect(partialA.inputs[0].tapScriptSignatures.count == 1)
        #expect(partialC.inputs[0].tapScriptSignatures.count == 1)

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
                                        ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
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
                                             ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)

        // Verify the witness cryptographically (see the helper below).
        let result = try verifyMultisigSpend(tx: signed, inputIndex: 0,
                                             spentOutputs: [utxo.spentOutput])
        #expect(result.validSignatures == 2)
        #expect(result.threshold == 2)
        #expect(result.keyCount == 3)
    }

    @Test("an immature coinbase coin cannot pass review; a mature one can")
    func coinbaseMaturity() throws {
        let (vault, _) = try TestVaults.multiAVault()
        var utxo = try TestVaults.funding(vault: vault, amount: 100_000, height: 1_000)
        utxo.isCoinbase = true
        let owned = [Vault.OutputCoordinate(choice: AddressChain.change.rawValue, index: 0)]
        let spend = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })

        // One confirmation short of Wallet.coinbaseMaturity: refused, and the
        // error counts the blocks left rather than restating the rule.
        let oneShort = utxo.height + Wallet.coinbaseMaturity - 2
        #expect(throws: VaultError.invalidSpend(
            "input 1 spends a coinbase that matures in 1 blocks")) {
            _ = try vault.reviewSpend(spend, knownUTXOs: [utxo],
                                      ownedOutputCoordinates: owned, chainTip: oneShort)
        }

        // The exact boundary — the funding block is confirmation one — passes,
        // and the same coin without the flag never trips the gate at all.
        let matureAt = utxo.height + Wallet.coinbaseMaturity - 1
        _ = try vault.reviewSpend(spend, knownUTXOs: [utxo],
                                  ownedOutputCoordinates: owned, chainTip: matureAt)
        var plain = utxo
        plain.isCoinbase = false
        _ = try vault.reviewSpend(spend, knownUTXOs: [plain],
                                  ownedOutputCoordinates: owned, chainTip: oneShort)
    }

    @Test("vault review trusts known coins and descriptor scripts, not PSBT labels")
    func vaultSpendReview() throws {
        let (vault, _) = try TestVaults.multiAVault()
        let utxo = try TestVaults.funding(vault: vault, amount: 100_000)
        let changeCoordinate = Vault.OutputCoordinate(choice: AddressChain.change.rawValue, index: 0)
        let created = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })

        let review = try vault.reviewSpend(
            created, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate],
                chainTip: testChainTip)
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
            forgedLabel, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate],
                chainTip: testChainTip)
        #expect(forgedReview.outputs[externalIndex].isVaultOwned == false)

        var wrongAmount = created
        wrongAmount.inputs[0].witnessUTXO = SighashBIP341.SpentOutput(
            amount: utxo.amount + 1, scriptPubKey: utxo.scriptPubKey)
        #expect(throws: VaultError.self) {
            _ = try vault.reviewSpend(
                wrongAmount, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate],
                chainTip: testChainTip)
        }

        var unsafeSighash = created
        unsafeSighash.inputs[0].sighashType = 2 // SIGHASH_NONE
        #expect(throws: VaultError.self) {
            _ = try vault.reviewSpend(
                unsafeSighash, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate],
                chainTip: testChainTip)
        }

        var changedPolicy = created
        changedPolicy.inputs[0].tapInternalKey = Data(repeating: 0x44, count: 32)
        #expect(throws: VaultError.self) {
            _ = try vault.reviewSpend(
                changedPolicy, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate],
                chainTip: testChainTip)
        }

        var absurdFee = created
        let paymentIndex = try #require(absurdFee.outputs.firstIndex { $0.script == destination })
        absurdFee.outputs[paymentIndex].amount = 1
        let vaultOutputIndex = try #require(absurdFee.outputs.firstIndex { $0.script != destination })
        absurdFee.outputs[vaultOutputIndex].amount = 1
        #expect(throws: VaultError.self) {
            _ = try vault.reviewSpend(
                absurdFee, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate],
                chainTip: testChainTip)
        }

        var unsupportedVersion = created
        unsupportedVersion.globals.removeAll { $0.type == PSBT.GlobalType.txVersion }
        unsupportedVersion.globals.append(PSBT.KeyValue(
            type: PSBT.GlobalType.txVersion,
            value: Data([3, 0, 0, 0])))
        #expect(throws: VaultError.self) {
            _ = try vault.reviewSpend(
                unsupportedVersion, knownUTXOs: [utxo], ownedOutputCoordinates: [changeCoordinate],
                chainTip: testChainTip)
        }
    }

    /// The creator and every reviewer apply one fee ceiling. Before this,
    /// `createSpend` built a proposal at any fee rate, and once the fee took
    /// more than ten percent of the inputs every cosigner's `partialSign`
    /// refused it: a PSBT nobody could sign.
    @Test("createSpend refuses the fee its cosigners' review would refuse")
    func createSpendFeeCeiling() throws {
        let (vault, _) = try TestVaults.multiAVault()
        let utxo = try TestVaults.funding(vault: vault, amount: 100_000)
        // A one-input, two-output multi_a spend is about 220 vbytes, so 100
        // sat/vB is roughly a 22,000-sat fee: past the 10,000-sat ceiling for
        // this coin, yet still affordable, so the ceiling is the only refusal.
        do {
            _ = try vault.createSpend(
                utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
                changeIndex: 0, feeRateSatPerVByte: 100, chainTip: testChainTip, randomness: { 0.5 })
            Issue.record("expected the fee ceiling to refuse the spend")
        } catch let VaultError.invalidSpend(message) {
            #expect(message.hasSuffix("exceeds the 10% safety limit for these inputs"))
        }
    }

    /// The ceiling is inclusive: a fee of exactly one tenth of the inputs
    /// passes review and one satoshi more does not. Driven at the review
    /// layer, where the outputs — and so the fee — can be set to the satoshi.
    @Test("the fee ceiling admits one tenth of the inputs and refuses one satoshi more")
    func feeCeilingBoundary() throws {
        let (vault, _) = try TestVaults.multiAVault()
        let utxo = try TestVaults.funding(vault: vault, amount: 100_000)
        let owned = [Vault.OutputCoordinate(choice: AddressChain.change.rawValue, index: 0)]
        let created = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        let paymentIndex = try #require(created.outputs.firstIndex { $0.script == destination })
        let vaultOutputIndex = try #require(created.outputs.firstIndex { $0.script != destination })
        let ceiling = utxo.amount / 10

        // Outputs totalling the inputs minus the ceiling: the fee is exactly it.
        var atCeiling = created
        atCeiling.outputs[paymentIndex].amount = utxo.amount - ceiling - 1
        atCeiling.outputs[vaultOutputIndex].amount = 1
        let review = try vault.reviewSpend(
            atCeiling, knownUTXOs: [utxo], ownedOutputCoordinates: owned, chainTip: testChainTip)
        #expect(review.fee == ceiling)

        // One satoshi less paid out is one satoshi over the ceiling.
        var overCeiling = atCeiling
        overCeiling.outputs[paymentIndex].amount = utxo.amount - ceiling - 2
        #expect(throws: VaultError.invalidSpend(
            "the \(ceiling + 1)-sat fee exceeds the 10% safety limit for these inputs")) {
            _ = try vault.reviewSpend(
                overCeiling, knownUTXOs: [utxo], ownedOutputCoordinates: owned, chainTip: testChainTip)
        }
    }

    // MARK: 2-of-2 MuSig2 key-path vault

    @Test("2-of-2 musig vault: nonce round, partial sigs, aggregate, BIP340-verifiable")
    func muSigVault() throws {
        let (vault, masters) = try TestVaults.muSig2Vault()

        let utxo = try TestVaults.funding(vault: vault, amount: 80_000)
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
            created, knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
        let changeScript = try vault.scriptPubKey(index: 0, choice: AddressChain.change.rawValue)
        #expect(review.outputs.first { $0.scriptPubKey == changeScript }?.isVaultOwned == true)

        var tooManyOutputs = created
        tooManyOutputs.outputs = Array(repeating: created.outputs[0], count: 1_001)
        #expect(throws: VaultError.self) {
            try vault.reviewSpend(tooManyOutputs, knownUTXOs: [utxo],
                                  ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
        }

        // Round 1: each cosigner attaches its public nonce to its own copy.
        let base64 = created.base64
        var noncePSBT_A = try PSBT(base64: base64)
        var secnoncesA = try vault.muSig2AttachNonce(
            &noncePSBT_A, input: 0, context: context, master: masters[0],
            knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
        var noncePSBT_B = try PSBT(base64: base64)
        var secnoncesB = try vault.muSig2AttachNonce(
            &noncePSBT_B, input: 0, context: context, master: masters[1],
            knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
        #expect(noncePSBT_A.inputs[0].musig2PubNonces.count == 1)
        let output = try Taproot.tweakedOutputKey(internalKey: context.internalKey, merkleRoot: nil)
        let signingKey = Data([output.parity ? 0x03 : 0x02]) + output.key
        #expect(noncePSBT_A.inputs[0].musig2PubNonces.keys.first?.aggregate == signingKey)
        #expect(signingKey != context.aggregate)
        #expect(secnoncesA.count == 1 && secnoncesB.count == 1)

        // Combine nonces, then round 2: each cosigner partial-signs the
        // combined PSBT.
        let withNonces = try noncePSBT_A.combined(with: [noncePSBT_B])
        #expect(withNonces.inputs[0].musig2PubNonces.count == 2)
        var signedA = withNonces
        try vault.muSig2Sign(&signedA, input: 0, context: context, master: masters[0],
                             secretNonces: &secnoncesA, knownUTXOs: [utxo],
                             ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
        var signedB = withNonces
        try vault.muSig2Sign(&signedB, input: 0, context: context, master: masters[1],
                             secretNonces: &secnoncesB, knownUTXOs: [utxo],
                             ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
        // The secnonce was zeroed — reuse is rejected.
        #expect(secnoncesA.values.first?.allSatisfy { $0 == 0 } == true)
        #expect(signedA.inputs[0].musig2PartialSigs.count == 1)

        // Combine partials, aggregate into the key-path signature, finalize.
        var combined = try signedA.combined(with: [signedB])
        try vault.muSig2Aggregate(&combined, input: 0, context: context,
                                  knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)
        #expect(combined.inputs[0].tapKeySignature?.count == 64)
        let signed = try vault.finalizeSpend(&combined, knownUTXOs: [utxo],
                                             ownedOutputCoordinates: ownedCoordinates,
                              chainTip: testChainTip)

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
        let (vault, _) = try TestVaults.muSig2Vault()
        let utxo = try TestVaults.funding(vault: vault, amount: 80_000)
        var psbt = try vault.createSpend(utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
                                         changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        let context = try vault.muSig2Context(choice: 0, index: 0)
        // The third master is not a participant: no nonce, no signature.
        let outsider = try TestVaults.masters()[2]
        #expect(throws: VaultError.noCosignerKey(input: 0)) {
            _ = try vault.muSig2AttachNonce(
                &psbt, input: 0, context: context, master: outsider,
                knownUTXOs: [utxo],
                ownedOutputCoordinates: [.init(choice: 1, index: 0)],
                chainTip: testChainTip)
        }
    }

    // MARK: - Vault thresholds and signing coverage
    //
    // Thresholds and signing coverage (epic #100, invariant S8).
    //
    // The flows above prove that *a* 2-of-3 spend works — cosigners 0 and 2.
    // A k-of-n custody promise is stronger than that: it says **every** valid
    // combination of k cosigners can spend, and no combination of fewer can.
    // One untested pair is a pair that might not be able to move the money when
    // it matters, which for an inheritance or a lost-key recovery is the whole
    // point of the vault.
    //
    // These tests therefore enumerate rather than sample.

    // MARK: Threshold boundaries

    /// k must lie in 1...n. Zero and negative thresholds would be a vault
    /// anyone can spend; k > n would be a vault nobody can spend.
    @Test("a threshold outside 1...n is refused", arguments: [-1, 0, 4, 99])
    func thresholdOutsideRangeRefused(_ k: Int) throws {
        let expressions = try TestVaults.masters().map { try TestVaults.keyExpression(master: $0) }
        #expect(throws: DescriptorError.invalidThreshold) {
            _ = try Vault.multiADescriptor(threshold: k, cosigners: expressions)
        }
    }

    /// Every in-range threshold builds, and each produces a *different*
    /// script — so the threshold genuinely reaches the output key rather than
    /// being decorative metadata.
    @Test("each in-range threshold builds a distinct vault")
    func inRangeThresholdsAreDistinct() throws {
        var addresses: Set<String> = []
        for k in 1 ... 3 {
            let built = try TestVaults.multiAVault(threshold: k)
            #expect(built.vault.usesUnspendableInternalKey)
            addresses.insert(try built.vault.address(index: 0))
        }
        #expect(addresses.count == 3, "1-of-3, 2-of-3 and 3-of-3 must not share an address")
    }

    // MARK: Every valid signing combination

    /// The headline S8 requirement: all three 2-of-3 pairs, each independently
    /// carried end to end and verified cryptographically.
    @Test("every 2-of-3 cosigner pair can spend",
          arguments: [(0, 1), (0, 2), (1, 2)])
    func everyPairCanSpend(_ pair: (Int, Int)) throws {
        let (vault, masters) = try TestVaults.multiAVault(threshold: 2)
        let utxo = try TestVaults.funding(vault: vault, amount: 100_000)
        let owned = [Vault.OutputCoordinate(choice: 1, index: 0)]
        let created = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })

        var first = try PSBT(base64: created.base64)
        try vault.partialSign(&first, master: masters[pair.0], knownUTXOs: [utxo],
                              ownedOutputCoordinates: owned, chainTip: testChainTip)
        var second = try PSBT(base64: created.base64)
        try vault.partialSign(&second, master: masters[pair.1], knownUTXOs: [utxo],
                              ownedOutputCoordinates: owned, chainTip: testChainTip)

        var combined = try first.combined(with: [second])
        #expect(combined.inputs[0].tapScriptSignatures.count == 2)
        let signed = try vault.finalizeSpend(&combined, knownUTXOs: [utxo],
                                             ownedOutputCoordinates: owned, chainTip: testChainTip)
        let result = try verifyMultisigSpend(tx: signed, inputIndex: 0,
                                            spentOutputs: [utxo.spentOutput])
        #expect(result.validSignatures == 2, "pair \(pair) must produce two valid signatures")
        #expect(result.threshold == 2)
        #expect(result.keyCount == 3)
    }

    /// A PSBT's derivation entries are written by the other cosigners. One
    /// that names our fingerprint with a path no BIP32 key can have is not
    /// ours, whatever it claims: it is skipped like any other mismatch, so a
    /// hostile or buggy entry cannot stop us signing a spend we hold a key for.
    @Test("a derivation entry too deep for any key is ignored, not fatal")
    func impossibleDerivationEntryIgnored() throws {
        let (vault, masters) = try TestVaults.multiAVault(threshold: 2)
        let utxo = try TestVaults.funding(vault: vault, amount: 100_000)
        let owned = [Vault.OutputCoordinate(choice: 1, index: 0)]
        let created = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })

        var psbt = try PSBT(base64: created.base64)
        psbt.inputs[0].tapBIP32Derivation[Data(repeating: 0x02, count: 32)] = PSBT.KeyOrigin(
            masterFingerprint: masters[0].fingerprint, path: Array(repeating: 0, count: 256))
        try vault.partialSign(&psbt, master: masters[0], knownUTXOs: [utxo],
                              ownedOutputCoordinates: owned, chainTip: testChainTip)
        #expect(psbt.inputs[0].tapScriptSignatures.count == 1)
    }

    /// The other half of the promise: no single cosigner can spend a 2-of-3,
    /// checked for each of the three in turn rather than for one sample.
    @Test("no single cosigner can finalize a 2-of-3", arguments: [0, 1, 2])
    func noSingleCosignerCanSpend(_ index: Int) throws {
        let (vault, masters) = try TestVaults.multiAVault(threshold: 2)
        let utxo = try TestVaults.funding(vault: vault, amount: 100_000)
        let owned = [Vault.OutputCoordinate(choice: 1, index: 0)]
        let created = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })

        var alone = try PSBT(base64: created.base64)
        try vault.partialSign(&alone, master: masters[index], knownUTXOs: [utxo],
                              ownedOutputCoordinates: owned, chainTip: testChainTip)
        #expect(alone.inputs[0].tapScriptSignatures.count == 1)

        var toFinalize = alone
        #expect(throws: (any Error).self) {
            _ = try vault.finalizeSpend(&toFinalize, knownUTXOs: [utxo],
                                        ownedOutputCoordinates: owned, chainTip: testChainTip)
        }
    }

    /// A 3-of-3 needs all three, and having exactly two is not enough — the
    /// boundary is checked from below as well as at it.
    @Test("a 3-of-3 vault needs all three cosigners")
    func threeOfThreeNeedsEveryone() throws {
        let (vault, masters) = try TestVaults.multiAVault(threshold: 3)
        let utxo = try TestVaults.funding(vault: vault, amount: 100_000)
        let owned = [Vault.OutputCoordinate(choice: 1, index: 0)]
        let created = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })

        var signed: [PSBT] = []
        for master in masters {
            var copy = try PSBT(base64: created.base64)
            try vault.partialSign(&copy, master: master, knownUTXOs: [utxo],
                                  ownedOutputCoordinates: owned, chainTip: testChainTip)
            signed.append(copy)
        }

        // Two of three: below threshold.
        var short = try signed[0].combined(with: [signed[1]])
        #expect(short.inputs[0].tapScriptSignatures.count == 2)
        #expect(throws: (any Error).self) {
            _ = try vault.finalizeSpend(&short, knownUTXOs: [utxo], ownedOutputCoordinates: owned, chainTip: testChainTip)
        }

        // All three: spendable.
        var full = try signed[0].combined(with: [signed[1], signed[2]])
        #expect(full.inputs[0].tapScriptSignatures.count == 3)
        let tx = try vault.finalizeSpend(&full, knownUTXOs: [utxo], ownedOutputCoordinates: owned, chainTip: testChainTip)
        let result = try verifyMultisigSpend(tx: tx, inputIndex: 0,
                                            spentOutputs: [utxo.spentOutput])
        #expect(result.validSignatures == 3)
        #expect(result.threshold == 3)
    }

    // MARK: Threshold arithmetic used by the creation screen

    /// `clamped` must never return a threshold outside 1...max(keyCount, 1),
    /// checked exhaustively over the range the stepper can reach rather than
    /// at a couple of sampled points.
    @Test("clamped never escapes 1...keyCount")
    func clampedStaysInRange() {
        for keyCount in 0 ... 6 {
            for threshold in -3 ... 9 {
                let value = VaultThreshold.clamped(threshold, keyCount: keyCount)
                #expect(value >= 1, "clamped(\(threshold), keyCount: \(keyCount)) = \(value)")
                #expect(value <= max(keyCount, 1))
                // Already-valid values are preserved rather than nudged.
                if threshold >= 1, threshold <= max(keyCount, 1) {
                    #expect(value == threshold)
                }
            }
        }
    }

    /// Adding the second signer snaps to 2-of-2, the safest useful default;
    /// every later change preserves a still-valid choice.
    @Test("reconciled snaps to 2-of-2 on the second key and preserves choice after")
    func reconciledDefaultsAndPreserves() {
        // First key present, second added: snap to 2 regardless of prior value.
        for previous in [1, 2, 5] {
            #expect(VaultThreshold.reconciled(previous, previousKeyCount: 1, keyCount: 2) == 2)
        }
        // Third key added: a valid existing choice survives.
        #expect(VaultThreshold.reconciled(2, previousKeyCount: 2, keyCount: 3) == 2)
        #expect(VaultThreshold.reconciled(3, previousKeyCount: 2, keyCount: 3) == 3)
        // Deleting a key clamps down rather than leaving an impossible vault.
        #expect(VaultThreshold.reconciled(3, previousKeyCount: 3, keyCount: 2) == 2)
        #expect(VaultThreshold.reconciled(2, previousKeyCount: 2, keyCount: 0) == 1)
    }

    /// The stepper and delete button cannot drive the draft into an invalid
    /// threshold, whatever order they are used in.
    @Test("draft threshold stays valid across stepper and deletion")
    func draftThresholdStaysValid() throws {
        var draft = VaultDraft(role: .scriptPath)
        let masters = try TestVaults.masters()
        for master in masters {
            try draft.add(try TestVaults.keyExpression(master: master), network: .signet)
            #expect(draft.threshold >= 1)
            #expect(draft.threshold <= draft.cosigners.count)
        }
        #expect(draft.threshold == 2, "three keys added one at a time defaults to 2-of-3")

        draft.setThreshold(3)
        #expect(draft.threshold == 3)
        draft.remove(at: IndexSet(integer: 2))
        #expect(draft.threshold == 2, "deleting a key must clamp the threshold down")
        draft.setThreshold(99)
        #expect(draft.threshold == 2)
        draft.setThreshold(-5)
        #expect(draft.threshold == 1)
    }

    // MARK: - PSBT multisig fields and combiner
    //
    // The Phase-5 PSBT fields and roles: BIP371 leaf fields (tap leaf script,
    // tap script sig, tap tree), BIP373 MuSig2 fields, the combiner role
    // (union merge, conflict/duplicate handling), and script-path finalize
    // including wrong-key rejection.

    /// A minimal 1-in/1-out PSBTv2 spending a fabricated multi_a vault UTXO.
    struct Fixture {
        let masters: [HDKey]
        let psbt: PSBT
        let tx: Transaction
        let leafScript: Script
        let controlBlock: Taproot.ControlBlock
        let leafKeys: [Data] // x-only, script order
        let secrets: [Data]

        init() throws {
            masters = try [Data(repeating: 0x11, count: 16), Data(repeating: 0x22, count: 16)]
                .map { try HDKey(seed: BIP39.seed(mnemonic: BIP39.mnemonic(entropy: $0))) }
            secrets = masters.map { $0.privateKey! }
            leafKeys = try secrets.map { Data(try P256K.Schnorr.PrivateKey(dataRepresentation: $0).xonly.bytes) }
            leafScript = try Multisig.script(threshold: 2, xonlyKeys: leafKeys, sorted: false)
            let tree = Taproot.Tree.leaf(script: leafScript)
            controlBlock = try Taproot.controlBlock(internalKey: Taproot.unspendableInternalKey,
                                                    tree: tree, leafIndex: 0)
            let scriptPubKey = try Taproot.scriptPubKey(internalKey: Taproot.unspendableInternalKey,
                                                        merkleRoot: Taproot.merkleRoot(of: tree))
            tx = try TransactionBuilder.build(
                inputs: [Transaction.Outpoint(txid: Data(repeating: 0x99, count: 32), vout: 0)],
                payments: [Payment(amount: 90_000, scriptPubKey: Data([0x51, 0x20] + repeatElement(0x77, count: 32)))])
            var psbt = try PSBT(unsignedTx: tx,
                                inputs: [PSBT.InputInfo(spentOutput: .init(amount: 100_000,
                                                                           scriptPubKey: scriptPubKey))],
                                outputs: [PSBT.OutputInfo()])
            try psbt.attachScriptPath(input: 0, controlBlock: controlBlock, leafScript: leafScript)
            self.psbt = psbt
        }
    }

    @Test("BIP371 leaf fields round-trip through the wire format")
    func leafFieldRoundTrip() throws {
        let fixture = try Fixture()
        let input = fixture.psbt.inputs[0]
        #expect(input.tapInternalKey == Taproot.unspendableInternalKey)
        let leaves = input.tapLeafScripts
        #expect(leaves.count == 1)
        #expect(leaves[0].controlBlock == fixture.controlBlock)
        #expect(leaves[0].script == fixture.leafScript.bytes)
        #expect(leaves[0].leafVersion == Taproot.leafVersion)
        #expect(leaves[0].leafHash == Taproot.leafHash(script: fixture.leafScript))

        // Signature fields.
        var psbt = fixture.psbt
        let sig = Data(repeating: 0x42, count: 64)
        psbt.inputs[0].tapScriptSignatures = [
            PSBT.TapScriptSignatureID(publicKey: fixture.leafKeys[0], leafHash: leaves[0].leafHash): sig,
        ]
        let parsed = try PSBT(serialized: psbt.serialized)
        #expect(parsed == psbt)
        #expect(parsed.inputs[0].tapScriptSignatures.count == 1)
        #expect(parsed.inputs[0].tapLeafScripts.count == 1)
        #expect(try PSBT(base64: psbt.base64) == psbt)
    }

    @Test("BIP371 tap tree + BIP373 musig2 fields round-trip")
    func outputAndMuSig2Fields() throws {
        var output = PSBT.Output()
        output.tapInternalKey = Taproot.unspendableInternalKey
        output.tapTree = [(depth: 0, leafVersion: Taproot.leafVersion, script: Data([0x51]))]
        var input = PSBT.Input()
        let aggregate = Data([0x02] + repeatElement(0x01, count: 32))
        let participants = [Data([0x02] + repeatElement(0x02, count: 32)),
                            Data([0x03] + repeatElement(0x03, count: 32))]
        input.musig2ParticipantPubKeys = [aggregate: participants]
        let id = PSBT.MuSig2KeyID(participant: participants[0], aggregate: aggregate)
        input.musig2PubNonces = [id: Data(repeating: 0x07, count: 66)]
        input.musig2PartialSigs = [id: Data(repeating: 0x08, count: 32)]
        // With a tapleaf hash suffix (script-path musig) the key grows by 32 bytes.
        let leafID = PSBT.MuSig2KeyID(participant: participants[1], aggregate: aggregate,
                                      leafHash: Data(repeating: 0x09, count: 32))
        var nonces = input.musig2PubNonces
        nonces[leafID] = Data(repeating: 0x0A, count: 66)
        input.musig2PubNonces = nonces

        let psbt = PSBT(globals: [
            PSBT.KeyValue(type: PSBT.GlobalType.inputCount, value: Data([0x01])),
            PSBT.KeyValue(type: PSBT.GlobalType.outputCount, value: Data([0x01])),
            PSBT.KeyValue(type: PSBT.GlobalType.version, value: Data([0x02, 0x00, 0x00, 0x00])),
        ], inputs: [input], outputs: [output])
        let parsed = try PSBT(serialized: psbt.serialized)
        #expect(parsed == psbt)
        #expect(parsed.outputs[0].tapTree?.count == 1)
        #expect(parsed.outputs[0].tapTree?[0].script == Data([0x51]))
        #expect(parsed.inputs[0].musig2ParticipantPubKeys[aggregate] == participants)
        #expect(parsed.inputs[0].musig2PubNonces.count == 2)
        #expect(parsed.inputs[0].musig2PubNonces[leafID] == Data(repeating: 0x0A, count: 66))
        #expect(parsed.inputs[0].musig2PartialSigs[id] == Data(repeating: 0x08, count: 32))
    }

    @Test("script-path signer attaches verified partial signatures")
    func scriptPathSigning() throws {
        let fixture = try Fixture()
        var psbt = fixture.psbt
        try psbt.signScriptPath(input: 0, privateKeys: [fixture.secrets[0]],
                                auxiliaryRand: Data(repeating: 0, count: 32))
        let sigs = psbt.inputs[0].tapScriptSignatures
        #expect(sigs.count == 1)
        let leafHash = Taproot.leafHash(script: fixture.leafScript)
        let sig = try #require(sigs[PSBT.TapScriptSignatureID(publicKey: fixture.leafKeys[0], leafHash: leafHash)])
        #expect(sig.count == 64) // SIGHASH_DEFAULT

        // A key that is not in the leaf signs nothing and throws.
        let outsider = Data(repeating: 0x07, count: 32)
        #expect(throws: PSBTError.self) {
            try psbt.signScriptPath(input: 0, privateKeys: [outsider])
        }
        #expect(psbt.inputs[0].tapScriptSignatures.count == 1)
    }

    @Test("combiner: union merge, duplicate dedupe, conflict detection")
    func combiner() throws {
        let fixture = try Fixture()
        var first = fixture.psbt
        var second = fixture.psbt
        try first.signScriptPath(input: 0, privateKeys: [fixture.secrets[0]],
                                 auxiliaryRand: Data(repeating: 0, count: 32))
        try second.signScriptPath(input: 0, privateKeys: [fixture.secrets[1]],
                                  auxiliaryRand: Data(repeating: 0, count: 32))

        let merged = try first.combined(with: [second])
        #expect(merged.inputs[0].tapScriptSignatures.count == 2)
        // Combining is idempotent — identical pairs dedupe.
        #expect(try merged.combined(with: [first]) == merged)
        #expect(try first.combined(with: []) == first)

        // Same key, different value → conflict.
        var conflicted = fixture.psbt
        conflicted.inputs[0].sighashType = 1 // SIGHASH_ALL vs the base DEFAULT
        #expect(throws: PSBTError.conflict(Data([PSBT.InType.sighashType]))) {
            _ = try fixture.psbt.combined(with: [conflicted])
        }

        // A PSBT of a different transaction cannot combine.
        let otherTx = try TransactionBuilder.build(
            inputs: [Transaction.Outpoint(txid: Data(repeating: 0x55, count: 32), vout: 1)],
            payments: [Payment(amount: 1_000, scriptPubKey: Data([0x51, 0x20] + repeatElement(0x11, count: 32)))])
        var other = try PSBT(unsignedTx: otherTx,
                             inputs: [PSBT.InputInfo(spentOutput: .init(amount: 2_000, scriptPubKey: Data([0x51, 0x20] + repeatElement(0x11, count: 32))))],
                             outputs: [PSBT.OutputInfo()])
        other.globals = fixture.psbt.globals // same map counts, different tx
        #expect(throws: PSBTError.self) { _ = try fixture.psbt.combined(with: [other]) }
    }

    @Test("finalize: threshold enforcement and wrong-key rejection")
    func finalizeScriptPath() throws {
        let fixture = try Fixture()
        // Below threshold: a single partial of a 2-of-2 cannot finalize.
        var partial = fixture.psbt
        try partial.signScriptPath(input: 0, privateKeys: [fixture.secrets[0]],
                                   auxiliaryRand: Data(repeating: 0, count: 32))
        #expect(throws: PSBTError.self) { try partial.finalize() }

        // Two valid partials finalize into the BIP387 witness.
        var other = fixture.psbt
        try other.signScriptPath(input: 0, privateKeys: [fixture.secrets[1]],
                                 auxiliaryRand: Data(repeating: 0, count: 32))
        var complete = try partial.combined(with: [other])
        try complete.finalize()
        let witness = try #require(complete.inputs[0].finalScriptWitness)
        #expect(witness.count == 4) // 2 sig slots + leaf script + control block
        #expect(witness[2] == fixture.leafScript.bytes)
        #expect(witness[3] == fixture.controlBlock.serialized)
        // Partial fields are cleared by the finalizer (BIP174).
        #expect(complete.inputs[0].tapScriptSignatures.isEmpty)
        #expect(complete.inputs[0].tapLeafScripts.isEmpty)

        // A foreign signature (valid schnorr, wrong key) is discarded by the
        // finalizer — the input stays below threshold and cannot finalize.
        let foreignSecret = Data(repeating: 0x33, count: 32)
        let foreignKey = Data(try P256K.Schnorr.PrivateKey(dataRepresentation: foreignSecret).xonly.bytes)
        let foreignSig = try Signer.scriptPathSignature(
            tx: fixture.tx, inputIndex: 0,
            spentOutputs: [fixture.psbt.inputs[0].witnessUTXO!],
            leafScript: fixture.leafScript, privateKey: foreignSecret,
            auxiliaryRand: Data(repeating: 0, count: 32))
        var poisoned = fixture.psbt
        poisoned.inputs[0].tapScriptSignatures = [
            PSBT.TapScriptSignatureID(publicKey: fixture.leafKeys[0], // attached under a false key id
                                      leafHash: Taproot.leafHash(script: fixture.leafScript)): foreignSig,
            PSBT.TapScriptSignatureID(publicKey: foreignKey,
                                      leafHash: Taproot.leafHash(script: fixture.leafScript)): foreignSig,
        ]
        #expect(foreignKey != fixture.leafKeys[0])
        #expect(throws: PSBTError.self) { try poisoned.finalize() }
    }

    @Test("script-path finalizer verifies the control block against the spent output")
    func finalizerRejectsUncommittedLeaf() throws {
        let fixture = try Fixture()
        var wrongOutput = fixture.psbt
        let unrelatedInternalKey = BIP86.xonlyPublicKey(of: fixture.masters[0])
        wrongOutput.inputs[0].witnessUTXO = .init(
            amount: 100_000,
            scriptPubKey: try BIP86.scriptPubKey(internalKey: unrelatedInternalKey))
        try wrongOutput.signScriptPath(input: 0, privateKeys: fixture.secrets,
                                       auxiliaryRand: Data(repeating: 0, count: 32))
        #expect(throws: PSBTError.self) { try wrongOutput.finalize() }

        var mismatchedVersion = fixture.psbt
        let original = try #require(mismatchedVersion.inputs[0].tapLeafScripts.first)
        mismatchedVersion.inputs[0].tapLeafScripts = [PSBT.TapLeafScript(
            controlBlock: original.controlBlock, script: original.script, leafVersion: 0xC2)]
        try mismatchedVersion.signScriptPath(input: 0, privateKeys: fixture.secrets,
                                             auxiliaryRand: Data(repeating: 0, count: 32))
        #expect(throws: PSBTError.self) { try mismatchedVersion.finalize() }
    }

    /// The vault is the second build site of an anti-fee-sniping locktime. Fixing
    /// only the wallet would move the fingerprint onto vault spends rather than remove it.
    @Test("a vault spend is stamped too")
    func vaultSpendStampsALocktime() throws {
        let masters = try (0 ..< 3).map { try HDKey(seed: Data(repeating: UInt8($0 + 1), count: 32)) }
        let descriptor = try Vault.multiADescriptor(
            threshold: 2, cosigners: masters.map { try TestVaults.keyExpression(master: $0) })
        let vault = try Vault(descriptor: descriptor, network: .signet)
        let utxo = try TestVaults.funding(vault: vault, amount: 100_000)

        let psbt = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: TestScripts.p2trDestination)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: 840_000,
            randomness: { 0.5 })
        // PSBT v2 carries it as the fallback locktime global, which is what the
        // finalizer rebuilds the transaction from.
        #expect(psbt.fallbackLocktime == 840_000)
    }
}

private struct MultisigVerification {
    var threshold: Int
    var keyCount: Int
    var validSignatures: Int
}

/// Replays BIP342 multi_a validation for a finalized input: the control
/// block must commit the leaf to the spent output key, then every witness
/// stack item is matched to its script key (reversed order, BIP387) and
/// each signature verified against the script-path sighash.
private func verifyMultisigSpend(tx: Transaction, inputIndex: Int,
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
