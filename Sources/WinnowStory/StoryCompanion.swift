import BitcoinCore
import BitcoinP2P
import Foundation
@_spi(WinnowStoryUnsafe) import WalletCore

public struct StoryCompanion: Sendable {
    public let state: StoryRunState

    public init(state: StoryRunState) { self.state = state }

    public func master(for personaID: String) throws -> HDKey {
        guard let secret = state.secrets.first(where: { $0.personaID == personaID }),
              let bytes = Data(hex: secret.seedHex) else {
            throw StoryModelError.invalidTransition("missing identity for \(personaID)")
        }
        if ["sofia", "lina", "elena"].contains(personaID) {
            let words = try BIP39.mnemonic(entropy: bytes)
            return try HDKey(seed: BIP39.seed(mnemonic: words))
        }
        return try HDKey(seed: bytes)
    }

    public func keyExpression(for personaID: String, multipath: Bool) throws -> String {
        let master = try master(for: personaID)
        let account = try master.derived(path: "m/86'/1'/0'")
        let fingerprint = String(format: "%08x", master.fingerprint)
        let base = "[\(fingerprint)/86'/1'/0']\(account.neutered.serialized(network: .testnet))"
        return multipath ? base + "/<0;1>/*" : base
    }

    public func standardAddress(for personaID: String, index: UInt32 = 0) throws -> String {
        let account = try master(for: personaID).derived(path: "m/86'/1'/0'")
        let key = try account.derived(path: "0/\(index)")
        return try BIP86.address(internalKey: key.publicKey.dropFirst(), hrp: "tb")
    }

    public func silentAddress(for personaID: String) async throws -> String {
        guard let secret = state.secrets.first(where: { $0.personaID == personaID }),
              let entropy = Data(hex: secret.seedHex), entropy.count == 16 else {
            throw StoryModelError.invalidTransition("\(personaID) is not an app-wallet identity")
        }
        let wallet = try Wallet.create(network: .signet, keyStore: InMemoryKeyStore(), entropy: entropy,
                                       creationHeight: 0)
        return try await wallet.silentPaymentAddress()
    }

    /// Builds a real, signed BIP352 payment from a named companion's known
    /// standard-address UTXO. The caller persists the result before relay so
    /// resuming never creates a different transaction.
    public func prepareSilentSend(label: String, from personaID: String,
                                  inputTxid: String, inputVout: UInt32,
                                  inputAmount: Int64, inputHeight: UInt32,
                                  recipient: String, amount: Int64,
                                  feeRateSatPerVByte: Double) async throws -> StoryCompanionTransaction {
        guard ["lina", "sofia", "elena"].contains(personaID) else {
            throw StoryModelError.invalidTransition("\(personaID) is not an app-wallet identity")
        }
        guard inputTxid.count == 64, inputTxid.allSatisfy(\.isHexDigit),
              inputAmount > 0, amount > 0, amount < inputAmount,
              feeRateSatPerVByte > 0 else {
            throw StoryModelError.invalidTransition("invalid companion silent-send amount, fee rate, or input")
        }

        let wallet = try companionWallet(
            personaID: personaID, inputTxid: inputTxid, inputVout: inputVout,
            inputAmount: inputAmount, inputHeight: inputHeight)
        let silent = try SilentPayment(amount: amount, address: recipient, network: .signet)
        // A fixed tip and a fixed draw, because a story capture is a published
        // artefact: a random locktime would change the txid from run to run and
        // every recorded vector with it. 0.5 misses the one-in-ten lookback
        // branch, so this is exactly `inputHeight`.
        let prepared = try await wallet.buildSend(
            payments: [], feeRateSatPerVByte: feeRateSatPerVByte,
            silentPayments: [silent], chainTip: inputHeight, randomness: { 0.5 })
        guard let tweakData = prepared.silentPaymentTweakData else {
            throw StoryModelError.invalidTransition("silent send did not produce BIP352 tweak data")
        }
        let raw = prepared.built.transaction.serialized(includeWitness: true)
        return StoryCompanionTransaction(
            label: label, personaID: personaID,
            txid: prepared.built.transaction.txid.displayHex,
            rawTransaction: raw.hex, tweakData: tweakData.hex,
            amount: amount, fee: prepared.built.fee)
    }

    /// Reconstructs the exact saved companion send in an isolated in-memory
    /// wallet, then uses WalletCore's BIP125 fee-bump path. The payment output,
    /// input set, and BIP352 tweak point must remain byte-for-byte identical;
    /// only the companion's change and fee may change.
    ///
    /// The caller persists the returned bytes before any relay. Calling this
    /// again with the same arguments produces the same signed replacement.
    public func prepareSilentFeeBump(label: String,
                                     replacing original: StoryCompanionTransaction,
                                     recipientPersonaID: String,
                                     feeRateSatPerVByte: Double) async throws
        -> StoryCompanionTransaction {
        guard feeRateSatPerVByte > 0,
              let raw = Data(hex: original.rawTransaction),
              let source = try? Transaction.decode(raw),
              source.inputs.count == 1,
              let input = source.inputs.first else {
            throw StoryModelError.invalidTransition("saved companion transaction cannot be fee-bumped")
        }
        let vsize = TransactionBuilder.vsize(of: source)
        guard vsize > 0 else {
            throw StoryModelError.invalidTransition("saved companion transaction has no virtual size")
        }
        guard feeRateSatPerVByte.isFinite, feeRateSatPerVByte <= 10_000,
              source.txid.displayHex == original.txid.lowercased(),
              input.sequence < 0xFFFF_FFFE else {
            throw StoryModelError.invalidTransition(
                "saved companion transaction is not a replaceable transaction")
        }
        let inputAmount = source.outputs.reduce(Int64(0)) { $0 + $1.value } + original.fee
        let currentFeeRate = Double(original.fee) / Double(vsize)
        guard feeRateSatPerVByte > currentFeeRate else {
            throw StoryModelError.invalidTransition(
                "replacement fee rate must exceed the saved transaction's fee rate")
        }

        // Authenticate the saved BIP352 destination against the named
        // recipient before carrying that output into a replacement.
        let recipientMaster = try master(for: recipientPersonaID)
        let scan = try SilentPaymentReceiving.scanKey(
            from: recipientMaster, coinType: 1, account: 0)
        let spend = try SilentPaymentReceiving.spendKey(
            from: recipientMaster, coinType: 1, account: 0)
        guard let scanPrivateKey = scan.privateKey,
              let tweakData = Data(hex: original.tweakData) else {
            throw StoryModelError.invalidTransition("saved silent-payment tweak is malformed")
        }
        let shared = try SilentPaymentReceiving.sharedSecret(
            scanPrivateKey: scanPrivateKey, tweakData: tweakData)
        let outputKeys = source.outputs.compactMap { output -> Data? in
            guard output.scriptPubKey.count == 34,
                  output.scriptPubKey.prefix(2).elementsEqual([0x51, 0x20]) else { return nil }
            return Data(output.scriptPubKey.dropFirst(2))
        }
        let matches = try SilentPaymentReceiving.scan(
            outputs: outputKeys, sharedSecret: shared,
            spendPublicKey: spend.publicKey)
        let matchedKeys = Set(matches.map(\.outputKey))
        let paymentOutputs = source.outputs.filter {
            $0.value == original.amount && $0.scriptPubKey.count == 34
                && matchedKeys.contains(Data($0.scriptPubKey.dropFirst(2)))
        }
        guard paymentOutputs.count == 1 else {
            throw StoryModelError.invalidTransition(
                "saved transaction does not contain exactly one payment to the named silent recipient")
        }

        // Locate Lina's known change output by derivation, not by position or
        // amount, then duplicate WalletCore's BIP125 fee calculation while
        // preserving the saved transaction's output order.
        let senderMaster = try master(for: original.personaID)
        let account = try senderMaster.derived(path: "m/86'/1'/0'")
        let inputKey = try account.derived(path: "0/0")
        let changeKey = try account.derived(path: "1/0")
        let inputScript = try BIP86.scriptPubKey(internalKey: inputKey.publicKey.dropFirst())
        let changeScript = try BIP86.scriptPubKey(internalKey: changeKey.publicKey.dropFirst())
        let changeIndices = source.outputs.indices.filter {
            source.outputs[$0].scriptPubKey == changeScript
        }
        guard changeIndices.count == 1, let changeIndex = changeIndices.first,
              let inputPrivateKey = inputKey.privateKey else {
            throw StoryModelError.invalidTransition(
                "saved transaction has no unique companion change output")
        }
        let payments = source.outputs.enumerated().compactMap { index, output -> Payment? in
            index == changeIndex ? nil
                : Payment(amount: output.value, scriptPubKey: output.scriptPubKey)
        }
        let paymentTotal = payments.reduce(Int64(0)) { $0 + $1.amount }
        let maximumFee = inputAmount - paymentTotal
        func requiredFee(vsize: Int) -> Int64 {
            let requested = Int64((Double(vsize) * feeRateSatPerVByte).rounded(.up))
            let incremental = Int64((Double(vsize) * 1.0).rounded(.up))
            return max(requested, original.fee + incremental)
        }

        let originalChange = source.outputs[changeIndex]
        let withChangeOutputs = payments.map {
            Transaction.Output(value: $0.amount, scriptPubKey: $0.scriptPubKey)
        } + [originalChange]
        let withChangeVSize = TransactionBuilder.signedVSize(
            inputCount: source.inputs.count, outputs: withChangeOutputs)
        let feeWithChange = requiredFee(vsize: withChangeVSize)
        let candidateChange = inputAmount - paymentTotal - feeWithChange
        let dust = CoinSelection.dustThreshold(scriptPubKey: changeScript)

        var replacementTransaction: Transaction
        let replacementFee: Int64
        if candidateChange >= dust {
            replacementFee = feeWithChange
            replacementTransaction = try TransactionBuilder.build(
                inputs: source.inputs.map(\.previousOutput), payments: payments,
                change: Payment(amount: candidateChange, scriptPubKey: changeScript),
                changePosition: changeIndex,
                sequence: TransactionBuilder.defaultSequence,
                locktime: source.locktime)
        } else {
            let noChangeOutputs = payments.map {
                Transaction.Output(value: $0.amount, scriptPubKey: $0.scriptPubKey)
            }
            let noChangeVSize = TransactionBuilder.signedVSize(
                inputCount: source.inputs.count, outputs: noChangeOutputs)
            let minimum = requiredFee(vsize: noChangeVSize)
            guard maximumFee >= minimum else {
                throw StoryModelError.invalidTransition(
                    "companion change cannot pay the requested replacement fee")
            }
            replacementFee = maximumFee
            replacementTransaction = try TransactionBuilder.build(
                inputs: source.inputs.map(\.previousOutput), payments: payments,
                sequence: TransactionBuilder.defaultSequence,
                locktime: source.locktime)
        }

        let spent = SighashBIP341.SpentOutput(amount: inputAmount, scriptPubKey: inputScript)
        let tweakedPrivateKey = try BIP86.tweakedPrivateKey(inputPrivateKey)
        try Signer.sign(
            tx: &replacementTransaction, spentOutputs: [spent],
            auxiliaryRand: Data(repeating: 0, count: 32)) { script in
                script == inputScript ? tweakedPrivateKey : nil
            }
        let actualRate = Double(replacementFee)
            / Double(TransactionBuilder.vsize(of: replacementTransaction))
        guard replacementFee > original.fee, actualRate > currentFeeRate,
              replacementTransaction.inputs.map(\.previousOutput)
                == source.inputs.map(\.previousOutput),
              replacementTransaction.outputs.contains(paymentOutputs[0]) else {
            throw StoryModelError.invalidTransition(
                "fee replacement changed the silent destination or did not increase the fee")
        }
        return StoryCompanionTransaction(
            label: label, personaID: original.personaID,
            txid: replacementTransaction.txid.displayHex,
            rawTransaction: replacementTransaction.serialized(includeWitness: true).hex,
            tweakData: original.tweakData.lowercased(), amount: original.amount,
            fee: replacementFee, replaces: original.txid.lowercased())
    }

    private func companionWallet(personaID: String,
                                 inputTxid: String, inputVout: UInt32,
                                 inputAmount: Int64, inputHeight: UInt32) throws -> Wallet {
        guard let secret = state.secrets.first(where: { $0.personaID == personaID }),
              let entropy = Data(hex: secret.seedHex), entropy.count == 16 else {
            throw StoryModelError.invalidTransition("\(personaID) is not an app-wallet identity")
        }
        let mnemonic = try BIP39.mnemonic(entropy: entropy)
        let inputAddress = try standardAddress(for: personaID)
        let inputScript = try Payment(amount: inputAmount, address: inputAddress,
                                      network: .signet).scriptPubKey
        let bundle = ImportBundle(
            network: "signet", mnemonic: mnemonic,
            lastKnownHeight: inputHeight,
            utxos: [ImportBundle.UTXO(
                txid: inputTxid.lowercased(), vout: inputVout,
                amount: inputAmount, scriptPubKey: inputScript.hex,
                chain: AddressChain.receive.rawValue, index: 0,
                height: inputHeight)],
            transactions: [ImportBundle.KnownTransaction(
                txid: inputTxid.lowercased(), height: inputHeight,
                received: inputAmount, spent: 0)])
        return try Wallet.importing(bundle, keyStore: InMemoryKeyStore())
    }

    public func inheritanceDescriptor() throws -> Descriptor {
        try Vault.multiADescriptor(
            threshold: 2,
            cosigners: ["elena", "leo", "marina"].map {
                try keyExpression(for: $0, multipath: true)
            })
    }

    public func jointReserveDescriptor() throws -> Descriptor {
        let participants = try ["elena", "mateo"].map { try keyExpression(for: $0, multipath: false) }
        return try Descriptor("tr(musig(\(participants.joined(separator: ",")))/<0;1>/*)")
    }

    public func partialSignInheritance(psbtBase64: String, as personaID: String) throws -> String {
        guard ["elena", "leo", "marina"].contains(personaID) else {
            throw StoryModelError.invalidTransition("\(personaID) is not an inheritance-vault signer")
        }
        let vault = try Vault(descriptor: inheritanceDescriptor(), network: .signet)
        var psbt = try PSBT(base64: psbtBase64)
        try vault.storyPartialSign(&psbt, master: master(for: personaID))
        return psbt.base64
    }

    /// Mateo's MuSig2 round 1. The returned state contains secret nonces and
    /// must immediately replace the protected run state on disk.
    public func attachMateoNonces(psbtBase64: String) throws -> (psbt: String, state: StoryRunState) {
        if let saved = state.musigPartialPSBT ?? state.musigNoncePSBT {
            return (saved, state)
        }
        let vault = try Vault(descriptor: jointReserveDescriptor(), network: .signet)
        var psbt = try PSBT(base64: psbtBase64)
        var updated = state
        updated.musigSecretNonces.removeAll()
        for input in psbt.inputs.indices {
            let context = try vault.muSig2Context(choice: 0, index: 0)
            let nonces = try vault.storyMuSig2AttachNonce(
                &psbt, input: input, context: context, master: master(for: "mateo"))
            for (pubkey, secret) in nonces {
                updated.musigSecretNonces["\(input):\(pubkey.hex)"] = secret.hex
            }
        }
        updated.musigNoncePSBT = psbt.base64
        updated.musigPartialPSBT = nil
        updated.updatedAt = Date()
        return (psbt.base64, updated)
    }

    /// Mateo's MuSig2 round 2. Consumes and removes the protected secret
    /// nonces so resuming cannot accidentally reuse them.
    public func signMateo(psbtBase64: String) throws -> (psbt: String, state: StoryRunState) {
        if let saved = state.musigPartialPSBT {
            return (saved, state)
        }
        let vault = try Vault(descriptor: jointReserveDescriptor(), network: .signet)
        var psbt = try PSBT(base64: psbtBase64)
        var updated = state
        guard !updated.musigSecretNonces.isEmpty else {
            throw StoryModelError.invalidTransition("Mateo has no live MuSig2 nonce session; repeat round 1")
        }
        for input in psbt.inputs.indices {
            let prefix = "\(input):"
            var nonces: [Data: Data] = [:]
            for (key, value) in updated.musigSecretNonces where key.hasPrefix(prefix) {
                guard let pubkey = Data(hex: String(key.dropFirst(prefix.count))),
                      let secret = Data(hex: value) else { continue }
                nonces[pubkey] = secret
            }
            let context = try vault.muSig2Context(choice: 0, index: 0)
            try vault.storyMuSig2Sign(&psbt, input: input, context: context,
                                      master: master(for: "mateo"), secretNonces: &nonces)
        }
        updated.musigSecretNonces.removeAll()
        updated.musigPartialPSBT = psbt.base64
        updated.updatedAt = Date()
        return (psbt.base64, updated)
    }
}
