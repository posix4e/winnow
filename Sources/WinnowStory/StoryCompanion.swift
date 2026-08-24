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
