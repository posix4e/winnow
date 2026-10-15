import Foundation
import VaultKit
import WalletCore

/// Deterministic vault fixtures (signet format, fully offline): cosigner
/// masters from fixed entropy, their key expressions, and the two vault shapes
/// the wallet supports.
public enum TestVaults {
    /// The three cosigners' entropy bytes, one repeated 16-byte seed each.
    public static let cosignerEntropy: [UInt8] = [0xA1, 0xB2, 0xC3]

    /// An HD master from a repeated one-byte 16-byte entropy, via BIP39.
    public static func master(entropyByte: UInt8) throws -> HDKey {
        try HDKey(seed: BIP39.seed(mnemonic: BIP39.mnemonic(entropy: Data(repeating: entropyByte, count: 16))))
    }

    /// Three cosigner HD masters (fixed entropy — deterministic fixtures).
    public static func masters() throws -> [HDKey] {
        try cosignerEntropy.map { try Self.master(entropyByte: $0) }
    }

    /// `[fp/86'/1'/0']tpub…/<0;1>/*` cosigner key expression text.
    public static func keyExpression(master: HDKey) throws -> String {
        try bareKeyExpression(master: master) + "/<0;1>/*"
    }

    /// Bare `[fp/86'/1'/0']tpub…` — musig() participants carry no own
    /// derivation when the musig has a suffix (BIP390).
    public static func bareKeyExpression(master: HDKey) throws -> String {
        let account = try master.derived(path: "m/86'/1'/0'")
        let fingerprint = String(format: "%08x", master.fingerprint)
        return "[\(fingerprint)/86'/1'/0']\(account.neutered.serialized(network: .testnet))"
    }

    /// A k-of-3 `sortedmulti_a` script-path vault over `masters()`.
    public static func multiAVault(threshold k: Int = 2) throws -> (vault: Vault, masters: [HDKey]) {
        let masters = try Self.masters()
        let descriptor = try Vault.multiADescriptor(
            threshold: k, cosigners: try masters.map { try Self.keyExpression(master: $0) })
        return (try Vault(descriptor: descriptor, network: .signet), masters)
    }

    /// The 2-of-2 MuSig2 key-path vault over the first two of `masters()`.
    public static func muSig2Vault() throws -> (vault: Vault, masters: [HDKey]) {
        let masters = try Self.masters().prefix(2).map { $0 }
        let keys = try masters.map { try Self.bareKeyExpression(master: $0) }
        return (try Vault("tr(musig(\(keys[0]),\(keys[1]))/<0;1>/*)", network: .signet), masters)
    }

    /// A fabricated funding UTXO paying the vault at (choice, index).
    public static func funding(vault: Vault, amount: Int64, choice: AddressChain = .receive,
                               index: UInt32 = 0, height: UInt32 = 100) throws -> WalletUTXO {
        try WalletUTXO(txid: Data(repeating: 0x5A, count: 32), vout: 0, amount: amount,
                       scriptPubKey: vault.scriptPubKey(index: index, choice: choice.rawValue),
                       chain: choice, index: index, height: height)
    }
}
