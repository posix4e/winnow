import Foundation
import WalletCore

/// Deterministic key fixtures (signet format, fully offline): HD masters
/// from fixed entropy and the account key expressions people share.
public enum TestKeys {
    /// Three fixed entropy bytes, one repeated 16-byte seed each.
    public static let entropyBytes: [UInt8] = [0xA1, 0xB2, 0xC3]

    /// An HD master from a repeated one-byte 16-byte entropy, via BIP39.
    public static func master(entropyByte: UInt8) throws -> HDKey {
        try HDKey(seed: BIP39.seed(mnemonic: BIP39.mnemonic(entropy: Data(repeating: entropyByte, count: 16))))
    }

    /// Three HD masters (fixed entropy — deterministic fixtures).
    public static func masters() throws -> [HDKey] {
        try entropyBytes.map { try Self.master(entropyByte: $0) }
    }

    /// `[fp/86'/1'/0']tpub…/<0;1>/*` — the account key expression a person
    /// shares to be paid.
    public static func keyExpression(master: HDKey) throws -> String {
        try bareKeyExpression(master: master) + "/<0;1>/*"
    }

    /// Bare `[fp/86'/1'/0']tpub…` without a derivation suffix.
    public static func bareKeyExpression(master: HDKey) throws -> String {
        let account = try master.derived(path: "m/86'/1'/0'")
        let fingerprint = String(format: "%08x", master.fingerprint)
        return "[\(fingerprint)/86'/1'/0']\(account.neutered.serialized(network: .testnet))"
    }

    /// `masters` in the order `account` lists their keys. The account
    /// builder sorts signers by key, so a test that names signer `i` by the
    /// position `approvals` reports uses this order.
    public static func inSignerOrder(_ masters: [HDKey], of account: MultisigAccount) throws -> [HDKey] {
        let listed = account.signers.compactMap { signer -> Data? in
            guard case let .extended(xpub, _) = signer.base else { return nil }
            return xpub.publicKey
        }
        return try masters.map { master in
            (master, listed.firstIndex(of: try master.derived(path: "m/86'/1'/0'").publicKey) ?? Int.max)
        }.sorted { $0.1 < $1.1 }.map(\.0)
    }
}
