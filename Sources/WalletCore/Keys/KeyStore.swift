import Foundation
import Security

public enum KeyStoreError: LocalizedError, Equatable {
    case notFound(walletID: String)
    case alreadyExists(walletID: String)
    case malformedSecret
    /// A recognizable account-secret format that this version cannot read.
    case unsupportedSecretVersion(String)
    case keychain(OSStatus)

    public var errorDescription: String? {
        switch self {
        case let .notFound(walletID):
            "The protected key for wallet \(walletID) is missing from this device."
        case let .alreadyExists(walletID):
            "This device already contains a protected key for wallet \(walletID)."
        case .malformedSecret:
            "The protected wallet key is damaged or has an unsupported format."
        case .unsupportedSecretVersion:
            "This wallet key uses an unsupported format version. Keep the key and open it with compatible wallet software."
        case .keychain(errSecUserCanceled):
            "Unlocking the wallet key was cancelled."
        case .keychain(errSecAuthFailed):
            "The device did not confirm it was you, so the wallet key stays locked."
        case .keychain(errSecInteractionNotAllowed):
            "The wallet key can only be unlocked while Winnow is on screen and the device is unlocked."
        case let .keychain(status):
            "The device could not reach the protected wallet key (\(SecCopyErrorMessageString(status, nil) as String? ?? "keychain status \(status)"))."
        }
    }
}

/// The signing secret of a wallet, as held by a `KeyStore`.
public enum WalletSecret: Equatable, Sendable {
    /// BIP39 mnemonic sentence (single spaces, checksummed).
    case mnemonic(String)
    /// BIP32 master extended private key, Base58Check (xprv/tprv).
    case masterKey(String)
    /// An account extended private key at the descriptor's origin, with the
    /// master fingerprint supplied separately by the caller. A BIP32 child key
    /// records its parent's fingerprint, which is not the master fingerprint.
    case accountKey(xprv: String, masterFingerprint: UInt32)

    private static let accountPrefix = "account/"
    private static let accountHeader = "account/1"

    /// Tagged text: the legacy `mnemonic` / `xprv` header and payload, or
    /// `account/1`, an eight-digit lowercase master fingerprint, and an xprv.
    /// Versionable and inspectable; the bytes are what lands in the keychain.
    public var serialized: Data {
        switch self {
        case let .mnemonic(words): Data("mnemonic\n\(words)".utf8)
        case let .masterKey(xprv): Data("xprv\n\(xprv)".utf8)
        case let .accountKey(xprv, fingerprint):
            Data("\(Self.accountHeader)\n\(String(format: "%08x", fingerprint))\n\(xprv)".utf8)
        }
    }

    public init(serialized: Data) throws {
        let text = String(decoding: serialized, as: UTF8.self)
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard let first = lines.first else { throw KeyStoreError.malformedSecret }
        switch first {
        case "mnemonic" where lines.count == 2: self = .mnemonic(String(lines[1]))
        case "xprv" where lines.count == 2: self = .masterKey(String(lines[1]))
        case Substring(Self.accountHeader):
            self = try Self.decodeAccount(lines)
        case let header where header.hasPrefix(Self.accountPrefix):
            // Only a bounded numeric version label can leave this parser.
            // A malformed header may contain the payload; never echo it.
            let version = header.dropFirst(Self.accountPrefix.count)
                .prefix { $0 >= "0" && $0 <= "9" }.prefix(8)
            // `account/1` is this build's own format, so a header that starts
            // like it and is not exactly it is damage, not a newer version to
            // send someone to other software for. A header naming another
            // version is reported by its bounded label alone.
            guard !version.isEmpty, Self.accountPrefix + version != Self.accountHeader else {
                throw KeyStoreError.malformedSecret
            }
            throw KeyStoreError.unsupportedSecretVersion(Self.accountPrefix + version)
        default: throw KeyStoreError.malformedSecret
        }
    }

    private static func decodeAccount(_ lines: [Substring]) throws -> WalletSecret {
        guard lines.count == 3, lines[1].utf8.count == 8,
              lines[1].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              let fingerprint = UInt32(lines[1], radix: 16)
        else { throw KeyStoreError.malformedSecret }
        return .accountKey(xprv: String(lines[2]), masterFingerprint: fingerprint)
    }
}

/// Secret storage for wallets, keyed by wallet ID. Implementations must keep
/// secrets on the device and out of any cloud sync/backup (docs/mobile.md §5:
/// the keys are the wallet).
public protocol KeyStore: Sendable {
    /// Stores `secret` under `walletID`; throws `alreadyExists` if occupied.
    func store(_ secret: WalletSecret, for walletID: String) throws
    /// Loads the secret for `walletID`; throws `notFound` if absent.
    func load(walletID: String) throws -> WalletSecret
    /// Deletes the secret for `walletID`; deleting an absent ID is a no-op.
    func delete(walletID: String) throws
    /// Brings a secret stored by an earlier version up to the store's
    /// current protection, without reading it. Returns whether anything
    /// changed. Stores with one notion of protection have nothing to do.
    @discardableResult
    func upgradeProtection(walletID: String) throws -> Bool
}

public extension KeyStore {
    @discardableResult
    func upgradeProtection(walletID: String) throws -> Bool { false }
}
