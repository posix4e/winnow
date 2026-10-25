import CryptoKit
import Foundation
import Security
import WalletCore

/// Where a store file's authentication key lives: somewhere a writer to the
/// app container cannot reach. The Keychain in the app; memory in the tests.
///
/// One key per file (store name and network), and the key's existence is the
/// record that the file has been sealed once. From then on the file is refused
/// unless it verifies, so a file dropped into the container — a substituted
/// pay-to key that validates perfectly, the case IR-010 describes — reads as
/// damage rather than as data.
protocol StoreKeyVault: Sendable {
    /// The key established for `account`, or nil while none has been.
    func key(for account: String) throws -> SymmetricKey?
    /// Makes and keeps a fresh key for `account`; refuses to replace one.
    func establishKey(for account: String) throws -> SymmetricKey
    /// Forgets the key for `account`. Only to undo an `establishKey` whose
    /// first sealed write failed, so the next launch adopts the unsealed file
    /// still on disk instead of refusing it.
    func discardKey(for account: String) throws
}

enum StoreKeyVaultError: Error, Equatable, LocalizedError {
    case alreadyEstablished(String)
    case malformedKey
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case let .alreadyEstablished(account):
            "This device already holds a protected key for the \(account) file."
        case .malformedKey:
            "The protected key for a store file is damaged."
        case let .keychain(status):
            "The device could not keep a store file's protected key (\(SecCopyErrorMessageString(status, nil) as String? ?? "keychain status \(status)"))."
        }
    }
}

/// The Keychain-backed vault: generic-password items under the wallet's own
/// service, so the E2E namespace wipe covers them; this device only; never
/// synchronised; readable once the device has been unlocked since boot, which
/// is the same window as the files they seal.
struct KeychainStoreKeyVault: StoreKeyVault {
    static let accountPrefix = "store-key."
    static let keyBytes = 32

    let service: String

    func key(for account: String) throws -> SymmetricKey? {
        var query = baseQuery(account)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else { throw StoreKeyVaultError.keychain(status) }
        guard data.count == Self.keyBytes else { throw StoreKeyVaultError.malformedKey }
        return SymmetricKey(data: data)
    }

    func establishKey(for account: String) throws -> SymmetricKey {
        let key = SymmetricKey(size: .bits256)
        var query = baseQuery(account)
        query[kSecValueData] = key.withUnsafeBytes { Data($0) }
        query[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem { throw StoreKeyVaultError.alreadyEstablished(account) }
        guard status == errSecSuccess else { throw StoreKeyVaultError.keychain(status) }
        return key
    }

    func discardKey(for account: String) throws {
        let status = SecItemDelete(baseQuery(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw StoreKeyVaultError.keychain(status)
        }
    }

    private func baseQuery(_ account: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: Self.accountPrefix + account,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
        ]
    }
}

/// The sealed shape of a store file: a header line carrying the file's
/// authentication code, then the JSON payload exactly as the store encoded it.
///
///     winnow-store-mac-v1 <64 hex>⏎{"people":[…]}
///
/// The payload stays readable and byte-exact, so the code is over the bytes
/// the store wrote rather than over a re-encoding. The code also covers the
/// store's name and network, so a sealed file cannot be dropped in under
/// another store's name, nor a signet file presented as mainnet.
enum SealedStoreFile {
    static let header = "winnow-store-mac-v1"
    private static let prefix = Data("\(header) ".utf8)

    enum Failure: Error, Equatable {
        /// The file carries no seal, and this store has a key: the file was
        /// not written by this app on this device.
        case unsealed
        /// The file is sealed, and this store has no key to verify it with.
        case keyMissing
        case malformed
        case verificationFailed
    }

    static func seal(_ payload: Data, store: String, network: BitcoinNetwork, key: SymmetricKey) -> Data {
        let code = CryptoKit.HMAC<CryptoKit.SHA256>.authenticationCode(
            for: domain(store, network) + payload, using: key)
        return prefix + Data("\(Data(code).hex)\n".utf8) + payload
    }

    static func isSealed(_ data: Data) -> Bool {
        data.starts(with: prefix)
    }

    /// The payload of a sealed file, once its code verifies.
    static func open(_ data: Data, store: String, network: BitcoinNetwork, key: SymmetricKey) throws -> Data {
        guard isSealed(data) else { throw Failure.unsealed }
        guard let newline = data.firstIndex(of: UInt8(ascii: "\n")) else { throw Failure.malformed }
        let hex = String(decoding: data[data.startIndex ..< newline].dropFirst(prefix.count), as: UTF8.self)
        guard let code = Data(hex: hex), code.count == CryptoKit.SHA256.byteCount else { throw Failure.malformed }
        let payload = Data(data[data.index(after: newline)...])
        guard CryptoKit.HMAC<CryptoKit.SHA256>.isValidAuthenticationCode(
            code, authenticating: domain(store, network) + payload, using: key)
        else { throw Failure.verificationFailed }
        return payload
    }

    private static func domain(_ store: String, _ network: BitcoinNetwork) -> Data {
        Data("\(header)\u{0}\(store)\u{0}\(network.rawValue)\u{0}".utf8)
    }
}

/// One store file's seal, shared by the stores that keep JSON on disk: reads
/// verify, writes seal, and the key's lifetime follows the first sealed write.
struct StoreSeal: Sendable {
    let store: String
    let keys: any StoreKeyVault

    /// The keychain account of the file's key: one per store and network.
    func account(_ network: BitcoinNetwork) -> String {
        "\(store).\(network.rawValue)"
    }

    /// The payload of `data`: verified when the file has a key; taken as it
    /// is when none exists yet, which marks a file that predates sealing for
    /// the caller to seal once it validates. A sealed file whose key is gone
    /// has nothing left to vouch for it and is refused.
    func read(_ data: Data, network: BitcoinNetwork) throws -> (payload: Data, predatesSealing: Bool) {
        guard let key = try keys.key(for: account(network)) else {
            guard !SealedStoreFile.isSealed(data) else { throw SealedStoreFile.Failure.keyMissing }
            return (data, true)
        }
        return (try SealedStoreFile.open(data, store: store, network: network, key: key), false)
    }

    /// Writes `payload` sealed. The first write establishes the key; if that
    /// write fails the key is discarded again, so an unsealed file still on
    /// disk is adopted next time rather than refused.
    func write(_ payload: Data, network: BitcoinNetwork, to url: URL,
               using writeData: @Sendable (Data, URL) throws -> Void) throws {
        let account = account(network)
        let existing = try keys.key(for: account)
        let key = try existing ?? keys.establishKey(for: account)
        do {
            try writeData(SealedStoreFile.seal(payload, store: store, network: network, key: key), url)
        } catch {
            if existing == nil { try? keys.discardKey(for: account) }
            throw error
        }
    }
}
