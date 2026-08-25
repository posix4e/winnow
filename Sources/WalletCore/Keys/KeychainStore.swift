import Foundation
import Security

/// Security.framework Keychain-backed KeyStore: `kSecClassGenericPassword`,
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (this device only — never
/// migrated via backup), `kSecAttrSynchronizable = false` (no iCloud sync).
///
/// SPM test runners have no keychain entitlements, so the package suite cannot
/// reach this. `AppTests/KeychainAttributeTests` can: it is hosted in the app,
/// stores a secret through this type and reads the attributes back out of the
/// Keychain, so the protection class is observed rather than reviewed. What
/// that still cannot show is that iOS *honours* it when the device locks —
/// the simulator has no data protection and no Secure Enclave.
public struct KeychainStore: KeyStore {
    /// kSecAttrService namespace for all entries; the wallet ID is the account.
    public let service: String

    public init(service: String = "org.btc-swift.wallet") {
        self.service = service
    }

    public func store(_ secret: WalletSecret, for walletID: String) throws {
        var query = baseQuery(walletID: walletID)
        query[kSecValueData] = secret.serialized
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem { throw KeyStoreError.alreadyExists(walletID: walletID) }
        guard status == errSecSuccess else { throw KeyStoreError.keychain(status) }
    }

    public func load(walletID: String) throws -> WalletSecret {
        var query = baseQuery(walletID: walletID)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { throw KeyStoreError.notFound(walletID: walletID) }
        guard status == errSecSuccess, let data = item as? Data else {
            throw KeyStoreError.keychain(status)
        }
        return try WalletSecret(serialized: data)
    }

    public func delete(walletID: String) throws {
        let status = SecItemDelete(baseQuery(walletID: walletID) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyStoreError.keychain(status)
        }
    }

    private func baseQuery(walletID: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: walletID,
            kSecAttrSynchronizable: kCFBooleanFalse as Any,
        ]
    }
}
