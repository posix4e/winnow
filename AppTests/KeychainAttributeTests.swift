@testable import WinnowApp
import Security
import WalletCore
import XCTest

/// What the Keychain actually recorded, read back (invariant S1).
///
/// `KeychainStore` says of itself: "Not covered by unit tests: SPM test
/// runners have no keychain entitlements. The app exercises this; the
/// implementation is deliberately straightforward and reviewed by reading."
/// The invariant matrix inherited that as "by construction" — the weakest
/// evidence class in the register, because it means a person read the source
/// and agreed with it.
///
/// This suite is hosted in the app, so it has the entitlements the package
/// tests lack and can ask the Keychain what it stored rather than asking the
/// source what it intended. A protection attribute that is set but never read
/// back is indistinguishable from one that is silently ignored.
///
/// **What this cannot show.** That iOS *honours* the attribute. The simulator's
/// Keychain is file-backed with no data protection and no Secure Enclave, so
/// locking the device is not modelled here at all. The claim earned is "we ask
/// for the right protection and the Keychain records it", not "the platform
/// enforces it" — the latter is Apple's contract and needs real hardware.
final class KeychainAttributeTests: XCTestCase {
    private let service = "org.btc-swift.tests.keychain-attributes"
    private var walletID = ""

    override func setUp() {
        super.setUp()
        walletID = "attributes-\(UUID().uuidString)"
    }

    override func tearDown() {
        try? KeychainStore(service: service).delete(walletID: walletID)
        super.tearDown()
    }

    /// The attributes the Keychain reports for a secret we just stored.
    private func storedAttributes() throws -> [CFString: Any] {
        let store = KeychainStore(service: service)
        try store.store(.mnemonic("abandon abandon abandon"), for: walletID)
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: walletID,
            kSecReturnAttributes: true,
            kSecMatchLimit: kSecMatchLimitOne,
            // Match whatever was stored, synchronizable or not. Without this
            // the query defaults to non-synchronizable only, and a secret
            // wrongly marked for iCloud would simply not be found — the test
            // would fail, but with "not found" rather than by observing the
            // attribute, which proves the item changed and not which way.
            kSecAttrSynchronizable: kSecAttrSynchronizableAny,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        XCTAssertEqual(status, errSecSuccess, "the secret we just stored was not found")
        return try XCTUnwrap(item as? [CFString: Any], "keychain returned no attributes")
    }

    func testStoredSecretIsAccessibleOnlyWhenUnlockedOnThisDevice() throws {
        let attributes = try storedAttributes()
        let accessible = try XCTUnwrap(attributes[kSecAttrAccessible] as? String,
                                       "no accessibility attribute was recorded at all")
        XCTAssertEqual(accessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String,
                       "stored with \(accessible): a weaker class survives a backup or an "
                       + "unattended device, which is the whole point of the stricter one")
    }

    func testStoredSecretIsNotSynchronizedToICloud() throws {
        let attributes = try storedAttributes()
        // Absent counts as false — Keychain omits the attribute when it is not
        // set — so the assertion is "never true" rather than "equals false".
        let synchronizable = attributes[kSecAttrSynchronizable] as? Bool ?? false
        XCTAssertFalse(synchronizable,
                       "the secret is marked synchronizable and would leave the device")
    }

    /// The control. Without it the two assertions above could both be passing
    /// against a query that silently matched nothing.
    func testTheSecretIsActuallyReadableBack() throws {
        let store = KeychainStore(service: service)
        try store.store(.mnemonic("abandon abandon about"), for: walletID)
        let loaded = try store.load(walletID: walletID)
        guard case let .mnemonic(text) = loaded else {
            return XCTFail("stored a mnemonic and loaded something else")
        }
        XCTAssertEqual(text, "abandon abandon about")
    }
}
