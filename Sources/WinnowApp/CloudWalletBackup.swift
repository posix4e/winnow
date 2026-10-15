import CryptoKit
import Foundation
import WalletCore

/// An encrypted cloud recovery copy, separate from the device-only signing Keychain.
/// The random wrapping key travels through iCloud Keychain; the cloud file
/// contains only authenticated ciphertext. Automatic updates reuse the sealed
/// phrase without reading the local signing key again.
struct CloudWalletBackup: Codable, Sendable {
    static let maximumBytes = 32 * 1024 * 1024
    static let maximumAppStateBytes = 10 * 1024 * 1024
    let version: Int
    let id: UUID
    let network: String
    let savedAt: Date
    let sealedPhrase: Data
    let sealedWallet: Data

    private struct State: Codable {
        var bundle: ImportBundle
        var appState: Data?
    }

    static func create(bundle: ImportBundle, appState: Data? = nil, id: UUID = UUID(), key: SymmetricKey,
                       savedAt: Date = Date()) throws -> Self {
        guard let words = bundle.mnemonic else { throw WalletError.mnemonicUnavailable }
        try BIP39.validate(mnemonic: words)
        _ = try Wallet.importing(bundle, keyStore: ValidationKeys())
        let phrase = try AES.GCM.seal(Data(words.utf8), using: key,
                                     authenticating: context(id, bundle.network, "phrase")).combined!
        return try make(bundle: bundle, appState: appState, id: id, key: key, savedAt: savedAt, phrase: phrase)
    }

    func updating(bundle: ImportBundle, appState: Data? = nil,
                  key: SymmetricKey, savedAt: Date = Date()) throws -> Self {
        let previous = try state(key: key)
        guard bundle.network == network, bundle.descriptor == previous.bundle.descriptor else {
            throw WalletError.descriptorMismatch
        }
        return try Self.make(bundle: bundle, appState: appState ?? previous.appState,
                             id: id, key: key, savedAt: savedAt, phrase: sealedPhrase)
    }

    func restoredBundle(key: SymmetricKey) throws -> ImportBundle {
        var bundle = try state(key: key).bundle
        let words = try AES.GCM.open(AES.GCM.SealedBox(combined: sealedPhrase), using: key,
                                     authenticating: Self.context(id, network, "phrase"))
        guard let mnemonic = String(data: words, encoding: .utf8) else {
            throw WalletError.invalidBundle("invalid cloud recovery words")
        }
        try BIP39.validate(mnemonic: mnemonic)
        bundle.mnemonic = mnemonic
        // Validate descriptor, coins, history and key agreement before the
        // caller touches the real Keychain or wallet files.
        _ = try Wallet.importing(bundle, keyStore: ValidationKeys())
        return bundle
    }

    /// App-owned data is inside the authenticated wallet ciphertext, so it
    /// cannot be stripped from an otherwise valid backup. Older copies lack it.
    func restoredAppState(key: SymmetricKey) throws -> Data? {
        try state(key: key).appState
    }

    func encoded() throws -> Data {
        let data = try JSONEncoder().encode(self)
        guard data.count <= Self.maximumBytes else {
            throw WalletError.invalidBundle("cloud backup is too large")
        }
        return data
    }

    static func decode(_ data: Data) throws -> Self {
        guard data.count <= maximumBytes else { throw WalletError.invalidBundle("cloud backup is too large") }
        let result = try JSONDecoder().decode(Self.self, from: data)
        guard (1...2).contains(result.version), BitcoinNetwork(rawValue: result.network) != nil,
              result.sealedPhrase.count <= 1024 else {
            throw WalletError.invalidBundle("unsupported cloud backup")
        }
        return result
    }

    private func state(key: SymmetricKey) throws -> State {
        guard (1...2).contains(version) else { throw WalletError.invalidBundle("unsupported cloud backup") }
        let data = try AES.GCM.open(AES.GCM.SealedBox(combined: sealedWallet), using: key,
                                   authenticating: Self.context(id, network, "wallet-\(savedAt.timeIntervalSince1970)"))
        let state: State
        if version == 1 { state = State(bundle: try ImportBundle.decode(data), appState: nil) }
        else {
            state = try JSONDecoder().decode(State.self, from: data)
            _ = try ImportBundle.decode(json: state.bundle.serialized())
        }
        guard state.bundle.network == network, state.bundle.mnemonic == nil,
              (state.appState?.count ?? 0) <= Self.maximumAppStateBytes else {
            throw WalletError.invalidBundle("cloud backup identity does not match")
        }
        return state
    }

    private static func make(bundle: ImportBundle, appState: Data?, id: UUID, key: SymmetricKey,
                             savedAt: Date, phrase: Data) throws -> Self {
        var publicBundle = bundle
        publicBundle.mnemonic = nil
        let data = Data(try publicBundle.serialized().utf8)
        _ = try ImportBundle.decode(data)
        guard (appState?.count ?? 0) <= maximumAppStateBytes else {
            throw WalletError.invalidBundle("cloud app data is too large")
        }
        let state = try JSONEncoder().encode(State(bundle: publicBundle, appState: appState))
        let sealed = try AES.GCM.seal(state, using: key,
                                     authenticating: context(id, bundle.network, "wallet-\(savedAt.timeIntervalSince1970)"))
        return Self(version: 2, id: id, network: bundle.network, savedAt: savedAt,
                    sealedPhrase: phrase, sealedWallet: sealed.combined!)
    }

    private static func context(_ id: UUID, _ network: String, _ purpose: String) -> Data {
        Data("Winnow cloud backup v1|\(id.uuidString)|\(network)|\(purpose)".utf8)
    }

    /// Runs the normal importer as a validation pass without persisting keys.
    private struct ValidationKeys: KeyStore {
        func store(_ secret: WalletSecret, for walletID: String) throws {}
        func load(walletID: String) throws -> WalletSecret { throw KeyStoreError.notFound(walletID: walletID) }
        func delete(walletID: String) throws {}
    }
}
