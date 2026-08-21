import BitcoinCore
import BitcoinP2P
import Foundation
import Security

#if DEBUG
/// Launch-environment hooks for the XCUITest end-to-end suite (UITests/).
/// Entirely inert unless the app is launched with WINNOW_E2E=1: a normal
/// launch never reads any of this and behaves exactly as before.
///
/// Test mode:
/// - redirects Application Support storage to a throwaway `BTCSwiftE2E-<run>`
///   directory and the Keychain to a dedicated service, so a real wallet's
///   state is never touched;
/// - can point protocol tests at a custom signet, while story runs omit those
///   overrides and use Winnow's ordinary public-signet peers;
/// - can fix the wallet entropy (or full mnemonic) so screenshots are
///   reproducible.
struct E2EMode {
    struct Event: Codable {
        let version: Int
        let timestamp: Date
        let name: String
        let persona: String?
        let fields: [String: String]
    }

    /// Namespace for storage ("main", "import", …) — each test scenario that
    /// needs a fresh wallet gets its own run id.
    let runID: String
    /// "host:port" of the local node, preconfigured as the manual peer.
    let peer: String?
    /// The custom signet's BIP325 challenge.
    let challenge: Data?
    /// Fixed wallet entropy for reproducible addresses/screenshots.
    let entropy: Data?
    /// Wipe this run's storage and the test Keychain namespace on launch.
    let reset: Bool
    /// Text the app puts on its own pasteboard at boot — drives the Paste
    /// buttons (send destination, import JSON) without cross-app paste
    /// consent prompts.
    let clipboard: String?
    /// Story role used only in journal labels (Sofía, Elena, replacement).
    let storyPersona: String?
    /// Reproducible story runs are locked to public signet. Ordinary UI tests
    /// and production launches leave this nil and retain the normal picker.
    let forcedNetwork: BitcoinNetwork?
    /// Optional initial shell tab for deterministic story-stage launches.
    /// This changes navigation only and is ignored outside E2E mode.
    let initialTab: String?
    /// Manual story runs exercise Local Authentication on the simulator.
    /// Ordinary XCUITests leave this false so they can run unattended.
    let requireDeviceAuthentication: Bool

    static let keychainServicePrefix = "org.btc-swift.wallet.e2e"

    /// What an environment says about E2E mode.
    ///
    /// `missingPinnedEntropy` exists because the alternative is silent and
    /// irreversible. A capture run screenshots the recovery-phrase screen and
    /// those images are committed to a public repository and published to the
    /// site. With no pinned entropy the app falls through to ordinary
    /// onboarding and generates a *real* seed, so a run that merely forgot the
    /// variable would publish live key material. Every launcher — both
    /// XCUITest call sites and the story runner — passes it today, so this can
    /// only be reached by a mistake, which is exactly when failing loudly is
    /// worth more than carrying on.
    enum Resolution {
        case inactive
        case active(E2EMode)
        case missingPinnedEntropy
    }

    /// Pure resolution, so the fail-closed rule is testable without a process
    /// environment.
    static func resolve(environment: [String: String]) -> Resolution {
        guard environment["WINNOW_E2E"] == "1" else { return .inactive }
        let entropy: Data?
        if let hex = environment["WINNOW_E2E_ENTROPY"] {
            entropy = Data(hex: hex)
        } else if let mnemonic = environment["WINNOW_E2E_MNEMONIC"] {
            entropy = try? entropyFrom(mnemonic: mnemonic)
        } else {
            entropy = nil
        }
        // Unparseable entropy or an invalid mnemonic land here too: a value
        // that was meant to be pinned but could not be read is a mistake of
        // the same kind, not a licence to generate one.
        guard let entropy else { return .missingPinnedEntropy }
        return .active(E2EMode(runID: environment["WINNOW_E2E_RUN"] ?? "main",
                       peer: environment["WINNOW_E2E_PEER"],
                       challenge: environment["WINNOW_E2E_CHALLENGE"].flatMap { Data(hex: $0) },
                       entropy: entropy,
                       reset: environment["WINNOW_E2E_RESET"] == "1",
                       clipboard: environment["WINNOW_E2E_CLIPBOARD"],
                       storyPersona: environment["WINNOW_STORY_PERSONA"],
                       forcedNetwork: environment["WINNOW_E2E_NETWORK"]
                           .flatMap(BitcoinNetwork.init(rawValue:)),
                       initialTab: environment["WINNOW_E2E_TAB"],
                       requireDeviceAuthentication: environment["WINNOW_E2E_DEVICE_AUTH"] == "1"))
    }

    static var current: E2EMode? {
        switch resolve(environment: ProcessInfo.processInfo.environment) {
        case .inactive:
            return nil
        case let .active(mode):
            return mode
        case .missingPinnedEntropy:
            preconditionFailure(
                "WINNOW_E2E=1 without a readable WINNOW_E2E_ENTROPY or WINNOW_E2E_MNEMONIC. "
                    + "A capture run must never generate a real seed: its screenshots are published.")
        }
    }

    /// The Application Support subdirectory used instead of "BTCSwift".
    var storageDirectoryName: String { "BTCSwiftE2E-\(runID)" }
    var keychainService: String { "\(Self.keychainServicePrefix).\(safeRunID)" }
    var defaultsSuiteName: String { "org.btc-swift.defaults.e2e.\(safeRunID)" }
    var defaults: UserDefaults { UserDefaults(suiteName: defaultsSuiteName) ?? .standard }

    private var safeRunID: String {
        runID.map { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" ? $0 : "_" }
            .reduce(into: "") { $0.append($1) }
    }

    /// The sync stack's network parameters: the custom signet when a
    /// challenge was injected, else the stock network params.
    var networkParams: NetworkParams? {
        challenge.map { .customSignet(challenge: $0, defaultPort: 38_401) }
    }

    /// `WINNOW_E2E_RESET=1`: drop this run's storage directory and every
    /// Keychain entry in the test namespace.
    func wipeIfRequested() {
        guard reset else { return }
        SecItemDelete([kSecClass: kSecClassGenericPassword,
                       kSecAttrService: keychainService] as CFDictionary)
        defaults.removePersistentDomain(forName: defaultsSuiteName)
        if let base = try? FileManager.default.url(for: .applicationSupportDirectory,
                                                   in: .userDomainMask,
                                                   appropriateFor: nil, create: true) {
            try? FileManager.default.removeItem(at: base.appending(path: storageDirectoryName,
                                                                   directoryHint: .isDirectory))
        }
    }

    /// Versioned, E2E-only event journal. It contains automation facts and
    /// public transaction material, never mnemonics, private keys, entropy,
    /// or MuSig2 secret nonces. Normal launches never construct E2EMode and
    /// therefore never create this file.
    func journal(_ name: String, fields: [String: String] = [:]) {
        let forbiddenFieldNames = ["entropy", "mnemonic", "privatekey", "secretnonce", "seedhex"]
        guard !fields.keys.contains(where: { key in
            let normalized = key.lowercased().filter(\.isLetter)
            return forbiddenFieldNames.contains(where: normalized.contains)
        }) else {
            // Fail closed: an unsafe schema mistake produces no event at all.
            return
        }
        let containsMnemonic = fields.values.contains { value in
            let wordCount = value.split(whereSeparator: \.isWhitespace).count
            guard [12, 15, 18, 21, 24].contains(wordCount) else { return false }
            return (try? BIP39.validate(mnemonic: value)) != nil
        }
        guard !containsMnemonic else { return }
        guard let base = try? FileManager.default.url(for: .applicationSupportDirectory,
                                                       in: .userDomainMask,
                                                       appropriateFor: nil, create: true) else { return }
        let directory = base.appending(path: storageDirectoryName, directoryHint: .isDirectory)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appending(path: "story-events.jsonl")
        let event = Event(version: 1, timestamp: Date(), name: name,
                          persona: storyPersona, fields: fields)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard var data = try? encoder.encode(event) else { return }
        data.append(0x0A)
        if FileManager.default.fileExists(atPath: url.path),
           let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            try? handle.seekToEnd()
            try? handle.write(contentsOf: data)
        } else {
            try? data.write(to: url, options: .atomic)
        }
        try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                               ofItemAtPath: url.path)
    }

    /// Mnemonic sentence → entropy (BIP39 decode; the injected mnemonic is
    /// reproduced exactly by the wallet creation screen).
    private static func entropyFrom(mnemonic: String) throws -> Data {
        let words = mnemonic.split(separator: " ").map(String.init)
        var bits: [UInt8] = []
        for word in words {
            guard let index = BIP39.wordlist.firstIndex(of: word) else {
                throw BIP39Error.wordNotInWordlist(word)
            }
            bits += (0 ..< 11).reversed().map { UInt8((index >> $0) & 1) }
        }
        let checksumLength = words.count / 3
        let entropyLength = (bits.count - checksumLength) / 8
        var entropy = Data(repeating: 0, count: entropyLength)
        for i in 0 ..< entropyLength * 8 where bits[i] == 1 {
            entropy[i / 8] |= 1 << UInt8(7 - (i % 8))
        }
        return entropy
    }
}
#else
/// A deliberately uninhabitable release-build stand-in.
///
/// The complete E2E implementation, including its environment-variable
/// parser, deterministic entropy injection, storage reset, custom peer, and
/// event journal, is removed by conditional compilation. Keeping only this
/// type-shaped stand-in lets shared application code use optional chaining
/// without placing a test activation path in a distributed binary.
struct E2EMode {
    static let current: E2EMode? = nil

    private init() {}

    var peer: String? { unavailable() }
    var entropy: Data? { unavailable() }
    var clipboard: String? { unavailable() }
    var forcedNetwork: BitcoinNetwork? { unavailable() }
    var initialTab: String? { unavailable() }
    var requireDeviceAuthentication: Bool { unavailable() }
    var keychainService: String { unavailable() }
    var defaults: UserDefaults { unavailable() }
    var networkParams: NetworkParams? { unavailable() }
    var storageDirectoryName: String { unavailable() }

    func wipeIfRequested() { unavailable() }
    func journal(_: String, fields _: [String: String] = [:]) { unavailable() }

    private func unavailable() -> Never {
        fatalError("Test mode is not present in release builds")
    }
}
#endif
