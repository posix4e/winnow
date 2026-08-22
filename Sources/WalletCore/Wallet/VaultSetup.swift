import BitcoinCore
import BitcoinP2P
import Foundation

/// The key-expression shape required by each vault policy.
public enum VaultCosignerRole: Sendable, Hashable {
    /// A BIP389 receive/change key such as `[fingerprint/path]tpub…/<0;1>/*`.
    case scriptPath
    /// A bare BIP390 participant such as `[fingerprint/path]tpub…`.
    case muSig2

    /// The one derivation suffix a signer of this role may carry.
    ///
    /// Pinning the suffix is what makes signer independence *provable* rather
    /// than sampled. Two expressions over distinct account keys that share an
    /// identical suffix template cannot resolve to the same public key at any
    /// `(index, choice)`; allow the suffixes to differ and they can agree at
    /// some later coordinate while looking distinct at the one a check
    /// happened to sample.
    ///
    /// `Vault.init` and `VaultCosignerKey` both enforce this, so it lives here
    /// rather than in either of them — if the two ever disagreed, the boundary
    /// would accept a shape the builder refuses.
    public var requiredDerivation: [Descriptor.Derivation.Element] {
        switch self {
        case .scriptPath: [.multipath([0, 1]), .wildcard(hardened: false)]
        case .muSig2: []
        }
    }
}

/// Plain-language validation failures for signer keys entered during vault setup.
public enum VaultCosignerKeyError: Error, Equatable, LocalizedError {
    case malformed
    case privateKey
    case extendedPublicKeyRequired
    case missingOrigin
    case originPathMismatch
    case wrongNetwork(expectedPrefix: String)
    case scriptPathDerivationRequired
    case muSig2DerivationForbidden
    case duplicateKey

    public var errorDescription: String? {
        switch self {
        case .malformed:
            return "That signer key isn't valid. Paste the public account key exported by the other signer."
        case .privateKey:
            return "That is a private key. For safety, paste only the public account key—never a seed phrase or private key."
        case .extendedPublicKeyRequired:
            return "A vault signer must be an extended public account key, not a single Bitcoin address or public key."
        case .missingOrigin:
            return "This signer key is missing its fingerprint and account path. Export the complete key expression from Winnow or a compatible wallet."
        case .originPathMismatch:
            return "This signer's account path does not match the public key. Export the complete signer key again instead of editing its path by hand."
        case let .wrongNetwork(expectedPrefix):
            return "That signer key is for a different Bitcoin network. This wallet needs a key beginning with \(expectedPrefix)."
        case .scriptPathDerivationRequired:
            return "For a k-of-n vault, the signer key must end in /<0;1>/* so Winnow can derive receive and change addresses."
        case .muSig2DerivationForbidden:
            return "For a MuSig2 vault, paste the bare signer account key without /<0;1>/*. Winnow adds the shared derivation after combining the keys."
        case .duplicateKey:
            return "That public signer key is already in this vault. Each signer must use a different key."
        }
    }
}

/// A validated, public-only signer key expression safe to keep in a vault draft.
public struct VaultCosignerKey: Sendable, Equatable {
    /// Ignores origin labels while retaining the actual public account key and
    /// derivation. Two expressions with the same identity cannot contribute
    /// two independent signatures.
    public struct Identity: Sendable, Equatable {
        fileprivate let key: HDKey
        fileprivate let derivation: Descriptor.Derivation
    }

    public let expression: String
    public let identity: Identity

    private init(expression: String, identity: Identity) {
        self.expression = expression
        self.identity = identity
    }

    public init(_ expression: String, role: VaultCosignerRole, network: BitcoinNetwork) throws {
        self = try Self.validate(expression, role: role,
                                 expectedNetwork: network == .mainnet ? .mainnet : .testnet)
    }

    /// Used by descriptor construction when the caller has not supplied its chain yet.
    static func validateWithoutNetwork(_ expression: String, role: VaultCosignerRole) throws -> Self {
        try validate(expression, role: role, expectedNetwork: nil)
    }

    private static func validate(_ expression: String, role: VaultCosignerRole,
                                 expectedNetwork: HDKey.Network?) throws -> Self {
        let trimmed = expression.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw VaultCosignerKeyError.malformed }

        let descriptor: Descriptor
        do {
            descriptor = try Descriptor("rawtr(\(trimmed))")
        } catch {
            throw VaultCosignerKeyError.malformed
        }

        guard case let .rawtr(.single(key)) = descriptor.expression else {
            throw VaultCosignerKeyError.malformed
        }

        switch key.base {
        case .privateKey:
            throw VaultCosignerKeyError.privateKey
        case let .extended(parsedKey, network):
            guard !parsedKey.isPrivate else { throw VaultCosignerKeyError.privateKey }
            return try finishValidation(trimmed: trimmed, key: key, hdKey: parsedKey,
                                        keyNetwork: network, role: role,
                                        expectedNetwork: expectedNetwork, descriptor: descriptor)
        case .publicKey:
            throw VaultCosignerKeyError.extendedPublicKeyRequired
        }
    }

    private static func finishValidation(trimmed: String, key: Descriptor.SingleKey,
                                         hdKey: HDKey, keyNetwork: HDKey.Network,
                                         role: VaultCosignerRole, expectedNetwork: HDKey.Network?,
                                         descriptor: Descriptor) throws -> Self {
        guard key.origin != nil else { throw VaultCosignerKeyError.missingOrigin }
        if let origin = key.origin {
            guard origin.path.count == Int(hdKey.depth),
                  hdKey.depth == 0 || origin.path.last == hdKey.childIndex
            else { throw VaultCosignerKeyError.originPathMismatch }
        }

        if let expectedNetwork, keyNetwork != expectedNetwork {
            throw VaultCosignerKeyError.wrongNetwork(
                expectedPrefix: expectedNetwork == .mainnet ? "xpub" : "tpub"
            )
        }

        guard key.derivation.elements == role.requiredDerivation else {
            switch role {
            case .scriptPath: throw VaultCosignerKeyError.scriptPathDerivationRequired
            case .muSig2: throw VaultCosignerKeyError.muSig2DerivationForbidden
            }
        }

        do {
            _ = try descriptor.derived(index: 0, network: keyNetwork)
        } catch {
            throw VaultCosignerKeyError.malformed
        }
        return Self(expression: trimmed, identity: Identity(key: hdKey.neutered,
                                                            derivation: key.derivation))
    }
}

/// The complete, testable state machine used by the vault-creation screen.
public struct VaultDraft: Sendable, Equatable {
    public private(set) var role: VaultCosignerRole
    public private(set) var threshold = 1
    public private(set) var cosigners: [VaultCosignerKey] = []

    public init(role: VaultCosignerRole = .scriptPath) {
        self.role = role
    }

    public var canBuild: Bool { cosigners.count >= 2 }

    /// The policy cannot be changed underneath signer expressions because
    /// script-path and MuSig2 participants use different derivation shapes.
    @discardableResult
    public mutating func setRole(_ newRole: VaultCosignerRole) -> Bool {
        guard cosigners.isEmpty else { return false }
        role = newRole
        threshold = 1
        return true
    }

    public mutating func add(_ expression: String, network: BitcoinNetwork) throws {
        let candidate = try VaultCosignerKey(expression, role: role, network: network)
        guard !cosigners.contains(where: { $0.identity == candidate.identity }) else {
            throw VaultCosignerKeyError.duplicateKey
        }
        let previousCount = cosigners.count
        cosigners.append(candidate)
        threshold = VaultThreshold.reconciled(threshold, previousKeyCount: previousCount,
                                              keyCount: cosigners.count)
    }

    public mutating func remove(at offsets: IndexSet) {
        let previousCount = cosigners.count
        for index in offsets.sorted(by: >) where cosigners.indices.contains(index) {
            cosigners.remove(at: index)
        }
        threshold = VaultThreshold.reconciled(threshold, previousKeyCount: previousCount,
                                              keyCount: cosigners.count)
    }

    public mutating func setThreshold(_ value: Int) {
        threshold = VaultThreshold.clamped(value, keyCount: cosigners.count)
    }
}

/// Deterministic threshold transitions shared by the UI and unit tests.
public enum VaultThreshold {
    /// Returns a valid threshold for `keyCount`, using one as the harmless draft
    /// value while fewer than two keys are present.
    public static func clamped(_ threshold: Int, keyCount: Int) -> Int {
        min(max(threshold, 1), max(keyCount, 1))
    }

    /// Adding the second signer creates the safest useful default: 2-of-2.
    /// All later additions and deletions preserve the user's choice when valid.
    public static func reconciled(_ threshold: Int, previousKeyCount: Int, keyCount: Int) -> Int {
        if previousKeyCount < 2, keyCount >= 2 { return 2 }
        return clamped(threshold, keyCount: keyCount)
    }
}
