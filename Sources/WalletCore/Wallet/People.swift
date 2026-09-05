import BitcoinCore
import BitcoinP2P
import Foundation

// MARK: - Pay-to

/// Where a person is paid: a ranged single-key Taproot descriptor, from which
/// every payment derives a fresh address, or one fixed address that every
/// payment reuses.
public enum PersonPayTo: Equatable, Sendable {
    /// Canonical serialized `tr(KEY/<0;1>/*)` or `tr(KEY/0/*)`, public key only.
    /// Payments always take the receive chain (choice 0).
    case descriptor(String)
    case address(String)
}

extension PersonPayTo: Codable {
    private enum CodingKeys: String, CodingKey { case kind, value }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(String.self, forKey: .kind)
        let value = try container.decode(String.self, forKey: .value)
        switch kind {
        case "descriptor": self = .descriptor(value)
        case "address": self = .address(value)
        default:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: container,
                                                   debugDescription: "unknown pay-to kind")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .descriptor(value):
            try container.encode("descriptor", forKey: .kind)
            try container.encode(value, forKey: .value)
        case let .address(value):
            try container.encode("address", forKey: .kind)
            try container.encode(value, forKey: .value)
        }
    }
}

/// Plain-language failures for a pay-to key.
public enum PersonPayToError: Error, Equatable, LocalizedError {
    case malformed
    case privateKey
    /// A key with no wildcard: it names one address, not a list.
    case singleAddressKey
    /// A tree, a musig() or a multi-key leaf: not one person's key.
    case notSingleKey
    case wrongNetwork(expected: BitcoinNetwork)
    /// Ranged, but not the receive/change shape Winnow derives from.
    case unsupportedDerivation

    public var errorDescription: String? {
        switch self {
        case .malformed:
            "That isn't a valid pay-to key. Paste the person's Winnow card or their public account key."
        case .privateKey:
            "That is a private key. For safety, paste only the public account key—never a seed phrase or private key."
        case .singleAddressKey:
            "This key gives one address only — paste the address itself instead."
        case .notSingleKey:
            "Winnow pays a person from a single-key descriptor such as tr([…]xpub…/<0;1>/*). Multi-key descriptors belong in shared savings."
        case let .wrongNetwork(expected):
            "That key is for a different Bitcoin network. This wallet is on \(expected.rawValue)."
        case .unsupportedDerivation:
            "This key derives addresses in a way Winnow cannot follow. Paste the account key ending in /<0;1>/* or /0/*."
        }
    }
}

extension PersonPayTo {
    /// The one derivation besides `VaultCosignerRole.scriptPath.requiredDerivation`
    /// a pay-to key may carry: receive chain only.
    static let receiveOnlyDerivation: [Descriptor.Derivation.Element] = [.step(0), .wildcard(hardened: false)]

    /// Validates a pay-to descriptor and returns it in canonical form.
    public static func descriptor(_ text: String, network: BitcoinNetwork) throws -> PersonPayTo {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let descriptor: Descriptor
        do {
            descriptor = try Descriptor(trimmed)
        } catch {
            throw PersonPayToError.malformed
        }
        guard case let .tr(keyExpression, tree) = descriptor.expression else {
            throw PersonPayToError.notSingleKey
        }
        guard tree == nil, case let .single(key) = keyExpression else {
            throw PersonPayToError.notSingleKey
        }
        switch key.base {
        case .privateKey:
            throw PersonPayToError.privateKey
        case .publicKey:
            throw PersonPayToError.singleAddressKey
        case let .extended(hdKey, keyNetwork):
            guard !hdKey.isPrivate else { throw PersonPayToError.privateKey }
            guard keyNetwork == Vault.hdNetwork(for: network) else {
                throw PersonPayToError.wrongNetwork(expected: network)
            }
        }
        let elements = key.derivation.elements
        guard elements == VaultCosignerRole.scriptPath.requiredDerivation
            || elements == receiveOnlyDerivation
        else {
            throw key.derivation.isRanged
                ? PersonPayToError.unsupportedDerivation
                : PersonPayToError.singleAddressKey
        }
        do {
            _ = try descriptor.derived(index: 0, network: Vault.hdNetwork(for: network))
        } catch {
            throw PersonPayToError.malformed
        }
        return .descriptor(descriptor.serialized())
    }

    /// Validates a plain address on `network`. `AddressError` carries its own
    /// wording (wrong network, silent-payment codes).
    public static func address(_ text: String, network: BitcoinNetwork) throws -> PersonPayTo {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        _ = try AddressDecoder.scriptPubKey(for: trimmed, network: network)
        return .address(trimmed)
    }

    public var derivesFreshAddresses: Bool {
        if case .descriptor = self { true } else { false }
    }

    public var text: String {
        switch self {
        case let .descriptor(value), let .address(value): value
        }
    }

    /// The address a payment at `index` goes to. A fixed address ignores the index.
    public func address(index: UInt32, network: BitcoinNetwork) throws -> String {
        switch self {
        case let .address(address):
            return address
        case let .descriptor(text):
            return try Descriptor(text).derived(index: index, network: Vault.hdNetwork(for: network))[0].address
        }
    }

    public func scriptPubKey(index: UInt32, network: BitcoinNetwork) throws -> Data {
        switch self {
        case let .address(address):
            return try AddressDecoder.scriptPubKey(for: address, network: network)
        case let .descriptor(text):
            return try Descriptor(text).derived(index: index, network: Vault.hdNetwork(for: network))[0].scriptPubKey
        }
    }

    /// Every script this person could have been paid at so far: indices
    /// `0 ..< count` of a descriptor, or the one address.
    public func scripts(upTo count: UInt32, network: BitcoinNetwork) throws -> [Data] {
        switch self {
        case .address:
            return [try scriptPubKey(index: 0, network: network)]
        case .descriptor:
            return try (0 ..< count).map { try scriptPubKey(index: $0, network: network) }
        }
    }

    /// What makes two pay-to keys the same person's: the script at index 0,
    /// so relabelling an origin cannot make a second entry.
    public func identity(network: BitcoinNetwork) throws -> Data {
        try scriptPubKey(index: 0, network: network)
    }
}

// MARK: - Signer keys

public enum PersonKeys {
    /// The compressed public key a signer expression resolves to at (0, 0):
    /// the identity used to refuse the same person twice.
    public static func signerIdentity(_ expression: String, network: BitcoinNetwork) throws -> Data {
        try VaultCosignerKey(expression, role: .scriptPath, network: network).publicKey(index: 0, choice: 0)
    }
}

// MARK: - Cards

public enum PersonCardError: Error, Equatable, LocalizedError {
    case notACard
    case unsupportedVersion(Int)
    case wrongNetwork(card: String, wallet: BitcoinNetwork)

    public var errorDescription: String? {
        switch self {
        case .notACard:
            "That isn't a Winnow card."
        case let .unsupportedVersion(version):
            "This card was made by a newer Winnow (card version \(version)). Update the app to read it."
        case let .wrongNetwork(card, wallet):
            "This card is for \(card); this wallet is on \(wallet.rawValue)."
        }
    }
}

/// What one person shares so others can pay them and save with them. Public
/// keys only; nothing here can spend.
public struct PersonCard: Codable, Equatable, Sendable {
    public static let kind = "person-card"
    public static let currentVersion = 1

    public var winnow: String
    public var version: Int
    public var network: String
    public var name: String
    /// Canonical pay-to descriptor, or a plain address.
    public var payTo: String?
    public var signerKey: String?

    public init(network: BitcoinNetwork, name: String, payTo: String?, signerKey: String?) {
        winnow = Self.kind
        version = Self.currentVersion
        self.network = network.rawValue
        self.name = name
        self.payTo = payTo
        self.signerKey = signerKey
    }

    public func serialized() throws -> String {
        try WinnowCardCoding.serialize(self)
    }

    public static func decode(_ text: String) throws -> PersonCard {
        let card: PersonCard = try WinnowCardCoding.decode(text, kind: kind)
        guard card.version >= 1, card.version <= currentVersion else {
            throw PersonCardError.unsupportedVersion(card.version)
        }
        return card
    }
}

/// A shared-savings descriptor, shared with every co-owner before any money
/// goes in.
public struct SharedSavingsCard: Codable, Equatable, Sendable {
    public static let kind = "shared-savings"
    public static let currentVersion = 1

    public var winnow: String
    public var version: Int
    public var network: String
    public var name: String
    public var descriptor: String

    public init(network: BitcoinNetwork, name: String, descriptor: String) {
        winnow = Self.kind
        version = Self.currentVersion
        self.network = network.rawValue
        self.name = name
        self.descriptor = descriptor
    }

    public func serialized() throws -> String {
        try WinnowCardCoding.serialize(self)
    }

    /// Decodes and proves the descriptor is a vault this wallet's network can hold.
    public static func decode(_ text: String, network: BitcoinNetwork) throws -> (card: SharedSavingsCard, vault: Vault) {
        let card: SharedSavingsCard = try WinnowCardCoding.decode(text, kind: kind)
        guard card.version >= 1, card.version <= currentVersion else {
            throw PersonCardError.unsupportedVersion(card.version)
        }
        guard card.network == network.rawValue else {
            throw PersonCardError.wrongNetwork(card: card.network, wallet: network)
        }
        let vault = try Vault(card.descriptor, network: network)
        return (card, vault)
    }
}

/// A spend of shared savings travelling between co-owners for approval.
public struct ApprovalRequest: Codable, Equatable, Sendable {
    public static let kind = "approval"
    public static let currentVersion = 1

    public var winnow: String
    public var version: Int
    public var network: String
    /// `VaultRecord.id` (the descriptor checksum); absent when a bare PSBT was pasted.
    public var vault: String?
    public var name: String?
    public var psbt: String

    public init(network: BitcoinNetwork, vault: String?, name: String?, psbt: PSBT) {
        winnow = Self.kind
        version = Self.currentVersion
        self.network = network.rawValue
        self.vault = vault
        self.name = name
        self.psbt = psbt.base64
    }

    public func serialized() throws -> String {
        try WinnowCardCoding.serialize(self)
    }

    /// Accepts the envelope or a bare Base64 PSBT.
    public static func decode(_ text: String, network: BitcoinNetwork) throws -> ApprovalRequest {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("{") {
            let request: ApprovalRequest = try WinnowCardCoding.decode(trimmed, kind: kind)
            guard request.version >= 1, request.version <= currentVersion else {
                throw PersonCardError.unsupportedVersion(request.version)
            }
            guard request.network == network.rawValue else {
                throw PersonCardError.wrongNetwork(card: request.network, wallet: network)
            }
            _ = try PSBT(base64: request.psbt)
            return request
        }
        let psbt = try PSBT(base64: trimmed)
        return ApprovalRequest(network: network, vault: nil, name: nil, psbt: psbt)
    }

    public func decodedPSBT() throws -> PSBT {
        try PSBT(base64: psbt)
    }
}

/// One JSON shape for every card: sorted keys, slashes unescaped so a key
/// expression reads as written, and a `winnow` field naming the kind.
enum WinnowCardCoding {
    private struct Envelope: Decodable {
        var winnow: String?
    }

    static func serialize<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(value), as: UTF8.self)
    }

    static func decode<T: Decodable>(_ text: String, kind: String) throws -> T {
        let data = Data(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        let decoder = JSONDecoder()
        guard let envelope = try? decoder.decode(Envelope.self, from: data), envelope.winnow == kind else {
            throw PersonCardError.notACard
        }
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw PersonCardError.notACard
        }
    }
}

// MARK: - Paste

/// What a paste on the Add person screen turned out to be.
public struct PersonImport: Equatable, Sendable {
    public enum Source: Equatable, Sendable {
        case card, keyExpression, descriptor, address
    }

    public var name: String?
    public var payTo: PersonPayTo?
    public var signerKey: String?
    public var source: Source

    public init(name: String?, payTo: PersonPayTo?, signerKey: String?, source: Source) {
        self.name = name
        self.payTo = payTo
        self.signerKey = signerKey
        self.source = source
    }
}

public enum PersonPasteError: Error, Equatable, LocalizedError {
    case empty
    case unrecognised

    public var errorDescription: String? {
        switch self {
        case .empty: "Paste the person's Winnow card, their public account key, or a Bitcoin address."
        case .unrecognised: "That doesn't look like a Winnow card, a public account key or a Bitcoin address."
        }
    }
}

/// Turns whatever was pasted into the fields of a person. Every accepted
/// form is validated on the way in; nothing private is ever kept.
public enum PersonPaste {
    public static func parse(_ text: String, network: BitcoinNetwork) throws -> PersonImport {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw PersonPasteError.empty }
        if trimmed.hasPrefix("{") {
            return try parseCard(trimmed, network: network)
        }
        if trimmed.hasPrefix("tr(") || trimmed.hasPrefix("rawtr(") {
            return try parseDescriptor(trimmed, network: network)
        }
        if let payTo = try? PersonPayTo.address(trimmed, network: network) {
            return PersonImport(name: nil, payTo: payTo, signerKey: nil, source: .address)
        }
        if let silentPayment = addressError(for: trimmed, network: network) {
            throw silentPayment
        }
        return try parseKeyExpression(trimmed, network: network)
    }

    /// A silent-payment code or a wrong-network address deserves its own
    /// message rather than "unrecognised".
    private static func addressError(for text: String, network: BitcoinNetwork) -> AddressError? {
        let lowered = text.lowercased()
        let looksLikeAddress = ["bc1", "tb1", "sp1", "tsp1", "1", "3", "m", "n", "2"]
            .contains { lowered.hasPrefix($0) } && !lowered.contains("pub")
        guard looksLikeAddress else { return nil }
        do {
            _ = try AddressDecoder.scriptPubKey(for: text, network: network)
            return nil
        } catch let error as AddressError {
            return error
        } catch {
            return nil
        }
    }

    private static func parseCard(_ text: String, network: BitcoinNetwork) throws -> PersonImport {
        let card = try PersonCard.decode(text)
        guard card.network == network.rawValue else {
            throw PersonCardError.wrongNetwork(card: card.network, wallet: network)
        }
        var payTo: PersonPayTo?
        if let raw = card.payTo?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty {
            payTo = raw.hasPrefix("tr(")
                ? try PersonPayTo.descriptor(raw, network: network)
                : try PersonPayTo.address(raw, network: network)
        }
        var signerKey: String?
        if let raw = card.signerKey?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty {
            signerKey = try VaultCosignerKey(raw, role: .scriptPath, network: network).expression
        }
        let name = card.name.trimmingCharacters(in: .whitespacesAndNewlines)
        return PersonImport(name: name.isEmpty ? nil : name, payTo: payTo, signerKey: signerKey, source: .card)
    }

    private static func parseDescriptor(_ text: String, network: BitcoinNetwork) throws -> PersonImport {
        let payTo = try PersonPayTo.descriptor(text, network: network)
        var signerKey: String?
        if case let .descriptor(canonical) = payTo,
           let inner = innerKeyExpression(canonical),
           let signer = try? VaultCosignerKey(inner, role: .scriptPath, network: network) {
            signerKey = signer.expression
        }
        return PersonImport(name: nil, payTo: payTo, signerKey: signerKey, source: .descriptor)
    }

    /// `tr(KEY)#checksum` → `KEY`.
    static func innerKeyExpression(_ canonical: String) -> String? {
        guard canonical.hasPrefix("tr(") else { return nil }
        let body = canonical.split(separator: "#", maxSplits: 1).first.map(String.init) ?? canonical
        guard body.hasSuffix(")") else { return nil }
        return String(body.dropFirst(3).dropLast())
    }

    private static func parseKeyExpression(_ text: String, network: BitcoinNetwork) throws -> PersonImport {
        do {
            let signer = try VaultCosignerKey(text, role: .scriptPath, network: network)
            let payTo = try PersonPayTo.descriptor("tr(\(signer.expression))", network: network)
            return PersonImport(name: nil, payTo: payTo, signerKey: signer.expression, source: .keyExpression)
        } catch VaultCosignerKeyError.scriptPathDerivationRequired {
            // `[fp/path]xpub…` with no suffix: supply the one Winnow uses.
            guard let signer = try? VaultCosignerKey(text + "/<0;1>/*", role: .scriptPath, network: network),
                  let payTo = try? PersonPayTo.descriptor("tr(\(signer.expression))", network: network)
            else { throw PersonPasteError.unrecognised }
            return PersonImport(name: nil, payTo: payTo, signerKey: signer.expression, source: .keyExpression)
        } catch VaultCosignerKeyError.missingOrigin {
            // A bare account key can be paid, but cannot co-own savings: a
            // signer needs its origin for the PSBT derivation fields.
            for candidate in [text, text + "/0/*"] {
                if let payTo = try? PersonPayTo.descriptor("tr(\(candidate))", network: network) {
                    return PersonImport(name: nil, payTo: payTo, signerKey: nil, source: .keyExpression)
                }
            }
            _ = try PersonPayTo.descriptor("tr(\(text)/0/*)", network: network)
            throw PersonPasteError.unrecognised
        } catch VaultCosignerKeyError.malformed {
            throw PersonPasteError.unrecognised
        }
    }
}

// MARK: - Labels

/// Who an output of a shared-savings spend pays, in the words a co-owner reads.
public enum PaymentLabel: Equatable, Sendable {
    case savings(String)
    case person(String)
    case you
    case unknown
}

/// Resolves output scripts against what this phone knows: the savings'
/// own derivations (decided by `Vault.reviewSpend`, never by PSBT metadata),
/// the people in the address book, and the wallet's own scripts.
public struct PaymentLabeler: Sendable {
    public var savingsName: String
    public var personScripts: [Data: String]
    public var ownScripts: Set<Data>

    public init(savingsName: String, personScripts: [Data: String], ownScripts: Set<Data>) {
        self.savingsName = savingsName
        self.personScripts = personScripts
        self.ownScripts = ownScripts
    }

    public func label(script: Data, isVaultOwned: Bool) -> PaymentLabel {
        if isVaultOwned { return .savings(savingsName) }
        if let name = personScripts[script] { return .person(name) }
        if ownScripts.contains(script) { return .you }
        return .unknown
    }
}
