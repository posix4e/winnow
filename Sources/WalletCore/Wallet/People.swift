import CryptoKit
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
    /// A BIP352 silent payment code (`sp1…`/`tsp1…`), canonical lower case.
    /// Reusable like a descriptor — every payment lands on a fresh on-chain
    /// address — but the address is derived from the sender's inputs, so
    /// there is no script to watch for or match against.
    case silentPayment(String)
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
        case "silentPayment": self = .silentPayment(value)
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
        case let .silentPayment(value):
            try container.encode("silentPayment", forKey: .kind)
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
    /// A `rawtr()` or other shape that is not one person's tweaked key.
    case notSingleKey
    case wrongNetwork(expected: BitcoinNetwork)
    /// Ranged, but not the receive/change shape Winnow derives from.
    case unsupportedDerivation
    /// A silent payment code has no script of its own: the address is made
    /// from the paying transaction's inputs.
    case noFixedScript

    public var errorDescription: String? {
        switch self {
        case .noFixedScript:
            "A silent payment code has no fixed address; its payments are derived when they are sent."
        case .malformed:
            "That isn't a valid pay-to key. Paste the person's Winnow card or their public account key."
        case .privateKey:
            "That is a private key. For safety, paste only the public account key—never a seed phrase or private key."
        case .singleAddressKey:
            "This key gives one address only — paste the address itself instead."
        case .notSingleKey:
            "Winnow pays a person from a single-key descriptor such as tr([…]xpub…/<0;1>/*)."
        case let .wrongNetwork(expected):
            "That key is for a different Bitcoin network. This wallet is on \(expected.rawValue)."
        case .unsupportedDerivation:
            "This key derives addresses in a way Winnow cannot follow. Paste the account key ending in /<0;1>/* or /0/*."
        }
    }
}

extension PersonPayTo {
    /// The receive/change shape every Winnow account key carries.
    static let receiveChangeDerivation: [Descriptor.Derivation.Element] = [.multipath([0, 1]), .wildcard(hardened: false)]

    /// The one other derivation a pay-to key may carry: receive chain only.
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
        guard case let .tr(key) = descriptor.expression else {
            throw PersonPayToError.notSingleKey
        }
        switch key.base {
        case .privateKey:
            throw PersonPayToError.privateKey
        case .publicKey:
            throw PersonPayToError.singleAddressKey
        case let .extended(hdKey, keyNetwork):
            guard !hdKey.isPrivate else { throw PersonPayToError.privateKey }
            guard keyNetwork == Wallet.hdNetwork(for: network) else {
                throw PersonPayToError.wrongNetwork(expected: network)
            }
        }
        let elements = key.derivation.elements
        guard elements == receiveChangeDerivation || elements == receiveOnlyDerivation else {
            throw key.derivation.isRanged
                ? PersonPayToError.unsupportedDerivation
                : PersonPayToError.singleAddressKey
        }
        do {
            _ = try descriptor.derived(index: 0, bitcoinNetwork: network)
        } catch {
            throw PersonPayToError.malformed
        }
        return .descriptor(descriptor.serialized())
    }

    /// Validates a plain address on `network`. `AddressError` carries its own
    /// wording (for example, a wrong-network address).
    public static func address(_ text: String, network: BitcoinNetwork) throws -> PersonPayTo {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        _ = try AddressDecoder.scriptPubKey(for: trimmed, network: network)
        return .address(trimmed)
    }

    /// Validates a silent payment code on `network` and returns it in canonical
    /// (lower-case) form. `SilentPaymentAddressError` carries its own wording.
    public static func silentPayment(_ text: String, network: BitcoinNetwork) throws -> PersonPayTo {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let code = try SilentPaymentAddress(trimmed, expectedHRP: SilentPayment.hrp(for: network))
        return .silentPayment(try code.encoded)
    }

    /// Whether the person's payment index moves with each payment. A silent
    /// payment code is reusable too, but by derivation, not by counting.
    public var derivesFreshAddresses: Bool {
        if case .descriptor = self { true } else { false }
    }

    public var isSilentPayment: Bool {
        if case .silentPayment = self { true } else { false }
    }

    public var text: String {
        switch self {
        case let .descriptor(value), let .address(value), let .silentPayment(value): value
        }
    }

    /// The address a payment at `index` goes to. A fixed address ignores the
    /// index; so does a silent payment code, which is what the send screen
    /// is handed and resolves to an output at signing time.
    public func address(index: UInt32, network: BitcoinNetwork) throws -> String {
        switch self {
        case let .address(address), let .silentPayment(address):
            return address
        case let .descriptor(text):
            return try Descriptor(text).derived(index: index, bitcoinNetwork: network)[0].address
        }
    }

    public func scriptPubKey(index: UInt32, network: BitcoinNetwork) throws -> Data {
        switch self {
        case let .address(address):
            return try AddressDecoder.scriptPubKey(for: address, network: network)
        case let .descriptor(text):
            return try Descriptor(text).derived(index: index, bitcoinNetwork: network)[0].scriptPubKey
        case .silentPayment:
            throw PersonPayToError.noFixedScript
        }
    }

    /// Every script this person could have been paid at so far: indices
    /// `0 ..< count` of a descriptor, or the one address. A silent payment
    /// code has none — its outputs are labelled from the send that made them.
    public func scripts(upTo count: UInt32, network: BitcoinNetwork) throws -> [Data] {
        switch self {
        case .address:
            return [try scriptPubKey(index: 0, network: network)]
        case .descriptor:
            return try (0 ..< count).map { try scriptPubKey(index: $0, network: network) }
        case .silentPayment:
            return []
        }
    }

    /// What makes two pay-to keys the same person's: the script at index 0,
    /// so relabelling an origin cannot make a second entry. A silent payment
    /// code is identified by its two keys (66 bytes, longer than any
    /// scriptPubKey Winnow pays, so the two kinds cannot collide).
    public func identity(network: BitcoinNetwork) throws -> Data {
        if case let .silentPayment(code) = self {
            let address = try SilentPaymentAddress(code)
            return address.scanKey + address.spendKey
        }
        return try scriptPubKey(index: 0, network: network)
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

/// A person's display name as it may be stored: trimmed, at most
/// `maximumLength` characters, and free of control characters and line
/// breaks — so a pasted card cannot plant megabytes into a file re-read at
/// every launch, or a second line above the address on the review screen.
public enum DisplayName {
    public static let maximumLength = 120

    public static func normalized(_ text: String) -> String? {
        let name = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= maximumLength,
              !name.unicodeScalars.contains(where: {
                  CharacterSet.controlCharacters.contains($0) || CharacterSet.newlines.contains($0)
              })
        else { return nil }
        return name
    }
}

/// What one person shares so others can pay them. Public keys only; nothing
/// here can spend. A card written by a Winnow that also carried a signer key
/// still decodes: unknown fields are ignored.
public struct PersonCard: Codable, Equatable, Sendable {
    public static let kind = "person-card"
    public static let currentVersion = 1

    public var winnow: String
    public var version: Int
    public var network: String
    public var name: String
    /// Canonical pay-to descriptor, or a plain address.
    public var payTo: String?

    public init(network: BitcoinNetwork, name: String, payTo: String?) {
        winnow = Self.kind
        version = Self.currentVersion
        self.network = network.rawValue
        self.name = name
        self.payTo = payTo
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

    /// A card is a name and a key; anything larger is not a card and must
    /// not be decoded, let alone persisted and re-read at every launch.
    public static let maximumBytes = 64 * 1_024

    static func decode<T: Decodable>(_ text: String, kind: String) throws -> T {
        let data = Data(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        guard data.count <= maximumBytes else { throw PersonCardError.notACard }
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
    public var source: Source

    public init(name: String?, payTo: PersonPayTo?, source: Source) {
        self.name = name
        self.payTo = payTo
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
            let payTo = try PersonPayTo.descriptor(trimmed, network: network)
            return PersonImport(name: nil, payTo: payTo, source: .descriptor)
        }
        if SilentPaymentAddress.looksLikeCode(trimmed) {
            return try parseSilentPayment(trimmed, network: network)
        }
        if let payTo = try? PersonPayTo.address(trimmed, network: network) {
            return PersonImport(name: nil, payTo: payTo, source: .address)
        }
        if let error = addressError(for: trimmed, network: network) {
            throw error
        }
        return try parseKeyExpression(trimmed, network: network)
    }

    /// An `sp1…`/`tsp1…` code. A wrong network is worth saying; anything else
    /// that merely looks like a code is unrecognised, like any other paste.
    private static func parseSilentPayment(_ text: String, network: BitcoinNetwork) throws -> PersonImport {
        do {
            let payTo = try PersonPayTo.silentPayment(text, network: network)
            return PersonImport(name: nil, payTo: payTo, source: .address)
        } catch let error as SilentPaymentAddressError {
            if case .wrongHRP = error { throw error }
            throw PersonPasteError.unrecognised
        }
    }

    /// Preserve address-specific errors such as a wrong network.
    private static func addressError(for text: String, network: BitcoinNetwork) -> AddressError? {
        let lowered = text.lowercased()
        let looksLikeAddress = ["bc1", "tb1", "1", "3", "m", "n", "2"]
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
            if raw.hasPrefix("tr(") {
                payTo = try PersonPayTo.descriptor(raw, network: network)
            } else if SilentPaymentAddress.looksLikeCode(raw) {
                payTo = try PersonPayTo.silentPayment(raw, network: network)
            } else {
                payTo = try PersonPayTo.address(raw, network: network)
            }
        }
        return PersonImport(name: DisplayName.normalized(card.name), payTo: payTo, source: .card)
    }

    /// A bare key expression: `[fp/path]tpub…/<0;1>/*` as Winnow exports it,
    /// or an account key without a suffix, which gets the receive/change
    /// shape (or, for a key with no origin, the receive chain) added. A
    /// private key or a key for another network is refused by name; anything
    /// else that cannot be paid is simply unrecognised.
    private static func parseKeyExpression(_ text: String, network: BitcoinNetwork) throws -> PersonImport {
        for candidate in [text, text + "/<0;1>/*", text + "/0/*"] {
            do {
                let payTo = try PersonPayTo.descriptor("tr(\(candidate))", network: network)
                return PersonImport(name: nil, payTo: payTo, source: .keyExpression)
            } catch PersonPayToError.privateKey {
                throw PersonPayToError.privateKey
            } catch let PersonPayToError.wrongNetwork(expected) {
                throw PersonPayToError.wrongNetwork(expected: expected)
            } catch {
                continue
            }
        }
        throw PersonPasteError.unrecognised
    }
}
