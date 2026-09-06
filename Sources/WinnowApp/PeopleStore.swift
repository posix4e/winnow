import BitcoinCore
import BitcoinP2P
import Foundation
import WalletCore

/// A person in the address book, as persisted at `people.json`. Public keys
/// only: nothing here can spend, so the file is not a wallet's and survives
/// deleting one.
struct PersonRecord: Codable, Equatable, Identifiable, Sendable {
    /// Opaque; a UUID string.
    var id: String
    var name: String
    /// Absent for a signer-only person.
    var payTo: PersonPayTo?
    /// A validated script-path signer expression, `[fp/path]xpub…/<0;1>/*`.
    var signerKey: String?
    /// The next receive-chain index a payment to this person derives.
    var nextPaymentIndex: UInt32 = 0

    var canCoOwnSavings: Bool { signerKey != nil }
    var derivesFreshAddresses: Bool { payTo?.derivesFreshAddresses == true }
}

enum PeopleStorageOpenResult: Equatable, Sendable {
    case missing
    case loaded
    case damaged(String)
}

enum PeopleStorageError: Error, Equatable, LocalizedError {
    case invalidState(String)
    case damaged
    case duplicate(existingName: String)
    case nothingToSave
    case unknownPerson
    case tooMany

    var errorDescription: String? {
        switch self {
        case let .invalidState(reason):
            "Invalid people storage: \(reason)"
        case .damaged:
            "Winnow could not safely read your People list, so nothing can be added to it until it is readable again."
        case let .duplicate(existingName):
            "That key already belongs to \(existingName)."
        case .nothingToSave:
            "Paste a card, a public account key or an address before saving."
        case .unknownPerson:
            "That person is no longer in your list."
        case .tooMany:
            "Winnow keeps at most \(PeopleStore.maximumPeople) people."
        }
    }
}

/// The address book. Mirrors `VaultStore`: one JSON file per network, a
/// strict validation that fails the whole snapshot closed, and a rollback
/// on any failed write. Differs in one way: damage is not fatal to the app.
/// A vault holds money; a person is a public key and a name. So a damaged
/// file is reported, left untouched, and refused every mutation until it
/// reads again, while the rest of the wallet carries on.
actor PeopleStore {
    static let maximumPeople = 1_000
    static let maximumNextIndex = VaultStore.maximumNextIndex

    private var records: [PersonRecord] = []
    private var storageURL: URL?
    private var network: BitcoinNetwork = .signet
    private var isDamaged = false
    private let writeData: @Sendable (Data, URL) throws -> Void

    init(writeData: @escaping @Sendable (Data, URL) throws -> Void = { data, url in
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }) {
        self.writeData = writeData
    }

    /// Points the store at its JSON file, loading any existing records.
    @discardableResult
    func configure(storageURL: URL?, network: BitcoinNetwork) -> PeopleStorageOpenResult {
        self.storageURL = storageURL
        self.network = network
        isDamaged = false
        guard let storageURL else {
            records = []
            return .missing
        }
        guard FileManager.default.fileExists(atPath: storageURL.path) else {
            records = []
            return .missing
        }
        do {
            let data = try Data(contentsOf: storageURL)
            let decoded = try JSONDecoder().decode([PersonRecord].self, from: data)
            try Self.validate(decoded, network: network)
            records = decoded
            return .loaded
        } catch {
            records = []
            isDamaged = true
            return .damaged(Self.damagedStorageMessage)
        }
    }

    var all: [PersonRecord] { records }

    func record(id: String) -> PersonRecord? {
        records.first { $0.id == id }
    }

    @discardableResult
    func add(name: String, payTo: PersonPayTo?, signerKey: String?) throws -> PersonRecord {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            throw PeopleStorageError.invalidState("a person needs a name")
        }
        guard payTo != nil || signerKey != nil else { throw PeopleStorageError.nothingToSave }
        guard records.count < Self.maximumPeople else { throw PeopleStorageError.tooMany }
        let candidate = PersonRecord(id: UUID().uuidString, name: trimmedName,
                                     payTo: payTo, signerKey: signerKey)
        if let existing = try Self.firstSharingAKey(with: candidate, among: records, network: network) {
            throw PeopleStorageError.duplicate(existingName: existing.name)
        }
        return try mutate { $0.append(candidate) }.first { $0.id == candidate.id }!
    }

    /// Replaces a person wholesale; the id must already exist.
    func update(_ record: PersonRecord) throws {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        guard let position = records.firstIndex(where: { $0.id == record.id }) else {
            throw PeopleStorageError.unknownPerson
        }
        let others = records.enumerated().filter { $0.offset != position }.map(\.element)
        if let existing = try Self.firstSharingAKey(with: record, among: others, network: network) {
            throw PeopleStorageError.duplicate(existingName: existing.name)
        }
        try mutate { $0[position] = record }
    }

    func remove(id: String) throws {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        guard records.contains(where: { $0.id == id }) else { return }
        try mutate { $0.removeAll { $0.id == id } }
    }

    /// Moves the person's payment counter past `index`. Monotonic, so a
    /// resumed send that already advanced it is a no-op, and never called
    /// for a preview that was cancelled.
    func advancePaymentIndex(id: String, past index: UInt32) throws {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        guard let position = records.firstIndex(where: { $0.id == id }) else {
            throw PeopleStorageError.unknownPerson
        }
        let next = index &+ 1
        guard next > records[position].nextPaymentIndex else { return }
        try mutate { $0[position].nextPaymentIndex = next }
    }

    /// Applies `change` to a copy, validates, persists, and keeps the copy
    /// only when every step succeeded.
    @discardableResult
    private func mutate(_ change: (inout [PersonRecord]) -> Void) throws -> [PersonRecord] {
        var candidate = records
        change(&candidate)
        try Self.validate(candidate, network: network)
        let previous = records
        records = candidate
        do {
            try persist()
        } catch {
            records = previous
            throw error
        }
        return records
    }

    private static let damagedStorageMessage =
        "Winnow found your People list but could not safely read it. The file was left untouched, and nothing can be added until it is readable again. Retry; if this continues, ask for help before changing anything."

    /// The existing person who already holds one of `candidate`'s keys, if any.
    /// Keys are compared as derived material, so relabelling an origin cannot
    /// make a second entry for the same account.
    private static func firstSharingAKey(with candidate: PersonRecord, among others: [PersonRecord],
                                         network: BitcoinNetwork) throws -> PersonRecord? {
        let payIdentity = try candidate.payTo?.identity(network: network)
        let signerIdentity = try candidate.signerKey.map { try PersonKeys.signerIdentity($0, network: network) }
        for other in others {
            if let payIdentity, let existing = try other.payTo?.identity(network: network),
               existing == payIdentity {
                return other
            }
            if let signerIdentity, let key = other.signerKey,
               try PersonKeys.signerIdentity(key, network: network) == signerIdentity {
                return other
            }
        }
        return nil
    }

    private static func validate(_ records: [PersonRecord], network: BitcoinNetwork) throws {
        guard records.count <= maximumPeople else {
            throw PeopleStorageError.invalidState("too many people")
        }
        var ids = Set<String>()
        var payIdentities = Set<Data>()
        var signerIdentities = Set<Data>()
        for record in records {
            guard ids.insert(record.id).inserted else {
                throw PeopleStorageError.invalidState("duplicate person identifier")
            }
            guard !record.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw PeopleStorageError.invalidState("a person has no name")
            }
            guard record.payTo != nil || record.signerKey != nil else {
                throw PeopleStorageError.invalidState("a person has no keys")
            }
            guard record.nextPaymentIndex <= maximumNextIndex else {
                throw PeopleStorageError.invalidState("payment index is out of range")
            }
            if let payTo = record.payTo {
                // Re-validating rebuilds the canonical form, which both proves
                // the key is public and on this network and pins the stored
                // text to what the validator would have written.
                let canonical: PersonPayTo
                switch payTo {
                case let .descriptor(text): canonical = try PersonPayTo.descriptor(text, network: network)
                case let .address(text): canonical = try PersonPayTo.address(text, network: network)
                }
                guard canonical == payTo else {
                    throw PeopleStorageError.invalidState("pay-to key is not in canonical form")
                }
                guard payIdentities.insert(try payTo.identity(network: network)).inserted else {
                    throw PeopleStorageError.invalidState("two people share a pay-to key")
                }
            }
            if let signerKey = record.signerKey {
                let validated = try VaultCosignerKey(signerKey, role: .scriptPath, network: network)
                guard validated.expression == signerKey else {
                    throw PeopleStorageError.invalidState("signer key is not in canonical form")
                }
                guard signerIdentities.insert(try validated.publicKey(index: 0, choice: 0)).inserted else {
                    throw PeopleStorageError.invalidState("two people share a signer key")
                }
            }
        }
    }

    private func persist() throws {
        guard let storageURL else { return }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(records)
        try writeData(data, storageURL)
    }
}
