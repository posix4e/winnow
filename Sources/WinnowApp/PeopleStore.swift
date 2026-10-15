import VaultKit
import WalletCore
import Foundation

/// A saved recipient or co-owner, as persisted at `people.json`. Public keys
/// only: nothing here can spend, so the file is not a wallet's and survives
/// deleting one.
struct PersonRecord: Codable, Equatable, Identifiable, Sendable {
    /// Opaque; a UUID string.
    var id: String
    var name: String
    /// Absent for a signer-only or label-only person.
    var payTo: PersonPayTo?
    /// A validated script-path signer expression, `[fp/path]xpub…/<0;1>/*`.
    var signerKey: String?
    /// The next receive-chain index a payment to this person derives.
    var nextPaymentIndex: UInt32 = 0
    /// Nil in older files: payable recipients were all saved. Keep the record
    /// when hiding a shortcut so past names and address counters survive.
    var savedRecipient: Bool?
    enum DestinationProvenance: String, Codable, Sendable {
        case supplied, localFunding, explorerFunding
    }
    var destinationProvenance: DestinationProvenance?
    var destinationSource: String?
    var hasUnverifiedFundingDestination: Bool {
        destinationProvenance == .localFunding || destinationProvenance == .explorerFunding
    }

    var canCoOwnSavings: Bool { signerKey != nil }
    var derivesFreshAddresses: Bool { payTo?.derivesFreshAddresses == true }
    var isSavedRecipient: Bool { payTo != nil && savedRecipient != false }
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
    case unknownPerson
    case tooMany

    var errorDescription: String? {
        switch self {
        case let .invalidState(reason):
            "Invalid people storage: \(reason)"
        case .damaged:
            "Winnow could not safely read your saved recipients, so they cannot be changed until the file is readable again."
        case let .duplicate(existingName):
            "That key already belongs to \(existingName)."
        case .unknownPerson:
            "That person is no longer in your list."
        case .tooMany:
            "Winnow keeps at most \(PeopleStore.maximumPeople) people."
        }
    }
}

/// Local recipient names, public keys, address counters, and per-payment
/// sender labels. Mirrors `VaultStore`: one JSON file per network, sealed
/// under a Keychain-held key, a strict validation that fails the whole
/// snapshot closed, and a rollback on any failed write. Differs in one way:
/// damage is not fatal to the app.
/// A vault holds money; a person is a public key and a name. So a damaged
/// file is reported, left untouched, and refused every mutation until it
/// reads again, while the rest of the wallet carries on.
actor PeopleStore {
    static let maximumPeople = 1_000
    /// Sender labels share the file and its bound: a label names a payment,
    /// never a key, so the map cannot outgrow the people list's ceiling.
    static let maximumSenderLabels = 1_000
    static let maximumNextIndex = VaultStore.maximumNextIndex

    private var records: [PersonRecord] = []
    /// Txid display hex → person id: who a received payment is labelled as
    /// coming from. Persisted in the same file as the records.
    private var senderByTxid: [String: String] = [:]
    private var storageURL: URL?
    private var network: BitcoinNetwork = .signet
    private var isDamaged = false
    private let writeData: @Sendable (Data, URL) throws -> Void
    /// Reads verify and writes seal, under a key the app container cannot
    /// reach: a signer key substituted in the file would validate perfectly
    /// and show up as a co-owner, so validation alone is not enough here.
    private let seal: StoreSeal

    init(keys: any StoreKeyVault, writeData: @escaping @Sendable (Data, URL) throws -> Void = { data, url in
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }) {
        seal = StoreSeal(store: "people", keys: keys)
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
            senderByTxid = [:]
            return .missing
        }
        guard FileManager.default.fileExists(atPath: storageURL.path) else {
            records = []
            senderByTxid = [:]
            return .missing
        }
        do {
            let file = try seal.read(try Self.boundedRead(storageURL), network: network)
            let payload = try Self.decodePayload(file.payload)
            try Self.validate(payload.people, senderByTxid: payload.senderByTxid, network: network)
            records = payload.people
            senderByTxid = payload.senderByTxid
            // A file from before sealing is adopted as it is and sealed now.
            // If that write fails the seal discards the key it made, so the
            // file is adopted again next launch; the records are loaded
            // either way.
            if file.predatesSealing { try? persist() }
            return .loaded
        } catch {
            records = []
            senderByTxid = [:]
            isDamaged = true
            return .damaged(Self.damagedStorageMessage(for: error))
        }
    }

    /// The file's payload. The file was a bare array of people before sender
    /// labels existed, and that older shape still decodes — as an envelope
    /// without any labels.
    struct Backup: Codable, Equatable, Sendable {
        var people: [PersonRecord]
        var senderByTxid: [String: String]

        init(people: [PersonRecord], senderByTxid: [String: String] = [:]) {
            self.people = people
            self.senderByTxid = senderByTxid
        }

        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            people = try container.decode([PersonRecord].self, forKey: .people)
            senderByTxid = try container.decodeIfPresent([String: String].self, forKey: .senderByTxid) ?? [:]
        }
    }

    private typealias PersistedPayload = Backup

    func backup() throws -> Backup {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        return Backup(people: records, senderByTxid: senderByTxid)
    }

    static func validateBackup(_ backup: Backup, network: BitcoinNetwork) throws {
        try validate(backup.people, senderByTxid: backup.senderByTxid, network: network)
        let ids = Set(backup.people.map(\.id))
        guard backup.senderByTxid.values.allSatisfy(ids.contains),
              try JSONEncoder().encode(backup).count <= maximumFileBytes else {
            throw PeopleStorageError.invalidState("invalid cloud address book")
        }
    }

    /// Keep contacts already on this device and never rewind a recipient's
    /// derivation counter. Remap labels when two snapshots name the same key.
    func planRestore(_ incoming: Backup) throws -> Backup {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        try Self.validateBackup(incoming, network: network)
        var merged = records
        var ids: [String: String] = [:]
        for person in incoming.people {
            let existing = try merged.first { $0.id == person.id }
                ?? Self.firstSharingAKey(with: person, among: merged, network: network)
            if let existing, let index = merged.firstIndex(where: { $0.id == existing.id }) {
                ids[person.id] = existing.id
                if try existing.payTo?.identity(network: network) == person.payTo?.identity(network: network) {
                    merged[index].nextPaymentIndex = max(existing.nextPaymentIndex, person.nextPaymentIndex)
                }
            } else {
                merged.append(person)
                ids[person.id] = person.id
            }
        }
        var labels = senderByTxid
        for (txid, id) in incoming.senderByTxid where labels[txid] == nil { labels[txid] = ids[id] }
        let result = Backup(people: merged, senderByTxid: labels)
        try Self.validateBackup(result, network: network)
        return result
    }

    func restore(_ backup: Backup) throws {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        try Self.validateBackup(backup, network: network)
        let previous = Backup(people: records, senderByTxid: senderByTxid)
        records = backup.people
        senderByTxid = backup.senderByTxid
        do { try persist() }
        catch {
            records = previous.people
            senderByTxid = previous.senderByTxid
            throw error
        }
    }

    private static func decodePayload(_ data: Data) throws -> PersistedPayload {
        if let envelope = try? JSONDecoder().decode(PersistedPayload.self, from: data) {
            return envelope
        }
        return PersistedPayload(people: try JSONDecoder().decode([PersonRecord].self, from: data))
    }

    var all: [PersonRecord] { records }

    /// Txid display hex → person id, as last persisted or mutated.
    var senderLabels: [String: String] { senderByTxid }

    /// The person labelled as the sender of the transaction with display
    /// hex `txidHex`. Nil when the payment is unlabelled — or when the
    /// person is gone, a dangling label being pruned on the next write.
    func sender(forTxidHex txidHex: String) -> PersonRecord? {
        guard let personID = senderByTxid[txidHex] else { return nil }
        return records.first { $0.id == personID }
    }

    func record(id: String) -> PersonRecord? {
        records.first { $0.id == id }
    }

    /// Labels a received payment with the person who paid it. The person
    /// must exist; the map is capped like the people list.
    func labelSender(txidHex: String, personID: String) throws {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        guard records.contains(where: { $0.id == personID }) else {
            throw PeopleStorageError.unknownPerson
        }
        guard senderByTxid[txidHex] != nil || senderByTxid.count < Self.maximumSenderLabels else {
            throw PeopleStorageError.tooMany
        }
        try mutateLabels { $0[txidHex] = personID }
    }

    /// Drops one payment's sender label, if it has one.
    func removeSenderLabel(txidHex: String) {
        guard senderByTxid[txidHex] != nil else { return }
        try? mutateLabels { $0[txidHex] = nil }
    }

    /// Removes the person outright, and every sender label naming them.
    /// Hiding a shortcut (`updateRecipient(id:saved:)`) keeps the record —
    /// and its labels — so past names survive; this forgets.
    func remove(id: String) throws {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        guard records.contains(where: { $0.id == id }) else {
            throw PeopleStorageError.unknownPerson
        }
        try mutate { $0.removeAll { $0.id == id } }
    }

    @discardableResult
    func add(name: String, payTo: PersonPayTo?, signerKey: String?,
             provenance: PersonRecord.DestinationProvenance? = nil, source: String? = nil) throws -> PersonRecord {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        let trimmedName = try Self.normalizedName(name)
        try Self.requireSource(source)
        // payTo and signerKey may both be absent: a name alone labels a
        // received payment, and keys can only ever be added by re-saving.
        let candidate = PersonRecord(id: UUID().uuidString, name: trimmedName,
                                     payTo: payTo, signerKey: signerKey,
                                     destinationProvenance: provenance, destinationSource: source)
        if let existing = try Self.firstSharingAKey(with: candidate, among: records, network: network) {
            if !existing.isSavedRecipient, payTo != nil, existing.payTo == payTo, existing.signerKey == signerKey {
                return try updateRecipient(id: existing.id, name: trimmedName, saved: true)
            }
            throw PeopleStorageError.duplicate(existingName: existing.name)
        }
        guard records.count < Self.maximumPeople else { throw PeopleStorageError.tooMany }
        return try mutate { $0.append(candidate) }.first { $0.id == candidate.id }!
    }

    /// Edit presentation only, preserving the current keys and payment counter.
    @discardableResult
    func updateRecipient(id: String, name: String? = nil, saved: Bool) throws -> PersonRecord {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        guard let position = records.firstIndex(where: { $0.id == id }) else {
            throw PeopleStorageError.unknownPerson
        }
        let normalized = try name.map(Self.normalizedName)
        return try mutate {
            if let normalized { $0[position].name = normalized }
            $0[position].savedRecipient = saved
        }[position]
    }

    /// The most a people file may weigh: a thousand people and a thousand
    /// sender labels fit in well under a megabyte.
    static let maximumFileBytes = 4 * 1_024 * 1_024

    /// Measures before reading, so a planted file is refused rather than held.
    static func boundedRead(_ url: URL) throws -> Data {
        let size = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int ?? Int.max
        guard size <= maximumFileBytes else { throw PeopleStorageError.invalidState("people file too large") }
        let data = try Data(contentsOf: url)
        guard data.count <= maximumFileBytes else { throw PeopleStorageError.invalidState("people file too large") }
        return data
    }

    /// A name is stored only in the form `DisplayName` allows: short, single
    /// line, no control characters.
    private static func normalizedName(_ name: String) throws -> String {
        guard let normalized = DisplayName.normalized(name) else {
            throw PeopleStorageError.invalidState("a person needs a short, single-line name")
        }
        return normalized
    }

    /// Where a destination came from is free text shown next to it; bounded
    /// like a name so a card cannot plant a page of it.
    static let maximumSourceLength = 256

    private static func requireSource(_ source: String?) throws {
        guard let source else { return }
        guard source.count <= maximumSourceLength, DisplayName.normalized(source) != nil else {
            throw PeopleStorageError.invalidState("a destination source must be short and single-line")
        }
    }

    /// A name-only record acquires a destination only through explicit selection.
    /// Existing destinations are immutable here so past payments retain meaning.
    func attachDestination(id: String, payTo: PersonPayTo, provenance: PersonRecord.DestinationProvenance,
                           source: String? = nil) throws {
        guard !isDamaged else { throw PeopleStorageError.damaged }
        guard let index = records.firstIndex(where: { $0.id == id }), records[index].payTo == nil else {
            throw PeopleStorageError.invalidState("only a name-only contact can attach a destination")
        }
        try Self.requireSource(source)
        var candidate = records[index]
        candidate.payTo = payTo
        if let duplicate = try Self.firstSharingAKey(with: candidate, among: records.filter { $0.id != id }, network: network) {
            throw PeopleStorageError.duplicate(existingName: duplicate.name)
        }
        try mutate {
            $0[index].payTo = payTo
            $0[index].destinationProvenance = provenance
            $0[index].destinationSource = source
            $0[index].savedRecipient = true
        }
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
    /// only when every step succeeded. Labels naming a person the change
    /// removed are pruned here — writes never leave a dangling label, even
    /// though reads tolerate one.
    @discardableResult
    private func mutate(_ change: (inout [PersonRecord]) -> Void) throws -> [PersonRecord] {
        var candidate = records
        change(&candidate)
        let surviving = Set(candidate.map(\.id))
        let candidateLabels = senderByTxid.filter { surviving.contains($0.value) }
        try Self.validate(candidate, senderByTxid: candidateLabels, network: network)
        let previous = records
        let previousLabels = senderByTxid
        records = candidate
        senderByTxid = candidateLabels
        do {
            try persist()
        } catch {
            records = previous
            senderByTxid = previousLabels
            throw error
        }
        return records
    }

    /// The labels half of `mutate`: the same validate-persist-rollback
    /// spine, with the records untouched.
    private func mutateLabels(_ change: (inout [String: String]) -> Void) throws {
        var candidate = senderByTxid
        change(&candidate)
        try Self.validate(records, senderByTxid: candidate, network: network)
        let previous = senderByTxid
        senderByTxid = candidate
        do {
            try persist()
        } catch {
            senderByTxid = previous
            throw error
        }
    }

    private static let damagedStorageMessage =
        "Winnow could not read the saved-recipient file. It has been left untouched. You can still send to an address; saved recipients cannot be changed until the file is readable again."

    private static let unverifiedStorageMessage =
        "The saved-recipient file could not be verified: it was not written by Winnow on this device, or its protected key is gone. It has been left untouched. You can still send to an address; saved recipients cannot be changed until the file verifies again."

    /// Damage and a failed seal read differently to the person who has to
    /// act on the message: one is a broken file, the other a substituted one.
    private static func damagedStorageMessage(for error: any Error) -> String {
        error is SealedStoreFile.Failure ? unverifiedStorageMessage : damagedStorageMessage
    }

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

    private static func validate(_ records: [PersonRecord], senderByTxid: [String: String] = [:],
                                 network: BitcoinNetwork) throws {
        guard records.count <= maximumPeople else {
            throw PeopleStorageError.invalidState("too many people")
        }
        guard senderByTxid.count <= maximumSenderLabels else {
            throw PeopleStorageError.invalidState("too many sender labels")
        }
        for txidHex in senderByTxid.keys {
            guard txidHex.count == 64, Data(hex: txidHex) != nil else {
                throw PeopleStorageError.invalidState("a sender label has an invalid transaction id")
            }
        }
        var ids = Set<String>()
        var payIdentities = Set<Data>()
        var signerIdentities = Set<Data>()
        for record in records {
            guard ids.insert(record.id).inserted else {
                throw PeopleStorageError.invalidState("duplicate person identifier")
            }
            try validateShape(record)
            try validatePayTo(record, network: network, seen: &payIdentities)
            try validateSigner(record, network: network, seen: &signerIdentities)
        }
    }

    /// What every person needs, whatever keys they carry — or do not: a
    /// label-only person holds a name and no keys at all.
    private static func validateShape(_ record: PersonRecord) throws {
        guard DisplayName.normalized(record.name) == record.name else {
            throw PeopleStorageError.invalidState("a person has no usable name")
        }
        try requireSource(record.destinationSource)
        guard record.nextPaymentIndex <= maximumNextIndex else {
            throw PeopleStorageError.invalidState("payment index is out of range")
        }
    }

    /// Re-validating rebuilds the canonical form, which both proves the key
    /// is public and on this network and pins the stored text to what the
    /// validator would have written. `seen` catches two people sharing one.
    private static func validatePayTo(_ record: PersonRecord, network: BitcoinNetwork,
                                      seen: inout Set<Data>) throws {
        guard let payTo = record.payTo else { return }
        let canonical: PersonPayTo
        switch payTo {
        case let .descriptor(text): canonical = try PersonPayTo.descriptor(text, network: network)
        case let .address(text): canonical = try PersonPayTo.address(text, network: network)
        }
        guard canonical == payTo else {
            throw PeopleStorageError.invalidState("pay-to key is not in canonical form")
        }
        guard seen.insert(try payTo.identity(network: network)).inserted else {
            throw PeopleStorageError.invalidState("two people share a pay-to key")
        }
    }

    private static func validateSigner(_ record: PersonRecord, network: BitcoinNetwork,
                                       seen: inout Set<Data>) throws {
        guard let signerKey = record.signerKey else { return }
        let validated = try VaultCosignerKey(signerKey, role: .scriptPath, network: network)
        guard validated.expression == signerKey else {
            throw PeopleStorageError.invalidState("signer key is not in canonical form")
        }
        guard seen.insert(try validated.publicKey(index: 0, choice: 0)).inserted else {
            throw PeopleStorageError.invalidState("two people share a signer key")
        }
    }

    private func persist() throws {
        guard let storageURL else { return }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(PersistedPayload(people: records, senderByTxid: senderByTxid))
        try seal.write(data, network: network, to: storageURL, using: writeData)
    }
}
