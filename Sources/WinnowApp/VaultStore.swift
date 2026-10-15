import VaultKit
import WalletCore
import Foundation

enum VaultStorageOpenResult: Equatable, Sendable {
    case missing
    case loaded
    case damaged(String)
}

enum VaultStorageError: Error, Equatable, LocalizedError {
    case invalidState(String)

    var errorDescription: String? {
        switch self {
        case let .invalidState(reason):
            "Invalid vault storage: \(reason)"
        }
    }
}

/// App-side vault bookkeeping: the persisted records plus the UTXO tracking
/// that `Wallet` performs for the single-sig wallet. Fed by the same combined
/// filter scan — a vault is just another set of watched scripts.
actor VaultStore {
    /// Prevents a forged persisted index from turning startup into billions of
    /// child-key derivations. Winnow is a bounded mobile wallet; reaching this
    /// operational ceiling requires migration instead of unbounded startup work.
    static let maximumWatchCount: UInt32 = 10_000
    static let maximumNextIndex = maximumWatchCount - 2

    private var records: [VaultRecord] = []
    private var storageURL: URL?
    private var network: BitcoinNetwork = .signet
    private let writeData: @Sendable (Data, URL) throws -> Void
    /// Reads verify and writes seal, under a key the app container cannot
    /// reach. `validate` catches a harmful shape; only the seal catches a
    /// well-formed record this app did not write.
    private let seal: StoreSeal

    init(keys: any StoreKeyVault, writeData: @escaping @Sendable (Data, URL) throws -> Void = { data, url in
        // Atomic, and unreadable until the device has been unlocked once
        // since boot: the same class the submission store uses for its file.
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }) {
        seal = StoreSeal(store: "vaults", keys: keys)
        self.writeData = writeData
    }

    /// Points the store at its JSON file, loading any existing records.
    @discardableResult
    func configure(storageURL: URL?, network: BitcoinNetwork) -> VaultStorageOpenResult {
        self.storageURL = storageURL
        self.network = network
        guard let storageURL else {
            records = []
            return .missing
        }
        guard FileManager.default.fileExists(atPath: storageURL.path) else {
            records = []
            return .missing
        }
        do {
            let file = try seal.read(try Self.boundedRead(storageURL), network: network)
            let decoded = try JSONDecoder().decode([VaultRecord].self, from: file.payload)
            try Self.validate(decoded, network: network)
            records = decoded
            // A file from before sealing is adopted as it is and sealed now;
            // a failed write leaves it for the next launch to adopt again.
            if file.predatesSealing { try? persist() }
            return .loaded
        } catch {
            records = []
            return .damaged(Self.damagedStorageMessage(for: error))
        }
    }

    var all: [VaultRecord] { records }

    func backupRecords() throws -> [VaultRecord] {
        guard !records.contains(where: { record in
            record.allUtxos.contains {
                $0.height == 0 || ($0.spent != nil && $0.spent?.height == nil)
            }
        }) else {
            throw WalletError.invalidBundle("Wait for shared-account payments to confirm before saving a backup.")
        }
        return records
    }

    /// Restore public account state; signing keys and live nonces are separate.
    func restore(_ restored: [VaultRecord]) throws {
        try Self.validate(restored, network: network)
        let previous = records
        records = restored
        do { try persist() } catch {
            records = previous
            throw error
        }
    }

    func record(id: String) -> VaultRecord? {
        records.first { $0.id == id }
    }

    /// The most a vault file may weigh: a hundred vaults with ten thousand
    /// coins each is far under this, so a larger file was not written here.
    static let maximumFileBytes = 16 * 1_024 * 1_024

    /// Measures before reading, so a planted file is refused rather than held.
    static func boundedRead(_ url: URL) throws -> Data {
        let size = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int ?? Int.max
        guard size <= maximumFileBytes else { throw VaultStorageError.invalidState("vault file too large") }
        let data = try Data(contentsOf: url)
        guard data.count <= maximumFileBytes else { throw VaultStorageError.invalidState("vault file too large") }
        return data
    }

    @discardableResult
    func add(name: String, descriptor: Descriptor, createdAtHeight: UInt32) throws -> VaultRecord {
        guard DisplayName.normalized(name) == name else {
            throw VaultStorageError.invalidState("an account needs a short, single-line name")
        }
        let serialized = descriptor.serialized()
        let id = String(serialized.split(separator: "#").last ?? Substring(serialized))
        guard !records.contains(where: { $0.id == id }) else {
            throw AppModel.AppError.duplicateVault
        }
        let record = VaultRecord(id: id, name: name, descriptor: serialized,
                                 createdAtHeight: createdAtHeight)
        let oldRecords = records
        records.append(record)
        do {
            try Self.validate(records, network: network)
            try persist()
        } catch {
            records = oldRecords
            throw error
        }
        return record
    }

    func remove(id: String) throws {
        let oldRecords = records
        records.removeAll { $0.id == id }
        do {
            try persist()
        } catch {
            records = oldRecords
            throw error
        }
    }

    /// Receive/change scripts of every vault, for the combined filter scan.
    func watchScripts(network: BitcoinNetwork) throws -> [Data] {
        guard network == self.network else {
            throw VaultStorageError.invalidState("vault network does not match the open wallet")
        }
        return try records.flatMap { record in
            try Vault(record.descriptor, network: network)
                .watchScripts(upTo: watchCount(for: record))
        }
    }

    /// Consumes one matched block like `Wallet.apply`: pays to vault scripts
    /// become UTXOs (advancing the index bookkeeping), spends shrink the set.
    func apply(match: BlockMatch, network: BitcoinNetwork) throws {
        guard network == self.network else {
            throw VaultStorageError.invalidState("vault network does not match the open wallet")
        }
        let oldRecords = records
        do {
            try applyValidated(match: match, network: network)
        } catch {
            records = oldRecords
            throw error
        }
    }

    private func applyValidated(match: BlockMatch, network: BitcoinNetwork) throws {
        var changed = false
        for recordIndex in records.indices {
            let owner = try ownerMap(for: records[recordIndex], network: network)
            for (txIndex, tx) in match.block.transactions.enumerated() {
                let txid = tx.txid
                if applySpends(of: tx, txid: txid, height: match.height,
                               recordIndex: recordIndex) {
                    changed = true
                }
                if try applyOutputs(of: tx, txid: txid, owner: owner,
                                    height: match.height,
                                    // A block's first transaction is its
                                    // coinbase, by consensus — and a coinbase
                                    // coin is unspendable for its first
                                    // `Wallet.coinbaseMaturity` confirmations,
                                    // which the review gate now checks.
                                    isCoinbase: txIndex == 0,
                                    recordIndex: recordIndex) {
                    changed = true
                }
            }
        }
        if changed {
            try Self.validate(records, network: network)
            try persist()
        }
    }

    /// script → (choice, index) for every address the record watches.
    private func ownerMap(for record: VaultRecord, network: BitcoinNetwork)
        throws -> [Data: (choice: Int, index: UInt32)] {
        let vault = try Vault(record.descriptor, network: network)
        var owner: [Data: (choice: Int, index: UInt32)] = [:]
        for index in 0 ..< watchCount(for: record) {
            for choice in 0 ..< 2 {
                owner[try vault.scriptPubKey(index: index, choice: choice)] = (choice, index)
            }
        }
        return owner
    }

    /// Tombstones the record's coins this transaction spends, and learns the
    /// height of tombstones written while the spend was only in flight.
    private func applySpends(of tx: Transaction, txid: Data, height: UInt32,
                             recordIndex: Int) -> Bool {
        var changed = false
        for input in tx.inputs {
            // Indexed into `allUtxos`, unspent rows only: an index into
            // the filtered view would address the wrong row.
            if let spent = records[recordIndex].allUtxos.firstIndex(where: {
                !$0.isSpent
                    && $0.txid == input.previousOutput.txid
                    && $0.vout == input.previousOutput.vout
            }) {
                // Marked, not removed, so a reorg can put it back.
                records[recordIndex].allUtxos[spent].spent =
                    WalletUTXO.SpentMarker(spentBy: txid, height: height)
                changed = true
            } else if let pending = records[recordIndex].allUtxos.firstIndex(where: {
                $0.spent != nil && $0.spent?.height == nil
                    && $0.txid == input.previousOutput.txid
                    && $0.vout == input.previousOutput.vout
            }) {
                // Tombstoned when the spend was signed, now confirmed:
                // the only moment its height can be learned. Without
                // this the row is never prunable and a rollback cannot
                // tell an in-flight spend from a buried one.
                records[recordIndex].allUtxos[pending].spent =
                    WalletUTXO.SpentMarker(spentBy: txid, height: height)
                changed = true
            }
        }
        return changed
    }

    /// Admits every watched output as one of the record's coins (or
    /// re-heights one already known) and advances gap-limit bookkeeping.
    private func applyOutputs(of tx: Transaction, txid: Data,
                              owner: [Data: (choice: Int, index: UInt32)],
                              height: UInt32, isCoinbase: Bool,
                              recordIndex: Int) throws -> Bool {
        var changed = false
        for (vout, output) in tx.outputs.enumerated() {
            guard let (choice, index) = owner[output.scriptPubKey] else { continue }
            guard vout <= Int(UInt32.max) else {
                throw VaultStorageError.invalidState("transaction output index is out of range")
            }
            if let existing = records[recordIndex].allUtxos.firstIndex(where: {
                $0.txid == txid && $0.vout == UInt32(vout)
            }) {
                // Re-applied block or pending change confirming.
                records[recordIndex].allUtxos[existing].height = height
            } else {
                records[recordIndex].allUtxos.append(WalletUTXO(
                    txid: txid, vout: UInt32(vout), amount: output.value,
                    scriptPubKey: output.scriptPubKey,
                    chain: AddressChain(rawValue: choice) ?? .receive,
                    index: index, height: height, isCoinbase: isCoinbase))
            }
            changed = true
            if choice == AddressChain.receive.rawValue, index >= records[recordIndex].nextReceiveIndex {
                records[recordIndex].nextReceiveIndex = index + 1
            }
            if choice == AddressChain.change.rawValue, index >= records[recordIndex].nextChangeIndex {
                records[recordIndex].nextChangeIndex = index + 1
            }
        }
        return changed
    }

    /// Marks the next receive index used ("New address" in the UI).
    func advanceReceiveIndex(id: String) throws {
        guard let index = records.firstIndex(where: { $0.id == id }) else { return }
        guard records[index].nextReceiveIndex < Self.maximumNextIndex else {
            throw VaultStorageError.invalidState("receive address index is out of range")
        }
        let oldRecords = records
        records[index].nextReceiveIndex += 1
        do {
            try persist()
        } catch {
            records = oldRecords
            throw error
        }
    }

    /// After a vault spend is broadcast: the selected inputs leave the set at
    /// once and the change output enters it pending (height 0) until its block
    /// match confirms it — the same rule `Wallet.send` applies locally.
    /// Returns false when the same spend was already recorded. This makes a
    /// repeated relay or resumed UI action harmless to local index state.
    @discardableResult
    func recordSpend(id: String, transaction: Transaction, changeScriptPubKey: Data?,
                     changeIndex: UInt32) throws -> Bool {
        guard let index = records.firstIndex(where: { $0.id == id }) else { return false }
        let vault = try Vault(records[index].descriptor, network: network)
        if let changeScriptPubKey {
            guard changeIndex <= Self.maximumNextIndex,
                  try vault.scriptPubKey(index: changeIndex, choice: AddressChain.change.rawValue)
                    == changeScriptPubKey
            else {
                throw VaultStorageError.invalidState("vault change output does not belong to this vault")
            }
            let matches = transaction.outputs.enumerated().filter {
                $0.element.scriptPubKey == changeScriptPubKey
            }
            guard matches.count == 1,
                  matches[0].offset <= Int(UInt32.max),
                  matches[0].element.value > 0,
                  matches[0].element.value <= BitcoinAmount.maximum
            else {
                throw VaultStorageError.invalidState("vault change output is missing or invalid")
            }
        }
        let spendsKnownInput = transaction.inputs.contains { input in
            records[index].utxos.contains {
                $0.txid == input.previousOutput.txid && $0.vout == input.previousOutput.vout
            }
        }
        guard spendsKnownInput else { return false }
        let oldRecords = records
        do {
            return try recordValidatedSpend(
                recordIndex: index, transaction: transaction,
                changeScriptPubKey: changeScriptPubKey, changeIndex: changeIndex)
        } catch {
            records = oldRecords
            throw error
        }
    }

    private func recordValidatedSpend(recordIndex index: Int, transaction: Transaction,
                                      changeScriptPubKey: Data?, changeIndex: UInt32) throws -> Bool {
        let txid = transaction.txid
        for input in transaction.inputs {
            // No height: this spend exists only in the transaction we just
            // signed. A rollback must leave these reserved while it restores
            // confirmed spends, or the vault re-selects coins its own
            // in-flight transaction already spends.
            for position in records[index].allUtxos.indices
            where !records[index].allUtxos[position].isSpent
                && records[index].allUtxos[position].txid == input.previousOutput.txid
                && records[index].allUtxos[position].vout == input.previousOutput.vout {
                records[index].allUtxos[position].spent =
                    WalletUTXO.SpentMarker(spentBy: txid, height: nil)
            }
        }
        if let changeScriptPubKey,
           let vout = transaction.outputs.firstIndex(where: { $0.scriptPubKey == changeScriptPubKey }) {
            let output = transaction.outputs[vout]
            records[index].allUtxos.append(WalletUTXO(
                txid: txid, vout: UInt32(vout), amount: output.value,
                scriptPubKey: changeScriptPubKey, chain: .change,
                index: changeIndex, height: 0))
            records[index].nextChangeIndex = changeIndex + 1
        }
        try Self.validate(records, network: network)
        try persist()
        return true
    }

    /// Indices 0 ..< max(used receive, used change, 1) + 2 of lookahead.
    private func watchCount(for record: VaultRecord) -> UInt32 {
        max(record.nextReceiveIndex, record.nextChangeIndex, 1) + 2
    }

    private static let damagedStorageMessage =
        "Winnow found local vault data but could not safely read it. The file and protected keys were left untouched. Retry; if this continues, restore from a known-good wallet bundle or ask for help before changing anything."

    private static let unverifiedStorageMessage =
        "Winnow found shared-account data it could not verify: the file was not written by Winnow on this device, or its protected key is gone. The file and protected keys were left untouched. Restore your shared accounts from a known-good wallet bundle, or ask for help before changing anything."

    private static func damagedStorageMessage(for error: any Error) -> String {
        error is SealedStoreFile.Failure ? unverifiedStorageMessage : damagedStorageMessage
    }

    static func validate(_ records: [VaultRecord], network: BitcoinNetwork) throws {
        var recordIDs = Set<String>()
        var outpoints = Set<Transaction.Outpoint>()
        var aggregate: Int64 = 0
        for record in records {
            guard recordIDs.insert(record.id).inserted else {
                throw VaultStorageError.invalidState("duplicate vault identifier")
            }
            let vault = try validatedRecordShape(record, network: network)
            try validateRecordCoins(record, vault: vault,
                                    outpoints: &outpoints, aggregate: &aggregate)
        }
    }

    /// The record's own shape: a canonical descriptor whose checksum is the
    /// record's identity, derivable at both chains, with indices in range.
    private static func validatedRecordShape(_ record: VaultRecord,
                                             network: BitcoinNetwork) throws -> Vault {
        guard DisplayName.normalized(record.name) == record.name else {
            throw VaultStorageError.invalidState("a vault has no usable name")
        }
        let descriptor = try Descriptor(record.descriptor)
        let canonical = descriptor.serialized()
        guard canonical == record.descriptor,
              canonical.split(separator: "#").last.map(String.init) == record.id
        else {
            throw VaultStorageError.invalidState("vault descriptor identifier does not match")
        }
        let vault = try Vault(descriptor: descriptor, network: network)
        _ = try vault.scriptPubKey(index: 0, choice: AddressChain.receive.rawValue)
        _ = try vault.scriptPubKey(index: 0, choice: AddressChain.change.rawValue)
        guard record.nextReceiveIndex <= maximumNextIndex,
              record.nextChangeIndex <= maximumNextIndex
        else {
            throw VaultStorageError.invalidState("vault address index is out of range")
        }
        return vault
    }

    /// Every persisted coin re-derived and bounded: it must belong to this
    /// descriptor below the record's own cursor, repeat no outpoint across
    /// the whole store, and keep the aggregate inside Bitcoin's range.
    private static func validateRecordCoins(_ record: VaultRecord, vault: Vault,
                                            outpoints: inout Set<Transaction.Outpoint>,
                                            aggregate: inout Int64) throws {
        for utxo in record.allUtxos {
            guard utxo.txid.count == 32,
                  utxo.amount > 0, utxo.amount <= BitcoinAmount.maximum,
                  utxo.spent.map({ $0.spentBy.count == 32 }) ?? true,
                  utxo.index < maximumWatchCount
            else {
                throw VaultStorageError.invalidState("vault output metadata is invalid")
            }
            let nextIndex = utxo.chain == .receive
                ? record.nextReceiveIndex : record.nextChangeIndex
            guard utxo.index < nextIndex,
                  try vault.scriptPubKey(index: utxo.index, choice: utxo.chain.rawValue)
                    == utxo.scriptPubKey
            else {
                throw VaultStorageError.invalidState("vault output does not belong to its descriptor")
            }
            guard outpoints.insert(utxo.outpoint).inserted else {
                throw VaultStorageError.invalidState("duplicate vault output")
            }
            // Spent rows can return after a reorg, so validate their ownership
            // too, but only live coins contribute to the balance ceiling.
            if utxo.isSpent { continue }
            let sum = aggregate.addingReportingOverflow(utxo.amount)
            guard !sum.overflow, sum.partialValue <= BitcoinAmount.maximum else {
                throw VaultStorageError.invalidState("vault balance is outside Bitcoin's monetary range")
            }
            aggregate = sum.partialValue
        }
    }

    /// Rewinds vault coins to a fork height, matching `Wallet.rollBack`.
    ///
    /// The same operation, for the same reason, and with the same exemption:
    /// a spend with no height is a vault transaction still in flight, so its
    /// inputs stay reserved rather than being handed back to coin selection.
    ///
    /// `createdAtHeight` and the address indices are untouched -- a reorg must
    /// not cost a vault its address gap any more than it costs the wallet one.
    func rollBack(to forkHeight: UInt32) throws {
        var candidate = records
        for index in candidate.indices {
            candidate[index].allUtxos.removeAll { $0.height > forkHeight }
            for position in candidate[index].allUtxos.indices {
                guard let height = candidate[index].allUtxos[position].spent?.height,
                      height > forkHeight
                else { continue }
                candidate[index].allUtxos[position].spent = nil
            }
        }
        guard candidate != records else { return }
        let previous = records
        records = candidate
        do {
            try persist()
        } catch {
            records = previous
            throw error
        }
    }

    private func persist() throws {
        guard let storageURL else { return }
        let data = try JSONEncoder().encode(records)
        try seal.write(data, network: network, to: storageURL, using: writeData)
    }
}
