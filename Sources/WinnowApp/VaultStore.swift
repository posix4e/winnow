import BitcoinCore
import BitcoinP2P
import Foundation
import WalletCore

/// Disambiguates the wire-format transaction from `SwiftUI.Transaction` in
/// app files that import both SwiftUI and BitcoinP2P (the module name also
/// collides with the `BitcoinP2P` enum, so module qualification is no help).
typealias BitcoinTransaction = Transaction

/// A created vault as persisted by the app (JSON at `vaults.json`). Signing
/// secrets never live here — vault spends load the wallet's master key from
/// the KeyStore for the duration of the signing call, like `Wallet` does.
struct VaultRecord: Codable, Equatable, Identifiable, Sendable {
    /// The descriptor checksum — stable and unique per descriptor.
    var id: String
    var name: String
    var descriptor: String
    /// Filter-scan height when the vault was added; funds sent earlier than
    /// this are not discovered (forward-only scanning, docs/read-side.md).
    var createdAtHeight: UInt32
    var nextReceiveIndex: UInt32 = 0
    var nextChangeIndex: UInt32 = 0
    /// Every vault coin row, spent ones included. Mutations go through this;
    /// reads should use `utxos`, which hides the tombstones.
    var allUtxos: [WalletUTXO] = []

    /// The coins this vault actually has.
    ///
    /// Computed rather than stored so a spent row cannot reach the balance,
    /// the spend screen, or `createSpend` by anyone forgetting to filter --
    /// `VaultDetailView` passes this straight into coin selection (#127).
    var utxos: [WalletUTXO] { allUtxos.filter { !$0.isSpent } }

    var balance: Int64 { utxos.reduce(0) { $0 + $1.amount } }

    /// The stored property is `allUtxos` while the on-disk key stays `utxos`,
    /// so a vaults.json written before #127 loads unchanged.
    private enum CodingKeys: String, CodingKey {
        case id, name, descriptor, createdAtHeight, nextReceiveIndex, nextChangeIndex
        case allUtxos = "utxos"
    }
}

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

    init(writeData: @escaping @Sendable (Data, URL) throws -> Void = { data, url in
        try data.write(to: url, options: .atomic)
    }) {
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
            let data = try Data(contentsOf: storageURL)
            let decoded = try JSONDecoder().decode([VaultRecord].self, from: data)
            try Self.validate(decoded, network: network)
            records = decoded
            return .loaded
        } catch {
            records = []
            return .damaged(Self.damagedStorageMessage)
        }
    }

    var all: [VaultRecord] { records }

    func record(id: String) -> VaultRecord? {
        records.first { $0.id == id }
    }

    @discardableResult
    func add(name: String, descriptor: Descriptor, createdAtHeight: UInt32) throws -> VaultRecord {
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
            let vault = try Vault(records[recordIndex].descriptor, network: network)
            var owner: [Data: (choice: Int, index: UInt32)] = [:]
            for index in 0 ..< watchCount(for: records[recordIndex]) {
                for choice in 0 ..< 2 {
                    owner[try vault.scriptPubKey(index: index, choice: choice)] = (choice, index)
                }
            }
            for tx in match.block.transactions {
                let txid = tx.txid
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
                            WalletUTXO.SpentMarker(spentBy: txid, height: match.height)
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
                            WalletUTXO.SpentMarker(spentBy: txid, height: match.height)
                        changed = true
                    }
                }
                for (vout, output) in tx.outputs.enumerated() {
                    guard let (choice, index) = owner[output.scriptPubKey] else { continue }
                    guard vout <= Int(UInt32.max) else {
                        throw VaultStorageError.invalidState("transaction output index is out of range")
                    }
                    if let existing = records[recordIndex].allUtxos.firstIndex(where: {
                        $0.txid == txid && $0.vout == UInt32(vout)
                    }) {
                        // Re-applied block or pending change confirming.
                        records[recordIndex].allUtxos[existing].height = match.height
                    } else {
                        records[recordIndex].allUtxos.append(WalletUTXO(
                            txid: txid, vout: UInt32(vout), amount: output.value,
                            scriptPubKey: output.scriptPubKey,
                            chain: AddressChain(rawValue: choice) ?? .receive,
                            index: index, height: match.height))
                    }
                    changed = true
                    if choice == AddressChain.receive.rawValue, index >= records[recordIndex].nextReceiveIndex {
                        records[recordIndex].nextReceiveIndex = index + 1
                    }
                    if choice == AddressChain.change.rawValue, index >= records[recordIndex].nextChangeIndex {
                        records[recordIndex].nextChangeIndex = index + 1
                    }
                }
            }
        }
        if changed {
            try Self.validate(records, network: network)
            try persist()
        }
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

    private static func validate(_ records: [VaultRecord], network: BitcoinNetwork) throws {
        var recordIDs = Set<String>()
        var outpoints = Set<Transaction.Outpoint>()
        var aggregate: Int64 = 0

        for record in records {
            guard recordIDs.insert(record.id).inserted else {
                throw VaultStorageError.invalidState("duplicate vault identifier")
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

            for utxo in record.utxos {
                guard utxo.txid.count == 32,
                      utxo.amount > 0, utxo.amount <= BitcoinAmount.maximum,
                      utxo.silentPaymentTweak == nil,
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
                let sum = aggregate.addingReportingOverflow(utxo.amount)
                guard !sum.overflow, sum.partialValue <= BitcoinAmount.maximum else {
                    throw VaultStorageError.invalidState("vault balance is outside Bitcoin's monetary range")
                }
                aggregate = sum.partialValue
            }
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
        try writeData(data, storageURL)
    }
}
