import WalletCore
import Foundation

enum MultisigStorageOpenResult: Equatable, Sendable {
    case missing
    case loaded
    case damaged(String)
}

enum MultisigStorageError: Error, Equatable, LocalizedError {
    case invalidState(String)
    case damaged
    case duplicate
    case tooMany

    var errorDescription: String? {
        switch self {
        case let .invalidState(reason):
            "Invalid multisig storage: \(reason)"
        case .damaged:
            "Winnow could not safely read its multisig accounts, so they cannot be changed until the file is readable again."
        case .duplicate:
            "This multisig account is already on this phone."
        case .tooMany:
            "Winnow keeps at most \(MultisigStore.maximumAccounts) multisig accounts."
        }
    }
}

/// App-side multisig bookkeeping: the persisted account records plus the coin
/// tracking `Wallet` performs for the wallet itself, fed by the same combined
/// filter scan (an account is just more watched scripts). One sealed JSON
/// file per wallet, `multisig.json`, cleared with the other per-wallet files.
/// Damage is reported, the file left untouched and every mutation refused
/// until it reads again; the wallet itself carries on.
actor MultisigStore {
    static let maximumAccounts = 100
    /// Prevents a forged persisted index from turning startup into billions of
    /// child-key derivations: a record watches at most this many indices
    /// plus `Wallet.gapLimit`.
    static let maximumNextIndex: UInt32 = 10_000 - 2
    /// A hundred accounts with ten thousand coins each is far under this.
    static let maximumFileBytes = 16 * 1_024 * 1_024

    typealias OwnerMap = [Data: (choice: Int, index: UInt32)]

    private var records: [MultisigAccountRecord] = []
    private var storageURL: URL?
    private var network: BitcoinNetwork = .signet
    private var isDamaged = false
    /// Each record's owner map, kept until its descriptor or watch count
    /// changes: every matched block asks for it, and each entry costs a
    /// derivation per signer plus a taproot tweak.
    private var ownerMaps: [String: (descriptor: String, watchCount: UInt32, owner: OwnerMap)] = [:]
    private let writeData: @Sendable (Data, URL) throws -> Void
    /// Reads verify and writes seal, under a key the app container cannot
    /// reach. `validate` catches a harmful shape; only the seal catches a
    /// well-formed descriptor substituted by someone else, which would
    /// otherwise make this phone show and sign for an account it never added.
    private let seal: StoreSeal

    init(keys: any StoreKeyVault, writeData: @escaping @Sendable (Data, URL) throws -> Void = { data, url in
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }) {
        seal = StoreSeal(store: "multisig", keys: keys)
        self.writeData = writeData
    }

    /// Points the store at its JSON file, loading any existing records.
    @discardableResult
    func configure(storageURL: URL?, network: BitcoinNetwork) -> MultisigStorageOpenResult {
        self.storageURL = storageURL
        self.network = network
        isDamaged = false
        records = []
        ownerMaps = [:]
        guard let storageURL, FileManager.default.fileExists(atPath: storageURL.path) else { return .missing }
        do {
            let file = try seal.read(try Self.boundedRead(storageURL), network: network)
            // No Winnow wrote this file before sealing existed, so an
            // unsealed one was put here by something else.
            guard !file.predatesSealing else { throw SealedStoreFile.Failure.unsealed }
            let decoded = try JSONDecoder().decode([MultisigAccountRecord].self, from: file.payload)
            try Self.validate(decoded, network: network)
            records = decoded
            return .loaded
        } catch {
            isDamaged = true
            return .damaged(error is SealedStoreFile.Failure ? Self.unverifiedStorageMessage : Self.damagedStorageMessage)
        }
    }

    var all: [MultisigAccountRecord] { records }

    func record(id: String) -> MultisigAccountRecord? {
        records.first { $0.id == id }
    }

    /// The records for a wallet bundle. A pending coin or an in-flight spend
    /// would restore as settled, so a backup waits for confirmation.
    func backupRecords() throws -> [MultisigAccountRecord] {
        guard !isDamaged else { throw MultisigStorageError.damaged }
        guard !records.contains(where: { record in
            record.allUtxos.contains { $0.height == 0 || ($0.spent != nil && $0.spent?.height == nil) }
        }) else {
            throw WalletError.invalidBundle("Wait for multisig account payments to confirm before saving a backup.")
        }
        return records
    }

    /// Replaces the records with a restored bundle's. A record holds no
    /// signatures, so nothing in flight survives a restore.
    func restore(_ restored: [MultisigAccountRecord]) throws {
        guard !isDamaged else { throw MultisigStorageError.damaged }
        try Self.validate(restored, network: network)
        try mutate { $0 = restored }
    }

    @discardableResult
    func add(name: String, account: MultisigAccount, createdAtHeight: UInt32) throws -> MultisigAccountRecord {
        guard !isDamaged else { throw MultisigStorageError.damaged }
        guard DisplayName.normalized(name) == name, !name.isEmpty else {
            throw MultisigStorageError.invalidState("an account needs a short, single-line name")
        }
        guard account.network == network else {
            throw MultisigStorageError.invalidState("the account's network does not match the open wallet")
        }
        guard !records.contains(where: { $0.id == account.id }) else { throw MultisigStorageError.duplicate }
        guard records.count < Self.maximumAccounts else { throw MultisigStorageError.tooMany }
        let record = MultisigAccountRecord(id: account.id, name: name, descriptor: account.descriptor.serialized(),
                                         createdAtHeight: createdAtHeight)
        try mutate { $0.append(record) }
        return record
    }

    func remove(id: String) throws {
        guard !isDamaged else { throw MultisigStorageError.damaged }
        try mutate { $0.removeAll { $0.id == id } }
        ownerMaps[id] = nil
    }

    /// Receive and change scripts of every account, for the combined scan.
    func watchScripts(network: BitcoinNetwork) throws -> [Data] {
        guard network == self.network else {
            throw MultisigStorageError.invalidState("the account network does not match the open wallet")
        }
        return try records.flatMap { record in
            try MultisigAccount(record.descriptor, network: network).watchScripts(upTo: Self.watchCount(for: record))
        }
    }

    /// Consumes one matched block like `Wallet.apply`: payments to account
    /// scripts become coins (advancing the address frontiers), spends turn
    /// coins into tombstones. Returns the in-flight spends a conflicting
    /// transaction in this block beat, which can never confirm, so the
    /// broadcaster stops relaying them.
    @discardableResult
    func apply(match: BlockMatch, network: BitcoinNetwork) throws -> [Data] {
        guard network == self.network else {
            throw MultisigStorageError.invalidState("the account network does not match the open wallet")
        }
        // A damaged store has no records, so nothing here can write over it.
        var candidate = records
        var changed = false
        var discarded: [Data] = []
        for recordIndex in candidate.indices {
            let owner = try ownerMap(for: candidate[recordIndex])
            for (txIndex, tx) in match.block.transactions.enumerated() {
                let txid = tx.txid
                if Self.applySpends(of: tx, txid: txid, height: match.height, to: &candidate[recordIndex],
                                    discarded: &discarded) {
                    changed = true
                }
                // A block's first transaction is its coinbase, and a coinbase
                // coin is unspendable for `Wallet.coinbaseMaturity` blocks,
                // which the spend review checks.
                if try Self.applyOutputs(of: tx, txid: txid, owner: owner, height: match.height,
                                         isCoinbase: txIndex == 0, to: &candidate[recordIndex]) {
                    changed = true
                }
            }
        }
        guard changed else { return [] }
        try Self.validate(candidate, network: network)
        try mutate { $0 = candidate }
        return discarded
    }

    /// script → (choice, index) for every address the record watches, from
    /// the cache while the record's descriptor and watch count are the ones
    /// it was built for.
    private func ownerMap(for record: MultisigAccountRecord) throws -> OwnerMap {
        let watchCount = Self.watchCount(for: record)
        if let cached = ownerMaps[record.id], cached.descriptor == record.descriptor,
           cached.watchCount == watchCount {
            return cached.owner
        }
        let account = try MultisigAccount(record.descriptor, network: network)
        var owner: OwnerMap = [:]
        for index in 0 ..< watchCount {
            for choice in 0 ..< 2 {
                owner[try account.scriptPubKey(index: index, choice: choice)] = (choice, index)
            }
        }
        ownerMaps[record.id] = (record.descriptor, watchCount, owner)
        return owner
    }

    /// Tombstones the record's coins this transaction spends, and learns the
    /// height of tombstones written while the spend was only in flight. A
    /// tombstone naming another transaction means that in-flight spend lost
    /// the race for the coin, so it is undone and added to `discarded`.
    private static func applySpends(of tx: Transaction, txid: Data, height: UInt32,
                                    to record: inout MultisigAccountRecord, discarded: inout [Data]) -> Bool {
        var changed = false
        var losers: [Data] = []
        for input in tx.inputs {
            let outpoint = input.previousOutput
            if let live = record.allUtxos.firstIndex(where: { !$0.isSpent && $0.outpoint == outpoint }) {
                // Marked, not removed, so a reorg can put it back.
                record.allUtxos[live].spent = WalletUTXO.SpentMarker(spentBy: txid, height: height)
                changed = true
            } else if let pending = record.allUtxos.firstIndex(where: {
                $0.spent != nil && $0.spent?.height == nil && $0.outpoint == outpoint
            }) {
                // Tombstoned when a spend was broadcast, or put back in
                // flight by a rollback, now confirmed: the only moment its
                // height can be learned. Confirmed by another transaction
                // (another signer's spend, or a replacement), the spend it
                // named can never confirm.
                if let loser = record.allUtxos[pending].spent?.spentBy, loser != txid {
                    losers.append(loser)
                }
                record.allUtxos[pending].spent = WalletUTXO.SpentMarker(spentBy: txid, height: height)
                changed = true
            }
        }
        // After every input, so a coin both spends took stays the winner's.
        discarded += dropLosingSpends(losers, from: &record)
        return changed
    }

    /// Undoes in-flight spends a confirmed conflict beat, as
    /// `Wallet.reconcilePendingConflict` does: their pending outputs are
    /// removed, not tombstoned, since no rescan would find them again; the
    /// inputs the winner did not take are released; and an in-flight spend
    /// of one of those outputs loses with them. Returns every spend undone.
    private static func dropLosingSpends(_ losers: [Data], from record: inout MultisigAccountRecord) -> [Data] {
        var queue = losers
        var dropped: [Data] = []
        while !queue.isEmpty {
            let loser = queue.removeFirst()
            guard !dropped.contains(loser) else { continue }
            dropped.append(loser)
            let neverExisted = { (utxo: WalletUTXO) in utxo.txid == loser && utxo.height == 0 }
            queue += record.allUtxos.filter(neverExisted).compactMap { utxo in
                utxo.spent.flatMap { $0.height == nil ? $0.spentBy : nil }
            }
            record.allUtxos.removeAll(where: neverExisted)
            let reservation = WalletUTXO.SpentMarker(spentBy: loser, height: nil)
            for position in record.allUtxos.indices where record.allUtxos[position].spent == reservation {
                record.allUtxos[position].spent = nil
            }
        }
        return dropped
    }

    /// Admits every watched output as a coin (or re-heights one already
    /// known) and advances the address frontiers.
    private static func applyOutputs(of tx: Transaction, txid: Data, owner: OwnerMap,
                                     height: UInt32, isCoinbase: Bool,
                                     to record: inout MultisigAccountRecord) throws -> Bool {
        var changed = false
        for (vout, output) in tx.outputs.enumerated() {
            // Zero-value outputs are consensus-valid and anyone who knows an
            // account address can send one. They are not coins: admitting one
            // fails `validate`, and the scan would retry this block forever.
            guard output.value > 0, let (choice, index) = owner[output.scriptPubKey] else { continue }
            guard vout <= Int(UInt32.max) else {
                throw MultisigStorageError.invalidState("transaction output index is out of range")
            }
            if let existing = record.allUtxos.firstIndex(where: { $0.txid == txid && $0.vout == UInt32(vout) }) {
                // A re-applied block, our own pending change confirming, or
                // a coin a rollback kept for a spend in flight.
                record.allUtxos[existing].height = height
            } else {
                record.allUtxos.append(WalletUTXO(
                    txid: txid, vout: UInt32(vout), amount: output.value, scriptPubKey: output.scriptPubKey,
                    chain: AddressChain(rawValue: choice) ?? .receive, index: index, height: height,
                    isCoinbase: isCoinbase))
            }
            changed = true
            if choice == AddressChain.receive.rawValue, index >= record.nextReceiveIndex {
                record.nextReceiveIndex = index + 1
            }
            if choice == AddressChain.change.rawValue, index >= record.nextChangeIndex {
                record.nextChangeIndex = index + 1
            }
        }
        return changed
    }

    /// Marks the next receive address used ("New address").
    func advanceReceiveIndex(id: String) throws {
        guard !isDamaged else { throw MultisigStorageError.damaged }
        guard let index = records.firstIndex(where: { $0.id == id }) else { return }
        guard records[index].nextReceiveIndex < Self.maximumNextIndex else {
            throw MultisigStorageError.invalidState("receive address index is out of range")
        }
        try mutate { $0[index].nextReceiveIndex += 1 }
    }

    /// After a spend is broadcast: its inputs become in-flight tombstones at
    /// once and the change output enters pending (height 0) until its block
    /// confirms it, the rule `Wallet.send` applies to the wallet's own coins.
    /// Returns false when the spend touches no live coin of the account, so a
    /// repeated relay or a resumed screen is harmless.
    @discardableResult
    func recordSpend(id: String, transaction: Transaction, changeIndex: UInt32?) throws -> Bool {
        guard !isDamaged else { throw MultisigStorageError.damaged }
        guard let index = records.firstIndex(where: { $0.id == id }) else { return false }
        var record = records[index]
        let account = try MultisigAccount(record.descriptor, network: network)
        let txid = transaction.txid
        var touched = false
        for input in transaction.inputs {
            for position in record.allUtxos.indices
            where !record.allUtxos[position].isSpent && record.allUtxos[position].outpoint == input.previousOutput {
                // No height: this spend exists only in the transaction just
                // broadcast. A rollback must keep these reserved.
                record.allUtxos[position].spent = WalletUTXO.SpentMarker(spentBy: txid, height: nil)
                touched = true
            }
        }
        guard touched else { return false }
        if let changeIndex {
            record.allUtxos.append(try Self.pendingChange(of: transaction, account: account, changeIndex: changeIndex))
            record.nextChangeIndex = max(record.nextChangeIndex, changeIndex + 1)
        }
        var candidate = records
        candidate[index] = record
        try Self.validate(candidate, network: network)
        try mutate { $0 = candidate }
        return true
    }

    /// The spend's one output to the account's change address at
    /// `changeIndex`, as a pending coin.
    private static func pendingChange(of transaction: Transaction, account: MultisigAccount,
                                      changeIndex: UInt32) throws -> WalletUTXO {
        guard changeIndex <= maximumNextIndex else {
            throw MultisigStorageError.invalidState("change address index is out of range")
        }
        let changeScript = try account.scriptPubKey(index: changeIndex, choice: AddressChain.change.rawValue)
        let matches = transaction.outputs.enumerated().filter { $0.element.scriptPubKey == changeScript }
        guard matches.count == 1, matches[0].element.value > 0,
              matches[0].element.value <= BitcoinAmount.maximum else {
            throw MultisigStorageError.invalidState("the change output is missing or invalid")
        }
        return WalletUTXO(txid: transaction.txid, vout: UInt32(matches[0].offset), amount: matches[0].element.value,
                          scriptPubKey: changeScript, chain: .change, index: changeIndex, height: 0)
    }

    /// Rewinds coins to a fork height, matching `Wallet.rollBack`: spends
    /// from fallen blocks go back in flight, and coins from fallen blocks
    /// leave unless a spend holds them. Like the wallet's, a pure function of
    /// the fork height, so a repeat changes nothing. Address frontiers are
    /// untouched.
    func rollBack(to forkHeight: UInt32) throws {
        var candidate = records
        for index in candidate.indices {
            Self.rependSpends(above: forkHeight, in: &candidate[index].allUtxos)
            Self.rewindCoins(above: forkHeight, in: &candidate[index].allUtxos)
        }
        guard candidate != records else { return }
        try mutate { $0 = candidate }
    }

    /// A spend whose block fell is back in every mempool that saw it, so its
    /// inputs stay reserved for it, as `Wallet.rollBack` keeps the wallet's
    /// (#157). Released, they would go into a new spend the network rejects.
    /// `applySpends` heights the reservation again when the spend confirms,
    /// and undoes the spend when a conflict confirms instead.
    private static func rependSpends(above forkHeight: UInt32, in coins: inout [WalletUTXO]) {
        for position in coins.indices {
            guard let marker = coins[position].spent, let height = marker.height, height > forkHeight
            else { continue }
            coins[position].spent = WalletUTXO.SpentMarker(spentBy: marker.spentBy, height: nil)
        }
    }

    /// Coins confirmed above the fork leave, since the rescan re-finds
    /// whichever still exist. That includes a fallen spend's change, as the
    /// wallet drops its own: kept at height 0, it would be offered to a new
    /// spend chained on a parent that is in no block, which a conflict on the
    /// new branch can beat and which this phone may not be relaying at all
    /// (another signer's spend). A coin a spend holds stays, at height 0, as
    /// the wallet keeps it. Dropped, the rescan would admit it again unspent
    /// while that spend is in flight, and `applyOutputs` re-heights it instead.
    private static func rewindCoins(above forkHeight: UInt32, in coins: inout [WalletUTXO]) {
        coins.removeAll { coin in
            let reserved = coin.spent != nil && coin.spent?.height == nil
            return coin.height > forkHeight && !reserved
        }
        for position in coins.indices where coins[position].height > forkHeight {
            coins[position].height = 0
        }
    }

    // MARK: - Validation and persistence

    /// Indices 0 ..< max(used receive, used change) + `Wallet.gapLimit` on
    /// both chains: the wallet's own lookahead. Every signer's phone hands
    /// out addresses, so a payment can land that far past this phone's
    /// frontier, and `AppModel` counts these scripts as the account's.
    static func watchCount(for record: MultisigAccountRecord) -> UInt32 {
        max(record.nextReceiveIndex, record.nextChangeIndex) + Wallet.gapLimit
    }

    /// Every record re-derived: a canonical descriptor whose checksum is the
    /// record's id, a supported account shape on this network, indices in
    /// range, and coins that belong to the descriptor below its frontiers,
    /// with no outpoint twice and the live total inside Bitcoin's range.
    static func validate(_ records: [MultisigAccountRecord], network: BitcoinNetwork) throws {
        guard records.count <= maximumAccounts else { throw MultisigStorageError.tooMany }
        var ids = Set<String>()
        var outpoints = Set<Transaction.Outpoint>()
        var total: Int64 = 0
        for record in records {
            guard ids.insert(record.id).inserted else {
                throw MultisigStorageError.invalidState("duplicate account identifier")
            }
            let account = try validatedShape(record, network: network)
            for utxo in record.allUtxos {
                try validate(utxo, of: record, account: account, outpoints: &outpoints, total: &total)
            }
        }
    }

    /// A usable name, a canonical descriptor whose checksum is the record's
    /// id, a supported account on this network, and indices in range.
    private static func validatedShape(_ record: MultisigAccountRecord, network: BitcoinNetwork) throws -> MultisigAccount {
        guard DisplayName.normalized(record.name) == record.name, !record.name.isEmpty else {
            throw MultisigStorageError.invalidState("an account has no usable name")
        }
        let account = try MultisigAccount(record.descriptor, network: network)
        guard account.descriptor.serialized() == record.descriptor, account.id == record.id else {
            throw MultisigStorageError.invalidState("account descriptor identifier does not match")
        }
        guard record.nextReceiveIndex <= maximumNextIndex, record.nextChangeIndex <= maximumNextIndex else {
            throw MultisigStorageError.invalidState("account address index is out of range")
        }
        return account
    }

    /// One coin re-derived below its frontier, never repeated across the
    /// store, with the live total kept inside Bitcoin's range.
    private static func validate(_ utxo: WalletUTXO, of record: MultisigAccountRecord, account: MultisigAccount,
                                 outpoints: inout Set<Transaction.Outpoint>, total: inout Int64) throws {
        guard utxo.txid.count == 32, utxo.amount > 0, utxo.amount <= BitcoinAmount.maximum,
              utxo.spent.map({ $0.spentBy.count == 32 }) ?? true else {
            throw MultisigStorageError.invalidState("account coin metadata is invalid")
        }
        let frontier = utxo.chain == .receive ? record.nextReceiveIndex : record.nextChangeIndex
        guard utxo.index < frontier,
              try account.scriptPubKey(index: utxo.index, choice: utxo.chain.rawValue) == utxo.scriptPubKey else {
            throw MultisigStorageError.invalidState("an account coin does not belong to its descriptor")
        }
        guard outpoints.insert(utxo.outpoint).inserted else {
            throw MultisigStorageError.invalidState("duplicate account coin")
        }
        // Spent rows can return after a reorg, so their ownership is checked
        // too; only live coins count toward the ceiling.
        guard !utxo.isSpent else { return }
        let (sum, overflow) = total.addingReportingOverflow(utxo.amount)
        guard !overflow, sum <= BitcoinAmount.maximum else {
            throw MultisigStorageError.invalidState("account balance is outside Bitcoin's monetary range")
        }
        total = sum
    }

    /// Measures before reading, so a planted file is refused rather than held.
    static func boundedRead(_ url: URL) throws -> Data {
        let size = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int ?? Int.max
        guard size <= maximumFileBytes else { throw MultisigStorageError.invalidState("account file too large") }
        let data = try Data(contentsOf: url)
        guard data.count <= maximumFileBytes else { throw MultisigStorageError.invalidState("account file too large") }
        return data
    }

    /// Applies a change and persists it, restoring the previous records if
    /// the write fails.
    private func mutate(_ change: (inout [MultisigAccountRecord]) throws -> Void) throws {
        let previous = records
        do {
            try change(&records)
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

    private static let damagedStorageMessage =
        "Winnow found multisig account data but could not safely read it. The file and protected keys were left untouched. Retry; if this continues, restore from a known-good wallet bundle or ask for help before changing anything."

    private static let unverifiedStorageMessage =
        "Winnow found multisig account data it could not verify: the file was not written by Winnow on this device, or its protected key is gone. The file and protected keys were left untouched. Restore your multisig accounts from a known-good wallet bundle, or ask for help before changing anything."
}
