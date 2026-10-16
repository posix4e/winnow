import Foundation
import P256K
import Testing
import TestSupport
@testable import WalletCore

/// Import bundle (docs/read-side.md §2.7.5): parsing, seeding, and the verify
/// report — including the mismatch cases that must surface, never go silent.
@Suite("Import bundle")
struct ImportBundleTests {
    /// A bundle for the test mnemonic with two claimed UTXOs (receive 0,
    /// receive 1) as of height 500.
    private func makeBundle() async throws -> ImportBundle {
        let wallet = try makeTestWallet(creationHeight: 400)
        func utxoJSON(_ index: UInt32, _ amount: Int64) async throws -> ImportBundle.UTXO {
            try await ImportBundle.UTXO(txid: Data(repeating: UInt8(0x50 + index), count: 32).displayHex,
                                        vout: 0, amount: amount,
                                        scriptPubKey: wallet.scriptPubKey(chain: .receive, index: index).hex,
                                        chain: 0, index: index, height: 490)
        }
        return try await ImportBundle(network: "signet",
                                      descriptor: wallet.descriptor.serialized(),
                                      mnemonic: testMnemonic,
                                      lastKnownHeight: 500,
                                      utxos: [utxoJSON(0, 100_000), utxoJSON(1, 50_000)],
                                      transactions: [ImportBundle.KnownTransaction(
                                          txid: Data(repeating: 0x50, count: 32).displayHex,
                                          height: 490, received: 100_000, spent: 0)])
    }

    @Test("JSON round trip of the documented format")
    func json() throws {
        let json = """
        {
          "version": 1,
          "network": "signet",
          "mnemonic": "\(testMnemonic)",
          "lastKnownHeight": 500,
          "utxos": [{"txid": "\(Data(repeating: 0x51, count: 32).displayHex)", "vout": 0,
                     "amount": 100000, "scriptPubKey": "5120ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                     "chain": 0, "index": 0, "height": 490}],
          "transactions": []
        }
        """
        let bundle = try JSONDecoder().decode(ImportBundle.self, from: Data(json.utf8))
        #expect(bundle.version == 1)
        #expect(bundle.network == "signet")
        #expect(bundle.utxos.count == 1)
        #expect(try JSONDecoder().decode(ImportBundle.self,
                                         from: JSONEncoder().encode(bundle)) == bundle)
    }

    @Test("importing seeds the wallet state; scanning resumes after the bundle height")
    func seeding() async throws {
        let bundle = try await makeBundle()
        let keyStore = InMemoryKeyStore()
        let wallet = try Wallet.importing(bundle, keyStore: keyStore)
        let id = await wallet.id
        #expect(id == "73c5da0a")
        #expect(await wallet.balance == 150_000)
        #expect(await wallet.utxos.count == 2)
        #expect(await wallet.history.count == 1)
        #expect(await wallet.creationHeight == 500)
        #expect(await wallet.nextScanHeight == 501)
        #expect(await wallet.nextReceiveIndex == 2) // past the highest claimed index
        // The secret enables spending.
        #expect(try keyStore.load(walletID: "73c5da0a") == .mnemonic(testMnemonic))

        // V1 remains a supported read format for descriptor-derived funds.
        var legacy = bundle
        legacy.version = 1
        let legacyWallet = try Wallet.importing(legacy, keyStore: InMemoryKeyStore())
        #expect(await legacyWallet.balance == 150_000)
    }

    @Test("payment details survive backup, legacy history loads, and a mismatched transaction is rejected")
    func paymentDetails() async throws {
        var bundle = try await makeBundle()
        let payment = Transaction(version: 2, inputs: [Transaction.Input(
            previousOutput: Transaction.Outpoint(txid: Data(repeating: 1, count: 32), vout: 0), scriptSig: Data(), sequence: 0xffff_fffd)],
            outputs: [Transaction.Output(value: 1_000, scriptPubKey: Data([0x51]))], locktime: 0)
        bundle.transactions[0].txid = payment.txid.displayHex
        let wallet = try Wallet.importing(bundle, keyStore: InMemoryKeyStore())
        #expect(await wallet.history[0].rawTransaction == nil)
        let balance = await wallet.balance
        try await wallet.rememberTransaction(payment)
        #expect(await wallet.balance == balance)
        let receipt = await wallet.history[0]
        #expect(try receipt.transaction() == payment)
        #expect(try JSONDecoder().decode(HistoryEntry.self, from: JSONEncoder().encode(receipt)) == receipt)
        let exported = try await wallet.exportBundle(includeMnemonic: false)
        let restored = try Wallet.importing(exported, keyStore: InMemoryKeyStore())
        #expect(try await restored.history[0].transaction() == payment)
        bundle.transactions[0].rawTransaction = payment.serialized(includeWitness: false)
        bundle.transactions[0].txid = Data(repeating: 2, count: 32).displayHex
        #expect(throws: WalletError.self) { try Wallet.importing(bundle, keyStore: InMemoryKeyStore()) }
    }

    @Test("block hashes survive export and import, and a malformed or pending one is refused")
    func blockHashes() async throws {
        var bundle = try await makeBundle()
        let block = Data(repeating: 0x0B, count: 32)
        let frontier = Data(repeating: 0x0F, count: 32)
        bundle.transactions[0].blockHash = block.displayHex
        bundle.lastKnownBlockHash = frontier.displayHex

        let decoded = try JSONDecoder().decode(ImportBundle.self, from: Data(try bundle.serialized().utf8))
        #expect(decoded == bundle)
        let wallet = try Wallet.importing(decoded, keyStore: InMemoryKeyStore())
        #expect(await wallet.history[0].blockHash == block)
        #expect(await wallet.scannedThroughHash == frontier)
        let exported = try await wallet.exportBundle(includeMnemonic: false)
        #expect(exported.transactions[0].blockHash == block.displayHex)
        #expect(exported.lastKnownBlockHash == frontier.displayHex)

        var malformed = bundle
        malformed.transactions[0].blockHash = "not-a-block"
        #expect(throws: WalletError.invalidBundle("bad block hash not-a-block")) {
            _ = try Wallet.importing(malformed, keyStore: InMemoryKeyStore())
        }
        var pending = bundle
        pending.transactions[0].height = 0
        #expect(throws: WalletError.self) { _ = try Wallet.importing(pending, keyStore: InMemoryKeyStore()) }
        var pendingEntry = await wallet.history[0]
        pendingEntry.height = 0
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(HistoryEntry.self, from: JSONEncoder().encode(pendingEntry))
        }
    }

    @Test("fee-replacement history survives export and import")
    func replacementHistory() async throws {
        var bundle = try await makeBundle()
        let replacement = Data(repeating: 0x91, count: 32)
        bundle.transactions[0].replacedBy = replacement.displayHex

        let serialized = try bundle.serialized()
        let decoded = try JSONDecoder().decode(ImportBundle.self, from: Data(serialized.utf8))
        let restored = try Wallet.importing(decoded, keyStore: InMemoryKeyStore())
        #expect(await restored.history[0].replacedBy == replacement)

        bundle.transactions[0].replacedBy = "not-a-txid"
        #expect(throws: WalletError.invalidBundle("bad replacement txid not-a-txid")) {
            _ = try Wallet.importing(bundle, keyStore: InMemoryKeyStore())
        }
    }

    @Test("descriptor/mnemonic disagreement and bad claims are rejected")
    func rejection() async throws {
        let bundle = try await makeBundle()
        // A different mnemonic than the descriptor carries.
        var mismatched = bundle
        mismatched.mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"
        #expect(throws: WalletError.descriptorMismatch) {
            _ = try Wallet.importing(mismatched, keyStore: InMemoryKeyStore())
        }
        // A claimed scriptPubKey that isn't what the descriptor derives.
        var bogus = bundle
        bogus.utxos[0].scriptPubKey = "5120ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        #expect(throws: WalletError.self) { _ = try Wallet.importing(bogus, keyStore: InMemoryKeyStore()) }
        // Neither descriptor nor mnemonic.
        var empty = bundle
        empty.descriptor = nil
        empty.mnemonic = nil
        #expect(throws: WalletError.invalidBundle("need a descriptor or a mnemonic")) {
            _ = try Wallet.importing(empty, keyStore: InMemoryKeyStore())
        }
        // Unknown network / future version.
        var badNetwork = bundle
        badNetwork.network = " PlutoNet "
        #expect(throws: WalletError.self) { _ = try Wallet.importing(badNetwork, keyStore: InMemoryKeyStore()) }
        var future = bundle
        future.version = 99
        #expect(throws: WalletError.invalidBundle("unsupported version 99")) {
            _ = try Wallet.importing(future, keyStore: InMemoryKeyStore())
        }

        var invalidAmount = bundle
        invalidAmount.utxos[0].amount = Int64.max
        #expect(throws: WalletError.invalidBundle("invalid UTXO amount \(Int64.max)")) {
            _ = try Wallet.importing(invalidAmount, keyStore: InMemoryKeyStore())
        }
        var duplicate = bundle
        duplicate.utxos.append(duplicate.utxos[0])
        #expect(throws: WalletError.invalidBundle("duplicate UTXO outpoint")) {
            _ = try Wallet.importing(duplicate, keyStore: InMemoryKeyStore())
        }
        var invalidHistory = bundle
        invalidHistory.transactions[0].received = -1
        #expect(throws: WalletError.invalidBundle("transaction history has invalid amounts")) {
            _ = try Wallet.importing(invalidHistory, keyStore: InMemoryKeyStore())
        }
        // Bounds a hostile bundle used to be able to trap or spin the wallet
        // on: a height with no block after it, and a cursor past the window
        // the gap-limit lookahead can derive from.
        var heightAtTheTop = bundle
        heightAtTheTop.lastKnownHeight = UInt32.max
        #expect(throws: WalletError.invalidBundle("last known height \(UInt32.max) is out of range")) {
            _ = try Wallet.importing(heightAtTheTop, keyStore: InMemoryKeyStore())
        }
        var cursorPastTheWindow = bundle
        cursorPastTheWindow.nextReceiveIndex = UInt32.max
        #expect(throws: WalletError.invalidBundle("address cursors leave no room for the gap-limit window")) {
            _ = try Wallet.importing(cursorPastTheWindow, keyStore: InMemoryKeyStore())
        }
        var changeCursorPastTheWindow = bundle
        changeCursorPastTheWindow.nextChangeIndex = HDKey.hardenedOffset
        #expect(throws: WalletError.invalidBundle("address cursors leave no room for the gap-limit window")) {
            _ = try Wallet.importing(changeCursorPastTheWindow, keyStore: InMemoryKeyStore())
        }
    }

    @Test("verify report: confirmed, spent-since-bundle (mismatch), discovered")
    func report() async throws {
        let bundle = try await makeBundle()
        let keyStore = InMemoryKeyStore()
        let wallet = try Wallet.importing(bundle, keyStore: keyStore)
        let claimed = try bundle.claimedUTXOs()

        var effects: [MatchEffect] = []
        // Block 501: claimed UTXO 0 gets spent by someone else; a new payment
        // the bundle didn't know about arrives at receive index 2.
        let spendTx = Transaction(version: 2, inputs: [
            Transaction.Input(previousOutput: claimed[0].outpoint, scriptSig: Data(), sequence: 0xFFFF_FFFF),
        ], outputs: [Transaction.Output(value: 99_000,
                                        scriptPubKey: Data([0x51, 0x20] + repeatElement(0x77, count: 32)))],
        locktime: 0)
        let newScript = try await wallet.scriptPubKey(chain: .receive, index: 2)
        let incomingTx = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: 25_000, scriptPubKey: newScript),
        ], locktime: 0)
        let match = fakeMatch(height: 501, transactions: [spendTx, incomingTx])
        effects.append(try await wallet.apply(match: match))

        let report = try await ImportReport.make(bundle: bundle, effects: effects,
                                                 finalUTXOs: wallet.utxos,
                                                 scannedFromHeight: 501, scannedToHeight: 501)
        #expect(!report.matchesBundle)
        #expect(report.spentSinceBundle.count == 1)
        #expect(report.spentSinceBundle[0].txid == claimed[0].txid)
        #expect(report.spentSinceBundle[0].spentBy == spendTx.txid)
        #expect(report.spentSinceBundle[0].height == 501)
        #expect(report.confirmedUTXOs.map(\.txid) == [claimed[1].txid])
        #expect(report.discoveredUTXOs.count == 1)
        #expect(report.discoveredUTXOs[0].amount == 25_000)
        // The wallet state itself also reflects the spend and the discovery.
        #expect(await wallet.balance == 75_000)
        #expect(await wallet.nextReceiveIndex == 3)
    }

    @Test("a bundle exported at the tip verifies clean (empty scan)")
    func cleanReport() async throws {
        let bundle = try await makeBundle()
        let wallet = try Wallet.importing(bundle, keyStore: InMemoryKeyStore())
        let report = try await ImportReport.make(bundle: bundle, effects: [],
                                                 finalUTXOs: wallet.utxos,
                                                 scannedFromHeight: 501, scannedToHeight: nil)
        #expect(report.matchesBundle)
        #expect(report.confirmedUTXOs.count == 2)
        #expect(report.discoveredUTXOs.isEmpty)
    }

    /// Funds a wallet at receive index 0 so export has a live UTXO + history.
    private func fundedWallet(keyStore: KeyStore = InMemoryKeyStore()) async throws -> Wallet {
        try await TestSupport.fundedWallet(keyStore: keyStore, coins: [(.receive, 0, 200_000, 100)],
                                           mature: false).wallet
    }

    @Test("export → import round trip carries balance, history and scan frontier")
    func exportRoundTrip() async throws {
        let original = try await fundedWallet()
        let bundle = try await original.exportBundle()
        #expect(bundle.version == 2)
        #expect(bundle.mnemonic == nil)
        #expect(bundle.descriptor != nil)
        #expect(bundle.lastKnownHeight == 99) // nextScanHeight 100 − 1
        #expect(bundle.utxos.count == 1)
        #expect(bundle.transactions.count == 1)

        // Display-hex hop: the file's txid is reversed relative to internal order.
        let originalTxid = try #require(await original.utxos.first).txid
        #expect(bundle.utxos[0].txid == originalTxid.displayHex)
        #expect(bundle.utxos[0].txid != originalTxid.hex)

        let json = try bundle.serialized()
        #expect(!json.contains("\"mnemonic\""))
        let parsed = try JSONDecoder().decode(ImportBundle.self, from: Data(json.utf8))
        #expect(parsed == bundle)

        let restored = try Wallet.importing(parsed, keyStore: InMemoryKeyStore())
        #expect(await restored.id == original.id)
        #expect(await restored.balance == 200_000)
        #expect(await restored.utxos.count == 1)
        #expect(await restored.utxos[0].txid == originalTxid)
        #expect(await restored.history.count == 1)
        #expect(await restored.history[0].received == 200_000)
        #expect(await restored.nextScanHeight == 100)
        #expect(await restored.creationHeight == 99)
        #expect(bundle.nextReceiveIndex == 1)
        #expect(await restored.nextReceiveIndex == 1)
        // Watch-only import must not invent a seed.
        let emptyStore = InMemoryKeyStore()
        _ = try Wallet.importing(parsed, keyStore: emptyStore)
        #expect(throws: KeyStoreError.notFound(walletID: "73c5da0a")) {
            _ = try emptyStore.load(walletID: "73c5da0a")
        }
    }

    @Test("export with the mnemonic is opt-in and yields a spendable wallet")
    func exportWithMnemonic() async throws {
        let original = try await fundedWallet()
        let watchOnly = try await original.exportBundle(includeMnemonic: false)
        #expect(watchOnly.mnemonic == nil)

        let hot = try await original.exportBundle(includeMnemonic: true)
        #expect(hot.mnemonic == testMnemonic)
        let json = try hot.serialized()
        #expect(json.contains(testMnemonic))

        let keyStore = InMemoryKeyStore()
        let restored = try Wallet.importing(hot, keyStore: keyStore)
        #expect(await restored.id == "73c5da0a")
        #expect(try keyStore.load(walletID: "73c5da0a") == .mnemonic(testMnemonic))
        #expect(try await restored.address(chain: .receive, index: 0)
                    == (try await original.address(chain: .receive, index: 0)))
    }

    @Test("export with the mnemonic refuses an xprv-only wallet")
    func exportXprvRefusesSeed() async throws {
        let keyStore = InMemoryKeyStore()
        let wallet = try await fundedWallet(keyStore: keyStore)
        let id = await wallet.id
        let master = try HDKey(seed: BIP39.seed(mnemonic: testMnemonic))
        try keyStore.delete(walletID: id)
        try keyStore.store(.masterKey(master.serialized(network: .testnet)), for: id)
        do {
            _ = try await wallet.exportBundle(includeMnemonic: true)
            Issue.record("expected WalletError.mnemonicUnavailable")
        } catch let error as WalletError {
            #expect(error == .mnemonicUnavailable)
        }
        // Watch-only export still works — the descriptor is public material.
        let watchOnly = try await wallet.exportBundle()
        #expect(watchOnly.mnemonic == nil)
        #expect(watchOnly.descriptor != nil)
    }

    /// The live app path (`AppModel.syncOnce`) calls `apply(match:)` and
    /// drives FilterSync itself — it never goes through `Wallet.scan`.
    /// Without `recordScanHeight`, export would still emit the
    /// creation/import height.
    @Test("app-style apply + recordScanHeight exports the live frontier")
    func exportAfterAppStyleFilterProgress() async throws {
        let storage = tempFileURL("wallet.json")
        defer { try? FileManager.default.removeItem(at: storage.deletingLastPathComponent()) }
        let keyStore = InMemoryKeyStore()
        // App path: apply(match:) + independent FilterSync progress, never
        // Wallet.scan. Persist must land on disk so a reopen sees it.
        let wallet = try makeTestWallet(storageURL: storage, keyStore: keyStore)
        try await fund(wallet, amount: 200_000, height: 100)

        #expect(await wallet.nextScanHeight == 100)
        let stale = try await wallet.exportBundle()
        #expect(stale.lastKnownHeight == 99)

        // FilterSync finished a pass whose next height is 250.
        try await wallet.recordScanHeight(250)
        #expect(await wallet.nextScanHeight == 250)
        let live = try await wallet.exportBundle()
        #expect(live.lastKnownHeight == 249)
        #expect(live.utxos.count == 1)

        let reopened = try Wallet.open(storageURL: storage, keyStore: keyStore)
        #expect(await reopened.nextScanHeight == 250)
        #expect(try await reopened.exportBundle().lastKnownHeight == 249)
    }

    @Test("export carries a known fee; older JSON without the key still decodes")
    func exportPreservesKnownFee() async throws {
        let wallet = try await fundedWallet()
        let utxo = try #require(await wallet.utxos.first)
        var spend = Transaction(version: 2, inputs: [
            Transaction.Input(previousOutput: utxo.outpoint, scriptSig: Data(), sequence: 0xFFFF_FFFD),
        ], outputs: [
            Transaction.Output(value: 199_000,
                               scriptPubKey: Data([0x51, 0x20] + repeatElement(0x55, count: 32))),
        ], locktime: 0)
        spend.inputs[0].witness = [Data(repeating: 0, count: 64)]
        try await wallet.apply(match: fakeMatch(height: 101, transactions: [spend]))
        #expect(await wallet.history[1].fee == 1_000)

        let bundle = try await wallet.exportBundle()
        #expect(bundle.transactions.count == 2)
        #expect(bundle.transactions[0].fee == nil) // incoming funding: fee unknown
        #expect(bundle.transactions[1].fee == 1_000)
        let json = try bundle.serialized()
        #expect(json.contains("\"fee\""))
        // Incoming history must not encode `"fee": null`.
        let parsed = try JSONDecoder().decode(ImportBundle.self, from: Data(json.utf8))
        #expect(parsed.transactions[0].fee == nil)
        #expect(parsed.transactions[1].fee == 1_000)

        let restored = try Wallet.importing(parsed, keyStore: InMemoryKeyStore())
        #expect(await restored.history[0].fee == nil)
        #expect(await restored.history[1].fee == 1_000)

        // Pre-fee v1 files still decode.
        let legacy = """
        {"version":1,"network":"signet","lastKnownHeight":0,"utxos":[],\
        "transactions":[{"txid":"\(Data(repeating: 0x50, count: 32).displayHex)",\
        "height":1,"received":100,"spent":0}]}
        """
        let old = try JSONDecoder().decode(ImportBundle.self, from: Data(legacy.utf8))
        #expect(old.transactions[0].fee == nil)
    }

    @Test("export with mnemonic maps a missing keystore entry to mnemonicUnavailable")
    func exportMissingKeystoreIsMnemonicUnavailable() async throws {
        let keyStore = InMemoryKeyStore()
        let wallet = try await fundedWallet(keyStore: keyStore)
        try keyStore.delete(walletID: await wallet.id)
        do {
            _ = try await wallet.exportBundle(includeMnemonic: true)
            Issue.record("expected WalletError.mnemonicUnavailable")
        } catch let error as WalletError {
            #expect(error == .mnemonicUnavailable)
        } catch {
            Issue.record("leaked \(error) instead of WalletError.mnemonicUnavailable")
        }
        // Watch-only export still works — the descriptor is public material.
        let watchOnly = try await wallet.exportBundle()
        #expect(watchOnly.mnemonic == nil)
    }

    @Test("export refuses a pending send — parent inputs would vanish from a restore")
    func exportRefusesPendingSend() async throws {
        let wallet = try await fundedWallet()
        try await matureCoinbase(wallet, height: 100)
        let matureBundle = try await wallet.exportBundle()
        #expect(matureBundle.utxos.first?.isCoinbase == true)
        let restored = try Wallet.importing(matureBundle, keyStore: InMemoryKeyStore())
        #expect(await restored.utxos.first?.isCoinbase == true)
        let destination = TestScripts.p2trDestination
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(prepared)
        let built = prepared.built
        #expect(await wallet.utxos.contains(where: { $0.height == 0 }))
        do {
            _ = try await wallet.exportBundle()
            Issue.record("expected WalletError.exportWhilePending")
        } catch let error as WalletError {
            #expect(error == .exportWhilePending)
        }
        try await wallet.apply(match: fakeMatch(height: 101, transactions: [built.transaction]))
        let bundle = try await wallet.exportBundle()
        #expect(bundle.utxos.allSatisfy { $0.height > 0 })
        #expect(bundle.nextChangeIndex == 1)
    }

    @Test("export carries derivation indices so a spent-out restore does not reuse addresses")
    func exportPreservesDerivationIndices() async throws {
        let original = try makeTestWallet()
        _ = try await original.freshReceiveAddress()
        _ = try await original.freshReceiveAddress()
        #expect(await original.nextReceiveIndex == 2)
        #expect(await original.utxos.isEmpty)

        let bundle = try await original.exportBundle()
        #expect(bundle.nextReceiveIndex == 2)
        #expect(bundle.nextChangeIndex == 0)
        #expect(bundle.utxos.isEmpty)

        let restored = try Wallet.importing(bundle, keyStore: InMemoryKeyStore())
        #expect(await restored.nextReceiveIndex == 2)
        #expect(try await restored.address(chain: .receive, index: 2)
                    == (try await original.address(chain: .receive, index: 2)))

        // Older files without the keys still decode; the importer then uses
        // the UTXO-derived floor (0 here — nothing claimed).
        var legacy = bundle
        legacy.nextReceiveIndex = nil
        legacy.nextChangeIndex = nil
        let old = try Wallet.importing(legacy, keyStore: InMemoryKeyStore())
        #expect(await old.nextReceiveIndex == 0)
    }

    // MARK: - Import bundle bounds
    //
    // Bounds and decoding semantics for imported bundles (invariants S7, S10).
    //
    // A bundle is the one input a user is actively invited to paste from
    // anywhere. Two of the properties it relies on are Foundation's, not
    // Winnow's: `JSONDecoder` refuses deeply nested JSON, and it resolves a
    // duplicate key to its *first* occurrence. Both are undocumented defaults.
    // They are pinned here so that a Foundation change cannot quietly alter
    // what a bundle means — a duplicate `network` key silently flipping from
    // `signet` to `mainnet` would change which chain a restored wallet
    // believes it is on.
    //
    // The explicit size bounds are what Foundation does not provide at all.

    static func bundle(utxos: String = "", transactions: String = "", extra: String = "") -> String {
        """
        {"version":2,"network":"signet","lastKnownHeight":1\(extra),\
        "utxos":[\(utxos)],"transactions":[\(transactions)]}
        """
    }

    static let coin = #"{"txid":"aa","vout":0,"amount":1,"scriptPubKey":"51","chain":0,"index":0,"height":1}"#

    // MARK: Decoding semantics that belong to Foundation

    /// A duplicate key resolves to its first occurrence. This is the safer of
    /// the two possible answers — it matches what a person reading the file
    /// top to bottom sees — but it is worth a test precisely because nothing
    /// in the format guarantees it.
    @Test("a duplicate key resolves to its first occurrence")
    func duplicateKeyTakesTheFirstValue() throws {
        let json = #"""
        {"version":2,"network":"signet","network":"mainnet","lastKnownHeight":1,"utxos":[],"transactions":[]}
        """#
        let bundle = try ImportBundle.decode(json: json)
        #expect(bundle.network == "signet",
                "a later duplicate key must not silently change the bundle's network")
    }

    /// Deeply nested JSON is refused rather than exhausting the stack. The
    /// descriptor parser needed its own bound for exactly this reason
    /// (`SEC-010`); this records that the JSON path already has one.
    @Test("deeply nested JSON is refused", arguments: [512, 20_000])
    func deeplyNestedJSONRefused(_ depth: Int) {
        let nested = String(repeating: "[", count: depth) + String(repeating: "]", count: depth)
        let json = Self.bundle(extra: ",\"junk\":\(nested)")
        #expect(throws: (any Error).self) {
            _ = try ImportBundle.decode(json: json)
        }
    }

    // MARK: Bounds Winnow has to impose itself

    /// Foundation will decode a bundle of any size. Every declared coin is
    /// then materialised and scanned, so the count is bounded before the
    /// allocation rather than after it.
    @Test("a bundle above the entry limit is refused")
    func tooManyEntriesRefused() throws {
        let coins = Array(repeating: Self.coin, count: ImportBundle.maximumEntries + 1)
            .joined(separator: ",")
        #expect(throws: WalletError.self) {
            _ = try ImportBundle.decode(json: Self.bundle(utxos: coins))
        }
    }

    @Test("a bundle above the byte limit is refused")
    func tooLargeRefused() throws {
        let filler = String(repeating: "a", count: ImportBundle.maximumSerializedBytes)
        let json = Self.bundle(extra: ",\"descriptor\":\"\(filler)\"")
        #expect(json.utf8.count > ImportBundle.maximumSerializedBytes)
        #expect(throws: WalletError.self) {
            _ = try ImportBundle.decode(json: json)
        }
    }

    /// Positive controls: ordinary bundles, and one right at the entry limit,
    /// still decode. Without these the refusals above could be explained by
    /// the decoder rejecting everything.
    @Test("an ordinary bundle decodes")
    func ordinaryBundleDecodes() throws {
        let bundle = try ImportBundle.decode(json: Self.bundle(utxos: Self.coin))
        #expect(bundle.network == "signet")
        #expect(bundle.utxos.count == 1)
    }

    @Test("a bundle exactly at the entry limit is accepted")
    func atTheLimitAccepted() throws {
        let coins = Array(repeating: Self.coin, count: ImportBundle.maximumEntries)
            .joined(separator: ",")
        let bundle = try ImportBundle.decode(json: Self.bundle(utxos: coins))
        #expect(bundle.utxos.count == ImportBundle.maximumEntries)
    }

    /// Malformed input still fails as an error rather than anything worse.
    @Test("truncated JSON is refused")
    func truncatedJSONRefused() {
        #expect(throws: (any Error).self) {
            _ = try ImportBundle.decode(json: #"{"version":2,"network":"sig"#)
        }
    }
}
