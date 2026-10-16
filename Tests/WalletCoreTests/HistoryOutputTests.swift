import Foundation
import Testing
import TestSupport
@testable import WalletCore

@Suite("History output metadata")
struct HistoryOutputTests {
    @Test("a committed send records where it paid and which output was change")
    func sendRecordsItsOutputs() async throws {
        let (wallet, _) = try await fundedWallet(coins: [(.receive, 0, 150_000, 100)])
        let destination = TestScripts.p2trDestination
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(prepared)

        let signed = prepared.built.transaction
        let paid = try #require(signed.outputs.firstIndex { $0.scriptPubKey == destination })
        let change = try #require(signed.outputs.firstIndex { $0.scriptPubKey != destination })
        let outputs = try #require(await wallet.history.first { $0.txid == signed.txid }?.outputs)
        #expect(outputs.external == [HistoryEntry.ExternalOutput(
            vout: UInt32(paid), amount: 100_000, scriptPubKey: destination)])
        #expect(outputs.change == [UInt32(change)])

        // Confirmation retires the pending send, which used to be the only
        // record of the destination. The entry keeps it.
        try await wallet.apply(match: fakeMatch(height: 150, transactions: [signed]))
        let confirmed = try #require(await wallet.history.first { $0.txid == signed.txid })
        #expect(confirmed.height == 150)
        #expect(await wallet.feeBumpableTxids.isEmpty)
        #expect(confirmed.outputs == outputs)
    }

    @Test("a send to one of our own addresses is neither an external output nor change")
    func sendToOwnAddressIsNotExternal() async throws {
        let (wallet, _) = try await fundedWallet(coins: [(.receive, 0, 150_000, 100)])
        let ours = try await wallet.scriptPubKey(chain: .receive, index: 1)
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: ours)],
            feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(prepared)

        let signed = prepared.built.transaction
        #expect(signed.outputs.count == 2)
        let outputs = try #require(await wallet.history.first { $0.txid == signed.txid }?.outputs)
        #expect(outputs.external.isEmpty)
        #expect(outputs.change.count == 1)
    }

    @Test("a fee-bumped replacement records the outputs it pays")
    func feeBumpRecordsItsOutputs() async throws {
        let (wallet, _) = try await fundedWallet(coins: [(.receive, 0, 150_000, 100)])
        let destination = TestScripts.p2trDestination
        let original = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(original)
        let originalTxid = original.built.transaction.txid
        let rate = try await wallet.pendingFeeRate(txid: originalTxid)
        let replacement = try await wallet.buildFeeBump(txid: originalTxid,
                                                        feeRateSatPerVByte: rate + 1)
        try await wallet.commitFeeBump(replacement)

        let signed = replacement.built.transaction
        let outputs = try #require(await wallet.history.first { $0.txid == signed.txid }?.outputs)
        #expect(outputs.external.map(\.amount) == [100_000])
        #expect(outputs.external.first?.scriptPubKey == destination)
        // Its change is smaller than the original's and still ours.
        #expect(outputs.change.count == 1)
    }

    @Test("recorded outputs round-trip through the state file")
    func recordedOutputsRoundTrip() async throws {
        let url = tempFileURL("history-outputs-wallet.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let keyStore = InMemoryKeyStore()
        let (wallet, _) = try await fundedWallet(storageURL: url, keyStore: keyStore,
                                                 coins: [(.receive, 0, 150_000, 100)])
        let prepared = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: TestScripts.p2trDestination)],
            feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(prepared)

        // The script goes to disk as hex, like a coin's.
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        let json = try #require(object as? [String: Any])
        let entries = try #require(json["history"] as? [[String: Any]])
        let recorded = try #require(entries.last?["outputs"] as? [String: Any])
        let external = try #require(recorded["external"] as? [[String: Any]])
        #expect(external.first?["scriptPubKey"] as? String == TestScripts.p2trDestination.hex)

        let reopened = try Wallet.open(storageURL: url, keyStore: keyStore)
        let entry = try #require(await reopened.history.first {
            $0.txid == prepared.built.transaction.txid
        })
        #expect(entry.outputs == (await wallet.history.last?.outputs))
        #expect(entry.outputs?.external.first?.amount == 100_000)
    }

    @Test("recipient metadata survives backup import; absent legacy metadata stays unknown")
    func backupCompatibility() async throws {
        let (wallet, _) = try await fundedWallet(coins: [(.receive, 0, 150_000, 100)])
        let send = try await wallet.buildSend(
            payments: [Payment(amount: 100_000, scriptPubKey: TestScripts.p2trDestination)],
            feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        try await wallet.commit(send)
        try await wallet.apply(match: fakeMatch(height: 150, transactions: [send.built.transaction]))
        let backup = try await wallet.exportBundle()
        let encoded = try JSONEncoder().encode(backup)
        let decoded = try JSONDecoder().decode(ImportBundle.self, from: encoded)
        let restored = try Wallet.importing(decoded, keyStore: InMemoryKeyStore())
        let entry = try #require(await restored.history.first { $0.txid == send.built.transaction.txid })
        #expect(entry.outputs?.external.first?.scriptPubKey == TestScripts.p2trDestination)
        #expect(entry.blockHash != nil)
        var legacy = entry
        legacy.outputs = nil
        let old = try JSONDecoder().decode(HistoryEntry.self, from: JSONEncoder().encode(legacy))
        #expect(old.outputs == nil)
        #expect(old.rawTransaction == entry.rawTransaction)
    }

    @Test("contradictory and invalid recipient metadata cannot load")
    func invalidMetadata() throws {
        let recipient = HistoryEntry.ExternalOutput(vout: 0, amount: 50_000,
                                                     scriptPubKey: TestScripts.p2trDestination)
        let invalid: [HistoryEntry.Outputs] = [
            .init(external: [recipient, recipient]),
            .init(external: [recipient], change: [0]),
            .init(change: [2, 1]), .init(change: [1, 1]),
            .init(external: [.init(vout: 0, amount: -1, scriptPubKey: recipient.scriptPubKey)]),
            .init(external: [.init(vout: 0, amount: 1, scriptPubKey: Data())]),
            .init(external: [.init(vout: 0, amount: BitcoinAmount.maximum, scriptPubKey: recipient.scriptPubKey),
                             .init(vout: 1, amount: 1, scriptPubKey: recipient.scriptPubKey)]),
        ]
        for outputs in invalid {
            let entry = HistoryEntry(txid: Data(repeating: 0x11, count: 32), height: 1,
                                     received: 0, spent: 50_000, outputs: outputs)
            let encoded = try JSONEncoder().encode(entry)
            #expect(throws: (any Error).self) { try JSONDecoder().decode(HistoryEntry.self, from: encoded) }
        }
        let transaction = makeFakeSegwitTx()
        let entry = HistoryEntry(txid: transaction.txid, height: 1, received: 0, spent: 50_000,
                                 rawTransaction: transaction.serialized(includeWitness: false),
                                 outputs: .init(external: [recipient]))
        // The txid is correct, but the recipient script contradicts those bytes.
        #expect(throws: (any Error).self) { try entry.transaction() }
    }

    /// An imported pending entry may carry a breakdown with no bytes to check
    /// it against. The block that confirms it brings the bytes; a breakdown
    /// they contradict is dropped there, so the file the wallet writes is one
    /// its own decoder accepts on the next launch.
    @Test("confirming an imported entry drops metadata its bytes contradict, and the file reopens")
    func contradictedImportedMetadataIsDropped() async throws {
        let url = tempFileURL("contradicted-outputs-wallet.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let keyStore = InMemoryKeyStore()
        let transaction = makeFakeSegwitTx()
        let source = try makeTestWallet(creationHeight: 400)
        var claimed = ImportBundle.KnownTransaction(txid: transaction.txid.displayHex, height: 0,
                                                    received: 0, spent: 0)
        claimed.outputs = .init(external: [.init(vout: 0, amount: transaction.outputs[0].value + 1,
                                                 scriptPubKey: transaction.outputs[0].scriptPubKey)])
        let bundle = try await ImportBundle(network: "signet",
                                            descriptor: source.descriptor.serialized(),
                                            mnemonic: testMnemonic,
                                            lastKnownHeight: 500, utxos: [], transactions: [claimed])
        let wallet = try Wallet.importing(bundle, keyStore: keyStore, storageURL: url)
        #expect(try #require(await wallet.history.first).outputs != nil,
                "display metadata without bytes is accepted on import")

        try await wallet.apply(match: fakeMatch(height: 600, transactions: [transaction]))
        let confirmed = try #require(await wallet.history.first { $0.txid == transaction.txid })
        #expect(confirmed.height == 600)
        #expect(confirmed.rawTransaction != nil)
        #expect(confirmed.outputs == nil, "the breakdown the bytes contradict is gone")

        let reopened = try Wallet.open(storageURL: url, keyStore: keyStore)
        let entry = try #require(await reopened.history.first { $0.txid == transaction.txid })
        #expect(entry.outputs == nil)
        #expect(try entry.transaction()?.txid == transaction.txid)
    }
}
