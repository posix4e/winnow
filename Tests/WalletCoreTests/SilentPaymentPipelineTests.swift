import BitcoinCore
import BitcoinP2P
import Foundation
import P256K
import Testing
@testable import WalletCore

/// The silent-payment receive pipeline above the crypto: index tweaks →
/// filter-stage candidates → block resolution → wallet credit, with the
/// index treated as untrusted for credits.
@Suite("Silent payment pipeline")
struct SilentPaymentPipelineTests {
    struct FakeTweakIndex: TweakIndexClient {
        var tweaksByHeight: [UInt32: [Data]]
        func tweaks(forBlockAt height: UInt32) async throws -> [Data] {
            tweaksByHeight[height] ?? []
        }
    }

    /// Sender wallet paying the `testEntropy` receiver's silent payment
    /// address; returns the paying tx, its true tweak data (recomputed from
    /// the prevouts the test controls, exactly what an honest index serves),
    /// and the funding script.
    private func makePayment(amounts: [Int64]) async throws -> (tx: Transaction, tweakData: Data) {
        let sender = try await Wallet.create(network: .signet, keyStore: InMemoryKeyStore(),
                                             entropy: Data(repeating: 1, count: 16),
                                             creationHeight: 100)
        let senderScript = try await sender.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: amounts.reduce(50_000, +), scriptPubKey: senderScript),
        ], locktime: 0)
        try await sender.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(sender, height: 100)

        let receiver = try await Wallet.create(network: .signet, keyStore: InMemoryKeyStore(),
                                               entropy: testEntropy, creationHeight: 100)
        let address = try await receiver.silentPaymentAddress()
        let built = try await sender.send(
            payments: [], feeRateSatPerVByte: 2,
            silentPayments: try amounts.map {
                try SilentPayment(amount: $0, address: address, network: .signet)
            }, chainTip: testChainTip, randomness: { 0.5 })
        let tx = built.transaction

        let inputKeys = tx.inputs.compactMap {
            SilentPaymentSending.eligiblePublicKey(prevoutScriptPubKey: senderScript,
                                                   scriptSig: $0.scriptSig, witness: $0.witness)
        }
        let sum = try #require(try SilentPaymentReceiving.inputPublicKeySum(inputKeys))
        let smallestOutpoint = tx.inputs.map { input -> Data in
            var littleEndianVout = input.previousOutput.vout.littleEndian
            return input.previousOutput.txid + withUnsafeBytes(of: &littleEndianVout) { Data($0) }
        }.min(by: { $0.lexicographicallyPrecedes($1) })!
        let tweakData = try SilentPaymentReceiving.tweakData(inputPublicKeySum: sum,
                                                             smallestOutpoint: smallestOutpoint)
        return (tx, tweakData)
    }

    private func receiverScanner() throws -> SilentPaymentBlockScanner {
        let master = try testMaster()
        let scan = try SilentPaymentReceiving.scanKey(from: master, coinType: 1)
        let spend = try SilentPaymentReceiving.spendKey(from: master, coinType: 1)
        return SilentPaymentBlockScanner(scanPrivateKey: scan.privateKey!,
                                         spendPublicKey: spend.publicKey)
    }

    @Test("index tweak → k=0 candidate → block resolution finds every k")
    func scannerResolvesBlock() async throws {
        let (tx, tweakData) = try await makePayment(amounts: [100_000, 40_000])
        let scanner = try receiverScanner()
        let candidates = try scanner.candidates(tweaks: [tweakData])
        #expect(candidates.count == 1)
        // The k=0 candidate script is an actual output of the paying tx.
        #expect(tx.outputs.contains { $0.scriptPubKey == candidates[0].script })

        let block = fakeMatch(height: 101, transactions: [tx]).block
        let found = try scanner.matches(in: block, candidates: candidates)
        #expect(found.count == 2) // k = 0 and k = 1, one candidate
        #expect(Set(found.map(\.amount)) == [100_000, 40_000])
        for payment in found {
            #expect(tx.outputs[Int(payment.vout)].scriptPubKey == payment.scriptPubKey)
        }
    }

    @Test("a filter false positive credits nothing")
    func falsePositive() async throws {
        let (tx, _) = try await makePayment(amounts: [100_000])
        let scanner = try receiverScanner()
        // A tweak unrelated to the block: valid point, no P_0 in any tx.
        let bogusTweak = try P256K.Signing.PrivateKey().publicKey.dataRepresentation
        let candidates = try scanner.candidates(tweaks: [bogusTweak])
        let block = fakeMatch(height: 101, transactions: [tx]).block
        #expect(try scanner.matches(in: block, candidates: candidates).isEmpty)
    }

    @Test("wallet credits, merges history, and re-applies idempotently")
    func walletCreditsViaCandidateCache() async throws {
        let (tx, tweakData) = try await makePayment(amounts: [100_000])
        let receiver = try await Wallet.create(network: .signet, keyStore: InMemoryKeyStore(),
                                               entropy: testEntropy, creationHeight: 100)
        let index = FakeTweakIndex(tweaksByHeight: [101: [tweakData]])
        let scripts = try await receiver.silentPaymentCandidateScripts(range: 101 ... 101,
                                                                       index: index)
        #expect(scripts[101]?.count == 1)
        // FilterSync would probe the filter with this script and fetch the
        // block; the wallet applies it from the candidate cache.
        let match = fakeMatch(height: 101, transactions: [tx])
        let effect = try await receiver.apply(match: match)
        #expect(effect.received.count == 1)
        #expect(effect.received[0].silentPaymentTweak != nil)
        #expect(await receiver.balance == 100_000)
        let history = await receiver.history
        #expect(history.count == 1)
        #expect(history[0].received == 100_000)

        // Same block again: nothing double-credited.
        let again = try await receiver.apply(match: match)
        #expect(again.received.isEmpty)
        #expect(await receiver.balance == 100_000)
        #expect(await receiver.history.count == 1)
    }

    @Test("a tx paying BIP86 and silent-payment outputs merges one entry")
    func dualPayment() async throws {
        let (tx, tweakData) = try await makePayment(amounts: [100_000])
        let receiver = try await Wallet.create(network: .signet, keyStore: InMemoryKeyStore(),
                                               entropy: testEntropy, creationHeight: 100)
        // Extend the paying tx with an output to the receiver's BIP86 chain.
        var combined = tx
        let bip86Script = try await receiver.scriptPubKey(chain: .receive, index: 0)
        combined.outputs.append(Transaction.Output(value: 25_000, scriptPubKey: bip86Script))

        let index = FakeTweakIndex(tweaksByHeight: [101: [tweakData]])
        _ = try await receiver.silentPaymentCandidateScripts(range: 101 ... 101, index: index)
        let effect = try await receiver.apply(match: fakeMatch(height: 101,
                                                               transactions: [combined]))
        #expect(effect.received.count == 2)
        #expect(await receiver.balance == 125_000)
        let history = await receiver.history
        #expect(history.count == 1)
        #expect(history[0].received == 125_000)
    }
}
