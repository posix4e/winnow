import BitcoinCore
import BitcoinP2P
import Foundation
import Testing
import WalletCore

/// The whole pipeline against the dev node over real P2P with custom-signet
/// params: mine a funding block to a Winnow address → bury it under 100
/// blocks (coinbase maturity) → discover it via FilterSync (BIP157) →
/// build+sign a spend with WalletCore → testmempoolaccept → relay via
/// TxBroadcaster → mine a confirmation → see it confirmed through our own
/// filter match.
///
/// Two environment quirks this test is built around:
/// - Core 31 does not sign custom-signet blocks, so the harness mines via
///   GBT + BIP325 signature + bitcoin-util grind + submitblock (SignetMiner).
/// - A background miner on this node produces a block every ~10 minutes, so
///   every mined block is checked to have become the tip (re-mined on a lost
///   race) and confirmation is detected by scanning, whoever mined the block.
@Suite("full-loop differential", .enabled(if: diffEnabled))
struct FullLoopDiffTests {
    private let endpoint = PeerEndpoint(host: BitcoinCLI.nodeHost, port: BitcoinCLI.p2pPort)

    @Test("mine → mature → filter-discover → sign → relay → confirm")
    func fullLoop() async throws {
        func trace(_ step: String) { FileHandle.standardError.write(Data("fullloop: \(step)\n".utf8)) }
        let params = NetworkParams.customSignet(challenge: BitcoinCLI.challenge,
                                                defaultPort: BitcoinCLI.p2pPort)

        // 1. Tip at start; a fresh wallet whose creation height is that tip.
        let startTip = try UInt32(BitcoinCLI.blockCount())
        let wallet = try await Wallet.create(network: .signet, keyStore: InMemoryKeyStore(),
                                             storageURL: tempFileURL("wallet.json"),
                                             creationHeight: startTip)
        _ = try await wallet.freshReceiveAddress()
        let fundingScript = try await wallet.scriptPubKey(chain: .receive, index: 0)

        // 2. Mine the funding block, then 99 more blocks. The funding block
        //    itself is confirmation one, so the coinbase is now at the exact
        //    100-confirmation consensus maturity boundary.
        let burnScript = try BIP86.scriptPubKey(
            internalKey: BIP86.xonlyPublicKey(of: testMaster().derived(path: "m/86'/1'/9'/0/1")))
        let fundingHash = try await SignetMiner.mineOntoTip(payingTo: fundingScript)
        trace("funding block \(fundingHash.prefix(16))…")
        for _ in 0 ..< 99 {
            _ = try await SignetMiner.mineOntoTip(payingTo: burnScript)
        }
        let fundingBlock = try BitcoinCLI.runObject(["getblock", fundingHash])
        // Not startTip + 1: a lost race is re-mined, which lands us one or
        // more blocks higher than the tip we measured before mining.
        let fundingHeight = try UInt32(BitcoinCLI.int(fundingBlock, "height"))
        #expect(try BitcoinCLI.int(fundingBlock, "confirmations") >= 100, "funding matured")
        trace("maturity done, tip \(try BitcoinCLI.blockCount())")

        // 3. P2P: header chain + FilterSync over the custom-signet network
        //    discovers the payment. (Built after mining so the local chain
        //    adopts the node's best chain in one sync, race-free.)
        let pool = PeerPool(params: params, peerCount: 1, manualPeers: [endpoint])
        await pool.start()
        defer { Task { await pool.stop() } }
        let peers = await pool.connectedPeers()
        let peer = try #require(peers.first, "no connection to \(BitcoinCLI.nodeHost):\(BitcoinCLI.p2pPort)")
        let chain = try HeaderChain(params: params, storageURL: tempFileURL("headers.bin"))
        try await chain.sync(using: peer, timeout: .seconds(60))
        let tip = try UInt32(BitcoinCLI.blockCount())
        #expect(await chain.height == tip, "header sync tip")
        #expect(await chain.tipHash.displayHex == (try BitcoinCLI.bestBlockHash()), "tip hash")

        let sync = try FilterSync(pool: pool, chain: chain, startHeight: startTip,
                                  storageURL: tempFileURL("filters.json"),
                                  requiredCheckpointPeers: 1)
        try await wallet.scan(using: sync)
        trace("first scan done")
        let fundingUTXO = try await #require(wallet.utxos.first, "filter match found no funding UTXO")
        #expect(fundingUTXO.amount == 5_000_000_000, "signet subsidy") // 50 BTC
        #expect(fundingUTXO.height == fundingHeight, "funded in the block we mined")
        let fundingTx = try BitcoinCLI.runObject(["getrawtransaction",
                                                  fundingUTXO.txid.displayHex, "true"])
        #expect(try BitcoinCLI.string(fundingTx, "blockhash") == fundingHash,
                "funding txid lands in our mined block")

        // 4. Build + sign a spend paying a throwaway BIP86 address 100k sats.
        let throwaway = try BIP86.address(
            internalKey: BIP86.xonlyPublicKey(of: testMaster().derived(path: "m/86'/1'/9'/0/0")),
            hrp: "tb")
        // The node's own tip, and a draw that misses the lookback branch, so the
        // locktime is exactly the tip. This is the one place that proves an
        // anti-fee-sniping locktime is acceptable to Core's mempool policy
        // rather than merely to our builder (#139): step 5 below puts this very
        // transaction through `testmempoolaccept`.
        let original = try await wallet.send(
            payments: [Payment(amount: 100_000, address: throwaway, network: .signet)],
            feeRateSatPerVByte: 1, chainTip: tip, randomness: { 0.5 })
        #expect(original.transaction.locktime == tip, "the send is stamped with the node's tip")
        let rawHex = original.transaction.serialized(includeWitness: true).hex
        trace("spend signed")

        // 5. Core's mempool policy check agrees the tx is valid.
        let accepted = try BitcoinCLI.runJSON(["testmempoolaccept", "[\"\(rawHex)\"]"]) as? [[String: Any]]
        let verdict = try #require(accepted?.first)
        #expect(verdict["allowed"] as? Bool == true,
                "testmempoolaccept rejected: \(verdict["reject-reason"] ?? "?")")
        #expect(verdict["txid"] as? String == original.transaction.txid.displayHex)
        #expect((verdict["vsize"] as? NSNumber)?.intValue == TransactionBuilder.vsize(of: original.transaction),
                "vsize agreement")

        // 6. Relay via our TxBroadcaster (inv → node's getdata → tx).
        let broadcaster = try TxBroadcaster(pool: pool, rebroadcastBaseInterval: .seconds(5))
        let originalTxid = try await broadcaster.broadcast(Data(hex: rawHex)!)
        var inMempool = false
        for _ in 0 ..< 15 {
            if (try? BitcoinCLI.runObject(["getmempoolentry", originalTxid.displayHex])) != nil {
                inMempool = true
                break
            }
            try await Task.sleep(for: .seconds(1))
        }
        #expect(inMempool, "node never requested/accepted our relayed tx")
        trace("in mempool")

        // 7. Build a same-input replacement and ask Core to enforce its
        // mempool policy against the live original before we relay it.
        let replacement = try await wallet.buildFeeBump(
            txid: originalTxid, feeRateSatPerVByte: 2)
        let replacementHex = replacement.built.transaction.serialized(includeWitness: true).hex
        let replacementResult = try BitcoinCLI.runJSON(
            ["testmempoolaccept", "[\"\(replacementHex)\"]"]) as? [[String: Any]]
        let replacementVerdict = try #require(replacementResult?.first)
        #expect(replacementVerdict["allowed"] as? Bool == true,
                "Core rejected RBF: \(replacementVerdict["reject-reason"] ?? "?")")
        #expect(replacement.built.transaction.inputs.map(\.previousOutput)
                == original.transaction.inputs.map(\.previousOutput))
        #expect(replacement.built.fee > original.fee)

        let replacementTxid = try await broadcaster.broadcast(
            Data(hex: replacementHex)!,
            feeRateSatPerVByte: Double(replacement.built.fee)
                / Double(TransactionBuilder.vsize(of: replacement.built.transaction)))
        try await wallet.commitFeeBump(replacement)
        try await broadcaster.cancel(originalTxid)
        var replacementInMempool = false
        for _ in 0 ..< 15 {
            if (try? BitcoinCLI.runObject(["getmempoolentry", replacementTxid.displayHex])) != nil {
                replacementInMempool = true
                break
            }
            try await Task.sleep(for: .seconds(1))
        }
        #expect(replacementInMempool, "node never accepted our relayed replacement")
        #expect((try? BitcoinCLI.runObject(["getmempoolentry", originalTxid.displayHex])) == nil,
                "original remained in mempool after replacement")
        trace("replacement in mempool")

        // 8. Mine blocks until the replacement confirms; then see it through
        //    our own filter match (whoever won the block race — the
        //    background miner also picks up mempool transactions).
        var confirmed = false
        for _ in 0 ..< 6 {
            _ = try await SignetMiner.mineBlock(payingTo: burnScript)
            try await wallet.scan(using: sync)
            if await wallet.history.first(where: {
                $0.txid == replacementTxid && $0.height > 0
            }) != nil {
                confirmed = true
                break
            }
        }
        #expect(confirmed, "replacement never confirmed")
        try await broadcaster.markConfirmed(replacementTxid)

        let history = await wallet.history
        #expect(history.first { $0.txid == originalTxid }?.replacedBy == replacementTxid)
        let sendEntry = try #require(
            history.first { $0.txid == replacementTxid }, "replacement missing from history")
        #expect(sendEntry.height > startTip + 101, "spend confirmed after maturity")
        #expect(sendEntry.fee == replacement.built.fee, "wallet replacement fee accounting")
        let remaining = await wallet.utxos
        #expect(remaining.count == 1, "only the change output remains")
        #expect(remaining[0].height == sendEntry.height, "change confirmed via filter match")
        #expect(remaining[0].amount == replacement.built.changeAmount)
        #expect(await broadcaster.pendingTxids.isEmpty, "broadcaster settled")
        trace("done")
    }
}
