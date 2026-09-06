import BitcoinCore
@testable import BitcoinP2P
import Foundation
import Testing

/// `getblockfilter` (Core 31.1, blockfilterindex) vs our BIP158 GCS: rebuild
/// each basic filter from the block's contents (output scripts + spent
/// prevout scripts, skipping empty/OP_RETURN) and compare the serialized
/// bytes exactly, then check our matcher against Core's filter.
@Suite("getblockfilter differential", .enabled(if: diffEnabled))
struct FilterDiffTests {
    /// BIP158 basic-filter item set for a block fetched as hex. Prevout
    /// scripts come from the node's txindex (read-only lookups).
    private func filterItems(_ block: Block) throws -> [Data] {
        func isFilterable(_ script: Data) -> Bool {
            !script.isEmpty && script.first != 0x6A // non-empty, not OP_RETURN (BIP158)
        }
        var items: [Data] = []
        for (txIndex, tx) in block.transactions.enumerated() {
            for output in tx.outputs where isFilterable(output.scriptPubKey) {
                items.append(output.scriptPubKey)
            }
            guard txIndex > 0 else { continue } // coinbase inputs have no prevout
            for input in tx.inputs {
                let scriptHex = try BitcoinCLI.spentScript(txid: input.previousOutput.txid.displayHex,
                                                           vout: Int(input.previousOutput.vout))
                let script = Data(hex: scriptHex)!
                if isFilterable(script) { items.append(script) }
            }
        }
        return items
    }

    @Test("rebuilt basic filters match getblockfilter for the 5 most recent blocks")
    func filters() async throws {
        try await ensureChain(atLeast: 5)
        let tip = try BitcoinCLI.blockCount()
        try #require(tip >= 5)
        for height in (tip - 4) ... tip {
            let hashDisplay = try BitcoinCLI.blockHash(at: height)
            let blockHex = try BitcoinCLI.run(["getblock", hashDisplay, "0"])
            let block = try Block.decode(Data(hex: blockHex)!)
            #expect(block.hash.displayHex == hashDisplay, "block decode/hash at \(height)")

            // Rebuild from contents and compare serialized bytes with Core's index.
            let key = Data(block.hash.prefix(16)) // BIP158: first 16 bytes of block hash
            let items = try filterItems(block)
            let ours = try GCSFilter(items: items, key: key)
            let core = try BitcoinCLI.runObject(["getblockfilter", hashDisplay])
            let coreHex = try BitcoinCLI.string(core, "filter")
            #expect(ours.serialized.hex == coreHex, "filter bytes at \(height)")

            // Our matcher on Core's filter: a script known in the block must
            // match; a made-up P2TR script must not.
            var reader = ByteReader(Data(hex: coreHex)!)
            let n = UInt32(try reader.readVarInt())
            let coreFilter = try GCSFilter(key: key, n: n, encoded: reader.readBytes(reader.remaining))
            if let knownIn = items.first {
                #expect(coreFilter.contains(knownIn), "matcher false negative at \(height)")
            }
            let outsider = Data([0x51, 0x20]) + Data(repeating: 0xEE, count: 32)
            #expect(!coreFilter.contains(outsider), "matcher false positive at \(height)")
        }
    }
}

/// `getblockheader` (Core 31.1) vs our header parse + PoW validation, using
/// the custom-signet params (same consensus fields as default signet).
@Suite("getblockheader differential", .enabled(if: diffEnabled))
struct HeaderDiffTests {
    @Test("header fields and proof of work across the chain")
    func headers() async throws {
        let params = NetworkParams.customSignet(challenge: BitcoinCLI.challenge,
                                                defaultPort: BitcoinCLI.p2pPort)
        try await ensureChain(atLeast: 5)
        let tip = try BitcoinCLI.blockCount()
        for height in Set([0, 1, tip / 2, tip - 1, tip]).sorted() {
            let hashDisplay = try BitcoinCLI.blockHash(at: height)
            let headerHex = try BitcoinCLI.run(["getblockheader", hashDisplay, "false"])
            let header = try BlockHeader.decode(Data(hex: headerHex)!)
            #expect(header.serialized.hex == headerHex, "header round-trip at \(height)")
            #expect(header.hash.displayHex == hashDisplay, "header hash at \(height)")

            let verbose = try BitcoinCLI.runObject(["getblockheader", hashDisplay, "true"])
            #expect(try BitcoinCLI.int(verbose, "version") == Int(header.version), "version at \(height)")
            #expect(try BitcoinCLI.string(verbose, "merkleroot") == header.merkleRoot.displayHex,
                    "merkleroot at \(height)")
            #expect(try BitcoinCLI.int(verbose, "time") == Int(header.time), "time at \(height)")
            #expect(try UInt32(BitcoinCLI.string(verbose, "bits"), radix: 16) == header.bits,
                    "bits at \(height)")
            #expect(try BitcoinCLI.int(verbose, "nonce") == Int(header.nonce), "nonce at \(height)")
            if height > 0 {
                #expect(try BitcoinCLI.string(verbose, "previousblockhash") == header.previousHash.displayHex,
                        "previous hash at \(height)")
            }

            // PoW: compact target decodes, is within powLimit, hash ≤ target.
            #expect(throws: Never.self) {
                try HeaderChain.checkedWork(for: header, params: params, height: UInt32(height))
            }
        }
    }
}
