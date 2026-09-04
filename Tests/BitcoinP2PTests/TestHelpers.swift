import BitcoinCore
import Foundation
@testable import BitcoinP2P

/// Test doubles shared across BitcoinP2PTests.

/// Regtest-style parameters: bits 0x207fffff gives a target near 2^255, so a
/// valid header is "mined" in ~2 nonce tries. Used to exercise HeaderChain's
/// real PoW checks without a node.
func makeTestParams(genesis: BlockHeader) -> NetworkParams {
    NetworkParams(
        network: .signet,
        magic: Data([0x0A, 0x03, 0xCF, 0x40]),
        defaultPort: 38333,
        genesisTime: genesis.time,
        genesisBits: genesis.bits,
        genesisNonce: genesis.nonce,
        genesisMerkleRoot: genesis.merkleRoot,
        genesisHash: genesis.hash,
        powLimit: Data(displayHex: "7fffff0000000000000000000000000000000000000000000000000000000000"),
        dnsSeeds: []
    )
}

/// Mines a header at trivial difficulty (bits 0x207fffff).
func minedHeader(previousHash: Data, merkleRoot: Data, time: UInt32) -> BlockHeader {
    let bits: UInt32 = 0x207F_FFFF
    let target = UInt256.target(compact: bits)!
    var nonce: UInt32 = 0
    while true {
        let header = BlockHeader(version: 1, previousHash: previousHash, merkleRoot: merkleRoot,
                                 time: time, bits: bits, nonce: nonce)
        if UInt256(littleEndian: header.hash) <= target { return header }
        nonce &+= 1
    }
}

/// A synthetic, fully valid (PoW-wise) block chain for loopback tests.
struct SyntheticChain {
    let params: NetworkParams
    /// All blocks, height-indexed (element 0 is genesis).
    let blocks: [Block]
    let watchScript: Data
    let watchHeight: UInt32
}

/// Builds a chain of single-transaction blocks; the block at `watchHeight`
/// pays to `watchScript` (a P2TR-shaped output).
func makeSyntheticChain(length: Int = 6, watchHeight: UInt32 = 3) -> SyntheticChain {
    let watchScript = Data([0x51, 0x20] + repeatElement(0x42, count: 32))

    func coinbase(height: Int, includeWatch: Bool) -> Transaction {
        let input = Transaction.Input(
            previousOutput: Transaction.Outpoint(txid: Data(repeating: 0, count: 32), vout: 0xFFFF_FFFF),
            scriptSig: Data([UInt8(height & 0xFF), UInt8(height >> 8 & 0xFF)]), sequence: 0xFFFF_FFFF)
        var outputs = [Transaction.Output(value: 5_000_000_000, scriptPubKey: Data([0x51]))]
        if includeWatch {
            outputs.append(Transaction.Output(value: 1_000, scriptPubKey: watchScript))
        }
        return Transaction(version: 2, inputs: [input], outputs: outputs, locktime: 0)
    }

    var blocks: [Block] = []
    var previousHash = Data(repeating: 0, count: 32)
    for height in 0 ... length {
        let tx = coinbase(height: height, includeWatch: height == watchHeight)
        // Single-tx block: merkle root is the txid.
        let header = minedHeader(previousHash: previousHash, merkleRoot: tx.txid,
                                 time: 1_600_000_000 + UInt32(height) * 600)
        blocks.append(Block(header: header, transactions: [tx]))
        previousHash = header.hash
    }
    return SyntheticChain(params: makeTestParams(genesis: blocks[0].header),
                          blocks: blocks,
                          watchScript: watchScript,
                          watchHeight: watchHeight)
}

/// A segwit transaction with one witness item, for relay tests.
func makeFakeSegwitTx() -> Transaction {
    var input = Transaction.Input(
        previousOutput: Transaction.Outpoint(txid: Data(repeating: 0x11, count: 32), vout: 0),
        scriptSig: Data(), sequence: 0xFFFF_FFFD)
    input.witness = [Data([0x30, 0x44, 0x02, 0x20]), Data(repeating: 0x02, count: 33)]
    let output = Transaction.Output(value: 50_000,
                                    scriptPubKey: Data([0x51, 0x20] + repeatElement(0x77, count: 32)))
    return Transaction(version: 2, inputs: [input], outputs: [output], locktime: 0)
}

/// Temporary file URL that is removed on test teardown best-effort.
func tempFileURL(_ name: String) -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("winnow-tests-\(UUID().uuidString)")
        .appendingPathComponent(name)
    try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                             withIntermediateDirectories: true)
    return url
}

/// Collects BlockMatches from FilterSync's @Sendable callback.
final class MatchCollector: @unchecked Sendable {
    private(set) var matches: [BlockMatch] = []
    func add(_ match: BlockMatch) { matches.append(match) }
}

func vectorData(_ name: String) throws -> Data {
    guard let url = Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Vectors") else {
        throw VectorError.missingFile(name)
    }
    return try Data(contentsOf: url)
}

enum VectorError: Error {
    case missingFile(String)
    case malformed(String)
}
