import WalletCore
import Foundation

/// Regtest-style parameters: bits 0x207fffff gives a target near 2^255, so a
/// valid header is "mined" in ~2 nonce tries. Used to exercise HeaderChain's
/// real PoW checks without a node.
public func makeTestParams(genesis: BlockHeader, noRetargeting: Bool = false) -> NetworkParams {
    NetworkParams(
        network: .signet,
        magic: Data([0x0A, 0x03, 0xCF, 0x40]),
        defaultPort: 38333,
        genesisTime: genesis.time,
        genesisBits: genesis.bits,
        genesisNonce: genesis.nonce,
        genesisMerkleRoot: genesis.merkleRoot,
        genesisHash: genesis.hash,
        // 7fffff00…00 in display order, stored in internal (reversed) order.
        powLimit: Data(repeating: 0, count: 29) + Data([0xFF, 0xFF, 0x7F]),
        dnsSeeds: [], noRetargeting: noRetargeting
    )
}

/// The trivial-difficulty target, bits 0x207fffff, as a 256-bit big-endian
/// number: mantissa 0x7fffff in the top three bytes, zero below. A hash meets
/// it when, read as a big-endian integer, it is no larger.
private let trivialTargetBigEndian: [UInt8] = [0x7F, 0xFF, 0xFF] + [UInt8](repeating: 0, count: 29)

/// Mines a header at trivial difficulty (bits 0x207fffff).
public func minedHeader(previousHash: Data, merkleRoot: Data, time: UInt32) -> BlockHeader {
    let bits: UInt32 = 0x207F_FFFF
    var nonce: UInt32 = 0
    while true {
        let header = BlockHeader(version: 1, previousHash: previousHash, merkleRoot: merkleRoot,
                                 time: time, bits: bits, nonce: nonce)
        // The hash is little-endian; reversed, it compares as the integer.
        let hashBigEndian = Array(header.hash.reversed())
        if !trivialTargetBigEndian.lexicographicallyPrecedes(hashBigEndian) { return header }
        nonce &+= 1
    }
}

/// A synthetic, fully valid (PoW-wise) block chain for loopback tests.
public struct SyntheticChain {
    public let params: NetworkParams
    /// All blocks, height-indexed (element 0 is genesis).
    public let blocks: [Block]
    public let watchScript: Data
    public let watchHeight: UInt32
}

/// Builds a chain of single-transaction blocks; the block at `watchHeight`
/// pays to `watchScript` (a P2TR-shaped output).
public func makeSyntheticChain(length: Int = 6, watchHeight: UInt32 = 3,
                               noRetargeting: Bool = false) -> SyntheticChain {
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
    return SyntheticChain(params: makeTestParams(genesis: blocks[0].header, noRetargeting: noRetargeting),
                          blocks: blocks,
                          watchScript: watchScript,
                          watchHeight: watchHeight)
}

/// A segwit transaction with one witness item, for relay tests. `value` is a
/// parameter only so a test that needs two pending transactions can have two
/// distinct txids; every caller that does not care keeps the original one.
public func makeFakeSegwitTx(value: Int64 = 50_000) -> Transaction {
    var input = Transaction.Input(
        previousOutput: Transaction.Outpoint(txid: Data(repeating: 0x11, count: 32), vout: 0),
        scriptSig: Data(), sequence: 0xFFFF_FFFD)
    input.witness = [Data([0x30, 0x44, 0x02, 0x20]), Data(repeating: 0x02, count: 33)]
    let output = Transaction.Output(value: value,
                                    scriptPubKey: Data([0x51, 0x20] + repeatElement(0x77, count: 32)))
    return Transaction(version: 2, inputs: [input], outputs: [output], locktime: 0)
}

/// Resumes a continuation at most once: the first resume wins, later ones
/// are dropped. Wraps every checked continuation handed to a Network.framework
/// state handler — NWConnection/NWListener can still deliver a state update
/// that was already in flight when `stateUpdateHandler` was cleared, so
/// nil-ing the handler inside itself does not by itself prevent a second
/// resume (a fatal "continuation misuse" trap; seen on CI as ECONNRESET
/// delivered after .ready).
public final class ResumeOnce: @unchecked Sendable {
    private var continuation: CheckedContinuation<Void, Error>?
    private let lock = NSLock()

    public init(_ continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }

    public func resume() {
        take()?.resume()
    }

    public func resume(throwing error: Error) {
        take()?.resume(throwing: error)
    }

    private func take() -> CheckedContinuation<Void, Error>? {
        lock.lock()
        defer { lock.unlock() }
        let continuation = continuation
        self.continuation = nil
        return continuation
    }
}
