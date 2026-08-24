import Foundation
import Testing
@testable import BitcoinP2P

/// Raw transaction and block parsing, incl. the genesis coinbase txid KAT.
@Suite("Transactions & blocks")
struct TransactionTests {
    /// Mainnet genesis coinbase (raw hex, widely reproduced).
    static let genesisCoinbaseHex = """
        0100000001000000000000000000000000000000000000000000000000000000000000000\
        0ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f3230303920\
        4368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f\
        757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe554827\
        1967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e5\
        1ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000
        """

    @Test("genesis coinbase parses and its txid is the known value")
    func genesisCoinbase() throws {
        let raw = try #require(Data(hex: Self.genesisCoinbaseHex))
        let tx = try Transaction.decode(raw)
        #expect(tx.txid.displayHex ==
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
        #expect(!tx.isSegwit)
        #expect(tx.inputs.count == 1 && tx.outputs.count == 1)
        #expect(tx.outputs[0].value == 5_000_000_000)
        // Round-trip: re-serialization is byte-identical.
        #expect(tx.serialized(includeWitness: true) == raw)
    }

    @Test("segwit tx round-trips; txid excludes the witness, wtxid includes it")
    func segwitSemantics() throws {
        let tx = makeFakeSegwitTx()
        let raw = tx.serialized(includeWitness: true)
        #expect(raw[4] == 0x00 && raw[5] == 0x01) // marker + flag
        let decoded = try Transaction.decode(raw)
        #expect(decoded == tx)
        #expect(decoded.isSegwit)
        #expect(decoded.txid == SHA256d.hash(tx.serialized(includeWitness: false)))
        #expect(decoded.wtxid == SHA256d.hash(raw))
        #expect(decoded.txid != decoded.wtxid)

        // Mutating only the witness leaves the txid untouched.
        var mutated = tx
        mutated.inputs[0].witness = [Data([0x01])]
        #expect(mutated.txid == tx.txid)
        #expect(mutated.wtxid != tx.wtxid)
    }

    @Test("legacy serialization of a segwit tx has no marker/flag")
    func legacySerialization() {
        let tx = makeFakeSegwitTx()
        let legacy = tx.serialized(includeWitness: false)
        #expect(legacy[4] == 0x01) // input count directly after version
    }

    @Test("block round-trips and hashes to its header hash")
    func blockRoundTrip() throws {
        let chain = makeSyntheticChain(length: 2, watchHeight: 1)
        let block = chain.blocks[2]
        let decoded = try Block.decode(block.serialized)
        #expect(decoded == block)
        #expect(decoded.hash == block.header.hash)
        #expect(decoded.transactions[0].outputs.count == 1)
    }

    @Test("truncated transactions throw")
    func truncated() {
        let raw = makeFakeSegwitTx().serialized(includeWitness: true)
        #expect(throws: WireError.self) { _ = try Transaction.decode(raw.dropLast(3)) }
    }

    @Test("an oversized input/output count is rejected, not allocated")
    func oversizedCountsRejected() {
        // version(4) + input count varint 0xFF <2^64-1> with no input bytes:
        // must throw, never reserveCapacity(Int(2^64-1)) (which would trap).
        var payload = Data()
        payload.appendInt32(2)
        payload.append(0xFF)
        payload.appendUInt64(UInt64.max)
        #expect(throws: WireError.self) { _ = try Transaction.decode(payload) }

        // A merely-huge 4-byte count (0xFE ...) is likewise rejected up front.
        var big = Data()
        big.appendInt32(2)
        big.append(0xFE)
        big.appendUInt32(UInt32.max)
        #expect(throws: WireError.self) { _ = try Transaction.decode(big) }
    }

    @Test("empty transaction vectors fail closed")
    func emptyTransactionsRejected() {
        // SegWit marker + nonzero flag + zero vin. Accepting this used to
        // produce a value whose canonical serialization could not be parsed.
        var noInputs = Data()
        noInputs.appendInt32(2)
        noInputs.append(contentsOf: [0, 1, 0])
        noInputs.append(1) // one output (unreachable)
        noInputs.appendInt64(0)
        noInputs.append(0)
        noInputs.appendUInt32(0)
        #expect(throws: WireError.malformed("tx has no inputs")) {
            _ = try Transaction.decode(noInputs)
        }

        var noOutputs = Data()
        noOutputs.appendInt32(2)
        noOutputs.append(1)
        noOutputs.append(Data(repeating: 0, count: 32))
        noOutputs.appendUInt32(0)
        noOutputs.append(0)
        noOutputs.appendUInt32(UInt32.max)
        noOutputs.append(0)
        noOutputs.appendUInt32(0)
        #expect(throws: WireError.malformed("tx has no outputs")) {
            _ = try Transaction.decode(noOutputs)
        }
    }

    @Test("valid block merkle root verifies; a tampered tx set does not")
    func merkleRootVerification() {
        // Single-tx block: root == the sole txid (synthetic chain uses this).
        let chain = makeSyntheticChain(length: 2, watchHeight: 1)
        let good = chain.blocks[2]
        #expect(good.hasValidMerkleRoot)

        // Swap in a different block's transaction (distinct coinbase → distinct
        // txid): the header's committed root no longer matches the tx set.
        let tampered = Block(header: good.header, transactions: chain.blocks[1].transactions)
        #expect(!tampered.hasValidMerkleRoot)

        // Duplicated txids (CVE-2012-2459 shape) are rejected outright.
        let doubled = Block(header: good.header,
                            transactions: good.transactions + good.transactions)
        #expect(!doubled.hasValidMerkleRoot)
    }
    /// A serialized script may exceed `MAX_SCRIPT_SIZE`.
    ///
    /// Consensus's 10,000-byte limit is a rule about *running* a script, not
    /// about carrying one. A transaction may create an output whose
    /// scriptPubKey is larger — it is unspendable, and the block holding it is
    /// still valid. Bitcoin Core decodes such a transaction without complaint;
    /// this asserts we do too.
    ///
    /// Found by the sustained signet soak, not by reasoning: the scan reached
    /// a real block carrying a 99,919-byte script, rejected it as a protocol
    /// violation, evicted the peer, was served the same block by the next one,
    /// and never advanced again. A wallet that stops seeing its own payments
    /// at an arbitrary block is the failure this pins.
    @Test("a script larger than MAX_SCRIPT_SIZE still parses", arguments: [10_001, 99_919])
    func oversizedSerializedScript(scriptSize: Int) throws {
        var raw = Data()
        raw.append(contentsOf: [0x02, 0x00, 0x00, 0x00])          // version 2
        raw.append(0x01)                                          // 1 input
        raw.append(Data(repeating: 0, count: 32))                 // prevout txid
        raw.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF])          // prevout vout
        raw.append(0x00)                                          // empty scriptSig
        raw.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF])          // sequence
        raw.append(0x01)                                          // 1 output
        raw.append(Data(repeating: 0, count: 8))                  // value 0
        // Minimal compactSize length, then an OP_RETURN-prefixed run of that
        // size. Minimal matters: our serializer emits the shortest form, so a
        // padded length would fail the round trip for reasons unrelated to the
        // bound under test.
        if scriptSize <= 0xFFFF {
            raw.append(0xFD)
            raw.append(contentsOf: withUnsafeBytes(of: UInt16(scriptSize).littleEndian) { Data($0) })
        } else {
            raw.append(0xFE)
            raw.append(contentsOf: withUnsafeBytes(of: UInt32(scriptSize).littleEndian) { Data($0) })
        }
        raw.append(0x6A)
        raw.append(Data(repeating: 0, count: scriptSize - 1))
        raw.append(contentsOf: [0x00, 0x00, 0x00, 0x00])          // locktime

        let decoded = try Transaction.decode(raw)
        #expect(decoded.outputs.count == 1)
        #expect(decoded.outputs[0].scriptPubKey.count == scriptSize,
                "the script was truncated or refused")
        #expect(decoded.serialized(includeWitness: false) == raw, "round trip")
    }
}
