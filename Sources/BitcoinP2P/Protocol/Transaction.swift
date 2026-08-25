import Foundation

/// Minimal raw-transaction model: enough to parse, re-serialize (with and
/// without witness) and hash. txid = SHA256d of the legacy serialization,
/// wtxid = SHA256d of the segwit serialization (BIP141/144).
public struct Transaction: Equatable, Sendable {
    public struct Outpoint: Equatable, Hashable, Sendable {
        public var txid: Data // 32 bytes, internal order
        public var vout: UInt32

        public init(txid: Data, vout: UInt32) {
            self.txid = txid
            self.vout = vout
        }
    }

    public struct Input: Equatable, Sendable {
        public var previousOutput: Outpoint
        public var scriptSig: Data
        public var sequence: UInt32
        public var witness: [Data] = []

        public init(previousOutput: Outpoint, scriptSig: Data, sequence: UInt32, witness: [Data] = []) {
            self.previousOutput = previousOutput
            self.scriptSig = scriptSig
            self.sequence = sequence
            self.witness = witness
        }
    }

    public struct Output: Equatable, Sendable {
        public var value: Int64
        public var scriptPubKey: Data

        public init(value: Int64, scriptPubKey: Data) {
            self.value = value
            self.scriptPubKey = scriptPubKey
        }
    }

    public var version: Int32
    public var inputs: [Input]
    public var outputs: [Output]
    public var locktime: UInt32

    public init(version: Int32, inputs: [Input], outputs: [Output], locktime: UInt32) {
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.locktime = locktime
    }

    public var isSegwit: Bool { inputs.contains { !$0.witness.isEmpty } }

    public func serialized(includeWitness: Bool) -> Data {
        var data = Data()
        data.appendInt32(version)
        let useWitness = includeWitness && isSegwit
        if useWitness {
            data.appendUInt8(0) // marker
            data.appendUInt8(1) // flag
        }
        data.appendCompactSize(UInt64(inputs.count))
        for input in inputs {
            data.append(input.previousOutput.txid)
            data.appendUInt32(input.previousOutput.vout)
            data.appendVarData(input.scriptSig)
            data.appendUInt32(input.sequence)
        }
        data.appendCompactSize(UInt64(outputs.count))
        for output in outputs {
            data.appendInt64(output.value)
            data.appendVarData(output.scriptPubKey)
        }
        if useWitness {
            for input in inputs {
                data.appendCompactSize(UInt64(input.witness.count))
                for item in input.witness { data.appendVarData(item) }
            }
        }
        data.appendUInt32(locktime)
        return data
    }

    /// txid in internal byte order (SHA256d of the no-witness serialization).
    public var txid: Data { SHA256d.hash(serialized(includeWitness: false)) }
    /// wtxid in internal byte order (SHA256d of the witness serialization).
    public var wtxid: Data { SHA256d.hash(serialized(includeWitness: true)) }

    /// Parses from a byte reader positioned at the transaction start; consumes
    /// exactly the transaction's bytes. Handles legacy and segwit (BIP144)
    /// serializations.
    /// The bound on a *serialized* script field.
    ///
    /// Not `MAX_SCRIPT_SIZE`. Consensus's 10,000-byte limit is enforced in
    /// `EvalScript`, when a script is *run*; it does not constrain what a
    /// transaction may carry. A transaction can create an output whose
    /// scriptPubKey is larger than that — it is simply unspendable — and the
    /// block containing it is valid. Core parses such a transaction without
    /// complaint, and a client that refuses to is the one that is wrong.
    ///
    /// Applying 10,000 here stalled a live signet scan permanently at the
    /// first block containing one: the block was rejected as a protocol
    /// violation, the peer was evicted, the next peer served the same block,
    /// and the frontier never advanced again. The only real bound is the
    /// message the reader is already working inside.
    static let maxSerializedScript = 4_000_000

    public static func decode(from reader: inout ByteReader) throws -> Transaction {
        let version = try reader.readInt32()
        var inputCount = try reader.readVarInt()
        var segwit = false
        if inputCount == 0 {
            // marker=0x00 must be followed by a nonzero flag (BIP144)
            let flag = try reader.readUInt8()
            guard flag != 0 else { throw WireError.malformed("tx flag 0") }
            segwit = true
            inputCount = try reader.readVarInt()
        }
        guard inputCount > 0 else { throw WireError.malformed("tx has no inputs") }
        // A non-witness input is ≥ 41 bytes (36 outpoint + 1 script length + 4
        // sequence), so a genuine count cannot exceed the bytes remaining. This
        // bounds the allocation against a malicious oversized compactSize — and
        // avoids Int(count) trapping — since the wire format leaves counts open.
        guard inputCount <= UInt64(reader.remaining / 41) else {
            throw WireError.malformed("tx input count \(inputCount)")
        }
        var inputs: [Input] = []
        inputs.reserveCapacity(Int(inputCount))
        for _ in 0 ..< inputCount {
            let outpoint = Outpoint(txid: try reader.readBytes(32), vout: try reader.readUInt32())
            let scriptSig = try reader.readVarData(maxLength: Self.maxSerializedScript)
            let sequence = try reader.readUInt32()
            inputs.append(Input(previousOutput: outpoint, scriptSig: scriptSig, sequence: sequence))
        }
        let outputCount = try reader.readVarInt()
        guard outputCount > 0 else { throw WireError.malformed("tx has no outputs") }
        // An output is ≥ 9 bytes (8 value + 1 script length); same bound.
        guard outputCount <= UInt64(reader.remaining / 9) else {
            throw WireError.malformed("tx output count \(outputCount)")
        }
        var outputs: [Output] = []
        outputs.reserveCapacity(Int(outputCount))
        for _ in 0 ..< outputCount {
            let value = try reader.readInt64()
            let scriptPubKey = try reader.readVarData(maxLength: Self.maxSerializedScript)
            outputs.append(Output(value: value, scriptPubKey: scriptPubKey))
        }
        if segwit {
            for index in inputs.indices {
                let itemCount = try reader.readVarInt()
                guard itemCount <= 1_000 else { throw WireError.malformed("witness items \(itemCount)") }
                for _ in 0 ..< itemCount {
                    inputs[index].witness.append(try reader.readVarData(maxLength: 4_000_000))
                }
            }
        }
        let locktime = try reader.readUInt32()
        return Transaction(version: version, inputs: inputs, outputs: outputs, locktime: locktime)
    }

    public static func decode(_ data: Data) throws -> Transaction {
        var reader = ByteReader(data)
        let tx = try decode(from: &reader)
        try reader.requireEnd()
        return tx
    }
}
