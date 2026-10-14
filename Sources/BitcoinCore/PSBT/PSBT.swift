import Foundation

public enum PSBTError: Error, Equatable, LocalizedError {
    case invalidMagic
    case truncated
    /// Keys must be unique within a map (BIP370).
    case duplicateKey(Data)
    /// PSBT versions other than BIP174 v0 and BIP370 v2 are unsupported.
    case unsupportedVersion(UInt32)
    case missingField(String)
    case malformed(String)
    case inconsistentCounts
    /// Combiner role: the same key carries different values in two PSBTs.
    case conflict(Data)

    public var errorDescription: String? {
        switch self {
        case .invalidMagic:
            "That text is not a valid PSBT."
        case .truncated:
            "The PSBT ended before all of its data could be read."
        case .duplicateKey:
            "The PSBT repeats a field that must appear only once."
        case let .unsupportedVersion(version):
            "This PSBT uses unsupported version \(version). Use PSBTv0 or PSBTv2."
        case let .missingField(field):
            "The PSBT is missing required data (\(field))."
        case let .malformed(reason):
            "The PSBT is malformed (\(reason))."
        case .inconsistentCounts:
            "The PSBT's input or output count does not match its transaction."
        case .conflict:
            "The PSBTs disagree about a field and cannot be combined safely."
        }
    }
}

/// PSBTv2 in memory, with BIP174 v0 import/export for external signers.
/// Unknown fields survive conversion and the BIP371/373 signing exchange.
public struct PSBT: Equatable, Sendable {
    /// A PSBT is an interchange document, not an arbitrary file container.
    /// Four megabytes matches Winnow's P2P payload budget and is an explicit
    /// mobile resource policy for the Taproot transaction shapes it supports.
    /// It is not a Bitcoin consensus limit on PSBT documents.
    public static let maxSerializedSize = 4_000_000
    public static let maxBase64Length = 5_333_336
    static let maxMapKeySize = 10_000
    static let maxMapPairs = 10_000
    static let maxInputOutputCount = 100_000
    /// BIP174/370 global key types.
    public enum GlobalType {
        public static let unsignedTx: UInt8 = 0x00 // v0 interchange only
        public static let txVersion: UInt8 = 0x02
        public static let fallbackLocktime: UInt8 = 0x03
        public static let inputCount: UInt8 = 0x04
        public static let outputCount: UInt8 = 0x05
        public static let version: UInt8 = 0xFB
    }

    /// BIP174/370/371/373 input key types.
    public enum InType {
        public static let witnessUTXO: UInt8 = 0x01
        public static let sighashType: UInt8 = 0x03
        public static let finalScriptWitness: UInt8 = 0x08
        public static let previousTxid: UInt8 = 0x0E
        public static let outputIndex: UInt8 = 0x0F
        public static let sequence: UInt8 = 0x10
        public static let tapKeySignature: UInt8 = 0x13
        public static let tapScriptSignature: UInt8 = 0x14
        public static let tapLeafScript: UInt8 = 0x15
        public static let tapBIP32Derivation: UInt8 = 0x16
        public static let tapInternalKey: UInt8 = 0x17
        public static let musig2ParticipantPubKeys: UInt8 = 0x1A
        public static let musig2PubNonce: UInt8 = 0x1B
        public static let musig2PartialSig: UInt8 = 0x1C
    }

    /// BIP370/371 output key types.
    public enum OutType {
        public static let amount: UInt8 = 0x03
        public static let script: UInt8 = 0x04
        public static let tapInternalKey: UInt8 = 0x05
        public static let tapTree: UInt8 = 0x06
        public static let tapBIP32Derivation: UInt8 = 0x07
    }

    /// A generic PSBT key-value pair. `key` is the type byte followed by any
    /// key data; equality and dedup are on the whole key (BIP174).
    public struct KeyValue: Equatable, Sendable {
        public var key: Data
        public var value: Data

        public init(type: UInt8, keyData: Data = Data(), value: Data) {
            key = Data([type]) + keyData
            self.value = value
        }

        public init(key: Data, value: Data) {
            self.key = key
            self.value = value
        }

        public var type: UInt8 { key.first ?? 0 }
        public var keyData: Data { key.dropFirst() }
    }

    /// BIP32 key origin for a Taproot key (BIP371 derivation value).
    public struct KeyOrigin: Equatable, Sendable {
        public var leafHashes: [Data]
        public var masterFingerprint: UInt32
        /// Full path from the fingerprint, hardened bit included per element.
        public var path: [UInt32]

        public init(leafHashes: [Data] = [], masterFingerprint: UInt32, path: [UInt32]) {
            self.leafHashes = leafHashes
            self.masterFingerprint = masterFingerprint
            self.path = path
        }
    }

    /// Identifies a PSBT_IN_TAP_SCRIPT_SIG entry: the x-only key that signed
    /// and the tapleaf hash of the script it signs for (BIP371).
    public struct TapScriptSignatureID: Hashable, Sendable {
        public var publicKey: Data // 32-byte x-only
        public var leafHash: Data

        public init(publicKey: Data, leafHash: Data) {
            self.publicKey = publicKey
            self.leafHash = leafHash
        }
    }

    /// A PSBT_IN_TAP_LEAF_SCRIPT entry (BIP371): the leaf script and its
    /// version, keyed (in the map) by the control block proving the leaf.
    public struct TapLeafScript: Equatable, Sendable {
        public var controlBlock: Taproot.ControlBlock
        public var script: Data
        public var leafVersion: UInt8

        public init(controlBlock: Taproot.ControlBlock, script: Data, leafVersion: UInt8) {
            self.controlBlock = controlBlock
            self.script = script
            self.leafVersion = leafVersion
        }

        /// H_TapLeaf for this leaf (BIP341).
        public var leafHash: Data {
            Taproot.leafHash(version: leafVersion, script: Script(script))
        }
    }

    /// Identifies a BIP373 MuSig2 nonce / partial-signature entry: the
    /// contributing participant and final signing keys (both compressed) plus the
    /// tapleaf hash when the aggregate key sits in a script (omitted for the
    /// key-path vault flow).
    public struct MuSig2KeyID: Hashable, Sendable {
        public var participant: Data // 33-byte compressed
        public var aggregate: Data // 33-byte compressed
        public var leafHash: Data?

        public init(participant: Data, aggregate: Data, leafHash: Data? = nil) {
            self.participant = participant
            self.aggregate = aggregate
            self.leafHash = leafHash
        }

        var keyData: Data {
            var data = participant + aggregate
            if let leafHash { data.append(leafHash) }
            return data
        }

        init?(keyData: Data) {
            let keyData = Data(keyData) // rebase slice indices to 0
            guard keyData.count == 66 || keyData.count == 98 else { return nil }
            participant = keyData.prefix(33)
            aggregate = keyData.subdata(in: 33 ..< 66)
            leafHash = keyData.count == 98 ? keyData.suffix(32) : nil
        }
    }

    public struct Input: Equatable, Sendable {
        public var pairs: [KeyValue]

        public init(pairs: [KeyValue] = []) {
            self.pairs = pairs
        }

        func pair(type: UInt8, keyData: Data = Data()) -> KeyValue? {
            pairs.first { $0.type == type && $0.keyData == keyData }
        }

        mutating func set(_ pair: KeyValue) {
            if let index = pairs.firstIndex(where: { $0.key == pair.key }) {
                pairs[index] = pair
            } else {
                // Keys stay sorted (canonical order) so in-memory and wire
                // order always agree.
                let position = pairs.firstIndex(where: { !$0.key.lexicographicallyPrecedes(pair.key) }) ?? pairs.count
                pairs.insert(pair, at: position)
            }
        }

        /// Drops the pair. A field set to nil is absent on the wire, not
        /// present with an empty or zero value that the parser rejects or,
        /// for an index or amount, silently reads as 0.
        mutating func remove(type: UInt8, keyData: Data = Data()) {
            pairs.removeAll { $0.type == type && $0.keyData == keyData }
        }

        /// PSBT_IN_PREVIOUS_TXID — 32 bytes, internal byte order.
        public var previousTxid: Data? {
            get {
                guard let value = pair(type: InType.previousTxid)?.value,
                      value.count == 32 else { return nil }
                return value
            }
            set {
                guard let newValue else { remove(type: InType.previousTxid); return }
                set(KeyValue(type: InType.previousTxid, value: newValue))
            }
        }

        /// PSBT_IN_OUTPUT_INDEX — uint32 LE.
        public var outputIndex: UInt32? {
            get {
                guard let value = pair(type: InType.outputIndex)?.value,
                      value.count == MemoryLayout<UInt32>.size else { return nil }
                return value.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
            }
            set {
                guard let newValue else { remove(type: InType.outputIndex); return }
                var value = Data()
                value.appendUInt32(newValue)
                set(KeyValue(type: InType.outputIndex, value: value))
            }
        }

        /// PSBT_IN_SEQUENCE — uint32 LE.
        public var sequence: UInt32? {
            get {
                guard let value = pair(type: InType.sequence)?.value,
                      value.count == MemoryLayout<UInt32>.size else { return nil }
                return value.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
            }
            set {
                guard let newValue else { remove(type: InType.sequence); return }
                var value = Data()
                value.appendUInt32(newValue)
                set(KeyValue(type: InType.sequence, value: value))
            }
        }

        /// PSBT_IN_SIGHASH_TYPE — uint32 LE (BIP341 hash_type).
        public var sighashType: UInt32? {
            get {
                guard let value = pair(type: InType.sighashType)?.value,
                      value.count == MemoryLayout<UInt32>.size else { return nil }
                return value.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
            }
            set {
                guard let newValue else { remove(type: InType.sighashType); return }
                var value = Data()
                value.appendUInt32(newValue)
                set(KeyValue(type: InType.sighashType, value: value))
            }
        }

        /// PSBT_IN_WITNESS_UTXO — int64 amount + compactSize script (CTxOut).
        public var witnessUTXO: SighashBIP341.SpentOutput? {
            get {
                guard let value = pair(type: InType.witnessUTXO)?.value else { return nil }
                var reader = ByteReader(value)
                guard let amount = try? reader.readInt64(),
                      let script = try? reader.readVarData(), reader.remaining == 0 else { return nil }
                return SighashBIP341.SpentOutput(amount: amount, scriptPubKey: script)
            }
            set {
                guard let newValue else { remove(type: InType.witnessUTXO); return }
                var value = Data()
                value.appendInt64(newValue.amount)
                value.appendVarData(newValue.scriptPubKey)
                set(KeyValue(type: InType.witnessUTXO, value: value))
            }
        }

        /// PSBT_IN_TAP_INTERNAL_KEY — 32-byte x-only key (BIP371).
        public var tapInternalKey: Data? {
            get { pair(type: InType.tapInternalKey)?.value }
            set {
                guard let newValue else { remove(type: InType.tapInternalKey); return }
                set(KeyValue(type: InType.tapInternalKey, value: newValue))
            }
        }

        /// PSBT_IN_TAP_KEY_SIG — 64-byte sig, or 65 with the sighash byte (BIP371).
        public var tapKeySignature: Data? {
            get { pair(type: InType.tapKeySignature)?.value }
            set {
                guard let newValue else { remove(type: InType.tapKeySignature); return }
                set(KeyValue(type: InType.tapKeySignature, value: newValue))
            }
        }

        /// PSBT_IN_TAP_BIP32_DERIVATION — keyed by the x-only pubkey (BIP371).
        public var tapBIP32Derivation: [Data: KeyOrigin] {
            get {
                var result: [Data: KeyOrigin] = [:]
                for pair in pairs where pair.type == InType.tapBIP32Derivation {
                    guard pair.keyData.count == 32 else { continue }
                    var reader = ByteReader(pair.value)
                    guard let count = try? reader.readVarInt(),
                          count <= UInt64(reader.remaining / 32) else { continue }
                    var leafHashes: [Data] = []
                    for _ in 0 ..< count {
                        guard let hash = try? reader.readBytes(32) else { break }
                        leafHashes.append(hash)
                    }
                    guard let fingerprint = try? reader.readUInt32() else { continue }
                    var path: [UInt32] = []
                    while reader.remaining >= 4 {
                        guard let step = try? reader.readUInt32() else { break }
                        path.append(step)
                    }
                    result[pair.keyData] = KeyOrigin(leafHashes: leafHashes,
                                                     masterFingerprint: fingerprint.bigEndian, path: path)
                }
                return result
            }
            set {
                pairs.removeAll { $0.type == InType.tapBIP32Derivation }
                for (pubkey, origin) in newValue.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }) {
                    var value = Data()
                    value.appendCompactSize(UInt64(origin.leafHashes.count))
                    for hash in origin.leafHashes { value.append(hash) }
                    value.appendUInt32(origin.masterFingerprint.bigEndian)
                    for step in origin.path { value.appendUInt32(step) }
                    set(KeyValue(type: InType.tapBIP32Derivation, keyData: pubkey, value: value))
                }
            }
        }

        /// PSBT_IN_FINAL_SCRIPTWITNESS — compactSize item count + var items.
        public var finalScriptWitness: [Data]? {
            get {
                guard let value = pair(type: InType.finalScriptWitness)?.value else { return nil }
                var reader = ByteReader(value)
                guard let count = try? reader.readVarInt() else { return nil }
                var items: [Data] = []
                for _ in 0 ..< count {
                    guard let item = try? reader.readVarData() else { return nil }
                    items.append(item)
                }
                return items
            }
            set {
                guard let newValue else { remove(type: InType.finalScriptWitness); return }
                var value = Data()
                value.appendCompactSize(UInt64(newValue.count))
                for item in newValue { value.appendVarData(item) }
                set(KeyValue(type: InType.finalScriptWitness, value: value))
            }
        }

        /// PSBT_IN_TAP_LEAF_SCRIPT — keyed by the control block; the value is
        /// the leaf script followed by its leaf version byte (BIP371).
        public var tapLeafScripts: [TapLeafScript] {
            get {
                pairs.compactMap { pair in
                    guard pair.type == InType.tapLeafScript,
                          let controlBlock = try? Taproot.ControlBlock(serialized: Data(pair.keyData)),
                          pair.value.count >= 1
                    else { return nil }
                    return TapLeafScript(controlBlock: controlBlock,
                                         script: pair.value.dropLast(),
                                         leafVersion: pair.value.last!)
                }
            }
            set {
                pairs.removeAll { $0.type == InType.tapLeafScript }
                for leaf in newValue.sorted(by: { $0.controlBlock.serialized.lexicographicallyPrecedes($1.controlBlock.serialized) }) {
                    var value = leaf.script
                    value.appendUInt8(leaf.leafVersion)
                    set(KeyValue(type: InType.tapLeafScript, keyData: leaf.controlBlock.serialized, value: value))
                }
            }
        }

        /// PSBT_IN_TAP_SCRIPT_SIG — keyed by x-only pubkey ‖ tapleaf hash;
        /// the 64-byte (65 with sighash byte) script-path signature (BIP371).
        public var tapScriptSignatures: [TapScriptSignatureID: Data] {
            get {
                var result: [TapScriptSignatureID: Data] = [:]
                for pair in pairs where pair.type == InType.tapScriptSignature {
                    let keyData = Data(pair.keyData)
                    guard keyData.count == 64 else { continue }
                    result[TapScriptSignatureID(publicKey: keyData.prefix(32),
                                                leafHash: keyData.suffix(32))] = pair.value
                }
                return result
            }
            set {
                pairs.removeAll { $0.type == InType.tapScriptSignature }
                for (id, signature) in newValue.sorted(by: { ($0.key.publicKey + $0.key.leafHash)
                    .lexicographicallyPrecedes($1.key.publicKey + $1.key.leafHash) }) {
                    set(KeyValue(type: InType.tapScriptSignature,
                                 keyData: id.publicKey + id.leafHash, value: signature))
                }
            }
        }

        /// PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS — keyed by the 33-byte
        /// compressed aggregate key; the value is the concatenated compressed
        /// participant keys in aggregation order (BIP373).
        public var musig2ParticipantPubKeys: [Data: [Data]] {
            get {
                var result: [Data: [Data]] = [:]
                for pair in pairs where pair.type == InType.musig2ParticipantPubKeys {
                    let aggregate = Data(pair.keyData)
                    guard aggregate.count == 33, pair.value.count % 33 == 0, !pair.value.isEmpty else { continue }
                    result[aggregate] = stride(from: pair.value.startIndex, to: pair.value.endIndex, by: 33)
                        .map { pair.value.subdata(in: $0 ..< $0 + 33) }
                }
                return result
            }
            set {
                pairs.removeAll { $0.type == InType.musig2ParticipantPubKeys }
                for (aggregate, participants) in newValue.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }) {
                    set(KeyValue(type: InType.musig2ParticipantPubKeys, keyData: aggregate,
                                 value: participants.reduce(Data(), +)))
                }
            }
        }

        /// PSBT_IN_MUSIG2_PUB_NONCE — 66-byte public nonces keyed by
        /// participant ‖ aggregate (‖ optional tapleaf hash) (BIP373).
        public var musig2PubNonces: [MuSig2KeyID: Data] {
            get { muSig2Values(type: InType.musig2PubNonce) }
            set { setMuSig2Values(type: InType.musig2PubNonce, newValue) }
        }

        /// PSBT_IN_MUSIG2_PARTIAL_SIG — 32-byte partial signatures keyed by
        /// participant ‖ aggregate (‖ optional tapleaf hash) (BIP373).
        public var musig2PartialSigs: [MuSig2KeyID: Data] {
            get { muSig2Values(type: InType.musig2PartialSig) }
            set { setMuSig2Values(type: InType.musig2PartialSig, newValue) }
        }

        private func muSig2Values(type: UInt8) -> [MuSig2KeyID: Data] {
            var result: [MuSig2KeyID: Data] = [:]
            for pair in pairs where pair.type == type {
                guard let id = MuSig2KeyID(keyData: pair.keyData) else { continue }
                result[id] = pair.value
            }
            return result
        }

        private mutating func setMuSig2Values(type: UInt8, _ values: [MuSig2KeyID: Data]) {
            pairs.removeAll { $0.type == type }
            for (id, value) in values.sorted(by: { $0.key.keyData.lexicographicallyPrecedes($1.key.keyData) }) {
                set(KeyValue(type: type, keyData: id.keyData, value: value))
            }
        }
    }

    public struct Output: Equatable, Sendable {
        public var pairs: [KeyValue]

        public init(pairs: [KeyValue] = []) {
            self.pairs = pairs
        }

        func pair(type: UInt8, keyData: Data = Data()) -> KeyValue? {
            pairs.first { $0.type == type && $0.keyData == keyData }
        }

        mutating func set(_ pair: KeyValue) {
            if let index = pairs.firstIndex(where: { $0.key == pair.key }) {
                pairs[index] = pair
            } else {
                // Keys stay sorted (canonical order) so in-memory and wire
                // order always agree.
                let position = pairs.firstIndex(where: { !$0.key.lexicographicallyPrecedes(pair.key) }) ?? pairs.count
                pairs.insert(pair, at: position)
            }
        }

        /// Drops the pair. A field set to nil is absent on the wire, not
        /// present with an empty or zero value that the parser rejects or,
        /// for an index or amount, silently reads as 0.
        mutating func remove(type: UInt8, keyData: Data = Data()) {
            pairs.removeAll { $0.type == type && $0.keyData == keyData }
        }

        /// PSBT_OUT_AMOUNT — int64 LE sats (BIP370).
        public var amount: Int64? {
            get {
                guard let value = pair(type: OutType.amount)?.value,
                      value.count == MemoryLayout<Int64>.size else { return nil }
                return value.withUnsafeBytes { $0.loadUnaligned(as: Int64.self).littleEndian }
            }
            set {
                guard let newValue else { remove(type: OutType.amount); return }
                var value = Data()
                value.appendInt64(newValue)
                set(KeyValue(type: OutType.amount, value: value))
            }
        }

        /// PSBT_OUT_SCRIPT — raw script bytes (BIP370).
        public var script: Data? {
            get { pair(type: OutType.script)?.value }
            set {
                guard let newValue else { remove(type: OutType.script); return }
                set(KeyValue(type: OutType.script, value: newValue))
            }
        }

        /// PSBT_OUT_TAP_INTERNAL_KEY — 32-byte x-only key (BIP371).
        public var tapInternalKey: Data? {
            get { pair(type: OutType.tapInternalKey)?.value }
            set {
                guard let newValue else { remove(type: OutType.tapInternalKey); return }
                set(KeyValue(type: OutType.tapInternalKey, value: newValue))
            }
        }

        /// PSBT_OUT_TAP_BIP32_DERIVATION — keyed by the x-only pubkey (BIP371).
        public var tapBIP32Derivation: [Data: KeyOrigin] {
            get {
                var result: [Data: KeyOrigin] = [:]
                for pair in pairs where pair.type == OutType.tapBIP32Derivation {
                    guard pair.keyData.count == 32 else { continue }
                    var reader = ByteReader(pair.value)
                    guard let count = try? reader.readVarInt(),
                          count <= UInt64(reader.remaining / 32) else { continue }
                    var leafHashes: [Data] = []
                    for _ in 0 ..< count {
                        guard let hash = try? reader.readBytes(32) else { break }
                        leafHashes.append(hash)
                    }
                    guard let fingerprint = try? reader.readUInt32() else { continue }
                    var path: [UInt32] = []
                    while reader.remaining >= 4 {
                        guard let step = try? reader.readUInt32() else { break }
                        path.append(step)
                    }
                    result[pair.keyData] = KeyOrigin(leafHashes: leafHashes,
                                                     masterFingerprint: fingerprint.bigEndian, path: path)
                }
                return result
            }
            set {
                pairs.removeAll { $0.type == OutType.tapBIP32Derivation }
                for (pubkey, origin) in newValue.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }) {
                    var value = Data()
                    value.appendCompactSize(UInt64(origin.leafHashes.count))
                    for hash in origin.leafHashes { value.append(hash) }
                    value.appendUInt32(origin.masterFingerprint.bigEndian)
                    for step in origin.path { value.appendUInt32(step) }
                    set(KeyValue(type: OutType.tapBIP32Derivation, keyData: pubkey, value: value))
                }
            }
        }

        /// PSBT_OUT_TAP_TREE — the output's script tree as a sequence of
        /// depth ‖ leaf version ‖ compactSize length ‖ script tuples (BIP371),
        /// letting recipients verify the output commits to the vault's leaves.
        public var tapTree: [(depth: UInt8, leafVersion: UInt8, script: Data)]? {
            get {
                guard let value = pair(type: OutType.tapTree)?.value else { return nil }
                var reader = ByteReader(value)
                var tuples: [(UInt8, UInt8, Data)] = []
                while reader.remaining > 0 {
                    guard let depth = try? reader.readUInt8(),
                          let leafVersion = try? reader.readUInt8(),
                          let script = try? reader.readVarData()
                    else { return nil }
                    tuples.append((depth, leafVersion, script))
                }
                return tuples
            }
            set {
                guard let newValue else {
                    pairs.removeAll { $0.type == OutType.tapTree }
                    return
                }
                var value = Data()
                for tuple in newValue {
                    value.appendUInt8(tuple.depth)
                    value.appendUInt8(tuple.leafVersion)
                    value.appendVarData(tuple.script)
                }
                set(KeyValue(type: OutType.tapTree, value: value))
            }
        }
    }

    public var globals: [KeyValue]
    public var inputs: [Input]
    public var outputs: [Output]

    public init(globals: [KeyValue], inputs: [Input], outputs: [Output]) {
        self.globals = globals
        self.inputs = inputs
        self.outputs = outputs
    }

    func globalPair(type: UInt8) -> KeyValue? {
        globals.first { $0.type == type }
    }

    /// PSBT_GLOBAL_VERSION — must be 2 (BIP370).
    public var version: UInt32? {
        guard let value = globalPair(type: GlobalType.version)?.value, value.count == 4 else { return nil }
        return value.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
    }

    /// PSBT_GLOBAL_TX_VERSION — int32 LE, defaults to 2 (BIP370).
    public var txVersion: Int32 {
        guard let value = globalPair(type: GlobalType.txVersion)?.value, value.count == 4 else { return 2 }
        return value.withUnsafeBytes { $0.loadUnaligned(as: Int32.self).littleEndian }
    }

    /// PSBT_GLOBAL_FALLBACK_LOCKTIME — uint32 LE, defaults to 0 (BIP370).
    public var fallbackLocktime: UInt32 {
        guard let value = globalPair(type: GlobalType.fallbackLocktime)?.value, value.count == 4 else { return 0 }
        return value.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
    }

    // MARK: - Serialization (BIP174/BIP370 wire format)

    /// "psbt" + 0xFF magic, then the global map, one map per input and output;
    /// maps are length-prefixed key/value sequences terminated by a zero key
    /// length. Keys are sorted (canonical BIP370 ordering).
    public var serialized: Data {
        var data = Data([0x70, 0x73, 0x62, 0x74, 0xFF])
        serializeMap(globals, into: &data)
        for input in inputs { serializeMap(input.pairs, into: &data) }
        for output in outputs { serializeMap(output.pairs, into: &data) }
        return data
    }

    /// Base64 form (the standard PSBT interchange encoding).
    public var base64: String { serialized.base64EncodedString() }

    /// BIP174 envelope for Bitcoin Core and other v0 signers. Signing fields
    /// stay intact; only the transaction's representation changes.
    public func base64V0() throws -> String {
        // Validate before dropping v2 fields; never export ambiguous locktime
        // requirements that unsignedTransaction() does not implement.
        let checked = try PSBT(serialized: serialized)
        guard !checked.inputs.contains(where: { input in
            input.pairs.contains { $0.type == 0x11 || $0.type == 0x12 }
        }) else { throw PSBTError.malformed("per-input locktime requirements are unsupported") }
        let unsigned = try checked.unsignedTransaction().serialized(includeWitness: false)
        var data = Data([0x70, 0x73, 0x62, 0x74, 0xFF])
        var globals = checked.globals.filter { ![UInt8(0x02), 0x03, 0x04, 0x05, 0x06, 0xFB].contains($0.type) }
        globals.append(KeyValue(type: GlobalType.unsignedTx, value: unsigned))
        serializeMap(globals, into: &data)
        for input in checked.inputs {
            serializeMap(input.pairs.filter { ![UInt8(0x0E), 0x0F, 0x10].contains($0.type) }, into: &data)
        }
        for output in checked.outputs {
            serializeMap(output.pairs.filter { ![UInt8(0x03), 0x04].contains($0.type) }, into: &data)
        }
        return data.base64EncodedString()
    }

    private func serializeMap(_ pairs: [KeyValue], into data: inout Data) {
        for pair in pairs.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }) {
            data.appendCompactSize(UInt64(pair.key.count))
            data.append(pair.key)
            data.appendCompactSize(UInt64(pair.value.count))
            data.append(pair.value)
        }
        data.appendUInt8(0) // map separator
    }

    /// Parses either envelope, normalizing v0 transaction fields to v2.
    public init(serialized data: Data) throws {
        guard data.count <= Self.maxSerializedSize else {
            throw PSBTError.malformed("document exceeds \(Self.maxSerializedSize) bytes")
        }
        var reader = ByteReader(data)
        let magic = try reader.readBytes(5)
        guard magic == Data([0x70, 0x73, 0x62, 0x74, 0xFF]) else { throw PSBTError.invalidMagic }

        func readMap() throws -> [KeyValue] {
            var pairs: [KeyValue] = []
            var seenKeys = Set<Data>()
            while true {
                let keyLength = try reader.readVarInt()
                guard keyLength > 0 else {
                    // PSBT maps are unordered on the wire. Normalize once at
                    // the boundary so equality, review snapshots, and later
                    // mutation do not depend on an attacker's field order.
                    return pairs.sorted { $0.key.lexicographicallyPrecedes($1.key) }
                }
                guard pairs.count < Self.maxMapPairs else {
                    throw PSBTError.malformed("map exceeds \(Self.maxMapPairs) fields")
                }
                guard keyLength <= UInt64(Self.maxMapKeySize),
                      keyLength <= UInt64(reader.remaining)
                else { throw PSBTError.malformed("map key length \(keyLength) is out of bounds") }
                let key = try reader.readBytes(Int(keyLength))
                let valueLength = try reader.readVarInt()
                guard valueLength <= UInt64(reader.remaining) else {
                    throw PSBTError.malformed("map value length \(valueLength) is out of bounds")
                }
                let value = try reader.readBytes(Int(valueLength))
                guard seenKeys.insert(key).inserted else { throw PSBTError.duplicateKey(key) }
                pairs.append(KeyValue(key: key, value: value))
            }
        }

        let globals = try readMap()
        func global(_ type: UInt8) -> KeyValue? { globals.first { $0.type == type } }
        let unsigned = try Self.unsignedV0Transaction(globals: globals)

        func count(_ type: UInt8) throws -> Int {
            guard let pair = global(type) else { throw PSBTError.missingField("global \(type)") }
            var valueReader = ByteReader(pair.value)
            let count = try valueReader.readVarInt()
            try valueReader.requireEnd()
            guard count <= UInt64(Self.maxInputOutputCount) else {
                throw PSBTError.malformed("input/output count \(count) exceeds \(Self.maxInputOutputCount)")
            }
            return Int(count)
        }
        let inputCount = try unsigned?.inputs.count ?? count(GlobalType.inputCount)
        let outputCount = try unsigned?.outputs.count ?? count(GlobalType.outputCount)
        var inputs: [Input] = []
        var outputs: [Output] = []
        for _ in 0 ..< inputCount { inputs.append(Input(pairs: try readMap())) }
        for _ in 0 ..< outputCount { outputs.append(Output(pairs: try readMap())) }
        try reader.requireEnd()
        try Self.validateKnownFields(globals: globals, inputs: inputs, outputs: outputs)
        if let unsigned {
            try self.init(v0: unsigned, globals: globals, inputs: inputs, outputs: outputs)
        } else {
            self.init(globals: globals, inputs: inputs, outputs: outputs)
        }
    }

    private static func unsignedV0Transaction(globals: [KeyValue]) throws -> Transaction? {
        func global(_ type: UInt8) -> KeyValue? { globals.first { $0.type == type } }
        let versionPair = global(GlobalType.version)
        guard versionPair == nil || versionPair?.value.count == 4 else {
            throw PSBTError.malformed("global version must be four bytes")
        }
        let version = versionPair?.value.withUnsafeBytes {
            $0.loadUnaligned(as: UInt32.self).littleEndian
        } ?? 0
        guard version == 0 || version == 2 else { throw PSBTError.unsupportedVersion(version) }
        if version == 0 {
            guard !globals.contains(where: { (0x02 ... 0x06).contains($0.type) }) else {
                throw PSBTError.malformed("v0 contains v2 transaction fields")
            }
            guard let pair = global(GlobalType.unsignedTx), pair.key.count == 1 else {
                throw PSBTError.missingField("v0 unsigned transaction")
            }
            let tx = try Transaction.decode(pair.value)
            guard tx.inputs.count <= Self.maxInputOutputCount,
                  tx.outputs.count <= Self.maxInputOutputCount,
                  tx.inputs.allSatisfy({ $0.scriptSig.isEmpty && $0.witness.isEmpty }),
                  tx.serialized(includeWitness: false) == pair.value else {
                throw PSBTError.malformed("v0 requires an unsigned non-witness transaction")
            }
            return tx
        } else if global(GlobalType.unsignedTx) != nil {
            throw PSBTError.malformed("v2 contains a v0 unsigned transaction")
        }

        return nil
    }

    private init(v0 unsigned: Transaction, globals: [KeyValue], inputs: [Input], outputs: [Output]) throws {
        var globals = globals
        var inputs = inputs
        var outputs = outputs
        guard !inputs.contains(where: { $0.pairs.contains { (0x0E ... 0x12).contains($0.type) } }),
              !outputs.contains(where: { $0.pairs.contains { $0.type == 0x03 || $0.type == 0x04 } }) else {
            throw PSBTError.malformed("v0 contains v2 input/output fields")
        }
        globals.removeAll { $0.type == GlobalType.unsignedTx || $0.type == GlobalType.version }
        globals += [KeyValue(type: GlobalType.version, value: Self.uint32le(2)),
                    KeyValue(type: GlobalType.txVersion, value: Self.int32le(unsigned.version)),
                    KeyValue(type: GlobalType.fallbackLocktime, value: Self.uint32le(unsigned.locktime)),
                    KeyValue(type: GlobalType.inputCount, value: Self.compactSize(UInt64(unsigned.inputs.count))),
                    KeyValue(type: GlobalType.outputCount, value: Self.compactSize(UInt64(unsigned.outputs.count)))]
        for (index, input) in unsigned.inputs.enumerated() {
            inputs[index].pairs += [KeyValue(type: InType.previousTxid, value: input.previousOutput.txid),
                                    KeyValue(type: InType.outputIndex, value: Self.uint32le(input.previousOutput.vout)),
                                    KeyValue(type: InType.sequence, value: Self.uint32le(input.sequence))]
            inputs[index].pairs.sort { $0.key.lexicographicallyPrecedes($1.key) }
        }
        for (index, output) in unsigned.outputs.enumerated() {
            outputs[index].pairs += [KeyValue(type: OutType.amount, value: Self.int64le(output.value)),
                                     KeyValue(type: OutType.script, value: output.scriptPubKey)]
            outputs[index].pairs.sort { $0.key.lexicographicallyPrecedes($1.key) }
        }
        globals.sort { $0.key.lexicographicallyPrecedes($1.key) }
        self.init(globals: globals, inputs: inputs, outputs: outputs)
    }

    public init(base64: String) throws {
        guard base64.utf8.count <= Self.maxBase64Length else {
            throw PSBTError.malformed("Base64 text exceeds \(Self.maxBase64Length) bytes")
        }
        guard let data = Data(base64Encoded: base64) else { throw PSBTError.invalidMagic }
        try self.init(serialized: data)
    }

    private static func validateKnownFields(globals: [KeyValue], inputs: [Input],
                                            outputs: [Output]) throws {
        func requireSingleton(_ pair: KeyValue, length: Int? = nil, name: String) throws {
            guard pair.key.count == 1 else {
                throw PSBTError.malformed("\(name) must not carry key data")
            }
            if let length, pair.value.count != length {
                throw PSBTError.malformed("\(name) must be \(length) bytes")
            }
        }

        for pair in globals {
            switch pair.type {
            case GlobalType.unsignedTx:
                try requireSingleton(pair, name: "unsigned transaction")
            case GlobalType.version, GlobalType.txVersion, GlobalType.fallbackLocktime:
                try requireSingleton(pair, length: 4, name: "global field \(pair.type)")
            case GlobalType.inputCount, GlobalType.outputCount:
                try requireSingleton(pair, name: "global field \(pair.type)")
            default:
                break
            }
        }

        for input in inputs {
            for pair in input.pairs {
                switch pair.type {
                case InType.previousTxid:
                    try requireSingleton(pair, length: 32, name: "previous transaction ID")
                case InType.outputIndex, InType.sequence, InType.sighashType:
                    try requireSingleton(pair, length: 4, name: "input field \(pair.type)")
                case InType.tapInternalKey:
                    try requireSingleton(pair, length: 32, name: "Taproot internal key")
                case InType.tapKeySignature:
                    try requireSingleton(pair, name: "Taproot key signature")
                    guard pair.value.count == 64 || pair.value.count == 65 else {
                        throw PSBTError.malformed("Taproot key signature must be 64 or 65 bytes")
                    }
                case InType.witnessUTXO, InType.finalScriptWitness:
                    try requireSingleton(pair, name: "input field \(pair.type)")
                default:
                    break
                }
            }
        }

        for output in outputs {
            for pair in output.pairs {
                switch pair.type {
                case OutType.amount:
                    try requireSingleton(pair, length: 8, name: "output amount")
                case OutType.tapInternalKey:
                    try requireSingleton(pair, length: 32, name: "output Taproot internal key")
                case OutType.script, OutType.tapTree:
                    try requireSingleton(pair, name: "output field \(pair.type)")
                default:
                    break
                }
            }
        }
    }
}
