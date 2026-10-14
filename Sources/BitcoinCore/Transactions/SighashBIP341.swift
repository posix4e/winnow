import CryptoKit
import Foundation

public enum SighashError: Error, Equatable {
    /// Not 0x00, and not (0x80?) | {0x01, 0x02, 0x03} (BIP341).
    case invalidHashType(UInt8)
    case inputIndexOutOfRange(index: Int, count: Int)
    case spentOutputCountMismatch(inputs: Int, spentOutputs: Int)
    /// SIGHASH_SINGLE requires an output at the input's index.
    case singleWithoutCorrespondingOutput(index: Int)
}

/// BIP341 signature hash for Taproot spends: key-path (ext_flag = 0) and
/// script-path (ext_flag = 1, the BIP342 common signature message extension),
/// with optional annex commitment. Implements the full common signature
/// message, including the sha_prevouts / sha_amounts / sha_scriptpubkeys /
/// sha_sequences / sha_outputs precomputed hashes. Key-path mode is verified
/// against the official BIP341 wallet test vectors; script-path mode against
/// vectors generated with Bitcoin Core's test framework
/// (bip341-scriptpath-test-vectors.json).
public enum SighashBIP341 {
    /// The output spent by an input — the BIP341 sighash commits to amounts
    /// and scriptPubKeys of all spent outputs.
    public struct SpentOutput: Equatable, Sendable {
        public var amount: Int64
        public var scriptPubKey: Data

        public init(amount: Int64, scriptPubKey: Data) {
            self.amount = amount
            self.scriptPubKey = scriptPubKey
        }
    }

    /// A BIP341 hash_type byte: 0x00 SIGHASH_DEFAULT, or (0x80 ANYONECANPAY |)
    /// 0x01 ALL / 0x02 NONE / 0x03 SINGLE.
    public struct HashType: Equatable, Sendable {
        public static let `default` = HashType(rawValue: 0x00)
        public static let all = HashType(rawValue: 0x01)
        public static let none = HashType(rawValue: 0x02)
        public static let single = HashType(rawValue: 0x03)

        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// BIP341 validity: exactly 0x00, or base type ALL/NONE/SINGLE with no
        /// bits set other than ANYONECANPAY.
        public var isValid: Bool {
            rawValue == 0 || (baseType != 0 && rawValue & 0x7C == 0)
        }

        public var isAnyoneCanPay: Bool { rawValue & 0x80 != 0 }
        /// 0x01 ALL / 0x02 NONE / 0x03 SINGLE; 0 for DEFAULT (which behaves as ALL).
        public var baseType: UInt8 { rawValue & 0x03 }

        /// True only for DEFAULT and plain ALL — the two types that commit to
        /// every output (no ANYONECANPAY). This wallet signs nothing else: a
        /// spend that fails to commit to its outputs lets a PSBT counterparty
        /// rewrite them after collecting signatures.
        public var commitsToAllOutputs: Bool { rawValue == 0x00 || rawValue == 0x01 }

        public var anyoneCanPay: HashType { HashType(rawValue: rawValue | 0x80) }
    }

    /// The BIP342 common signature message extension (ext_flag = 1): the
    /// tapleaf hash, key version and code separator position appended to
    /// SigMsg for script-path spends.
    public struct ScriptPath: Equatable, Sendable {
        /// Default key version for BIP342 tapscript leaves (0x00).
        public static let tapscriptKeyVersion: UInt8 = 0x00
        /// Default code separator position: no OP_CODESEPARATOR executed.
        public static let noCodeseparator: UInt32 = 0xFFFF_FFFF

        /// H_TapLeaf(leafVersion || script) committing to the executed leaf.
        public var tapleafHash: Data
        /// 0x00 for BIP342 tapscript.
        public var keyVersion: UInt8
        /// 0xFFFFFFFF when no OP_CODESEPARATOR was executed (BIP342).
        public var codeseparatorPosition: UInt32

        public init(tapleafHash: Data, keyVersion: UInt8 = ScriptPath.tapscriptKeyVersion,
                    codeseparatorPosition: UInt32 = ScriptPath.noCodeseparator) {
            self.tapleafHash = tapleafHash
            self.keyVersion = keyVersion
            self.codeseparatorPosition = codeseparatorPosition
        }

        /// The extension for spending a tapscript leaf (default version, no
        /// executed code separator).
        public init(leafScript: Script, leafVersion: UInt8 = Taproot.leafVersion) {
            self.init(tapleafHash: Taproot.leafHash(version: leafVersion, script: leafScript))
        }
    }

    /// The precomputed sha_* hashes of the common signature message (BIP341),
    /// reusable across inputs when the hash type commits to them.
    public struct CommonHashes: Equatable, Sendable {
        public var prevouts: Data
        public var amounts: Data
        public var scriptPubKeys: Data
        public var sequences: Data
        public var outputs: Data
    }

    /// sha_prevouts / sha_amounts / sha_scriptpubkeys / sha_sequences /
    /// sha_outputs over the whole transaction (single SHA256 each, BIP341).
    public static func commonHashes(tx: Transaction, spentOutputs: [SpentOutput]) throws -> CommonHashes {
        guard tx.inputs.count == spentOutputs.count else {
            throw SighashError.spentOutputCountMismatch(inputs: tx.inputs.count, spentOutputs: spentOutputs.count)
        }
        var prevouts = Data()
        var sequences = Data()
        for input in tx.inputs {
            prevouts.append(input.previousOutput.txid)
            prevouts.appendUInt32(input.previousOutput.vout)
            sequences.appendUInt32(input.sequence)
        }
        var amounts = Data()
        var scriptPubKeys = Data()
        for output in spentOutputs {
            amounts.appendInt64(output.amount)
            scriptPubKeys.appendVarData(output.scriptPubKey)
        }
        var outputs = Data()
        for output in tx.outputs {
            outputs.appendInt64(output.value)
            outputs.appendVarData(output.scriptPubKey)
        }
        return CommonHashes(prevouts: sha256(prevouts),
                            amounts: sha256(amounts),
                            scriptPubKeys: sha256(scriptPubKeys),
                            sequences: sha256(sequences),
                            outputs: sha256(outputs))
    }

    /// The message m = 0x00 || SigMsg(hash_type, ext_flag) that is hashed for
    /// the signature (BIP341 "Common signature message"). Key-path when
    /// `scriptPath` is nil (ext_flag = 0); script-path with the BIP342
    /// extension appended when set (ext_flag = 1). `annex`, when present, is
    /// the full annex including its 0x50 prefix; it is committed as
    /// sha_annex = SHA256(compactSize(len) || annex) and sets the low bit of
    /// spend_type = ext_flag * 2 + annex_present.
    public static func signatureMessage(tx: Transaction, inputIndex: Int,
                                        spentOutputs: [SpentOutput], hashType: HashType,
                                        scriptPath: ScriptPath? = nil, annex: Data? = nil) throws -> Data {
        try checkArguments(tx: tx, inputIndex: inputIndex,
                           spentOutputs: spentOutputs, hashType: hashType)
        let common = try commonHashes(tx: tx, spentOutputs: spentOutputs)
        var message = Data([0x00]) // epoch 0
        message.appendUInt8(hashType.rawValue)
        message.appendInt32(tx.version)
        message.appendUInt32(tx.locktime)
        if !hashType.isAnyoneCanPay {
            message.append(common.prevouts)
            message.append(common.amounts)
            message.append(common.scriptPubKeys)
            message.append(common.sequences)
        }
        if hashType.baseType != HashType.none.baseType, hashType.baseType != HashType.single.baseType {
            message.append(common.outputs)
        }
        // spend_type = ext_flag * 2 + annex_present (BIP341).
        message.appendUInt8((scriptPath != nil ? 2 : 0) | (annex != nil ? 1 : 0))
        appendInputSegment(&message, tx: tx, inputIndex: inputIndex,
                           spentOutputs: spentOutputs, hashType: hashType, annex: annex)
        if hashType.baseType == HashType.single.baseType {
            guard inputIndex < tx.outputs.count else {
                throw SighashError.singleWithoutCorrespondingOutput(index: inputIndex)
            }
            var serialized = Data()
            serialized.appendInt64(tx.outputs[inputIndex].value)
            serialized.appendVarData(tx.outputs[inputIndex].scriptPubKey)
            message.append(sha256(serialized))
        }
        if let scriptPath { // BIP342 extension, appended last
            message.append(scriptPath.tapleafHash)
            message.appendUInt8(scriptPath.keyVersion)
            message.appendUInt32(scriptPath.codeseparatorPosition)
        }
        return message
    }

    /// The argument contract, checked before a single byte is assembled.
    private static func checkArguments(tx: Transaction, inputIndex: Int,
                                       spentOutputs: [SpentOutput],
                                       hashType: HashType) throws {
        guard hashType.isValid else { throw SighashError.invalidHashType(hashType.rawValue) }
        guard inputIndex >= 0, inputIndex < tx.inputs.count else {
            throw SighashError.inputIndexOutOfRange(index: inputIndex, count: tx.inputs.count)
        }
        guard tx.inputs.count == spentOutputs.count else {
            throw SighashError.spentOutputCountMismatch(inputs: tx.inputs.count, spentOutputs: spentOutputs.count)
        }
    }

    /// BIP341's per-input data, in spec order: the ANYONECANPAY outpoint
    /// fields or the input index, then the hashed annex when present.
    private static func appendInputSegment(_ message: inout Data, tx: Transaction,
                                           inputIndex: Int, spentOutputs: [SpentOutput],
                                           hashType: HashType, annex: Data?) {
        if hashType.isAnyoneCanPay {
            let input = tx.inputs[inputIndex]
            let spent = spentOutputs[inputIndex]
            message.append(input.previousOutput.txid)
            message.appendUInt32(input.previousOutput.vout)
            message.appendInt64(spent.amount)
            message.appendVarData(spent.scriptPubKey)
            message.appendUInt32(input.sequence)
        } else {
            message.appendUInt32(UInt32(inputIndex))
        }
        if let annex {
            var prefixed = Data()
            prefixed.appendVarData(annex)
            message.append(sha256(prefixed))
        }
    }

    /// The 32-byte sighash: TaggedHash("TapSighash", 0x00 || SigMsg) (BIP341).
    public static func sighash(tx: Transaction, inputIndex: Int,
                               spentOutputs: [SpentOutput], hashType: HashType = .default,
                               scriptPath: ScriptPath? = nil, annex: Data? = nil) throws -> Data {
        TaggedHash.hash("TapSighash", try signatureMessage(tx: tx, inputIndex: inputIndex,
                                                           spentOutputs: spentOutputs, hashType: hashType,
                                                           scriptPath: scriptPath, annex: annex))
    }

    private static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}
