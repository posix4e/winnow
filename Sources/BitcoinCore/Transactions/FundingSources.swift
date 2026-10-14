import CryptoKit
import Foundation

/// Best-effort identification of the addresses that funded a transaction,
/// reconstructed only from data the transaction itself reveals.
///
/// A Bitcoin transaction names no sender. What it carries per input is the
/// data that satisfied the spent output's locking script — and for most
/// script types that data *reveals the spent script itself*, which is an
/// address the funder once gave out. The reconstruction never touches the
/// network: peers cannot serve arbitrary confirmed prevouts (no txindex
/// serving), which is why the app offers an explicit, warned explorer lookup
/// for the inputs that stay opaque.
///
/// Opaque by construction:
/// - Taproot key-path inputs (witness = one Schnorr signature) reveal
///   nothing about the spent key.
/// - Legacy bare-pubkey and bare-multisig inputs reveal no address either:
///   their scripts live only in the spent output.
///
/// A reconstructed address is "the address that funded this input", never
/// proof of who controls it — exchanges, coinjoins and multisig wallets all
/// fund payments from addresses that do not identify the payer. The app
/// presents it with that warning.
public enum FundingSources {
    /// How one input's spent script was reconstructed, or why it was not.
    public enum Revelation: Equatable, Sendable {
        /// scriptSig = `<signature> <public key>` → P2PKH.
        case publicKeyHash
        /// scriptSig's last push is the redeem script → P2SH (incl. wrapped
        /// segwit, whose funding address is the P2SH wrapper).
        case scriptHash
        /// witness = `<signature> <public key>` → P2WPKH.
        case witnessKeyHash
        /// witness's last item is the witness script → P2WSH.
        case witnessScriptHash
        /// witness ends in tapscript + control block → the P2TR output key is
        /// recomputed from internal key, merkle path and leaf (BIP341).
        case taprootScriptPath
        /// Block reward input: no funder.
        case coinbase
        /// Witness is a single Schnorr signature (BIP341 key path): the spent
        /// key appears nowhere in the transaction.
        case taprootKeyPath
        /// The data matches no standard shape (bare P2PK, bare multisig,
        /// exotic scripts): nothing to reconstruct.
        case unrecognized
    }

    /// One input's funding source.
    public struct Source: Equatable, Sendable {
        public var inputIndex: Int
        public var revelation: Revelation
        /// The reconstructed spent script, when the revelation carries one.
        public var scriptPubKey: Data?

        public init(inputIndex: Int, revelation: Revelation, scriptPubKey: Data?) {
            self.inputIndex = inputIndex
            self.revelation = revelation
            self.scriptPubKey = scriptPubKey
        }
    }

    /// Per-input reconstruction, in input order.
    public static func sources(of transaction: Transaction) -> [Source] {
        transaction.inputs.enumerated().map { index, input in
            let (revelation, script) = revelation(of: input)
            return Source(inputIndex: index, revelation: revelation, scriptPubKey: script)
        }
    }

    /// The distinct revealed funding scripts, in first-seen order.
    public static func fundingScripts(of transaction: Transaction) -> [Data] {
        var seen: [Data] = []
        for input in transaction.inputs {
            let (_, script) = revelation(of: input)
            if let script, !seen.contains(script) { seen.append(script) }
        }
        return seen
    }

    // MARK: - Classification

    private static func revelation(of input: Transaction.Input) -> (Revelation, Data?) {
        if input.previousOutput.txid == Data(repeating: 0, count: 32),
           input.previousOutput.vout == 0xFFFF_FFFF {
            return (.coinbase, nil)
        }
        // A non-empty scriptSig spends a legacy output: P2PKH, P2SH (whose
        // wrapper is the funding address even when it wraps segwit), or
        // something address-less. Native segwit spends carry an empty one.
        if !input.scriptSig.isEmpty {
            return legacyRevelation(scriptSig: input.scriptSig)
        }
        guard !input.witness.isEmpty else { return (.unrecognized, nil) }
        return segwitRevelation(witness: input.witness)
    }

    private static func legacyRevelation(scriptSig: Data) -> (Revelation, Data?) {
        guard let items = pushedItems(scriptSig), let last = items.last else {
            return (.unrecognized, nil)
        }
        if items.count == 2, looksLikeSignature(items[0]), looksLikePublicKey(items[1]) {
            return (.publicKeyHash, Data([0x76, 0xA9, 0x14]) + Hash160.hash(items[1]) + Data([0x88, 0xAC]))
        }
        // Bare P2PK (a lone signature) and bare multisig (dummy + signatures)
        // reveal no script; a redeem script is neither sig- nor key-shaped.
        if !last.isEmpty, !looksLikeSignature(last), !looksLikePublicKey(last) {
            return (.scriptHash, Data([0xA9, 0x14]) + Hash160.hash(last) + Data([0x87]))
        }
        return (.unrecognized, nil)
    }

    private static func segwitRevelation(witness full: [Data]) -> (Revelation, Data?) {
        // BIP341 annex, when present, is the last item and starts with 0x50.
        // It exists only for taproot spends, so strip it only when the rest
        // then reads as taproot; a v0 witness script that happens to begin
        // with 0x50 must not be eaten.
        if full.count >= 2, full.last?.first == 0x50 {
            let trimmed = Array(full.dropLast())
            let (revelation, script) = classify(trimmed)
            if revelation == .taprootKeyPath || revelation == .taprootScriptPath {
                return (revelation, script)
            }
        }
        return classify(full)
    }

    private static func classify(_ witness: [Data]) -> (Revelation, Data?) {
        if witness.count == 2, looksLikeSignature(witness[0]), looksLikePublicKey(witness[1]) {
            return (.witnessKeyHash, Data([0x00, 0x14]) + Hash160.hash(witness[1]))
        }
        if witness.count == 1, witness[0].count == 64 || witness[0].count == 65 {
            return (.taprootKeyPath, nil)
        }
        if witness.count >= 2, let taproot = taprootScriptPath(witness: witness) {
            return taproot
        }
        if let script = witness.last, !script.isEmpty {
            return (.witnessScriptHash, Data([0x00, 0x20]) + Data(SHA256.hash(data: script)))
        }
        return (.unrecognized, nil)
    }

    /// Script-path taproot spend: witness = `<stack…> <tapscript> <control
    /// block>`. Restricted to the BIP342 tapscript leaf version; a mismatch of
    /// the recomputed output key's parity against the control block's bit
    /// rejects the classification (a valid spend cannot produce one). A P2WSH
    /// witness script of exactly 33+32m bytes could theoretically pass for a
    /// control block — no standard template produces one, and the residual
    /// ambiguity is inherent to reading a transaction without its prevouts.
    private static func taprootScriptPath(witness: [Data]) -> (Revelation, Data?)? {
        guard let controlData = witness.last, witness.count >= 2,
              let control = try? Taproot.ControlBlock(serialized: controlData),
              control.leafVersion == Taproot.leafVersion else { return nil }
        let scriptData = witness[witness.count - 2]
        guard !scriptData.isEmpty else { return nil }
        let script = Script(scriptData)
        var root = Taproot.leafHash(version: control.leafVersion, script: script)
        for sibling in control.path { root = Taproot.branchHash(root, sibling) }
        guard let (key, parity) = try? Taproot.tweakedOutputKey(internalKey: control.internalKey,
                                                                merkleRoot: root),
              parity == control.outputKeyParity else { return nil }
        return (.taprootScriptPath, Data([0x51, 0x20]) + key)
    }

    // MARK: - Shapes

    /// DER-encoded ECDSA signature plus sighash byte.
    private static func looksLikeSignature(_ data: Data) -> Bool {
        data.count >= 9 && data.count <= 73 && data.first == 0x30
    }

    /// SEC public key, compressed or uncompressed.
    private static func looksLikePublicKey(_ data: Data) -> Bool {
        (data.count == 33 && (data.first == 0x02 || data.first == 0x03))
            || (data.count == 65 && data.first == 0x04)
    }

    /// Decomposes a scriptSig into its pushed items. ScriptSigs of standard
    /// spends contain only pushes (OP_0 pushes the empty vector, the legacy
    /// multisig dummy); any other opcode means the shape is not ours to read,
    /// and a truncated push means malformed — both come back nil.
    private static func pushedItems(_ script: Data) -> [Data]? {
        var items: [Data] = []
        var index = script.startIndex
        func take(_ count: Int) -> Data? {
            guard script.endIndex - index >= count else { return nil }
            defer { index += count }
            return script.subdata(in: index ..< index + count)
        }
        while index < script.endIndex {
            let opcode = script[index]
            index += 1
            switch opcode {
            case 0x00:
                items.append(Data())
            case 0x01 ... 0x4B:
                guard let item = take(Int(opcode)) else { return nil }
                items.append(item)
            case 0x4C:
                guard let count = take(1), let item = take(Int(count[0])) else { return nil }
                items.append(item)
            case 0x4D:
                guard let count = take(2), let item = take(Int(UInt16(count[0]) | UInt16(count[1]) << 8))
                else { return nil }
                items.append(item)
            case 0x4E:
                guard let count = take(4) else { return nil }
                let length = UInt32(count[0]) | UInt32(count[1]) << 8
                    | UInt32(count[2]) << 16 | UInt32(count[3]) << 24
                guard let item = take(Int(length)) else { return nil }
                items.append(item)
            default:
                return nil
            }
        }
        return items
    }
}
