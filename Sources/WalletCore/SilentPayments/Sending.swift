import CryptoKit
import Foundation
import P256K

public enum SilentPaymentSendingError: Error, Equatable {
    /// No input is from the BIP352 Inputs For Shared Secret Derivation list.
    case noEligibleInputs
    /// The eligible input private keys sum to zero — BIP352: fail.
    case inputKeysSumToZero
    /// hash_BIP0352/Inputs is not a valid scalar (negligible probability).
    case invalidInputHash
    /// hash_BIP0352/SharedSecret is not a valid scalar (negligible probability).
    case invalidTweak
    /// More than K_max = 2323 recipients share one scan key (BIP352 DoS limit).
    case tooManyRecipientsPerGroup
    /// An input or tweak scalar is not a valid private key.
    case invalidPrivateKey
    /// A recipient scan/spend key is not a valid compressed public key.
    case invalidRecipientKey
}

/// BIP352 silent payments, send side: input eligibility, the shared-secret
/// derivation (input_hash · a · B_scan), and the per-recipient P2TR output
/// scripts. Winnow sends only; the eligibility rules are the ones both sides
/// of the protocol share, so a receiver could reuse them unchanged.
///
/// Exercised by `SilentPaymentTests` (every official sending vector),
/// `SilentPaymentSendTests` (the wallet's own inputs) and the app flow in
/// `SilentPaymentSendFlowTests`.
public enum SilentPaymentSending {
    /// BIP352 K_max: per-group (shared scan key) recipient limit.
    public static let maxRecipientsPerGroup = 2323

    /// One transaction input as the sender sees it. The wallet only spends
    /// P2TR key-path, in which case `privateKey` is the BIP341-tweaked private
    /// key of the taproot output key (BIP352 §P2TR: "the sender uses the
    /// private key corresponding to the taproot output key") and
    /// `scriptSig`/`witness` stay empty — the witness does not exist yet when
    /// the outputs are derived. The sender MUST control the keys of every
    /// eligible input (BIP352 excludes shared-control inputs from derivation;
    /// the wallet case always satisfies this).
    public struct Input: Equatable, Sendable {
        /// 32 bytes, internal (wire/little-endian) byte order.
        public var txid: Data
        public var vout: UInt32
        public var prevoutScriptPubKey: Data
        public var scriptSig: Data
        public var witness: [Data]
        public var privateKey: Data

        public init(txid: Data, vout: UInt32, prevoutScriptPubKey: Data,
                    scriptSig: Data = Data(), witness: [Data] = [], privateKey: Data) {
            self.txid = txid
            self.vout = vout
            self.prevoutScriptPubKey = prevoutScriptPubKey
            self.scriptSig = scriptSig
            self.witness = witness
            self.privateKey = privateKey
        }

        /// COutPoint serialization: txid (LSB first) ‖ vout (LSB first) — the
        /// byte order outpoints are sorted and hashed in (BIP352).
        public var outpoint: Data {
            var littleEndianVout = vout.littleEndian
            return txid + withUnsafeBytes(of: &littleEndianVout) { Data($0) }
        }
    }

    /// The sender-side derivation context: which inputs were eligible, the
    /// summed private key a, and the input hash committing to the smallest
    /// outpoint and A = a·G (BIP352 §Creating outputs).
    public struct Context: Equatable, Sendable {
        /// Compressed public keys of the eligible inputs, in input order.
        public var eligiblePublicKeys: [Data]
        /// a = Σ aᵢ mod n (each P2TR aᵢ normalized to even Y first).
        public var privateKeySum: Data
        /// hash_BIP0352/Inputs(outpoint_L ‖ A).
        public var inputHash: Data
    }

    /// The public key an input contributes to the shared secret, or nil when
    /// the input is not on the BIP352 Inputs For Shared Secret Derivation list
    /// (P2TR, P2WPKH, P2SH-P2WPKH, P2PKH — compressed keys only). Mirrors the
    /// BIP352 reference's get_pubkey_from_input.
    public static func eligiblePublicKey(of input: Input) -> Data? {
        eligiblePublicKey(prevoutScriptPubKey: input.prevoutScriptPubKey,
                          scriptSig: input.scriptSig, witness: input.witness)
    }

    /// The same eligibility rules without a private key — the list is shared
    /// by both sides of BIP352; the sending vectors exercise every input type
    /// even though the wallet itself only ever spends P2TR key paths.
    public static func eligiblePublicKey(prevoutScriptPubKey script: Data,
                                         scriptSig: Data, witness: [Data]) -> Data? {
        if isP2PKH(script) { return p2pkhKey(script: script, scriptSig: scriptSig) }
        if isP2SH(script) { return p2shP2wpkhKey(scriptSig: scriptSig, witness: witness) }
        if isP2WPKH(script) { return p2wpkhKey(witness: witness) }
        if isP2TR(script) { return p2trKey(script: script, witness: witness) }
        return nil
    }

    /// P2PKH: slide a 33-byte window over the scriptSig from the back and
    /// take the first slice whose HASH160 matches the scriptPubKey hash —
    /// finds the compressed key even in malleated scriptSigs (BIP352).
    private static func p2pkhKey(script: Data, scriptSig: Data) -> Data? {
        let hash = script.subdata(in: script.startIndex + 3 ..< script.startIndex + 23)
        guard scriptSig.count >= 33 else { return nil }
        // Count is not a 0-based index — Data slices may have startIndex != 0.
        let sigStart = scriptSig.startIndex
        for endOffset in stride(from: scriptSig.count, through: 33, by: -1) {
            let end = scriptSig.index(sigStart, offsetBy: endOffset)
            let begin = scriptSig.index(end, offsetBy: -33)
            let candidate = scriptSig.subdata(in: begin ..< end)
            guard hash160(candidate) == hash, isValidCompressedKey(candidate) else { continue }
            return Data(candidate)
        }
        return nil
    }

    /// P2SH-P2WPKH: the redeem script (scriptSig minus its push opcode) is a
    /// P2WPKH program; the key is the last witness item.
    private static func p2shP2wpkhKey(scriptSig: Data, witness: [Data]) -> Data? {
        let redeemScript = scriptSig.dropFirst()
        guard isP2WPKH(redeemScript), let key = witness.last, isValidCompressedKey(key) else { return nil }
        return key
    }

    private static func p2wpkhKey(witness: [Data]) -> Data? {
        guard let key = witness.last, isValidCompressedKey(key) else { return nil }
        return key
    }

    /// P2TR: the receiver takes the x-only output key from the scriptPubKey,
    /// returned as the even-Y lift's compressed form (BIP340 lift_x). A
    /// script-path spend whose internal key is the BIP341 NUMS point H is
    /// skipped (BIP352) — no key-path private key exists for such outputs. An
    /// empty witness means the sender hasn't signed yet; it knows the spend is
    /// key-path, so the input is eligible.
    private static func p2trKey(script: Data, witness: [Data]) -> Data? {
        var stack = witness
        // BIP341: a last item starting with 0x50 is the annex.
        if stack.count > 1, stack.last?.first == 0x50 { stack.removeLast() }
        if stack.count > 1, let controlBlock = stack.last, controlBlock.count >= 33 {
            let internalKey = controlBlock.subdata(in: controlBlock.startIndex + 1 ..< controlBlock.startIndex + 33)
            if internalKey == Taproot.unspendableInternalKey { return nil }
        }
        let outputKey = script.dropFirst(2)
        guard isValidXonlyKey(outputKey) else { return nil }
        return Data([0x02]) + outputKey
    }

    /// Collects the eligible inputs and computes a and the input hash
    /// (BIP352 §Creating outputs):
    /// - P2TR private keys are negated when their point has odd Y, so sender
    ///   and receiver agree on the x-only key's secret (BIP340 d / n−d),
    /// - a = 0 fails,
    /// - input_hash = hash_BIP0352/Inputs(outpoint_L ‖ A) over the
    ///   lexicographically smallest outpoint of ALL transaction inputs.
    public static func context(inputs: [Input]) throws -> Context {
        var publicKeys: [Data] = []
        var sum = Data(repeating: 0, count: 32)
        for input in inputs {
            guard let publicKey = eligiblePublicKey(of: input) else { continue }
            var secret = input.privateKey
            if isP2TR(input.prevoutScriptPubKey), try publicKeyPoint(secret).first == 0x03 {
                secret = try negate(secret)
            }
            sum = try scalarAdd(sum, secret)
            publicKeys.append(publicKey)
        }
        guard !publicKeys.isEmpty else { throw SilentPaymentSendingError.noEligibleInputs }
        guard sum != Data(repeating: 0, count: 32) else {
            throw SilentPaymentSendingError.inputKeysSumToZero
        }
        let aggregateKey = try publicKeyPoint(sum) // A = a·G
        let smallestOutpoint = inputs.map(\.outpoint)
            .min(by: { $0.lexicographicallyPrecedes($1) }) ?? Data()
        let inputHash = TaggedHash.hash("BIP0352/Inputs", smallestOutpoint + aggregateKey)
        guard isValidScalar(inputHash) else { throw SilentPaymentSendingError.invalidInputHash }
        return Context(eligiblePublicKeys: publicKeys, privateKeySum: sum, inputHash: inputHash)
    }

    /// ecdh_shared_secret = input_hash · a · B_scan, serialized compressed.
    public static func sharedSecret(context: Context, scanKey: Data) throws -> Data {
        guard let scanPoint = try? P256K.Signing.PublicKey(dataRepresentation: scanKey, format: .compressed)
        else { throw SilentPaymentSendingError.invalidRecipientKey }
        let scalar = try scalarMultiply(context.inputHash, context.privateKeySum)
        guard let shared = try? scanPoint.multiply([UInt8](scalar)) else {
            throw SilentPaymentSendingError.invalidRecipientKey
        }
        return shared.dataRepresentation
    }

    /// One output: t_k = hash_BIP0352/SharedSecret(ser_P(ecdh) ‖ ser32(k)),
    /// P = B_m + t_k·G, encoded as a BIP341 taproot scriptPubKey. ser32 is
    /// big-endian (BIP352 conventions).
    public static func outputScript(sharedSecret: Data, spendKey: Data, k: UInt32) throws -> Data {
        guard let spendPoint = try? P256K.Signing.PublicKey(dataRepresentation: spendKey, format: .compressed)
        else { throw SilentPaymentSendingError.invalidRecipientKey }
        var bigEndianK = k.bigEndian
        let tweak = TaggedHash.hash("BIP0352/SharedSecret",
                                    sharedSecret + withUnsafeBytes(of: &bigEndianK) { Data($0) })
        guard isValidScalar(tweak) else { throw SilentPaymentSendingError.invalidTweak }
        guard let tweakPoint = try? P256K.Signing.PrivateKey(dataRepresentation: tweak),
              let outputPoint = try? spendPoint.combine([tweakPoint.publicKey], format: .compressed)
        else { throw SilentPaymentSendingError.invalidRecipientKey }
        return Data([0x51, 0x20]) + outputPoint.dataRepresentation.dropFirst()
    }

    /// The full sender pipeline: one P2TR scriptPubKey per recipient, aligned
    /// with `recipients`. Recipients are grouped by scan key (one ECDH per
    /// group); within a group, k counts up over the group's spend keys, so
    /// paying the same address twice still yields two distinct outputs.
    public static func outputScripts(inputs: [Input], recipients: [SilentPaymentAddress]) throws -> [Data] {
        let context = try context(inputs: inputs)
        var groupOfScanKey: [Data: Int] = [:]
        var groups: [(scanKey: Data, recipientIndices: [Int])] = []
        for (index, recipient) in recipients.enumerated() {
            if let group = groupOfScanKey[recipient.scanKey] {
                groups[group].recipientIndices.append(index)
            } else {
                groupOfScanKey[recipient.scanKey] = groups.count
                groups.append((recipient.scanKey, [index]))
            }
        }
        for group in groups where group.recipientIndices.count > maxRecipientsPerGroup {
            throw SilentPaymentSendingError.tooManyRecipientsPerGroup
        }
        var scripts = [Data](repeating: Data(), count: recipients.count)
        for group in groups {
            let secret = try sharedSecret(context: context, scanKey: group.scanKey)
            for (k, index) in group.recipientIndices.enumerated() {
                scripts[index] = try outputScript(sharedSecret: secret,
                                                  spendKey: recipients[index].spendKey, k: UInt32(k))
            }
        }
        return scripts
    }

    // MARK: - Script templates

    /// P2TR: OP_1 <32-byte x-only key> (BIP341).
    static func isP2TR(_ script: Data) -> Bool {
        script.count == 34 && script.first == 0x51 && script.dropFirst().first == 0x20
    }

    /// P2WPKH: OP_0 <20-byte key hash> (BIP141).
    static func isP2WPKH(_ script: Data) -> Bool {
        script.count == 22 && script.first == 0x00 && script.dropFirst().first == 0x14
    }

    /// P2PKH: OP_DUP OP_HASH160 <20-byte key hash> OP_EQUALVERIFY OP_CHECKSIG.
    static func isP2PKH(_ script: Data) -> Bool {
        script.count == 25 && script.prefix(3).elementsEqual([0x76, 0xA9, 0x14])
            && script.suffix(2).elementsEqual([0x88, 0xAC])
    }

    /// P2SH: OP_HASH160 <20-byte script hash> OP_EQUAL (BIP13).
    static func isP2SH(_ script: Data) -> Bool {
        script.count == 23 && script.prefix(2).elementsEqual([0xA9, 0x14]) && script.last == 0x87
    }

    // MARK: - Scalar and point helpers (mod n, via P256K)

    static let scalarZero = Data(repeating: 0, count: 32)

    /// The secp256k1 group order n (SEC 2 §2.4.1): the exclusive upper bound
    /// of a valid private key or tweak.
    static let groupOrder = Data([
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ])

    static func isValidScalar(_ scalar: Data) -> Bool {
        scalar.count == 32 && scalar != scalarZero && scalar.lexicographicallyPrecedes(groupOrder)
    }

    static func isValidCompressedKey(_ key: Data) -> Bool {
        key.count == 33
            && (try? P256K.Signing.PublicKey(dataRepresentation: key, format: .compressed)) != nil
    }

    /// lift_x validity (BIP340): x < p and the even-Y point exists. Checked by
    /// parsing 0x02 ‖ x as a compressed public key.
    static func isValidXonlyKey(_ key: some DataProtocol) -> Bool {
        key.count == 32
            && (try? P256K.Signing.PublicKey(dataRepresentation: Data([0x02]) + Data(key),
                                             format: .compressed)) != nil
    }

    /// HASH160 (SHA256 then RIPEMD160) — the P2PKH/P2WPKH key hash.
    static func hash160(_ data: Data) -> Data {
        RIPEMD160.hash(Data(SHA256.hash(data: data)))
    }

    /// s·G as a compressed public key (s must be a valid nonzero scalar); the
    /// first byte carries the Y parity used by the P2TR even-Y normalization.
    static func publicKeyPoint(_ scalar: Data) throws -> Data {
        guard isValidScalar(scalar),
              let key = try? P256K.Signing.PrivateKey(dataRepresentation: scalar)
        else { throw SilentPaymentSendingError.invalidPrivateKey }
        return key.publicKey.dataRepresentation
    }

    /// (a + b) mod n; zero operands pass through and a zero result stays zero
    /// (BIP352's a = 0 check happens in `context`).
    static func scalarAdd(_ a: Data, _ b: Data) throws -> Data {
        if a == scalarZero { return b }
        if b == scalarZero { return a }
        guard isValidScalar(a), isValidScalar(b),
              let key = try? P256K.Signing.PrivateKey(dataRepresentation: a)
        else { throw SilentPaymentSendingError.invalidPrivateKey }
        // Valid operands: tweak_add only fails when the result is zero.
        guard let sum = try? key.add([UInt8](b)) else { return scalarZero }
        return sum.dataRepresentation
    }

    /// (a · b) mod n.
    static func scalarMultiply(_ a: Data, _ b: Data) throws -> Data {
        guard isValidScalar(a), isValidScalar(b),
              let key = try? P256K.Signing.PrivateKey(dataRepresentation: a),
              let product = try? key.multiply([UInt8](b))
        else { throw SilentPaymentSendingError.invalidPrivateKey }
        return product.dataRepresentation
    }

    /// −s mod n.
    static func negate(_ scalar: Data) throws -> Data {
        guard isValidScalar(scalar),
              let key = try? P256K.Signing.PrivateKey(dataRepresentation: scalar)
        else { throw SilentPaymentSendingError.invalidPrivateKey }
        return key.negation.dataRepresentation
    }
}
