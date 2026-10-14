import Foundation
import P256K

public enum SignerError: Error, Equatable {
    case invalidPrivateKey
    case spentOutputCountMismatch(inputs: Int, spentOutputs: Int)
    /// No key resolved for an input's spent scriptPubKey (hex).
    case missingKey(scriptPubKey: String)
    /// A leaf script that is not a canonical multi_a/sortedmulti_a tapscript.
    case malformedLeafScript
}

/// Single-sig Taproot key-path signer (BIP341/BIP340): the tweaked private key
/// (BIP86 — internal key tweaked with NO merkle root, see BitcoinCore's
/// `BIP86.tweakedPrivateKey`), a Schnorr signature over the BIP341 sighash, and
/// a witness of a single stack item (the 64-byte signature; 65 bytes with the
/// sighash byte appended for non-default hash types).
public enum Signer {
    /// Produces the witness stack for one input. `tweakedPrivateKey` is the
    /// BIP86 tweaked secret for the input's output key.
    public static func witness(tx: Transaction, inputIndex: Int,
                               spentOutputs: [SighashBIP341.SpentOutput],
                               tweakedPrivateKey: Data,
                               hashType: SighashBIP341.HashType = .default,
                               auxiliaryRand: Data? = nil) throws -> [Data] {
        let sighash = try SighashBIP341.sighash(tx: tx, inputIndex: inputIndex,
                                                spentOutputs: spentOutputs, hashType: hashType)
        guard let key = try? P256K.Schnorr.PrivateKey(dataRepresentation: tweakedPrivateKey) else {
            throw SignerError.invalidPrivateKey
        }
        var message = [UInt8](sighash)
        var aux = [UInt8](auxiliaryRand ?? randomAuxiliaryRand())
        let signature = try key.signature(message: &message, auxiliaryRand: &aux)
        var item = signature.dataRepresentation
        // BIP341: a 64-byte sig implies SIGHASH_DEFAULT; other types append the byte.
        if hashType != .default { item.append(hashType.rawValue) }
        return [item]
    }

    /// Signs every input in place (witness = single signature item).
    /// `privateKeyFor` resolves the BIP86 tweaked private key from the spent
    /// scriptPubKey; returning nil throws `missingKey`.
    public static func sign(tx: inout Transaction, spentOutputs: [SighashBIP341.SpentOutput],
                            hashType: SighashBIP341.HashType = .default,
                            auxiliaryRand: Data? = nil,
                            privateKeyFor: (Data) throws -> Data?) throws {
        guard tx.inputs.count == spentOutputs.count else {
            throw SignerError.spentOutputCountMismatch(
                inputs: tx.inputs.count, spentOutputs: spentOutputs.count)
        }
        for index in tx.inputs.indices {
            guard let privateKey = try privateKeyFor(spentOutputs[index].scriptPubKey) else {
                throw SignerError.missingKey(scriptPubKey: spentOutputs[index].scriptPubKey.hex)
            }
            tx.inputs[index].witness = try witness(tx: tx, inputIndex: index, spentOutputs: spentOutputs,
                                                   tweakedPrivateKey: privateKey, hashType: hashType,
                                                   auxiliaryRand: auxiliaryRand)
        }
    }

    /// Fresh 32-byte auxiliary randomness for BIP340 nonce derivation.
    static func randomAuxiliaryRand() -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255, using: &generator) })
    }

    // MARK: - Script-path spends (BIP341 ext_flag = 1, BIP387 multi_a)

    /// A BIP342 script-path signature for one key of a tapscript leaf: the
    /// plain x-only key signs **without any taproot tweak**; the sighash
    /// commits to the leaf via the BIP342 extension (ext_flag = 1), and to
    /// `annex` when the spend carries one (with its 0x50 prefix). The
    /// returned item is 64 bytes, or 65 with the hash type byte appended for
    /// non-default hash types (BIP341).
    public static func scriptPathSignature(tx: Transaction, inputIndex: Int,
                                           spentOutputs: [SighashBIP341.SpentOutput],
                                           leafScript: Script, leafVersion: UInt8 = Taproot.leafVersion,
                                           hashType: SighashBIP341.HashType = .default,
                                           annex: Data? = nil,
                                           privateKey: Data, auxiliaryRand: Data? = nil) throws -> Data {
        let sighash = try SighashBIP341.sighash(tx: tx, inputIndex: inputIndex, spentOutputs: spentOutputs,
                                                hashType: hashType,
                                                scriptPath: SighashBIP341.ScriptPath(leafScript: leafScript,
                                                                                     leafVersion: leafVersion),
                                                annex: annex)
        guard let key = try? P256K.Schnorr.PrivateKey(dataRepresentation: privateKey) else {
            throw SignerError.invalidPrivateKey
        }
        var message = [UInt8](sighash)
        var aux = [UInt8](auxiliaryRand ?? randomAuxiliaryRand())
        var item = try key.signature(message: &message, auxiliaryRand: &aux).dataRepresentation
        if hashType != .default { item.append(hashType.rawValue) }
        return item
    }

    /// The BIP387 witness stack for a `multi_a`/`sortedmulti_a` leaf spend:
    /// one stack item per script key — the 64/65-byte signature, or an empty
    /// placeholder for non-signing keys — in the script's key order REVERSED
    /// (the first OP_CHECKSIG pops the top of the stack), followed by the leaf
    /// script and the control block. `signatures` maps x-only keys (as they
    /// appear in the script) to signature items, e.g. from
    /// `scriptPathSignature` or PSBT_IN_TAP_SCRIPT_SIG fields.
    public static func multisigWitness(signatures: [Data: Data], leafScript: Script,
                                       controlBlock: Taproot.ControlBlock) throws -> [Data] {
        guard let (_, keys) = Multisig.parse(leafScript) else {
            throw SignerError.malformedLeafScript
        }
        var stack = keys.reversed().map { signatures[$0] ?? Data() }
        stack.append(leafScript.bytes)
        stack.append(controlBlock.serialized)
        return stack
    }
}
