import Foundation
import P256K
import WalletCore

/// The receiving side of BIP352, as a test fixture: a receiver with its own
/// scan and spend keys, and the §Scanning derivation that tells which outputs
/// of a transaction were paid to it. Written from the BIP against `P256K`
/// directly, without the wallet's sender code, so an app flow or the signet
/// journey can check the wallet's derived outputs against an independent
/// reconstruction. Bitcoin Core on the fixture node has no BIP352 support, so
/// this is also what stands in for the recipient's wallet there.
public struct SilentPaymentTestReceiver: Sendable {
    /// `b_scan`: 32 bytes.
    public let scanPrivateKey: Data
    /// `B_spend`: 33-byte compressed.
    public let spendPublicKey: Data
    /// The receiver's `sp1…`/`tsp1…` code for `network`.
    public let code: String

    /// A receiver whose keys come from a fixed seed byte, so a test's
    /// expectations are stable across runs. Paths follow BIP352 §Key
    /// Derivation (`m/352'/coin'/account'/1'/0` scan, `…/0'/0` spend).
    public init(network: BitcoinNetwork, seedByte: UInt8 = 0x5A) throws {
        let master = try HDKey(seed: Data(repeating: seedByte, count: 32))
        let coin = network == .mainnet ? 0 : 1
        let scan = try master.derived(path: "m/352'/\(coin)'/0'/1'/0")
        let spend = try master.derived(path: "m/352'/\(coin)'/0'/0'/0")
        guard let scanPrivateKey = scan.privateKey else { throw ReceiverError.noPrivateKey }
        self.scanPrivateKey = scanPrivateKey
        spendPublicKey = spend.neutered.publicKey
        code = try SilentPaymentAddress(scanKey: scan.neutered.publicKey, spendKey: spendPublicKey,
                                        hrp: SilentPayment.hrp(for: network)).encoded
    }

    public enum ReceiverError: Error {
        case noPrivateKey
        case noInputs
        case notKeyPathInputs
    }

    /// The P2TR scripts `P_0 … P_(count-1)` this receiver would find in
    /// `transaction`, whose inputs all spend the P2TR key-path outputs in
    /// `prevoutScripts` (one per input, in input order). BIP352 §Scanning:
    /// `A = Σ lift_x(output key)`, `input_hash = hash(outpoint_L ‖ A)`,
    /// `ecdh = input_hash·b_scan·A`, `P_k = B_spend + hash(ecdh ‖ k)·G`.
    public func expectedOutputScripts(in transaction: Transaction, prevoutScripts: [Data],
                                      count: Int) throws -> [Data] {
        guard !transaction.inputs.isEmpty, prevoutScripts.count == transaction.inputs.count else {
            throw ReceiverError.noInputs
        }
        let points = try prevoutScripts.map { script -> P256K.Signing.PublicKey in
            guard script.count == 34, script.first == 0x51 else { throw ReceiverError.notKeyPathInputs }
            return try P256K.Signing.PublicKey(dataRepresentation: Data([0x02]) + script.dropFirst(2),
                                               format: .compressed)
        }
        let sum = points.count == 1 ? points[0] : try points[0].combine(Array(points.dropFirst()), format: .compressed)
        let smallestOutpoint = transaction.inputs.map { input -> Data in
            var vout = input.previousOutput.vout.littleEndian
            return input.previousOutput.txid + withUnsafeBytes(of: &vout) { Data($0) }
        }.min { $0.lexicographicallyPrecedes($1) }!
        let inputHash = TaggedHash.hash("BIP0352/Inputs", smallestOutpoint + sum.dataRepresentation)
        let shared = try sum.multiply([UInt8](inputHash), format: .compressed)
            .multiply([UInt8](scanPrivateKey), format: .compressed)
        let spend = try P256K.Signing.PublicKey(dataRepresentation: spendPublicKey, format: .compressed)
        return try (0 ..< count).map { k -> Data in
            var bigEndianK = UInt32(k).bigEndian
            let tweak = TaggedHash.hash("BIP0352/SharedSecret",
                                        shared.dataRepresentation + withUnsafeBytes(of: &bigEndianK) { Data($0) })
            let tweakPoint = try P256K.Signing.PrivateKey(dataRepresentation: tweak).publicKey
            let output = try spend.combine([tweakPoint], format: .compressed)
            return Data([0x51, 0x20]) + output.dataRepresentation.dropFirst()
        }
    }
}
