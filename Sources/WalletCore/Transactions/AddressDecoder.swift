import BitcoinCore
import BitcoinP2P
import Foundation

public enum AddressError: Error, Equatable, LocalizedError {
    case invalidAddress(String)
    /// A BIP352 silent-payment code. Well-formed, and not something this build
    /// can pay: reporting it as invalid would be false, and would send the user
    /// looking for the wrong problem.
    case silentPaymentAddress(String)
    /// Address belongs to a different network (HRP or base58 prefix mismatch).
    case wrongNetwork(String)
    case unsupportedWitnessVersion(Int)
    case unsupportedWitnessProgram(version: Int, length: Int)

    public var errorDescription: String? {
        switch self {
        case .invalidAddress:
            "That is not a valid Bitcoin address."
        case .silentPaymentAddress:
            "That is a silent-payment address, and this build cannot pay one. Silent payments moved to the alpha build — nothing is wrong with the address."
        case .wrongNetwork:
            "That address belongs to a different Bitcoin network."
        case let .unsupportedWitnessVersion(version):
            "That address uses future Bitcoin witness version \(version). Winnow cannot safely send to it before the output type is activated."
        case let .unsupportedWitnessProgram(version, length):
            "That address uses an unsupported witness-v\(version) program length (\(length) bytes)."
        }
    }
}

/// Standard Bitcoin address → scriptPubKey decoding: bech32/bech32m segwit
/// (BIP173/BIP350, incl. P2TR v1) and Base58Check P2PKH/P2SH (BIP13). The
/// wallet itself is Taproot-only, but payments can target any standard type.
public enum AddressDecoder {
    /// bech32 HRP and base58 version bytes per network (signet uses the
    /// testnet constants, BIP325).
    public static func hrp(for network: BitcoinNetwork) -> String {
        switch network {
        case .mainnet: "bc"
        case .signet: "tb"
        }
    }

    /// Decodes an address to its output scriptPubKey, enforcing the network.
    public static func scriptPubKey(for address: String, network: BitcoinNetwork) throws -> Data {
        let lowercased = address.lowercased()
        // Checked before anything else: an sp1…/tsp1… code is well-formed and
        // unpayable here, which is a different fact from a malformed address.
        if lowercased.hasPrefix("sp1") || lowercased.hasPrefix("tsp1") {
            throw AddressError.silentPaymentAddress(address)
        }
        if lowercased.hasPrefix("bc1") || lowercased.hasPrefix("tb1") {
            let expectedPrefix = hrp(for: network) + "1"
            guard lowercased.hasPrefix(expectedPrefix) else {
                throw AddressError.wrongNetwork(address)
            }
            do {
                return try segwitScriptPubKey(for: address, network: network)
            } catch let error as AddressError {
                throw error
            } catch {
                throw AddressError.invalidAddress(address)
            }
        }
        do {
            return try base58ScriptPubKey(for: address, network: network)
        } catch let error as AddressError {
            throw error
        } catch {
            throw AddressError.invalidAddress(address)
        }
    }

    /// Whether a scriptPubKey is P2TR (OP_1 <32-byte program>, BIP341).
    public static func isP2TR(_ scriptPubKey: Data) -> Bool {
        scriptPubKey.count == 34 && scriptPubKey.first == 0x51 && scriptPubKey.dropFirst().first == 0x20
    }

    // MARK: - Internals

    /// Segwit: OP_n <program>; v0 must be bech32 with a 20/32-byte program
    /// (P2WPKH/P2WSH), v1+ bech32m (BIP350).
    private static func segwitScriptPubKey(for address: String, network: BitcoinNetwork) throws -> Data {
        let (version, program) = try SegwitAddress.decode(address, expectedHRP: hrp(for: network))
        switch version {
        case 0:
            break // BIP141 P2WPKH/P2WSH lengths are enforced by SegwitAddress.
        case 1:
            guard program.count == 32 else {
                throw AddressError.unsupportedWitnessProgram(version: version, length: program.count)
            }
        default:
            // Unknown witness versions are deliberately forward-compatible at
            // consensus and can be anyone-can-spend before their rules activate.
            // Decoding one must never imply that it is safe to fund.
            throw AddressError.unsupportedWitnessVersion(version)
        }
        var script = Data([version == 0 ? 0x00 : 0x50 + UInt8(version), UInt8(program.count)])
        script.append(program)
        return script
    }

    /// Base58Check: 0x00/0x6F P2PKH (OP_DUP … OP_CHECKSIG), 0x05/0xC4 P2SH.
    private static func base58ScriptPubKey(for address: String, network: BitcoinNetwork) throws -> Data {
        let payload = try Base58Check.decode(address)
        guard payload.count == 21 else { throw AddressError.invalidAddress(address) }
        let hash = payload.dropFirst()
        let p2pkhPrefix: UInt8 = network == .mainnet ? 0x00 : 0x6F
        let p2shPrefix: UInt8 = network == .mainnet ? 0x05 : 0xC4
        switch payload.first {
        case p2pkhPrefix:
            return Data([0x76, 0xA9, 0x14]) + hash + Data([0x88, 0xAC])
        case p2shPrefix:
            return Data([0xA9, 0x14]) + hash + Data([0x87])
        default:
            throw AddressError.wrongNetwork(address)
        }
    }
}
