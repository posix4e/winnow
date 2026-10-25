import Foundation
import P256K

public enum SilentPaymentAddressError: Error, Equatable {
    /// Not a bech32m string (silent payment addresses always use bech32m,
    /// BIP352 §Address encoding — never bech32, unlike segwit v0).
    case invalidEncoding
    /// The address HRP does not match the expected network's.
    case wrongHRP(expected: String, actual: String)
    /// BIP352 defines version 0 ("…1q…"); versions 1–31 are reserved.
    case unsupportedVersion(Int)
    /// The data part must decode to exactly 66 bytes (two compressed keys).
    case invalidDataLength(Int)
    /// Scan or spend key is not a valid compressed secp256k1 public key.
    case invalidPublicKey
}

/// A BIP352 silent payment address: a bech32m string with HRP "sp" (mainnet)
/// or "tsp" (all test networks), version 0, data part = ser_P(B_scan) ‖
/// ser_P(B_m) — the receiver's 33-byte compressed scan key and spend key
/// (label-tweaked when the receiver handed out a labeled address; senders
/// treat it as opaque). Sending.swift consumes these; Receiving.swift
/// derives the wallet's own.
public struct SilentPaymentAddress: Equatable, Sendable {
    /// The only version BIP352 defines.
    public static let version = 0
    /// A v0 address is 117 characters; BIP352 suggests a 1023-character limit
    /// (not BIP173's 90) so future versions can extend the payload.
    public static let maxAddressLength = 1023

    /// Whether `text` is shaped like a silent payment code — a `sp1…` or
    /// `tsp1…` prefix in either case — so callers can route it to this parser
    /// rather than the address decoder. A shape check only: the initializer
    /// decides validity.
    public static func looksLikeCode(_ text: String) -> Bool {
        let lowered = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return lowered.hasPrefix("sp1") || lowered.hasPrefix("tsp1")
    }

    /// 33-byte compressed scan public key.
    public let scanKey: Data
    /// 33-byte compressed spend public key (B_m).
    public let spendKey: Data
    /// "sp" (mainnet) or "tsp" (test networks) — BIP352 §Address encoding.
    public let hrp: String

    public init(scanKey: Data, spendKey: Data, hrp: String) throws {
        guard scanKey.count == 33, Self.isValidPublicKey(scanKey),
              spendKey.count == 33, Self.isValidPublicKey(spendKey)
        else { throw SilentPaymentAddressError.invalidPublicKey }
        self.scanKey = scanKey
        self.spendKey = spendKey
        self.hrp = hrp
    }

    /// The bech32m encoding ("sp1q…" / "tsp1q…").
    public var encoded: String {
        get throws {
            let data = try [UInt8(Self.version)]
                + SegwitAddress.convertBits(Array(scanKey + spendKey), from: 8, to: 5, pad: true)
            return try Bech32.encode(hrp: hrp, data: data, encoding: .bech32m,
                                     maxLength: Self.maxAddressLength)
        }
    }

    /// Decodes and strictly validates an address: bech32m, version 0, a
    /// 66-byte payload of two valid compressed public keys. `expectedHRP`,
    /// when given, enforces the network.
    public init(_ string: String, expectedHRP: String? = nil) throws {
        let decoded: (hrp: String, data: [UInt8], encoding: Bech32.Encoding)
        do {
            decoded = try Bech32.decode(string, maxLength: Self.maxAddressLength)
        } catch {
            // A bad checksum, a mixed case or an overlong string: not a code.
            throw SilentPaymentAddressError.invalidEncoding
        }
        guard decoded.encoding == .bech32m else { throw SilentPaymentAddressError.invalidEncoding }
        if let expectedHRP, decoded.hrp != expectedHRP {
            throw SilentPaymentAddressError.wrongHRP(expected: expectedHRP, actual: decoded.hrp)
        }
        // The first data value is the version; 5-bit bech32 values are ≤ 31,
        // which is exactly BIP352's version range (v31 reserved).
        let version = Int(decoded.data.first ?? 0)
        guard version == Self.version else {
            throw SilentPaymentAddressError.unsupportedVersion(version)
        }
        let payload = try SegwitAddress.convertBits(Array(decoded.data.dropFirst()), from: 5, to: 8, pad: false)
        guard payload.count == 66 else {
            throw SilentPaymentAddressError.invalidDataLength(payload.count)
        }
        try self.init(scanKey: Data(payload.prefix(33)), spendKey: Data(payload.suffix(33)),
                      hrp: decoded.hrp)
    }

    private static func isValidPublicKey(_ key: Data) -> Bool {
        (try? P256K.Signing.PublicKey(dataRepresentation: key, format: .compressed)) != nil
    }
}
