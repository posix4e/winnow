import CryptoKit
import Foundation
import P256K

public enum BIP32Error: Error, Equatable {
    case invalidSeed
    case invalidPath
    case hardenedDerivationFromPublicKey
    case derivationFailed
    case invalidSerializedKey
    case invalidVersion
    /// The key is at depth 255, and a byte counts no deeper. A
    /// deserialized key can name any depth, so the walk refuses rather than
    /// overflowing.
    case depthExhausted
}

/// BIP32 hierarchical deterministic key (secp256k1).
public struct HDKey: Sendable, Equatable {
    public static let hardenedOffset: UInt32 = 0x8000_0000

    /// Serialization version (mainnet xprv/xpub, testnet tprv/tpub).
    public enum Network: Sendable {
        case mainnet
        case testnet

        var privateVersion: UInt32 {
            switch self {
            case .mainnet: 0x0488_ADE4
            case .testnet: 0x0435_8394
            }
        }

        var publicVersion: UInt32 {
            switch self {
            case .mainnet: 0x0488_B21E
            case .testnet: 0x0435_87CF
            }
        }
    }

    public let depth: UInt8
    public let parentFingerprint: UInt32
    public let childIndex: UInt32
    public let chainCode: Data
    public let privateKey: Data? // 32 bytes, nil for neutered keys
    public let publicKey: Data // 33 bytes, compressed

    public var isPrivate: Bool { privateKey != nil }

    /// Master key from a BIP39 seed: HMAC-SHA512(key="Bitcoin seed", seed).
    public init(seed: Data) throws {
        let i = Self.hmacSHA512(key: Data("Bitcoin seed".utf8), data: seed)
        let (secret, chain) = (i.prefix(32), i.suffix(32))
        guard let _ = try? P256K.Signing.PrivateKey(dataRepresentation: secret) else {
            throw BIP32Error.invalidSeed
        }
        let publicKey = try Self.publicKey(for: Data(secret))
        self.init(depth: 0, parentFingerprint: 0, childIndex: 0,
                  chainCode: Data(chain), privateKey: Data(secret), publicKey: publicKey)
    }

    public init(depth: UInt8, parentFingerprint: UInt32, childIndex: UInt32,
                chainCode: Data, privateKey: Data?, publicKey: Data) {
        self.depth = depth
        self.parentFingerprint = parentFingerprint
        self.childIndex = childIndex
        self.chainCode = chainCode
        self.privateKey = privateKey
        self.publicKey = publicKey
    }

    /// HASH160 fingerprint of the compressed public key (first 4 bytes).
    public var fingerprint: UInt32 {
        Hash160.hash(publicKey).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
    }

    /// The neutered (public-only) form of this key.
    public var neutered: HDKey {
        HDKey(depth: depth, parentFingerprint: parentFingerprint, childIndex: childIndex,
              chainCode: chainCode, privateKey: nil, publicKey: publicKey)
    }

    /// Child key derivation at a single index (>= hardenedOffset for hardened).
    public func child(at index: UInt32) throws -> HDKey {
        guard depth < UInt8.max else { throw BIP32Error.depthExhausted }
        let hardened = index >= Self.hardenedOffset
        var data = Data()
        if hardened {
            guard let privateKey else { throw BIP32Error.hardenedDerivationFromPublicKey }
            data.append(0)
            data.append(privateKey)
        } else {
            data.append(publicKey)
        }
        withUnsafeBytes(of: index.bigEndian) { data.append(contentsOf: $0) }

        let i = Self.hmacSHA512(key: chainCode, data: data)
        let (tweak, childChain) = (Data(i.prefix(32)), Data(i.suffix(32)))

        do {
            if let privateKey {
                let key = try P256K.Signing.PrivateKey(dataRepresentation: privateKey)
                let childSecret = try key.add([UInt8](tweak)).dataRepresentation
                return HDKey(depth: depth + 1, parentFingerprint: fingerprint, childIndex: index,
                             chainCode: childChain, privateKey: childSecret,
                             publicKey: try Self.publicKey(for: childSecret))
            } else {
                let key = try P256K.Signing.PublicKey(dataRepresentation: publicKey, format: .compressed)
                let childPublic = try key.add([UInt8](tweak), format: .compressed).dataRepresentation
                return HDKey(depth: depth + 1, parentFingerprint: fingerprint, childIndex: index,
                             chainCode: childChain, privateKey: nil, publicKey: childPublic)
            }
        } catch {
            // Tweak >= n or child key invalid (probability < 2^-127 per BIP32).
            throw BIP32Error.derivationFailed
        }
    }

    /// Derives along a path like "m/84'/0'/0'/0/0" (also accepts h/H suffixes).
    public func derived(path: String) throws -> HDKey {
        var key = self
        var components = path.split(separator: "/").map(String.init)
        if components.first == "m" || components.first == "M" { components.removeFirst() }
        for component in components {
            let hardened = component.hasSuffix("'") || component.hasSuffix("h") || component.hasSuffix("H")
            let digits = hardened ? String(component.dropLast()) : component
            guard let index = UInt32(digits), index < Self.hardenedOffset else {
                throw BIP32Error.invalidPath
            }
            key = try key.child(at: index + (hardened ? Self.hardenedOffset : 0))
        }
        return key
    }

    /// Base58Check serialization (78-byte payload: version/depth/fingerprint/index/chain/key).
    public func serialized(network: Network = .mainnet) -> String {
        var payload = Data()
        let version = isPrivate ? network.privateVersion : network.publicVersion
        withUnsafeBytes(of: version.bigEndian) { payload.append(contentsOf: $0) }
        payload.append(depth)
        withUnsafeBytes(of: parentFingerprint.bigEndian) { payload.append(contentsOf: $0) }
        withUnsafeBytes(of: childIndex.bigEndian) { payload.append(contentsOf: $0) }
        payload.append(chainCode)
        if let privateKey {
            payload.append(0)
            payload.append(privateKey)
        } else {
            payload.append(publicKey)
        }
        return Base58Check.encode(payload)
    }

    /// Parses a Base58Check-serialized extended key, validating version, key material,
    /// and the master-key invariants (zero depth implies zero fingerprint/index).
    public static func deserialize(_ string: String) throws -> HDKey {
        let payload = try Base58Check.decode(string)
        guard payload.count == 78 else { throw BIP32Error.invalidSerializedKey }
        let version = payload.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        let depth = payload[payload.index(payload.startIndex, offsetBy: 4)]
        let parentFingerprint = payload.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 5, as: UInt32.self).bigEndian }
        let childIndex = payload.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 9, as: UInt32.self).bigEndian }
        let chainCode = payload.subdata(in: 13 ..< 45)
        let keyData = payload.subdata(in: 45 ..< 78)

        let knownVersions: [UInt32] = [Network.mainnet.privateVersion, Network.mainnet.publicVersion,
                                       Network.testnet.privateVersion, Network.testnet.publicVersion]
        guard knownVersions.contains(version) else { throw BIP32Error.invalidVersion }
        if depth == 0, parentFingerprint != 0 || childIndex != 0 {
            throw BIP32Error.invalidSerializedKey
        }

        let isPrivateVersion = version == Network.mainnet.privateVersion || version == Network.testnet.privateVersion
        if isPrivateVersion {
            guard keyData.first == 0 else { throw BIP32Error.invalidSerializedKey }
            let secret = keyData.dropFirst()
            guard let key = try? P256K.Signing.PrivateKey(dataRepresentation: secret) else {
                throw BIP32Error.invalidSerializedKey
            }
            return HDKey(depth: depth, parentFingerprint: parentFingerprint, childIndex: childIndex,
                         chainCode: chainCode, privateKey: Data(secret),
                         publicKey: key.publicKey.dataRepresentation)
        } else {
            guard keyData.count == 33,
                  (try? P256K.Signing.PublicKey(dataRepresentation: keyData, format: .compressed)) != nil
            else { throw BIP32Error.invalidSerializedKey }
            return HDKey(depth: depth, parentFingerprint: parentFingerprint, childIndex: childIndex,
                         chainCode: chainCode, privateKey: nil, publicKey: keyData)
        }
    }

    static func hmacSHA512(key: Data, data: Data) -> Data {
        Data(HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    static func publicKey(for secret: Data) throws -> Data {
        try P256K.Signing.PrivateKey(dataRepresentation: secret).publicKey.dataRepresentation
    }
}
