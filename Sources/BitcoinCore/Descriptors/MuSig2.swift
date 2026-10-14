import CryptoKit
import Foundation
import P256K

/// BIP327 MuSig2 two-round signing protocol, built on the same public P256K
/// point/scalar operations as the KeyAgg implementation in MuSig.swift.
/// Nonces and partial signatures travel between cosigners via the BIP373 PSBT
/// fields (see WalletCore's PSBT extensions).
///
/// All public byte strings follow the BIP327 serializations: plain public
/// keys 33-byte compressed, public nonces 66 bytes (two compressed points),
/// aggregate nonces 66 bytes (an all-zero 33-byte component encodes the
/// point at infinity), partial signatures 32 bytes.
extension MuSig {
    public enum MuSig2Error: Error, Equatable {
        case invalidPublicKey
        case invalidNonce
        case invalidSecretKey
        case invalidTweak
        case invalidPartialSignature
        /// A signer contributed a key/nonce/signature that fails verification.
        case invalidContribution(String)
        /// The signer's public key is not among the session's participants.
        case unknownSigner
        /// The secret nonce was already used (it is zeroed after signing).
        case secnonceReused
        /// Secret nonce does not belong to this public key.
        case secnonceMismatch
    }

    /// BIP327 KeyAgg context: the aggregate point plus the accumulated parity
    /// (gacc) and tweak (tacc) scalars. Tweaks are applied with `applyTweak`;
    /// signers need gacc to possibly negate their secret key, the aggregator
    /// needs tacc to produce the final signature.
    public struct KeyAggContext: Equatable, Sendable {
        /// The aggregate point Q (compressed), after all tweaks so far.
        public private(set) var aggregateKey: Data
        /// gacc as a 32-byte scalar (1 or n−1 times the previous value, mod n).
        public private(set) var parityAccumulator: Data
        /// tacc as a 32-byte scalar (0 when untweaked).
        public private(set) var tweakAccumulator: Data

        init(aggregateKey: Data, parityAccumulator: Data, tweakAccumulator: Data) {
            self.aggregateKey = aggregateKey
            self.parityAccumulator = parityAccumulator
            self.tweakAccumulator = tweakAccumulator
        }

        /// x-only form of the (possibly tweaked) aggregate key — the key the
        /// final BIP340 signature verifies against.
        public var xonlyAggregateKey: Data { Data(aggregateKey.dropFirst()) }

        /// Whether the aggregate point has even Y.
        var hasEvenY: Bool { aggregateKey.first == 0x02 }
    }

    /// A 32-byte one (mod-n identity) and zero scalar.
    static let scalarOne = Data(repeating: 0, count: 31) + Data([0x01])
    static let scalarZero = Data(repeating: 0, count: 32)

    /// BIP327 KeyAgg as a context (gacc = 1, tacc = 0). Keys must be sorted
    /// with `keySort` first when the protocol requires sorting (BIP390 does).
    public static func keyAggContext(publicKeys: [Data]) throws -> KeyAggContext {
        let aggregateKey: Data
        do {
            aggregateKey = try aggregate(publicKeys)
        } catch {
            // BIP327 InvalidContributionError: a participant key is invalid.
            throw MuSig2Error.invalidContribution("pubkey")
        }
        return KeyAggContext(aggregateKey: aggregateKey,
                             parityAccumulator: scalarOne, tweakAccumulator: scalarZero)
    }

    /// BIP327 ApplyTweak: Q′ = g·Q + t·G with g = −1 when an x-only tweak
    /// meets an odd-Y Q (and g = 1 otherwise); gacc′ = g·gacc, tacc′ = t + g·tacc.
    /// The Taproot output-key tweak (BIP341 TapTweak hash) is an x-only tweak;
    /// BIP328 derivation steps from the synthetic aggregate xpub are plain tweaks.
    public static func applyTweak(_ context: KeyAggContext, tweak: Data, isXOnly: Bool) throws -> KeyAggContext {
        guard tweak.count == 32, tweak.lexicographicallyPrecedes(groupOrder) else {
            throw MuSig2Error.invalidTweak
        }
        let negate = isXOnly && !context.hasEvenY
        let point = try parsePoint(context.aggregateKey)
        let adjusted = negate ? point.negation : point
        guard let tweaked = try? adjusted.add([UInt8](tweak), format: .compressed) else {
            throw MuSig2Error.invalidTweak // tweaked point at infinity
        }
        let g = negate ? groupOrderMinusOne : scalarOne
        return KeyAggContext(aggregateKey: tweaked.dataRepresentation,
                             parityAccumulator: try scalarMultiply(g, context.parityAccumulator),
                             tweakAccumulator: try scalarAdd(tweak, scalarMultiply(g, context.tweakAccumulator)))
    }

    /// BIP327 NonceGen: two secret scalars k_1, k_2 derived from the random
    /// `rand` (XORed with a MuSig/aux-tagged hash when a secret key is given),
    /// the signer's plain public key, the aggregate key, the message and
    /// arbitrary extra input (e.g. a session counter). The returned secret
    /// nonce is single-use: `partialSign` zeroes it.
    /// BIP327's rand masking: with a secret key present, rand is XORed with
    /// TaggedHash("MuSig/aux", rand) of it, so a broken RNG alone cannot
    /// leak the nonce relationship.
    private static func maskedRand(_ rand: Data, secretKey: Data?) -> Data {
        guard let secretKey else { return rand }
        let mask = TaggedHash.hash("MuSig/aux", rand)
        return Data(zip(secretKey, mask).map { $0 ^ $1 })
    }

    /// The optional message, tagged and length-prefixed exactly as BIP327's
    /// NonceGen hashes it: 0x00 for absent, 0x01 || len64be || message.
    private static func lengthPrefixed(_ message: Data?) -> Data {
        var prefixed = Data()
        guard let message else {
            prefixed.append(0x00)
            return prefixed
        }
        prefixed.append(0x01)
        var length = UInt64(message.count).bigEndian
        withUnsafeBytes(of: &length) { prefixed.append(contentsOf: $0) }
        prefixed.append(message)
        return prefixed
    }

    public static func nonceGenerate(secretKey: Data? = nil, publicKey: Data,
                                     aggregateKey: Data? = nil, message: Data? = nil,
                                     extraInput: Data? = nil, rand: Data? = nil) throws
        -> (secretNonce: Data, publicNonce: Data)
    {
        let rand = rand ?? randomBytes(32)
        guard rand.count == 32, publicKey.count == 33 else { throw MuSig2Error.invalidNonce }
        if let secretKey { guard secretKey.count == 32 else { throw MuSig2Error.invalidSecretKey } }
        if let aggregateKey { guard aggregateKey.count == 32 else { throw MuSig2Error.invalidNonce } }
        let randValue = maskedRand(rand, secretKey: secretKey)
        let prefixed = lengthPrefixed(message)
        func nonceHash(_ index: UInt8) throws -> Data {
            var buffer = Data()
            buffer.append(randValue)
            buffer.append(UInt8(publicKey.count))
            buffer.append(publicKey)
            buffer.append(UInt8(aggregateKey?.count ?? 0))
            if let aggregateKey { buffer.append(aggregateKey) }
            buffer.append(prefixed)
            let extra = extraInput ?? Data()
            var extraLength = UInt32(extra.count).bigEndian
            withUnsafeBytes(of: &extraLength) { buffer.append(contentsOf: $0) }
            buffer.append(extra)
            buffer.append(index)
            return TaggedHash.hash("MuSig/nonce", buffer)
        }
        let k1 = reduceModGroupOrder(try nonceHash(0))
        let k2 = reduceModGroupOrder(try nonceHash(1))
        guard Data(k1) != scalarZero, Data(k2) != scalarZero else { throw MuSig2Error.invalidNonce }
        let r1 = try privateToPublic(Data(k1))
        let r2 = try privateToPublic(Data(k2))
        return (Data(k1) + Data(k2) + publicKey, r1 + r2)
    }

    /// BIP327 NonceAgg: component-wise point sums of the public nonces; a
    /// component summing to the point at infinity is encoded as 33 zero bytes.
    public static func nonceAggregate(publicNonces: [Data]) throws -> Data {
        guard !publicNonces.isEmpty, publicNonces.allSatisfy({ $0.count == 66 }) else {
            throw MuSig2Error.invalidNonce
        }
        var aggregate = Data()
        for component in 0 ..< 2 {
            var points: [P256K.Signing.PublicKey] = []
            for nonce in publicNonces {
                let start = nonce.startIndex + component * 33
                let serialized = nonce.subdata(in: start ..< start + 33)
                guard let point = try? P256K.Signing.PublicKey(dataRepresentation: serialized,
                                                               format: .compressed)
                else { throw MuSig2Error.invalidContribution("pubnonce") }
                points.append(point)
            }
            if let sum = addPoints(points) {
                aggregate.append(sum.dataRepresentation)
            } else {
                aggregate.append(Data(repeating: 0, count: 33)) // infinity encoding (BIP327)
            }
        }
        return aggregate
    }

    /// Everything a signer/verifier/aggregator needs for one signing session:
    /// the aggregate nonce, the (sorted) participant keys, the tweak chain
    /// (BIP328 path tweaks with isXOnly = false, then the BIP341 TapTweak with
    /// isXOnly = true) and the 32-byte message (for the vault: the BIP341
    /// key-path sighash).
    public struct Session: Equatable, Sendable {
        public var aggregateNonce: Data
        public var publicKeys: [Data]
        public var tweaks: [Data]
        public var isXOnlyTweaks: [Bool]
        public var message: Data

        public init(aggregateNonce: Data, publicKeys: [Data], tweaks: [Data] = [],
                    isXOnlyTweaks: [Bool] = [], message: Data) {
            self.aggregateNonce = aggregateNonce
            self.publicKeys = publicKeys
            self.tweaks = tweaks
            self.isXOnlyTweaks = isXOnlyTweaks
            self.message = message
        }

        /// BIP327 GetSessionValues: the tweaked aggregate key context, nonce
        /// coefficient b, effective nonce point R, and challenge e.
        func values() throws -> (context: KeyAggContext, b: Data, noncePoint: Data, challenge: Data) {
            guard tweaks.count == isXOnlyTweaks.count else { throw MuSig2Error.invalidTweak }
            var context = try keyAggContext(publicKeys: publicKeys)
            for (tweak, isXOnly) in zip(tweaks, isXOnlyTweaks) {
                context = try applyTweak(context, tweak: tweak, isXOnly: isXOnly)
            }
            guard aggregateNonce.count == 66 else { throw MuSig2Error.invalidNonce }
            let b = Data(reduceModGroupOrder(TaggedHash.hash("MuSig/noncecoef",
                                                             aggregateNonce + context.xonlyAggregateKey + message)))
            // cpoint_ext: an all-zero component is the point at infinity.
            let r1 = try parsePointExt(aggregateNonce.prefix(33))
            let r2 = try parsePointExt(aggregateNonce.suffix(33))
            let effective = addPoints(r1, try r2.map { try multiplyPoint($0, b) } ?? nil)
            // BIP327: an infinity effective nonce is replaced by the generator.
            let noncePoint = try effective.map { $0.dataRepresentation }
                ?? privateToPublic(scalarOne)
            var challengeInput = Data(noncePoint.dropFirst())
            challengeInput.append(context.xonlyAggregateKey)
            challengeInput.append(message)
            let challenge = Data(reduceModGroupOrder(TaggedHash.hash("BIP0340/challenge", challengeInput)))
            return (context, b, noncePoint, challenge)
        }

        /// The key aggregate coefficient of `publicKey` in this session (BIP327).
        func coefficient(of publicKey: Data) throws -> Data {
            guard publicKeys.contains(publicKey) else { throw MuSig2Error.unknownSigner }
            let listHash = TaggedHash.hash("KeyAgg list", publicKeys.reduce(Data(), +))
            var secondKey: Data?
            for key in publicKeys.dropFirst() where key != publicKeys[0] {
                secondKey = key
                break
            }
            if publicKey == secondKey { return scalarOne }
            return Data(reduceModGroupOrder(TaggedHash.hash("KeyAgg coefficient", listHash + publicKey)))
        }
    }

    /// BIP327 Sign: the 32-byte partial signature. The secret nonce is zeroed
    /// in place — reusing a secnonce across sessions leaks the secret key.
    public static func partialSign(secretNonce: inout Data, secretKey: Data, session: Session) throws -> Data {
        defer { secretNonce.replaceSubrange(secretNonce.startIndex..., with: Data(repeating: 0, count: secretNonce.count)) }
        guard secretNonce.count == 97 else { throw MuSig2Error.invalidNonce }
        let (context, b, noncePoint, challenge) = try session.values()
        var k1 = secretNonce.prefix(32)
        var k2 = secretNonce.subdata(in: secretNonce.startIndex + 32 ..< secretNonce.startIndex + 64)
        guard Data(k1) != scalarZero, Data(k2) != scalarZero else { throw MuSig2Error.secnonceReused }
        let nonceIsOdd = noncePoint.first == 0x03
        if nonceIsOdd { // negate both nonce scalars (BIP327 Sign)
            k1 = try scalarNegate(Data(k1))
            k2 = try scalarNegate(Data(k2))
        }
        let secret = secretKey
        guard secret.count == 32, secret != scalarZero, secret.lexicographicallyPrecedes(groupOrder) else {
            throw MuSig2Error.invalidSecretKey
        }
        let publicKey = try privateToPublic(secret)
        guard publicKey == secretNonce.suffix(33) else { throw MuSig2Error.secnonceMismatch }
        let coefficient = try session.coefficient(of: publicKey)
        // d = g · gacc · d′ with g = −1 when the tweaked aggregate key is odd-Y.
        var effectiveSecret = secret
        if !context.hasEvenY { effectiveSecret = try scalarNegate(effectiveSecret) }
        if context.parityAccumulator != scalarOne { effectiveSecret = try scalarNegate(effectiveSecret) }
        let signaturePart = try scalarMultiply(challenge, scalarMultiply(coefficient, effectiveSecret))
        return try scalarAdd(Data(k1), scalarAdd(scalarMultiply(b, Data(k2)), signaturePart))
    }

    /// BIP327 PartialSigVerify: s·G == R_s + e·a·g·gacc·P with R_s the
    /// signer's effective nonce (negated when the aggregate nonce point is odd-Y).
    public static func partialVerify(partialSignature: Data, publicNonce: Data,
                                     publicKey: Data, session: Session) throws -> Bool {
        guard partialSignature.count == 32, publicNonce.count == 66, publicKey.count == 33 else {
            throw MuSig2Error.invalidPartialSignature
        }
        guard partialSignature != scalarZero, partialSignature.lexicographicallyPrecedes(groupOrder) else { return false }
        let (context, b, noncePoint, challenge) = try session.values()
        guard let r1 = try? parsePoint(publicNonce.prefix(33)),
              let r2 = try? parsePoint(publicNonce.suffix(33))
        else { throw MuSig2Error.invalidContribution("pubnonce") }
        var effective = addPoints(r1, try multiplyPoint(r2, b))
        if noncePoint.first == 0x03 { effective = effective?.negation }
        let point = try parsePoint(publicKey)
        let coefficient = try session.coefficient(of: publicKey)
        // g′ = g · gacc with g = −1 when the tweaked aggregate key is odd-Y.
        var factor = context.parityAccumulator
        if !context.hasEvenY { factor = try scalarNegate(factor) }
        factor = try scalarMultiply(challenge, scalarMultiply(coefficient, factor))
        let scaled = try multiplyPoint(point, factor)
        guard let right = addPoints(effective, scaled) else { return false }
        return try privateToPublic(partialSignature) == right.dataRepresentation
    }

    /// BIP327 PartialSigAgg: the 64-byte BIP340 signature x(R) || s with
    /// s = Σ s_i + e·g·tacc, valid for the tweaked aggregate key.
    public static func partialSigAggregate(partialSignatures: [Data], session: Session) throws -> Data {
        let (context, _, noncePoint, challenge) = try session.values()
        var sum = scalarZero
        for signature in partialSignatures {
            guard signature.count == 32 else { throw MuSig2Error.invalidPartialSignature }
            guard signature.lexicographicallyPrecedes(groupOrder) else {
                throw MuSig2Error.invalidContribution("psig")
            }
            sum = try scalarAdd(sum, signature)
        }
        if context.tweakAccumulator != scalarZero {
            var factor = context.tweakAccumulator
            if !context.hasEvenY { factor = try scalarNegate(factor) }
            sum = try scalarAdd(sum, scalarMultiply(challenge, factor))
        }
        return Data(noncePoint.dropFirst()) + sum
    }

    /// The x-only aggregate key after applying the whole tweak chain — the
    /// key that appears in the Taproot output and that the final signature
    /// verifies against.
    public static func aggregateXonly(publicKeys: [Data], tweaks: [Data], isXOnlyTweaks: [Bool]) throws -> Data {
        Data(try aggregate(publicKeys: publicKeys, tweaks: tweaks, isXOnlyTweaks: isXOnlyTweaks).dropFirst())
    }

    /// The tweaked compressed key, including the parity required by BIP373.
    public static func aggregate(publicKeys: [Data], tweaks: [Data], isXOnlyTweaks: [Bool]) throws -> Data {
        guard tweaks.count == isXOnlyTweaks.count else { throw MuSig2Error.invalidTweak }
        var context = try keyAggContext(publicKeys: publicKeys)
        for (tweak, isXOnly) in zip(tweaks, isXOnlyTweaks) {
            context = try applyTweak(context, tweak: tweak, isXOnly: isXOnly)
        }
        return context.aggregateKey
    }

    /// The BIP328 plain-tweak for one unhardened BIP32 step from the synthetic
    /// aggregate xpub: IL = HMAC-SHA512(chainCode, compressedKey ‖ index)[0:32].
    /// Signers apply it with `applyTweak(_, isXOnly: false)`; the matching
    /// public derivation lives in `MuSig.syntheticExtendedKey`.
    public static func bip328Tweak(chainCode: Data, aggregatePublicKey: Data, index: UInt32) -> Data {
        var data = Data()
        data.append(aggregatePublicKey)
        var bigEndianIndex = index.bigEndian
        withUnsafeBytes(of: &bigEndianIndex) { data.append(contentsOf: $0) }
        return Data(HMAC<CryptoKit.SHA512>.authenticationCode(for: data, using: SymmetricKey(data: chainCode)).prefix(32))
    }

    // MARK: - Scalar and point helpers (mod n, via P256K)

    static let groupOrderMinusOne: Data = {
        var bytes = [UInt8](groupOrder)
        bytes[31] &-= 1
        return Data(bytes)
    }()

    static func scalarIsValid(_ scalar: Data) -> Bool {
        scalar.count == 32 && scalar != scalarZero && scalar.lexicographicallyPrecedes(groupOrder)
    }

    /// (a + b) mod n. Zero operands are passed through (the only structural
    /// zero in BIP327 is tacc); a zero result throws (negligible probability).
    static func scalarAdd(_ a: Data, _ b: Data) throws -> Data {
        if a == scalarZero { return b }
        if b == scalarZero { return a }
        guard scalarIsValid(a), scalarIsValid(b),
              let key = try? P256K.Signing.PrivateKey(dataRepresentation: a),
              let sum = try? key.add([UInt8](b))
        else { throw MuSig2Error.invalidSecretKey }
        return sum.dataRepresentation
    }

    /// (a · b) mod n; zero times anything is zero.
    static func scalarMultiply(_ a: Data, _ b: Data) throws -> Data {
        if a == scalarZero || b == scalarZero { return scalarZero }
        guard scalarIsValid(a), scalarIsValid(b),
              let key = try? P256K.Signing.PrivateKey(dataRepresentation: a),
              let product = try? key.multiply([UInt8](b))
        else { throw MuSig2Error.invalidSecretKey }
        return product.dataRepresentation
    }

    /// −s mod n (zero stays zero).
    static func scalarNegate(_ scalar: Data) throws -> Data {
        if scalar == scalarZero { return scalarZero }
        guard scalarIsValid(scalar),
              let key = try? P256K.Signing.PrivateKey(dataRepresentation: scalar)
        else { throw MuSig2Error.invalidSecretKey }
        return key.negation.dataRepresentation
    }

    /// s·G as a compressed public key (s must be a valid nonzero scalar).
    static func privateToPublic(_ scalar: Data) throws -> Data {
        guard scalarIsValid(scalar),
              let key = try? P256K.Signing.PrivateKey(dataRepresentation: scalar)
        else { throw MuSig2Error.invalidSecretKey }
        return key.publicKey.dataRepresentation
    }

    static func parsePoint(_ serialized: Data.SubSequence) throws -> P256K.Signing.PublicKey {
        guard let point = try? P256K.Signing.PublicKey(dataRepresentation: serialized, format: .compressed) else {
            throw MuSig2Error.invalidPublicKey
        }
        return point
    }

    /// cpoint_ext (BIP327): 33 zero bytes decode to the point at infinity (nil).
    static func parsePointExt(_ serialized: Data.SubSequence) throws -> P256K.Signing.PublicKey? {
        if serialized.allSatisfy({ $0 == 0 }) { return nil }
        return try parsePoint(serialized)
    }

    /// Point addition where nil is the point at infinity; a nil result means
    /// the sum is infinity (P256K's combine fails on that case).
    static func addPoints(_ a: P256K.Signing.PublicKey?, _ b: P256K.Signing.PublicKey?) -> P256K.Signing.PublicKey? {
        switch (a, b) {
        case (nil, nil): return nil
        case let (point?, nil): return point
        case let (nil, point?): return point
        case let (first?, second?):
            return try? first.combine([second], format: .compressed)
        }
    }

    static func addPoints(_ points: [P256K.Signing.PublicKey]) -> P256K.Signing.PublicKey? {
        guard let first = points.first else { return nil }
        return try? first.combine(Array(points.dropFirst()), format: .compressed)
    }

    /// Scalar times point; a zero scalar yields the point at infinity (nil).
    static func multiplyPoint(_ point: P256K.Signing.PublicKey, _ scalar: Data) throws -> P256K.Signing.PublicKey? {
        if scalar == scalarZero { return nil }
        guard scalarIsValid(scalar), let scaled = try? point.multiply([UInt8](scalar)) else {
            throw MuSig2Error.invalidPublicKey
        }
        return scaled
    }

    static func randomBytes(_ count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0 ..< count).map { _ in UInt8.random(in: 0 ... 255, using: &generator) })
    }
}
