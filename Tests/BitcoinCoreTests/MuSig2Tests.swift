import Foundation
import P256K
import Testing
import TestSupport
@testable import BitcoinCore
@testable import WalletCore

/// Official BIP327 MuSig2 test vectors (bitcoin/bips bip-0327/vectors):
/// key sorting, key aggregation with tweaks, nonce generation/aggregation,
/// partial signing/verification, and final signature aggregation — including
/// the x-only tweak cases that Taproot vaults rely on.
@Suite("BIP327 MuSig2 vectors")
struct MuSig2Tests {
    static func vectors(_ name: String) throws -> [String: Any] {
        try Vectors.json(name, in: .module, subdirectory: "Vectors/bip327") as! [String: Any]
    }

    static func hex(_ value: String) -> Data { value.isEmpty ? Data() : Data(hex: value)! }
    static func hexList(_ value: Any) -> [Data] { (value as! [String]).map(hex) }

    @Test("key sort")
    func keySort() throws {
        let vectors = try Self.vectors("key_sort_vectors.json")
        let pubkeys = Self.hexList(vectors["pubkeys"]!)
        let sorted = Self.hexList(vectors["sorted_pubkeys"]!)
        #expect(MuSig.keySort(pubkeys) == sorted)
    }

    @Test("key aggregation, including tweaked contexts")
    func keyAgg() throws {
        let vectors = try Self.vectors("key_agg_vectors.json")
        let pubkeys = Self.hexList(vectors["pubkeys"]!)
        let tweaks = Self.hexList(vectors["tweaks"]!)
        for testCase in vectors["valid_test_cases"] as! [[String: Any]] {
            let keys = (testCase["key_indices"] as! [Int]).map { pubkeys[$0] }
            let context = try MuSig.keyAggContext(publicKeys: keys)
            #expect(context.xonlyAggregateKey == Self.hex(testCase["expected"] as! String))
            #expect(context.parityAccumulator == MuSig.scalarOne)
            #expect(context.tweakAccumulator == MuSig.scalarZero)
        }
        for testCase in vectors["error_test_cases"] as! [[String: Any]] {
            let keys = (testCase["key_indices"] as! [Int]).map { pubkeys[$0] }
            let caseTweaks = (testCase["tweak_indices"] as! [Int]).map { tweaks[$0] }
            let isXOnly = testCase["is_xonly"] as! [Bool]
            #expect(throws: MuSig.MuSig2Error.self) {
                var context = try MuSig.keyAggContext(publicKeys: keys)
                for (tweak, xonly) in zip(caseTweaks, isXOnly) {
                    context = try MuSig.applyTweak(context, tweak: tweak, isXOnly: xonly)
                }
            }
        }
    }

    @Test("nonce generation")
    func nonceGen() throws {
        let vectors = try Self.vectors("nonce_gen_vectors.json")
        for (index, testCase) in (vectors["test_cases"] as! [[String: Any]]).enumerated() {
            // BIP327 distinguishes an absent message (0x00 prefix) from an
            // empty one (0x01 || 8-byte length) — "" is the empty byte array.
            func maybe(_ key: String) -> Data? { (testCase[key] as? String).map(Self.hex) }
            let (secretNonce, publicNonce) = try MuSig.nonceGenerate(
                secretKey: maybe("sk"),
                publicKey: Self.hex(testCase["pk"] as! String),
                aggregateKey: maybe("aggpk"),
                message: maybe("msg"),
                extraInput: maybe("extra_in"),
                rand: Self.hex(testCase["rand_"] as! String))
            #expect(secretNonce == Self.hex(testCase["expected_secnonce"] as! String), "case \(index)")
            #expect(publicNonce == Self.hex(testCase["expected_pubnonce"] as! String), "case \(index)")
        }
    }

    @Test("nonce aggregation, with the infinity encoding")
    func nonceAgg() throws {
        let vectors = try Self.vectors("nonce_agg_vectors.json")
        let nonces = Self.hexList(vectors["pnonces"]!)
        for testCase in vectors["valid_test_cases"] as! [[String: Any]] {
            let selected = (testCase["pnonce_indices"] as! [Int]).map { nonces[$0] }
            #expect(try MuSig.nonceAggregate(publicNonces: selected) == Self.hex(testCase["expected"] as! String))
        }
        for testCase in vectors["error_test_cases"] as! [[String: Any]] {
            let selected = (testCase["pnonce_indices"] as! [Int]).map { nonces[$0] }
            #expect(throws: MuSig.MuSig2Error.self) { _ = try MuSig.nonceAggregate(publicNonces: selected) }
        }
    }

    @Test("partial sign and verify")
    func signVerify() throws {
        let vectors = try Self.vectors("sign_verify_vectors.json")
        let secret = Self.hex(vectors["sk"] as! String)
        let pubkeys = Self.hexList(vectors["pubkeys"]!)
        let secnonces = Self.hexList(vectors["secnonces"]!)
        let nonces = Self.hexList(vectors["pnonces"]!)
        let aggnonces = Self.hexList(vectors["aggnonces"]!)
        let messages = Self.hexList(vectors["msgs"]!)

        for testCase in vectors["valid_test_cases"] as! [[String: Any]] {
            let keys = (testCase["key_indices"] as! [Int]).map { pubkeys[$0] }
            let selected = (testCase["nonce_indices"] as! [Int]).map { nonces[$0] }
            let aggnonce = aggnonces[testCase["aggnonce_index"] as! Int]
            // The vector nonces must aggregate to the given aggnonce.
            #expect(try MuSig.nonceAggregate(publicNonces: selected) == aggnonce)
            let message = messages[testCase["msg_index"] as! Int]
            let signerIndex = testCase["signer_index"] as! Int
            let expected = Self.hex(testCase["expected"] as! String)

            let session = MuSig.Session(aggregateNonce: aggnonce, publicKeys: keys, message: message)
            var secnonce = secnonces[0]
            let partial = try MuSig.partialSign(secretNonce: &secnonce, secretKey: secret, session: session)
            #expect(partial == expected)
            #expect(secnonce.allSatisfy { $0 == 0 }) // single-use: zeroed after signing
            #expect(try MuSig.partialVerify(partialSignature: partial, publicNonce: selected[signerIndex],
                                            publicKey: keys[signerIndex], session: session))
        }

        for testCase in vectors["sign_error_test_cases"] as! [[String: Any]] {
            let keys = (testCase["key_indices"] as! [Int]).map { pubkeys[$0] }
            let session = MuSig.Session(aggregateNonce: aggnonces[testCase["aggnonce_index"] as! Int],
                                        publicKeys: keys, message: messages[testCase["msg_index"] as! Int])
            var secnonce = secnonces[testCase["secnonce_index"] as! Int]
            #expect(throws: MuSig.MuSig2Error.self) {
                _ = try MuSig.partialSign(secretNonce: &secnonce, secretKey: secret, session: session)
            }
        }

        for testCase in vectors["verify_fail_test_cases"] as! [[String: Any]] {
            let keys = (testCase["key_indices"] as! [Int]).map { pubkeys[$0] }
            let selected = (testCase["nonce_indices"] as! [Int]).map { nonces[$0] }
            let signerIndex = testCase["signer_index"] as! Int
            let session = MuSig.Session(aggregateNonce: try MuSig.nonceAggregate(publicNonces: selected),
                                        publicKeys: keys, message: messages[testCase["msg_index"] as! Int])
            let valid = try MuSig.partialVerify(partialSignature: Self.hex(testCase["sig"] as! String),
                                                publicNonce: selected[signerIndex],
                                                publicKey: keys[signerIndex], session: session)
            #expect(!valid)
        }

        for testCase in vectors["verify_error_test_cases"] as! [[String: Any]] {
            let keys = (testCase["key_indices"] as! [Int]).map { pubkeys[$0] }
            let selected = (testCase["nonce_indices"] as! [Int]).map { nonces[$0] }
            let signerIndex = testCase["signer_index"] as! Int
            #expect(throws: MuSig.MuSig2Error.self) {
                let session = MuSig.Session(aggregateNonce: try MuSig.nonceAggregate(publicNonces: selected),
                                            publicKeys: keys, message: messages[testCase["msg_index"] as! Int])
                _ = try MuSig.partialVerify(partialSignature: Self.hex(testCase["sig"] as! String),
                                            publicNonce: selected[signerIndex],
                                            publicKey: keys[signerIndex], session: session)
            }
        }
    }

    @Test("signing with plain and x-only tweaks (the Taproot vault shape)")
    func tweaks() throws {
        let vectors = try Self.vectors("tweak_vectors.json")
        let secret = Self.hex(vectors["sk"] as! String)
        let pubkeys = Self.hexList(vectors["pubkeys"]!)
        let secnonce = Self.hex(vectors["secnonce"] as! String)
        let nonces = Self.hexList(vectors["pnonces"]!)
        let aggnonce = Self.hex(vectors["aggnonce"] as! String)
        let tweaks = Self.hexList(vectors["tweaks"]!)
        let message = Self.hex(vectors["msg"] as! String)

        for testCase in vectors["valid_test_cases"] as! [[String: Any]] {
            let keys = (testCase["key_indices"] as! [Int]).map { pubkeys[$0] }
            let caseTweaks = (testCase["tweak_indices"] as! [Int]).map { tweaks[$0] }
            let isXOnly = testCase["is_xonly"] as! [Bool]
            let signerIndex = testCase["signer_index"] as! Int
            let session = MuSig.Session(aggregateNonce: aggnonce, publicKeys: keys,
                                        tweaks: caseTweaks, isXOnlyTweaks: isXOnly, message: message)
            var nonce = secnonce
            let partial = try MuSig.partialSign(secretNonce: &nonce, secretKey: secret, session: session)
            #expect(partial == Self.hex(testCase["expected"] as! String))
            let selected = (testCase["nonce_indices"] as! [Int]).map { nonces[$0] }
            #expect(try MuSig.partialVerify(partialSignature: partial, publicNonce: selected[signerIndex],
                                            publicKey: keys[signerIndex], session: session))
        }

        for testCase in vectors["error_test_cases"] as! [[String: Any]] {
            let keys = (testCase["key_indices"] as! [Int]).map { pubkeys[$0] }
            let caseTweaks = (testCase["tweak_indices"] as! [Int]).map { tweaks[$0] }
            let session = MuSig.Session(aggregateNonce: aggnonce, publicKeys: keys,
                                        tweaks: caseTweaks, isXOnlyTweaks: testCase["is_xonly"] as! [Bool],
                                        message: message)
            var nonce = secnonce
            #expect(throws: MuSig.MuSig2Error.self) {
                _ = try MuSig.partialSign(secretNonce: &nonce, secretKey: secret, session: session)
            }
        }
    }

    @Test("partial signature aggregation yields a BIP340-verifiable signature")
    func sigAgg() throws {
        let vectors = try Self.vectors("sig_agg_vectors.json")
        let pubkeys = Self.hexList(vectors["pubkeys"]!)
        let nonces = Self.hexList(vectors["pnonces"]!)
        let tweaks = Self.hexList(vectors["tweaks"]!)
        let partials = Self.hexList(vectors["psigs"]!)
        let message = Self.hex(vectors["msg"] as! String)

        for testCase in vectors["valid_test_cases"] as! [[String: Any]] {
            let keys = (testCase["key_indices"] as! [Int]).map { pubkeys[$0] }
            let caseTweaks = (testCase["tweak_indices"] as! [Int]).map { tweaks[$0] }
            let isXOnly = testCase["is_xonly"] as! [Bool]
            let sigs = (testCase["psig_indices"] as! [Int]).map { partials[$0] }
            let aggnonce = Self.hex(testCase["aggnonce"] as! String)
            // The vector nonces must aggregate to the given aggnonce.
            let selected = (testCase["nonce_indices"] as! [Int]).map { nonces[$0] }
            #expect(try MuSig.nonceAggregate(publicNonces: selected) == aggnonce)
            let session = MuSig.Session(aggregateNonce: aggnonce, publicKeys: keys,
                                        tweaks: caseTweaks, isXOnlyTweaks: isXOnly, message: message)
            let signature = try MuSig.partialSigAggregate(partialSignatures: sigs, session: session)
            #expect(signature == Self.hex(testCase["expected"] as! String))
            // The aggregate signature verifies against the tweaked aggregate key.
            let aggregateKey = try MuSig.aggregateXonly(publicKeys: keys, tweaks: caseTweaks, isXOnlyTweaks: isXOnly)
            let key = P256K.Schnorr.XonlyKey(dataRepresentation: aggregateKey)
            var messageBytes = [UInt8](message)
            #expect(key.isValid(try P256K.Schnorr.SchnorrSignature(dataRepresentation: signature),
                                for: &messageBytes))
        }

        for testCase in vectors["error_test_cases"] as! [[String: Any]] {
            let keys = (testCase["key_indices"] as! [Int]).map { pubkeys[$0] }
            let caseTweaks = (testCase["tweak_indices"] as! [Int]).map { tweaks[$0] }
            let sigs = (testCase["psig_indices"] as! [Int]).map { partials[$0] }
            let session = MuSig.Session(aggregateNonce: Self.hex(testCase["aggnonce"] as! String),
                                        publicKeys: keys, tweaks: caseTweaks,
                                        isXOnlyTweaks: testCase["is_xonly"] as! [Bool], message: message)
            #expect(throws: MuSig.MuSig2Error.self) {
                _ = try MuSig.partialSigAggregate(partialSignatures: sigs, session: session)
            }
        }
    }
}

// MARK: - Session safety

/// Adversarial MuSig2 session handling (epic #100, invariant S4).
///
/// `MuSig2Tests` proves the BIP327 vectors compute the right answers on the
/// happy path. This suite proves the opposite: that a secret nonce cannot be
/// used twice, cannot survive a failed or cancelled attempt, cannot be moved
/// between signers or sessions, and that a partial signature cannot be
/// replayed into a session it was not produced for.
///
/// Nonce reuse is the one MuSig2 mistake with catastrophic consequences, and
/// it is reached through ordinary operational accidents — a retried signing
/// attempt, a restored PSBT, two vault screens open at once — rather than
/// through cryptographic weakness. Every test here therefore asserts a
/// *refusal*, not a computation.
@Suite("MuSig2 session safety")
struct MuSig2SessionSafetyTests {
    /// A deterministic 2-of-2 MuSig2 setup. Fixed scalars and fixed nonce
    /// randomness keep every failure reproducible from the source alone.
    struct Fixture {
        let secretKeys: [Data]
        let publicKeys: [Data]
        let secretNonces: [Data]
        let publicNonces: [Data]

        init(nonceSeed: UInt8 = 0xA0) throws {
            let secrets = [
                Data(repeating: 0x11, count: 32),
                Data(repeating: 0x22, count: 32),
            ]
            secretKeys = secrets
            publicKeys = try secrets.map { try MuSig.privateToPublic($0) }
            var secNonces: [Data] = []
            var pubNonces: [Data] = []
            for (offset, secret) in secrets.enumerated() {
                let generated = try MuSig.nonceGenerate(
                    secretKey: secret,
                    publicKey: try MuSig.privateToPublic(secret),
                    rand: Data(repeating: nonceSeed &+ UInt8(offset), count: 32))
                secNonces.append(generated.secretNonce)
                pubNonces.append(generated.publicNonce)
            }
            secretNonces = secNonces
            publicNonces = pubNonces
        }

        func session(message: Data) throws -> MuSig.Session {
            MuSig.Session(aggregateNonce: try MuSig.nonceAggregate(publicNonces: publicNonces),
                          publicKeys: publicKeys,
                          message: message)
        }
    }

    static let messageA = Data(repeating: 0x01, count: 32)
    static let messageB = Data(repeating: 0x02, count: 32)

    /// The core one-use property: having signed one message, the same secret
    /// nonce must not sign a second. This is the reuse that leaks key material
    /// across concurrent sessions, so the refusal has to be unconditional.
    @Test("a secret nonce cannot sign a second message")
    func nonceRefusedForSecondMessage() throws {
        let fixture = try Fixture()
        var secretNonce = fixture.secretNonces[0]

        let first = try MuSig.partialSign(secretNonce: &secretNonce,
                                          secretKey: fixture.secretKeys[0],
                                          session: try fixture.session(message: Self.messageA))
        #expect(first.count == 32)
        #expect(secretNonce.allSatisfy { $0 == 0 }, "signing must consume the secret nonce")

        #expect(throws: MuSig.MuSig2Error.secnonceReused) {
            _ = try MuSig.partialSign(secretNonce: &secretNonce,
                                      secretKey: fixture.secretKeys[0],
                                      session: try fixture.session(message: Self.messageB))
        }
    }

    /// Re-signing the *same* message is refused too. A user who taps sign
    /// twice, or a PSBT restored from disk after a partial failure, must not
    /// find a live nonce waiting.
    @Test("a secret nonce cannot re-sign the same message")
    func nonceRefusedForRepeatOfSameMessage() throws {
        let fixture = try Fixture()
        var secretNonce = fixture.secretNonces[0]
        let session = try fixture.session(message: Self.messageA)

        _ = try MuSig.partialSign(secretNonce: &secretNonce,
                                  secretKey: fixture.secretKeys[0], session: session)
        #expect(throws: MuSig.MuSig2Error.secnonceReused) {
            _ = try MuSig.partialSign(secretNonce: &secretNonce,
                                      secretKey: fixture.secretKeys[0], session: session)
        }
    }

    /// Interruption and cancellation, fail closed. A signing attempt that
    /// throws must still consume the nonce, so a retry cannot resurrect it.
    /// A rollback that restores pre-attempt state is the dangerous shape here;
    /// consuming on the error path is what makes that rollback inert.
    @Test("a failed signing attempt still consumes the nonce")
    func failedAttemptConsumesNonce() throws {
        let fixture = try Fixture()
        var secretNonce = fixture.secretNonces[0]
        let session = try fixture.session(message: Self.messageA)

        // Wrong signer for this nonce: the attempt must fail...
        #expect(throws: MuSig.MuSig2Error.secnonceMismatch) {
            _ = try MuSig.partialSign(secretNonce: &secretNonce,
                                      secretKey: fixture.secretKeys[1], session: session)
        }
        // ...and must have burned the nonce on the way out.
        #expect(secretNonce.allSatisfy { $0 == 0 },
                "a throwing signing attempt must not leave a usable nonce behind")
        #expect(throws: MuSig.MuSig2Error.secnonceReused) {
            _ = try MuSig.partialSign(secretNonce: &secretNonce,
                                      secretKey: fixture.secretKeys[0], session: session)
        }
    }

    /// A nonce belongs to exactly one signer. Transplanting one cosigner's
    /// nonce onto another's key is refused before any scalar arithmetic.
    @Test("a nonce cannot be transplanted to another signer")
    func nonceBoundToItsSigner() throws {
        let fixture = try Fixture()
        var foreign = fixture.secretNonces[1]
        #expect(throws: MuSig.MuSig2Error.secnonceMismatch) {
            _ = try MuSig.partialSign(secretNonce: &foreign,
                                      secretKey: fixture.secretKeys[0],
                                      session: try fixture.session(message: Self.messageA))
        }
    }

    /// Two sessions running at once are safe only when each holds its own
    /// nonce. Both sign; neither can borrow the other's.
    @Test("concurrent sessions each need their own nonce")
    func concurrentSessionsNeedDistinctNonces() throws {
        let first = try Fixture(nonceSeed: 0xA0)
        let second = try Fixture(nonceSeed: 0xB0)
        #expect(first.publicNonces != second.publicNonces, "fixtures must differ to model two sessions")

        var nonceA = first.secretNonces[0]
        var nonceB = second.secretNonces[0]
        let sessionA = try first.session(message: Self.messageA)
        let sessionB = try second.session(message: Self.messageB)

        let partialA = try MuSig.partialSign(secretNonce: &nonceA,
                                             secretKey: first.secretKeys[0], session: sessionA)
        let partialB = try MuSig.partialSign(secretNonce: &nonceB,
                                             secretKey: second.secretKeys[0], session: sessionB)
        #expect(partialA != partialB)
        #expect(try MuSig.partialVerify(partialSignature: partialA, publicNonce: first.publicNonces[0],
                                        publicKey: first.publicKeys[0], session: sessionA))
        #expect(try MuSig.partialVerify(partialSignature: partialB, publicNonce: second.publicNonces[0],
                                        publicKey: second.publicKeys[0], session: sessionB))

        // Both nonces are now spent; neither session can be signed again.
        #expect(nonceA.allSatisfy { $0 == 0 })
        #expect(nonceB.allSatisfy { $0 == 0 })
    }

    /// Replay across sessions: a partial signature produced for one message
    /// must not verify in a session over a different message.
    @Test("a partial signature does not replay into another session")
    func partialDoesNotReplayAcrossSessions() throws {
        let fixture = try Fixture()
        var secretNonce = fixture.secretNonces[0]
        let sessionA = try fixture.session(message: Self.messageA)
        let partial = try MuSig.partialSign(secretNonce: &secretNonce,
                                            secretKey: fixture.secretKeys[0], session: sessionA)

        #expect(try MuSig.partialVerify(partialSignature: partial, publicNonce: fixture.publicNonces[0],
                                        publicKey: fixture.publicKeys[0], session: sessionA))

        let sessionB = try fixture.session(message: Self.messageB)
        #expect(try !MuSig.partialVerify(partialSignature: partial, publicNonce: fixture.publicNonces[0],
                                         publicKey: fixture.publicKeys[0], session: sessionB),
                "a partial over message A must not verify over message B")
    }

    /// Reorder: partial signatures are not interchangeable between
    /// participants, so a shuffled collection fails verification rather than
    /// silently aggregating into a wrong signature.
    @Test("partial signatures are not interchangeable between participants")
    func partialsAreNotInterchangeable() throws {
        let fixture = try Fixture()
        let session = try fixture.session(message: Self.messageA)
        var nonce0 = fixture.secretNonces[0]
        var nonce1 = fixture.secretNonces[1]

        let partial0 = try MuSig.partialSign(secretNonce: &nonce0,
                                             secretKey: fixture.secretKeys[0], session: session)
        let partial1 = try MuSig.partialSign(secretNonce: &nonce1,
                                             secretKey: fixture.secretKeys[1], session: session)
        #expect(partial0 != partial1)

        // Each verifies against its own signer.
        #expect(try MuSig.partialVerify(partialSignature: partial0, publicNonce: fixture.publicNonces[0],
                                        publicKey: fixture.publicKeys[0], session: session))
        #expect(try MuSig.partialVerify(partialSignature: partial1, publicNonce: fixture.publicNonces[1],
                                        publicKey: fixture.publicKeys[1], session: session))
        // Swapped, neither does.
        #expect(try !MuSig.partialVerify(partialSignature: partial0, publicNonce: fixture.publicNonces[1],
                                         publicKey: fixture.publicKeys[1], session: session))
        #expect(try !MuSig.partialVerify(partialSignature: partial1, publicNonce: fixture.publicNonces[0],
                                         publicKey: fixture.publicKeys[0], session: session))
    }

    /// A signer who is not part of the session cannot have a coefficient
    /// derived for them, so an outsider's contribution is rejected as an
    /// unknown signer rather than being aggregated.
    @Test("a non-participant is rejected as an unknown signer")
    func nonParticipantRejected() throws {
        let fixture = try Fixture()
        let session = try fixture.session(message: Self.messageA)
        let outsider = try MuSig.privateToPublic(Data(repeating: 0x33, count: 32))

        #expect(throws: MuSig.MuSig2Error.unknownSigner) {
            _ = try MuSig.partialVerify(partialSignature: Data(repeating: 0x01, count: 32),
                                        publicNonce: fixture.publicNonces[0],
                                        publicKey: outsider, session: session)
        }
    }
}
