import Foundation
import P256K
import Testing
@testable import BitcoinCore

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
