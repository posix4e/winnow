import BitcoinCore
import Foundation
import Testing
@testable import WalletCore

/// A vault policy must need as many independent signers as it advertises
/// (epic #100, invariants S3, S4 and S8).
///
/// `Vault.multiADescriptor` refuses a repeated cosigner while *building* a
/// vault, and the creation screen refuses one while *drafting*. Neither of
/// those is the boundary that matters. Every other way into a vault reaches
/// `Vault.init` directly: restoring persisted records, an imported bundle, a
/// descriptor pasted by hand, or a tampered vault store — which is the epic's
/// own hostile-persistence threat model.
///
/// A repeated participant is not a cosmetic defect. `musig(K, K)` presents as
/// 2-of-2 while being spendable by whoever holds K alone, because both partial
/// signatures come from the same key.
@Suite("Vault signer independence")
struct VaultSignerIndependenceTests {
    typealias Flow = VaultFlowTests

    static func nums() -> String { Taproot.unspendableInternalKey.hex }

    // MARK: - Duplicates are refused at the vault boundary

    @Test("a MuSig2 vault repeating a participant is refused")
    func muSig2DuplicateParticipantRefused() throws {
        let masters = try Flow.masters()
        let key = try Flow.bareKeyExpression(master: masters[0])
        let descriptor = try Descriptor("tr(musig(\(key),\(key))/<0;1>/*)")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    @Test("a script-path vault repeating a cosigner is refused")
    func multiADuplicateCosignerRefused() throws {
        let masters = try Flow.masters()
        let key = try Flow.keyExpression(master: masters[0])
        let descriptor = try Descriptor("tr(\(Self.nums()),sortedmulti_a(2,\(key),\(key)))")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    /// The comparison is on derived key material, so an origin label — which
    /// is unauthenticated metadata — cannot disguise the repeat.
    @Test("a duplicate disguised by a different origin label is still refused")
    func duplicateBehindRelabelledOriginRefused() throws {
        let masters = try Flow.masters()
        let real = try Flow.bareKeyExpression(master: masters[0])
        // Same account key, different origin text.
        guard let bracket = real.firstIndex(of: "]") else {
            Issue.record("fixture has no origin label")
            return
        }
        let accountKey = String(real[real.index(after: bracket)...])
        let relabelled = "[deadbeef/86'/1'/0']\(accountKey)"
        #expect(real != relabelled)

        let descriptor = try Descriptor("tr(musig(\(real),\(relabelled))/<0;1>/*)")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    /// A repeat anywhere in a larger participant set is caught, not only an
    /// adjacent pair.
    @Test("a duplicate in any position of a three-participant vault is refused")
    func duplicateInAnyPositionRefused() throws {
        let masters = try Flow.masters()
        let a = try Flow.bareKeyExpression(master: masters[0])
        let b = try Flow.bareKeyExpression(master: masters[1])
        let descriptor = try Descriptor("tr(musig(\(a),\(b),\(a))/<0;1>/*)")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    // MARK: - Positive controls

    /// Without these, every refusal above could be explained by the
    /// initializer rejecting these shapes outright.
    @Test("a MuSig2 vault with distinct participants is accepted")
    func distinctMuSig2Accepted() throws {
        let masters = try Flow.masters()
        let a = try Flow.bareKeyExpression(master: masters[0])
        let b = try Flow.bareKeyExpression(master: masters[1])
        let vault = try Vault(descriptor: try Descriptor("tr(musig(\(a),\(b))/<0;1>/*)"), network: .signet)
        #expect(try vault.address(index: 0).hasPrefix("tb1p"))
    }

    @Test("a script-path vault with distinct cosigners is accepted")
    func distinctMultiAAccepted() throws {
        let masters = try Flow.masters()
        let expressions = try masters.map { try Flow.keyExpression(master: $0) }
        let vault = try Vault(descriptor: try Vault.multiADescriptor(threshold: 2, cosigners: expressions),
                              network: .signet)
        #expect(vault.usesUnspendableInternalKey)
        #expect(try vault.address(index: 0).hasPrefix("tb1p"))
    }

    /// The path that matters most in practice: a persisted or imported
    /// descriptor string, reconstructed exactly as the vault store does it.
    @Test("a duplicate reaching the vault store as a descriptor string is refused")
    func duplicateFromDescriptorTextRefused() throws {
        let masters = try Flow.masters()
        let key = try Flow.bareKeyExpression(master: masters[0])
        let text = try Descriptor("tr(musig(\(key),\(key))/<0;1>/*)").serialized()
        #expect(throws: VaultError.self) {
            _ = try Vault(text, network: .signet)
        }
    }

    // MARK: - Signers that only collide at a later coordinate (#133)

    /// `[fp/86'/1'/0']tpub…/<choice>/<index>` — a *fixed* path, so it resolves
    /// to the same key at every address index. That is what lets it hide from
    /// a check that samples one coordinate.
    static func fixedExpression(master: HDKey, choice: UInt32, index: UInt32) throws -> String {
        let account = try master.derived(path: "m/86'/1'/0'")
        let fingerprint = String(format: "%08x", master.fingerprint)
        return "[\(fingerprint)/86'/1'/0']\(account.neutered.serialized(network: .testnet))/\(choice)/\(index)"
    }

    /// Resolves one key expression on its own, so a collision can be shown
    /// without going through `Vault` — which now refuses these outright.
    static func resolve(_ expression: String, index: UInt32, choice: Int) throws -> Data {
        let descriptor = try Descriptor("rawtr(\(expression))")
        guard case let .rawtr(key) = descriptor.expression else {
            throw VaultError.invalidDescriptor("fixture is not a rawtr")
        }
        return try descriptor.publicKey(of: key, index: index, choice: choice)
    }

    /// The premise, proved independently of `Vault`: these two expressions are
    /// different keys at `(index: 0, choice: 0)` — the only coordinate the old
    /// check sampled — and the *same* key one address later. Sampling more
    /// indices would not be a proof either; only pinning the suffix is.
    @Test("two expressions over one account key can differ at index 0 and collide at index 1")
    func collisionExistsAtALaterIndex() throws {
        let master = try Flow.masters()[0]
        let ranged = try Flow.keyExpression(master: master)
        let fixed = try Self.fixedExpression(master: master, choice: 0, index: 1)

        #expect(try Self.resolve(ranged, index: 0, choice: 0) != Self.resolve(fixed, index: 0, choice: 0))
        #expect(try Self.resolve(ranged, index: 1, choice: 0) == Self.resolve(fixed, index: 1, choice: 0))
    }

    @Test("a script-path vault whose cosigners collide at a later receive index is refused")
    func collidingReceiveIndexRefused() throws {
        let master = try Flow.masters()[0]
        let ranged = try Flow.keyExpression(master: master)
        let fixed = try Self.fixedExpression(master: master, choice: 0, index: 1)
        let descriptor = try Descriptor("tr(\(Self.nums()),sortedmulti_a(2,\(ranged),\(fixed)))")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    /// The same trick on the change chain: multipath choice 1 is the change
    /// branch, so a vault can be sound for every receive address and collide
    /// on change.
    @Test("a script-path vault whose cosigners collide at a later change index is refused")
    func collidingChangeIndexRefused() throws {
        let master = try Flow.masters()[0]
        let ranged = try Flow.keyExpression(master: master)
        let fixed = try Self.fixedExpression(master: master, choice: 1, index: 1)

        #expect(try Self.resolve(ranged, index: 1, choice: 1) == Self.resolve(fixed, index: 1, choice: 1))

        let descriptor = try Descriptor("tr(\(Self.nums()),sortedmulti_a(2,\(ranged),\(fixed)))")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    /// BIP390 forbids a ranged participant only when the musig suffix is
    /// non-empty, so this shape parses and would collide exactly like the
    /// script-path one.
    @Test("a MuSig2 vault whose participants carry their own colliding suffixes is refused")
    func muSig2ParticipantSuffixRefused() throws {
        let master = try Flow.masters()[0]
        let ranged = try Flow.keyExpression(master: master)
        let fixed = try Self.fixedExpression(master: master, choice: 0, index: 1)
        let descriptor = try Descriptor("tr(musig(\(ranged),\(fixed)))")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    /// A cosigner suffix that is merely *unsupported* — not yet colliding —
    /// is refused too. Independence is proved by the pin, so anything outside
    /// it has to go, whether or not this particular pair happens to overlap.
    @Test("an unsupported cosigner derivation is refused even without a collision")
    func unsupportedSuffixRefused() throws {
        let masters = try Flow.masters()
        let a = try Flow.keyExpression(master: masters[0])
        let b = try Self.fixedExpression(master: masters[1], choice: 0, index: 7)
        let descriptor = try Descriptor("tr(\(Self.nums()),sortedmulti_a(2,\(a),\(b)))")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    /// The failure has to say what is actually wrong. "Malformed descriptor"
    /// or a generic key error would send someone looking in the wrong place.
    @Test("the refusal names the derivation paths, not malformed text")
    func refusalNamesTheDerivation() throws {
        let master = try Flow.masters()[0]
        let ranged = try Flow.keyExpression(master: master)
        let fixed = try Self.fixedExpression(master: master, choice: 0, index: 1)
        let descriptor = try Descriptor("tr(\(Self.nums()),sortedmulti_a(2,\(ranged),\(fixed)))")
        do {
            _ = try Vault(descriptor: descriptor, network: .signet)
            Issue.record("expected the vault to be refused")
        } catch let VaultError.invalidDescriptor(message) {
            #expect(message.contains("derivation"))
        }
    }

    // MARK: - The internal key must not be able to spend alone

    /// A `multi_a` vault commits its threshold in a tapscript leaf, but the
    /// key path is always available to whoever holds the internal key. With a
    /// real key there, a "2-of-3" is spendable by one party without touching
    /// the script at all.
    @Test("a script-path vault whose internal key can spend alone is refused")
    func spendableInternalKeyRefused() throws {
        let masters = try Flow.masters()
        let a = try Flow.keyExpression(master: masters[0])
        let b = try Flow.keyExpression(master: masters[1])
        let internalKey = try Flow.keyExpression(master: masters[2])
        let descriptor = try Descriptor("tr(\(internalKey),sortedmulti_a(2,\(a),\(b)))")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    @Test("the internal-key refusal says the internal key can spend on its own")
    func spendableInternalKeyRefusalIsSpecific() throws {
        let masters = try Flow.masters()
        let a = try Flow.keyExpression(master: masters[0])
        let b = try Flow.keyExpression(master: masters[1])
        let internalKey = try Flow.keyExpression(master: masters[2])
        let descriptor = try Descriptor("tr(\(internalKey),sortedmulti_a(2,\(a),\(b)))")
        do {
            _ = try Vault(descriptor: descriptor, network: .signet)
            Issue.record("expected the vault to be refused")
        } catch let VaultError.invalidDescriptor(message) {
            #expect(message.contains("internal key"))
        }
    }
}
