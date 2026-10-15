import Foundation
import Testing
import TestSupport
@testable import VaultKit
@testable import WalletCore

/// Who may join a vault: cosigner identity, origin consistency, network
/// binding, role-bound derivation, the creation screen's draft state machine,
/// and the independence a policy must have at the `Vault` boundary itself
/// (epic #100, invariants S3, S4 and S8).
///
/// A k-of-n vault is only k-of-n if the n cosigners are n *different* people.
/// The dangerous case is not a malformed key — that fails loudly — but the
/// same account key entered twice wearing different clothes, which would
/// silently build a 2-of-3 vault that one key holder can spend alone.
///
/// Three suites merged here, each a section below: the identity definition
/// itself, the draft that the creation screen drives, and the vault-boundary
/// refusals every persisted or pasted descriptor has to survive.
@Suite("Vault admission")
struct VaultAdmissionTests {
    // MARK: - Vault cosigner identity
    //
    // `VaultCosignerKey.Identity` is deliberately defined as the neutered
    // account key plus its derivation, ignoring the origin label, precisely so
    // that relabelling cannot manufacture a second identity. These tests hold
    // that definition to account.

    /// Three distinct mainnet account keys at depth 4, child 100'.
    static let keyA = "xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa"
    static let keyB = "xpub6EYajCJHe2CK53RLVXrN14uWoEttZgrRSaRztujsXg7yRhGtHmLBt9ot9Pd5ugfwWEu6eWyJYKSshyvZFKDXiNbBcoK42KRZbxwjRQpm5Js"
    static let keyC = "xpub6Dgsze3ujLi1EiHoCtHFMS9VLS1UheVqxrHGfP7sBJ2DBfChEUHV4MDwmxAXR2ayeytpwm3zJEU3H3pjCR6q6U5sP2p2qzAD71x9z5QShK2"

    /// A script-path cosigner expression: origin, account key, `/<0;1>/*`.
    static func scriptPath(_ origin: String, _ key: String) -> String {
        "[\(origin)]\(key)/<0;1>/*"
    }

    static let originA = "6738736c/48'/0'/0'/100'"
    static let originB = "b2b1f0cf/44'/0'/0'/100'"
    static let originC = "a666a867/44'/0'/0'/100'"

    // MARK: Duplicate identity survives relabelling

    /// `'` and `h` are the same hardened marker. Spelling the origin path the
    /// other way must not buy a second seat in the vault.
    @Test("the same key with an alternate hardened marker is still a duplicate")
    func duplicateAcrossHardenedMarkerSpelling() throws {
        let apostrophe = Self.scriptPath("6738736c/48'/0'/0'/100'", Self.keyA)
        let letterH = Self.scriptPath("6738736c/48h/0h/0h/100h", Self.keyA)
        #expect(apostrophe != letterH, "the two expressions must differ as text")

        #expect(throws: VaultCosignerKeyError.duplicateKey) {
            _ = try Vault.multiADescriptor(threshold: 2, cosigners: [apostrophe, letterH])
        }
    }

    /// A fingerprint is hex; case is not identity.
    @Test("the same key with a differently-cased fingerprint is still a duplicate")
    func duplicateAcrossFingerprintCase() throws {
        let lower = Self.scriptPath("6738736c/48'/0'/0'/100'", Self.keyA)
        let upper = Self.scriptPath("6738736C/48'/0'/0'/100'", Self.keyA)
        #expect(lower != upper)

        #expect(throws: VaultCosignerKeyError.duplicateKey) {
            _ = try Vault.multiADescriptor(threshold: 2, cosigners: [lower, upper])
        }
    }

    /// The strongest form: an origin label is unauthenticated metadata, so a
    /// wholly different fingerprint and path must not create a second
    /// identity for one account key.
    @Test("an unrelated origin label does not create a second identity")
    func duplicateAcrossEntirelyDifferentOrigin() throws {
        let real = Self.scriptPath("6738736c/48'/0'/0'/100'", Self.keyA)
        let relabelled = Self.scriptPath("deadbeef/48'/1'/7'/100'", Self.keyA)

        #expect(throws: VaultCosignerKeyError.duplicateKey) {
            _ = try Vault.multiADescriptor(threshold: 2, cosigners: [real, relabelled])
        }
    }

    /// A duplicate anywhere in the set is caught, not just an adjacent pair.
    @Test("a duplicate is caught in any position of the cosigner set")
    func duplicateCaughtInAnyPosition() throws {
        let a = Self.scriptPath(Self.originA, Self.keyA)
        let b = Self.scriptPath(Self.originB, Self.keyB)
        let aAgain = Self.scriptPath("deadbeef/48'/1'/7'/100'", Self.keyA)

        #expect(throws: VaultCosignerKeyError.duplicateKey) {
            _ = try Vault.multiADescriptor(threshold: 2, cosigners: [a, b, aAgain])
        }
    }

    /// Positive control: three genuinely different keys must build a vault.
    /// Without this, every test above would also pass if the constructor
    /// rejected everything.
    @Test("three distinct cosigners build a vault descriptor")
    func distinctCosignersAreAccepted() throws {
        let descriptor = try Vault.multiADescriptor(threshold: 2, cosigners: [
            Self.scriptPath(Self.originA, Self.keyA),
            Self.scriptPath(Self.originB, Self.keyB),
            Self.scriptPath(Self.originC, Self.keyC),
        ])
        #expect(descriptor.serialized().contains("sortedmulti_a(2,"))
    }

    // MARK: Origin consistency

    /// The origin path must have as many elements as the key has depth,
    /// otherwise the label describes a different key than the one supplied.
    @Test("an origin path shorter than the key depth is rejected")
    func originDepthMismatchRejected() throws {
        #expect(throws: VaultCosignerKeyError.originPathMismatch) {
            _ = try VaultCosignerKey(Self.scriptPath("6738736c/48'/0'/0'", Self.keyA),
                                     role: .scriptPath, network: .mainnet)
        }
    }

    /// The final origin element must be the key's own child index.
    @Test("an origin whose last element is not the key's child index is rejected")
    func originChildIndexMismatchRejected() throws {
        #expect(throws: VaultCosignerKeyError.originPathMismatch) {
            _ = try VaultCosignerKey(Self.scriptPath("6738736c/48'/0'/0'/101'", Self.keyA),
                                     role: .scriptPath, network: .mainnet)
        }
    }

    /// A key with no origin label at all cannot be checked against anything,
    /// so it is refused rather than admitted on trust.
    @Test("a key without an origin label is rejected")
    func missingOriginRejected() throws {
        #expect(throws: VaultCosignerKeyError.missingOrigin) {
            _ = try VaultCosignerKey("\(Self.keyA)/<0;1>/*", role: .scriptPath, network: .mainnet)
        }
    }

    // MARK: Network binding

    /// A mainnet account key offered to a signet vault is refused, so a vault
    /// cannot be assembled from keys belonging to two different chains.
    @Test("a mainnet key is refused for a signet vault")
    func crossNetworkKeyRejected() throws {
        #expect(throws: VaultCosignerKeyError.wrongNetwork(expectedPrefix: "tpub")) {
            _ = try VaultCosignerKey(Self.scriptPath(Self.originA, Self.keyA),
                                     role: .scriptPath, network: .signet)
        }
    }

    /// The same key is accepted for the chain it actually belongs to.
    @Test("a mainnet key is accepted for a mainnet vault")
    func matchingNetworkAccepted() throws {
        let key = try VaultCosignerKey(Self.scriptPath(Self.originA, Self.keyA),
                                       role: .scriptPath, network: .mainnet)
        #expect(key.expression.contains(Self.keyA))
    }

    // MARK: Role-bound derivation

    /// Script-path cosigners are pinned to `/<0;1>/*`. Pinning matters for
    /// identity too: if arbitrary derivations were allowed, one account key
    /// could present two derivations as two independent cosigners.
    @Test("a script-path cosigner with a non-canonical derivation is rejected")
    func scriptPathDerivationPinned() throws {
        #expect(throws: VaultCosignerKeyError.scriptPathDerivationRequired) {
            _ = try VaultCosignerKey("[\(Self.originA)]\(Self.keyA)/<2;3>/*",
                                     role: .scriptPath, network: .mainnet)
        }
    }

    /// A MuSig2 participant is a bare BIP390 key; a derivation suffix here is
    /// refused rather than silently ignored.
    @Test("a MuSig2 participant carrying a derivation is rejected")
    func muSig2DerivationForbidden() throws {
        #expect(throws: VaultCosignerKeyError.muSig2DerivationForbidden) {
            _ = try VaultCosignerKey(Self.scriptPath(Self.originA, Self.keyA),
                                     role: .muSig2, network: .mainnet)
        }
    }

    /// An extended *private* key must never be accepted as a cosigner: a
    /// vault draft is public-only material.
    @Test("a private key is refused as a cosigner")
    func privateKeyRefused() throws {
        // BIP32 test vector 1 master key: a genuinely valid xprv, depth 0, so
        // the origin path is empty.
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        #expect(throws: VaultCosignerKeyError.privateKey) {
            _ = try VaultCosignerKey("[6738736c]\(xprv)/<0;1>/*",
                                     role: .scriptPath, network: .mainnet)
        }
        // Bare, with neither origin nor derivation: the private material is
        // named before the shape is, so the message says what actually
        // happened rather than what else the expression lacks.
        #expect(throws: VaultCosignerKeyError.privateKey) {
            _ = try VaultCosignerKey(xprv, role: .scriptPath, network: .mainnet)
        }
        #expect(VaultCosignerKeyError.privateKey.localizedDescription.contains("private key"))
        // The refusal is specific, not incidental: the matching public key of
        // the same seed is accepted at the same origin, so what is rejected is
        // the private material rather than the shape of the expression.
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        #expect(throws: Never.self) {
            _ = try VaultCosignerKey("[6738736c]\(xpub)/<0;1>/*",
                                     role: .scriptPath, network: .mainnet)
        }
    }

    // MARK: - Vault draft duplicate handling
    //
    // The vault-creation screen's state machine (invariant S3, the "and UI"
    // half). `VaultDraft` is what the creation screen drives, so the duplicate
    // refusal has to hold here too — not only in the descriptor constructor
    // that runs afterwards. These tests used the identity fixtures above
    // through a `Fixture` typealias; they now reach them as `Self`.

    /// Adding the same account key a second time under a different origin
    /// label is refused, and the draft is left exactly as it was.
    @Test("the draft refuses a relabelled duplicate and keeps its state")
    func draftRefusesRelabelledDuplicate() throws {
        var draft = VaultDraft(role: .scriptPath)
        try draft.add(Self.scriptPath(Self.originA, Self.keyA), network: .mainnet)
        try draft.add(Self.scriptPath(Self.originB, Self.keyB), network: .mainnet)
        let before = draft

        #expect(throws: VaultCosignerKeyError.duplicateKey) {
            try draft.add(Self.scriptPath("deadbeef/48'/1'/7'/100'", Self.keyA),
                          network: .mainnet)
        }
        #expect(draft == before, "a rejected cosigner must not mutate the draft")
        #expect(draft.cosigners.count == 2)
    }

    /// Positive control: distinct keys accumulate and the draft becomes
    /// buildable, so the refusal above is specific rather than a blanket no.
    @Test("the draft accepts distinct cosigners and becomes buildable")
    func draftAcceptsDistinctCosigners() throws {
        var draft = VaultDraft(role: .scriptPath)
        #expect(!draft.canBuild)
        try draft.add(Self.scriptPath(Self.originA, Self.keyA), network: .mainnet)
        #expect(!draft.canBuild)
        try draft.add(Self.scriptPath(Self.originB, Self.keyB), network: .mainnet)
        #expect(draft.canBuild)
        #expect(draft.cosigners.count == 2)
    }

    /// A MuSig2 group takes one seat of a k-of-n through its BIP328
    /// synthetic xpub: depth 0, the fixed chaincode, the aggregate key, and
    /// an origin naming only the key's own fingerprint. Admission alone is
    /// not the claim — a well-formed depth-0 tpub of anything would pass —
    /// so the seat must resolve to the group's own key-path internal key.
    @Test("a BIP328 synthetic group xpub is admitted as a script-path cosigner")
    func syntheticGroupXpubAdmitted() throws {
        let (group, _) = try TestVaults.muSig2Vault()
        let context = try group.muSig2Context(choice: 0, index: 0)
        let synthetic = try MuSig.syntheticExtendedKey(aggregatePublicKey: context.aggregate)
        let groupSeat = "[\(String(format: "%08x", synthetic.fingerprint))]"
            + synthetic.serialized(network: .testnet) + "/<0;1>/*"
        var draft = VaultDraft(role: .scriptPath)
        try draft.add(groupSeat, network: .signet)
        #expect(!draft.canBuild)
        try draft.add(TestVaults.keyExpression(master: TestVaults.masters()[2]), network: .signet)
        #expect(draft.canBuild)
        #expect(draft.threshold == 2)
        #expect(draft.cosigners.count == 2)
        let seatKey = try draft.cosigners[0].publicKey(index: 0, choice: 0)
        #expect(Data(seatKey.dropFirst()) == context.internalKey,
                "the seat must derive the group's internal key, not merely parse")

        let descriptor = try Vault.multiADescriptor(threshold: draft.threshold,
                                                    cosigners: draft.cosigners.map(\.expression))
        let vault = try Vault(descriptor: descriptor, network: .signet)
        #expect(vault.isScriptPath)
        #expect(vault.threshold == 2)
        #expect(vault.signerCount == 2)
        #expect(try vault.signerKeys().contains(seatKey))
    }

    /// Script-path and MuSig2 participants use different derivation shapes, so
    /// the policy must not change underneath expressions already entered.
    @Test("the role cannot change once cosigners have been entered")
    func roleLockedAfterFirstCosigner() throws {
        var draft = VaultDraft(role: .scriptPath)
        let toMuSig = draft.setRole(.muSig2)
        #expect(toMuSig)
        #expect(draft.role == .muSig2)
        let backToScriptPath = draft.setRole(.scriptPath)
        #expect(backToScriptPath)
        #expect(draft.role == .scriptPath)
        try draft.add(Self.scriptPath(Self.originA, Self.keyA), network: .mainnet)
        let lockedOut = draft.setRole(.muSig2)
        #expect(!lockedOut, "changing role with cosigners present must be refused")
        #expect(draft.role == .scriptPath)
        // Removing the last cosigner releases the lock again.
        draft.remove(at: IndexSet(integer: 0))
        let released = draft.setRole(.muSig2) // mutating: cannot sit inside #expect
        #expect(released)
        #expect(draft.role == .muSig2)
        #expect(draft.threshold == 1)
    }

    /// Removing a cosigner frees its identity again, so a legitimate re-entry
    /// after a correction is not permanently blocked.
    @Test("removing a cosigner releases its identity")
    func removalReleasesIdentity() throws {
        var draft = VaultDraft(role: .scriptPath)
        try draft.add(Self.scriptPath(Self.originA, Self.keyA), network: .mainnet)
        draft.remove(at: IndexSet(integer: 0))
        #expect(draft.cosigners.isEmpty)
        try draft.add(Self.scriptPath(Self.originA, Self.keyA), network: .mainnet)
        #expect(draft.cosigners.count == 1)
    }

    @Test("restored signing accounts refuse private cosigner keys", arguments: [false, true])
    func restoredPrivateKeyRefused(muSig2: Bool) throws {
        let masters = try TestVaults.masters()
        let account = try masters[0].derived(path: "m/86'/1'/0'")
        let keys = try masters.prefix(2).map { try TestVaults.keyExpression(master: $0) }
        let publicText = muSig2
            ? "tr(musig(\(keys.map { String($0.dropLast("/<0;1>/*".count)) }.joined(separator: ",")))/<0;1>/*)"
            : "tr(\(Self.nums()),sortedmulti_a(2,\(keys.joined(separator: ","))))"
        _ = try Vault(publicText, network: .signet)
        let privateText = publicText.replacingOccurrences(
            of: account.neutered.serialized(network: .testnet),
            with: account.serialized(network: .testnet))
        #expect(privateText != publicText)
        #expect(throws: VaultError.self) {
            _ = try Vault(privateText, network: .signet)
        }
    }

    // MARK: - Vault signer independence
    //
    // `Vault.multiADescriptor` refuses a repeated cosigner while *building* a
    // vault, and the creation screen refuses one while *drafting*. Neither of
    // those is the boundary that matters. Every other way into a vault reaches
    // `Vault.init` directly: restoring persisted records, an imported bundle, a
    // descriptor pasted by hand, or a tampered vault store — which is the
    // epic's own hostile-persistence threat model.
    //
    // A repeated participant is not a cosmetic defect. `musig(K, K)` presents
    // as 2-of-2 while being spendable by whoever holds K alone, because both
    // partial signatures come from the same key.

    static func nums() -> String { Taproot.unspendableInternalKey.hex }

    // MARK: Duplicates are refused at the vault boundary

    @Test("a script-path vault repeating a cosigner is refused")
    func multiADuplicateCosignerRefused() throws {
        let masters = try TestVaults.masters()
        let key = try TestVaults.keyExpression(master: masters[0])
        let descriptor = try Descriptor("tr(\(Self.nums()),sortedmulti_a(2,\(key),\(key)))")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    /// The comparison is on derived key material, so an origin label — which
    /// is unauthenticated metadata — cannot disguise the repeat.
    @Test("a duplicate disguised by a different origin label is still refused")
    func duplicateBehindRelabelledOriginRefused() throws {
        let masters = try TestVaults.masters()
        let real = try TestVaults.bareKeyExpression(master: masters[0])
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
        let masters = try TestVaults.masters()
        let a = try TestVaults.bareKeyExpression(master: masters[0])
        let b = try TestVaults.bareKeyExpression(master: masters[1])
        let descriptor = try Descriptor("tr(musig(\(a),\(b),\(a))/<0;1>/*)")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    // MARK: Positive controls

    /// Without these, every refusal above could be explained by the
    /// initializer rejecting these shapes outright.
    @Test("a MuSig2 vault with distinct participants is accepted")
    func distinctMuSig2Accepted() throws {
        let masters = try TestVaults.masters()
        let a = try TestVaults.bareKeyExpression(master: masters[0])
        let b = try TestVaults.bareKeyExpression(master: masters[1])
        let vault = try Vault(descriptor: try Descriptor("tr(musig(\(a),\(b))/<0;1>/*)"), network: .signet)
        #expect(try vault.address(index: 0).hasPrefix("tb1p"))
    }

    @Test("a script-path vault with distinct cosigners is accepted")
    func distinctMultiAAccepted() throws {
        let masters = try TestVaults.masters()
        let expressions = try masters.map { try TestVaults.keyExpression(master: $0) }
        let vault = try Vault(descriptor: try Vault.multiADescriptor(threshold: 2, cosigners: expressions),
                              network: .signet)
        #expect(vault.usesUnspendableInternalKey)
        #expect(try vault.address(index: 0).hasPrefix("tb1p"))
    }

    /// The path that matters most in practice: a persisted or imported
    /// descriptor string, reconstructed exactly as the vault store does it.
    @Test("a duplicate reaching the vault store as a descriptor string is refused")
    func duplicateFromDescriptorTextRefused() throws {
        let masters = try TestVaults.masters()
        let key = try TestVaults.bareKeyExpression(master: masters[0])
        let text = try Descriptor("tr(musig(\(key),\(key))/<0;1>/*)").serialized()
        #expect(throws: VaultError.self) {
            _ = try Vault(text, network: .signet)
        }
    }

    // MARK: Signers that only collide at a later coordinate (#133)

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
        let master = try TestVaults.masters()[0]
        let ranged = try TestVaults.keyExpression(master: master)
        let fixed = try Self.fixedExpression(master: master, choice: 0, index: 1)

        #expect(try Self.resolve(ranged, index: 0, choice: 0) != Self.resolve(fixed, index: 0, choice: 0))
        #expect(try Self.resolve(ranged, index: 1, choice: 0) == Self.resolve(fixed, index: 1, choice: 0))
    }

    @Test("a script-path vault whose cosigners collide at a later receive index is refused")
    func collidingReceiveIndexRefused() throws {
        let master = try TestVaults.masters()[0]
        let ranged = try TestVaults.keyExpression(master: master)
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
        let master = try TestVaults.masters()[0]
        let ranged = try TestVaults.keyExpression(master: master)
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
        let master = try TestVaults.masters()[0]
        let ranged = try TestVaults.keyExpression(master: master)
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
        let masters = try TestVaults.masters()
        let a = try TestVaults.keyExpression(master: masters[0])
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
        let master = try TestVaults.masters()[0]
        let ranged = try TestVaults.keyExpression(master: master)
        let fixed = try Self.fixedExpression(master: master, choice: 0, index: 1)
        let descriptor = try Descriptor("tr(\(Self.nums()),sortedmulti_a(2,\(ranged),\(fixed)))")
        do {
            _ = try Vault(descriptor: descriptor, network: .signet)
            Issue.record("expected the vault to be refused")
        } catch let VaultError.invalidDescriptor(message) {
            #expect(message.contains("derivation"))
        }
    }

    // MARK: The internal key must not be able to spend alone

    /// A `multi_a` vault commits its threshold in a tapscript leaf, but the
    /// key path is always available to whoever holds the internal key. With a
    /// real key there, a "2-of-3" is spendable by one party without touching
    /// the script at all.
    @Test("a script-path vault whose internal key can spend alone is refused")
    func spendableInternalKeyRefused() throws {
        let masters = try TestVaults.masters()
        let a = try TestVaults.keyExpression(master: masters[0])
        let b = try TestVaults.keyExpression(master: masters[1])
        let internalKey = try TestVaults.keyExpression(master: masters[2])
        let descriptor = try Descriptor("tr(\(internalKey),sortedmulti_a(2,\(a),\(b)))")
        #expect(throws: VaultError.self) {
            _ = try Vault(descriptor: descriptor, network: .signet)
        }
    }

    @Test("the internal-key refusal says the internal key can spend on its own")
    func spendableInternalKeyRefusalIsSpecific() throws {
        let masters = try TestVaults.masters()
        let a = try TestVaults.keyExpression(master: masters[0])
        let b = try TestVaults.keyExpression(master: masters[1])
        let internalKey = try TestVaults.keyExpression(master: masters[2])
        let descriptor = try Descriptor("tr(\(internalKey),sortedmulti_a(2,\(a),\(b)))")
        do {
            _ = try Vault(descriptor: descriptor, network: .signet)
            Issue.record("expected the vault to be refused")
        } catch let VaultError.invalidDescriptor(message) {
            #expect(message.contains("internal key"))
        }
    }
}
