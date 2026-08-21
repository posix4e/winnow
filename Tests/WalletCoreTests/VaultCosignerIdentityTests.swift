import BitcoinCore
import Foundation
import Testing
@testable import WalletCore

/// Cosigner identity, origin consistency and network binding (epic #100,
/// invariant S3).
///
/// A k-of-n vault is only k-of-n if the n cosigners are n *different* people.
/// The dangerous case is not a malformed key — that fails loudly — but the
/// same account key entered twice wearing different clothes, which would
/// silently build a 2-of-3 vault that one key holder can spend alone.
///
/// `VaultCosignerKey.Identity` is deliberately defined as the neutered account
/// key plus its derivation, ignoring the origin label, precisely so that
/// relabelling cannot manufacture a second identity. These tests hold that
/// definition to account.
@Suite("Vault cosigner identity")
struct VaultCosignerIdentityTests {
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

    // MARK: - Duplicate identity survives relabelling

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

    // MARK: - Origin consistency

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

    // MARK: - Network binding

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

    // MARK: - Role-bound derivation

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
        // The refusal is specific, not incidental: the matching public key of
        // the same seed is accepted at the same origin, so what is rejected is
        // the private material rather than the shape of the expression.
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        #expect(throws: Never.self) {
            _ = try VaultCosignerKey("[6738736c]\(xpub)/<0;1>/*",
                                     role: .scriptPath, network: .mainnet)
        }
    }
}

/// The vault-creation screen's state machine (epic #100, invariant S3, the
/// "and UI" half). `VaultDraft` is what the creation screen drives, so the
/// duplicate refusal has to hold here too — not only in the descriptor
/// constructor that runs afterwards.
@Suite("Vault draft duplicate handling")
struct VaultDraftIdentityTests {
    typealias Fixture = VaultCosignerIdentityTests

    /// Adding the same account key a second time under a different origin
    /// label is refused, and the draft is left exactly as it was.
    @Test("the draft refuses a relabelled duplicate and keeps its state")
    func draftRefusesRelabelledDuplicate() throws {
        var draft = VaultDraft(role: .scriptPath)
        try draft.add(Fixture.scriptPath(Fixture.originA, Fixture.keyA), network: .mainnet)
        try draft.add(Fixture.scriptPath(Fixture.originB, Fixture.keyB), network: .mainnet)
        let before = draft

        #expect(throws: VaultCosignerKeyError.duplicateKey) {
            try draft.add(Fixture.scriptPath("deadbeef/48'/1'/7'/100'", Fixture.keyA),
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
        try draft.add(Fixture.scriptPath(Fixture.originA, Fixture.keyA), network: .mainnet)
        #expect(!draft.canBuild)
        try draft.add(Fixture.scriptPath(Fixture.originB, Fixture.keyB), network: .mainnet)
        #expect(draft.canBuild)
        #expect(draft.cosigners.count == 2)
    }

    /// Script-path and MuSig2 participants use different derivation shapes, so
    /// the policy must not change underneath expressions already entered.
    @Test("the role cannot change once cosigners have been entered")
    func roleLockedAfterFirstCosigner() throws {
        var draft = VaultDraft(role: .scriptPath)
        let toMuSig = draft.setRole(.muSig2)
        #expect(toMuSig)
        let backToScriptPath = draft.setRole(.scriptPath)
        #expect(backToScriptPath)
        try draft.add(Fixture.scriptPath(Fixture.originA, Fixture.keyA), network: .mainnet)
        let lockedOut = draft.setRole(.muSig2)
        #expect(!lockedOut, "changing role with cosigners present must be refused")
    }

    /// Removing a cosigner frees its identity again, so a legitimate re-entry
    /// after a correction is not permanently blocked.
    @Test("removing a cosigner releases its identity")
    func removalReleasesIdentity() throws {
        var draft = VaultDraft(role: .scriptPath)
        try draft.add(Fixture.scriptPath(Fixture.originA, Fixture.keyA), network: .mainnet)
        draft.remove(at: IndexSet(integer: 0))
        #expect(draft.cosigners.isEmpty)
        try draft.add(Fixture.scriptPath(Fixture.originA, Fixture.keyA), network: .mainnet)
        #expect(draft.cosigners.count == 1)
    }
}
