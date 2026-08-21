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
}
