import BitcoinCore
import Foundation
import P256K
import Testing
@testable import WalletCore

/// Thresholds and signing coverage (epic #100, invariant S8).
///
/// `VaultFlowTests` proves that *a* 2-of-3 spend works — cosigners 0 and 2.
/// A k-of-n custody promise is stronger than that: it says **every** valid
/// combination of k cosigners can spend, and no combination of fewer can.
/// One untested pair is a pair that might not be able to move the money when
/// it matters, which for an inheritance or a lost-key recovery is the whole
/// point of the vault.
///
/// These tests therefore enumerate rather than sample.
@Suite("Vault thresholds and signing coverage")
struct VaultThresholdTests {
    typealias Flow = VaultFlowTests

    let destination = Data([0x51, 0x20] + repeatElement(0x77, count: 32))

    /// Builds a k-of-3 vault from the shared deterministic cosigner masters.
    static func vault(threshold k: Int) throws -> (vault: Vault, masters: [HDKey]) {
        let masters = try Flow.masters()
        let descriptor = try Vault.multiADescriptor(
            threshold: k, cosigners: try masters.map { try Flow.keyExpression(master: $0) })
        return (try Vault(descriptor: descriptor, network: .signet), masters)
    }

    // MARK: - Threshold boundaries

    /// k must lie in 1...n. Zero and negative thresholds would be a vault
    /// anyone can spend; k > n would be a vault nobody can spend.
    @Test("a threshold outside 1...n is refused", arguments: [-1, 0, 4, 99])
    func thresholdOutsideRangeRefused(_ k: Int) throws {
        let expressions = try Flow.masters().map { try Flow.keyExpression(master: $0) }
        #expect(throws: DescriptorError.invalidThreshold) {
            _ = try Vault.multiADescriptor(threshold: k, cosigners: expressions)
        }
    }

    /// Every in-range threshold builds, and each produces a *different*
    /// script — so the threshold genuinely reaches the output key rather than
    /// being decorative metadata.
    @Test("each in-range threshold builds a distinct vault")
    func inRangeThresholdsAreDistinct() throws {
        var addresses: Set<String> = []
        for k in 1 ... 3 {
            let built = try Self.vault(threshold: k)
            #expect(built.vault.usesUnspendableInternalKey)
            addresses.insert(try built.vault.address(index: 0))
        }
        #expect(addresses.count == 3, "1-of-3, 2-of-3 and 3-of-3 must not share an address")
    }

    // MARK: - Every valid signing combination

    /// The headline S8 requirement: all three 2-of-3 pairs, each independently
    /// carried end to end and verified cryptographically.
    @Test("every 2-of-3 cosigner pair can spend",
          arguments: [(0, 1), (0, 2), (1, 2)])
    func everyPairCanSpend(_ pair: (Int, Int)) throws {
        let (vault, masters) = try Self.vault(threshold: 2)
        let utxo = try Flow.funding(vault: vault, amount: 100_000)
        let owned = [Vault.OutputCoordinate(choice: 1, index: 0)]
        let created = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2)

        var first = try PSBT(base64: created.base64)
        try vault.partialSign(&first, master: masters[pair.0], knownUTXOs: [utxo],
                              ownedOutputCoordinates: owned)
        var second = try PSBT(base64: created.base64)
        try vault.partialSign(&second, master: masters[pair.1], knownUTXOs: [utxo],
                              ownedOutputCoordinates: owned)

        var combined = try first.combined(with: [second])
        #expect(combined.inputs[0].tapScriptSignatures.count == 2)
        let signed = try vault.finalizeSpend(&combined, knownUTXOs: [utxo],
                                             ownedOutputCoordinates: owned)
        let result = try Flow().verifyMultisigSpend(tx: signed, inputIndex: 0,
                                                    spentOutputs: [utxo.spentOutput])
        #expect(result.validSignatures == 2, "pair \(pair) must produce two valid signatures")
        #expect(result.threshold == 2)
        #expect(result.keyCount == 3)
    }

    /// The other half of the promise: no single cosigner can spend a 2-of-3,
    /// checked for each of the three in turn rather than for one sample.
    @Test("no single cosigner can finalize a 2-of-3", arguments: [0, 1, 2])
    func noSingleCosignerCanSpend(_ index: Int) throws {
        let (vault, masters) = try Self.vault(threshold: 2)
        let utxo = try Flow.funding(vault: vault, amount: 100_000)
        let owned = [Vault.OutputCoordinate(choice: 1, index: 0)]
        let created = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2)

        var alone = try PSBT(base64: created.base64)
        try vault.partialSign(&alone, master: masters[index], knownUTXOs: [utxo],
                              ownedOutputCoordinates: owned)
        #expect(alone.inputs[0].tapScriptSignatures.count == 1)

        var toFinalize = alone
        #expect(throws: (any Error).self) {
            _ = try vault.finalizeSpend(&toFinalize, knownUTXOs: [utxo],
                                        ownedOutputCoordinates: owned)
        }
    }

    /// A 3-of-3 needs all three, and having exactly two is not enough — the
    /// boundary is checked from below as well as at it.
    @Test("a 3-of-3 vault needs all three cosigners")
    func threeOfThreeNeedsEveryone() throws {
        let (vault, masters) = try Self.vault(threshold: 3)
        let utxo = try Flow.funding(vault: vault, amount: 100_000)
        let owned = [Vault.OutputCoordinate(choice: 1, index: 0)]
        let created = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: destination)],
            changeIndex: 0, feeRateSatPerVByte: 2)

        var signed: [PSBT] = []
        for master in masters {
            var copy = try PSBT(base64: created.base64)
            try vault.partialSign(&copy, master: master, knownUTXOs: [utxo],
                                  ownedOutputCoordinates: owned)
            signed.append(copy)
        }

        // Two of three: below threshold.
        var short = try signed[0].combined(with: [signed[1]])
        #expect(short.inputs[0].tapScriptSignatures.count == 2)
        #expect(throws: (any Error).self) {
            _ = try vault.finalizeSpend(&short, knownUTXOs: [utxo], ownedOutputCoordinates: owned)
        }

        // All three: spendable.
        var full = try signed[0].combined(with: [signed[1], signed[2]])
        #expect(full.inputs[0].tapScriptSignatures.count == 3)
        let tx = try vault.finalizeSpend(&full, knownUTXOs: [utxo], ownedOutputCoordinates: owned)
        let result = try Flow().verifyMultisigSpend(tx: tx, inputIndex: 0,
                                                    spentOutputs: [utxo.spentOutput])
        #expect(result.validSignatures == 3)
        #expect(result.threshold == 3)
    }

    // MARK: - Threshold arithmetic used by the creation screen

    /// `clamped` must never return a threshold outside 1...max(keyCount, 1),
    /// checked exhaustively over the range the stepper can reach rather than
    /// at a couple of sampled points.
    @Test("clamped never escapes 1...keyCount")
    func clampedStaysInRange() {
        for keyCount in 0 ... 6 {
            for threshold in -3 ... 9 {
                let value = VaultThreshold.clamped(threshold, keyCount: keyCount)
                #expect(value >= 1, "clamped(\(threshold), keyCount: \(keyCount)) = \(value)")
                #expect(value <= max(keyCount, 1))
                // Already-valid values are preserved rather than nudged.
                if threshold >= 1, threshold <= max(keyCount, 1) {
                    #expect(value == threshold)
                }
            }
        }
    }

    /// Adding the second signer snaps to 2-of-2, the safest useful default;
    /// every later change preserves a still-valid choice.
    @Test("reconciled snaps to 2-of-2 on the second key and preserves choice after")
    func reconciledDefaultsAndPreserves() {
        // First key present, second added: snap to 2 regardless of prior value.
        for previous in [1, 2, 5] {
            #expect(VaultThreshold.reconciled(previous, previousKeyCount: 1, keyCount: 2) == 2)
        }
        // Third key added: a valid existing choice survives.
        #expect(VaultThreshold.reconciled(2, previousKeyCount: 2, keyCount: 3) == 2)
        #expect(VaultThreshold.reconciled(3, previousKeyCount: 2, keyCount: 3) == 3)
        // Deleting a key clamps down rather than leaving an impossible vault.
        #expect(VaultThreshold.reconciled(3, previousKeyCount: 3, keyCount: 2) == 2)
        #expect(VaultThreshold.reconciled(2, previousKeyCount: 2, keyCount: 0) == 1)
    }

    /// The stepper and delete button cannot drive the draft into an invalid
    /// threshold, whatever order they are used in.
    @Test("draft threshold stays valid across stepper and deletion")
    func draftThresholdStaysValid() throws {
        var draft = VaultDraft(role: .scriptPath)
        let masters = try Flow.masters()
        for master in masters {
            try draft.add(try Flow.keyExpression(master: master), network: .signet)
            #expect(draft.threshold >= 1)
            #expect(draft.threshold <= draft.cosigners.count)
        }
        #expect(draft.threshold == 2, "three keys added one at a time defaults to 2-of-3")

        draft.setThreshold(3)
        #expect(draft.threshold == 3)
        draft.remove(at: IndexSet(integer: 2))
        #expect(draft.threshold == 2, "deleting a key must clamp the threshold down")
        draft.setThreshold(99)
        #expect(draft.threshold == 2)
        draft.setThreshold(-5)
        #expect(draft.threshold == 1)
    }
}
