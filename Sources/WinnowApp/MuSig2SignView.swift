import VaultKit
import WalletCore
import SwiftUI
import UIKit

/// MuSig2 n-of-n: round 1 attaches this device's public nonce (the secret
/// nonces stay in this screen's memory — leaving before round 2 abandons the
/// session), cosigners' nonce-bearing PSBTs are combined, round 2 signs,
/// partials are combined, aggregated → broadcast.
struct MuSig2SignView: View {
    let recordID: String
    var initialPSBT: PSBT?
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    enum SignError: LocalizedError {
        case unknownInput
        case noWorkingPSBT

        var errorDescription: String? {
            switch self {
            case .unknownInput: "An input of this PSBT is not a known UTXO of the vault."
            case .noWorkingPSBT: "Add a PSBT first."
            }
        }
    }

    @State private var pasted = ""
    @State private var working: PSBT?
    @State private var spendReview: Vault.SpendReview?
    @State private var reviewedOutputLines: [OutputLine] = []
    @State private var spendReviewError: String?
    @State private var output: String?
    @State private var error: String?
    @State private var broadcastTxid: Data?
    @State private var broadcasting = false
    @State private var authorizing = false
    /// MuSig2 round-1 secret nonces per input (participant pubkey → secnonce).
    /// Never persisted, never shown — zeroed by round 2.
    @State private var secretNonces: [Int: [Data: Data]] = [:]
    /// Round transitions are explicit so a completed signer cannot attach a
    /// second nonce or sign twice while this sheet remains open.
    @State private var nonceSessionStarted = false
    @State private var signedMuSig2ThisSession = false
    @State private var operationEpoch = SensitivePresentationEpoch()
    @State private var operationTask: Task<Void, Never>?

    private var record: VaultRecord? { model.vaults.first { $0.id == recordID } }
    private var vault: Vault? { record.flatMap { try? Vault($0.descriptor, network: model.network) } }

    private var participantCount: Int? {
        guard case let .muSig2(participants, _) = vault?.policy else { return nil }
        return participants.count
    }

    /// The lowest per-input count — the spend is ready only when every input is.
    private var minNonces: Int { working?.inputs.map(\.musig2PubNonces.count).min() ?? 0 }
    private var minPartialSigs: Int { working?.inputs.map(\.musig2PartialSigs.count).min() ?? 0 }
    private var workingInputsRemainAvailable: Bool { spendReview != nil }

    /// A cheap identity for trusted local state. Imported/combined proposals
    /// are reviewed synchronously once; this task only rechecks when the local
    /// coin set or descriptor frontier changes.
    private struct TrustedStateIdentity: Equatable {
        var utxos: [WalletUTXO]
        var nextReceiveIndex: UInt32
        var nextChangeIndex: UInt32
    }

    private var trustedStateIdentity: TrustedStateIdentity? {
        record.map {
            TrustedStateIdentity(utxos: $0.utxos, nextReceiveIndex: $0.nextReceiveIndex,
                                 nextChangeIndex: $0.nextChangeIndex)
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                if let broadcastTxid {
                    Section {
                        Text("Payment sent")
                            .font(.headline)
                            .foregroundStyle(.green)
                            .accessibilityIdentifier("vaultPaymentSent")
                        Text(broadcastTxid.displayHex)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                    } footer: {
                        Text("You can close this screen.")
                    }
                } else {
                    signingSections
                }
            }
            .navigationTitle(broadcastTxid == nil ? "Approve payment" : "Payment")
            .onAppear {
                if let initialPSBT, working == nil {
                    pasted = initialPSBT.base64
                    addPasted()
                }
            }
            .task(id: trustedStateIdentity) {
                refreshSpendReview()
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") {
                        clearSensitiveSigningState()
                        dismiss()
                    }
                }
            }
            .onChange(of: scenePhase) { _, phase in
                guard phase == .background else { return }
                clearSensitiveSigningState()
                dismiss()
            }
            .onDisappear { clearSensitiveSigningState() }
        }
    }

    @ViewBuilder
    private var signingSections: some View {
        Section {
            TextField("Paste a PSBT (Base64)", text: $pasted)
                .font(.system(.caption, design: .monospaced))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .accessibilityIdentifier("psbtField")
            Button("Paste from clipboard") {
                pasted = model.pasteboardText() ?? ""
            }
            .accessibilityIdentifier("psbtPasteButton")
            Button("Add reply") { addPasted() }
                .accessibilityIdentifier("addPSBTButton")
                .disabled(authorizing
                    || pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        } footer: {
            Text("Paste the payment or the other signer’s reply here.")
        }
        if working != nil {
            reviewSection
            progressSection
            actionsSection
        }
        if let error {
            Section { Text(error).foregroundStyle(.red).font(.footnote) }
        }
        if let output {
            Section("PSBT to share") { CopyableTextBlock(text: output) }
        }
    }

    // MARK: - Review (what you are signing)

    private struct OutputLine {
        let destination: String
        let amount: Int64
        let isVaultOwned: Bool
    }

    /// Best-effort scriptPubKey → address; falls back to hex for non-standard
    /// scripts so an unrecognized destination is shown, never hidden.
    private func destination(forScript script: Data) -> String {
        AddressDecoder.address(for: script, network: model.network) ?? script.hex
    }

    /// Outputs the spend pays, materialized once when review succeeds rather
    /// than rebuilding every address during each SwiftUI body evaluation.
    private func outputLines(for review: Vault.SpendReview) -> [OutputLine] {
        review.outputs.map {
            OutputLine(destination: destination(forScript: $0.scriptPubKey),
                       amount: $0.amount, isVaultOwned: $0.isVaultOwned)
        }
    }

    private var feeAmount: Int64? {
        spendReview?.fee
    }

    private var sighashLabel: String {
        guard let types = spendReview?.sighashTypes else { return "unavailable" }
        let unique = Set(types)
        if unique == Set([UInt32(0)]) { return "DEFAULT — all inputs commit to every output" }
        if unique == Set([UInt32(1)]) { return "ALL — all inputs commit to every output" }
        if unique == Set([UInt32(0), UInt32(1)]) {
            return "DEFAULT / ALL — all inputs commit to every output"
        }
        return "unavailable"
    }

    private var locktimeLabel: String {
        guard let locktime = spendReview?.fallbackLocktime else { return "unavailable" }
        return locktime == 0 ? "none" : String(locktime)
    }

    private var sequenceLabel: String {
        guard let sequences = spendReview?.sequences else { return "unavailable" }
        return sequences.contains(where: { $0 < 0xFFFF_FFFE }) ? "replaceable (RBF)" : "final"
    }

    @ViewBuilder
    private var reviewSection: some View {
        Section {
            if spendReview != nil {
                ForEach(reviewedOutputLines.indices, id: \.self) { index in
                    let line = reviewedOutputLines[index]
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(line.isVaultOwned ? "Back to this account" : "Pays")
                                .font(.caption)
                                .foregroundStyle(line.isVaultOwned ? Color.secondary : Color.primary)
                            Spacer()
                            Text("\(line.amount) sat")
                                .font(.system(.callout, design: .monospaced))
                        }
                        ReviewAddress(address: line.destination)
                    }
                    .padding(.vertical, 1)
                }
                if let feeAmount {
                    LabeledContent("Fee", value: "\(feeAmount) sat")
                }
                NavigationLink("Transaction details") {
                    Form {
                        LabeledContent("Sighash", value: sighashLabel)
                        LabeledContent("Version", value: String(spendReview?.transactionVersion ?? 0))
                        LabeledContent("Locktime", value: locktimeLabel)
                        LabeledContent("Sequence", value: sequenceLabel)
                    }
                    .navigationTitle("Transaction details")
                }
            } else {
                Label("Winnow cannot safely review this proposal", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                Text(spendReviewError ?? "The vault or proposal is unavailable.")
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Check this payment")
        } footer: {
            Text(spendReview == nil
                 ? "Fix the problem above before approving this payment."
                 : "Check the address, amount, and fee on both devices before approving.")
        }
    }

    @ViewBuilder
    private var progressSection: some View {
        if let participantCount {
            Section("Next step") {
                Text(signingInstruction(required: participantCount))
                    .accessibilityIdentifier("musigNextStep")
                if !secretNonces.isEmpty {
                    Text("Keep this screen open while you use the other signer. If you leave or lock the phone, start a fresh exchange on both devices.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder
    private var actionsSection: some View {
        if let participantCount {
            Section("Actions") {
                Button("Prepare this phone") { attachNonces() }
                    .accessibilityIdentifier("musigNonceButton")
                    .disabled(nonceSessionStarted || minNonces >= participantCount
                        || minPartialSigs > 0 || !workingInputsRemainAvailable
                        || authorizing || broadcastTxid != nil)
                Button("Approve on this phone") { signMuSig2() }
                    .accessibilityIdentifier("musigSignButton")
                    .disabled(!nonceSessionStarted || signedMuSig2ThisSession
                        || secretNonces.isEmpty || minNonces < participantCount
                        || minPartialSigs >= participantCount || !workingInputsRemainAvailable
                        || authorizing)
                Button(broadcasting ? "Sending…" : "Send payment") {
                    aggregateAndBroadcast()
                }
                .accessibilityIdentifier("musigBroadcastButton")
                .disabled(minPartialSigs < participantCount || !workingInputsRemainAvailable
                    || authorizing || broadcasting || broadcastTxid != nil)
                if !workingInputsRemainAvailable {
                    stalePSBTMessage
                }
                if minNonces > 0 && broadcastTxid == nil {
                    Button("Start again") { restartExchange() }
                        .accessibilityIdentifier("musigRestartButton")
                        .disabled(authorizing || broadcasting)
                }
            }
        }
    }

    private func restartExchange() {
        guard var proposal = working else { return }
        for index in proposal.inputs.indices {
            proposal.inputs[index].pairs.removeAll {
                [PSBT.InType.musig2PubNonce, PSBT.InType.musig2PartialSig,
                 PSBT.InType.tapKeySignature, PSBT.InType.finalScriptWitness].contains($0.type)
            }
        }
        clearSensitiveSigningState()
        working = proposal
        refreshSpendReview()
    }

    private func signingInstruction(required: Int) -> String {
        if minPartialSigs >= required { return "Every approval is here. You can send the payment." }
        if signedMuSig2ThisSession { return "Copy the request below to the other signer, then add its signed reply here." }
        if minNonces >= required && nonceSessionStarted { return "The signers are ready. Check the payment, then approve it on this phone." }
        if nonceSessionStarted { return "Copy the request below to the other signer, then paste its reply above." }
        return "Check the payment, then prepare this phone for the signing exchange."
    }

    private var stalePSBTMessage: some View {
        Text("This PSBT is no longer a valid spend of the vault's available coins. It may be stale or altered; create or import a valid PSBT instead.")
            .font(.footnote)
            .foregroundStyle(.orange)
    }

    /// Reconstructs the authorization review from trusted local vault state.
    /// Output BIP32 metadata is never used to decide that an output is change.
    private func authorizationInputs() throws -> (vault: Vault, record: VaultRecord,
                                                   coordinates: [Vault.OutputCoordinate]) {
        guard let vault, let record else { throw SignError.unknownInput }
        var coordinates = record.utxos.map {
            Vault.OutputCoordinate(choice: $0.chain.rawValue, index: $0.index)
        }
        coordinates.append(Vault.OutputCoordinate(
            choice: AddressChain.receive.rawValue, index: record.nextReceiveIndex))
        coordinates.append(Vault.OutputCoordinate(
            choice: AddressChain.change.rawValue, index: record.nextChangeIndex))
        return (vault, record, coordinates)
    }

    private func validateSpend(_ psbt: PSBT) throws -> Vault.SpendReview {
        guard let record else { throw SignError.unknownInput }
        return try model.reviewVaultSpend(psbt, record: record)
    }

    private func refreshSpendReview() {
        guard let working else {
            spendReview = nil
            reviewedOutputLines = []
            spendReviewError = nil
            return
        }
        do {
            let review = try validateSpend(working)
            spendReview = review
            reviewedOutputLines = outputLines(for: review)
            spendReviewError = nil
        } catch {
            spendReview = nil
            reviewedOutputLines = []
            spendReviewError = error.localizedDescription
        }
    }

    private func addPasted() {
        error = nil
        do {
            let incoming = try PSBT(base64: pasted.trimmingCharacters(in: .whitespacesAndNewlines))
            let candidate = try working?.combined(with: [incoming]) ?? incoming
            let review = try validateSpend(candidate)
            spendReview = review
            reviewedOutputLines = outputLines(for: review)
            spendReviewError = nil
            working = candidate
            output = try candidate.base64V0()
            if let working { model.journalPSBT(stage: "vault-psbt-combined", psbt: working) }
            pasted = ""
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// The vault coordinates (multipath choice, index) of a PSBT input, found
    /// via the vault's UTXO set — the PSBT itself carries only the outpoint.
    private func context(for input: PSBT.Input, vault: Vault, record: VaultRecord) throws -> Vault.MuSig2Context {
        guard let txid = input.previousTxid, let vout = input.outputIndex,
              let utxo = record.utxos.first(where: { $0.txid == txid && $0.vout == vout })
        else { throw SignError.unknownInput }
        return try vault.muSig2Context(choice: utxo.chain.rawValue, index: utxo.index)
    }

    // MARK: - MuSig2

    private func attachNonces() {
        guard let initial = working else {
            error = SignError.noWorkingPSBT.localizedDescription
            return
        }
        operationTask?.cancel()
        let token = operationEpoch.begin()
        authorizing = true
        error = nil
        operationTask = Task { @MainActor in
            do {
                let result = try await model.withMasterKey(
                    reason: "Start signing this MuSig2 vault transaction") { master in
                    let inputs = try authorizationInputs()
                    var psbt = initial
                    var nonces: [Int: [Data: Data]] = [:]
                    for index in psbt.inputs.indices {
                        let signingContext = try context(
                            for: psbt.inputs[index], vault: inputs.vault, record: inputs.record)
                        nonces[index] = try inputs.vault.muSig2AttachNonce(
                            &psbt, input: index, context: signingContext, master: master,
                            knownUTXOs: inputs.record.utxos,
                            ownedOutputCoordinates: inputs.coordinates,
                            chainTip: model.status.tipHeight)
                    }
                    return (psbt, nonces)
                }
                try Task.checkCancellation()
                guard accepts(token) else { return }
                let reply = try result.0.base64V0()
                secretNonces = result.1
                nonceSessionStarted = true
                working = result.0
                output = reply
                model.journalPSBT(stage: "musig2-public-nonces", psbt: result.0)
            } catch is CancellationError {
                // Secret nonces produced for an invalidated presentation are
                // never installed into view state or exposed for round two.
            } catch {
                if accepts(token) { self.error = error.localizedDescription }
            }
            guard accepts(token) else { return }
            authorizing = false
            operationTask = nil
        }
    }

    private func signMuSig2() {
        guard let initial = working else { return }
        var initialNonces = secretNonces
        operationTask?.cancel()
        let token = operationEpoch.begin()
        authorizing = true
        error = nil
        operationTask = Task { @MainActor in
            // Whatever happens below, the copy this task took of the secret
            // nonces is overwritten before it is freed.
            defer { Self.scrub(&initialNonces) }
            do {
                let psbt = try await model.withMasterKey(
                    reason: "Complete signing this MuSig2 vault transaction") { master in
                    let inputs = try authorizationInputs()
                    // Stage nonce mutations beside the PSBT. Authentication
                    // cancellation or any later failure leaves the live nonce
                    // session untouched and retryable.
                    var psbt = initial
                    var stagedNonces = initialNonces
                    defer { Self.scrub(&stagedNonces) }
                    for index in psbt.inputs.indices {
                        let signingContext = try context(
                            for: psbt.inputs[index], vault: inputs.vault, record: inputs.record)
                        var nonces = stagedNonces[index] ?? [:]
                        try inputs.vault.muSig2Sign(
                            &psbt, input: index, context: signingContext, master: master,
                            secretNonces: &nonces, knownUTXOs: inputs.record.utxos,
                            ownedOutputCoordinates: inputs.coordinates,
                            chainTip: model.status.tipHeight)
                        stagedNonces[index] = nonces
                    }
                    return psbt
                }
                try Task.checkCancellation()
                guard accepts(token) else { return }
                let reply = try psbt.base64V0()
                working = psbt
                output = reply
                Self.scrub(&secretNonces)
                signedMuSig2ThisSession = true
                model.journalPSBT(stage: "musig2-partial-signed", psbt: psbt)
            } catch is CancellationError {
                // The presentation was invalidated; the session cannot be
                // resumed with the old nonce material.
            } catch {
                if accepts(token) { self.error = error.localizedDescription }
            }
            guard accepts(token) else { return }
            authorizing = false
            operationTask = nil
        }
    }

    private func aggregateAndBroadcast() {
        guard !broadcasting, broadcastTxid == nil,
              var psbt = working, let vault, let record else { return }
        operationTask?.cancel()
        let token = operationEpoch.begin()
        broadcasting = true
        operationTask = Task { @MainActor in
            do {
                try Task.checkCancellation()
                let inputs = try authorizationInputs()
                for index in psbt.inputs.indices {
                    let context = try context(for: psbt.inputs[index], vault: vault, record: record)
                    try vault.muSig2Aggregate(
                        &psbt, input: index, context: context,
                        knownUTXOs: inputs.record.utxos,
                        ownedOutputCoordinates: inputs.coordinates,
                        chainTip: model.status.tipHeight)
                }
                model.journalPSBT(stage: "musig2-aggregated", psbt: psbt)
                let transaction = try vault.finalizeSpend(
                    &psbt, knownUTXOs: inputs.record.utxos,
                    ownedOutputCoordinates: inputs.coordinates,
                    chainTip: model.status.tipHeight)
                let txid = try await commitAndBroadcast(transaction, vault: vault, record: record)
                guard accepts(token) else { return }
                broadcastTxid = txid
            } catch is CancellationError {
                // The persistent model reconciles an operation that already
                // crossed the broadcast boundary.
            } catch {
                if accepts(token) { self.error = error.localizedDescription }
            }
            guard accepts(token) else { return }
            broadcasting = false
            operationTask = nil
        }
    }

    // MARK: - Broadcast

    /// Broadcasts the finalized spend and commits it to the vault's local
    /// UTXO set (inputs out, change in pending — the `Wallet.send` rule).
    private func commitAndBroadcast(_ transaction: WalletCore.Transaction, vault: Vault,
                                    record: VaultRecord) async throws -> Data {
        try await model.broadcastVaultSpend(transaction, vault: vault, record: record)
    }

    private func accepts(_ token: SensitivePresentationEpoch.Token) -> Bool {
        operationEpoch.accepts(token, whilePresentationIsAllowed: scenePhase != .background)
    }

    private func clearSensitiveSigningState() {
        operationEpoch.invalidate()
        operationTask?.cancel()
        operationTask = nil
        pasted = ""
        working = nil
        output = nil
        error = nil
        broadcastTxid = nil
        broadcasting = false
        authorizing = false
        Self.scrub(&secretNonces)
        nonceSessionStarted = false
        signedMuSig2ThisSession = false
    }

    /// Overwrites every secret nonce before dropping the dictionary. Best
    /// effort: a `Data` still shared with a copy elsewhere is copied rather
    /// than zeroed by `resetBytes`, so the keys are materialised first (a
    /// `keys` view would itself keep the storage shared) and the view's own
    /// copies are scrubbed on every exit path.
    private static func scrub(_ nonces: inout [Int: [Data: Data]]) {
        for input in Array(nonces.keys) {
            for key in Array(nonces[input]?.keys ?? [:].keys) {
                let count = nonces[input]?[key]?.count ?? 0
                nonces[input]?[key]?.resetBytes(in: 0 ..< count)
            }
        }
        nonces.removeAll(keepingCapacity: false)
    }
}
