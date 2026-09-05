import BitcoinCore
import BitcoinP2P
import SwiftUI
import UIKit
import WalletCore

/// Signer/combiner/finalizer roles for vault spends (BIP370/371/373).
///
/// multi_a k-of-n: collect partial-signed PSBTs, sign with this device's key,
/// combine when every input carries k signatures, finalize → broadcast.
///
/// MuSig2 n-of-n: round 1 attaches this device's public nonce (the secret
/// nonces stay in this screen's memory — leaving before round 2 abandons the
/// session), cosigners' nonce-bearing PSBTs are combined, round 2 signs,
/// partials are combined, aggregated → broadcast.
struct VaultSignView: View {
    let recordID: String
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

    private var threshold: Int? {
        guard case let .multiA(k, _, _, _) = vault?.policy else { return nil }
        return k
    }

    private var participantCount: Int? {
        guard case let .muSig2(participants, _) = vault?.policy else { return nil }
        return participants.count
    }

    /// The lowest per-input count — the spend is ready only when every input is.
    private var minSignatures: Int { working?.inputs.map(\.tapScriptSignatures.count).min() ?? 0 }
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
                Section {
                    TextField("Paste a PSBT (Base64)", text: $pasted)
                        .font(.system(.caption, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .accessibilityIdentifier("psbtField")
                    Button("Paste from clipboard") {
                        pasted = UIPasteboard.general.string ?? ""
                    }
                    .accessibilityIdentifier("psbtPasteButton")
                    Button("Add / combine PSBT") { addPasted() }
                        .accessibilityIdentifier("addPSBTButton")
                        .disabled(authorizing
                            || pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                } footer: {
                    Text("The first PSBT becomes the working copy; further PSBTs are combined into it (BIP174 combiner role).")
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
                    Section("PSBT to share") {
                        CopyableTextBlock(text: output)
                    }
                }

                if let broadcastTxid {
                    Section {
                        Label("Broadcast", systemImage: "checkmark.seal")
                            .foregroundStyle(.green)
                        Text(broadcastTxid.displayHex)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                        Text("A filter match will confirm it in a block; the vault's balance updates then.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Sign / combine")
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

    // MARK: - Review (what you are signing)

    private struct OutputLine {
        let destination: String
        let amount: Int64
        let isVaultOwned: Bool
    }

    private var hrp: String { model.network == .mainnet ? "bc" : "tb" }

    /// Best-effort scriptPubKey → address; falls back to hex for non-standard
    /// scripts so an unrecognized destination is shown, never hidden.
    private func destination(forScript script: Data) -> String {
        guard script.count >= 4, let first = script.first else { return script.hex }
        let version: Int? = first == 0x00 ? 0 : (first >= 0x51 && first <= 0x60 ? Int(first) - 0x50 : nil)
        guard let version else { return script.hex }
        let pushLength = Int(script[script.index(script.startIndex, offsetBy: 1)])
        let program = Data(script.dropFirst(2))
        guard program.count == pushLength, (2 ... 40).contains(program.count),
              let address = try? SegwitAddress.encode(hrp: hrp, version: version, program: program)
        else { return script.hex }
        return address
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
                            Text(line.isVaultOwned ? "Vault-owned output" : "Pays")
                                .font(.caption)
                                .foregroundStyle(line.isVaultOwned ? Color.secondary : Color.primary)
                            Spacer()
                            Text("\(line.amount) sat")
                                .font(.system(.callout, design: .monospaced))
                        }
                        Text(line.destination)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    .padding(.vertical, 1)
                }
                if let feeAmount {
                    LabeledContent("Fee", value: "\(feeAmount) sat")
                }
                LabeledContent("Sighash", value: sighashLabel)
                LabeledContent("Version", value: String(spendReview?.transactionVersion ?? 0))
                LabeledContent("Locktime", value: locktimeLabel)
                LabeledContent("Sequence", value: sequenceLabel)
            } else {
                Label("Winnow cannot safely review this proposal", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                Text(spendReviewError ?? "The vault or proposal is unavailable.")
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Review — what you are signing")
        } footer: {
            Text(spendReview == nil
                 ? "Signing and broadcasting remain disabled until the proposal passes every check."
                 : "A cosigner can propose any transaction. Winnow verifies known inputs and vault-owned output scripts; your signature authorizes exactly the destinations and fee shown here.")
        }
    }

    @ViewBuilder
    private var progressSection: some View {
        if let threshold {
            Section("Progress") {
                LabeledContent("Signatures", value: "\(minSignatures) of \(threshold) per input")
            }
        } else if let participantCount {
            Section("Progress") {
                LabeledContent("Public nonces", value: "\(minNonces) of \(participantCount) per input")
                LabeledContent("Partial signatures", value: "\(minPartialSigs) of \(participantCount) per input")
                if !secretNonces.isEmpty {
                    Text("This device's secret nonces live only on this screen — leaving before round 2 abandons the session.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    @ViewBuilder
    private var actionsSection: some View {
        if let threshold {
            Section("Actions") {
                Button("Sign with this device") { signMultiA() }
                    .disabled(authorizing || !workingInputsRemainAvailable || broadcastTxid != nil)
                Button(broadcasting ? "Broadcasting…" : "Finalize & broadcast") {
                    finalizeAndBroadcast()
                }
                .disabled(minSignatures < threshold || !workingInputsRemainAvailable
                    || authorizing || broadcasting || broadcastTxid != nil)
                if !workingInputsRemainAvailable {
                    stalePSBTMessage
                }
            }
        } else if let participantCount {
            Section("Actions") {
                Button("Round 1 — attach this device's nonce") { attachNonces() }
                    .disabled(nonceSessionStarted || minNonces >= participantCount
                        || minPartialSigs > 0 || !workingInputsRemainAvailable
                        || authorizing || broadcastTxid != nil)
                Button("Round 2 — sign with this device") { signMuSig2() }
                    .disabled(!nonceSessionStarted || signedMuSig2ThisSession
                        || secretNonces.isEmpty || minNonces < participantCount
                        || minPartialSigs >= participantCount || !workingInputsRemainAvailable
                        || authorizing)
                Button(broadcasting ? "Broadcasting…" : "Aggregate & broadcast") {
                    aggregateAndBroadcast()
                }
                .disabled(minPartialSigs < participantCount || !workingInputsRemainAvailable
                    || authorizing || broadcasting || broadcastTxid != nil)
                if !workingInputsRemainAvailable {
                    stalePSBTMessage
                }
            }
        }
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

    // MARK: - multi_a

    private func signMultiA() {
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
                guard let record else { throw SignError.unknownInput }
                let psbt = try await model.partialSignVaultSpend(
                    initial, record: record, reason: "Sign this shared-vault transaction")
                try Task.checkCancellation()
                guard accepts(token) else { return }
                working = psbt
                output = psbt.base64
            } catch is CancellationError {
                // Inactive/background transitions deliberately abandon output.
            } catch {
                if accepts(token) { self.error = error.localizedDescription }
            }
            guard accepts(token) else { return }
            authorizing = false
            operationTask = nil
        }
    }

    private func finalizeAndBroadcast() {
        guard !broadcasting, broadcastTxid == nil,
              let psbt = working, let record else { return }
        operationTask?.cancel()
        let token = operationEpoch.begin()
        broadcasting = true
        operationTask = Task { @MainActor in
            do {
                try Task.checkCancellation()
                let txid = try await model.finalizeAndBroadcastVaultSpend(psbt, record: record)
                guard accepts(token) else { return }
                broadcastTxid = txid
            } catch is CancellationError {
                // Broadcast may already have crossed its external commit
                // point; AppModel remains the source of truth after dismissal.
            } catch {
                if accepts(token) { self.error = error.localizedDescription }
            }
            guard accepts(token) else { return }
            broadcasting = false
            operationTask = nil
        }
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
                            ownedOutputCoordinates: inputs.coordinates)
                    }
                    return (psbt, nonces)
                }
                try Task.checkCancellation()
                guard accepts(token) else { return }
                secretNonces = result.1
                nonceSessionStarted = true
                working = result.0
                output = result.0.base64
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
        let initialNonces = secretNonces
        operationTask?.cancel()
        let token = operationEpoch.begin()
        authorizing = true
        error = nil
        operationTask = Task { @MainActor in
            do {
                let psbt = try await model.withMasterKey(
                    reason: "Complete signing this MuSig2 vault transaction") { master in
                    let inputs = try authorizationInputs()
                    // Stage nonce mutations beside the PSBT. Authentication
                    // cancellation or any later failure leaves the live nonce
                    // session untouched and retryable.
                    var psbt = initial
                    var stagedNonces = initialNonces
                    for index in psbt.inputs.indices {
                        let signingContext = try context(
                            for: psbt.inputs[index], vault: inputs.vault, record: inputs.record)
                        var nonces = stagedNonces[index] ?? [:]
                        try inputs.vault.muSig2Sign(
                            &psbt, input: index, context: signingContext, master: master,
                            secretNonces: &nonces, knownUTXOs: inputs.record.utxos,
                            ownedOutputCoordinates: inputs.coordinates)
                        stagedNonces[index] = nonces
                    }
                    return psbt
                }
                try Task.checkCancellation()
                guard accepts(token) else { return }
                working = psbt
                output = psbt.base64
                secretNonces.removeAll(keepingCapacity: false)
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
                        ownedOutputCoordinates: inputs.coordinates)
                }
                model.journalPSBT(stage: "musig2-aggregated", psbt: psbt)
                let transaction = try vault.finalizeSpend(
                    &psbt, knownUTXOs: inputs.record.utxos,
                    ownedOutputCoordinates: inputs.coordinates)
                let txid = try await commitAndBroadcast(transaction, vault: vault, record: record)
                guard accepts(token) else { return }
                broadcastTxid = txid
            } catch is CancellationError {
                // See finalizeAndBroadcast: the persistent model reconciles
                // an operation that crossed the broadcast boundary.
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
    private func commitAndBroadcast(_ transaction: BitcoinTransaction, vault: Vault,
                                    record: VaultRecord) async throws -> Data {
        let txid = try await model.broadcast(transaction)
        let changeIndex = record.nextChangeIndex
        let changeScript = try? vault.scriptPubKey(index: changeIndex, choice: AddressChain.change.rawValue)
        _ = await model.recordVaultSpend(id: record.id, transaction: transaction,
                                         changeScriptPubKey: changeScript, changeIndex: changeIndex)
        return txid
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
        secretNonces.removeAll(keepingCapacity: false)
        nonceSessionStarted = false
        signedMuSig2ThisSession = false
    }
}
