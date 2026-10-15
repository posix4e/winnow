import VaultKit
import WalletCore
import SwiftUI
import UIKit

/// The state of one shared-savings spend on this phone: the working PSBT,
/// the review that says what it pays, who has approved so far, and the
/// three moves a co-owner can make. All script-path accounts use this flow;
/// MuSig2 accounts use their own two-round signing exchange.
@MainActor
@Observable
final class VaultSpendSession {
    struct Line: Identifiable, Equatable {
        let id: Int
        let label: PaymentLabel
        let address: String
        let amount: Int64

        var title: String {
            switch label {
            case let .savings(name): "Back into \(name)"
            case let .person(name): "Pays \(name)"
            case .you: "Pays you (your wallet)"
            case .unknown: "Pays an unsaved address"
            }
        }
    }

    enum SessionError: LocalizedError {
        case unknownSavings(String?)
        case notTheseSavings
        case noWorkingPSBT

        var errorDescription: String? {
            switch self {
            case let .unknownSavings(name):
                "This request is for \(name.map { "“\($0)”" } ?? "savings that are") not on this phone. Ask the person who created them to share the savings card — money sent before you add them cannot be approved from this phone."
            case .notTheseSavings:
                "This request belongs to different shared savings."
            case .noWorkingPSBT:
                "Paste a request first."
            }
        }
    }

    let recordID: String
    private let model: AppModel

    private(set) var working: PSBT?
    private(set) var review: Vault.SpendReview?
    private(set) var lines: [Line] = []
    /// Signer positions (descriptor order) that have signed every input.
    private(set) var approvals: Set<Int> = []
    private(set) var signerNames: [Int: String] = [:]
    private(set) var ownPosition: Int?
    /// The current request or approval to share with another signer.
    private(set) var output: String?
    private(set) var error: String?
    private(set) var broadcastTxid: Data?
    private(set) var busy = false
    private var operationTask: Task<Void, Never>?

    init(model: AppModel, recordID: String) {
        self.model = model
        self.recordID = recordID
    }

    var record: VaultRecord? { model.vaults.first { $0.id == recordID } }

    var threshold: Int? {
        guard let record, let vault = try? model.vault(for: record), vault.isScriptPath else { return nil }
        return vault.threshold
    }

    var approvedByYou: Bool { ownPosition.map { approvals.contains($0) } ?? false }

    var fee: Int64? { review?.fee }

    var canFinish: Bool {
        guard let threshold, working != nil, review != nil, broadcastTxid == nil else { return false }
        return approvals.count >= threshold
    }

    /// "Approved by you · waiting for Alice or Bob (1 of 2)".
    var progressText: String {
        guard let threshold else { return "" }
        let approved = approvals.sorted().map { signerNames[$0] ?? "a co-owner" }
        let waiting = signerNames.keys.filter { !approvals.contains($0) }.sorted().map { signerNames[$0] ?? "a co-owner" }
        var parts: [String] = []
        parts.append(approved.isEmpty ? "No approvals yet" : "Approved by \(approved.joined(separator: ", "))")
        if approvals.count < threshold, !waiting.isEmpty {
            parts.append("waiting for \(waiting.joined(separator: " or "))")
        }
        return parts.joined(separator: " · ") + " (\(approvals.count) of \(threshold))"
    }

    /// Takes a request (envelope or bare PSBT), combines it into the working
    /// copy, and re-reviews. A request for other savings is refused by name.
    func add(text: String) {
        error = nil
        do {
            guard let record else { throw SessionError.unknownSavings(nil) }
            let request = try ApprovalRequest.decode(text, network: model.network)
            if let vaultID = request.vault, vaultID != record.id {
                let known = model.vaults.contains { $0.id == vaultID }
                throw known ? SessionError.notTheseSavings : SessionError.unknownSavings(request.name)
            }
            let incoming = try request.decodedPSBT()
            let candidate = try working?.combined(with: [incoming]) ?? incoming
            try refresh(with: candidate, record: record)
            working = candidate
            output = try model.approvalRequest(for: record, psbt: candidate).serialized()
            model.journalPSBT(stage: "vault-psbt-combined", psbt: candidate)
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Re-runs the review against trusted local state (the coin set moved,
    /// or the frontier did). Clears the review when the spend is no longer
    /// valid, so nothing can be approved or finished on stale coins.
    func recheck() {
        guard let working, let record else {
            review = nil
            lines = []
            approvals = []
            return
        }
        do {
            try refresh(with: working, record: record)
        } catch {
            review = nil
            lines = []
            approvals = []
            self.error = error.localizedDescription
        }
    }

    private func refresh(with psbt: PSBT, record: VaultRecord) throws {
        let vault = try model.vault(for: record)
        let reviewed = try model.reviewVaultSpend(psbt, record: record)
        let labeler = PaymentLabeler(savingsName: record.name,
                                     personScripts: model.personScripts(),
                                     ownScripts: model.ownWatchScripts)
        lines = reviewed.outputs.enumerated().map { index, output in
            Line(id: index,
                 label: labeler.label(script: output.scriptPubKey, isVaultOwned: output.isVaultOwned),
                 address: Self.address(forScript: output.scriptPubKey, network: model.network),
                 amount: output.amount)
        }
        approvals = try vault.signers(of: psbt, knownUTXOs: record.utxos)
        review = reviewed
        resolveSignerNames(vault: vault)
    }

    private func resolveSignerNames(vault: Vault) {
        signerNames = [:]
        ownPosition = nil
        guard let keys = try? vault.signerKeys() else { return }
        let ownKey = try? model.ownSignerIdentity()
        var identities: [Data: String] = [:]
        for person in model.people {
            guard let signerKey = person.signerKey,
                  let key = try? PersonKeys.signerIdentity(signerKey, network: model.network)
            else { continue }
            identities[key] = person.name
        }
        for (position, key) in keys.enumerated() {
            if key == ownKey {
                signerNames[position] = "you"
                ownPosition = position
            } else {
                signerNames[position] = identities[key] ?? "an unnamed co-owner"
            }
        }
    }

    /// Adds this device's approval, then prepares the envelope to share back.
    func approve() async {
        guard let initial = working, let record, !busy else {
            if working == nil { error = SessionError.noWorkingPSBT.localizedDescription }
            return
        }
        await perform {
            let signed = try await self.model.partialSignVaultSpend(
                initial, record: record, reason: "Approve this shared-savings payment")
            try Task.checkCancellation()
            try self.refresh(with: signed, record: record)
            self.working = signed
            self.output = try self.model.approvalRequest(for: record, psbt: signed).serialized()
            self.model.journalApproval("approval.given", vaultID: record.id,
                                       fields: ["approvals": String(self.approvals.count)])
        }
    }

    /// Finalizes and sends it. Enabled only once enough approvals are present
    /// on every input.
    func finish() async {
        guard canFinish, let working, let record, !busy else { return }
        await perform {
            let txid = try await self.model.finalizeAndBroadcastVaultSpend(working, record: record)
            try Task.checkCancellation()
            self.broadcastTxid = txid
            self.model.journalApproval("approval.finished", vaultID: record.id,
                                       fields: ["txid": txid.displayHex])
        }
    }

    /// The session owns cancellation even if authentication finishes after dismissal.
    private func perform(_ action: @escaping @MainActor () async throws -> Void) async {
        guard !busy else { return }
        busy = true
        error = nil
        let task = Task { @MainActor in
            do { try await action() }
            catch is CancellationError { }
            catch {
                if !Task.isCancelled { self.error = error.localizedDescription }
            }
            if !Task.isCancelled {
                busy = false
                operationTask = nil
            }
        }
        operationTask = task
        await task.value
    }

    func clear() {
        operationTask?.cancel()
        operationTask = nil
        working = nil
        review = nil
        lines = []
        approvals = []
        output = nil
        error = nil
        broadcastTxid = nil
        busy = false
    }

    /// Best-effort scriptPubKey → address; hex for anything non-standard so
    /// a destination is shown, never hidden.
    static func address(forScript script: Data, network: BitcoinNetwork) -> String {
        AddressDecoder.address(for: script, network: network) ?? script.hex
    }
}

/// The script-path approval screen: paste a request or raw PSBT, review,
/// approve, share, and finish when enough co-owners have signed.
/// Sensitive state is dropped when the app backgrounds or the sheet closes.
struct ApprovalView: View {
    let recordID: String
    var initialPSBT: PSBT?
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var session: VaultSpendSession?
    @State private var pasted = ""

    var body: some View {
        NavigationStack {
            Form {
                if let session {
                    content(session)
                } else {
                    BusyIndicator()
                }
            }
            .navigationTitle(session?.broadcastTxid == nil ? "Approve a request" : "Payment")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") {
                        session?.clear()
                        dismiss()
                    }
                }
            }
            .onAppear {
                if session == nil {
                    session = VaultSpendSession(model: model, recordID: recordID)
                    if let initialPSBT { session?.add(text: initialPSBT.base64) }
                }
            }
            .task(id: model.vaults.first { $0.id == recordID }) {
                session?.recheck()
            }
            .onChange(of: scenePhase) { _, phase in
                guard phase == .background else { return }
                session?.clear()
                dismiss()
            }
            .onDisappear { session?.clear() }
        }
    }

    @ViewBuilder
    private func content(_ session: VaultSpendSession) -> some View {
        if let txid = session.broadcastTxid {
            sentSection(txid)
        } else {
            requestSection(session)
            if session.working != nil {
                reviewSection(session)
                decisionSection(session)
            }
            if let error = session.error, session.review != nil || session.working == nil {
                Section { Text(error).foregroundStyle(.red).font(.footnote).accessibilityIdentifier("approvalError") }
            }
            if let output = session.output { shareSection(output, session: session) }
        }
    }

    /// Where the request comes in.
    private func requestSection(_ session: VaultSpendSession) -> some View {
        Section {
            TextField("Paste the request", text: $pasted, axis: .vertical)
                .lineLimit(1...4)
                .font(.system(.caption, design: .monospaced))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .accessibilityIdentifier("approvalRequestField")
            Button("Paste from clipboard") {
                pasted = model.pasteboardText() ?? ""
            }
            .accessibilityIdentifier("approvalPasteButton")
            Button("Review request") {
                session.add(text: pasted)
                if session.error == nil { pasted = "" }
            }
            .accessibilityIdentifier("reviewApprovalButton")
            .disabled(session.busy || pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        } footer: {
            Text("A request is what a co-owner shares when they want money to leave the savings. Paste it here; Winnow shows exactly what it pays before you approve.")
        }
    }

    /// What the request pays, line by line, or why it cannot be reviewed.
    private func reviewSection(_ session: VaultSpendSession) -> some View {
        Section {
            if session.review != nil {
                ForEach(session.lines) { line in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(line.title)
                                .font(.callout)
                                .foregroundStyle(line.label == .savings(session.record?.name ?? "") ? Color.secondary : Color.primary)
                            Spacer()
                            Text(satsText(line.amount))
                                .font(.system(.callout, design: .monospaced))
                        }
                        Text(line.address)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    .accessibilityIdentifier("approvalOutputLine")
                }
                if let fee = session.fee {
                    LabeledContent("Fee", value: satsText(fee))
                }
                Text(session.progressText)
                    .font(.footnote)
                    .accessibilityIdentifier("approvalProgress")
            } else {
                Label("Winnow cannot safely review this request", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                Text(session.error ?? "The savings or the request are unavailable.")
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("What it pays")
        } footer: {
            Text("Anyone can propose a payment. Winnow checks the coins are these savings' own and that your approval covers exactly what is shown here.")
        }
    }

    /// Approve, and finish once enough co-owners have.
    private func decisionSection(_ session: VaultSpendSession) -> some View {
        Section {
            Button(session.busy ? "Working…" : "Approve") {
                Task { await session.approve() }
            }
            .accessibilityIdentifier("approveButton")
            .disabled(session.busy || session.review == nil || session.approvedByYou)
            Button("Finish — send it") {
                Task { await session.finish() }
            }
            .accessibilityIdentifier("finishApprovalButton")
            .disabled(!session.canFinish || session.busy)
        } footer: {
            Text(session.canFinish
                 ? "Enough co-owners have approved. Finishing broadcasts the payment."
                 : "When enough co-owners have approved, whoever holds the last approval taps Finish.")
        }
    }

    private func shareSection(_ output: String, session: VaultSpendSession) -> some View {
        Section {
            CopyableTextBlock(text: output)
                .accessibilityIdentifier("approvalOutputBlock")
            if model.advancedMode, let raw = try? session.working?.base64V0() {
                DisclosureGroup("Raw PSBT") {
                    CopyableTextBlock(text: raw)
                        .accessibilityIdentifier("approvalRawPSBT")
                }
                .accessibilityIdentifier("approvalRawPSBTDisclosure")
            }
        } header: {
            Text(session.approvedByYou ? "Share your approval" : "Share payment request")
        } footer: {
            Text("Send this back to a co-owner, or to whoever will finish the payment.")
        }
    }

    private func sentSection(_ txid: Data) -> some View {
        Section {
            Label("Sent", systemImage: "checkmark.seal")
                .foregroundStyle(.green)
                .accessibilityIdentifier("approvalBroadcast")
            Text(txid.displayHex)
                .font(.system(.caption2, design: .monospaced))
                .textSelection(.enabled)
            Text("The savings balance updates once a block includes it.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}
