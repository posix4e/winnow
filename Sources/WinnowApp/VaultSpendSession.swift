import BitcoinCore
import BitcoinP2P
import SwiftUI
import UIKit
import WalletCore

/// The state of one shared-savings spend on this phone: the working PSBT,
/// the review that says what it pays, who has approved so far, and the
/// three moves a co-owner can make. Script-path k-of-n only; MuSig2 vaults
/// stay on the expert screen. Every check runs through `AppModel`'s vault
/// helpers, the same code the expert screen uses.
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
            case .unknown: "Pays an address not in People"
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
    /// The envelope to hand back after this device approved.
    private(set) var output: String?
    private(set) var error: String?
    private(set) var broadcastTxid: Data?
    private(set) var busy = false

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
                signerNames[position] = identities[key] ?? "a co-owner not in People"
            }
        }
    }

    /// Adds this device's approval, then prepares the envelope to share back.
    func approve() async {
        guard let initial = working, let record, !busy else {
            if working == nil { error = SessionError.noWorkingPSBT.localizedDescription }
            return
        }
        busy = true
        error = nil
        defer { busy = false }
        do {
            let signed = try await model.partialSignVaultSpend(
                initial, record: record, reason: "Approve this shared-savings payment")
            try refresh(with: signed, record: record)
            working = signed
            output = try model.approvalRequest(for: record, psbt: signed).serialized()
            model.journalApproval("approval.given", vaultID: record.id,
                                  fields: ["approvals": String(approvals.count)])
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Finalizes and sends it. Enabled only once enough approvals are present
    /// on every input.
    func finish() async {
        guard canFinish, let working, let record, !busy else { return }
        busy = true
        error = nil
        defer { busy = false }
        do {
            let txid = try await model.finalizeAndBroadcastVaultSpend(working, record: record)
            broadcastTxid = txid
            model.journalApproval("approval.finished", vaultID: record.id,
                                  fields: ["txid": txid.displayHex])
        } catch {
            self.error = error.localizedDescription
        }
    }

    func clear() {
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
        let hrp = network == .mainnet ? "bc" : "tb"
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
}

/// The beginner's approval screen: paste a request, read what it pays in
/// plain words, approve, share the approval back, and finish when enough
/// co-owners have. Sensitive state is dropped the moment the app backgrounds,
/// as on the expert screen.
struct ApprovalView: View {
    let recordID: String
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
                    ProgressView()
                }
            }
            .navigationTitle("Approve a request")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") {
                        session?.clear()
                        dismiss()
                    }
                }
            }
            .onAppear {
                if session == nil { session = VaultSpendSession(model: model, recordID: recordID) }
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
        if session.broadcastTxid == nil {
            Section {
                TextField("Paste the request", text: $pasted, axis: .vertical)
                    .font(.system(.caption, design: .monospaced))
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .accessibilityIdentifier("approvalRequestField")
                Button("Paste from clipboard") {
                    pasted = UIPasteboard.general.string ?? ""
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

        if session.working != nil {
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

            if session.broadcastTxid == nil {
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
        }

        if let error = session.error, session.review != nil || session.working == nil {
            Section { Text(error).foregroundStyle(.red).font(.footnote).accessibilityIdentifier("approvalError") }
        }

        if let output = session.output, session.broadcastTxid == nil {
            Section {
                CopyableTextBlock(text: output)
                    .accessibilityIdentifier("approvalOutputBlock")
            } header: {
                Text("Share your approval")
            } footer: {
                Text("Send this back to a co-owner, or to whoever will finish the payment.")
            }
        }

        if let txid = session.broadcastTxid {
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
}
