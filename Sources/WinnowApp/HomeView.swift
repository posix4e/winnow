import WalletCore
import Foundation
import SwiftUI

/// Immutable identity of the fields that produced a fee-bump preview. A late
/// async result is accepted only while this request still matches the form.
struct FeeBumpReviewInputs: Equatable {
    let txid: Data
    let targetRateText: String

    var targetRate: Double? {
        Double(targetRateText.trimmingCharacters(in: .whitespacesAndNewlines))
    }
}

/// Advanced mode's Wallet tab: balance (confirmed sats), the vault tools,
/// sync detail, and the local transaction history. History speaks in
/// confirmed blocks only — a pending send we broadcast is labeled "awaiting
/// confirmation", never "incoming" (docs/read-side.md §3.3). Beginner mode
/// shows the same wallet on one screen (BeginnerHomeView) and reuses the
/// rows and the payment detail below.
struct HomeView: View {
    var sendFrom: (String) -> Void
    /// Opens Send pre-addressed to a saved person, from a payment's detail.
    var sendToPerson: (String) -> Void
    @Environment(AppModel.self) private var model
    @State private var showReceive = false
    @State private var showSharedSavings = false
    @State private var showExtraDevice = false
    @State private var showAddSavings = false
    @State private var showAdvancedAccount = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Balance · confirmed")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        Text(satsText(model.status.balance))
                            .font(.system(.largeTitle, design: .rounded).bold())
                            .accessibilityIdentifier("balanceText")
                            .accessibilityValue(satsText(model.status.balance))
                        Text("\(model.status.utxoCount) UTXO(s)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }

                Section("Savings") {
                    ForEach(model.vaults) { record in
                        if let vault = try? model.vault(for: record) {
                            NavigationLink {
                                AccountDetailView(recordID: record.id) { sendFrom(record.id) }
                            } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(record.name)
                                    Text("\(vault.threshold) of \(vault.signerCount) keys required · \(satsText(record.balance))")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .accessibilityIdentifier("walletSavings-\(record.name)")
                        }
                    }
                    Button("Save with other people") { showSharedSavings = true }
                        .accessibilityIdentifier("walletSharedSavingsButton")
                    Button("Add a shared account") { showAddSavings = true }
                        .accessibilityIdentifier("addSharedSavingsButton")
                    Button("New account with custom rules") { showAdvancedAccount = true }
                        .accessibilityIdentifier("newVaultButton")
                    Button("Require another signing device") { showExtraDevice = true }
                        .accessibilityIdentifier("walletExtraDeviceButton")
                }

                Section("Sync") {
                    if let statusText = model.syncStatusText {
                        if case .peerDiscoveryFailed = model.syncPhase {
                            Text(statusText)
                                .font(.footnote)
                                .foregroundStyle(.red)
                            Button("Retry") {
                                Task { await model.retryPeerDiscovery() }
                            }
                            .accessibilityIdentifier("retryPeersButton")
                        } else {
                            BusyIndicator(text: statusText)
                                .accessibilityIdentifier("syncProgressText")
                        }
                    }
                    // nextScanHeight is the NEXT block to scan, so a fully
                    // scanned tip reads "tip+1 of tip" — clamp the display.
                    // Absent when no scan has produced a position yet: the
                    // status line above is already saying what is happening,
                    // and a zeroed row said "block 0 of 0" (#99).
                    if let filterScan = model.syncPhase.filterScanText(
                        fallbackScanned: model.status.nextScanHeight,
                        fallbackTip: model.status.tipHeight
                    ) {
                        LabeledContent("Filter scan", value: filterScan)
                    }
                    LabeledContent("Peers", value: "\(model.status.peerCount)")
                    ChainCheckStatus()
                    if model.status.syncing, model.syncStatusText == nil {
                        BusyIndicator(text: "Scanning filters…")
                    }
                    if let error = model.status.lastSyncError {
                        Text(error)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                    // A relay problem, not a sync failure — sync is running.
                    if let quarantined = model.status.relayStoreQuarantined {
                        Text(quarantined)
                            .font(.footnote)
                            .foregroundStyle(.orange)
                            .accessibilityIdentifier("relayStoreQuarantined")
                    }
                    Button("Sync now") {
                        Task { await model.syncNow() }
                    }
                    .accessibilityIdentifier("syncNowButton")
                    .disabled(model.status.syncing)
                }

                Section("Transactions") {
                    if model.status.history.isEmpty {
                        Text("No transactions yet. Payments appear here once they confirm in a block.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(Array(model.status.history.enumerated()), id: \.offset) { _, entry in
                        NavigationLink(value: entry.txid) { HistoryRow(entry: entry) }
                        .accessibilityIdentifier("historyPayment-\(entry.txid.displayHex)")
                    }
                }
            }
            .navigationTitle("Winnow")
            .navigationDestination(for: Data.self) { PaymentDetailView(txid: $0, sendToPerson: sendToPerson) }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    // The way back to the one-screen interface. Every
                    // setting made here stays in effect there.
                    Button("Simple") { model.setAdvancedMode(false) }
                        .accessibilityIdentifier("advancedModeButton")
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Receive") { showReceive = true }
                        .accessibilityIdentifier("receiveButton")
                }
            }
            .sheet(isPresented: $showReceive) {
                ReceiveView()
            }
            .sheet(isPresented: $showSharedSavings) { SharedSavingsCreateView() }
            .sheet(isPresented: $showAddSavings) { AddSharedSavingsView() }
            .sheet(isPresented: $showAdvancedAccount) { VaultCreateView() }
            .sheet(isPresented: $showExtraDevice) { VaultCreateView(role: .muSig2) }
            .refreshable {
                await model.syncNow()
            }
        }
    }
}

/// One payment in the list. Advanced mode shows the block, the fee and the
/// replacement's id; beginner mode says Confirmed, Pending or Replaced.
struct HistoryRow: View {
    @Environment(AppModel.self) private var model
    let entry: HistoryEntry

    /// Net effect on the wallet: received (incl. our own change) minus spent.
    private var net: Int64 { entry.received - entry.spent }

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                let labels = Array(Set(model.labeledReceiveOutputs(entry).map(\.label))).sorted()
                if !labels.isEmpty {
                    Text(labels.joined(separator: " · "))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("paymentReceiveLabels-\(entry.txid.displayHex)")
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text("\(net >= 0 ? "+" : "−")\(abs(net).formatted()) sats")
                    .foregroundStyle(net >= 0 ? .green : .primary)
                if model.advancedMode { detailedStatus } else { plainStatus }
            }
        }
    }

    /// Confirmed, Pending or Replaced, under the same identifiers the
    /// detailed wording carries, so a journey reads either.
    @ViewBuilder
    private var plainStatus: some View {
        if entry.replacedBy != nil {
            Text("Replaced")
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("transactionReplaced-\(entry.txid.displayHex)")
        } else if entry.height > 0 {
            Text("Confirmed")
                .accessibilityIdentifier("transactionConfirmation-\(entry.txid.displayHex)")
                .font(.caption)
                .foregroundStyle(.secondary)
        } else {
            Text("Pending")
                .font(.caption)
                .foregroundStyle(.orange)
        }
    }

    @ViewBuilder
    private var detailedStatus: some View {
        if let replacement = entry.replacedBy {
            Text("replaced by \(replacement.displayHex.prefix(8))…")
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("transactionReplaced-\(entry.txid.displayHex)")
        } else if entry.height > 0 {
            Text("block \(entry.height)")
                .accessibilityIdentifier("transactionConfirmation-\(entry.txid.displayHex)")
                .font(.caption)
                .foregroundStyle(.secondary)
        } else {
            Text("awaiting confirmation")
                .font(.caption)
                .foregroundStyle(.orange)
        }
        if let fee = entry.fee {
            Text("fee \(fee.formatted()) sats")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private var title: String {
        guard net < 0 else {
            if let sender = model.receivedSender(entry) { return "Received from \(sender.name)" }
            return "Received"
        }
        let recipients = model.paymentRecipients(entry)
        if recipients.count == 1, let person = recipients.first?.person { return "Sent to \(person.name)" }
        return "Sent"
    }
}

/// One payment: who, how much, the local labels, and the sender. The raw
/// addresses and the transaction id are folded away in beginner mode; the
/// explorer link and fee bumping are Advanced.
struct PaymentDetailView: View {
    let txid: Data
    let sendToPerson: (String) -> Void
    @Environment(AppModel.self) private var model
    @State private var editing: AppModel.PaymentRecipient?
    @State private var labelingSender = false
    @State private var editingReceiveLabel: AppModel.LabeledReceiveOutput?
    @State private var attachingDestination: PersonRecord?
    @State private var showFeeBump = false
    @State private var loading = false
    @State private var error: String?

    private var entry: HistoryEntry? { model.status.history.first { $0.txid == txid } }

    var body: some View {
        Form {
            if let entry {
                Section { HistoryRow(entry: entry) }
                ForEach(model.paymentRecipients(entry)) { recipient in
                    Section {
                        if let person = recipient.person { Text(person.name).font(.headline) }
                        technical("Address") { CopyableTextBlock(text: recipient.address) }
                        Text(satsText(recipient.amount))
                        Button(recipient.person?.isSavedRecipient == true ? "Rename recipient" : "Save recipient") {
                            editing = recipient
                        }
                        .accessibilityIdentifier("savePaymentRecipient-\(recipient.id)")
                        .disabled(model.peopleStorageNotice != nil)
                        if let person = recipient.person, person.isSavedRecipient {
                            Button("Remove from saved recipients", role: .destructive) {
                                Task {
                                    do { try await model.updateRecipient(id: person.id, saved: false) }
                                    catch { self.error = error.localizedDescription }
                                }
                            }
                            .accessibilityIdentifier("removePaymentRecipient-\(recipient.id)")
                        }
                    }
                }
                let labeledOutputs = model.labeledReceiveOutputs(entry)
                if !labeledOutputs.isEmpty {
                    Section("Receive address labels") {
                        ForEach(labeledOutputs) { output in
                            VStack(alignment: .leading, spacing: 8) {
                                Text(output.label).font(.headline)
                                technical("Address") { CopyableTextBlock(text: output.address) }
                                Text(satsText(output.amount))
                                Button("Edit address label") { editingReceiveLabel = output }
                                    .accessibilityIdentifier("editPaymentReceiveLabel-\(output.id)")
                            }
                        }
                        Text("These are your local notes about the addresses paid. They do not verify who sent the payment.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if let notice = model.receiveLabelStorageNotice {
                    Text(notice).foregroundStyle(.orange)
                }
                if entry.received > 0 { senderSection(entry) }
                if entry.rawTransaction == nil, entry.spent > 0 {
                    Section {
                        if loading || model.status.syncing { BusyIndicator(text: "Loading payment details…") }
                        else { Button("Load payment details") { Task { await load() } } }
                    }
                }
                if let error { Text(error).foregroundStyle(.red).accessibilityIdentifier("paymentDetailsError") }
                if model.advancedMode {
                    Section("Transaction") {
                        CopyableIdentifier(value: txid.displayHex, accessibilityID: "copyTransactionIDButton")
                        WarnedExplorerLink(title: "View transaction", url: model.esploraTransactionURL(txid),
                                           exposedItem: "transaction ID", accessibilityID: "explorerTransactionButton")
                        if model.status.feeBumpableTxids.contains(txid) {
                            Button("Bump fee") { showFeeBump = true }.accessibilityIdentifier("bumpFeeButton")
                        }
                    }
                } else {
                    Section {
                        technical("Transaction ID") {
                            CopyableIdentifier(value: txid.displayHex, accessibilityID: "copyTransactionIDButton")
                        }
                    }
                }
            } else { Text("This payment is no longer in the wallet’s history.") }
        }
        .navigationTitle("Payment")
        .sheet(item: $editingReceiveLabel) { output in
            NavigationStack {
                ScrollView {
                    ReceiveAddressLabelEditor(address: output.address) { editingReceiveLabel = nil }
                        .padding()
                }
                .navigationTitle("Address label")
                .navigationBarTitleDisplayMode(.inline)
            }
        }
        .sheet(item: $editing) { AddPersonView(person: $0.person, address: $0.address) }
        .sheet(item: $attachingDestination) { person in
            AddPersonView(person: person, txid: txid,
                          senderCandidates: entry.map { model.senderCandidates(for: $0) } ?? [])
        }
        .sheet(isPresented: $labelingSender) {
            AddPersonView(txid: txid,
                          senderCandidates: entry.map { model.senderCandidates(for: $0) } ?? [])
        }
        .sheet(isPresented: $showFeeBump) { FeeBumpView(txid: txid) }
        .task(id: model.status.syncing) {
            if !model.status.syncing { await load() }
        }
    }

    /// A raw address or id: in full for Advanced mode, folded behind a
    /// title for a beginner, who can still open and copy it.
    @ViewBuilder
    private func technical<Content: View>(_ title: String, @ViewBuilder content: @escaping () -> Content) -> some View {
        if model.advancedMode {
            content()
        } else {
            DisclosureGroup(title) { content() }
        }
    }

    /// Who the payment came from: a saved label and the way to change it, or
    /// the way to make one. The candidates themselves — and the warned
    /// explorer lookup for the inputs that reveal nothing — live in the
    /// sheet, so this section stays two rows deep.
    private func senderSection(_ entry: HistoryEntry) -> some View {
        Section("Sender") {
            if let sender = model.receivedSender(entry) {
                Text(sender.name).font(.headline)
                    .accessibilityIdentifier("senderName")
                if sender.payTo != nil {
                    Button("Send to \(sender.name)") { sendToPerson(sender.id) }
                        .accessibilityIdentifier("sendToSenderButton")
                } else {
                    Text("This label has no payment destination.")
                    Button("Add destination for \(sender.name)") { attachingDestination = sender }
                        .accessibilityIdentifier("attachSenderDestinationButton")
                        .disabled(model.peopleStorageNotice != nil)
                }
                Button("Change sender") { labelingSender = true }
                    .accessibilityIdentifier("changeSenderButton")
                    .disabled(model.peopleStorageNotice != nil)
                Button("Remove sender label", role: .destructive) {
                    Task { await model.removeReceivedSenderLabel(txid: entry.txid) }
                }
                .accessibilityIdentifier("removeSenderLabelButton")
            } else {
                Button("Save sender as person") { labelingSender = true }
                    .accessibilityIdentifier("saveSenderButton")
                    .disabled(model.peopleStorageNotice != nil)
            }
        }
    }

    private func load() async {
        guard let entry, entry.spent > 0, entry.rawTransaction == nil, !loading else { return }
        loading = true
        error = nil
        defer { loading = false }
        do { try await model.loadPaymentDetails(entry) }
        catch is CancellationError { }
        catch { self.error = error.localizedDescription }
    }
}

/// Explicit same-input RBF flow. The suggested rate is one sat/vB above the
/// current effective rate; WalletCore may raise the actual result further to
/// satisfy BIP125's incremental-relay-fee rule.
private struct FeeBumpView: View {
    private struct ReviewedFeeBump {
        let request: FeeBumpReviewInputs
        let preview: FeeBumpPreview
    }

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    let txid: Data
    @State private var currentRate: Double?
    @State private var targetRateText = ""
    @State private var reviewedFeeBump: ReviewedFeeBump?
    @State private var error: String?
    @State private var bumping = false
    @State private var replacementTxid: Data?

    private var targetRate: Double? {
        Double(targetRateText.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private var reviewInputs: FeeBumpReviewInputs {
        FeeBumpReviewInputs(txid: txid, targetRateText: targetRateText)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Transaction") {
                    CopyableIdentifier(value: txid.displayHex,
                                       accessibilityID: "copyOriginalTransactionIDButton")
                    LabeledContent("Current rate", value: currentRate.map(feeRateText) ?? "—")
                }

                if replacementTxid == nil {
                    Section {
                        TextField("Higher rate (sat/vB)", text: $targetRateText)
                            .keyboardType(.decimalPad)
                            .accessibilityIdentifier("bumpFeeRateField")
                        Button("Review replacement") { review() }
                            .accessibilityIdentifier("reviewFeeBumpButton")
                            .disabled(targetRate == nil)
                    } header: {
                        Text("Replacement fee")
                    } footer: {
                        Text("The recipient and inputs stay the same. The extra fee comes from change; Winnow enforces a higher absolute fee, a higher feerate, and the incremental relay fee.")
                    }
                }

                if let reviewedFeeBump, replacementTxid == nil {
                    let preview = reviewedFeeBump.preview
                    Section("Review") {
                        LabeledContent("Actual rate", value: feeRateText(preview.feeRateSatPerVByte))
                        LabeledContent("Replacement fee", value: satsText(preview.fee))
                        if let change = preview.changeAmount {
                            LabeledContent("Change back", value: satsText(change))
                        } else {
                            LabeledContent("Change back", value: "none (remainder becomes fee)")
                        }
                        Button(bumping ? "Signing & broadcasting…" : "Sign & replace") { bump() }
                            .accessibilityIdentifier("confirmFeeBumpButton")
                            .disabled(bumping)
                    }
                }

                if let replacementTxid {
                    Section("Replacement broadcast") {
                        Label("Original marked replaced", systemImage: "arrow.triangle.2.circlepath")
                            .foregroundStyle(.green)
                        CopyableIdentifier(value: replacementTxid.displayHex,
                                           accessibilityID: "copyReplacementTransactionIDButton")
                        Button("Done") { dismiss() }
                    }
                }

                if let error {
                    Section {
                        Text(error)
                            .font(.footnote)
                            .foregroundStyle(.red)
                            .accessibilityIdentifier("feeBumpError")
                    }
                }
            }
            .navigationTitle("Bump fee")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
            .onChange(of: reviewInputs) { _, _ in
                reviewedFeeBump = nil
                error = nil
            }
            .task { await load() }
        }
    }

    private func load() async {
        do {
            let rate = try await model.pendingFeeRate(txid: txid)
            currentRate = rate
            // One sat/vB above the current rate, and never below the floor
            // peers report: a bump under the floor is refused at review, so
            // the suggestion starts where a review can pass.
            let floor = model.status.feeFloorSatPerVByte.map { ceil($0) } ?? 0
            let suggestedRate = max(ceil(rate + 1), floor)
            targetRateText = String(format: "%.0f", suggestedRate)
            let requested = reviewInputs
            guard let targetRate = requested.targetRate else { return }
            let candidate = try await model.previewFeeBump(
                txid: requested.txid, feeRateSatPerVByte: targetRate)
            guard requested == reviewInputs else { return }
            reviewedFeeBump = ReviewedFeeBump(request: requested, preview: candidate)
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func review() {
        let requested = reviewInputs
        guard let targetRate = requested.targetRate else { return }
        error = nil
        reviewedFeeBump = nil
        Task {
            do {
                let candidate = try await model.previewFeeBump(
                    txid: requested.txid, feeRateSatPerVByte: targetRate)
                guard requested == reviewInputs else { return }
                reviewedFeeBump = ReviewedFeeBump(request: requested, preview: candidate)
            } catch {
                guard requested == reviewInputs else { return }
                self.error = error.localizedDescription
            }
        }
    }

    private func bump() {
        guard let reviewedFeeBump else { return }
        bumping = true
        error = nil
        Task {
            do {
                replacementTxid = try await model.bumpFee(preview: reviewedFeeBump.preview)
            } catch {
                self.error = error.localizedDescription
            }
            bumping = false
        }
    }
}
