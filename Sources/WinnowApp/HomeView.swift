import BitcoinP2P
import Foundation
import SwiftUI
import WalletCore

/// Immutable identity of the fields that produced a fee-bump preview. A late
/// async result is accepted only while this request still matches the form.
struct FeeBumpReviewInputs: Equatable {
    let txid: Data
    let targetRateText: String

    var targetRate: Double? {
        Double(targetRateText.trimmingCharacters(in: .whitespacesAndNewlines))
    }
}

/// Balance (confirmed sats), sync status, and the local transaction history.
/// History speaks in confirmed blocks only — a pending send we broadcast is
/// labeled "awaiting confirmation", never "incoming" (docs/read-side.md §3.3).
struct HomeView: View {
    @Environment(AppModel.self) private var model
    @State private var showReceive = false

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
                            ProgressView(statusText)
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
                    if model.status.syncing, model.syncStatusText == nil {
                        ProgressView("Scanning filters…")
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
                        HistoryRow(entry: entry,
                                   canBump: model.status.feeBumpableTxids.contains(entry.txid))
                    }
                }
            }
            .navigationTitle("Winnow")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("Receive") { showReceive = true }
                        .accessibilityIdentifier("receiveButton")
                }
            }
            .sheet(isPresented: $showReceive) {
                ReceiveView()
            }
            .refreshable {
                await model.syncNow()
            }
        }
    }
}

private struct HistoryRow: View {
    @Environment(AppModel.self) private var model
    let entry: HistoryEntry
    let canBump: Bool
    @State private var showFeeBump = false

    /// Net effect on the wallet: received (incl. our own change) minus spent.
    private var net: Int64 { entry.received - entry.spent }

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(net >= 0 ? "Received" : "Sent")
                    .font(.headline)
                CopyableIdentifier(value: entry.txid.displayHex, abbreviated: true,
                                   accessibilityID: "copyTransactionIDButton")
                WarnedExplorerLink(
                    title: "View transaction",
                    url: model.esploraTransactionURL(entry.txid),
                    exposedItem: "transaction ID",
                    accessibilityID: "explorerTransactionButton")
                    .font(.caption)
                if canBump {
                    Button("Bump fee") { showFeeBump = true }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .accessibilityIdentifier("bumpFeeButton")
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text("\(net >= 0 ? "+" : "−")\(abs(net).formatted()) sats")
                    .foregroundStyle(net >= 0 ? .green : .primary)
                if let replacement = entry.replacedBy {
                    Text("replaced by \(replacement.displayHex.prefix(8))…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("transactionReplaced")
                } else if entry.height > 0 {
                    Text("block \(entry.height)")
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
        }
        .sheet(isPresented: $showFeeBump) {
            FeeBumpView(txid: entry.txid)
        }
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
            let suggestedRate = ceil(rate + 1)
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
