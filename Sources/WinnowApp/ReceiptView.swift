import BitcoinP2P
import SwiftUI
import WalletCore

/// One transaction's submission receipt (issue #51): the route it took, what
/// happened on it, and the actions that still apply. The receipt is the
/// coordinator's; this view only reads the snapshot and asks for changes.
struct ReceiptView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    let txid: Data
    @State private var showRelayConfirm = false
    @State private var showAbandonConfirm = false
    @State private var error: String?

    private var receipt: SubmissionReceipt? { model.status.receipt(for: txid) }

    var body: some View {
        NavigationStack {
            Form {
                if let receipt {
                    Section("Submission") {
                        CopyableIdentifier(value: receipt.txid.displayHex, abbreviated: true,
                                           accessibilityID: "copyReceiptTransactionIDButton")
                        LabeledContent("Route", value: receipt.route.label)
                            .accessibilityIdentifier("receiptRoute")
                        LabeledContent("State", value: receipt.state.rawValue)
                            .accessibilityIdentifier("receiptState")
                        if let height = receipt.confirmedAtHeight {
                            Label("Seen in block \(height)", systemImage: "checkmark.seal")
                                .foregroundStyle(.green)
                        }
                        if let rejection = receipt.rejection {
                            Label(rejection.policy
                                  ? "Declined for policy reasons: \(rejection.reason)"
                                  : "Rejected: \(rejection.reason)",
                                  systemImage: "xmark.octagon")
                                .font(.footnote)
                                .foregroundStyle(.red)
                        }
                        if let status = receipt.providerStatus {
                            providerStatusRow(status)
                        }
                        if receipt.isDeliveryUnconfirmed {
                            Label("Delivery unconfirmed after \(receipt.submitAttempt) attempts. The transaction is held and can be routed again.",
                                  systemImage: "exclamationmark.triangle")
                                .font(.footnote)
                                .foregroundStyle(.orange)
                        }
                        if let lastError = receipt.lastError {
                            Text(lastError).font(.footnote).foregroundStyle(.orange)
                        }
                    }

                    Section("Timeline") {
                        ForEach(Array(receipt.timeline.enumerated()), id: \.offset) { _, entry in
                            LabeledContent(entry.state.rawValue,
                                           value: entry.at.formatted(date: .abbreviated, time: .shortened))
                        }
                    }

                    if !receipt.routeHistory.isEmpty {
                        Section("Route changes") {
                            ForEach(Array(receipt.routeHistory.enumerated()), id: \.offset) { _, approval in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("\(approval.from.label) → \(approval.to.label)")
                                    Text(approval.approvedAt.formatted(date: .abbreviated, time: .shortened))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }

                    Section("Actions") {
                        if receipt.canReroute, receipt.route != .peers {
                            Button("Relay to Bitcoin peers") { showRelayConfirm = true }
                                .accessibilityIdentifier("receiptRelayToPeersButton")
                        }
                        // Withdrawn once the transaction is confirmed, replaced
                        // or abandoned (#155): offering the bytes then only
                        // invites a conflicting rebroadcast.
                        if !receipt.state.isTerminal {
                            CopyableIdentifier(value: receipt.rawTransaction.hex, abbreviated: true,
                                               label: "Copy raw",
                                               accessibilityID: "copyReceiptRawTransactionButton")
                        }
                        if !receipt.state.isTerminal {
                            Button("Stop tracking", role: .destructive) { showAbandonConfirm = true }
                                .accessibilityIdentifier("abandonSubmissionButton")
                        }
                    }
                } else {
                    Section {
                        Text("Winnow has no submission receipt for this transaction. Transactions sent before receipts existed, or received from others, have none.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }

                if let error {
                    Section {
                        Text(error).font(.footnote).foregroundStyle(.red)
                            .accessibilityIdentifier("receiptError")
                    }
                }
            }
            .navigationTitle("Receipt")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
            .alert("Relay to Bitcoin peers?", isPresented: $showRelayConfirm) {
                Button("Relay") { reroute(to: .peers) }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This makes the transaction public to Bitcoin peers now, and the change is recorded in its receipt.")
            }
            .alert("Stop tracking this transaction?", isPresented: $showAbandonConfirm) {
                Button("Stop tracking", role: .destructive) { abandon() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Winnow stops relaying and polling for it. The coins stay reserved: the signed transaction still exists and may be mined by anyone who has it.")
            }
        }
    }

    @ViewBuilder
    private func providerStatusRow(_ status: ProviderStatusSnapshot) -> some View {
        switch status.kind {
        case .confirmed:
            Label("The miner reports it confirmed\(status.reportedHeight.map { " in block \($0)" } ?? ""), awaiting Winnow's own verification.",
                  systemImage: "clock.badge.checkmark")
                .font(.footnote)
        case .pending:
            VStack(alignment: .leading, spacing: 2) {
                if let position = status.position {
                    Text("Miner mempool position: block \(position)").font(.footnote)
                }
                if let odds = status.inclusionOdds {
                    Text("Inclusion odds reported: \(odds)%").font(.footnote)
                }
                if let message = status.message {
                    Text(message).font(.footnote).foregroundStyle(.secondary)
                }
            }
        case .rejected:
            Text("The miner reports: \(status.message ?? "rejected")").font(.footnote).foregroundStyle(.red)
        case .notFound:
            Text("The miner does not report this transaction.").font(.footnote).foregroundStyle(.secondary)
        }
    }

    private func reroute(to route: SubmissionRoute) {
        Task {
            do { _ = try await model.reroute(txid, to: route) } catch { self.error = error.localizedDescription }
        }
    }

    private func abandon() {
        Task {
            do { try await model.abandonSubmission(txid) } catch { self.error = error.localizedDescription }
        }
    }
}

/// Every receipt, newest first. Advanced mode's Settings entry.
struct SubmissionsListView: View {
    private struct Selection: Identifiable {
        let txid: Data
        var id: Data { txid }
    }

    @Environment(AppModel.self) private var model
    @State private var selected: Selection?

    var body: some View {
        List {
            if model.status.receipts.isEmpty {
                Text("No submissions yet. Every transaction Winnow signs from now on gets a receipt here.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            ForEach(model.status.receipts) { receipt in
                Button {
                    selected = Selection(txid: receipt.txid)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(receipt.txid.displayHex.prefix(16) + "…")
                            .font(.system(.footnote, design: .monospaced))
                        Text("\(receipt.route.label) · \(receipt.state.rawValue) · \(receipt.createdAt.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .navigationTitle("Submissions")
        .sheet(item: $selected) { selection in
            ReceiptView(txid: selection.txid)
        }
    }
}
