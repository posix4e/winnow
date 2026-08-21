import BitcoinP2P
import SwiftUI
import UIKit
import WalletCore

/// Immutable identity of the fields that produced a send preview. Equality is
/// the authorization boundary for async preview results: a result created for
/// older text or a different network must never re-enable the signing button.
struct SendReviewInputs: Equatable {
    let destination: String
    let amountText: String
    let priority: FeePolicy.Priority
    let overrideText: String
    let network: BitcoinNetwork

    var trimmedDestination: String {
        destination.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var amount: Int64? { Int64(amountText) }
}

/// Send to any standard address or an sp1…/tsp1… silent payment code: fee
/// selection (FeePolicy presets + the peers' feefilter floor + override), a
/// review step, then sign + broadcast via TxBroadcaster. Relay status comes
/// from the broadcaster's events; confirmation arrives as a filter match
/// ("seen in block N").
struct SendView: View {
    @Environment(AppModel.self) private var model

    @State private var destination = ""
    @State private var amountText = ""
    @State private var priority: FeePolicy.Priority = .medium
    @State private var overrideText = ""
    @State private var resolvedRate: Double?
    @State private var preview: AppModel.SendPreview?
    @State private var error: String?
    @State private var sending = false
    @State private var sentTxid: Data?
    @State private var relayLog: [String] = []
    @State private var relayedPeers: Set<String> = []
    @State private var feeFloorNotice = false
    @State private var confirmedHeight: UInt32?
    @FocusState private var amountFocused: Bool

    private var override: Double? {
        Double(overrideText.trimmingCharacters(in: .whitespaces))
    }

    private var destinationIsSilentPayment: Bool {
        let trimmed = destination.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return trimmed.hasPrefix("sp1") || trimmed.hasPrefix("tsp1")
    }

    private var reviewInputs: SendReviewInputs {
        SendReviewInputs(destination: destination, amountText: amountText,
                         priority: priority, overrideText: overrideText,
                         network: model.network)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Destination") {
                    TextField("Address or sp1… silent payment code", text: $destination)
                        .font(.system(.footnote, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .accessibilityIdentifier("destinationField")
                    Button("Paste") {
                        destination = UIPasteboard.general.string ?? ""
                    }
                    .accessibilityIdentifier("pasteDestinationButton")
                    TextField("Amount (sats)", text: $amountText)
                        .keyboardType(.numberPad)
                        .focused($amountFocused)
                        .accessibilityIdentifier("amountField")
                        .toolbar {
                            ToolbarItemGroup(placement: .keyboard) {
                                Spacer()
                                Button("Done") { amountFocused = false }
                            }
                        }
                }

                if destinationIsSilentPayment {
                    Section {
                        Label("Silent payments are experimental", systemImage: "flask")
                            .foregroundStyle(.orange)
                        Text("Sending does not use a tweak-data service, but receiving support and interoperability are still developing. Confirm that the recipient actively supports BIP352.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }

                Section {
                    Picker("Priority", selection: $priority) {
                        Text("Low").tag(FeePolicy.Priority.low)
                        Text("Medium").tag(FeePolicy.Priority.medium)
                        Text("High").tag(FeePolicy.Priority.high)
                    }
                    LabeledContent("Resolved rate", value: resolvedRate.map(feeRateText) ?? "—")
                    LabeledContent("Network floor", value: model.status.feeFloorSatPerVByte.map(feeRateText) ?? "unknown")
                    TextField("Override (sat/vB, optional)", text: $overrideText)
                        .keyboardType(.decimalPad)
                } header: {
                    Text("Fee")
                } footer: {
                    Text("A filter-only wallet cannot see the fee market: the rate is the override, then your own confirmed transactions' median, then a conservative preset — never below the peers' relay floor.")
                }

                if let error {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.footnote)
                            .accessibilityIdentifier("sendError")
                    }
                }

                if sentTxid == nil {
                    Section {
                        Button("Review payment") { review() }
                            .accessibilityIdentifier("reviewButton")
                            .disabled(destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                      || Int64(amountText) == nil)
                    }
                }

                if let preview, sentTxid == nil {
                    Section("Review") {
                        LabeledContent("Pays", value: !preview.silentPayments.isEmpty
                                       ? "silent payment (derived P2TR output)"
                                       : abbreviated(preview.destination))
                        LabeledContent("Amount", value: satsText(preview.payments.map(\.amount).reduce(0, +)
                                                                   + preview.silentPayments.map(\.amount).reduce(0, +)))
                        LabeledContent("Fee", value: satsText(preview.fee))
                        LabeledContent("Rate", value: feeRateText(preview.feeRateSatPerVByte))
                        LabeledContent("Inputs", value: "\(preview.inputCount)")
                        if let change = preview.changeAmount {
                            LabeledContent("Change back", value: satsText(change))
                        }
                        Button(sending ? "Signing & broadcasting…" : "Sign & broadcast") { send() }
                            .accessibilityIdentifier("sendButton")
                            .disabled(sending)
                    }
                }

                if let sentTxid {
                    Section("Broadcast") {
                        Text(sentTxid.displayHex)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                        WarnedExplorerLink(
                            title: "View transaction",
                            url: model.esploraTransactionURL(sentTxid),
                            exposedItem: "transaction ID",
                            accessibilityID: "explorerBroadcastButton")
                        if !relayedPeers.isEmpty {
                            Text("Relayed to \(relayedPeers.count) peer(s)")
                                .font(.footnote)
                                .accessibilityIdentifier("relayedCount")
                        }
                        if feeFloorNotice {
                            Label("The network relay floor is now above this fee — it may not propagate; consider a higher fee.",
                                  systemImage: "exclamationmark.triangle")
                                .font(.footnote)
                                .foregroundStyle(.orange)
                                .accessibilityIdentifier("feeFloorNotice")
                        }
                        ForEach(Array(relayLog.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.footnote)
                        }
                        if let confirmedHeight {
                            Label("Seen in block \(confirmedHeight)", systemImage: "checkmark.seal")
                                .foregroundStyle(.green)
                                .accessibilityIdentifier("broadcastConfirmed")
                        } else {
                            Text("Awaiting confirmation — a filter match will report the block here.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .accessibilityIdentifier("broadcastPending")
                        }
                        Button("New payment") { reset() }
                    }
                }
            }
            .navigationTitle("Send")
            .task(id: feeInputs) {
                resolvedRate = await model.resolvedFeeRate(priority: priority, override: override)
            }
            .task(id: sentTxid) {
                await watchBroadcastEvents()
            }
            .onChange(of: reviewInputs) { _, _ in
                // Any edit invalidates the authorization review immediately.
                // The async request guard in review() also prevents an older
                // request from restoring it after this change.
                preview = nil
            }
            .onChange(of: model.status.history) { _, history in
                guard let sentTxid, confirmedHeight == nil,
                      let entry = history.first(where: { $0.txid == sentTxid }), entry.height > 0
                else { return }
                confirmedHeight = entry.height
            }
        }
    }

    /// Recomputes the resolved rate when priority/override/floor change.
    private var feeInputs: String {
        "\(priority.rawValue)|\(overrideText)|\(model.status.feeFloorSatPerVByte ?? -1)"
    }

    private func abbreviated(_ destination: String) -> String {
        guard destination.count > 32 else { return destination }
        return "\(destination.prefix(16))…\(destination.suffix(12))"
    }

    private func review() {
        error = nil
        preview = nil
        let requested = reviewInputs
        guard let amount = requested.amount, amount > 0 else {
            error = "Enter an amount in sats."
            return
        }
        Task {
            do {
                let candidate = try await model.previewSend(
                    destination: requested.destination, amount: amount,
                    priority: requested.priority,
                    override: Double(requested.overrideText.trimmingCharacters(in: .whitespaces)))
                guard requested == reviewInputs else { return }
                preview = candidate
            } catch {
                guard requested == reviewInputs else { return }
                self.error = error.localizedDescription
            }
        }
    }

    private func send() {
        // The button is disabled while `sending`, but that is presentation:
        // it does not survive a double tap delivered before the disabled
        // state renders. AppModel.exclusively is the real guarantee; this
        // check just keeps an accidental second tap from surfacing an error
        // banner instead of doing nothing.
        guard let preview, !sending else { return }
        sending = true
        error = nil
        Task {
            do {
                sentTxid = try await model.send(preview: preview)
            } catch {
                self.error = error.localizedDescription
            }
            sending = false
        }
    }

    private func reset() {
        destination = ""
        amountText = ""
        preview = nil
        sentTxid = nil
        relayLog = []
        relayedPeers = []
        feeFloorNotice = false
        confirmedHeight = nil
        error = nil
    }

    /// Follows the broadcast: TxBroadcaster events (announced → a peer asked
    /// for the tx) plus mempool-window echoes (§2.8 — a peer inv'ing our txid
    /// back proves the network has it), until the filter match confirms it.
    /// The window is bounded by this send-status view.
    private func watchBroadcastEvents() async {
        guard let sentTxid, let broadcaster = model.stack?.broadcaster else { return }
        let window = model.makeMempoolWindow(watchScripts: [])
        if let window {
            await window.watchEcho(of: sentTxid)
            await window.start()
        }
        let echoTask = window.map { window in
            Task {
                for await event in await window.events() {
                    guard case let .txidEchoed(txid, peer) = event, txid == sentTxid else { continue }
                    relayedPeers.insert(peer.description)
                }
            }
        }
        for await event in await broadcaster.events() {
            switch event {
            case let .announced(txid, peerCount) where txid == sentTxid:
                relayLog.append("Announced to \(peerCount) peer(s)")
            case let .requested(txid, peer) where txid == sentTxid:
                if relayedPeers.insert(peer.description).inserted {
                    relayLog.append("Relayed to \(peer)")
                }
            case let .feeFloorExceeded(txid, _) where txid == sentTxid:
                feeFloorNotice = true
            case let .confirmed(txid) where txid == sentTxid:
                // The history snapshot here can still hold the pending
                // (height 0) entry — the post-sync refresh lands the real
                // height, and the onChange below then fills it in.
                if let height = model.status.history.first(where: { $0.txid == txid })?.height,
                   height > 0 {
                    confirmedHeight = height
                }
                // Propagation tracking ends at confirmation.
                echoTask?.cancel()
                if let window { Task { await window.stop() } }
            default:
                break
            }
        }
        echoTask?.cancel()
        await window?.stop()
    }
}
