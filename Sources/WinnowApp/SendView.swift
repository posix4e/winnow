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
    /// How the signed transaction leaves the phone (issue #51). Part of the
    /// identity so a route change after review clears the preview.
    var route: SubmissionRoute = .peers

    var trimmedDestination: String {
        destination.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var amount: Int64? { Int64(amountText) }
}

/// Send to any standard address: fee
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
    /// Advanced mode only; beginner mode never shows it and always sends
    /// through peers.
    @State private var route: SubmissionRoute = .peers
    /// The route the sent transaction actually took, kept so the status
    /// section knows whether a peer relay is even expected.
    @State private var sentRoute: SubmissionRoute = .peers
    @State private var showRelayConfirm = false
    @State private var resolvedRate: Double?
    @State private var preview: AppModel.SendPreview?
    @State private var error: String?
    @State private var sending = false
    @State private var sentTxid: Data?
    /// Hex of the signed transaction, while it is still pending.
    @State private var rawTransaction: String?
    @State private var relayLog: [String] = []
    @State private var relayedPeers: Set<String> = []
    @State private var feeFloorNotice = false
    @State private var confirmedHeight: UInt32?
    @FocusState private var amountFocused: Bool

    private var override: Double? {
        Double(overrideText.trimmingCharacters(in: .whitespaces))
    }

    private var reviewInputs: SendReviewInputs {
        SendReviewInputs(destination: destination, amountText: amountText,
                         priority: priority, overrideText: overrideText,
                         network: model.network,
                         route: model.advancedMode ? route : .peers)
    }

    private var routeFooter: String {
        switch route {
        case .peers:
            "Relayed to Winnow's own Bitcoin peers. The default, and the only route beginner mode uses."
        case .export:
            "Signed but not submitted. Winnow reserves the coins and hands you the raw transaction; you can relay it to Bitcoin peers later from its receipt."
        case .minerOnly, .minerAndPeers:
            "Submitted to the selected miner."
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Destination") {
                    TextField("Bitcoin address", text: $destination)
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

                // Above the review, not inside it: the review section exists
                // only while a preview does, and picking a route clears the
                // preview, so a picker inside it would vanish on the tap.
                if model.advancedMode, sentTxid == nil {
                    Section {
                        Picker("Route", selection: $route) {
                            Text("Bitcoin peers").tag(SubmissionRoute.peers)
                            Text("Export signed transaction").tag(SubmissionRoute.export)
                        }
                        .accessibilityIdentifier("submissionRoutePicker")
                    } header: {
                        Text("Submission")
                    } footer: {
                        Text(routeFooter)
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
                        LabeledContent("Pays", value: abbreviated(preview.destination))
                        LabeledContent("Amount",
                                       value: satsText(preview.payments.map(\.amount).reduce(0, +)))
                        LabeledContent("Fee", value: satsText(preview.fee))
                        LabeledContent("Rate", value: feeRateText(preview.feeRateSatPerVByte))
                        LabeledContent("Inputs", value: "\(preview.inputCount)")
                        if let change = preview.changeAmount {
                            LabeledContent("Change back", value: satsText(change))
                        }
                        if model.advancedMode {
                            LabeledContent("Route", value: preview.route.label)
                                .accessibilityIdentifier("reviewRoute")
                        }
                        // Warn, never block. A small consolidating or test
                        // payment is legitimate and the user may mean it;
                        // refusing outright would be worse than the current
                        // silence (#140).
                        if let proportion = preview.feeProportion {
                            Label(proportion.message(sats: satsText),
                                  systemImage: "exclamationmark.triangle")
                                .font(.footnote)
                                .foregroundStyle(.orange)
                                .accessibilityIdentifier("feeProportionWarning")
                        }
                        // #151: sending mid-sync stamps a locktime below the
                        // real tip, a gap Core-built transactions essentially
                        // never show. The send is allowed; the disclosure is
                        // made here so it is at least informed.
                        if preview.locktimeLagsTip {
                            Label("Header sync is still catching up, so this transaction will "
                                  + "carry a locktime behind the network tip — on-chain, that "
                                  + "reveals it was signed mid-sync. Waiting for sync avoids it.",
                                  systemImage: "clock.arrow.circlepath")
                                .font(.footnote)
                                .foregroundStyle(.orange)
                                .accessibilityIdentifier("locktimeLagWarning")
                        }
                        Button(sendButtonTitle(for: preview.route)) { send() }
                            .accessibilityIdentifier("sendButton")
                            .disabled(sending)
                    }
                }

                if let sentTxid {
                    Section(sentRoute.touchesPeers ? "Broadcast" : "Signed transaction") {
                        CopyableIdentifier(value: sentTxid.displayHex,
                                           accessibilityID: "copyBroadcastTransactionIDButton")
                        if model.advancedMode, let receipt = model.status.receipt(for: sentTxid) {
                            LabeledContent("Route", value: receipt.route.label)
                                .accessibilityIdentifier("sentRoute")
                            LabeledContent("State", value: receipt.state.rawValue)
                                .accessibilityIdentifier("sentState")
                        }
                        if !sentRoute.submits {
                            Text("Not submitted. Copy the raw transaction below and hand it to another system, or relay it to Bitcoin peers from here. The coins are reserved either way.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .accessibilityIdentifier("exportNotice")
                            Button("Relay to Bitcoin peers") { showRelayConfirm = true }
                                .accessibilityIdentifier("relayToPeersButton")
                        }
                        // When relay is not working, or the route never
                        // relayed at all, the signed bytes are the only way
                        // out of the device. Withdrawn once a block has it:
                        // at that point the transaction is public and the
                        // txid is the handle, so offering the bytes only
                        // invites confusion. The receipt's re-route (#51) is
                        // the recorded alternative to pasting them by hand.
                        if let rawTransaction, confirmedHeight == nil {
                            CopyableIdentifier(value: rawTransaction, abbreviated: true,
                                               label: "Copy raw",
                                               accessibilityID: "copyRawTransactionButton")
                        }
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
            .task(id: "\(sentTxid?.displayHex ?? "")|\(sentRoute.label)") {
                await watchBroadcastEvents()
            }
            .alert("Relay to Bitcoin peers?", isPresented: $showRelayConfirm) {
                Button("Relay") { relayToPeers() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This makes the transaction public to Bitcoin peers now, and the change is recorded in its receipt.")
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

    private func sendButtonTitle(for route: SubmissionRoute) -> String {
        if sending { return route.submits ? "Signing & broadcasting…" : "Signing…" }
        return route.submits ? "Sign & broadcast" : "Sign & export"
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
                    override: Double(requested.overrideText.trimmingCharacters(in: .whitespaces)),
                    route: requested.route)
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
                let txid = try await model.send(preview: preview)
                sentRoute = preview.route
                sentTxid = txid
                rawTransaction = await model.rawTransactionHex(txid)
            } catch {
                self.error = error.localizedDescription
            }
            sending = false
        }
    }

    /// The export route's recorded second thought: the approval is written
    /// to the receipt before a single peer hears about the transaction.
    private func relayToPeers() {
        guard let sentTxid else { return }
        Task {
            do {
                let receipt = try await model.reroute(sentTxid, to: .peers)
                sentRoute = receipt.route
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    private func reset() {
        destination = ""
        amountText = ""
        preview = nil
        sentTxid = nil
        sentRoute = .peers
        rawTransaction = nil
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
        // Silence is not failure on a route that never announces: there is
        // no echo to wait for and no fee floor to compare against.
        guard sentRoute.touchesPeers else { return }
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
