import BitcoinP2P
import SwiftUI
import UIKit
import WalletCore

/// Fresh BIP86 receive address with a QR. The address is peeked (not marked
/// used) until a payment to it confirms or the user asks for a new one.
///
/// While this screen is open, a bounded mempool window (docs/read-side.md
/// §2.8) subscribes to full transaction relay and matches locally against the
/// displayed address: payments show as "Unconfirmed" within seconds of the
/// sender broadcasting. The window closes when the screen disappears or the
/// app backgrounds — everything else arrives via filter match at confirmation.
struct ReceiveView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    /// One unconfirmed payment seen via the mempool window.
    struct UnconfirmedPayment: Identifiable, Equatable {
        let txid: Data
        let amount: Int64
        var id: Data { txid }
    }

    @State private var address: String?
    @State private var silentPaymentAddress: String?
    @State private var error: String?
    @State private var unconfirmed: [UnconfirmedPayment] = []
    @State private var window: MempoolWindow?
    @State private var windowTask: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if let address {
                    QRCodeView(content: address)
                        .frame(width: 240, height: 240)
                        .padding(.top)
                    Text(address)
                        .font(.system(.footnote, design: .monospaced))
                        .multilineTextAlignment(.center)
                        .textSelection(.enabled)
                        .padding(.horizontal)
                        .accessibilityIdentifier("receiveAddress")
                        .accessibilityValue(address)
                    HStack(spacing: 16) {
                        Button("Copy") { ClipboardPolicy.interchange.apply(address) }
                        ShareLink(item: address)
                        Button("New address") { newAddress() }
                    }
                    .buttonStyle(.bordered)
                    WarnedExplorerLink(
                        title: "View address",
                        url: model.esploraAddressURL(address),
                        exposedItem: "address",
                        accessibilityID: "explorerAddressButton")
                    ForEach(unconfirmed) { payment in
                        Label("Unconfirmed: +\(satsText(payment.amount)) — awaiting confirmation",
                              systemImage: "clock")
                            .font(.subheadline)
                            .foregroundStyle(.orange)
                            .padding(.horizontal)
                            .accessibilityIdentifier("unconfirmedPayment")
                    }
                    Text("While this screen is open, incoming payments appear as unconfirmed within seconds. Everything else appears once it confirms in a block.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                    if let silentPaymentAddress {
                        Divider().padding(.horizontal)
                        Text("Experimental · Silent payment address")
                            .font(.subheadline.weight(.semibold))
                        Text(silentPaymentAddress)
                            .font(.system(.footnote, design: .monospaced))
                            .multilineTextAlignment(.center)
                            .textSelection(.enabled)
                            .padding(.horizontal)
                            .accessibilityIdentifier("silentPaymentAddress")
                        HStack(spacing: 16) {
                            Button("Copy") { ClipboardPolicy.interchange.apply(silentPaymentAddress) }
                            ShareLink(item: silentPaymentAddress)
                        }
                        .buttonStyle(.bordered)
                        Text("Static and reusable, but receiving is experimental. Payments are only found while silent payments and its configured tweak-data service remain available.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                    }
                } else if let error {
                    ContentUnavailableView("No address", systemImage: "exclamationmark.triangle",
                                           description: Text(error))
                } else {
                    ProgressView()
                }
                Spacer()
            }
            .navigationTitle("Receive")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task {
                address = try? await model.currentReceiveAddress()
                if address == nil { error = "The wallet is not available." }
                if model.spReceiveEnabled {
                    silentPaymentAddress = try? await model.currentSilentPaymentAddress()
                }
                await openWindow()
            }
            .onDisappear { closeWindow() }
            .onChange(of: scenePhase) { _, phase in
                // The window is bounded by the screen AND the foreground
                // (sync-while-active); reopen when back active and still shown.
                switch phase {
                case .background: closeWindow()
                case .active: Task { await openWindow() }
                default: break
                }
            }
            .onChange(of: model.status.history) { _, history in
                // The mempool window owns only the temporary presentation.
                // Once normal filter sync records the same tx in a block,
                // remove its stale orange row immediately.
                unconfirmed.removeAll { payment in
                    history.contains { $0.txid == payment.txid && $0.height > 0 }
                }
            }
        }
    }

    private func newAddress() {
        Task {
            do {
                closeWindow()
                unconfirmed = []
                address = try await model.freshReceiveAddress()
                await openWindow()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    /// Opens the mempool window on the displayed address and starts consuming
    /// its events. No-op when already open or without an address.
    private func openWindow() async {
        guard window == nil, let address,
              let script = try? AddressDecoder.scriptPubKey(for: address, network: model.network),
              let window = model.makeMempoolWindow(watchScripts: [script])
        else { return }
        self.window = window
        await window.start()
        let events = await window.events()
        windowTask = Task {
            for await event in events {
                guard case let .paymentSeen(txid, amount, _) = event else { continue }
                if !unconfirmed.contains(where: { $0.txid == txid }) {
                    unconfirmed.append(UnconfirmedPayment(txid: txid, amount: amount))
                }
            }
        }
    }

    private func closeWindow() {
        windowTask?.cancel()
        windowTask = nil
        guard let window else { return }
        self.window = nil
        Task { await window.stop() }
    }
}
