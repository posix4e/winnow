import VaultKit
import WalletCore
import SwiftUI

/// The whole of beginner mode: one screen, no settings. Balance and whether
/// the wallet is up to date, Receive and Send, what happened, shared savings
/// once there are any, and the backup. Everything technical — fees, peers,
/// block heights, signing tools, every setting — is Advanced mode, which is
/// the three-tab interface behind the toolbar button. Settings made there
/// stay in effect here; they are just not shown.
struct BeginnerHomeView: View {
    @Environment(AppModel.self) private var model
    @State private var showReceive = false
    @State private var showSend = false
    @State private var sendAccountID: String?
    @State private var sendPersonID: String?
    @State private var showSavingsChooser = false
    @State private var confirmAdvanced = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Balance")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        Text(satsText(model.status.balance))
                            .font(.system(.largeTitle, design: .rounded).bold())
                            .accessibilityIdentifier("balanceText")
                            .accessibilityValue(satsText(model.status.balance))
                        HStack(spacing: 8) {
                            status
                            if model.network != .mainnet {
                                Text("Signet · test coins")
                                    .font(.caption)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 2)
                                    .background(Capsule().fill(.quaternary))
                                    .accessibilityIdentifier("networkTag")
                            }
                        }
                        .font(.footnote)
                    }
                    .padding(.vertical, 4)
                    if model.network == .mainnet {
                        PeerRoutingBanner()
                    }
                    if case .peersUnavailable = model.syncSummary {
                        Button("Retry") {
                            Task { await model.retryPeerDiscovery() }
                        }
                        .accessibilityIdentifier("retryPeersButton")
                    }
                    if let error = model.simpleSyncError {
                        Text(error)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }

                Section {
                    HStack(spacing: 12) {
                        Button { showReceive = true } label: {
                            Text("Receive").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .accessibilityIdentifier("receiveButton")
                        Button { showSend = true } label: {
                            Text("Send").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .accessibilityIdentifier("openSendButton")
                    }
                    .controlSize(.large)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                }

                Section("Activity") {
                    if model.status.history.isEmpty {
                        Text("Nothing yet. Payments appear here once they are confirmed.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(Array(model.status.history.enumerated()), id: \.offset) { _, entry in
                        NavigationLink(value: entry.txid) { HistoryRow(entry: entry) }
                            .accessibilityIdentifier("historyPayment-\(entry.txid.displayHex)")
                    }
                }

                Section {
                    ForEach(model.vaults) { record in
                        if let vault = try? model.vault(for: record) {
                            NavigationLink {
                                AccountDetailView(recordID: record.id) { sendFrom(record.id) }
                            } label: {
                                HStack(alignment: .firstTextBaseline) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(record.name)
                                        Text(rule(of: vault))
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Text(satsText(record.balance))
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .accessibilityIdentifier("walletSavings-\(record.name)")
                        }
                    }
                    Button("Save with someone…") { showSavingsChooser = true }
                        .accessibilityIdentifier("saveWithSomeoneButton")
                } header: {
                    if !model.vaults.isEmpty { Text("Shared savings") }
                }

                Section("Backup") {
                    Label(model.cloudBackups.statusTitle, systemImage: model.cloudBackups.statusTitle == "Backed up" ? "checkmark.icloud" : "icloud")
                        .accessibilityIdentifier("cloudBackupStatus")
                    if let saved = model.cloudBackups.lastSaved {
                        Text("Last saved \(saved.formatted())").font(.caption).foregroundStyle(.secondary)
                    }
                    if let message = model.cloudBackups.message {
                        Text(message).font(.footnote).foregroundStyle(.secondary)
                    }
                    if model.cloudBackups.statusTitle == "Not backed up" {
                        Text("Your wallet still works. Keep a manual backup until iCloud is available.")
                            .font(.footnote).foregroundStyle(.secondary)
                        NavigationLink("Save a manual backup") { WalletBackupView() }
                            .accessibilityIdentifier("backupButton")
                    }
                }
            }
            .navigationTitle("Winnow")
            .navigationDestination(for: Data.self) { PaymentDetailView(txid: $0, sendToPerson: sendToPerson) }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("Advanced") { confirmAdvanced = true }
                        .accessibilityIdentifier("advancedModeButton")
                }
            }
            .alert("Turn on Advanced mode?", isPresented: $confirmAdvanced) {
                Button("Turn on") { model.setAdvancedMode(true) }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The app changes to three tabs — Wallet, Send and Settings — with fee controls, network settings, signing tools and technical details. Simple, on the Wallet tab, brings this screen back and keeps every setting you changed.")
            }
            .sheet(isPresented: $showReceive) { ReceiveView() }
            .sheet(isPresented: $showSend, onDismiss: {
                sendAccountID = nil
                sendPersonID = nil
            }) {
                SendView(accountID: $sendAccountID, personID: $sendPersonID, presentedAsSheet: true)
            }
            .sheet(isPresented: $showSavingsChooser) { SavingsChooserView() }
            .refreshable { await model.syncNow() }
        }
    }

    /// One line: the same three states the advanced Sync section spells out.
    @ViewBuilder
    private var status: some View {
        switch model.syncSummary {
        case .peersUnavailable:
            Text("Couldn't reach the Bitcoin network — check your connection.")
                .foregroundStyle(.red)
                .accessibilityIdentifier("syncSummaryText")
        case .syncing:
            BusyIndicator(text: "Syncing…")
                .accessibilityIdentifier("syncSummaryText")
        case .synced:
            Label("Up to date", systemImage: "checkmark.circle")
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("syncSummaryText")
        }
    }

    /// Who can spend, in words: the descriptor's threshold, not a label.
    private func rule(of vault: Vault) -> String {
        guard vault.isScriptPath else { return "All \(vault.signerCount) signers must approve" }
        if vault.threshold == 1 { return "Any one of \(vault.signerCount) owners can spend" }
        return "Any \(vault.threshold) of \(vault.signerCount) owners can spend"
    }

    private func sendFrom(_ accountID: String) {
        sendAccountID = accountID
        sendPersonID = nil
        showSend = true
    }

    private func sendToPerson(_ personID: String) {
        sendAccountID = nil
        sendPersonID = personID
        showSend = true
    }
}

/// The two ways into shared savings, one sheet. Choosing swaps the sheet's
/// content for the flow itself, so its Cancel and Done close the sheet.
struct SavingsChooserView: View {
    private enum Choice { case start, join }
    @State private var choice: Choice?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        switch choice {
        case .start:
            SharedSavingsCreateView()
        case .join:
            AddSharedSavingsView()
        case nil:
            NavigationStack {
                List {
                    Section {
                        Button("Start savings with people you’ve added") { choice = .start }
                            .accessibilityIdentifier("walletSharedSavingsButton")
                        Button("Join savings someone shared with you") { choice = .join }
                            .accessibilityIdentifier("addSharedSavingsButton")
                    } footer: {
                        Text("Shared savings need more than one of you to approve a payment. Whoever starts them shares a card; everyone else joins from it.")
                    }
                }
                .navigationTitle("Save with someone")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }
                    }
                }
            }
        }
    }
}

/// Backup, reached from the one screen. Advanced mode shows the same
/// section inside Settings.
struct WalletBackupView: View {
    var body: some View {
        Form {
            BackupSection()
        }
        .navigationTitle("Back up")
    }
}
