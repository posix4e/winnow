import WalletCore
import SwiftUI

/// Advanced mode's Settings tab: network, backup, manual peers, warned
/// external explorer links, chain-validation mode, and the live peer status
/// list. The switch back to the one-screen interface is on the Wallet tab,
/// not here — without Advanced mode there are no settings at all.
struct SettingsView: View {
    @Environment(AppModel.self) private var model

    @State private var newPeer = ""
    @State private var peerError: String?
    @State private var connectedPeers: [PeerInfo] = []
    @State private var confirmPeerReset = false
    @State private var resettingPeers = false
    @State private var showReadSide = false
    @State private var showPapers = false
    @State private var showDestroyWallet = false
    @State private var destroyError: String?

    struct PeerInfo: Equatable, Identifiable {
        var id: String { endpoint }
        let endpoint: String
        let userAgent: String
        let startHeight: Int32
        /// BIP133 feefilter (sat/kvB).
        let feeFilter: Int64?
        let network: PeerNetwork

        var networkLabel: String {
            switch network {
            case .clearnet: "Clearnet · sees your IP"
            case .tor: "Tor"
            case .i2p: "I2P"
            }
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                // Signet is an Advanced-mode concern; see showsNetworkPicker
                // for why a signet wallet always keeps the row.
                if model.showsNetworkPicker {
                    Section {
                        Picker("Network", selection: Binding(
                            get: { model.network },
                            set: { newValue in Task { await model.switchNetwork(to: newValue) } }
                        )) {
                            Text("Mainnet").tag(BitcoinNetwork.mainnet)
                            Text("Signet").tag(BitcoinNetwork.signet)
                        }
                        .disabled(model.e2e?.forcedNetwork != nil)
                    } footer: {
                        if model.e2e?.forcedNetwork != nil {
                            Text("This debug session is locked to \(model.network == .mainnet ? "mainnet" : "public signet").")
                        } else {
                            Text("Each network has a separate wallet. Signet uses test coins with no value.")
                        }
                    }
                }

                BackupSection()

                if model.advancedMode {
                    PeerGatewaysSection()
                    Section {
                        if let shipped = CensusCatalog.bundled {
                            Text("Observed \(shipped.date): \(AppModel.candidateCount(shipped, networks: model.activePeerGateways.networks)).").accessibilityIdentifier("peerCatalogNotice")
                        } else { Text("This build carries no peer list. Winnow uses saved peers and, when clearnet is allowed, DNS seeds.") }
                    } header: { Text("Mainnet peer list") } footer: {
                        Text("Each release carries the census of its day, the list it starts from. Every selected peer still undergoes Winnow's normal checks.")
                    }
                }

                if model.showsManualPeers {
                Section {
                    ForEach(model.manualPeers, id: \.self) { peer in
                        Text(peer).font(.system(.footnote, design: .monospaced))
                    }
                    .onDelete { model.removeManualPeers(at: $0) }
                    HStack {
                        TextField("host:port", text: $newPeer)
                            .font(.system(.footnote, design: .monospaced))
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                        Button("Add") { addPeer() }
                            .disabled(newPeer.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                    if let peerError {
                        Text(peerError).foregroundStyle(.red).font(.footnote)
                    }
                    Button("Reconnect peers") {
                        Task { await model.reconnect() }
                    }
                } header: {
                    Text("Manual peers")
                } footer: {
                    Text("Manual peers are tried first when their network is enabled. Clearnet seeds resolve over HTTPS (Cloudflare 1.1.1.1), with system DNS as the fallback. Overlay names are resolved by their SOCKS gateway. The default port is 8333 (mainnet) / 38333 (signet). Peers must advertise compact filters and pass Winnow's checks.")
                }
                }

                if model.showsExplorerSettings {
                Section {
                    Picker("Block explorer", selection: Binding(
                        get: { model.explorerProvider },
                        set: { model.setExplorerProvider($0) }
                    )) {
                        Text("blockstream.info").tag(AppModel.ExplorerProvider.blockstream)
                        Text("mempool.space").tag(AppModel.ExplorerProvider.mempool)
                        Text("Custom").tag(AppModel.ExplorerProvider.custom)
                    }
                    .pickerStyle(.menu)
                    .accessibilityIdentifier("explorerProviderPicker")
                    if model.explorerProvider == .custom {
                        TextField("Esplora-compatible website URL", text: Binding(
                            get: { model.esploraURLString },
                            set: { model.setEsploraURL($0) }
                        ))
                        .font(.system(.footnote, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .accessibilityIdentifier("esploraURLField")
                    }
                    Text("Selected: \(model.esploraBaseURL.absoluteString)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("What this trades away") { showReadSide = true }
                } header: {
                    Text("External block explorer")
                } footer: {
                    Text("Winnow does not use the explorer for balances, synchronization, fees or broadcasting. Every funding-address lookup asks for consent and explains the transaction-ID disclosure; you must explicitly select any result. External browser links have their own warning: the browser shares its IP address with the site. On signet, the blockstream.info preset uses mempool.space.")
                }
                }

                if model.showsChainVerification {
                Section {
                    Toggle("Verify the chain from genesis", isOn: Binding(
                        get: { model.verifyFromGenesis },
                        set: { enabled in Task { await model.setVerifyFromGenesis(enabled) } }
                    ))
                    .accessibilityIdentifier("verifyFromGenesisToggle")
                    if model.verifyFromGenesis {
                        Text("Turning this off later keeps the chain you already verified.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Chain verification")
                } footer: {
                    Text("Winnow normally starts from a block header built into the app, then verifies every block after it. That header was produced by syncing this same code from block 0, and anyone can reproduce it — but on your phone it begins as a value you are taking from us rather than one you computed. Turn this on to skip it and re-derive the entire chain from block 0 instead. It downloads and proof-of-work-checks every header ever mined, which takes several minutes and discards the headers already stored.")
                }
                }

                if model.advancedMode {
                Section("Connected peers") {
                    ForEach(connectedPeers) { peer in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(peer.networkLabel)
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(peer.network == .clearnet ? .orange : .green)
                                .accessibilityIdentifier("peerNetwork")
                            Text(peer.endpoint)
                                .font(.system(.footnote, design: .monospaced))
                                .accessibilityIdentifier("peerEndpoint")
                            Text("\(peer.userAgent) · height \(peer.startHeight)"
                                + (peer.feeFilter.map { " · floor \($0) sat/kvB" } ?? ""))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    if connectedPeers.isEmpty {
                        Text("No peers connected.").font(.footnote).foregroundStyle(.secondary)
                    }
                    Button("Refresh") { Task { await refreshPeers() } }
                        .accessibilityIdentifier("refreshPeersButton")
                    Button(resettingPeers ? "Resetting…" : "Reset and shuffle peers") {
                        confirmPeerReset = true
                    }
                    .accessibilityIdentifier("resetPeersButton")
                    .disabled(resettingPeers)
                    .confirmationDialog("Reset and shuffle peers?",
                                        isPresented: $confirmPeerReset, titleVisibility: .visible) {
                        Button("Reset and shuffle peers", role: .destructive) {
                            Task {
                                resettingPeers = true
                                defer { resettingPeers = false }
                                await model.resetPeers()
                                await refreshPeers()
                            }
                        }
                        .accessibilityIdentifier("confirmResetPeersButton")
                        Button("Cancel", role: .cancel) {}
                    } message: {
                        Text("Disconnects all peers, forgets saved peers, and finds new ones from the downloaded peer list and, when clearnet is allowed, DNS seeds. Your manual peers and downloaded catalog are kept.")
                    }
                }
                }

                Section("About") {
                    LabeledContent("Version", value: AppModel.appVersionText)
                    if model.advancedMode {
                        LabeledContent("Wallet ID", value: model.walletID ?? "—")
                    }
                    Button("Design papers") { showPapers = true }
                }

                if model.walletID != nil {
                    Section {
                        Button("Delete wallet from this device", role: .destructive) {
                            showDestroyWallet = true
                        }
                        .accessibilityIdentifier("deleteWalletButton")
                    } header: {
                        Text("Danger zone")
                    } footer: {
                        Text("Removes this \(model.network.rawValue) wallet and its shared savings so you can create or import another. The key is deleted from this device; restore it from your iCloud backup or a backup file that includes the recovery phrase, or the money is gone. People you added stay on this phone, and block headers are kept, so the next wallet does not re-sync the chain.")
                    }
                }
            }
            .navigationTitle("Settings")
            .task(id: model.advancedMode) {
                if model.advancedMode { await refreshPeers() }
            }
            .alert("Delete this wallet?", isPresented: $showDestroyWallet) {
                Button("Delete wallet", role: .destructive) {
                    Task {
                        do { try await model.destroyWallet() }
                        catch { destroyError = error.localizedDescription }
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This deletes the key from this device. Winnow can restore it from your iCloud backup or from a backup file that includes the recovery phrase. Without one of those or the phrase itself, any money in this wallet is unrecoverable. Check you have one before continuing.")
            }
            .alert("Could not delete the wallet",
                   isPresented: Binding(get: { destroyError != nil },
                                        set: { if !$0 { destroyError = nil } })) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(destroyError ?? "")
            }
            .sheet(isPresented: $showReadSide) {
                ReadSideDocumentView()
            }
            .sheet(isPresented: $showPapers) {
                DesignPapersView()
            }
        }
    }

    private func addPeer() {
        do {
            try model.addManualPeer(newPeer)
            newPeer = ""
            peerError = nil
        } catch {
            peerError = error.localizedDescription
        }
    }

    private func refreshPeers() async {
        guard let pool = model.stack?.pool else {
            connectedPeers = []
            return
        }
        var infos: [PeerInfo] = []
        for peer in await pool.connectedPeers() {
            let endpoint = await peer.endpoint
            infos.append(PeerInfo(endpoint: endpoint.description,
                                  userAgent: await peer.peerUserAgent,
                                  startHeight: await peer.peerStartHeight,
                                  feeFilter: await peer.feeFilter,
                                  network: PeerNetwork(host: endpoint.host)))
        }
        connectedPeers = infos
    }
}

/// Settings → Backup → Export: emit the v2 ImportBundle JSON (watch-only
/// by default; seed behind an explicit confirm).
struct ExportBundleView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    @State private var includeMnemonic = false
    @State private var confirmSeed = false
    @State private var fileURL: URL?
    @State private var error: String?
    @State private var busy = false
    @State private var staging = ExportStagingFile()
    @State private var exportEpoch = SensitivePresentationEpoch()
    @State private var exportTask: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle("Include recovery phrase", isOn: $includeMnemonic)
                        .accessibilityIdentifier("exportIncludeMnemonicToggle")
                        .onChange(of: includeMnemonic) { _, _ in
                            resetExport()
                        }
                    if includeMnemonic {
                        Text("This file includes your phone’s signing key. Keep it as private as your recovery words.")
                            .foregroundStyle(.orange)
                            .font(.footnote)
                    }
                } footer: {
                    Text("The file saves your history and shared accounts. Each signer needs their own key backup.")
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red).font(.footnote) }
                }
                if let fileURL {
                    Section("Backup ready") {
                        Text(includeMnemonic
                             ? "Includes your recovery words. Keep this file private."
                             : "Recovery words are not included. Keep them separately.")
                            .accessibilityIdentifier("backupContentsNote")
                        ShareLink("Save or share backup", item: fileURL)
                            .accessibilityIdentifier("exportShareLink")
                    }
                } else {
                    Section {
                        Button("Create backup file") {
                            if includeMnemonic {
                                confirmSeed = true
                            } else {
                                export()
                            }
                        }
                        .disabled(busy)
                        .accessibilityIdentifier("exportConfirmButton")
                    }
                }
            }
            .navigationTitle("Back up wallet")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") {
                        clearSensitiveExport()
                        dismiss()
                    }
                }
            }
            .alert("Include the recovery phrase?", isPresented: $confirmSeed) {
                Button("Export with phrase", role: .destructive) { export() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This adds your phone's signing key to the file. Anyone with the file can use that key.")
            }
            .onChange(of: scenePhase) { _, phase in
                guard phase == .background else { return }
                clearSensitiveExport()
                dismiss()
            }
            .onDisappear { clearSensitiveExport() }
        }
    }

    private func resetExport() {
        exportEpoch.invalidate()
        exportTask?.cancel()
        exportTask = nil
        fileURL = nil
        error = nil
        busy = false
        staging.remove()
    }

    private func clearSensitiveExport() {
        confirmSeed = false
        includeMnemonic = false
        resetExport()
    }

    private func export() {
        exportTask?.cancel()
        let token = exportEpoch.begin()
        let seedBearing = includeMnemonic
        busy = true
        error = nil
        exportTask = Task { @MainActor in
            // Each operation owns its staging object. A cancelled, stale task
            // can therefore delete only its own file, never a newer export.
            let operationStaging = ExportStagingFile()
            do {
                let text = try await model.exportWalletBundle(includeMnemonic: seedBearing)
                try Task.checkCancellation()
                guard exportEpoch.accepts(
                    token, whilePresentationIsAllowed: scenePhase != .background
                ) else { return }
                let name = "winnow-\(model.network.rawValue)-\(model.walletID ?? "wallet").json"
                let url = try operationStaging.write(text, suggestedName: name)
                guard exportEpoch.accepts(
                    token, whilePresentationIsAllowed: scenePhase != .background
                ) else {
                    operationStaging.remove()
                    return
                }
                staging.remove()
                staging = operationStaging
                fileURL = url
            } catch is CancellationError {
                operationStaging.remove()
            } catch {
                operationStaging.remove()
                if exportEpoch.accepts(token, whilePresentationIsAllowed: scenePhase != .background) {
                    fileURL = nil
                    self.error = error.localizedDescription
                }
            }
            guard exportEpoch.accepts(
                token, whilePresentationIsAllowed: scenePhase != .background
            ) else {
                return
            }
            busy = false
            exportTask = nil
        }
    }
}
