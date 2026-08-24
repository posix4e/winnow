import BitcoinP2P
import LocalAuthentication
import SwiftUI
import WalletCore

/// Network, manual peers, warned external explorer links, chain-validation
/// mode, and the live peer status list.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase

    @State private var newPeer = ""
    @State private var peerError: String?
    @State private var connectedPeers: [PeerInfo] = []
    @State private var showReadSide = false
    @State private var showPapers = false
    @State private var showDestroyWallet = false
    @State private var destroyError: String?
    @State private var showExport = false
    @State private var revealedMnemonic: String?
    @State private var revealError: String?
    @State private var revealing = false
    @State private var revealEpoch = SensitivePresentationEpoch()
    @State private var revealTask: Task<Void, Never>?

    struct PeerInfo: Equatable, Identifiable {
        var id: String { endpoint }
        let endpoint: String
        let userAgent: String
        let startHeight: Int32
        /// BIP133 feefilter (sat/kvB).
        let feeFilter: Int64?
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Network", selection: Binding(
                        get: { model.network },
                        set: { newValue in Task { await model.switchNetwork(to: newValue) } }
                    )) {
                        Text("Signet").tag(BitcoinNetwork.signet)
                        Text("Mainnet").tag(BitcoinNetwork.mainnet)
                    }
                    .disabled(model.e2e?.forcedNetwork != nil)
                } footer: {
                    if model.e2e?.forcedNetwork != nil {
                        Text("This reproducible story run is locked to public signet.")
                    } else {
                        Text("Each network has its own wallet on this device. Switching opens that network's wallet, or onboarding when it has none.")
                    }
                }

                Section {
                    Button("Export wallet bundle") { showExport = true }
                        .disabled(model.walletID == nil)
                        .accessibilityIdentifier("exportBundleButton")
                    Button("Show recovery phrase") { reveal() }
                        .disabled(model.walletID == nil || revealing)
                        .accessibilityIdentifier("revealPhraseButton")
                    if let revealError {
                        Text(revealError).foregroundStyle(.red).font(.footnote)
                    }
                } header: {
                    Text("Backup")
                } footer: {
                    Text("The bundle is the history. A new phone cannot recover this wallet from the 12 words alone — export this file and keep it with the words. Showing the phrase asks for device authentication first.")
                }

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
                    Text("Manual peers are tried before DNS seeds. Seeds resolve over HTTPS (Cloudflare 1.1.1.1), then system DNS. The default port is 8333 (mainnet) / 38333 (signet). Peers must serve BIP157 compact filters.")
                }

                Section {
                    TextField("Explorer website URL (empty = mempool.space)", text: Binding(
                        get: { model.esploraURLString },
                        set: { model.setEsploraURL($0) }
                    ))
                    .font(.system(.footnote, design: .monospaced))
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .accessibilityIdentifier("esploraURLField")
                    Text("Selected: \(model.esploraBaseURL.absoluteString)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("What this trades away") { showReadSide = true }
                } header: {
                    Text("External block explorer")
                } footer: {
                    Text("This is a link destination only. Winnow never contacts it for balances, history, fees, synchronization, or broadcasting. Tapping an address or transaction shows a privacy warning before opening the selected website. You may enter a custom Esplora-compatible website.")
                }

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

                Section("Connected peers") {
                    ForEach(connectedPeers) { peer in
                        VStack(alignment: .leading, spacing: 2) {
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
                }


                Section("About") {
                    LabeledContent("WalletCore", value: WalletCore.version)
                    LabeledContent("BitcoinP2P", value: BitcoinP2P.version)
                    LabeledContent("Wallet ID", value: model.walletID ?? "—")
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
                        Text("Removes this \(model.network.rawValue) wallet and its vaults so you can create or import another. The key is deleted from this device — without your recovery phrase the money is gone. Block headers are kept, so the next wallet does not re-sync the chain.")
                    }
                }
            }
            .navigationTitle("Settings")
            .task { await refreshPeers() }
            .alert("Delete this wallet?", isPresented: $showDestroyWallet) {
                Button("Delete wallet", role: .destructive) {
                    Task {
                        do { try await model.destroyWallet() }
                        catch { destroyError = error.localizedDescription }
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This deletes the key from this device. Anyone holding the recovery phrase can still restore it; without that phrase, any money in this wallet is unrecoverable. Check you have the phrase written down before continuing.")
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
            .sheet(item: revealedItem) { words in
                RevealPhraseView(mnemonic: words.text)
            }
            .sheet(isPresented: $showExport) {
                ExportBundleView()
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .background { clearSensitivePresentations() }
            }
            .onDisappear { clearSensitivePresentations() }
        }
    }

    private struct RevealedItem: Identifiable {
        var id: String { text }
        let text: String
    }

    /// Bridges the optional revealed mnemonic to an Identifiable sheet item.
    private var revealedItem: Binding<RevealedItem?> {
        Binding(
            get: { revealedMnemonic.map(RevealedItem.init) },
            set: { revealedMnemonic = $0?.text }
        )
    }

    private func reveal() {
        revealTask?.cancel()
        let token = revealEpoch.begin()
        revealing = true
        revealError = nil
        revealTask = Task { @MainActor in
            do {
                let words = try await model.revealMnemonic()
                try Task.checkCancellation()
                guard revealEpoch.accepts(
                    token, whilePresentationIsAllowed: scenePhase != .background
                ) else { return }
                revealedMnemonic = words
            } catch let error as LAError where error.code == .userCancel {
                // Cancelling the auth prompt is a decision, not a failure.
            } catch is CancellationError {
                // Leaving the active scene is an intentional fail-closed exit.
            } catch {
                if revealEpoch.accepts(token, whilePresentationIsAllowed: scenePhase != .background) {
                    revealError = error.localizedDescription
                }
            }
            guard revealEpoch.accepts(
                token, whilePresentationIsAllowed: scenePhase != .background
            ) else {
                return
            }
            revealing = false
            revealTask = nil
        }
    }

    private func clearSensitivePresentations() {
        revealEpoch.invalidate()
        revealTask?.cancel()
        revealTask = nil
        revealedMnemonic = nil
        revealError = nil
        revealing = false
        showExport = false
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
            infos.append(PeerInfo(endpoint: await peer.endpoint.description,
                                  userAgent: await peer.peerUserAgent,
                                  startHeight: await peer.peerStartHeight,
                                  feeFilter: await peer.feeFilter))
        }
        connectedPeers = infos
    }
}

/// Settings → Backup → Export: emit the v2 ImportBundle JSON (watch-only
/// by default; seed behind an explicit confirm).
private struct ExportBundleView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    @State private var includeMnemonic = false
    @State private var confirmSeed = false
    /// Display-only JSON. A seed-bearing export is redacted before it enters
    /// view state; the complete value goes directly to the protected staging
    /// file and is then released.
    @State private var previewJSON: String?
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
                        Text("A bundle with the seed is a hot backup. Anyone who has the file can spend. Share it the same way you would share the words — not through iCloud or a chat.")
                            .foregroundStyle(.orange)
                            .font(.footnote)
                    }
                } footer: {
                    Text("Off by default. Without the phrase the bundle restores history and the descriptor, not the ability to spend.")
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red).font(.footnote) }
                }
                if let previewJSON {
                    Section("Bundle") {
                        CopyableTextBlock(text: previewJSON)
                        if includeMnemonic {
                            Text("The recovery phrase is in the shared file, not shown here.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                        if let fileURL {
                            ShareLink("Share \(fileURL.lastPathComponent)", item: fileURL)
                                .accessibilityIdentifier("exportShareLink")
                        }
                    }
                } else {
                    Section {
                        Button(includeMnemonic ? "Export with recovery phrase" : "Export watch-only bundle") {
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
            .navigationTitle("Export wallet")
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
                Text("The file will contain the 12 words. Treat it as cash.")
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
        previewJSON = nil
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
                previewJSON = seedBearing ? ImportBundle.redactedPreview(text) : text
                fileURL = url
            } catch is CancellationError {
                operationStaging.remove()
            } catch {
                operationStaging.remove()
                if exportEpoch.accepts(token, whilePresentationIsAllowed: scenePhase != .background) {
                    fileURL = nil
                    previewJSON = nil
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

/// Settings → Backup → Show recovery phrase: the words and an explicit,
/// short-lived copy control, available only after device authentication.
private struct RevealPhraseView: View {
    let mnemonic: String
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    private var words: [String] { mnemonic.split(separator: " ").map(String.init) }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                        ForEach(Array(words.enumerated()), id: \.offset) { index, word in
                            Text("\(index + 1). \(word)")
                                .font(.system(.body, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .privacySensitive()
                    .accessibilityIdentifier("revealedPhraseGrid")
                } footer: {
                    Text("These words are the wallet. Anyone who sees them can spend — keep them offline, on paper, and close this screen when done.")
                }
                Section {
                    RecoveryPhraseCopyButton(
                        phrase: mnemonic, accessibilityID: "settingsCopyPhraseButton")
                } footer: {
                    Text("Copying is less private than paper. The clipboard item stays on this device and expires after two minutes.")
                }
            }
            .navigationTitle("Recovery phrase")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .background { dismiss() }
            }
        }
    }
}
