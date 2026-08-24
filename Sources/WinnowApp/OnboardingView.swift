import LocalAuthentication
import SwiftUI
import UIKit
import WalletCore

/// Create a fresh wallet (mnemonic shown once) or import a bundle with its
/// history (docs/import.md: there is no historical back-scan — the bundle
/// *is* the history).
struct OnboardingView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase

    @State private var busy: String?
    @State private var error: String?
    @State private var mnemonic: String?
    @State private var writtenDown = false
    @State private var showImport = false
    @State private var suppressAutomaticBackupResume = false
    @State private var phraseEpoch = SensitivePresentationEpoch()
    @State private var phraseTask: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("A Taproot-only wallet that learns about your money from Bitcoin peers using compact block filters, without asking a wallet server about your addresses. Blocks provide the confirmed record; while Receive is open, Winnow can also show a temporary unconfirmed observation from peer relay traffic. Sync runs while the app is open.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Section {
                    if model.hasPendingBackup {
                        Button {
                            suppressAutomaticBackupResume = false
                            resumePendingBackup()
                        } label: {
                            Label("Resume wallet backup", systemImage: "key.viewfinder")
                        }
                        .accessibilityIdentifier("resumeBackupButton")
                    } else if model.walletID != nil {
                        Button {
                            model.finishOnboarding()
                        } label: {
                            Label("Continue with imported wallet", systemImage: "checkmark.circle")
                        }
                        .accessibilityIdentifier("resumeImportedWalletButton")
                    } else {
                        Button {
                            create()
                        } label: {
                            Label("Create new wallet", systemImage: "plus.circle")
                        }
                        .accessibilityIdentifier("createWalletButton")
                        Button {
                            showImport = true
                        } label: {
                            Label("Import wallet bundle", systemImage: "square.and.arrow.down")
                        }
                        .accessibilityIdentifier("importWalletButton")
                    }
                } footer: {
                    Text("Network: \(model.network.rawValue) (change in Settings). Your backup appears immediately; peer and header synchronization continues while you secure it.")
                }
                if let busy {
                    Section { ProgressView(model.syncStatusText ?? busy) }
                }
                if let error {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.footnote)
                    }
                }
            }
            .navigationTitle("Winnow")
            .sheet(isPresented: $showImport) {
                ImportBundleView()
            }
            .sheet(item: mnemonicString, onDismiss: {
                // A swipe-dismiss without the confirmed Done leaves the backup
                // pending — re-present instead of stranding the user on the
                // onboarding list. Done clears the flag before this fires, so
                // the confirmed path cannot loop.
                if scenePhase == .active, !suppressAutomaticBackupResume {
                    resumePendingBackup()
                }
            }) { words in
                MnemonicBackupView(mnemonic: words.text, writtenDown: $writtenDown) {
                    model.finishOnboarding()
                }
            }
            .task {
                // Relaunched mid-backup: resume the sheet with the same words,
                // straight from the Keychain (#5).
                if mnemonic == nil { resumePendingBackup() }
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .background { clearSensitiveOnboardingState() }
            }
            .onDisappear { clearSensitiveOnboardingState() }
        }
    }

    /// Bridges the optional mnemonic String to an Identifiable sheet item.
    private var mnemonicString: Binding<MnemonicItem?> {
        Binding(
            get: { mnemonic.map(MnemonicItem.init) },
            set: { mnemonic = $0?.text }
        )
    }

    private struct MnemonicItem: Identifiable {
        var id: String { text }
        let text: String
    }

    private func create() {
        phraseTask?.cancel()
        let token = phraseEpoch.begin()
        busy = "Creating the wallet…"
        error = nil
        phraseTask = Task { @MainActor in
            do {
                let words = try await model.createWallet()
                try Task.checkCancellation()
                guard phraseEpoch.accepts(
                    token, whilePresentationIsAllowed: scenePhase != .background
                ) else { return }
                busy = nil
                mnemonic = words
            } catch is CancellationError {
                // The Keychain backup-pending flag remains the source of
                // truth if creation crossed an inactive transition.
            } catch {
                if phraseEpoch.accepts(token, whilePresentationIsAllowed: scenePhase != .background) {
                    busy = nil
                    self.error = error.localizedDescription
                }
            }
            guard phraseEpoch.accepts(
                token, whilePresentationIsAllowed: scenePhase != .background
            ) else {
                return
            }
            phraseTask = nil
        }
    }

    private func resumePendingBackup() {
        phraseTask?.cancel()
        let token = phraseEpoch.begin()
        phraseTask = Task { @MainActor in
            do {
                let words = try await model.pendingBackupMnemonic()
                try Task.checkCancellation()
                guard phraseEpoch.accepts(
                    token, whilePresentationIsAllowed: scenePhase != .background
                ) else { return }
                mnemonic = words
            } catch let authError as LAError where authError.code == .userCancel {
                // The backup remains pending and will be offered again.
            } catch is CancellationError {
                // Leaving the active scene intentionally abandons this reveal.
            } catch {
                if phraseEpoch.accepts(token, whilePresentationIsAllowed: scenePhase != .background) {
                    self.error = error.localizedDescription
                }
            }
            guard phraseEpoch.accepts(
                token, whilePresentationIsAllowed: scenePhase != .background
            ) else {
                return
            }
            phraseTask = nil
        }
    }

    private func clearSensitiveOnboardingState() {
        suppressAutomaticBackupResume = true
        phraseEpoch.invalidate()
        phraseTask?.cancel()
        phraseTask = nil
        mnemonic = nil
        writtenDown = false
        busy = nil
        error = nil
    }
}

/// The 12 words, shown exactly once, with the written-down confirmation.
private struct MnemonicBackupView: View {
    @Environment(AppModel.self) private var model
    let mnemonic: String
    @Binding var writtenDown: Bool
    let onFinish: () -> Void
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    private var words: [String] { mnemonic.split(separator: " ").map(String.init) }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Write these \(words.count) words down, in order, and keep them offline. They are the only backup of this wallet — they are stored in this device's Keychain and never leave it.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Section {
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                        ForEach(Array(words.enumerated()), id: \.offset) { index, word in
                            Text("\(index + 1). \(word)")
                                .font(.system(.body, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .privacySensitive()
                }
                Section {
                    RecoveryPhraseCopyButton(
                        phrase: mnemonic, accessibilityID: "backupCopyPhraseButton")
                } footer: {
                    Text("Copying is less private than paper. The clipboard item stays on this device and expires after two minutes.")
                }
                if let progress = model.syncStatusText {
                    Section {
                        ProgressView(progress)
                            .accessibilityIdentifier("backupSyncProgress")
                    } header: {
                        Text("Wallet synchronization")
                    } footer: {
                        Text("You can copy or write down the phrase while Winnow validates headers from Bitcoin peers. Backup does not wait for synchronization.")
                    }
                }
                Section {
                    Toggle("I have written the words down", isOn: $writtenDown)
                        .accessibilityIdentifier("writtenDownToggle")
                    Button("Done") {
                        dismiss()
                        onFinish()
                    }
                    .accessibilityIdentifier("backupDoneButton")
                    .disabled(!writtenDown)
                }
            }
            .navigationTitle("Wallet backup")
            .interactiveDismissDisabled(!writtenDown)
            .onChange(of: scenePhase) { _, phase in
                if phase == .background { dismiss() }
            }
        }
    }
}

/// Paste an ImportBundle JSON (WalletCore's format v1); verification scans
/// forward from the bundle's height and its report is shown.
private struct ImportBundleView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    @State private var json = ""
    @State private var busy = false
    @State private var error: String?
    @State private var report: ImportReport?
    @State private var imported = false
    @State private var importEpoch = SensitivePresentationEpoch()
    @State private var importTask: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $json)
                        .font(.system(.caption, design: .monospaced))
                        // Keep real bundles scrollable inside the editor. A
                        // minimum-only height lets TextEditor expand to the
                        // full JSON and can push the import action thousands
                        // of points off-screen.
                        .frame(height: 160)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .accessibilityIdentifier("importJSONEditor")
                    Button("Paste from clipboard") {
                        json = UIPasteboard.general.string ?? ""
                    }
                    .accessibilityIdentifier("importPasteButton")
                } header: {
                    Text("Import bundle (JSON)")
                } footer: {
                    Text("Exported by Winnow (Settings → Export wallet bundle) or by previous wallet software: descriptor and/or mnemonic, known UTXOs and transactions, and the last scanned height. There is no back-scan — the bundle is the history; filters verify it from its height forward.\n\nSilent-payment receipts will not appear. Their output scripts cannot be derived from a recovery phrase alone, so this build cannot find them and will show a balance without them. Those coins are still on the chain and still yours — open the wallet in an alpha build to see them.")
                }
                if busy {
                    Section { ProgressView("Importing and verifying…") }
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red).font(.footnote) }
                }
                if report != nil || imported
                    || (model.walletID != nil && !model.hasPendingBackup) {
                    if let report {
                        Section("Verification report") {
                            LabeledContent("Scanned from block", value: "\(report.scannedFromHeight)")
                            if let to = report.scannedToHeight {
                                LabeledContent("Scanned to block", value: "\(to)")
                            }
                            LabeledContent("Claimed UTXOs confirmed", value: "\(report.confirmedUTXOs.count)")
                            LabeledContent("Claimed but spent since", value: "\(report.spentSinceBundle.count)")
                            LabeledContent("Discovered since bundle", value: "\(report.discoveredUTXOs.count)")
                            if !report.matchesBundle {
                                Text("Some claimed UTXOs were already spent — the bundle was stale or wrong. The chain won; check the report above.")
                                    .foregroundStyle(.orange)
                                    .font(.footnote)
                            }
                        }
                        .accessibilityIdentifier("importReportSection")
                    }
                    Section {
                        Button("Continue") {
                            model.finishOnboarding()
                            dismiss()
                        }
                        .accessibilityIdentifier("importContinueButton")
                    }
                } else {
                    Section {
                        Button("Import and verify") { importBundle() }
                            .accessibilityIdentifier("importVerifyButton")
                            .disabled(json.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || busy)
                    }
                }
            }
            .navigationTitle("Import wallet")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") {
                        clearSensitiveImport()
                        dismiss()
                    }
                }
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .background { clearSensitiveImport() }
            }
            .onDisappear { clearSensitiveImport() }
        }
    }

    private func importBundle() {
        importTask?.cancel()
        let token = importEpoch.begin()
        let payload = json
        busy = true
        error = nil
        importTask = Task { @MainActor in
            do {
                let result = try await model.importWallet(bundleJSON: payload)
                try Task.checkCancellation()
                guard importEpoch.accepts(
                    token, whilePresentationIsAllowed: scenePhase != .background
                ) else { return }
                report = result
                // A seed-bearing bundle must not remain in view state after
                // it has been handed to WalletCore/Keychain.
                json = ""
                imported = true
                if result == nil {
                    error = "Imported, but no peers were reachable for verification yet — the regular sync will verify from the bundle's height."
                }
            } catch is CancellationError {
                // The text is cleared below; an import that already crossed
                // its commit boundary remains discoverable through AppModel.
            } catch {
                if importEpoch.accepts(token, whilePresentationIsAllowed: scenePhase != .background) {
                    self.error = error.localizedDescription
                }
            }
            guard importEpoch.accepts(
                token, whilePresentationIsAllowed: scenePhase != .background
            ) else {
                return
            }
            busy = false
            importTask = nil
        }
    }

    private func clearSensitiveImport() {
        importEpoch.invalidate()
        importTask?.cancel()
        importTask = nil
        json = ""
        busy = false
        error = nil
        report = nil
    }
}
