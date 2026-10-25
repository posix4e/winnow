import SwiftUI

/// Advanced controls; beginner mode only displays the backup status.
struct CloudBackupView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Toggle("Automatic iCloud backup", isOn: Binding(
                        get: { model.cloudBackups.automaticEnabled },
                        set: { enabled in Task { await model.setAutomaticCloudBackup(enabled) } }
                    ))
                    .accessibilityIdentifier("automaticCloudBackupToggle")
                    Text(model.cloudBackups.statusTitle)
                        .accessibilityIdentifier("cloudBackupStatus")
                    if let saved = model.cloudBackups.lastSaved {
                        LabeledContent("Last saved to iCloud", value: saved.formatted())
                    }
                    if let message = model.cloudBackups.message { Text(message).foregroundStyle(.secondary) }
                } footer: {
                    Text("Includes this phone’s signing key, wallet history, saved people and labels. Updates while Winnow is open, after pending payments confirm.")
                }
                Section {
                    Text("Restore using the same Apple Account with iCloud and Passwords & Keychain enabled. Access to the cloud backup and its synchronized key can restore spending access.")
                    Text("Turning this off leaves existing copies in iCloud. Keep a manual backup too.")
                }
            }
            .navigationTitle("iCloud backup")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
        }
    }
}

struct CloudRestoreView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    @State private var operation: Task<Void, Never>?
    @State private var restoring = false
    @State private var restored = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                if restored || model.walletID != nil {
                    Section {
                        Text("Your wallet is restored. Keep Winnow open to check for newer payments and finish this device’s automatic backup.")
                        if let notice = model.cloudRestoreNotice { Text(notice) }
                        Button("Continue") { model.finishOnboarding(); dismiss() }
                    }
                } else {
                    Section {
                        ForEach(model.cloudBackups.available) { backup in
                            Button {
                                restore(backup.id)
                            } label: {
                                Label(backup.savedAt.formatted(), systemImage: "icloud.and.arrow.down")
                            }
                            .disabled(restoring)
                        }
                        if model.cloudBackups.available.isEmpty, !model.cloudBackups.busy {
                            Text("No backup found for this network yet.")
                        }
                        Button("Check again") {
                            operation = Task { await model.discoverCloudBackups() }
                        }.disabled(restoring || model.cloudBackups.busy)
                    } header: {
                        Text("Choose a saved backup")
                    } footer: {
                        Text("Use the same Apple Account and enable Passwords & Keychain. Backups may take time to appear on a new device. Restoring never replaces a wallet already on this phone.")
                    }
                }
                if restoring || model.cloudBackups.busy { ProgressView(restoring ? "Restoring wallet…" : "Checking iCloud…") }
                if let error { Text(error).foregroundStyle(.secondary) }
                if let message = model.cloudBackups.message { Text(message).foregroundStyle(.secondary) }
            }
            .navigationTitle("Restore from iCloud")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } } }
            .task { await model.discoverCloudBackups() }
            .onDisappear { cancel() }
            .onChange(of: scenePhase) { _, phase in if phase == .background { cancel() } }
        }
    }

    private func restore(_ id: UUID) {
        restoring = true
        error = nil
        operation = Task { @MainActor in
            defer { restoring = false }
            do {
                let report = try await model.restoreCloudBackup(id)
                try Task.checkCancellation()
                restored = true
                if let report, !report.matchesBundle {
                    error = "Some payments changed since this backup. Winnow updated the wallet from the network; review the restored balances."
                } else if report == nil {
                    error = "Restored. Network verification will resume when peers are reachable."
                }
            } catch is CancellationError { }
            catch { if !Task.isCancelled { self.error = error.localizedDescription } }
        }
    }

    private func cancel() {
        operation?.cancel()
        operation = nil
        model.cloudBackups.suspend()
        restoring = false
    }
}
