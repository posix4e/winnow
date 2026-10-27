import SwiftUI
import WalletCore

/// Builds a k-of-n account from this phone's key, the other signers' keys
/// (other Winnows show theirs under "This phone's key" when joining) and
/// optionally a Ledger's, with an optional timelocked recovery path. The
/// finished descriptor is shown to share: every other signer adds the same
/// account by pasting it under "Join with a descriptor".
struct MultisigBuildView: View {
    enum RecoveryMode: String, CaseIterable, Identifiable {
        case fewerSigners, separateKey
        var id: String { rawValue }
    }

    @Environment(AppModel.self) private var model
    @State private var name = ""
    @State private var otherKeys: [String] = []
    @State private var includeLedger = false
    @State private var threshold = 2
    @State private var withRecovery = false
    @State private var recoveryMode: RecoveryMode = .fewerSigners
    @State private var recoveryThreshold = 1
    @State private var recoveryKey = ""
    @State private var recoveryDays = 30
    @State private var creating = false
    @State private var error: String?
    @State private var created: MultisigAccountRecord?

    /// About 144 blocks a day; BIP68 counts at most 65,535 blocks.
    static func blocks(forDays days: Int) -> UInt32 {
        UInt32(min(days * 144, Int(MultisigAccount.maximumRecoveryBlocks)))
    }

    private var signerCount: Int { 1 + otherKeys.count + (includeLedger ? 1 : 0) }

    private var recoveryPlan: MultisigAccount.RecoveryPlan? {
        guard withRecovery else { return nil }
        let blocks = Self.blocks(forDays: recoveryDays)
        switch recoveryMode {
        case .fewerSigners: return .fewerSigners(threshold: recoveryThreshold, blocks: blocks)
        case .separateKey:
            return .separateKeys(threshold: 1, keys: [recoveryKey.trimmingCharacters(in: .whitespacesAndNewlines)],
                                 blocks: blocks)
        }
    }

    var body: some View {
        Form {
            if let created {
                createdSection(created)
            } else {
                Section {
                    TextField("Name", text: $name)
                        .autocorrectionDisabled()
                        .accessibilityIdentifier("multisigBuildNameField")
                }
                signersSection
                thresholdSection
                recoverySection
                Section {
                    Button(creating ? "Creating…" : "Create account") { create() }
                        .accessibilityIdentifier("multisigBuildCreateButton")
                        .disabled(creating || DisplayName.normalized(name) == nil || signerCount < 2
                            || (withRecovery && recoveryMode == .separateKey && recoveryKey.isEmpty))
                } footer: {
                    Text(includeLedger
                        ? "Open the Bitcoin app on the Ledger (Bitcoin Test on signet), version 2.2.1 or later for a recovery path. It reads the Ledger's key, then asks you to approve the account on the Ledger."
                        : "Winnow watches the account from the next block it scans.")
                }
                if let error {
                    Section { Text(error).font(.footnote).foregroundStyle(.red).accessibilityIdentifier("multisigBuildError") }
                }
            }
        }
        .navigationTitle("New multisig account")
        .onChange(of: signerCount) { _, count in
            threshold = min(max(threshold, 1), count)
            recoveryThreshold = min(max(recoveryThreshold, 1), count)
        }
    }

    private var signersSection: some View {
        Section {
            if let key = try? model.multisigKeyExpression() {
                VStack(alignment: .leading, spacing: 4) {
                    Text("This phone").font(.caption).foregroundStyle(.secondary)
                    MultisigLiteralRow(text: key, copyIdentifier: "multisigBuildOwnKeyCopy")
                }
            }
            ForEach(otherKeys.indices, id: \.self) { index in
                HStack(alignment: .top) {
                    ReviewAddress(address: otherKeys[index])
                    Button(role: .destructive) { otherKeys.remove(at: index) } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Remove this signer")
                }
            }
            Button("Paste a signer's key") {
                if let text = model.pasteboardText()?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty,
                   !otherKeys.contains(text) {
                    otherKeys.append(text)
                }
            }
            .accessibilityIdentifier("multisigBuildPasteKeyButton")
            Toggle("Include a Ledger", isOn: $includeLedger)
                .accessibilityIdentifier("multisigBuildLedgerToggle")
        } header: {
            Text("Signers · \(signerCount)")
        } footer: {
            Text("Another Winnow shows its key under Join with a descriptor → This phone's key. Any signer's key works: [fingerprint/path]xpub…/<0;1>/*.")
        }
    }

    private var thresholdSection: some View {
        Section {
            Stepper("Any \(threshold) of \(signerCount) spend at once", value: $threshold, in: 1 ... max(signerCount, 1))
                .accessibilityIdentifier("multisigBuildThresholdStepper")
        }
    }

    @ViewBuilder
    private var recoverySection: some View {
        Section {
            Toggle("Recovery after a delay", isOn: $withRecovery)
                .accessibilityIdentifier("multisigBuildRecoveryToggle")
            if withRecovery {
                Picker("After the delay", selection: $recoveryMode) {
                    Text("Fewer signers").tag(RecoveryMode.fewerSigners)
                    Text("A recovery key").tag(RecoveryMode.separateKey)
                }
                .pickerStyle(.segmented)
                switch recoveryMode {
                case .fewerSigners:
                    Stepper("Any \(recoveryThreshold) of the \(signerCount) signers", value: $recoveryThreshold,
                            in: 1 ... max(signerCount, 1))
                        .accessibilityIdentifier("multisigBuildRecoveryThresholdStepper")
                case .separateKey:
                    if recoveryKey.isEmpty {
                        Button("Paste the recovery key") {
                            recoveryKey = model.pasteboardText()?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                        }
                        .accessibilityIdentifier("multisigBuildPasteRecoveryKeyButton")
                    } else {
                        ReviewAddress(address: recoveryKey)
                        Button("Remove the recovery key", role: .destructive) { recoveryKey = "" }
                    }
                }
                Stepper("After \(recoveryDays) days (\(Self.blocks(forDays: recoveryDays)) blocks)", value: $recoveryDays,
                        in: 1 ... 455)
                    .accessibilityIdentifier("multisigBuildRecoveryDaysStepper")
            }
        } footer: {
            if withRecovery {
                Text("The delay counts from when each coin is received. Once it passes, the recovery path can spend that coin without the other signers, so move coins before then if you do not want that.")
            }
        }
    }

    private func createdSection(_ record: MultisigAccountRecord) -> some View {
        Section {
            Text("Account created").font(.headline).foregroundStyle(.green)
                .accessibilityIdentifier("multisigBuildCreated")
            QRCodeView(content: record.descriptor)
                .frame(maxWidth: 260)
                .frame(maxWidth: .infinity)
            CopyableTextBlock(text: record.descriptor)
            NavigationLink(value: MultisigRoute.account(record.id)) { Text("Open the account") }
        } footer: {
            Text("Every other signer adds this same descriptor under Join with a descriptor. Check that each one shows the same first address.")
        }
    }

    private func create() {
        creating = true
        error = nil
        Task {
            defer { creating = false }
            do {
                created = try await model.createMultisigAccount(name: name, threshold: threshold, otherKeys: otherKeys,
                                                                includeLedger: includeLedger, recovery: recoveryPlan)
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}
