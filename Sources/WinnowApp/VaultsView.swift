import SwiftUI
import UIKit
import VaultKit
import WalletCore

/// Builds a vault descriptor from cosigner key expressions (pasted, or this
/// device's own wallet key), previews the descriptor and first address, and
/// saves it into the vault store.
struct VaultCreateView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var name = ""
    @State private var draft = VaultDraft()
    @State private var pasted = ""
    @State private var builtDescriptor: Descriptor?
    @State private var error: String?
    @State private var saving = false

    init(role: VaultCosignerRole = .scriptPath) {
        _draft = State(initialValue: VaultDraft(role: role))
    }

    private var isMuSig2: Bool { draft.role == .muSig2 }
    private var policyName: String { isMuSig2 ? "MuSig2" : "k-of-n" }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Vault name", text: $name)
                        .accessibilityIdentifier("vaultNameField")
                    Picker("Who must approve", selection: Binding(
                        get: { draft.role },
                        set: { role in
                            if draft.setRole(role) {
                                error = nil
                                builtDescriptor = nil
                            }
                        }
                    )) {
                        Text("Choose a threshold").tag(VaultCosignerRole.scriptPath)
                        Text("Every signing key").tag(VaultCosignerRole.muSig2)
                    }
                    .accessibilityIdentifier("vaultPolicyPicker")
                    .disabled(!draft.cosigners.isEmpty)
                    if !isMuSig2 {
                        if draft.cosigners.count >= 2 {
                            Stepper("Required signatures: \(draft.threshold) of \(draft.cosigners.count)",
                                    value: Binding(
                                        get: { draft.threshold },
                                        set: { value in
                                            draft.setThreshold(value)
                                            builtDescriptor = nil
                                        }
                                    ), in: 1 ... draft.cosigners.count)
                                .accessibilityIdentifier("vaultThresholdStepper")
                        } else {
                            LabeledContent("Required signatures") {
                                Text("Add at least two signers")
                                    .foregroundStyle(.secondary)
                            }
                            .accessibilityIdentifier("vaultThresholdPending")
                        }
                    }
                    if !draft.cosigners.isEmpty {
                        Text("Remove all signer keys before changing the policy.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } footer: {
                    Text(isMuSig2
                         ? "Use separate keys for this phone and another signing device. Every key is needed for every payment; losing a required key can lock the funds. External signers must support Winnow’s MuSig2 exchange; hardware-wallet compatibility is not yet verified."
                         : "Share control with a threshold such as 2 of 3. Any two keys can authorize a payment; one can be unavailable. Keep the keys separate if you want one device to be insufficient.")
                        .accessibilityIdentifier("vaultPurpose")
                }

                Section {
                    ForEach(Array(draft.cosigners.enumerated()), id: \.offset) { index, cosigner in
                        VStack(alignment: .leading) {
                            Text("Cosigner \(index + 1)").font(.caption)
                            Text(cosigner.expression)
                                .font(.system(.caption2, design: .monospaced))
                                .lineLimit(2)
                        }
                    }
                    .onDelete(perform: deleteCosigners)
                    TextField("Paste a cosigner key expression", text: $pasted)
                        .font(.system(.caption, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .accessibilityIdentifier("cosignerField")
                    Button("Add pasted key") { addPasted() }
                        .accessibilityIdentifier("addPastedKeyButton")
                        .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    Button("Add this device's key") { addOwn() }
                        .accessibilityIdentifier("addDeviceKeyButton")
                } header: {
                    Text("Cosigners")
                } footer: {
                    Text(isMuSig2
                         ? "MuSig2 participants are bare key expressions: [fingerprint/path]xpub with no derivation suffix (BIP390)."
                         : "Each cosigner is a key expression like [fingerprint/86'/1'/0']xpub…/<0;1>/*. The vault's internal key is the BIP341 NUMS point — no one can key-path spend around the multisig.")
                }

                if let error {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                            .font(.footnote)
                            .accessibilityIdentifier("vaultErrorText")
                    }
                }

                Section {
                    Button("Build descriptor") { build() }
                        .accessibilityIdentifier("buildDescriptorButton")
                        .disabled(!draft.canBuild)
                }

                if let builtDescriptor, let vault = try? Vault(descriptor: builtDescriptor, network: model.network) {
                    VaultPolicySection(vault: vault)
                    Section("Descriptor") {
                        CopyableTextBlock(text: builtDescriptor.serialized())
                            .accessibilityIdentifier("descriptorBlock")
                    }
                    Section("First address") {
                        if let address = try? vault.address(index: 0) {
                            CopyableTextBlock(text: address)
                        }
                    }
                    Section {
                        Button(saving ? "Saving…" : "Save vault") { save(descriptor: builtDescriptor) }
                            .accessibilityIdentifier("saveVaultButton")
                            .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty || saving)
                    }
                }
            }
            .navigationTitle("New \(policyName) vault")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func addPasted() {
        let text = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        if addCosigner(text) { pasted = "" }
    }

    private func addOwn() {
        do {
            let expression = try model.ownKeyExpression(multipathSuffix: !isMuSig2)
            _ = addCosigner(expression)
        } catch {
            self.error = error.localizedDescription
        }
    }

    @discardableResult
    private func addCosigner(_ expression: String) -> Bool {
        do {
            try draft.add(expression, network: model.network)
            error = nil
            builtDescriptor = nil
            return true
        } catch {
            self.error = error.localizedDescription
            builtDescriptor = nil
            return false
        }
    }

    private func deleteCosigners(at offsets: IndexSet) {
        draft.remove(at: offsets)
        error = nil
        builtDescriptor = nil
    }

    private func build() {
        error = nil
        do {
            let validated = draft.cosigners.map(\.expression)
            let descriptor: Descriptor
            if isMuSig2 {
                descriptor = try Descriptor("tr(musig(\(validated.joined(separator: ",")))/<0;1>/*)")
            } else {
                descriptor = try Vault.multiADescriptor(threshold: draft.threshold, cosigners: validated)
            }
            _ = try Vault(descriptor: descriptor, network: model.network) // validates the policy shape
            builtDescriptor = descriptor
        } catch {
            builtDescriptor = nil
            self.error = error.localizedDescription
        }
    }

    private func save(descriptor: Descriptor) {
        saving = true
        Task {
            do {
                _ = try await model.addVault(name: name.trimmingCharacters(in: .whitespaces),
                                             descriptor: descriptor)
                dismiss()
            } catch {
                self.error = error.localizedDescription
                saving = false
            }
        }
    }
}
