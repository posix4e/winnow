import VaultKit
import WalletCore
import SwiftUI

/// One approving key of shared savings: who it is, and its fingerprint for
/// comparing with that person's own phone. A key nobody in the address book
/// holds is named as such, in red, rather than left off the list.
struct SignerKeyRow: View {
    let signer: AppModel.SharedSavings.Signer

    private var name: String {
        if signer.isYou { return "you" }
        return signer.name ?? "Not one of your people"
    }

    var body: some View {
        HStack {
            Text(name)
                .foregroundStyle(signer.isYou || signer.name != nil ? Color.primary : Color.red)
            Spacer()
            Text(signer.fingerprint)
                .font(.system(.footnote, design: .monospaced))
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("savingsSigner-\(signer.fingerprint)")
    }
}

/// Shared account controls; the descriptor chooses the approval method.
struct AccountDetailView: View {
    let recordID: String
    var send: () -> Void
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var showSigning = false
    @State private var showBackup = false
    @State private var showShare = false
    @State private var confirmRemove = false

    private var record: VaultRecord? { model.vaults.first { $0.id == recordID } }
    private var savings: AppModel.SharedSavings? { model.sharedSavings.first { $0.id == recordID } }

    private func maturityNote(for utxo: WalletUTXO) -> String {
        guard utxo.isCoinbase, utxo.height > 0 else { return "" }
        let matureAt = utxo.height + Wallet.coinbaseMaturity - 1
        guard model.status.tipHeight < matureAt else { return "" }
        return " · matures in \(matureAt - model.status.tipHeight) blocks"
    }

    var body: some View {
        List {
            if let record, let vault = try? model.vault(for: record) {
                Section("Receive") {
                    if let address = try? vault.address(index: record.nextReceiveIndex) {
                        HStack {
                            Spacer()
                            QRCodeView(content: address)
                                .frame(width: 180, height: 180)
                            Spacer()
                        }
                        CopyableTextBlock(text: address)
                            .accessibilityIdentifier("accountReceiveAddress")
                        Button("New address") {
                            Task { await model.advanceVaultReceiveIndex(id: record.id) }
                        }
                    }
                }

                Section("Balance · confirmed") {
                    LabeledContent("Total") {
                        Text(satsText(record.balance))
                            .accessibilityIdentifier("accountBalance")
                    }
                    if record.utxos.isEmpty {
                        Text("No money in yet. Payments to this account appear once they confirm in a block.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }

                VaultPolicySection(vault: vault)

                Section {
                    Button("Send", action: send)
                        .accessibilityIdentifier("sendFromAccountButton")
                        .disabled(record.utxos.isEmpty)
                    Button(vault.isScriptPath ? "Approve a request" : "Continue signing") { showSigning = true }
                        .accessibilityIdentifier(vault.isScriptPath ? "approveRequestButton" : "continueSigningButton")
                } footer: {
                    Text(vault.isScriptPath
                         ? "Send prepares a payment for the co-owners to approve. To approve someone else’s payment, open their request."
                         : "Create a payment, then exchange approvals with the other signer.")
                }

                Section {
                    Button("Back up this wallet") { showBackup = true }
                        .accessibilityIdentifier("accountBackupButton")
                } footer: {
                    Text("Save the wallet backup file and your recovery phrase. Each other signer needs its own key backup. A backup cannot replace a missing signer’s key.")
                }

                if vault.isScriptPath {
                    Section {
                        if let savings {
                            Text(([savings.includesYou ? "you" : nil].compactMap { $0 } + savings.coOwners.map(\.name)).joined(separator: ", "))
                                .accessibilityIdentifier("savingsCoOwners")
                            ForEach(savings.signers) { signer in
                                SignerKeyRow(signer: signer)
                            }
                        }
                        Button("Share the savings card") { showShare = true }
                            .accessibilityIdentifier("shareSavingsCardButton")
                    } header: {
                        Text("Co-owners")
                    } footer: {
                        Text("Every key that can approve a payment, with its fingerprint. Compare each with the card its owner shows you; a key that is not one of your people can approve payments all the same.")
                    }
                }

                if model.advancedMode {
                    Section {
                        DisclosureGroup("Technical details") {
                            CopyableTextBlock(text: record.descriptor)
                            ForEach(Array(record.utxos.enumerated()), id: \.offset) { _, utxo in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(satsText(utxo.amount))
                                    Text("\(utxo.txid.displayHex.prefix(16))…:\(utxo.vout) · \(utxo.height > 0 ? "block \(utxo.height)" : "awaiting confirmation")\(maturityNote(for: utxo))")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }

                if vault.isScriptPath {
                    Section {
                        Button("Remove from this phone", role: .destructive) { confirmRemove = true }
                            .accessibilityIdentifier("removeSavingsButton")
                    } footer: {
                        Text("Forgets these savings here. The money stays where it is; other co-owners keep their copies, and the card adds it back.")
                    }
                }
            } else {
                Text("This account is no longer on this phone.")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle(record?.name ?? "Account")
        .sheet(isPresented: $showSigning) {
            if let record, let vault = try? model.vault(for: record) {
                if vault.isScriptPath {
                    ApprovalView(recordID: recordID)
                } else {
                    MuSig2SignView(recordID: recordID)
                }
            }
        }
        .sheet(isPresented: $showBackup) { ExportBundleView() }
        .sheet(isPresented: $showShare) {
            if let record {
                NavigationStack {
                    SharedSavingsShareView(record: record)
                        .navigationTitle("Savings card")
                        .toolbar {
                            ToolbarItem(placement: .confirmationAction) {
                                Button("Done") { showShare = false }
                            }
                        }
                }
            }
        }
        .confirmationDialog("Remove these savings from this phone?", isPresented: $confirmRemove) {
            Button("Remove", role: .destructive) {
                Task {
                    await model.removeVault(id: recordID)
                    dismiss()
                }
            }
            Button("Cancel", role: .cancel) {}
        }
    }
}

/// Read from the spending descriptor, never from a label or imported claim.
struct VaultPolicySection: View {
    let vault: Vault

    var body: some View {
        Section {
            Text("\(vault.threshold) of \(vault.signerCount) signing keys required")
                .accessibilityIdentifier("vaultRequiredKeys")
            Text(vault.isScriptPath ? "Shared control" : "Every signing key")
                .accessibilityIdentifier("vaultPolicyPurpose")
            Text(vault.threshold == 1
                 ? "One signing key can spend these funds."
                 : "One signing key cannot spend these funds.")
                .accessibilityIdentifier("vaultSingleKeyRule")
            DisclosureGroup("What this policy proves") {
                Text(vault.isScriptPath
                     ? "The spending script enforces the threshold, with no secret key that bypasses it. A spend reveals the script and threshold on chain; the receiving address alone does not."
                     : "MuSig2 requires every participating key and produces one Taproot key-path signature. The signature itself does not reveal how many devices participated. There is no recovery path if a required key and its backups are lost.")
                Text("Names and cards do not enforce protection. The policy cannot prove who has key copies, where they are kept, or safety from physical coercion.")
            }
            .font(.footnote)
        } header: {
            Text("Signing policy")
        }
    }
}
