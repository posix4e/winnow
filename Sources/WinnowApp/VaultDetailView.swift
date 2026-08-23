import BitcoinCore
import BitcoinP2P
import SwiftUI
import UIKit
import WalletCore

/// One vault: receive address, tracked UTXOs, and the spend flow entry
/// points (creator role here, signer/combiner in `VaultSignView`).
struct VaultDetailView: View {
    let recordID: String
    @Environment(AppModel.self) private var model
    @State private var showSpend = false
    @State private var showSign = false

    private var record: VaultRecord? { model.vaults.first { $0.id == recordID } }

    var body: some View {
        List {
            if let record, let vault = try? Vault(record.descriptor, network: model.network) {
                Section("Receive") {
                    if let address = try? vault.address(index: record.nextReceiveIndex) {
                        HStack {
                            Spacer()
                            QRCodeView(content: address)
                                .frame(width: 180, height: 180)
                            Spacer()
                        }
                        CopyableTextBlock(text: address)
                        Button("New address") {
                            Task { await model.advanceVaultReceiveIndex(id: record.id) }
                        }
                    }
                }

                Section("Balance · confirmed") {
                    LabeledContent("Total", value: satsText(record.balance))
                    ForEach(Array(record.utxos.enumerated()), id: \.offset) { _, utxo in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(satsText(utxo.amount))
                            Text("\(utxo.txid.displayHex.prefix(16))…:\(utxo.vout) · \(utxo.height > 0 ? "block \(utxo.height)" : "awaiting confirmation")")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    if record.utxos.isEmpty {
                        Text("No funds found yet. Payments to the vault's addresses appear once they confirm in a block.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }

                Section {
                    Button("Create spend PSBT…") { showSpend = true }
                        .disabled(record.utxos.isEmpty)
                    Button("Sign / combine PSBTs…") { showSign = true }
                } footer: {
                    Text("Spends run as a PSBTv2 workflow: create here, partial-sign on each cosigner device, combine when enough partials are collected, then finalize and broadcast.")
                }
            } else {
                Text("This vault is no longer available.")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle(record?.name ?? "Vault")
        .sheet(isPresented: $showSpend) {
            VaultSpendView(recordID: recordID)
        }
        .sheet(isPresented: $showSign) {
            VaultSignView(recordID: recordID)
        }
    }
}

/// Creator role: destination + amount + feerate → the spend PSBT (Base64),
/// shared with the cosigners. Silent-payment destinations are not offered
/// from vaults — BIP352 output derivation needs the input keys aggregated,
/// which a k-of-n/n-of-n spend does not have at build time.
struct VaultSpendView: View {
    let recordID: String
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var destination = ""
    @State private var amountText = ""
    @State private var feeRateText = ""
    @State private var created: String?
    @State private var error: String?

    private var record: VaultRecord? { model.vaults.first { $0.id == recordID } }

    var body: some View {
        NavigationStack {
            Form {
                Section("Spend from vault") {
                    LabeledContent("Available", value: satsText(record?.balance ?? 0))
                    TextField("Destination address", text: $destination)
                        .font(.system(.footnote, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    TextField("Amount (sats)", text: $amountText)
                        .keyboardType(.numberPad)
                    TextField("Feerate (sat/vB)", text: $feeRateText)
                        .keyboardType(.decimalPad)
                }
                if let error {
                    Section { Text(error).foregroundStyle(.red).font(.footnote) }
                }
                Section {
                    Button("Create spend PSBT") { create() }
                        .disabled(destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                                  || Int64(amountText) == nil)
                }
                if let created {
                    Section {
                        CopyableTextBlock(text: created)
                    } header: {
                        Text("Spend PSBT")
                    } footer: {
                        Text("Share this with the cosigners. Each signs it in “Sign / combine PSBTs”; combine the partials there when enough are collected.")
                    }
                }
            }
            .navigationTitle("Create spend")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task {
                let rate = await model.resolvedFeeRate(priority: .medium, override: nil)
                feeRateText = rate.formatted(.number.precision(.fractionLength(0 ... 2)))
            }
        }
    }

    private func create() {
        error = nil
        created = nil
        guard let record, let vault = try? Vault(record.descriptor, network: model.network) else { return }
        let trimmed = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.lowercased().hasPrefix("sp1"), !trimmed.lowercased().hasPrefix("tsp1") else {
            error = "Silent payments from vaults are not supported — the vault has no single input key to derive the output from."
            return
        }
        do {
            guard let amount = Int64(amountText), amount > 0,
                  let feeRate = Double(feeRateText), feeRate > 0
            else {
                error = "Enter an amount in sats and a feerate in sat/vB."
                return
            }
            let payment = try Payment(amount: amount, address: trimmed, network: model.network)
            let psbt = try vault.createSpend(utxos: record.utxos, payments: [payment],
                                             changeIndex: record.nextChangeIndex,
                                             feeRateSatPerVByte: feeRate,
                                             chainTip: model.status.tipHeight)
            created = psbt.base64
            model.journalPSBT(stage: "vault-spend-created", psbt: psbt)
        } catch {
            self.error = error.localizedDescription
        }
    }
}
