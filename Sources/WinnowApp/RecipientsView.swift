import VaultKit
import WalletCore
import SwiftUI
import UIKit

struct SavedRecipientsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var choose: (PersonRecord) -> Void
    @State private var adding = false
    @State private var editing: PersonRecord?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                if let notice = model.peopleStorageNotice ?? error {
                    Text(notice).foregroundStyle(.red).accessibilityIdentifier("recipientError")
                }
                if model.people.filter({ $0.savedRecipient != false }).isEmpty {
                    Text("Save a recipient from a payment in Wallet, or add an address or card here.")
                        .foregroundStyle(.secondary)
                }
                ForEach(model.people.filter { $0.savedRecipient != false }) { person in
                    Button(person.payTo == nil ? "\(person.name) — add destination" : person.name) {
                        if person.payTo == nil { editing = person }
                        else { choose(person); dismiss() }
                    }
                        .accessibilityIdentifier("chooseRecipient-\(person.name)")
                        .swipeActions(edge: .leading) {
                            Button("Rename") { editing = person }
                        }
                        .swipeActions {
                            Button("Remove", role: .destructive) { remove(person) }
                        }
                        .contextMenu {
                            Button("Rename") { editing = person }
                            Button("Remove from saved", role: .destructive) { remove(person) }
                        }
                }
            }
            .navigationTitle("Saved recipients")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } }
                ToolbarItem(placement: .primaryAction) {
                    Button("Add") { adding = true }
                        .accessibilityIdentifier("addRecipientButton")
                        .disabled(model.peopleStorageNotice != nil)
                }
            }
            .sheet(isPresented: $adding) { AddPersonView() }
            .sheet(item: $editing) { AddPersonView(person: $0) }
        }
    }

    private func remove(_ person: PersonRecord) {
        Task {
            do { try await model.updateRecipient(id: person.id, saved: false) }
            catch { self.error = error.localizedDescription }
        }
    }
}

/// One editor for a saved recipient, a payment's address, or a co-owner's card.
/// With `txid` set it labels a received payment instead: a name is enough on
/// its own, and the funding addresses the payment itself reveals — or the
/// explicitly tapped explorer lookup — can be attached to the person.
struct AddPersonView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    var person: PersonRecord?
    var forSigning = false
    /// The received payment being labelled, when this sheet is a sender flow.
    var txid: Data?
    /// Offline-reconstructed funding addresses (WalletCore `FundingSources`).
    var senderCandidates: [AppModel.SenderCandidate] = []
    @State private var name: String
    @State private var pasted: String
    @State private var error: String?
    @State private var saving = false
    @State private var confirmInfer = false
    @State private var lookupConsent: AppModel.ExplorerLookupConsent?
    @State private var inferredSource: String?
    @State private var inferring = false
    @State private var inferredAddresses: [String] = []
    @State private var lookupTask: Task<Void, Never>?
    @State private var selectedFundingAddress: String?
    @State private var selectedFundingProvenance: PersonRecord.DestinationProvenance?

    init(person: PersonRecord? = nil, address: String = "", forSigning: Bool = false,
         txid: Data? = nil, senderCandidates: [AppModel.SenderCandidate] = []) {
        self.person = person
        self.forSigning = forSigning
        self.txid = txid
        self.senderCandidates = senderCandidates
        _name = State(initialValue: person?.name ?? "")
        _pasted = State(initialValue: address)
    }

    private var labelingSender: Bool { txid != nil && person == nil }
    private var choosingFundingDestination: Bool { txid != nil && person?.payTo == nil }
    private var explorerHost: String { model.esploraBaseURL.host ?? "the explorer" }

    private var parsed: PersonImport? { try? PersonPaste.parse(pasted, network: model.network) }
    private var effectiveName: String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? parsed?.name ?? "" : trimmed
    }
    private var canSave: Bool {
        guard !saving, !effectiveName.isEmpty else { return false }
        if !pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, parsed == nil { return false }
        if person != nil { return true }
        if labelingSender { return true } // a name alone is a valid label
        return forSigning ? parsed?.signerKey != nil : parsed?.payTo != nil
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $name).accessibilityIdentifier("personNameField")
                    if person?.payTo == nil {
                        TextField(forSigning ? "Paste a card or signer key" : "Paste an address or card",
                                  text: $pasted, axis: .vertical)
                            .autocorrectionDisabled().textInputAutocapitalization(.never)
                            .accessibilityIdentifier("personPasteField")
                        Button("Paste from clipboard") { pasted = model.pasteboardText() ?? "" }
                            .accessibilityIdentifier("personPasteButton")
                    }
                }
                if labelingSender, !model.people.isEmpty {
                    Section("Or choose someone saved") {
                        ForEach(model.people) { saved in
                            Button(saved.name) { choose(saved) }
                                .accessibilityIdentifier("chooseSenderPerson-\(saved.name)")
                        }
                    }
                }
                if choosingFundingDestination, !senderCandidates.isEmpty {
                    Section {
                        ForEach(senderCandidates) { candidate in
                            Button(candidate.address) {
                                pasted = candidate.address
                                selectedFundingAddress = candidate.address
                                selectedFundingProvenance = .localFunding
                            }
                                .font(.system(.footnote, design: .monospaced))
                                .accessibilityIdentifier("senderCandidate-\(candidate.id)")
                        }
                    } header: {
                        Text("Funding addresses this payment reveals")
                    } footer: {
                        Text(Self.fundingWarning)
                            .accessibilityIdentifier("senderCandidateWarning")
                    }
                }
                if choosingFundingDestination, senderCandidates.isEmpty {
                    Section {
                        Button(inferring ? "Looking up…" : "Find funding addresses with \(explorerHost)") {
                            if let txid { lookupConsent = model.senderLookupConsent(txid: txid) }
                            confirmInfer = true
                        }
                        .accessibilityIdentifier("inferSenderButton")
                        .disabled(inferring)
                    } footer: {
                        Text("The locally stored payment does not reveal a funding address. You can request unverified funding addresses from \(explorerHost) after reviewing what the lookup discloses.")
                    }
                }
                if !inferredAddresses.isEmpty {
                    Section {
                        ForEach(inferredAddresses, id: \.self) { address in
                            Button(address) {
                                pasted = address
                                selectedFundingAddress = address
                                selectedFundingProvenance = .explorerFunding
                            }
                                .font(.system(.footnote, design: .monospaced))
                                .accessibilityIdentifier("inferredSender-\(address)")
                        }
                    } header: {
                        Text("Funded by, according to \(explorerHost)")
                    } footer: {
                        Text(Self.fundingWarning)
                    }
                }
                if let parsed, person == nil {
                    Section {
                        if let payTo = parsed.payTo {
                            Text(payTo.derivesFreshAddresses ? "Fresh address each payment" : "Uses this same address each time")
                                .accessibilityIdentifier("personPayToSummary")
                        }
                        if forSigning {
                            Text(parsed.signerKey != nil ? "Can approve shared payments" : "Ask for their signer key or Winnow card")
                                .accessibilityIdentifier("personSignerSummary")
                        }
                    }.font(.footnote).foregroundStyle(.secondary)
                }
                if let error { Text(error).foregroundStyle(.red).accessibilityIdentifier("personError") }
                Section {
                    Button(saving ? "Saving…" : "Save") { save() }
                        .accessibilityIdentifier("savePersonButton").disabled(!canSave)
                }
            }
            .navigationTitle(navigationTitle)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
            .onDisappear { lookupTask?.cancel() }
            .onChange(of: pasted) { _, text in
                error = nil
                guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
                do { _ = try PersonPaste.parse(text, network: model.network) }
                catch { self.error = error.localizedDescription }
            }
            .confirmationDialog("Look up funding addresses with \(explorerHost)?",
                                isPresented: $confirmInfer, titleVisibility: .visible) {
                Button("Look up with \(explorerHost)") { infer() }
                    .accessibilityIdentifier("confirmInferSenderButton")
                Button("Cancel", role: .cancel) {}
            } message: {
                Text((lookupConsent?.disclosure ?? "No lookup selected.") + " Funding addresses do not establish who sent the payment or where they want a payment sent.")
            }
        }
    }

    private var navigationTitle: String {
        if labelingSender { return "Save sender" }
        if let person, person.payTo == nil { return "Add destination for \(person.name)" }
        return person?.isSavedRecipient == true ? "Rename recipient" : forSigning ? "Add co-owner" : "Save recipient"
    }

    /// Shown wherever a guessed funding address could be attached.
    private static let fundingWarning =
        "A funding address is unverified as a destination for this person. Exchanges, coinjoins and shared wallets can make it misleading. Select one only after checking with the person. Sending to it reuses an address; ask for a fresh address or payment card."

    private func choose(_ saved: PersonRecord) {
        guard let txid else { return }
        saving = true
        Task {
            defer { saving = false }
            do {
                try await model.labelReceivedSender(txid: txid, personID: saved.id)
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }

    private func infer() {
        guard let lookupConsent else { return }
        inferring = true
        lookupTask = Task {
            defer { inferring = false }
            do {
                let addresses = try await model.lookupSenderOnline(consent: lookupConsent)
                inferredSource = lookupConsent.baseURL.absoluteString
                inferredAddresses = addresses
                try Task.checkCancellation()
            } catch { self.error = error.localizedDescription }
        }
    }

    private var destinationProvenance: PersonRecord.DestinationProvenance? {
        guard parsed?.payTo != nil else { return nil }
        return pasted == selectedFundingAddress ? selectedFundingProvenance : .supplied
    }

    private var destinationSource: String? {
        switch destinationProvenance {
        case .localFunding: txid?.displayHex
        case .explorerFunding: inferredSource
        default: nil
        }
    }

    private func save() {
        saving = true
        Task {
            defer { saving = false }
            do {
                if let person {
                    if person.payTo == nil, let payTo = parsed?.payTo {
                        try await model.attachDestination(id: person.id, payTo: payTo,
                                                          provenance: destinationProvenance ?? .supplied,
                                                          source: destinationSource)
                    }
                    try await model.updateRecipient(id: person.id, name: effectiveName, saved: true)
                } else if labelingSender {
                    let record = try await model.addPerson(name: effectiveName, payTo: parsed?.payTo,
                                                           signerKey: nil,
                                                           provenance: destinationProvenance,
                                                           source: destinationSource)
                    try await model.labelReceivedSender(txid: txid!, personID: record.id)
                } else if let parsed {
                    try await model.addPerson(name: effectiveName, payTo: parsed.payTo, signerKey: parsed.signerKey)
                }
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }
}

/// This wallet's card: public keys only, plus the name others will see.
struct ShareMyCardView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""

    private var cardText: String? {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return try? model.ownPersonCard(name: trimmed).serialized()
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Your name, as others will see it", text: $name)
                        .accessibilityIdentifier("ownNameField")
                }
                if let cardText {
                    Section {
                        HStack {
                            Spacer()
                            QRCodeView(content: cardText)
                                .frame(width: 200, height: 200)
                            Spacer()
                        }
                        CopyableTextBlock(text: cardText)
                            .accessibilityIdentifier("ownCardBlock")
                        if let fingerprint = model.ownSignerFingerprint {
                            LabeledContent("Your key") {
                                Text(fingerprint).font(.system(.body, design: .monospaced))
                            }
                            .accessibilityIdentifier("ownSignerFingerprint")
                        }
                    } header: {
                        Text("Your card")
                    } footer: {
                        Text("This card carries public keys only. Anyone who has it can pay you and can see every address it derives, the same way your wallet does. People who pay you from their address book use the same list of addresses as your Receive screen, so two people paying at once can land on one address — a privacy detail, never a loss. Your key’s fingerprint is what a co-owner sees next to your name; if theirs reads differently, the card they hold is not yours.")
                    }
                } else {
                    Section {
                        Text("Add a name to make your card.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Share my card")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear {
                name = model.ownDisplayName
                model.journalCardShared()
            }
            .onChange(of: name) { _, value in model.setOwnDisplayName(value) }
        }
    }
}
