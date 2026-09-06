import BitcoinCore
import BitcoinP2P
import SwiftUI
import UIKit
import WalletCore

/// The People tab: the address book, the savings shared with the people in
/// it, and, in Advanced mode, the raw vault list behind those savings.
struct PeopleView: View {
    @Environment(AppModel.self) private var model
    @State private var showAddPerson = false
    @State private var showShareCard = false
    @State private var showCreateSavings = false
    @State private var showAddSavings = false
    @State private var approveRecordID: String?

    var body: some View {
        NavigationStack {
            List {
                if let notice = model.peopleStorageNotice {
                    Section {
                        Text(notice)
                            .font(.footnote)
                            .foregroundStyle(.red)
                            .accessibilityIdentifier("peopleStorageNotice")
                    }
                }

                Section {
                    ForEach(model.sharedSavings) { savings in
                        NavigationLink(destination: SharedSavingsDetailView(recordID: savings.id)) {
                            SharedSavingsRow(savings: savings)
                        }
                        .accessibilityIdentifier("sharedSavingsRow")
                    }
                    Button("New shared savings") { showCreateSavings = true }
                        .accessibilityIdentifier("newSharedSavingsButton")
                    Button("Add from a card") { showAddSavings = true }
                        .accessibilityIdentifier("addSharedSavingsButton")
                    if let first = model.sharedSavings.first {
                        Button("Approve a request") {
                            approveRecordID = model.sharedSavings.count == 1 ? first.id : nil
                            if model.sharedSavings.count == 1 { approveRecordID = first.id }
                        }
                        .accessibilityIdentifier("approveRequestButton")
                        .disabled(model.sharedSavings.count != 1)
                    }
                } header: {
                    Text("Shared savings")
                } footer: {
                    Text(model.sharedSavings.isEmpty
                         ? "Money in shared savings moves only when enough co-owners approve. Create some with people who have a signer key, or add savings someone shared with you."
                         : (model.sharedSavings.count == 1
                            ? "Requests to approve arrive from co-owners as text; paste them here."
                            : "To approve a request, open the savings it belongs to."))
                }

                Section {
                    if model.people.isEmpty {
                        Text("Add the people you pay and save with. A person's card carries the keys Winnow needs to pay them a fresh address every time, and to hold money together.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .accessibilityIdentifier("peopleEmptyState")
                    }
                    ForEach(model.people) { person in
                        NavigationLink(destination: PersonDetailView(personID: person.id)) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(person.name)
                                Text(PersonDetailView.summary(for: person))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .accessibilityIdentifier("personRow-\(person.name)")
                    }
                    .onDelete { offsets in
                        let ids = offsets.map { model.people[$0].id }
                        Task { for id in ids { try? await model.removePerson(id: id) } }
                    }
                } header: {
                    Text("People")
                }

                if model.advancedMode {
                    VaultsSection()
                }
            }
            .navigationTitle("People")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Share my card") { showShareCard = true }
                        .accessibilityIdentifier("shareMyCardButton")
                        .disabled(model.walletID == nil)
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("Add person") { showAddPerson = true }
                        .accessibilityIdentifier("addPersonButton")
                        .disabled(model.peopleStorageNotice != nil)
                }
            }
            .sheet(isPresented: $showAddPerson) { AddPersonView() }
            .sheet(isPresented: $showShareCard) { ShareMyCardView() }
            .sheet(isPresented: $showCreateSavings) { SharedSavingsCreateView() }
            .sheet(isPresented: $showAddSavings) { AddSharedSavingsView() }
            .sheet(item: Binding(
                get: { approveRecordID.map { ApproveTarget(id: $0) } },
                set: { approveRecordID = $0?.id }
            )) { target in
                ApprovalView(recordID: target.id)
            }
        }
    }

    private struct ApproveTarget: Identifiable {
        let id: String
    }
}

struct SharedSavingsRow: View {
    let savings: AppModel.SharedSavings

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(savings.name)
                Text(Self.caption(for: savings))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(satsText(savings.balance))
                .font(.subheadline)
        }
    }

    static func caption(for savings: AppModel.SharedSavings) -> String {
        var parts = ["\(savings.threshold) of \(savings.signerCount) must approve"]
        var owners: [String] = []
        if savings.includesYou { owners.append("you") }
        owners += savings.coOwners.map(\.name)
        if !owners.isEmpty { parts.append("with " + owners.joined(separator: ", ")) }
        if savings.unknownSignerCount > 0 {
            parts.append("\(savings.unknownSignerCount) co-owner\(savings.unknownSignerCount == 1 ? "" : "s") not in People")
        }
        return parts.joined(separator: " · ")
    }
}

/// Name plus whatever was pasted: a card, a key, or an address. What was
/// understood is shown before saving, so a paste that gives one fixed
/// address is seen to be that.
struct AddPersonView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var pasted = ""
    @State private var parsed: PersonImport?
    @State private var parseError: String?
    @State private var saveError: String?
    @State private var saving = false

    private var effectiveName: String {
        let typed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return typed.isEmpty ? (parsed?.name ?? "") : typed
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $name)
                        .accessibilityIdentifier("personNameField")
                    TextField("Paste a card, key or address", text: $pasted, axis: .vertical)
                        .font(.system(.caption, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .accessibilityIdentifier("personPasteField")
                    Button("Paste from clipboard") {
                        pasted = UIPasteboard.general.string ?? ""
                    }
                    .accessibilityIdentifier("personPasteButton")
                } footer: {
                    Text("Their Winnow card gives you both a fresh address for every payment and the key to hold savings together. A public account key does the same; a plain address is reused every time.")
                }

                if let parsed {
                    Section("What Winnow understood") {
                        if let payTo = parsed.payTo {
                            Label(payTo.derivesFreshAddresses ? "Fresh address each payment" : "Single address — reused every time",
                                  systemImage: payTo.derivesFreshAddresses ? "arrow.triangle.2.circlepath" : "eye")
                                .foregroundStyle(payTo.derivesFreshAddresses ? Color.primary : Color.orange)
                                .accessibilityIdentifier("personPayToSummary")
                        } else {
                            Label("No pay-to key: you cannot pay this person yet", systemImage: "minus.circle")
                                .foregroundStyle(.secondary)
                        }
                        Label(parsed.signerKey != nil ? "Can co-own savings" : "Cannot co-own savings — ask for a Winnow card",
                              systemImage: parsed.signerKey != nil ? "lock.shield" : "lock.slash")
                            .foregroundStyle(parsed.signerKey != nil ? Color.primary : Color.secondary)
                            .accessibilityIdentifier("personSignerSummary")
                    }
                }

                if let message = parseError ?? saveError {
                    Section {
                        Text(message)
                            .foregroundStyle(.red)
                            .font(.footnote)
                            .accessibilityIdentifier("personError")
                    }
                }

                Section {
                    Button(saving ? "Saving…" : "Save") { save() }
                        .accessibilityIdentifier("savePersonButton")
                        .disabled(saving || parsed == nil || effectiveName.isEmpty)
                }
            }
            .navigationTitle("Add person")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onChange(of: pasted) { _, text in parse(text) }
        }
    }

    private func parse(_ text: String) {
        saveError = nil
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            parsed = nil
            parseError = nil
            return
        }
        do {
            parsed = try PersonPaste.parse(trimmed, network: model.network)
            parseError = nil
        } catch {
            parsed = nil
            parseError = error.localizedDescription
        }
    }

    private func save() {
        guard let parsed else { return }
        saving = true
        saveError = nil
        Task {
            do {
                try await model.addPerson(name: effectiveName, payTo: parsed.payTo, signerKey: parsed.signerKey)
                dismiss()
            } catch {
                saveError = error.localizedDescription
            }
            saving = false
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
                    } header: {
                        Text("Your card")
                    } footer: {
                        Text("This card carries public keys only. Anyone who has it can pay you and can see every address it derives, the same way your wallet does. People who pay you from their address book use the same list of addresses as your Receive screen, so two people paying at once can land on one address — a privacy detail, never a loss.")
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

/// One person: how they can be paid, whether they can hold savings, the
/// savings they share, and the way to pay them.
struct PersonDetailView: View {
    let personID: String
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var showPay = false
    @State private var confirmRemove = false

    private var person: PersonRecord? { model.people.first { $0.id == personID } }

    private var savings: [AppModel.SharedSavings] {
        model.sharedSavings.filter { savings in savings.coOwners.contains { $0.id == personID } }
    }

    static func summary(for person: PersonRecord) -> String {
        var parts: [String] = []
        if let payTo = person.payTo {
            parts.append(payTo.derivesFreshAddresses ? "Fresh address each payment" : "Single address — reused")
        }
        if person.canCoOwnSavings { parts.append("Can co-own savings") }
        return parts.isEmpty ? "No keys" : parts.joined(separator: " · ")
    }

    var body: some View {
        List {
            if let person {
                Section {
                    if let payTo = person.payTo {
                        Label(payTo.derivesFreshAddresses ? "Fresh address each payment" : "Single address — reused every time",
                              systemImage: payTo.derivesFreshAddresses ? "arrow.triangle.2.circlepath" : "eye")
                            .foregroundStyle(payTo.derivesFreshAddresses ? Color.primary : Color.orange)
                        Button("Pay \(person.name)") { showPay = true }
                            .accessibilityIdentifier("payPersonButton")
                            .disabled(model.walletID == nil)
                    } else {
                        Text("No pay-to key yet. Ask \(person.name) for their Winnow card to pay them.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Label(person.canCoOwnSavings ? "Can co-own savings" : "Cannot co-own savings — ask for a Winnow card",
                          systemImage: person.canCoOwnSavings ? "lock.shield" : "lock.slash")
                        .foregroundStyle(person.canCoOwnSavings ? Color.primary : Color.secondary)
                }

                Section("Shared savings with \(person.name)") {
                    if savings.isEmpty {
                        Text(person.canCoOwnSavings
                             ? "None yet. Create shared savings from the People tab and pick \(person.name) as a co-owner."
                             : "\(person.name) needs a signer key first.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(savings) { entry in
                        NavigationLink(destination: SharedSavingsDetailView(recordID: entry.id)) {
                            SharedSavingsRow(savings: entry)
                        }
                    }
                }

                if model.advancedMode {
                    Section("Details for experts") {
                        if let payTo = person.payTo {
                            LabeledContent("Pay-to") { Text(payTo.derivesFreshAddresses ? "descriptor" : "address") }
                            CopyableTextBlock(text: payTo.text)
                            LabeledContent("Next payment index", value: String(person.nextPaymentIndex))
                        }
                        if let signerKey = person.signerKey {
                            LabeledContent("Signer key") { Text("script path") }
                            CopyableTextBlock(text: signerKey)
                        }
                    }
                }

                Section {
                    Button("Remove \(person.name)", role: .destructive) { confirmRemove = true }
                        .accessibilityIdentifier("removePersonButton")
                } footer: {
                    Text("Removing a person forgets their keys on this phone. Savings you share with them stay, and still need their approval.")
                }
            } else {
                Text("This person is no longer in your list.")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle(person?.name ?? "Person")
        .sheet(isPresented: $showPay) {
            if let person { SendView(recipient: person) }
        }
        .confirmationDialog("Remove \(person?.name ?? "this person")?", isPresented: $confirmRemove) {
            Button("Remove", role: .destructive) {
                Task {
                    try? await model.removePerson(id: personID)
                    dismiss()
                }
            }
            Button("Cancel", role: .cancel) {}
        }
    }
}
