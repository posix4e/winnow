@testable import WinnowApp
import BitcoinCore
import BitcoinP2P
import WalletCore
import XCTest

/// How people reach the send review and how vaults become shared savings.
@MainActor
final class PeoplePaymentTests: XCTestCase {
    private final class SilentAuthenticator: DeviceAuthenticating {
        func authenticate(reason: String) async throws {}
    }

    private var savedNetwork: String?

    override func setUp() {
        super.setUp()
        savedNetwork = UserDefaults.standard.string(forKey: AppModel.DefaultsKey.network)
        UserDefaults.standard.set(BitcoinNetwork.signet.rawValue, forKey: AppModel.DefaultsKey.network)
    }

    override func tearDown() {
        if let savedNetwork {
            UserDefaults.standard.set(savedNetwork, forKey: AppModel.DefaultsKey.network)
        } else {
            UserDefaults.standard.removeObject(forKey: AppModel.DefaultsKey.network)
        }
        super.tearDown()
    }

    func testAReviewIsInvalidatedByTheRecipientOrTheirAddressIndex() {
        let base = SendReviewInputs(destination: "", amountText: "1000", priority: .medium,
                                    overrideText: "", network: .signet, personID: "alice", paymentIndex: 3)
        XCTAssertNotEqual(base, SendReviewInputs(destination: "", amountText: "1000", priority: .medium,
                                                 overrideText: "", network: .signet, personID: "bob", paymentIndex: 3))
        XCTAssertNotEqual(base, SendReviewInputs(destination: "", amountText: "1000", priority: .medium,
                                                 overrideText: "", network: .signet, personID: "alice", paymentIndex: 4))
        XCTAssertEqual(SendReviewInputs(destination: "tb1p", amountText: "1", priority: .low,
                                        overrideText: "", network: .signet).personID, nil)
    }

    func testSharedSavingsAreDerivedFromSignerKeysWhetherOrNotPeopleAreKnown() async throws {
        let model = AppModel(deviceAuthenticator: SilentAuthenticator())
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("people-payment-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        await model.vaultStore.configure(storageURL: directory.appendingPathComponent("vaults.json"), network: .signet)
        await model.peopleStore.configure(storageURL: directory.appendingPathComponent("people.json"), network: .signet)

        let masters = try [0xA1, 0xB2, 0xC3].map { byte -> HDKey in
            try HDKey(seed: BIP39.seed(mnemonic: BIP39.mnemonic(entropy: Data(repeating: UInt8(byte), count: 16))))
        }
        let keys = try masters.map { master -> String in
            let account = try master.derived(path: "m/86'/1'/0'")
            return "[\(String(format: "%08x", master.fingerprint))/86'/1'/0']\(account.neutered.serialized(network: .testnet))/<0;1>/*"
        }
        let descriptor = try Vault.multiADescriptor(threshold: 2, cosigners: keys)
        try await model.vaultStore.add(name: "Savings with Alice, Bob", descriptor: descriptor, createdAtHeight: 0)
        await model.refresh()

        // No people yet: the vault still shows, with every signer unaccounted for.
        XCTAssertEqual(model.sharedSavings.count, 1)
        XCTAssertEqual(model.sharedSavings[0].coOwners, [])
        XCTAssertEqual(model.sharedSavings[0].unknownSignerCount, 3)
        XCTAssertEqual(model.sharedSavings[0].threshold, 2)
        XCTAssertEqual(model.sharedSavings[0].signerCount, 3)
        XCTAssertFalse(model.sharedSavings[0].includesYou, "no wallet is open, so no own key")

        // Two of the three signers become people; the vault finds them by key.
        try await model.addPerson(name: "Alice", payTo: nil, signerKey: keys[0])
        try await model.addPerson(name: "Bob", payTo: nil, signerKey: keys[2].replacingOccurrences(of: "'", with: "h"))
        XCTAssertEqual(model.sharedSavings[0].coOwners.map(\.name), ["Alice", "Bob"])
        XCTAssertEqual(model.sharedSavings[0].unknownSignerCount, 1)
        XCTAssertEqual(SharedSavingsRow.caption(for: model.sharedSavings[0]),
                       "2 of 3 must approve · with Alice, Bob · 1 co-owner not in People")

        // Removing a person cannot dangle: the vault simply loses a name.
        try await model.removePerson(id: model.people[0].id)
        XCTAssertEqual(model.sharedSavings[0].coOwners.map(\.name), ["Bob"])
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.appendingPathComponent("people.json").path))

        // A person needs a signer key to co-own savings; a pay-to-only person is refused.
        let payOnly = try await model.addPerson(
            name: "Carol", payTo: try PersonPayTo.descriptor("tr(\(keys[1]))", network: .signet), signerKey: nil)
        do {
            _ = try await model.createSharedSavings(name: "x", coOwners: [payOnly], threshold: 1)
            XCTFail("a person without a signer key co-owned savings")
        } catch AppModel.AppError.personCannotCoOwn(let name) {
            XCTAssertEqual(name, "Carol")
        }
        // Paying Carol peeks index 0 and never moves it on its own.
        let (address, index) = try model.nextPaymentAddress(for: payOnly)
        XCTAssertEqual(index, 0)
        XCTAssertTrue(address.hasPrefix("tb1p"))
        XCTAssertEqual(try model.nextPaymentAddress(for: payOnly).address, address)
        await model.advancePersonPaymentIndex(id: payOnly.id, past: 0)
        XCTAssertEqual(model.people.first { $0.id == payOnly.id }?.nextPaymentIndex, 1)
        XCTAssertNotEqual(try model.nextPaymentAddress(for: model.people.first { $0.id == payOnly.id }!).address, address)
        XCTAssertEqual(model.personScripts().values.filter { $0 == "Carol" }.count, Int(1 + Wallet.gapLimit))
    }

    func testAnApprovalRequestForUnknownSavingsIsRefusedByName() async throws {
        let model = AppModel(deviceAuthenticator: SilentAuthenticator())
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("people-approval-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        await model.vaultStore.configure(storageURL: directory.appendingPathComponent("vaults.json"), network: .signet)
        let masters = try [0xA1, 0xB2].map { byte -> HDKey in
            try HDKey(seed: BIP39.seed(mnemonic: BIP39.mnemonic(entropy: Data(repeating: UInt8(byte), count: 16))))
        }
        let keys = try masters.map { master -> String in
            let account = try master.derived(path: "m/86'/1'/0'")
            return "[\(String(format: "%08x", master.fingerprint))/86'/1'/0']\(account.neutered.serialized(network: .testnet))/<0;1>/*"
        }
        let record = try await model.vaultStore.add(name: "Ours", descriptor: Vault.multiADescriptor(threshold: 2, cosigners: keys),
                                                    createdAtHeight: 0)
        await model.refresh()
        let session = VaultSpendSession(model: model, recordID: record.id)
        let stray = ApprovalRequest(network: .signet, vault: "deadbeef", name: "Someone else's",
                                    psbt: PSBT(globals: [], inputs: [], outputs: []))
        session.add(text: try stray.serialized())
        XCTAssertEqual(session.working, nil)
        XCTAssertTrue(session.error?.contains("Someone else's") == true, session.error ?? "")
        XCTAssertTrue(session.error?.contains("not on this phone") == true)
        session.add(text: "garbage")
        XCTAssertNotNil(session.error)
        XCTAssertEqual(session.threshold, 2)
    }
}
