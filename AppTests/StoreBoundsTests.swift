@testable import WinnowApp
import WalletCore
import XCTest

/// The people store measures their file before reading it and
/// refuse a name that is not short and single-line — the two bounds the
/// independent review of 2026-09-14 found missing (IR-016, IR-031).
final class StoreBoundsTests: XCTestCase {
    /// A sparse file of the given logical size: what the size check sees.
    private func sparseFile(bytes: Int) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-store-bounds-\(UUID().uuidString).json")
        XCTAssertTrue(FileManager.default.createFile(atPath: url.path, contents: nil))
        let handle = try FileHandle(forWritingTo: url)
        try handle.truncate(atOffset: UInt64(bytes))
        try handle.close()
        return url
    }

    func testOversizedPeopleFileFailsClosed() async throws {
        let keys = InMemoryStoreKeyVault()
        let url = try sparseFile(bytes: PeopleStore.maximumFileBytes + 1)
        defer { try? FileManager.default.removeItem(at: url) }
        let store = PeopleStore(keys: keys)
        guard case .damaged = await store.configure(storageURL: url, network: .signet) else {
            return XCTFail("an oversized people file was read")
        }
        let people = await store.all
        XCTAssertTrue(people.isEmpty)
    }
    func testPersonNameMustBeShortAndSingleLine() async throws {
        let keys = InMemoryStoreKeyVault()
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-people-names-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let store = PeopleStore(keys: keys)
        _ = await store.configure(storageURL: url, network: .signet)
        let person = try await store.add(name: "  Ada  ", payTo: nil)
        XCTAssertEqual(person.name, "Ada")
        do {
            _ = try await store.add(name: "Ada\nPay bc1q…", payTo: nil)
            XCTFail("a multi-line name was accepted")
        } catch PeopleStorageError.invalidState {}
        do {
            _ = try await store.add(name: String(repeating: "a", count: DisplayName.maximumLength + 1),
                                    payTo: nil)
            XCTFail("an over-long name was accepted")
        } catch PeopleStorageError.invalidState {}
        do {
            _ = try await store.updateRecipient(id: person.id, name: "Ada\u{7}", saved: true)
            XCTFail("a control character was accepted on rename")
        } catch PeopleStorageError.invalidState {}
    }
}
