import Foundation
import Testing
@testable import BitcoinP2P

/// Bounds on the persisted header file (epic #100, invariant S10).
///
/// The compact-filter progress file already refuses to be read past a ceiling.
/// The header file did not, and it is read during startup: `Data(contentsOf:)`
/// on an arbitrarily large file exhausts memory before any of the fail-closed
/// corruption handling downstream can run. That is the same shape as the
/// descriptor crash in `SEC-010` — a hostile or damaged store taking the app
/// down at launch rather than being rejected by it.
///
/// Mainnet headers are 80 bytes each and grow by roughly 4 MB a year, so a
/// real chain is far below the ceiling and these refusals cannot affect one.
@Suite("Header storage bounds")
struct HeaderStorageBoundsTests {
    /// Creates a file that *reports* a huge size without occupying the disk,
    /// so the size guard can be exercised without writing 256 MB.
    static func sparseFile(bytes: Int64) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-headers-\(UUID().uuidString).dat")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let handle = try FileHandle(forWritingTo: url)
        try handle.truncate(atOffset: UInt64(bytes))
        try handle.close()
        return url
    }

    @Test("a header file above the ceiling is refused before it is read")
    func oversizedHeaderFileRefused() throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 2)
        let url = try Self.sparseFile(bytes: Int64(HeaderChain.maximumHeaderFileBytes) + 1)
        defer { try? FileManager.default.removeItem(at: url) }

        // Confirm the fixture really does present an oversized file.
        let size = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber
        #expect(size?.int64Value ?? 0 > Int64(HeaderChain.maximumHeaderFileBytes))

        do {
            _ = try HeaderChain(params: chain.params, storageURL: url)
            Issue.record("an oversized header file was accepted")
        } catch let error as HeaderChainError {
            guard case let .storageCorrupt(message) = error, message.contains("above the") else {
                Issue.record("rejected as \(error) rather than an over-limit storageCorrupt")
                return
            }
        }
    }

    /// Positive control: a file just under the ceiling is not rejected for
    /// being too large. It is still refused — a sparse file is not a valid
    /// header chain — but as a corrupt chain rather than an oversized one, so
    /// the size guard is not simply rejecting everything.
    @Test("a file under the ceiling is not rejected for its size")
    func underLimitNotRejectedForSize() throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 2)
        let url = try Self.sparseFile(bytes: 4_096)
        defer { try? FileManager.default.removeItem(at: url) }

        do {
            _ = try HeaderChain(params: chain.params, storageURL: url)
        } catch let error as HeaderChainError {
            if case let .storageCorrupt(message) = error {
                #expect(!message.contains("above the"),
                        "a small file must not be refused for its size")
            }
        }
    }

    /// A real persisted chain still round-trips, so the guard does not affect
    /// ordinary operation.
    @Test("an ordinary persisted chain still loads")
    func ordinaryChainRoundTrips() async throws {
        let chain = makeSyntheticChain(length: 5, watchHeight: 6)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-headers-\(UUID().uuidString).dat")
        defer { try? FileManager.default.removeItem(at: url) }

        let written = try HeaderChain(params: chain.params, storageURL: url)
        let appended = try await written.connect(chain.blocks.dropFirst().map(\.header))
        #expect(appended == 5)

        let reloaded = try HeaderChain(params: chain.params, storageURL: url)
        #expect(await reloaded.height == written.height)
    }
}
