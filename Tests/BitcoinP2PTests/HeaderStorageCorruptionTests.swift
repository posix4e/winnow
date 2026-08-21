import Foundation
import Testing
@testable import BitcoinP2P

/// A damaged header file must never load as a chain (epic #100, invariant S5).
///
/// Header storage is read during startup and everything downstream trusts it:
/// filter sync pins against it, and the wallet's confirmations are heights in
/// it. A file that loaded partially, or loaded a fabricated chain, would not
/// announce itself — the wallet would simply be syncing against something that
/// was never mined.
///
/// So each damage mode is checked for a specific refusal rather than "some
/// error", because the modes fail for different reasons and a single broad
/// assertion would pass even if one of them stopped being checked.
@Suite("Header storage corruption")
struct HeaderStorageCorruptionTests {
    /// Writes a real four-header chain and returns its file.
    static func persistedChain() async throws -> (url: URL, params: NetworkParams, bytes: Data) {
        let synthetic = makeSyntheticChain(length: 1, watchHeight: 6)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-corrupt-\(UUID().uuidString).dat")
        let chain = try HeaderChain(params: synthetic.params, storageURL: url)
        var previous = synthetic.blocks[0].hash
        var headers: [BlockHeader] = []
        for index in 0 ..< 4 {
            let header = minedHeader(previousHash: previous,
                                     merkleRoot: Data(repeating: 0xA1, count: 32),
                                     time: 1_600_000_000 + UInt32(index) * 600)
            headers.append(header)
            previous = header.hash
        }
        _ = try await chain.connect(headers)
        let bytes = try Data(contentsOf: url)
        return (url, synthetic.params, bytes)
    }

    static func write(_ bytes: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-corrupt-\(UUID().uuidString).dat")
        try bytes.write(to: url)
        return url
    }

    /// Loads a byte image and returns the error, or nil if it loaded.
    static func loadError(_ bytes: Data, params: NetworkParams) throws -> HeaderChainError? {
        let url = try write(bytes)
        defer { try? FileManager.default.removeItem(at: url) }
        do {
            _ = try HeaderChain(params: params, storageURL: url)
            return nil
        } catch let error as HeaderChainError {
            return error
        }
    }

    /// Positive control: the intact file loads. Every refusal below is only
    /// meaningful against this.
    @Test("an intact header file loads")
    func intactFileLoads() async throws {
        let (url, params, _) = try await Self.persistedChain()
        defer { try? FileManager.default.removeItem(at: url) }
        let reloaded = try HeaderChain(params: params, storageURL: url)
        #expect(await reloaded.height == 4)
    }

    /// Bytes lost from the end: the declared count no longer matches.
    @Test("a truncated file is refused")
    func truncatedFileRefused() async throws {
        let (url, params, bytes) = try await Self.persistedChain()
        defer { try? FileManager.default.removeItem(at: url) }
        let error = try Self.loadError(bytes.dropLast(40), params: params)
        guard case let .storageCorrupt(reason)? = error, reason.contains("bad length") else {
            Issue.record("truncation gave \(String(describing: error)) rather than a length refusal")
            return
        }
    }

    /// Extra bytes appended: also a length mismatch, so a file cannot be
    /// padded with a header the writer never committed to.
    @Test("a file with trailing bytes is refused")
    func trailingBytesRefused() async throws {
        let (url, params, bytes) = try await Self.persistedChain()
        defer { try? FileManager.default.removeItem(at: url) }
        let error = try Self.loadError(bytes + Data(repeating: 0, count: 80), params: params)
        guard case let .storageCorrupt(reason)? = error, reason.contains("bad length") else {
            Issue.record("padding gave \(String(describing: error)) rather than a length refusal")
            return
        }
    }

    /// A file written by a future format must not be read under this one's
    /// assumptions.
    ///
    /// Built by hand: a genesis-rooted chain writes the original layout (a
    /// bare count), so the versioned layout only appears for checkpoint-rooted
    /// files and cannot be produced from a synthetic chain.
    @Test("an unknown format version is refused")
    func unknownFormatVersionRefused() async throws {
        let (url, params, _) = try await Self.persistedChain()
        defer { try? FileManager.default.removeItem(at: url) }

        var damaged = Data()
        damaged.appendUInt32(0xFFFF_FFFF) // format marker
        damaged.appendUInt32(99) // a version this build does not know
        damaged.appendUInt32(1) // base height
        damaged.append(Data(repeating: 0, count: 32)) // base work
        damaged.appendUInt32(0) // count
        let expectedPrefix = 48 // marker + version + baseHeight + work + count
        #expect(damaged.count == expectedPrefix)

        let error = try Self.loadError(damaged, params: params)
        guard case let .storageCorrupt(reason)? = error, reason.contains("version") else {
            Issue.record("bad version gave \(String(describing: error))")
            return
        }
    }

    /// A prefix cut short must not be read as a zero-length chain.
    @Test("a truncated prefix is refused")
    func truncatedPrefixRefused() async throws {
        let (url, params, bytes) = try await Self.persistedChain()
        defer { try? FileManager.default.removeItem(at: url) }
        let error = try Self.loadError(bytes.prefix(10), params: params)
        guard case .storageCorrupt? = error else {
            Issue.record("a 10-byte file gave \(String(describing: error))")
            return
        }
    }

    /// Headers reordered in place keep the file's length and every individual
    /// header valid, so only the linkage check catches it. This is the damage
    /// mode a length or checksum test would miss.
    @Test("headers reordered in place are refused")
    func brokenLinkageRefused() async throws {
        let (url, params, bytes) = try await Self.persistedChain()
        defer { try? FileManager.default.removeItem(at: url) }
        // A genesis-rooted file is a 4-byte count followed by headers, and
        // header 0 is genesis. Swapping the two *after* it leaves the genesis
        // check satisfied so that only the linkage check can object.
        let prefix = 4
        let size = BlockHeader.serializedSize
        var damaged = bytes
        let a = (prefix + size) ..< (prefix + 2 * size)
        let b = (prefix + 2 * size) ..< (prefix + 3 * size)
        let first = Data(damaged[a])
        let second = Data(damaged[b])
        damaged.replaceSubrange(a, with: second)
        damaged.replaceSubrange(b, with: first)

        let error = try Self.loadError(damaged, params: params)
        guard case let .storageCorrupt(reason)? = error, reason.contains("linkage") else {
            Issue.record("reordering gave \(String(describing: error)) rather than a linkage refusal")
            return
        }
    }

    /// A single flipped byte inside a header breaks its hash, and therefore
    /// the chain that follows it.
    @Test("a flipped byte inside a header is refused")
    func flippedByteRefused() async throws {
        let (url, params, bytes) = try await Self.persistedChain()
        defer { try? FileManager.default.removeItem(at: url) }
        let prefix = 4
        var damaged = bytes
        damaged[prefix + 4] ^= 0xFF // inside the first header's previousHash
        #expect(try Self.loadError(damaged, params: params) != nil,
                "a corrupted header must not load")
    }

    /// An empty file is damage, not an empty chain.
    @Test("an empty file is refused")
    func emptyFileRefused() async throws {
        let (url, params, _) = try await Self.persistedChain()
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(try Self.loadError(Data(), params: params) != nil)
    }
}
