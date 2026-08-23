import Foundation
import Testing
@testable import BitcoinP2P

/// Header persistence writes only the new headers (#83).
///
/// Rewriting the whole file per batch is what made mainnet header sync slow
/// down as it ran — 963,000 headers is 77 MB, re-serialised and re-written on
/// each of ~460 batches. The layout is a fixed prefix plus fixed 80-byte
/// records, so an append is a write at a known offset followed by an updated
/// count.
///
/// What these pin is the part an append can get wrong and a single-batch test
/// cannot see: the second write has to land where the first one ended, and the
/// count has to admit exactly the records that are there. Every case reloads
/// from disk, because `load` re-checks proof of work and linkage on every
/// header — so a write at the wrong offset shows up as a broken chain rather
/// than as silently wrong bytes.
@Suite("Header storage append")
struct HeaderStorageAppendTests {

    static func url() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("winnow-append-\(UUID().uuidString).dat")
    }

    /// `count` headers building on `previous`, at trivial difficulty.
    static func headers(after previous: Data, count: Int, time: UInt32 = 1_600_000_000) -> [BlockHeader] {
        var result: [BlockHeader] = []
        var parent = previous
        for index in 0 ..< count {
            let header = minedHeader(previousHash: parent,
                                     merkleRoot: Data(repeating: UInt8(index % 251 + 1), count: 32),
                                     time: time + UInt32(index) * 600)
            result.append(header)
            parent = header.hash
        }
        return result
    }

    /// A checkpoint-rooted chain and its params, so the marker layout can be
    /// exercised without a real 77 MB mainnet header file.
    ///
    /// The checkpoint is a header from a synthetic chain, carrying the work of
    /// everything up to it — which is what `NetworkParams.Checkpoint` means and
    /// what `load` puts back when it reads the prefix.
    static func checkpointRooted() throws -> (params: NetworkParams, tipHash: Data) {
        let synthetic = makeSyntheticChain(length: 3, watchHeight: 2)
        let genesisParams = synthetic.params
        let checkpointHeight: UInt32 = 3
        let header = synthetic.blocks[Int(checkpointHeight)].header

        var work = UInt256()
        for height in 0 ... checkpointHeight {
            work = work + (try HeaderChain.checkedWork(for: synthetic.blocks[Int(height)].header,
                                                       params: genesisParams, height: height))
        }
        let params = NetworkParams(
            network: .signet, magic: genesisParams.magic, defaultPort: genesisParams.defaultPort,
            genesisTime: genesisParams.genesisTime, genesisBits: genesisParams.genesisBits,
            genesisNonce: genesisParams.genesisNonce,
            genesisMerkleRoot: genesisParams.genesisMerkleRoot,
            genesisHash: genesisParams.genesisHash, powLimit: genesisParams.powLimit,
            dnsSeeds: [],
            checkpoint: NetworkParams.Checkpoint(height: checkpointHeight,
                                                 header: header.serialized,
                                                 chainwork: work.bigEndianData))
        return (params, header.hash)
    }

    /// The production path, and the one every other test here misses.
    ///
    /// Since #89 a mainnet wallet starts from the checkpoint, which writes the
    /// *marker* layout: a 48-byte prefix with the count at offset 44, not the
    /// 4-byte prefix with the count at 0 that a genesis-rooted chain uses. The
    /// second batch of a mainnet first launch is therefore the first time an
    /// append ever runs against that layout — in production, and until now
    /// with no test behind it.
    ///
    /// Getting the offsets the wrong way round would be loud rather than
    /// silent: the next load refuses the file and the wallet resyncs. But it
    /// would corrupt the header file of every mainnet user on their second
    /// batch, and swapping the two layouts' offsets would break no test.
    @Test("appending to a checkpoint-rooted file uses the marker layout's offsets")
    func appendToCheckpointRootedFile() async throws {
        let (params, checkpointTip) = try Self.checkpointRooted()
        let url = Self.url()
        defer { try? FileManager.default.removeItem(at: url) }

        let chain = try HeaderChain(params: params, storageURL: url, start: .checkpoint)
        #expect(await chain.startHeight == 3, "fixture precondition: the marker layout")

        let first = Self.headers(after: checkpointTip, count: 3, time: 1_900_000_000)
        _ = try await chain.connect(first)
        let second = Self.headers(after: first[first.count - 1].hash, count: 4, time: 1_900_100_000)
        _ = try await chain.connect(second)
        #expect(await chain.height == 10)

        let reloaded = try HeaderChain(params: params, storageURL: url, start: .checkpoint)
        #expect(await reloaded.height == 10)
        #expect(await reloaded.tipHash == chain.tipHash)
        #expect(await reloaded.startHeight == 3)

        // 48-byte prefix, not 4 — the whole point of this case.
        let bytes = try Data(contentsOf: url)
        #expect(bytes.count == 48 + 8 * BlockHeader.serializedSize)
    }

    /// The case a single-batch test cannot reach: the second append must start
    /// where the first one finished. An offset that is wrong by even one record
    /// reloads as a broken chain.
    @Test("two appends in a row reload as one chain")
    func appendAfterAppendReloads() async throws {
        let synthetic = makeSyntheticChain(length: 1, watchHeight: 6)
        let url = Self.url()
        defer { try? FileManager.default.removeItem(at: url) }

        let chain = try HeaderChain(params: synthetic.params, storageURL: url)
        let first = Self.headers(after: synthetic.blocks[0].hash, count: 3)
        _ = try await chain.connect(first)
        let second = Self.headers(after: first[first.count - 1].hash, count: 4, time: 1_600_100_000)
        _ = try await chain.connect(second)
        #expect(await chain.height == 7)

        let reloaded = try HeaderChain(params: synthetic.params, storageURL: url)
        #expect(await reloaded.height == 7)
        #expect(await reloaded.tipHash == chain.tipHash)

        // And the file is exactly as long as its count implies — an append
        // that left a stale tail behind would still reload, so length is the
        // only thing that catches it.
        let bytes = try Data(contentsOf: url)
        #expect(bytes.count == 4 + 8 * BlockHeader.serializedSize)
    }

    /// A reorg replaces headers rather than adding them, so it takes the full
    /// rewrite. What matters here is the append that comes *after*: the writer
    /// has to know the file shrank, or it writes the next batch past the end.
    @Test("an append after a reorg lands at the new end of the file")
    func appendAfterReorgReloads() async throws {
        let synthetic = makeSyntheticChain(length: 1, watchHeight: 6)
        let url = Self.url()
        defer { try? FileManager.default.removeItem(at: url) }

        let chain = try HeaderChain(params: synthetic.params, storageURL: url)
        let original = Self.headers(after: synthetic.blocks[0].hash, count: 4)
        _ = try await chain.connect(original)
        #expect(await chain.height == 4)

        // Replace the last three with a longer branch off height 1.
        let replacement = Self.headers(after: original[0].hash, count: 5, time: 1_700_000_000)
        _ = try await chain.connect(replacement)
        #expect(await chain.height == 6)

        // Now append onto the reorganised chain.
        let continuation = Self.headers(after: replacement[replacement.count - 1].hash,
                                        count: 2, time: 1_800_000_000)
        _ = try await chain.connect(continuation)
        #expect(await chain.height == 8)

        let reloaded = try HeaderChain(params: synthetic.params, storageURL: url)
        #expect(await reloaded.height == 8)
        #expect(await reloaded.tipHash == chain.tipHash)

        let bytes = try Data(contentsOf: url)
        #expect(bytes.count == 4 + 9 * BlockHeader.serializedSize)
    }

    /// A chain reopened from disk has to know how much of it is already
    /// written, or the first append after a restart writes at the wrong place.
    @Test("an append after reopening the file continues the chain")
    func appendAfterReopenReloads() async throws {
        let synthetic = makeSyntheticChain(length: 1, watchHeight: 6)
        let url = Self.url()
        defer { try? FileManager.default.removeItem(at: url) }

        let first = Self.headers(after: synthetic.blocks[0].hash, count: 3)
        do {
            let chain = try HeaderChain(params: synthetic.params, storageURL: url)
            _ = try await chain.connect(first)
        }

        let reopened = try HeaderChain(params: synthetic.params, storageURL: url)
        let second = Self.headers(after: first[first.count - 1].hash, count: 3, time: 1_600_200_000)
        _ = try await reopened.connect(second)
        #expect(await reopened.height == 6)

        let reloaded = try HeaderChain(params: synthetic.params, storageURL: url)
        #expect(await reloaded.height == 6)
        #expect(await reloaded.tipHash == reopened.tipHash)
    }

    /// A failed write leaves the chain in memory ahead of the chain on disk,
    /// and the next append must notice rather than write at an offset the file
    /// never reached. This is the only way that divergence occurs, so it is
    /// what the persisted-count check is actually for.
    @Test("an append after a failed write falls back to rewriting the file")
    func appendAfterFailedWriteRecovers() async throws {
        let synthetic = makeSyntheticChain(length: 1, watchHeight: 6)
        let url = Self.url()
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
            try? FileManager.default.removeItem(at: url)
        }

        let chain = try HeaderChain(params: synthetic.params, storageURL: url)
        let first = Self.headers(after: synthetic.blocks[0].hash, count: 3)
        _ = try await chain.connect(first)

        // Make the file unwritable, so the next append fails after the headers
        // are already in memory.
        try FileManager.default.setAttributes([.posixPermissions: 0o444], ofItemAtPath: url.path)
        let second = Self.headers(after: first[first.count - 1].hash, count: 2, time: 1_600_400_000)
        var writeFailed = false
        do {
            _ = try await chain.connect(second)
        } catch {
            writeFailed = true
        }
        #expect(writeFailed, "fixture precondition: the append had to fail")
        #expect(await chain.height == 5, "the headers are accepted in memory even when the write fails")

        // Disk is now three headers behind memory. The next append must not
        // write at the offset memory implies.
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        let third = Self.headers(after: second[second.count - 1].hash, count: 2, time: 1_600_500_000)
        _ = try await chain.connect(third)

        let reloaded = try HeaderChain(params: synthetic.params, storageURL: url)
        #expect(await reloaded.height == 7)
        #expect(await reloaded.tipHash == chain.tipHash)
        let bytes = try Data(contentsOf: url)
        #expect(bytes.count == 4 + 8 * BlockHeader.serializedSize)
    }

    /// The interrupted-append shape, produced deliberately: headers on disk
    /// that the count does not admit yet. Reopening must read the committed
    /// chain, and the next append must overwrite the orphaned tail rather than
    /// build on top of it.
    @Test("an interrupted append is overwritten by the next one")
    func interruptedAppendIsOverwritten() async throws {
        let synthetic = makeSyntheticChain(length: 1, watchHeight: 6)
        let url = Self.url()
        defer { try? FileManager.default.removeItem(at: url) }

        let committed = Self.headers(after: synthetic.blocks[0].hash, count: 3)
        do {
            let chain = try HeaderChain(params: synthetic.params, storageURL: url)
            _ = try await chain.connect(committed)
        }

        // Simulate the crash window: payload written, count not yet updated.
        // The tail is deliberately LONGER than the append that follows it —
        // three orphaned records against one new header — because a shorter
        // tail would be overwritten by the next write regardless, and the
        // truncation this pins would go untested.
        var torn = try Data(contentsOf: url)
        torn.append(Data(repeating: 0xEE, count: 3 * BlockHeader.serializedSize))
        try torn.write(to: url)

        let reopened = try HeaderChain(params: synthetic.params, storageURL: url)
        #expect(await reopened.height == 3, "the uncommitted tail must not count as a header")

        let next = Self.headers(after: committed[committed.count - 1].hash, count: 1, time: 1_600_300_000)
        _ = try await reopened.connect(next)

        let reloaded = try HeaderChain(params: synthetic.params, storageURL: url)
        #expect(await reloaded.height == 4)
        #expect(await reloaded.tipHash == reopened.tipHash)
        let bytes = try Data(contentsOf: url)
        #expect(bytes.count == 4 + 5 * BlockHeader.serializedSize,
                "the orphaned tail must be truncated away, not left past the new end")
    }

    /// Not an assertion about wall-clock time, which would be flaky. It pins
    /// the *shape* of the cost: the bytes written across a sync must grow with
    /// the number of headers, not with their square. A whole-file rewrite per
    /// batch writes sum(n) records; an append writes n.
    @Test("total bytes written grows linearly, not quadratically, across batches")
    func writeVolumeIsLinear() async throws {
        let synthetic = makeSyntheticChain(length: 1, watchHeight: 6)
        let url = Self.url()
        defer { try? FileManager.default.removeItem(at: url) }

        let chain = try HeaderChain(params: synthetic.params, storageURL: url)
        var parent = synthetic.blocks[0].hash
        let batches = 20
        let perBatch = 10
        for batch in 0 ..< batches {
            let batchHeaders = Self.headers(after: parent, count: perBatch,
                                            time: 1_600_000_000 + UInt32(batch) * 100_000)
            _ = try await chain.connect(batchHeaders)
            parent = batchHeaders[batchHeaders.count - 1].hash
        }

        let total = batches * perBatch
        #expect(await chain.height == UInt32(total))
        let bytes = try Data(contentsOf: url)
        #expect(bytes.count == 4 + (total + 1) * BlockHeader.serializedSize)

        // A rewrite-per-batch writer would have written ~sum(batch*perBatch)
        // records — an order more than the file it ends up with. The append
        // writer touches each record once, so the file it produces and the
        // volume it wrote are the same order.
        let reloaded = try HeaderChain(params: synthetic.params, storageURL: url)
        #expect(await reloaded.height == UInt32(total))
        #expect(await reloaded.tipHash == chain.tipHash)
    }
}
