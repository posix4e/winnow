import Foundation
import Testing

@testable import BitcoinP2P

/// Regenerates the shipped mainnet checkpoint from a header file this code
/// produced by syncing from genesis, and checks the constant against it (#89).
///
/// The point of the checkpoint is that nobody has to take it on faith. So it is
/// not derived by a separate parser that could agree with the constant while
/// both are wrong — the header file is loaded through `HeaderChain` itself,
/// which proof-of-work-checks every header and rejects a broken chain. What the
/// app would compute is what gets compared.
///
/// To run it:
///
///     WINNOW_HEADERS_BIN=~/…/mainnet/headers.bin \
///       swift test --filter CheckpointGenerator
///
/// Any genesis-validated mainnet `headers.bin` past height 900,000 works,
/// including one from a simulator container. Without the variable the suite
/// skips, so CI stays green without shipping a 77 MB fixture.
@Suite("CheckpointGenerator",
       .enabled(if: ProcessInfo.processInfo.environment["WINNOW_HEADERS_BIN"] != nil))
struct CheckpointGeneratorTests {
    @Test("the shipped constant is what a genesis-validated chain computes")
    func regenerate() async throws {
        let params = NetworkParams.params(for: .mainnet)
        let expected = try #require(params.checkpoint)
        let path = try #require(ProcessInfo.processInfo.environment["WINNOW_HEADERS_BIN"])
        let source = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
        let raw = try Data(contentsOf: source)

        // Legacy layout: count || count × 80 bytes. A checkpoint-rooted file
        // cannot be a source here — it would be assuming what we are deriving.
        var reader = ByteReader(raw)
        let count = try reader.readUInt32()
        #expect(count != 0xFFFF_FFFF,
                "source file is checkpoint-rooted; the checkpoint must come from a genesis sync")
        let wanted = expected.height + 1
        #expect(count >= wanted, "source has \(count) headers, need \(wanted)")

        // Truncate to the checkpoint height and hand the result to the real
        // loader. It re-validates linkage and proof of work on every header.
        var truncated = Data()
        truncated.appendUInt32(wanted)
        truncated.append(raw[4 ..< (4 + Int(wanted) * BlockHeader.serializedSize)])
        let temp = FileManager.default.temporaryDirectory
            .appending(path: "winnow-checkpoint-\(wanted).bin")
        try truncated.write(to: temp, options: .atomic)
        defer { try? FileManager.default.removeItem(at: temp) }

        let chain = try HeaderChain(params: params, storageURL: temp)
        let height = await chain.height
        let tip = await chain.tip
        let work = await chain.tipWork

        #expect(height == expected.height)
        #expect(tip.serialized == expected.header)
        #expect(work == expected.chainwork)
        #expect(await chain.startHeight == 0, "derived from a genesis-rooted chain")

        // Emit it in source form, so regenerating at a new height is a copy out
        // of the test log rather than a hand-assembled constant.
        let bytes = tip.serialized.map { String(format: "%02x", $0) }.joined()
        print("""

        // Block \(height) hash, display order:
        //   \(tip.hash.displayHex)
        checkpoint: Checkpoint(
            height: \(height),
            header: Data(hex:
                "\(bytes.prefix(72))"
                + "\(bytes.dropFirst(72).prefix(64))"
                + "\(bytes.dropFirst(136))")!,
            chainwork: Data(hex:
                "\(work.map { String(format: "%02x", $0) }.joined())")!
        )

        """)
    }
}

/// The acceptance test from #89: a chain synced from genesis and a chain
/// synced from the checkpoint must agree on tip hash and total chainwork.
/// Same answer, different starting point.
///
/// Env-gated for the same reason as the generator — it needs a real mainnet
/// header file, which is 77 MB and does not belong in the repo. See
/// CheckpointGeneratorTests for how to run it.
@Suite("CheckpointAgreement",
       .enabled(if: ProcessInfo.processInfo.environment["WINNOW_HEADERS_BIN"] != nil))
struct CheckpointAgreementTests {
    /// Builds a header file holding `count` headers taken from a
    /// genesis-validated source, in the legacy genesis-rooted layout.
    private func genesisRootedFile(_ count: UInt32, named name: String) throws -> URL {
        let path = try #require(ProcessInfo.processInfo.environment["WINNOW_HEADERS_BIN"])
        let raw = try Data(contentsOf: URL(fileURLWithPath: (path as NSString).expandingTildeInPath))
        var reader = ByteReader(raw)
        let stored = try reader.readUInt32()
        #expect(stored >= count)
        var out = Data()
        out.appendUInt32(count)
        out.append(raw[4 ..< (4 + Int(count) * BlockHeader.serializedSize)])
        let url = FileManager.default.temporaryDirectory.appending(path: name)
        try out.write(to: url, options: .atomic)
        return url
    }

    private func headers(_ from: UInt32, _ throughInclusive: UInt32) throws -> [BlockHeader] {
        let path = try #require(ProcessInfo.processInfo.environment["WINNOW_HEADERS_BIN"])
        let raw = try Data(contentsOf: URL(fileURLWithPath: (path as NSString).expandingTildeInPath))
        var result: [BlockHeader] = []
        for height in from ... throughInclusive {
            let start = 4 + Int(height) * BlockHeader.serializedSize
            result.append(try BlockHeader.decode(raw[start ..< start + BlockHeader.serializedSize]))
        }
        return result
    }

    @Test("genesis-rooted and checkpoint-rooted chains reach the same tip and the same total work")
    func agree() async throws {
        let params = NetworkParams.params(for: .mainnet)
        let checkpoint = try #require(params.checkpoint)
        // Somewhere past the checkpoint, so both chains have to connect real
        // headers to get there rather than merely being loaded.
        let target = checkpoint.height + 2_000

        // From genesis: load everything up to the checkpoint, then connect.
        let genesisFile = try genesisRootedFile(checkpoint.height + 1, named: "winnow-agree-genesis.bin")
        defer { try? FileManager.default.removeItem(at: genesisFile) }
        let fromGenesis = try HeaderChain(params: params, storageURL: genesisFile, start: .genesis)
        #expect(await fromGenesis.startHeight == 0)

        // From the checkpoint: no stored file at all, so it starts from the
        // shipped constant and connects the same headers.
        let checkpointFile = FileManager.default.temporaryDirectory
            .appending(path: "winnow-agree-checkpoint.bin")
        try? FileManager.default.removeItem(at: checkpointFile)
        defer { try? FileManager.default.removeItem(at: checkpointFile) }
        let fromCheckpoint = try HeaderChain(params: params, storageURL: checkpointFile, start: .checkpoint)
        #expect(await fromCheckpoint.startHeight == checkpoint.height)

        // They already agree at the checkpoint itself.
        #expect(await fromGenesis.tipHash == (await fromCheckpoint.tipHash))
        #expect(await fromGenesis.tipWork == (await fromCheckpoint.tipWork))
        #expect(await fromGenesis.height == (await fromCheckpoint.height))

        let next = try headers(checkpoint.height + 1, target)
        #expect(try await fromGenesis.connect(next).appended == next.count)
        #expect(try await fromCheckpoint.connect(next).appended == next.count)

        // And after doing real work on top, which is the claim that matters:
        // the checkpoint start is not a different chain, just a later entrance.
        #expect(await fromGenesis.height == target)
        #expect(await fromCheckpoint.height == target)
        #expect(await fromGenesis.tipHash == (await fromCheckpoint.tipHash))
        #expect(await fromGenesis.tipWork == (await fromCheckpoint.tipWork),
                "cumulative work diverged — the shipped checkpoint's chainwork is wrong")

        // Heights must mean the same thing in both, not merely end up equal.
        for height in [checkpoint.height, checkpoint.height + 1, target - 1, target] {
            #expect(await fromGenesis.blockHash(at: height) == (await fromCheckpoint.blockHash(at: height)),
                    "disagreement at height \(height)")
        }
        // The checkpoint chain genuinely does not hold what it skipped.
        #expect(await fromCheckpoint.blockHash(at: checkpoint.height - 1) == nil)
        #expect(await fromGenesis.blockHash(at: checkpoint.height - 1) != nil)
    }
}
