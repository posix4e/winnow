import Foundation
import Testing
@testable import BitcoinP2P

/// HeaderChain: PoW-checked connect, fork choice, locator, persistence —
/// over a synthetic mined chain (bits 0x207fffff, so PoW is real but trivial).
@Suite("HeaderChain")
struct HeaderChainTests {
    @Test("connects valid headers and tracks work")
    func connect() async throws {
        let chain = makeSyntheticChain(length: 5, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        let appended = try await headerChain.connect(chain.blocks.dropFirst().map(\.header))
        #expect(appended.appended == 5)
        #expect(await headerChain.height == 5)
        #expect(await headerChain.tipHash == chain.blocks[5].hash)
        #expect(await headerChain.blockHash(at: 0) == chain.blocks[0].hash)

        // Work doubles from height 2 to height 4 (constant bits).
        let work4 = await headerChain.tipWork
        #expect(!work4.isEmpty)
    }

    @Test("rejects a header that does not link to the chain")
    func rejectsUnlinked() async throws {
        let chain = makeSyntheticChain(length: 3, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        let orphan = minedHeader(previousHash: Data(repeating: 0x99, count: 32),
                                 merkleRoot: Data(repeating: 0, count: 32), time: 1_600_100_000)
        await #expect(throws: HeaderChainError.doesNotConnect) {
            try await headerChain.connect([orphan])
        }
    }

    @Test("rejects headers failing proof of work")
    func rejectsBadPoW() async throws {
        let chain = makeSyntheticChain(length: 2, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        // Link to genesis but with mainnet-hard bits and an unmined nonce.
        let bad = BlockHeader(version: 1, previousHash: chain.blocks[0].hash,
                              merkleRoot: Data(repeating: 0, count: 32),
                              time: 1_600_000_600, bits: 0x1D00_FFFF, nonce: 0)
        await #expect(throws: HeaderChainError.self) { try await headerChain.connect([bad]) }
    }

    @Test("rejects targets above powLimit")
    func rejectsAbovePowLimit() async throws {
        let chain = makeSyntheticChain(length: 2, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        // bits 0x2100ffff: target = 0xffff * 256^30 > powLimit (0x207fffff-based).
        let tooEasy = BlockHeader(version: 1, previousHash: chain.blocks[0].hash,
                                  merkleRoot: Data(repeating: 0, count: 32),
                                  time: 1_600_000_600, bits: 0x2100_FFFF, nonce: 0)
        await #expect(throws: HeaderChainError.targetAbovePowLimit(height: 1)) {
            try await headerChain.connect([tooEasy])
        }
    }

    @Test("a longer branch replaces; a shorter one is refused")
    func forkChoice() async throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 6)
        let genesis = chain.blocks[0]
        let headerChain = try HeaderChain(params: chain.params)

        func branch(count: Int, tag: UInt8, fromTime time: UInt32) -> [BlockHeader] {
            var headers: [BlockHeader] = []
            var previous = genesis.hash
            for i in 0 ..< count {
                let header = minedHeader(previousHash: previous,
                                         merkleRoot: Data(repeating: tag, count: 32),
                                         time: time + UInt32(i) * 600)
                headers.append(header)
                previous = header.hash
            }
            return headers
        }

        let branchA = branch(count: 3, tag: 0xAA, fromTime: 1_600_010_000)
        try await headerChain.connect(branchA)
        #expect(await headerChain.tipHash == branchA[2].hash)

        // Shorter competing branch (less work) must not replace the tip.
        let shorter = branch(count: 2, tag: 0xBB, fromTime: 1_600_020_000)
        await #expect(throws: HeaderChainError.reorgWithoutMoreWork) {
            try await headerChain.connect(shorter)
        }
        #expect(await headerChain.tipHash == branchA[2].hash)

        // Longer branch (more work) reorganizes the chain.
        let longer = branch(count: 5, tag: 0xCC, fromTime: 1_600_030_000)
        try await headerChain.connect(longer)
        #expect(await headerChain.height == 5)
        #expect(await headerChain.tipHash == longer[4].hash)
    }

    @Test("block locator: tip first, exponential steps, genesis last")
    func locator() async throws {
        let chain = makeSyntheticChain(length: 20, watchHeight: 6)
        let headerChain = try HeaderChain(params: chain.params)
        try await headerChain.connect(chain.blocks.dropFirst().map(\.header))
        let locator = await headerChain.blockLocator()
        #expect(locator.first == chain.blocks[20].hash)
        #expect(locator.last == chain.blocks[0].hash)
        // 10 single steps then doubling: heights 20,19,…,11, then 9,7,3? — just
        // assert monotonic decrease and full inclusion of the recent window.
        for header in chain.blocks[11 ... 20] {
            #expect(locator.contains(header.hash))
        }
    }

    @Test("persists and reloads from disk, re-validating PoW")
    func persistence() async throws {
        let chain = makeSyntheticChain(length: 4, watchHeight: 6)
        let file = tempFileURL("headers.dat")
        let headerChain = try HeaderChain(params: chain.params, storageURL: file)
        try await headerChain.connect(chain.blocks.dropFirst().map(\.header))
        let reloaded = try HeaderChain(params: chain.params, storageURL: file)
        #expect(await reloaded.height == 4)
        #expect(await reloaded.tipHash == chain.blocks[4].hash)
        try? FileManager.default.removeItem(at: file.deletingLastPathComponent())
    }

    /// A build that cannot interpret a checkpoint-rooted file must say so
    /// rather than read it as genesis-rooted — that would silently shift every
    /// height in the chain, and nothing downstream would notice (#89).
    @Test("a checkpoint-rooted header file is refused, not misread")
    func checkpointFileRefused() async throws {
        let chain = makeSyntheticChain(length: 2, watchHeight: 6)
        let file = tempFileURL("headers.dat")

        var data = Data()
        data.appendUInt32(0xFFFF_FFFF)          // format marker
        data.appendUInt32(1)                    // version
        data.appendUInt32(500_000)              // base height
        data.append(Data(repeating: 0, count: 32)) // base work
        data.appendUInt32(UInt32(chain.blocks.count))
        for block in chain.blocks { data.append(block.header.serialized) }
        try data.write(to: file)

        #expect(throws: HeaderChainError.self) {
            _ = try HeaderChain(params: chain.params, storageURL: file)
        }
        try? FileManager.default.removeItem(at: file.deletingLastPathComponent())
    }

    @Test("corrupt store is rejected")
    func corruptStore() async throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 6)
        let file = tempFileURL("headers.dat")
        try Data([0xDE, 0xAD, 0xBE]).write(to: file)
        await #expect(throws: HeaderChainError.self) {
            _ = try HeaderChain(params: chain.params, storageURL: file)
        }
        try? FileManager.default.removeItem(at: file.deletingLastPathComponent())
    }

    @Test("repeated difficulty caching still verifies every stored header hash")
    func cachedDifficultyStillChecksPoW() async throws {
        let chain = makeSyntheticChain(length: 1, watchHeight: 6)
        let genesis = chain.blocks[0].header
        var nonce: UInt32 = 0
        var bad = BlockHeader(version: 1, previousHash: genesis.hash,
                              merkleRoot: Data(repeating: 0xA5, count: 32),
                              time: genesis.time + 600, bits: genesis.bits, nonce: nonce)
        while (try? HeaderChain.checkedWork(for: bad, params: chain.params, height: 1)) != nil {
            nonce &+= 1
            bad = BlockHeader(version: 1, previousHash: genesis.hash,
                              merkleRoot: bad.merkleRoot, time: bad.time,
                              bits: genesis.bits, nonce: nonce)
        }

        let file = tempFileURL("headers.dat")
        var stored = Data()
        stored.appendUInt32(2)
        stored.append(genesis.serialized)
        stored.append(bad.serialized)
        try stored.write(to: file)
        #expect(throws: HeaderChainError.insufficientProofOfWork(height: 1)) {
            _ = try HeaderChain(params: chain.params, storageURL: file)
        }
        try? FileManager.default.removeItem(at: file.deletingLastPathComponent())
    }
}

/// A shipped checkpoint is a constant someone has to trust, so it should be
/// impossible to get wrong quietly. These are the checks that can run without
/// the 900,000 headers it was derived from (#89).
@Suite("Mainnet checkpoint")
struct MainnetCheckpointTests {
    private var checkpoint: NetworkParams.Checkpoint {
        get throws {
            guard let cp = NetworkParams.params(for: .mainnet).checkpoint else {
                throw HeaderChainError.storageCorrupt("mainnet has no checkpoint")
            }
            return cp
        }
    }

    @Test("the header is well formed and satisfies its own proof of work")
    func headerIsValid() throws {
        let cp = try checkpoint
        let header = try BlockHeader.decode(cp.header)
        #expect(cp.header.count == 80)
        #expect(cp.chainwork.count == 32)

        // The hash must clear the target the header itself claims. A typo in
        // the bytes fails here rather than 900,000 blocks later.
        let target = try #require(UInt256.target(compact: header.bits))
        #expect(UInt256(littleEndian: header.hash) <= target)
        #expect(target <= UInt256(littleEndian: NetworkParams.params(for: .mainnet).powLimit))
    }

    @Test("the hash matches the block recorded in the source comment")
    func hashMatchesRecordedValue() throws {
        let header = try BlockHeader.decode(try checkpoint.header)
        // Display order is the reverse of internal order.
        let display = Data(header.hash.reversed()).map { String(format: "%02x", $0) }.joined()
        #expect(display == "000000000000000000010538edbfd2d5b809a33dd83f284aeea41c6d0d96968a")
    }

    @Test("cumulative work is plausible for the height and below the total supply of work")
    func chainworkSane() throws {
        let cp = try checkpoint
        // Orientation first. `Data(hex:)` keeps byte order and
        // `Data(displayHex:)` reverses it, and a reversed 32-byte chainwork is
        // still enormous and still non-zero — so every plausibility check below
        // passes just as happily on garbage. Pin the actual bytes: leading
        // zeros at the front, the low-order byte at the end.
        #expect(cp.chainwork.prefix(20).allSatisfy { $0 == 0 })
        #expect(cp.chainwork.last == 0x1c)
        #expect(cp.chainwork.map { String(format: "%02x", $0) }.joined()
            == "0000000000000000000000000000000000000000c8bbeae4127a204b0317861c")

        let work = UInt256(bigEndian: cp.chainwork)
        // Non-zero, and far above the work of any single block: a checkpoint
        // whose chainwork was left at zero or copied from one header would
        // lose every fork-choice comparison against a genesis-rooted peer.
        #expect(!work.isZero)
        let header = try BlockHeader.decode(cp.header)
        let target = try #require(UInt256.target(compact: header.bits))
        let single = try #require(UInt256.blockWork(target: target))
        #expect(work > single)
        #expect(cp.height == 900_000)
    }
}


/// Starting the chain somewhere other than block 0, end to end (#89 phase 3).
///
/// These run everywhere: the only fixture is block 900,001's header, 80 bytes,
/// which is enough to make a checkpoint-rooted chain do real work and write a
/// real file. The full genesis-vs-checkpoint comparison needs a mainnet header
/// file and lives in CheckpointAgreementTests.
@Suite("Checkpoint start")
struct CheckpointStartTests {
    /// The block right after the shipped mainnet checkpoint.
    /// 00000000000000000001a8ff030609a6248e0f6e77f9f141aeb21e4eac4f83fc
    static let block900_001 = Data(hex:
        "00e000208a96960d6d1ca4ee4a283fd83da309b8d5d2bfed380501000000000000000000"
        + "371c9ffd63d75fb36c57d58eb842d23c0e7ec049daf16d94cc38805c346e9d52"
        + "e880426874370217973dc83b")!

    private func tempURL(_ name: String) -> URL {
        let url = FileManager.default.temporaryDirectory.appending(path: "winnow-\(name).bin")
        try? FileManager.default.removeItem(at: url)
        return url
    }

    @Test("a fresh checkpoint-started chain begins at the checkpoint, not at zero")
    func startsAtCheckpoint() async throws {
        let params = NetworkParams.params(for: .mainnet)
        let cp = try #require(params.checkpoint)
        let chain = try HeaderChain(params: params, storageURL: nil, start: .checkpoint)
        #expect(await chain.startHeight == cp.height)
        #expect(await chain.height == cp.height)
        #expect(await chain.tip.serialized == cp.header)
        #expect(await chain.tipWork == cp.chainwork)
        // It genuinely does not hold what it skipped — no silent zero-filling.
        #expect(await chain.header(at: cp.height - 1) == nil)
        #expect(await chain.header(at: 0) == nil)
    }

    @Test("the default is still genesis, so existing callers are unchanged")
    func defaultIsGenesis() async throws {
        let chain = try HeaderChain(params: .mainnet, storageURL: nil)
        #expect(await chain.startHeight == 0)
        #expect(await chain.height == 0)
    }

    @Test("a network with no checkpoint starts at genesis whatever the setting says")
    func signetIgnoresTheSetting() async throws {
        let chain = try HeaderChain(params: .signet, storageURL: nil, start: .checkpoint)
        #expect(await chain.startHeight == 0)
        #expect(await chain.tip == HeaderChain.genesisHeader(for: .signet))
    }

    @Test("a checkpoint-rooted chain connects real headers and reloads from its own file")
    func roundTrip() async throws {
        let params = NetworkParams.params(for: .mainnet)
        let cp = try #require(params.checkpoint)
        let url = tempURL("checkpoint-roundtrip")
        defer { try? FileManager.default.removeItem(at: url) }

        let chain = try HeaderChain(params: params, storageURL: url, start: .checkpoint)
        let next = try BlockHeader.decode(Self.block900_001)
        #expect(try await chain.connect([next]).appended == 1)
        #expect(await chain.height == cp.height + 1)
        let workAfter = await chain.tipWork

        // Reopening must land on exactly the same chain — this is the format
        // phase 1 added, now written and read by the same build.
        let reopened = try HeaderChain(params: params, storageURL: url, start: .checkpoint)
        #expect(await reopened.startHeight == cp.height)
        #expect(await reopened.height == cp.height + 1)
        #expect(await reopened.tipHash == next.hash)
        #expect(await reopened.tipWork == workAfter)
        #expect(await reopened.blockHash(at: cp.height) == (await chain.blockHash(at: cp.height)))
    }

    @Test("turning verification on refuses the checkpoint-rooted file instead of misreading it")
    func genesisRefusesCheckpointFile() async throws {
        let params = NetworkParams.params(for: .mainnet)
        let cp = try #require(params.checkpoint)
        let url = tempURL("checkpoint-then-genesis")
        defer { try? FileManager.default.removeItem(at: url) }

        let chain = try HeaderChain(params: params, storageURL: url, start: .checkpoint)
        #expect(try await chain.connect([try BlockHeader.decode(Self.block900_001)]).appended == 1)

        // The file is not damaged; it just answers a different question. Saying
        // so lets the app rebuild rather than treat block 900,000 as block 0.
        #expect(throws: HeaderChainError.startMismatch(stored: cp.height, wanted: 0)) {
            _ = try HeaderChain(params: params, storageURL: url, start: .genesis)
        }
    }

    @Test("turning verification off keeps a chain that was already verified from genesis")
    func checkpointAcceptsGenesisFile() async throws {
        let params = NetworkParams.params(for: .signet)
        let url = tempURL("genesis-then-checkpoint")
        defer { try? FileManager.default.removeItem(at: url) }
        // Any genesis-rooted file will do; signet's is cheap to make.
        let chain = try HeaderChain(params: params, storageURL: url, start: .genesis)
        #expect(await chain.startHeight == 0)

        // A chain validated from block 0 already satisfies everything a
        // checkpoint start claims, so switching the setting must not throw it
        // away and re-sync.
        let reopened = try HeaderChain(params: params, storageURL: url, start: .checkpoint)
        #expect(await reopened.startHeight == 0)
    }
}


/// Choosing where to start for a given wallet (#89 phase 3).
///
/// This is the rule that keeps a speed optimisation from becoming a wrong
/// balance, so it is worth stating case by case.
@Suite("Checkpoint start policy")
struct CheckpointStartPolicyTests {
    private let mainnet = NetworkParams.params(for: .mainnet).checkpoint
    private var cpHeight: UInt32 { mainnet?.height ?? 0 }

    @Test("no wallet yet: the checkpoint is free to use")
    func noWallet() {
        #expect(HeaderChain.Start.forWallet(birthday: nil, checkpoint: mainnet,
                                            verifyFromGenesis: false) == .checkpoint)
    }

    @Test("a wallet born at or after the checkpoint keeps the fast path")
    func modernWallet() {
        #expect(HeaderChain.Start.forWallet(birthday: cpHeight, checkpoint: mainnet,
                                            verifyFromGenesis: false) == .checkpoint)
        #expect(HeaderChain.Start.forWallet(birthday: cpHeight + 50_000, checkpoint: mainnet,
                                            verifyFromGenesis: false) == .checkpoint)
    }

    @Test("a wallet older than the checkpoint gets the whole chain, setting or not")
    func olderWalletOverridesTheDefault() {
        // The blocks holding its coins are below the checkpoint, and filters
        // are fetched by block hash — a checkpoint-rooted chain simply cannot
        // ask about them. Reporting a balance short by whatever is down there
        // would be worse than a slow first launch.
        #expect(HeaderChain.Start.forWallet(birthday: 0, checkpoint: mainnet,
                                            verifyFromGenesis: false) == .genesis)
        #expect(HeaderChain.Start.forWallet(birthday: cpHeight - 1, checkpoint: mainnet,
                                            verifyFromGenesis: false) == .genesis)
    }

    @Test("the setting always wins toward more verification, never toward less")
    func settingOnlyAddsWork() {
        for birthday: UInt32? in [nil, 0, cpHeight, cpHeight + 1] {
            #expect(HeaderChain.Start.forWallet(birthday: birthday, checkpoint: mainnet,
                                                verifyFromGenesis: true) == .genesis)
        }
    }

    @Test("a network with no checkpoint always starts at genesis")
    func noCheckpoint() {
        #expect(NetworkParams.params(for: .signet).checkpoint == nil)
        #expect(HeaderChain.Start.forWallet(birthday: 900_000, checkpoint: nil,
                                            verifyFromGenesis: false) == .genesis)
    }
}
