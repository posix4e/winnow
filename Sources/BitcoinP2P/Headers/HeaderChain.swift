import Foundation

public enum HeaderChainError: LocalizedError, Equatable {
    case doesNotConnect
    case invalidTarget(height: UInt32)
    case targetAbovePowLimit(height: UInt32)
    case insufficientProofOfWork(height: UInt32)
    case reorgWithoutMoreWork
    case storageCorrupt(String)
    case storageUnavailable(String)
    case badPeerResponse(String)
    /// The stored chain starts somewhere the caller did not ask for — turning
    /// "verify from genesis" on with a checkpoint-rooted file, or the reverse.
    /// The chain is not corrupt, it just answers a different question, so the
    /// fix is to rebuild rather than to repair.
    case startMismatch(stored: UInt32, wanted: UInt32)

    public var errorDescription: String? {
        switch self {
        case .doesNotConnect:
            "A peer sent block headers that do not connect to the known Bitcoin chain."
        case let .startMismatch(stored, wanted):
            "The stored chain starts at block \(stored) but this setting needs one starting at \(wanted)."
        case let .invalidTarget(height):
            "A peer sent an invalid proof-of-work target at block \(height)."
        case let .targetAbovePowLimit(height):
            "A peer sent an impossibly easy proof-of-work target at block \(height)."
        case let .insufficientProofOfWork(height):
            "A peer sent a header without enough proof of work at block \(height)."
        case .reorgWithoutMoreWork:
            "A peer offered an older or weaker Bitcoin chain."
        case let .storageCorrupt(reason):
            "The saved block-header data is damaged (\(reason))."
        case let .storageUnavailable(reason):
            "Winnow could not read or save its local block-header data (\(reason))."
        case let .badPeerResponse(reason):
            "A peer returned an invalid block-header response (\(reason))."
        }
    }
}

/// Headers-only view of the best proof-of-work chain, synced with `getheaders`.
///
/// What is validated per header (deliberately minimal, light-client scope):
/// - previous-hash linkage to the known chain,
/// - compact bits decodes to a valid target ≤ consensus powLimit,
/// - SHA256d(header) ≤ target (proof of work).
///
/// What is NOT validated (documented deviation from full validation):
/// - the difficulty *retarget schedule* (claimed bits are accepted as long as
///   each header individually satisfies its claimed target),
/// - timestamps (no median-time-past / future-drift rules),
/// - anything below the header (merkle root, signet block signatures).
/// Fork choice is cumulative-work; competing branches replace ours only with
/// strictly more work.
public actor HeaderChain {
    public static let maxHeadersPerRequest = 2_000

    public let params: NetworkParams
    private let storageURL: URL?

    /// Main chain. Element 0 is at `baseHeight`; index + baseHeight = height.
    private var headers: [BlockHeader]
    /// Cumulative work, aligned with `headers`. Element 0 carries the work of
    /// the whole chain up to and including `headers[0]`, so fork choice keeps
    /// comparing totals even when the chain does not start at genesis.
    private var chainwork: [UInt256]
    /// Absolute heights, not indices.
    private var heightByHash: [Data: UInt32]
    /// Height of `headers[0]`. Zero when syncing from genesis; a checkpoint
    /// height when starting from one (#89). Every index/height conversion in
    /// this type goes through it.
    private let baseHeight: UInt32

    /// Where a fresh chain begins.
    ///
    /// `.genesis` re-derives every block's work from block 0, which is the
    /// wallet's original guarantee and takes minutes on first launch.
    /// `.checkpoint` starts from the constant in `NetworkParams`, which is
    /// derived from a genesis sync and reproducible (#89) — but is, in the end,
    /// a value shipped with the app rather than one the phone computed.
    public enum Start: Sendable, Equatable {
        case genesis
        case checkpoint

        /// Chooses where the chain should start for a given wallet.
        ///
        /// The checkpoint is a speed decision and must never become a
        /// correctness one. Compact filters are fetched by block hash, so a
        /// chain starting at the checkpoint cannot scan blocks below it — and a
        /// wallet whose history begins earlier would report a balance missing
        /// whatever it holds down there. Anything older than the checkpoint
        /// therefore starts at genesis regardless of the setting.
        ///
        /// - Parameters:
        ///   - walletBirthday: the lowest height whose filters the wallet still
        ///     needs; nil when there is no wallet yet.
        ///   - checkpoint: the network's checkpoint, if it ships one.
        ///   - verifyFromGenesis: the user's setting.
        public static func forWallet(birthday walletBirthday: UInt32?,
                                     checkpoint: NetworkParams.Checkpoint?,
                                     verifyFromGenesis: Bool) -> Start {
            if verifyFromGenesis { return .genesis }
            guard let checkpoint else { return .genesis }
            guard let walletBirthday else { return .checkpoint }
            return walletBirthday >= checkpoint.height ? .checkpoint : .genesis
        }
    }

    public init(params: NetworkParams, storageURL: URL? = nil, start: Start = .genesis) throws {
        self.params = params
        self.storageURL = storageURL
        // A network without a checkpoint (signet, whose whole chain is small)
        // starts at genesis whatever the setting says.
        let checkpoint = start == .checkpoint ? params.checkpoint : nil

        if let storageURL, FileManager.default.fileExists(atPath: storageURL.path) {
            let loaded: (headers: [BlockHeader], chainwork: [UInt256],
                         heightByHash: [Data: UInt32], baseHeight: UInt32)
            do {
                loaded = try Self.load(from: storageURL, params: params)
            } catch let error as HeaderChainError {
                throw error
            } catch {
                throw HeaderChainError.storageUnavailable(
                    "could not read the header file: \(error.localizedDescription)")
            }
            try Self.checkStoredStart(loaded.baseHeight, headers: loaded.headers, wanted: checkpoint)
            headers = loaded.headers
            chainwork = loaded.chainwork
            heightByHash = loaded.heightByHash
            baseHeight = loaded.baseHeight
        } else if let checkpoint {
            let header = try BlockHeader.decode(checkpoint.header)
            // PoW-check it like any other header. A checkpoint is a starting
            // point, not an exemption.
            _ = try Self.checkedWork(for: header, params: params, height: checkpoint.height)
            headers = [header]
            chainwork = [UInt256(bigEndian: checkpoint.chainwork)]
            heightByHash = [header.hash: checkpoint.height]
            baseHeight = checkpoint.height
        } else {
            let genesis = HeaderChain.genesisHeader(for: params)
            headers = [genesis]
            // Seed cumulative work for genesis.
            chainwork = [try Self.checkedWork(for: genesis, params: params, height: 0)]
            heightByHash = [genesis.hash: 0]
            baseHeight = 0
        }
    }

    /// A stored chain answers exactly one question — "starting where?" — and
    /// mixing the answers silently would misplace every height. Rather than
    /// repair a file that is not damaged, say which start it holds and let the
    /// caller rebuild.
    ///
    /// A genesis-rooted file is always accepted: it is strictly more validated
    /// than a checkpoint start asks for, so a user who already synced from
    /// genesis keeps their chain when the checkpoint default arrives.
    private static func checkStoredStart(_ storedBase: UInt32, headers: [BlockHeader],
                                         wanted: NetworkParams.Checkpoint?) throws {
        if storedBase == 0 { return }
        guard let wanted else {
            throw HeaderChainError.startMismatch(stored: storedBase, wanted: 0)
        }
        guard storedBase == wanted.height, headers.first?.serialized == wanted.header else {
            // Same height, different header means the file was written against
            // a different checkpoint constant than this build ships.
            throw HeaderChainError.startMismatch(stored: storedBase, wanted: wanted.height)
        }
    }

    /// Genesis header reconstructed from the network parameters.
    public static func genesisHeader(for params: NetworkParams) -> BlockHeader {
        BlockHeader(version: 1, previousHash: Data(repeating: 0, count: 32),
                    merkleRoot: params.genesisMerkleRoot, time: params.genesisTime,
                    bits: params.genesisBits, nonce: params.genesisNonce)
    }

    public var tip: BlockHeader { headers[headers.count - 1] }
    public var tipHash: Data { tip.hash }
    public var height: UInt32 { baseHeight + UInt32(headers.count - 1) }
    /// Lowest height this chain holds. Zero unless started from a checkpoint.
    public var startHeight: UInt32 { baseHeight }

    /// Cumulative chainwork at the tip, big-endian (display) byte order.
    public var tipWork: Data { chainwork[chainwork.count - 1].bigEndianData }

    public func header(at height: UInt32) -> BlockHeader? {
        guard height >= baseHeight else { return nil }
        let index = Int(height - baseHeight)
        return index < headers.count ? headers[index] : nil
    }

    public func blockHash(at height: UInt32) -> Data? {
        header(at: height)?.hash
    }

    /// Standard getheaders locator: the last 10 heights step 1, then
    /// exponentially larger steps back, ending at the first block this chain
    /// holds — genesis, or the checkpoint when started from one.
    public func blockLocator() -> [Data] {
        var locator: [Data] = []
        var step = 1
        var index = headers.count - 1
        while index > 0 {
            locator.append(headers[index].hash)
            if locator.count >= 10 { step *= 2 }
            index = max(index - step, 0)
        }
        locator.append(headers[0].hash)
        return locator
    }

    /// Validates PoW for one header. Returns the block's work contribution.
    static func checkedWork(for header: BlockHeader, params: NetworkParams, height: UInt32) throws -> UInt256 {
        let (target, work) = try targetAndWork(bits: header.bits, params: params, height: height)
        let hashAsNumber = UInt256(littleEndian: header.hash)
        guard hashAsNumber <= target else { throw HeaderChainError.insufficientProofOfWork(height: height) }
        return work
    }

    /// Target decoding and block-work division depend only on `bits`. Header
    /// files commonly repeat the same difficulty for long stretches, so load
    /// can cache this expensive result while still hashing and PoW-checking
    /// every individual header.
    private static func targetAndWork(bits: UInt32, params: NetworkParams,
                                      height: UInt32) throws -> (UInt256, UInt256) {
        guard let target = UInt256.target(compact: bits) else {
            throw HeaderChainError.invalidTarget(height: height)
        }
        let powLimit = UInt256(littleEndian: params.powLimit)
        guard target <= powLimit else { throw HeaderChainError.targetAbovePowLimit(height: height) }
        guard let work = UInt256.blockWork(target: target) else {
            throw HeaderChainError.invalidTarget(height: height)
        }
        return (target, work)
    }

    /// Connects a batch of headers received from a peer. The first header must
    /// build on a block already in the chain (usually the tip; an earlier
    /// height means a reorg, accepted only with strictly more total work).
    /// Returns the number of headers appended.
    @discardableResult
    public func connect(_ newHeaders: [BlockHeader]) throws -> Int {
        guard !newHeaders.isEmpty else { return 0 }
        guard let forkHeight = heightByHash[newHeaders[0].previousHash] else {
            throw HeaderChainError.doesNotConnect
        }

        // Fast path: extending the tip, which is every batch of an ordinary
        // sync. The staged path below copies both arrays and rebuilds the
        // whole hash index, so its cost grows with the chain — 460 batches
        // against mainnet meant hundreds of millions of redundant operations
        // (#86). An append touches only the new headers.
        if forkHeight == height {
            var previousHash = headers[headers.count - 1].hash
            var work = chainwork[chainwork.count - 1]
            var appended: [BlockHeader] = []
            var appendedWork: [UInt256] = []
            appended.reserveCapacity(newHeaders.count)
            appendedWork.reserveCapacity(newHeaders.count)
            for header in newHeaders {
                let height = baseHeight + UInt32(headers.count + appended.count)
                guard header.previousHash == previousHash else {
                    throw HeaderChainError.doesNotConnect
                }
                work = work + (try Self.checkedWork(for: header, params: params, height: height))
                appended.append(header)
                appendedWork.append(work)
                previousHash = header.hash
            }
            let firstNewHeight = baseHeight + UInt32(headers.count)
            headers.append(contentsOf: appended)
            chainwork.append(contentsOf: appendedWork)
            for (offset, header) in appended.enumerated() {
                heightByHash[header.hash] = firstNewHeight + UInt32(offset)
            }
            try persist()
            return newHeaders.count
        }

        let forkIndex = Int(forkHeight - baseHeight)
        var stagedHeaders = Array(headers[...forkIndex])
        var stagedWork = Array(chainwork[...forkIndex])
        for header in newHeaders {
            let height = baseHeight + UInt32(stagedHeaders.count)
            guard header.previousHash == stagedHeaders[stagedHeaders.count - 1].hash else {
                throw HeaderChainError.doesNotConnect
            }
            let work = try Self.checkedWork(for: header, params: params, height: height)
            stagedHeaders.append(header)
            stagedWork.append(stagedWork[stagedWork.count - 1] + work)
        }

        // A shorter replacement branch must carry strictly more work.
        if forkIndex < headers.count - 1,
           stagedWork[stagedWork.count - 1] <= chainwork[chainwork.count - 1] {
            throw HeaderChainError.reorgWithoutMoreWork
        }

        headers = stagedHeaders
        chainwork = stagedWork
        heightByHash = heightByHash.filter { $0.value <= forkHeight }
        for (index, header) in headers.enumerated() where heightByHash[header.hash] == nil {
            heightByHash[header.hash] = baseHeight + UInt32(index)
        }
        try persist()
        return newHeaders.count
    }

    /// Syncs from the current tip to the peer's best tip via getheaders.
    public func sync(using peer: PeerConnection, timeout: Duration = .seconds(30)) async throws {
        while true {
            let request = GetHeadersMessage(version: PeerConnection.protocolVersion,
                                            locatorHashes: blockLocator())
            let message = try await peer.request(.getheaders(request),
                                                 expecting: ["headers"],
                                                 timeout: timeout)
            guard case let .headers(batch) = message else {
                throw HeaderChainError.badPeerResponse("expected headers")
            }
            if batch.isEmpty { return }
            try connect(batch)
            if batch.count < Self.maxHeadersPerRequest { return }
        }
    }

    // MARK: - Persistence

    /// File format: uint32 LE header count, then raw 80-byte headers in height
    /// order. Rewritten atomically on every successful connect — fine for a
    /// fresh-wallet client whose chains are short.
    /// Legacy files begin with a header count. A count can never be this
    /// value, so it is safe as a format marker: seeing it means the file
    /// carries a base height and base work before the count.
    private static let formatMarker: UInt32 = 0xFFFF_FFFF
    private static let formatVersion: UInt32 = 1

    private func persist() throws {
        guard let storageURL else { return }
        var data = Data()
        if baseHeight == 0 {
            // Genesis-rooted chains keep the original layout, so a file
            // written here still opens in an older build.
            data.appendUInt32(UInt32(headers.count))
        } else {
            data.appendUInt32(Self.formatMarker)
            data.appendUInt32(Self.formatVersion)
            data.appendUInt32(baseHeight)
            data.append(chainwork[0].bigEndianData)
            data.appendUInt32(UInt32(headers.count))
        }
        for header in headers { data.append(header.serialized) }
        // .atomic writes to a temp file then renames — safe mid-write crash.
        do {
            try data.write(to: storageURL, options: .atomic)
        } catch {
            throw HeaderChainError.storageUnavailable(
                "could not save the header file: \(error.localizedDescription)")
        }
    }

    /// A header file is bounded before it is read, the way the compact-filter
    /// progress file already is.
    ///
    /// Mainnet headers are 80 bytes each and grow by roughly 4 MB a year, so
    /// the whole chain is well under 100 MB and this ceiling leaves decades of
    /// headroom. It exists for the file that is *not* a real chain: a damaged
    /// or tampered store is read during startup, and `Data(contentsOf:)` on an
    /// arbitrarily large file exhausts memory before any of the fail-closed
    /// corruption handling downstream gets a chance to run.
    static let maximumHeaderFileBytes = 256 * 1_024 * 1_024

    private static func load(from url: URL, params: NetworkParams) throws
        -> (headers: [BlockHeader], chainwork: [UInt256], heightByHash: [Data: UInt32], baseHeight: UInt32) {
        if let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
           let size = attributes[.size] as? NSNumber,
           size.int64Value > Int64(maximumHeaderFileBytes) {
            throw HeaderChainError.storageCorrupt(
                "header file is \(size.int64Value) bytes, above the \(maximumHeaderFileBytes)-byte limit")
        }
        let data = try Data(contentsOf: url)
        // Re-checked after reading: the file can change between the two.
        guard data.count <= maximumHeaderFileBytes else {
            throw HeaderChainError.storageCorrupt(
                "header file is \(data.count) bytes, above the \(maximumHeaderFileBytes)-byte limit")
        }
        var reader = ByteReader(data)
        guard let first = try? reader.readUInt32() else {
            throw HeaderChainError.storageCorrupt("bad length")
        }
        var baseHeight: UInt32 = 0
        var baseWork = UInt256()
        var prefix = 4
        var count = first
        if first == formatMarker {
            guard let version = try? reader.readUInt32(), version == formatVersion else {
                throw HeaderChainError.storageCorrupt("unsupported header-file version")
            }
            guard let base = try? reader.readUInt32(),
                  let workBytes = try? reader.readBytes(32),
                  let stored = try? reader.readUInt32()
            else { throw HeaderChainError.storageCorrupt("truncated header-file prefix") }
            baseHeight = base
            baseWork = UInt256(bigEndian: workBytes)
            count = stored
            prefix = 4 + 4 + 4 + 32 + 4
        }
        guard data.count == prefix + Int(count) * BlockHeader.serializedSize else {
            throw HeaderChainError.storageCorrupt("bad length")
        }
        let genesis = HeaderChain.genesisHeader(for: params)
        var loadedHeaders: [BlockHeader] = []
        var loadedWork: [UInt256] = []
        var work = UInt256()
        var workByBits: [UInt32: (target: UInt256, work: UInt256)] = [:]
        for index in 0 ..< count {
            guard let header = try? BlockHeader.decode(from: &reader) else {
                throw HeaderChainError.storageCorrupt("bad header at \(index)")
            }
            let parameters: (target: UInt256, work: UInt256)
            if let cached = workByBits[header.bits] {
                parameters = cached
            } else {
                parameters = try targetAndWork(bits: header.bits, params: params, height: baseHeight + index)
                workByBits[header.bits] = parameters
            }
            // Caching block-work must never cache header validity: every hash
            // remains independently checked against the repeated target.
            let hashAsNumber = UInt256(littleEndian: header.hash)
            guard hashAsNumber <= parameters.target else {
                throw HeaderChainError.insufficientProofOfWork(height: baseHeight + index)
            }
            if index == 0, baseHeight > 0 {
                // The first header of a checkpoint chain carries the work of
                // everything before it, which cannot be recomputed from a file
                // that does not contain those headers.
                work = baseWork
            } else {
                work = work + parameters.work
            }
            if baseHeight == 0, index == 0, header != genesis {
                throw HeaderChainError.storageCorrupt("genesis mismatch")
            }
            if index > 0, header.previousHash != loadedHeaders[loadedHeaders.count - 1].hash {
                throw HeaderChainError.storageCorrupt("broken linkage at \(baseHeight + index)")
            }
            loadedHeaders.append(header)
            loadedWork.append(work)
        }
        let index = Dictionary(uniqueKeysWithValues:
            loadedHeaders.enumerated().map { ($1.hash, baseHeight + UInt32($0)) })
        return (loadedHeaders, loadedWork, index, baseHeight)
    }
}
