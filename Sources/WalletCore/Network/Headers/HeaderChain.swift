import Foundation

public enum HeaderChainError: LocalizedError, Equatable {
    case doesNotConnect
    case invalidTarget(height: UInt32)
    case targetAbovePowLimit(height: UInt32)
    case insufficientProofOfWork(height: UInt32)
    /// The header's target differs from the network's required difficulty.
    case unexpectedDifficulty(height: UInt32)
    /// The header claims a time more than two hours ahead of this device's
    /// clock — Core's rule, and the one that stops a fabricated chain from
    /// easing its own difficulty by pretending weeks have passed.
    case timestampTooFarInFuture(height: UInt32)
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
        case let .unexpectedDifficulty(height):
            "A peer sent the wrong proof-of-work difficulty at block \(height)."
        case let .timestampTooFarInFuture(height):
            "A peer sent a block header dated too far in the future at block \(height)."
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
/// - SHA256d(header) ≤ target (proof of work),
/// - the required difficulty, including the timespan-based adjustment every
///   2,016 blocks on mainnet and signet. The same rule applies during sync,
///   a reorg, and loading saved headers.
///
/// - a timestamp no more than two hours ahead of the device clock (Core's
///   future-drift rule), so a chain cannot ease its own difficulty by
///   claiming that weeks have passed.
///
/// What is NOT validated (documented deviation from full validation):
/// - the first adjustment after a mid-period checkpoint, when the preceding
///   period's first header is unavailable, is verified only as a bound:
///   Core clamps every retarget to at most four times easier, so a target
///   past 4× the previous one is refused, but the exact value is not known.
///   The shipped mainnet checkpoint sits on a period boundary (959,616 =
///   476 × 2016), so no such adjustment exists today; the bound stays as the
///   guard for any future mid-period constant,
/// - median-time-past (no rule against a timestamp earlier than recent ones),
/// - anything below the header (merkle root, signet block signatures).
/// Fork choice is cumulative-work; competing branches replace ours only with
/// strictly more work.
public actor HeaderChain {
    public static let maxHeadersPerRequest = 2_000
    /// How far ahead of the device clock a header's time may be (Core's
    /// MAX_FUTURE_BLOCK_TIME).
    public static let maximumFutureDrift: UInt32 = 2 * 60 * 60
    public let params: NetworkParams
    private let storageURL: URL?
    /// The device clock in seconds, injectable so a test can move it.
    private let now: @Sendable () -> UInt32

    /// Main chain. Element 0 is at `baseHeight`; index + baseHeight = height.
    private var headers: [BlockHeader]
    /// Cumulative work, aligned with `headers`. Element 0 carries the work of
    /// the whole chain up to and including `headers[0]`, so fork choice keeps
    /// comparing totals even when the chain does not start at genesis.
    private var chainwork: [UInt256]
    /// How many headers the file on disk currently claims. Tracked so an
    /// append knows where the record area ends without re-reading the file,
    /// and so any divergence falls back to a full rewrite rather than writing
    /// at a guessed offset (#83).
    private var persistedCount: Int = 0
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

    public init(params: NetworkParams, storageURL: URL? = nil, start: Start = .genesis,
                now: @escaping @Sendable () -> UInt32 = { UInt32(clamping: Int(Date().timeIntervalSince1970)) }) throws {
        self.params = params
        self.storageURL = storageURL
        self.now = now
        // A network without a checkpoint (signet, whose whole chain is small)
        // starts at genesis whatever the setting says.
        let checkpoint = start == .checkpoint ? params.checkpoint : nil

        if let storageURL, FileManager.default.fileExists(atPath: storageURL.path) {
            let loaded: (headers: [BlockHeader], chainwork: [UInt256], baseHeight: UInt32)
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
            baseHeight = loaded.baseHeight
            persistedCount = loaded.headers.count
        } else if let checkpoint {
            let header = try BlockHeader.decode(checkpoint.header)
            // PoW-check it like any other header. A checkpoint is a starting
            // point, not an exemption.
            _ = try Self.checkedWork(for: header, params: params, height: checkpoint.height)
            headers = [header]
            chainwork = [UInt256(bigEndian: checkpoint.chainwork)]
            baseHeight = checkpoint.height
        } else {
            let genesis = HeaderChain.genesisHeader(for: params)
            headers = [genesis]
            // Seed cumulative work for genesis.
            chainwork = [try Self.checkedWork(for: genesis, params: params, height: 0)]
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
    /// The tip's height and hash read in one job, for a caller that must not
    /// see them move between two reads: a cfcheckpt request names the hash
    /// and expects the count the height implies.
    public var tipSnapshot: (height: UInt32, hash: Data) { (height, tip.hash) }
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

    /// Core's CalculateNextWorkRequired, including regtest's fixed difficulty.
    /// nil means a checkpoint omitted the history needed for this adjustment.
    static func expectedBits(height: UInt32, previous: BlockHeader,
                             periodFirst: BlockHeader?, params: NetworkParams) throws -> UInt32? {
        guard !params.noRetargeting, height % params.difficultyAdjustmentInterval == 0 else { return previous.bits }
        guard let periodFirst else { return nil }
        guard let target = UInt256.target(compact: previous.bits) else {
            throw HeaderChainError.invalidTarget(height: height - 1)
        }
        let timespan = Int64(params.powTargetTimespan)
        let elapsed = min(max(Int64(previous.time) - Int64(periodFirst.time), timespan / 4), timespan * 4)
        let adjusted = target.multiplied(by: UInt32(elapsed))
            .quotientAndRemainder(dividingBy: UInt256(UInt64(timespan))).quotient
        return min(adjusted, UInt256(littleEndian: params.powLimit)).compact
    }

    /// The caller supplies the preceding branch by index, so an uncommitted
    /// batch and a replacement branch use their own period-start header.
    private static func requireDifficulty(_ header: BlockHeader, height: UInt32, baseHeight: UInt32,
                                          params: NetworkParams, preceding: (Int) -> BlockHeader) throws {
        guard height > baseHeight else { return }
        let interval = params.difficultyAdjustmentInterval
        let firstIndex = Int(height) - Int(interval) - Int(baseHeight)
        let first = height % interval == 0 && firstIndex >= 0 ? preceding(firstIndex) : nil
        let previous = preceding(Int(height - baseHeight) - 1)
        let expected = try expectedBits(height: height, previous: previous, periodFirst: first, params: params)
        if let expected {
            guard header.bits == expected else { throw HeaderChainError.unexpectedDifficulty(height: height) }
        } else {
            try requireBoundedAdjustment(header, previous: previous, params: params, height: height)
        }
    }

    /// The one adjustment a mid-period checkpoint cannot verify exactly is
    /// still bounded. Core clamps every retarget to at most four times
    /// easier, so a target beyond 4× the previous one is wrong whatever the
    /// period's timestamps were. Before this bound the first boundary after
    /// the checkpoint accepted any target up to powLimit — difficulty 1 —
    /// which under eclipse made a fabricated chain cost 2^32 hashes a block.
    static func requireBoundedAdjustment(_ header: BlockHeader, previous: BlockHeader,
                                         params: NetworkParams, height: UInt32) throws {
        guard let target = UInt256.target(compact: header.bits),
              let previousTarget = UInt256.target(compact: previous.bits)
        else { throw HeaderChainError.invalidTarget(height: height) }
        let ceiling = min(previousTarget.multiplied(by: 4), UInt256(littleEndian: params.powLimit))
        guard target <= ceiling else { throw HeaderChainError.unexpectedDifficulty(height: height) }
    }

    /// Core's future-drift rule. Every retarget reads the period's first and
    /// last timestamps, and the clamp allows 4× easier per period only when
    /// four target timespans appear to have elapsed — so a header dated far
    /// enough ahead would let a chain lower its own difficulty. Two hours of
    /// drift is what Core tolerates.
    private func requireTimestamp(_ header: BlockHeader, height: UInt32) throws {
        let limit = now() &+ Self.maximumFutureDrift
        guard header.time <= limit else { throw HeaderChainError.timestampTooFarInFuture(height: height) }
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
    /// Reports what the batch did, including the fork height when it replaced
    /// an existing branch -- the one fact a consumer needs in order to rewind.
    @discardableResult
    public func connect(_ newHeaders: [BlockHeader]) throws -> ConnectOutcome {
        guard let first = newHeaders.first else { return ConnectOutcome(appended: 0) }
        guard let parent = index(of: first.previousHash) else {
            throw HeaderChainError.doesNotConnect
        }
        // A reply can repeat known headers before extending the chain. Find
        // its parent once, then compare the known prefix in chain order.
        var nextIndex = parent + 1
        var remaining = newHeaders[...]
        while let first = remaining.first, nextIndex < headers.count, first == headers[nextIndex] {
            remaining = remaining.dropFirst()
            nextIndex += 1
        }
        guard !remaining.isEmpty else { return ConnectOutcome(appended: 0) }
        let newHeaders = Array(remaining)
        if nextIndex == headers.count {
            return try appendToTip(newHeaders)
        }
        return try replaceBranch(with: newHeaders, forkHeight: baseHeight + UInt32(nextIndex - 1))
    }

    /// Ordinary sync extends the tip. For an older parent, the next stored
    /// header already contains its hash; search backwards without retaining
    /// a second hash index for the entire chain. Element zero's predecessor
    /// is outside the chain, including when it starts at a checkpoint.
    private func index(of hash: Data) -> Int? {
        if hash == tipHash { return headers.count - 1 }
        guard let child = headers.lastIndex(where: { $0.previousHash == hash }), child > 0 else { return nil }
        return child - 1
    }

    /// The ordinary-sync path: proof-of-work-check and append, with the
    /// persistence write incremental too. A reorg cannot reach here, so the
    /// outcome carries no fork height by definition.
    private func appendToTip(_ newHeaders: [BlockHeader]) throws -> ConnectOutcome {
        var previous = headers[headers.count - 1]
        var work = chainwork[chainwork.count - 1]
        var appended: [BlockHeader] = []
        var appendedWork: [UInt256] = []
        appended.reserveCapacity(newHeaders.count)
        appendedWork.reserveCapacity(newHeaders.count)
        for header in newHeaders {
            let height = baseHeight + UInt32(headers.count + appended.count)
            guard header.previousHash == previous.hash else {
                throw HeaderChainError.doesNotConnect
            }
            work = work + (try Self.checkedWork(for: header, params: params, height: height))
            try requireTimestamp(header, height: height)
            try Self.requireDifficulty(header, height: height, baseHeight: baseHeight, params: params) { index in
                index < headers.count ? headers[index] : appended[index - headers.count]
            }
            appended.append(header)
            appendedWork.append(work)
            previous = header
        }
        headers.append(contentsOf: appended)
        chainwork.append(contentsOf: appendedWork)
        try persistAppended(from: headers.count - appended.count)
        return ConnectOutcome(appended: newHeaders.count)
    }

    /// The reorg path: stage the replacement branch from the fork, admit it
    /// only with strictly more work, then swap the stored chain.
    private func replaceBranch(with newHeaders: [BlockHeader],
                               forkHeight: UInt32) throws -> ConnectOutcome {
        let forkIndex = Int(forkHeight - baseHeight)
        var stagedHeaders = Array(headers[...forkIndex])
        var stagedWork = Array(chainwork[...forkIndex])
        for header in newHeaders {
            let height = baseHeight + UInt32(stagedHeaders.count)
            let previous = stagedHeaders[stagedHeaders.count - 1]
            guard header.previousHash == previous.hash else {
                throw HeaderChainError.doesNotConnect
            }
            let work = try Self.checkedWork(for: header, params: params, height: height)
            try requireTimestamp(header, height: height)
            try Self.requireDifficulty(header, height: height, baseHeight: baseHeight, params: params) {
                stagedHeaders[$0]
            }
            stagedHeaders.append(header)
            stagedWork.append(stagedWork[stagedWork.count - 1] + work)
        }

        // A shorter replacement branch must carry strictly more work.
        if forkIndex < headers.count - 1,
           stagedWork[stagedWork.count - 1] <= chainwork[chainwork.count - 1] {
            throw HeaderChainError.reorgWithoutMoreWork
        }

        let disconnected = headers.count - 1 - forkIndex
        headers = stagedHeaders
        chainwork = stagedWork
        try persist()
        return ConnectOutcome(appended: newHeaders.count,
                              forkHeight: disconnected > 0 ? forkHeight : nil,
                              disconnectedHeaders: disconnected)
    }

    /// Syncs from the current tip to the peer's best tip via getheaders.
    @discardableResult
    public func sync(using peer: PeerConnection,
                     timeout: Duration = .seconds(30)) async throws -> SyncOutcome {
        var outcome = SyncOutcome()
        var replays = 0
        while true {
            let request = GetHeadersMessage(version: PeerConnection.protocolVersion,
                                            locatorHashes: blockLocator())
            let message = try await peer.request(.getheaders(request),
                                                 expecting: ["headers"],
                                                 timeout: timeout)
            guard case let .headers(batch) = message else {
                throw HeaderChainError.badPeerResponse("expected headers")
            }
            if batch.isEmpty { return outcome }
            let answeredNothing = try connectSyncReply(batch, replays: replays, outcome: &outcome)
            // Ask again, a bounded number of times, so the sync ends on the
            // peer's actual answer rather than on a batch it did not mean.
            if answeredNothing {
                replays += 1
                if replays > Self.maxReplayedBatches { return outcome }
                continue
            }
            if batch.count < Self.maxHeadersPerRequest { return outcome }
        }
    }

    /// Interprets a single reply without mixing response classification with
    /// the async request loop. Only connected headers alter the chain.
    private func connectSyncReply(_ batch: [BlockHeader], replays: Int,
                                  outcome: inout SyncOutcome) throws -> Bool {
        do {
            let connected = try connect(batch)
            outcome.absorb(connected)
            // A batch made only of headers already held answers nothing:
            // it was an announcement or a stale reply that the wait
            // consumed in place of the real one.
            return connected.appended == 0
        } catch HeaderChainError.doesNotConnect where batch.count == 1 {
            // A BIP130 tip announcement can race the requested reply
            // after the transport has purged its old backlog. Its parent
            // may be ahead of our chain. Never append it without linkage;
            // request the missing chain again within the same retry budget.
            guard replays < Self.maxReplayedBatches else {
                throw HeaderChainError.doesNotConnect
            }
            return true
        } catch HeaderChainError.reorgWithoutMoreWork
            where batch.count == 1 && batch[0].previousHash == tip.previousHash {
            // A sibling of our tip with no more work: the losing block
            // of a race the peer saw first. Being on the losing side is
            // a state, not a lie, so it counts as a batch that answered
            // nothing. A lighter branch longer than one block is not
            // what a race produces and stays a fault.
            outcome.staleSiblings += 1
            return true
        }
    }

    /// How many already-known batches one sync call absorbs before it
    /// returns without news rather than asking again.
    static let maxReplayedBatches = 4

    // MARK: - Persistence

    /// File format: uint32 LE header count, then raw 80-byte headers in height
    /// order. Rewritten atomically on every successful connect — fine for a
    /// fresh-wallet client whose chains are short.
    /// Legacy files begin with a header count. A count can never be this
    /// value, so it is safe as a format marker: seeing it means the file
    /// carries a base height and base work before the count.
    private static let formatMarker: UInt32 = 0xFFFF_FFFF
    private static let formatVersion: UInt32 = 1

    /// Bytes before the first header: a bare count for the genesis layout,
    /// marker + version + baseHeight + baseWork + count for the other.
    private var prefixSize: Int { baseHeight == 0 ? 4 : 4 + 4 + 4 + 32 + 4 }
    /// Offset of the mutable header count within the prefix.
    private var countOffset: Int { baseHeight == 0 ? 0 : 4 + 4 + 4 + 32 }

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
            try data.write(to: storageURL,
                           options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            throw HeaderChainError.storageUnavailable(
                "could not save the header file: \(error.localizedDescription)")
        }
        persistedCount = headers.count
    }

    /// Writes only the headers appended since the last save.
    ///
    /// Rewriting the whole file on every batch is what made mainnet header
    /// sync get slower as it ran: 963,000 headers is 77 MB, re-serialised and
    /// re-written 460 times over a first sync (#83). The layout is a
    /// fixed-size prefix followed by fixed 80-byte records in height order, so
    /// the new headers go straight onto the end and the only field that
    /// changes is the count.
    ///
    /// **Payload first, then the count.** That order is the whole crash-safety
    /// argument. A crash between the two leaves a file whose count is stale
    /// and whose tail is bytes nothing refers to — recoverable, and the tail is
    /// ignored on load. The reverse order would leave a count claiming headers
    /// that are not there, which is indistinguishable from real truncation.
    /// Each write is followed by `synchronize()` so the order survives the
    /// filesystem, not just the process.
    ///
    /// Falls back to a full rewrite whenever the file is not in the state this
    /// assumes — a different persisted count, or no file at all.
    private func persistAppended(from oldCount: Int) throws {
        guard let storageURL else { return }
        guard oldCount == persistedCount, oldCount > 0,
              FileManager.default.fileExists(atPath: storageURL.path)
        else {
            try persist()
            return
        }
        var payload = Data()
        payload.reserveCapacity((headers.count - oldCount) * BlockHeader.serializedSize)
        for header in headers[oldCount...] { payload.append(header.serialized) }

        do {
            let handle = try FileHandle(forWritingTo: storageURL)
            defer { try? handle.close() }
            try handle.seek(toOffset: UInt64(prefixSize + oldCount * BlockHeader.serializedSize))
            try handle.write(contentsOf: payload)
            // Drop anything a previously interrupted append left beyond the
            // new end, so the file is exactly the length its count implies.
            try handle.truncate(atOffset: UInt64(prefixSize + headers.count * BlockHeader.serializedSize))
            try handle.synchronize()

            var count = Data()
            count.appendUInt32(UInt32(headers.count))
            try handle.seek(toOffset: UInt64(countOffset))
            try handle.write(contentsOf: count)
            try handle.synchronize()
        } catch {
            throw HeaderChainError.storageUnavailable(
                "could not append to the header file: \(error.localizedDescription)")
        }
        persistedCount = headers.count
    }

    /// The most recent reorg this chain applied.
    ///
    /// `connect` returns only how many headers it appended, so a caller cannot
    /// tell an ordinary extension from a branch swap that disconnected blocks
    /// it has already acted on. Anything deriving state from block contents —
    /// the wallet's scan frontier above all — has to know, because a
    /// forward-only scan never revisits a height it has passed. Without this
    /// the swap is silent and downstream state keeps describing the orphaned
    /// branch.
    /// What one batch of headers did to the chain.
    public struct ConnectOutcome: Equatable, Sendable {
        /// Headers this batch added.
        public var appended: Int
        /// The last height the old and new branches agree on, when the batch
        /// replaced an existing branch. nil for an ordinary extension.
        public var forkHeight: UInt32?
        /// How many headers the swap removed.
        public var disconnectedHeaders: Int = 0
    }

    /// What a whole sync did.
    ///
    /// This replaced a sticky `lastReorg` property, which was the wrong shape
    /// twice over: a poller could read the same value after later ordinary
    /// syncs and roll back a second time, and two swaps inside one sync
    /// collapsed into whichever happened last, losing the deeper one.
    ///
    /// Reporting the *lowest* fork height of the sync fixes both, and it can
    /// because a rollback is a pure function of the height it rolls back to.
    /// Rolling back to the lowest fork covers every swap the sync performed,
    /// so collapsing becomes harmless rather than lossy, and no event identity
    /// or acknowledgement protocol is needed. The value is per-sync and is not
    /// retained, so it cannot be replayed.
    public struct SyncOutcome: Equatable, Sendable {
        /// Headers added across the whole sync.
        public var connected: Int = 0
        /// The lowest fork height of any branch swap during this sync, or nil
        /// if the chain only ever extended.
        public var minForkHeight: UInt32?
        /// Headers disconnected across the whole sync.
        public var disconnectedHeaders: Int = 0

        /// Batches that offered a sibling of the tip with no more work — the
        /// peer is on the losing side of a race, not lying.
        public var staleSiblings = 0

        mutating func absorb(_ batch: ConnectOutcome) {
            connected += batch.appended
            disconnectedHeaders += batch.disconnectedHeaders
            guard let fork = batch.forkHeight else { return }
            minForkHeight = min(minForkHeight ?? fork, fork)
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
        -> (headers: [BlockHeader], chainwork: [UInt256], baseHeight: UInt32) {
        let data = try readBoundedHeaderFile(at: url)
        var reader = ByteReader(data)
        let (baseHeight, baseWork, count, prefix) = try parsedHeaderFilePrefix(&reader)
        // A file SHORTER than its count claims is truncation — bytes the count
        // says are there and are not — and stays a refusal.
        //
        // A file LONGER is the interrupted-append case, and is read up to the
        // count with the tail ignored. Headers are appended before the count
        // that admits them (#83), so a crash between the two writes leaves
        // exactly this shape, and refusing it would turn every crash during
        // header sync into a corrupt-file error requiring a full resync.
        //
        // This does relax a check that previously refused any trailing bytes.
        // What it costs is small: the count gates how many records are read,
        // so bytes past it are never decoded, and an attacker who can write
        // the file can write a consistent count just as easily — padding was
        // never the barrier. The barrier is that every header up to the count
        // is independently proof-of-work and linkage checked below, and that
        // is unchanged.
        let expectedLength = prefix + Int(count) * BlockHeader.serializedSize
        guard data.count >= expectedLength else {
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
            try checkLineage(of: header, at: index, baseHeight: baseHeight,
                             genesis: genesis, loaded: loadedHeaders)
            try requireDifficulty(header, height: baseHeight + index, baseHeight: baseHeight, params: params) {
                loadedHeaders[$0]
            }
            loadedHeaders.append(header)
            loadedWork.append(work)
        }
        return (loadedHeaders, loadedWork, baseHeight)
    }

    /// A loaded header must be the genesis where the file starts at genesis,
    /// and must link to its predecessor everywhere else.
    private static func checkLineage(of header: BlockHeader, at index: UInt32,
                                     baseHeight: UInt32, genesis: BlockHeader,
                                     loaded: [BlockHeader]) throws {
        if baseHeight == 0, index == 0, header != genesis {
            throw HeaderChainError.storageCorrupt("genesis mismatch")
        }
        if index > 0, header.previousHash != loaded[loaded.count - 1].hash {
            throw HeaderChainError.storageCorrupt("broken linkage at \(baseHeight + index)")
        }
    }

    /// The header file, read under the byte cap — checked against the
    /// reported size before reading and against the bytes after, because the
    /// file can change between the two.
    private static func readBoundedHeaderFile(at url: URL) throws -> Data {
        if let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
           let size = attributes[.size] as? NSNumber,
           size.int64Value > Int64(maximumHeaderFileBytes) {
            throw HeaderChainError.storageCorrupt(
                "header file is \(size.int64Value) bytes, above the \(maximumHeaderFileBytes)-byte limit")
        }
        let data = try Data(contentsOf: url)
        guard data.count <= maximumHeaderFileBytes else {
            throw HeaderChainError.storageCorrupt(
                "header file is \(data.count) bytes, above the \(maximumHeaderFileBytes)-byte limit")
        }
        return data
    }

    /// The file's prefix: either a bare legacy count, or the versioned
    /// marker followed by checkpoint base height, accumulated base work, and
    /// the stored count.
    private static func parsedHeaderFilePrefix(_ reader: inout ByteReader) throws
        -> (baseHeight: UInt32, baseWork: UInt256, count: UInt32, prefix: Int) {
        guard let first = try? reader.readUInt32() else {
            throw HeaderChainError.storageCorrupt("bad length")
        }
        guard first == formatMarker else { return (0, UInt256(), first, 4) }
        guard let version = try? reader.readUInt32(), version == formatVersion else {
            throw HeaderChainError.storageCorrupt("unsupported header-file version")
        }
        guard let base = try? reader.readUInt32(),
              let workBytes = try? reader.readBytes(32),
              let stored = try? reader.readUInt32()
        else { throw HeaderChainError.storageCorrupt("truncated header-file prefix") }
        return (base, UInt256(bigEndian: workBytes), stored, 4 + 4 + 4 + 32 + 4)
    }
}
