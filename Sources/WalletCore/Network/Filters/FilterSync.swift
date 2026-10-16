import Foundation

public enum FilterSyncError: LocalizedError, Equatable, Sendable {
    case busy
    case noPeers
    /// Every peer is briefly resting after a slow reply — transient, unlike
    /// `noPeers`, which means there is nothing to dial at all.
    case peersCoolingDown(Int)
    /// Peers (or a peer vs. our pinned chain) disagree on filter commitments.
    case checkpointMismatch(String)
    case badPeerResponse(String)
    /// A cfilter's hash does not reproduce the pinned filter header chain.
    case filterHeaderMismatch(height: UInt32)
    /// A cfilter arrived for a block we did not ask about.
    case unexpectedBlockHash
    /// The pool is holding seats for transaction relay only
    /// (`PeerPool.enterRelayOnly(seats:)`), so there is no read side to run.
    case relayOnly
    /// `FilterSync.CrossCheckPolicy.requireDistinctSources` is in force and
    /// the peers that agreed about our filter commitments did not span
    /// acquisition channels, so the run advanced nothing.
    case crossCheckUnavailable(String)

    public var errorDescription: String? {
        switch self {
        case .busy:
            "Finishing sync. Try loading the payment again in a moment."
        case .noPeers:
            "No Bitcoin peers are available for compact-filter synchronization."
        case .relayOnly:
            "Winnow is keeping Bitcoin peers connected only to finish relaying a payment. Resume syncing to scan for new blocks."
        case let .peersCoolingDown(count):
            "\(count) Bitcoin peer\(count == 1 ? " is" : "s are") resting briefly after a slow reply. Scanning will resume on its own."
        case let .checkpointMismatch(reason):
            "Bitcoin peers disagreed about compact-filter checkpoints (\(reason))."
        case let .badPeerResponse(reason):
            "A Bitcoin peer returned invalid compact-filter data (\(reason))."
        case let .filterHeaderMismatch(height):
            "A compact filter did not match its authenticated header at block \(height)."
        case .unexpectedBlockHash:
            "A Bitcoin peer returned a compact filter for a block Winnow did not request."
        case let .crossCheckUnavailable(reason):
            "Winnow could not check this scan against connections from different sources (\(reason)). Nothing was scanned; it will try again as the peer pool changes."
        }
    }
}

public enum FilterSyncStorageError: LocalizedError, Equatable, Sendable {
    case unreadable
    case tooLarge(maxBytes: Int)
    case damaged(String)
    case writeFailed
    case frontierBeforeWallet(stored: UInt32, wallet: UInt32)
    case frontierBeyondTip(stored: UInt32, tip: UInt32)

    public var errorDescription: String? {
        switch self {
        case .unreadable:
            "Winnow could not read its compact-filter progress file. Scanning is stopped so wallet history is not skipped."
        case let .tooLarge(maxBytes):
            "The compact-filter progress file is unexpectedly large (limit: \(maxBytes) bytes). Scanning is stopped."
        case let .damaged(reason):
            "The compact-filter progress file is damaged (\(reason)). Scanning is stopped; Winnow will not replace it automatically."
        case .writeFailed:
            "Winnow could not safely save compact-filter progress. The scan frontier was not advanced."
        case let .frontierBeforeWallet(stored, wallet):
            "Saved compact-filter progress starts at block \(stored), behind the wallet's required block \(wallet). Scanning is stopped."
        case let .frontierBeyondTip(stored, tip):
            "Saved compact-filter progress points to block \(stored), beyond the validated chain tip \(tip). Scanning is stopped."
        }
    }
}

/// A block whose compact filter matched the watch list.
public struct BlockMatch: Sendable, Equatable {
    public let height: UInt32
    public let blockHash: Data // internal byte order
    public let block: Block

    public init(height: UInt32, blockHash: Data, block: Block) {
        self.height = height
        self.blockHash = blockHash
        self.block = block
    }
}

/// BIP157 client-side filter sync, forward-only from a start height
/// (fresh-wallet design: see docs/read-side.md).
///
/// Flow per `sync` run:
/// 1. Sync the block-header chain to the peer tip (getheaders).
/// 2. `getcfcheckpt` at the tip from up to 3 peers spanning source classes —
///    the same selection step 3 uses, not seating order; peers that disagree
///    with the majority answer are disconnected (BIP157 filters are not
///    consensus-committed — cross-peer comparison is the mitigation). Which
///    endpoints agreed, and through which acquisition channels, is recorded
///    as a `CrossCheckReceipt` and saved beside the frontier, and
///    `CrossCheckPolicy` decides whether an answer that came through a single
///    channel may advance the scan at all.
/// 3. `getcfheaders` per ≤1000-block batch from up to 3 peers spanning source
///    classes, judged by the same strict-majority rule as step 2 — never by
///    which peer was seated first; the announced previous filter header must
///    equal our pinned header at batchStart-1 (zero at genesis), then the
///    filter-hash chain is walked forward and pinned per height. Every
///    checkpoint boundary the batch pins is compared against the cfcheckpt
///    reference before the batch's filters are read.
/// 4. `getcfilters` (type 0x00) for the batch, asked for in chunks of
///    `filtersPerChunk` and released chunk by chunk; each filter must
///    reproduce the pinned header chain given the block hash from our
///    PoW-checked header chain — this is what anchors filters to the block
///    chain.
/// 5. Each filter is matched locally against the watch list with BitcoinCore's
///    GCSFilter; on a hit the full block is fetched (getdata MSG_WITNESS_BLOCK),
///    its hash verified, and handed to `onMatch`.
/// 6. Progress (next scan height + pinned filter headers) is persisted after
///    every batch whose boundary comparison passed. A batch that fails it
///    delivers no match and persists nothing, so no store ever carries
///    effects from a batch whose commitments were refused. What is written is
///    pruned to the headers a later check can still ask for: every checkpoint
///    boundary, and the run of recent heights a reorg could rewind into
///    (`prunedFilterHeaders`).
///
/// A run scans to the chain tip unless the caller passes `maxBlocks`, which
/// stops it that many blocks past the frontier; the next run resumes from the
/// persisted frontier.
public actor FilterSync {
    public enum PersistenceState: Equatable, Sendable {
        case disabled
        case missing
        case loaded
    }

    public static let basicFilterType: UInt8 = 0
    /// Bitcoin Core serves at most 1000 filters / 2000 filter headers per request.
    public static let maxRangePerRequest: UInt32 = 1_000
    /// BIP157 checkpoint interval in blocks.
    public static let checkpointInterval: UInt32 = 1_000
    /// How many filters one `getcfilters` request asks for. A batch is still
    /// up to `maxRangePerRequest` blocks — that is the span the cfheaders
    /// cross-check covers and the span progress is saved after — but its
    /// filters arrive a chunk at a time, so a scan holds a chunk rather than
    /// a whole batch. At 100 the burst a peer can put in memory before any of
    /// it is matched is a tenth of what it was.
    public static let defaultFiltersPerChunk: UInt32 = 100

    /// The most bytes one `cfilter` message may carry before the peer sending
    /// it is refused, and the unit `chunkByteBound` multiplies out.
    ///
    /// Derived, because nothing already stated bounds it usefully.
    /// `GCSFilter.maxEncodedSize` is the decoder's resource ceiling and is
    /// 4,000,000 — the same number as `MessageFramer.maxPayloadSize`, so a
    /// burst bounded by it is bounded by exactly what the framer already
    /// enforced, message by message, and 100 of those is 400 MB.
    ///
    /// A BIP158 basic filter is bounded by the block it summarises. The
    /// element set is one entry per non-OP_RETURN output plus one per spent
    /// prevout script, and a block of at most 4,000,000 serialized bytes
    /// (Core's MAX_BLOCK_SERIALIZED_SIZE, which is also the protocol message
    /// maximum) cannot hold more than 4,000,000 / 9 ≈ 444,444 outputs, the
    /// smallest output being 8 value bytes and a 1-byte empty script; inputs
    /// are 41 bytes each and so bound the count lower still. Golomb-Rice at
    /// P=19 spends 19 remainder bits plus a unary terminator per element, and
    /// the quotients over the whole sorted set sum to at most n·M / 2^19 ≈
    /// 1.5n bits, so an n-element filter is under 21.5n bits — about 2.7n
    /// bytes, or ~1.19 MB at the maximum n. This rounds that up, and stays
    /// far above the 15–20 KB a real full block actually produces.
    ///
    /// It is a resource bound, deliberately not a plausibility one: refusing
    /// at anything near what honest peers send would drop them on the first
    /// unusual block, and that is a worse failure than holding 1.25 MB.
    public static let maxFilterMessageBytes = 1_250_000

    /// How many bytes a chunk of `filters` cfilters may total. The bound
    /// travels with the request, so a short final chunk is bounded by its own
    /// length rather than by the chunk size the run was configured with.
    static func chunkByteBound(filters: Int) -> Int {
        filters * maxFilterMessageBytes
    }

    /// How many distinct source classes must agree before
    /// `CrossCheckPolicy.requireDistinctSources` lets a scan advance. Two,
    /// because what it rules out is one channel agreeing with itself, and how
    /// many answers are needed to name a liar is a separate question the
    /// strict-majority tally already asks.
    public static let minimumAgreeingSourceClasses = 2

    /// Whether a scan may advance on answers that all reached us through one
    /// acquisition channel.
    ///
    /// `crossSourceSet` already prefers a set that spans classes, but it is a
    /// ceiling and not a quota: one class, or one peer, is used rather than
    /// refused. Two ordinary pool states reach that, neither of them an
    /// attack. `DiversityPolicy` exempts manual peers from the source rule, so
    /// someone who typed in three of their own nodes has one class holding
    /// every seat; and the ceiling counts against `peerCount` rather than
    /// against how many peers are actually connected, so a pool sitting at two
    /// of its three seats admits two peers of one class. In both, the
    /// comparison that is supposed to span channels can run entirely inside
    /// one of them.
    ///
    /// Every network defaults to `acceptSingleSource`, which is how the scan
    /// behaved before the policy existed: a pool that can only ever reach one
    /// class (overlay-only routing seats census peers alone; a user who typed
    /// in every seat holds manual peers alone) keeps syncing. Requiring
    /// distinct sources on mainnet by default is a product decision for its
    /// own change, with a way for those pools to satisfy it; a caller that
    /// wants it today passes `requireDistinctSources` explicitly.
    public enum CrossCheckPolicy: String, Codable, Sendable, CaseIterable {
        public static func `default`(for network: BitcoinNetwork) -> Self {
            .acceptSingleSource
        }

        /// Whatever agreed is enough, down to a lone surviving peer.
        case acceptSingleSource
        /// The adopted `cfcheckpt` answer must have come from peers of at
        /// least `minimumAgreeingSourceClasses` distinct known classes, or the
        /// run throws `FilterSyncError.crossCheckUnavailable` having changed
        /// nothing.
        case requireDistinctSources

        /// Whether this run's agreement may advance spend-relevant state.
        func admits(_ receipt: CrossCheckReceipt) -> Bool {
            switch self {
            case .acceptSingleSource: true
            case .requireDistinctSources: receipt.spansDistinctSources
            }
        }
    }

    /// Who agreed about the filter commitments a run scanned on, kept so a
    /// caller can say afterwards which acquisition channels corroborated the
    /// answer rather than inferring it from configuration — which, per
    /// `CrossCheckPolicy`, does not imply it.
    ///
    /// It attests to the checkpoint comparison the run anchored on, not to
    /// every request that followed it. A peer that agreed and then dropped is
    /// still named, because what was corroborated across channels is the
    /// answer this run scanned against; the per-batch cfheaders comparison
    /// then runs over whichever approved peers are still there, and the batch
    /// commit is refused if it disagrees with that answer either way.
    ///
    /// Saved with the frontier and rewritten on every commit, so the two
    /// always describe the same pass; a run that advances nothing leaves the
    /// previous receipt alone because it left the frontier alone too. A
    /// degraded run under `acceptSingleSource` writes an honest one-class
    /// receipt rather than none — missing corroboration is a thing to record,
    /// not to hide — and `spansDistinctSources` is what separates the two.
    public struct CrossCheckReceipt: Codable, Sendable, Equatable {
        /// One peer whose `cfcheckpt` answer was adopted.
        public struct Agreement: Codable, Sendable, Equatable {
            /// `PeerEndpoint.description`: host and port, which is what the
            /// pool already writes to its peers file.
            public let endpoint: String
            /// The class the pool reached this endpoint through, and nil when
            /// it knows none. An unknown class never counts towards
            /// `spansDistinctSources`: not knowing where a peer came from is
            /// not evidence that it came from somewhere else.
            public let source: PeerSource?

            public init(endpoint: String, source: PeerSource?) {
                self.endpoint = endpoint
                self.source = source
            }

            private enum CodingKeys: String, CodingKey { case endpoint, source }

            /// A class this build does not know decodes as nil — "unknown
            /// never counts" is already what nil means — rather than refusing
            /// the whole progress file over a note about who corroborated it.
            public init(from decoder: any Decoder) throws {
                let container = try decoder.container(keyedBy: CodingKeys.self)
                endpoint = try container.decode(String.self, forKey: .endpoint)
                source = try container.decodeIfPresent(String.self, forKey: .source)
                    .flatMap(PeerSource.init(rawValue:))
            }
        }

        /// The chain height the answers were about.
        public let tipHeight: UInt32
        /// SHA256d over the adopted `cfcheckpt` message, hex. Two receipts
        /// carrying the same digest name the same answer, so runs can be
        /// compared without keeping the checkpoint list itself.
        public let answerDigest: String
        /// The peers whose answer was adopted, in the order they were asked.
        public let agreed: [Agreement]

        public init(tipHeight: UInt32, answerDigest: String, agreed: [Agreement]) {
            self.tipHeight = tipHeight
            self.answerDigest = answerDigest
            self.agreed = agreed
        }

        /// The distinct known classes among `agreed`.
        public var sourceClasses: Set<PeerSource> { Set(agreed.compactMap(\.source)) }

        /// Whether the agreement spans acquisition channels.
        ///
        /// "At least two distinct classes agreed" and "no single class
        /// supplied every agreeing answer" are one predicate, not two, once
        /// the classes being counted are the *agreeing peers'* rather than the
        /// pool's. Counting the pool's is the mistake this type exists to
        /// stop: a pool holding three classes proves nothing about which of
        /// them answered.
        public var spansDistinctSources: Bool {
            sourceClasses.count >= FilterSync.minimumAgreeingSourceClasses
        }
    }

    /// Persisted sync progress.
    public struct Progress: Codable, Sendable, Equatable {
        /// Height of the next block whose filter must be scanned.
        public var nextScanHeight: UInt32
        /// Pinned filter headers: decimal height → hex (internal byte order).
        public var filterHeaders: [String: String]
        /// The cross-check the run that last moved this frontier ran. Nil in a
        /// file written before receipts existed — an absent field decodes to
        /// nil, so there is nothing to migrate — and nil after a rollback,
        /// which is a corroboration taken on a branch that no longer exists.
        public var crossCheck: CrossCheckReceipt?
        /// What a file says it is, when it says. Forward progress never
        /// writes it (a nil is omitted from the JSON), so every file on disk
        /// carries none; a range-scan record writes `RangeScanProgress.recordKind`,
        /// which is how `validate(progress:startHeight:)` refuses one that was
        /// handed to the forward loader.
        public private(set) var record: String?

        public init(nextScanHeight: UInt32, filterHeaders: [String: String] = [:],
                    crossCheck: CrossCheckReceipt? = nil) {
            self.nextScanHeight = nextScanHeight
            self.filterHeaders = filterHeaders
            self.crossCheck = crossCheck
        }
    }

    public let pool: PeerPool
    public let chain: HeaderChain
    /// How many peers to consult for the cfcheckpt comparison (and for the
    /// initial cfheaders cross-check). If fewer are connected, all connected
    /// peers are used and the comparison simply covers those.
    ///
    /// Defaults to the whole pool rather than a subset of it. At two, the
    /// comparison took the first two connected peers — and the pool's source
    /// ceiling permits two peers to share a class, so the check that exists to
    /// compare independent sources could run entirely inside one of them (#3).
    /// Consulting every connected peer removes that: no class may hold the
    /// whole pool, so a full-pool comparison necessarily spans more than one
    /// source. It also uses all the evidence available instead of discarding a
    /// third of it, at the cost of one extra round trip per sync.
    ///
    /// That last argument holds less than it reads, which is why the peers
    /// asked are now chosen by `crossSourceSet` rather than by seating order
    /// and why `CrossCheckPolicy` counts the classes that actually answered.
    /// `DiversityPolicy` exempts manual peers from the source rule, so an
    /// all-manual pool is one class holding every seat; and its ceiling counts
    /// against `peerCount`, not against how many peers are connected, so a
    /// pool at two of three seats admits two peers of one class. In both, a
    /// full-pool comparison spans exactly one source.
    public let requiredCheckpointPeers: Int
    /// Filters per `getcfilters` request, clamped to 1 ... `maxRangePerRequest`.
    /// A caller that is tighter on memory than on round trips lowers it; see
    /// `defaultFiltersPerChunk`.
    public let filtersPerChunk: UInt32
    /// Whether this instance may advance on answers from a single acquisition
    /// channel. Defaults to `CrossCheckPolicy.default(for:)` for the network.
    public let crossCheckPolicy: CrossCheckPolicy
    private let storageURL: URL?
    public nonisolated let persistenceState: PersistenceState
    private var progress: Progress
    private var requesting = false
    var rangeRun: RangeScanRun?

    private static let maximumProgressBytes = 128 * 1_024 * 1_024
    private static let maximumPinnedHeaders = 2_000_000
    /// A receipt names the peers that answered one `getcfcheckpt` round, which
    /// is at most three. The bound is generous rather than exact because it is
    /// here to stop a file growing without limit, not to restate a request
    /// size a later version may change.
    private static let maximumReceiptEntries = 64
    /// `host:port`, and a hostname is bounded at 253 characters.
    private static let maximumReceiptEndpointBytes = 320

    public init(pool: PeerPool, chain: HeaderChain, startHeight: UInt32,
                storageURL: URL? = nil, requiredCheckpointPeers: Int = 3,
                filtersPerChunk: UInt32 = FilterSync.defaultFiltersPerChunk,
                crossCheckPolicy: CrossCheckPolicy? = nil) throws {
        self.pool = pool
        self.chain = chain
        self.storageURL = storageURL
        self.requiredCheckpointPeers = requiredCheckpointPeers
        self.filtersPerChunk = min(max(1, filtersPerChunk), Self.maxRangePerRequest)
        self.crossCheckPolicy = crossCheckPolicy ?? .default(for: pool.params.network)
        if let storageURL {
            let result = try Self.load(storageURL: storageURL, startHeight: startHeight)
            persistenceState = result.state
            progress = result.progress
        } else {
            persistenceState = .disabled
            progress = Progress(nextScanHeight: startHeight)
        }
    }

    public var nextScanHeight: UInt32 { progress.nextScanHeight }
    /// Highest fully-scanned height; nil when nothing has been scanned yet.
    public var lastScannedHeight: UInt32? {
        progress.nextScanHeight == 0 ? nil : progress.nextScanHeight - 1
    }

    /// The next height to scan and the hash of the last block scanned, read
    /// together so a caller can persist both (`Wallet.recordScanHeight`)
    /// without a pass landing between two reads.
    public func frontier() async -> (nextScanHeight: UInt32, scannedThroughHash: Data?) {
        let next = progress.nextScanHeight
        guard next > 0 else { return (next, nil) }
        return (next, await chain.blockHash(at: next - 1))
    }

    public func filterHeader(at height: UInt32) -> Data? {
        progress.filterHeaders[String(height)].flatMap { Data(hex: $0) }
    }

    /// One run at a time, shared by `sync`, `transaction(_:at:)` and
    /// `scanRange`: all three take this flag, so any of them while another
    /// is running throws `busy` having changed nothing.
    func beginRequest() throws {
        guard !requesting else { throw FilterSyncError.busy }
        requesting = true
    }

    func endRequest() { requesting = false }

    /// Fetch a historical receipt without changing scan progress or balances.
    /// Peer requests match by command, so they cannot overlap a filter scan.
    public func transaction(_ txid: Data, at height: UInt32) async throws -> Transaction {
        try beginRequest()
        defer { requesting = false }
        guard let hash = await chain.blockHash(at: height) else {
            throw FilterSyncError.badPeerResponse("the payment's block header is unavailable")
        }
        var lastError: any Error = FilterSyncError.noPeers
        // Through the same gate as a scan: a relay-only pool holds its seats
        // for a payment going out, and a bad block here would unseat the only
        // one through `misbehaving` with nothing to dial a replacement.
        for peer in try await peersForReading().prefix(3) {
            try Task.checkCancellation()
            do {
                let block = try await verifiedBlock(from: peer, height: height, blockHash: hash,
                                                    timeout: .seconds(30))
                guard await chain.blockHash(at: height) == hash,
                      let transaction = block.transactions.first(where: { $0.txid == txid }) else {
                    throw FilterSyncError.badPeerResponse("the payment is not in this block")
                }
                return transaction
            } catch { lastError = error }
        }
        throw lastError
    }

    /// The cross-check that authorised the frontier on disk, which is what a
    /// caller reads after a restart to say which sources it is standing on.
    /// Nil means no run has advanced this store since receipts existed, or a
    /// rollback cleared one — never "it was corroborated and we lost the note".
    public var lastCrossCheck: CrossCheckReceipt? { progress.crossCheck }

    /// `maxBlocks` bounds one run: at most that many blocks are scanned before
    /// it returns, and the next call resumes from the persisted frontier. Nil
    /// scans to the tip, which is what every caller had before. A bounded run
    /// is for a scheduler that must hand control back on a deadline — a
    /// foreground-only scan on a phone — rather than run to the tip once.
    ///
    /// `onReorg` is called with the fork height when the header sync replaced a
    /// branch, and is awaited **before** any filter work resumes.
    ///
    /// Returns the run's `CrossCheckReceipt` — who agreed about the filter
    /// commitments it scanned on — or nil for a run that found nothing to
    /// scan and so compared nobody. The same receipt is saved with the
    /// frontier, so a caller that restarts reads `lastCrossCheck` instead.
    /// Discardable: a caller that does not check its corroboration is in
    /// exactly the position it was in before receipts existed.
    ///
    /// The ordering is the requirement, not a convenience. Scanning forward
    /// from a frontier that describes the orphaned branch is precisely the bug
    /// being fixed, so the rollback has to finish first, and a throw from it
    /// aborts the sync rather than proceeding with state that is known stale
    /// (#127).
    @discardableResult
    public func sync(watchScripts: [Data],
                     maxBlocks: UInt32? = nil,
                     onReorg: (@Sendable (UInt32) async throws -> Void)? = nil,
                     onMatch: @Sendable (BlockMatch) async throws -> Void) async throws
        -> CrossCheckReceipt? {
        try beginRequest()
        defer { requesting = false }
        var peers = try await peersForReading()

        // 1. Headers to tip. A stale or broken peer is evicted and the pool
        // retries another peer without discarding already-persisted progress.
        let headerOutcome = try await pool.syncHeaders(chain)

        // 1a. A branch was replaced, so everything derived from the old one is
        // wrong. Roll back to the lowest fork the sync saw before reading a
        // single filter: the frontier below is the thing that would otherwise
        // carry the orphaned branch forward.
        try await rollBackIfForked(headerOutcome, onReorg: onReorg)
        peers = await pool.connectedPeers()
        guard !peers.isEmpty else { throw FilterSyncError.noPeers }
        let (tip, tipHash) = await chain.tipSnapshot
        try Self.validate(progress: progress, againstTip: tip)
        guard tip >= progress.nextScanHeight else { return nil }
        // How far this run may go. Everything below stops at the ceiling
        // rather than the tip, and a run that asked for no blocks at all stops
        // before any filter request is sent.
        guard let room = Self.scanCeiling(frontier: progress.nextScanHeight,
                                          maxBlocks: maxBlocks, tip: tip) else { return nil }

        // 2. cfcheckpt cross-peer comparison: collect answers about our tip,
        // adopt the majority, and only peers whose answer matched may go on
        // to serve filters. A pinned boundary the adopted reference
        // contradicts is rewound here, before any filter is read, when the
        // reference has the cross-source agreement to outrank it.
        let (reference, approvedEndpoints, receipt) = try await adoptReference(
            from: peers, tipHash: tipHash, tip: tip, onReorg: onReorg)
        peers = try await approved(peers: approvedEndpoints)
        // A rewind may have moved the frontier back; the ceiling follows it.
        let ceiling = Self.scanCeiling(frontier: progress.nextScanHeight,
                                       maxBlocks: maxBlocks, tip: tip) ?? room

        // 3+4+5. Batches of ≤1000 blocks, to the tip or this run's ceiling.
        // A ceiling below the tip only shortens the last batch, exactly as the
        // tip already does, so the cross-check and the save still happen once
        // per batch.
        while progress.nextScanHeight <= ceiling {
            let batchStart = progress.nextScanHeight
            let batchStop = UInt32(min(UInt64(batchStart) + UInt64(Self.maxRangePerRequest) - 1, UInt64(ceiling)))
            guard let stopHash = await chain.blockHash(at: batchStop) else {
                throw FilterSyncError.badPeerResponse("missing header at \(batchStop)")
            }
            let proposedHeaders = try await pinFilterHeaders(
                batchStart: batchStart, batchStop: batchStop,
                stopHash: stopHash, peers: peers,
                startingFrom: progress.filterHeaders)
            // Every checkpoint boundary this batch pins is compared against
            // the cfcheckpt reference before the batch is applied. All of the
            // batch's effects — the caller's `onMatch` work, the scan
            // frontier, the persisted progress — are downstream of this line,
            // so a batch whose commitments disagree with the announced
            // checkpoints is refused having changed nothing. Comparing only
            // at the end of the sync (below) left every batch already applied
            // by the time the disagreement was found, and left the boundaries
            // crossed by earlier batches uncompared until the next run.
            try Self.checkPinnedBoundaries(of: proposedHeaders, against: reference, tip: tip)
            // The cross-check may have just disconnected `peers[0]` as the
            // minority, so the list is re-derived before anything is sent to
            // it. Same intersection as above, for the same reason: a long
            // sync must not drift onto replacements dialled mid-scan whose
            // checkpoints were never compared against anyone's. If every
            // approved peer has gone, stop rather than continue unvetted —
            // the next `sync` redoes the comparison from scratch.
            peers = try await approved(peers: approvedEndpoints)
            try await scanFilters(batchStart: batchStart, batchStop: batchStop,
                                  peer: peers[0], watchScripts: watchScripts,
                                  filterHeaders: proposedHeaders,
                                  onMatch: onMatch)
            var candidate = progress
            candidate.nextScanHeight = batchStop + 1
            // The whole batch was needed to verify the batch; only the part a
            // later check can still ask for is kept.
            candidate.filterHeaders = Self.prunedFilterHeaders(
                proposedHeaders, frontier: candidate.nextScanHeight)
            // Written on every batch rather than once at the end, so the
            // corroboration on disk can never describe an older pass than the
            // frontier beside it — including when a later batch throws.
            candidate.crossCheck = receipt
            try persist(candidate)
            progress = candidate
        }

        // Final guard: the highest checkpoint header we computed must equal
        // the one the checkpoint peers announced (Core's last cfcheckpt entry
        // is the header at the greatest multiple of 1000 ≤ tip). A bounded run
        // that stopped below that height has not pinned it yet, so there is
        // nothing to compare and the run that reaches it does the comparing.
        //
        let lastCheckpoint = (tip / Self.checkpointInterval) * Self.checkpointInterval
        if lastCheckpoint > 0, let pinned = filterHeader(at: lastCheckpoint),
           let announced = reference.filterHeaders.last, pinned != announced {
            throw FilterSyncError.checkpointMismatch("checkpoint filter header at \(lastCheckpoint) disagrees with cfcheckpt")
        }
        return receipt
    }

    /// The peers a run may read the chain over, refused in the read side's own
    /// terms. A relay-only pool is holding seats so a signed payment can finish
    /// going out, not so the chain can be read over them; the header sync
    /// would refuse anyway, and refusing first spends no cfcheckpt round trip.
    /// Entry only: a run already past this keeps reading over the seats if the
    /// pool narrows underneath it (see `PeerPool.enterRelayOnly(seats:)`; the
    /// caller cancels and awaits a running scan before narrowing). An empty
    /// pool is routinely a transient state rather than a peerless one, since
    /// transport failures cool peers off rather than banning them, so "no
    /// peers" is said only when nothing is cooling (#82).
    func peersForReading() async throws -> [PeerConnection] {
        guard await pool.mode == .full else { throw FilterSyncError.relayOnly }
        let peers = await pool.connectedPeers()
        guard !peers.isEmpty else {
            let cooling = await pool.coolingEndpoints.count
            throw cooling > 0 ? FilterSyncError.peersCoolingDown(cooling) : FilterSyncError.noPeers
        }
        return peers
    }

    /// The cfcheckpt anchoring every run is judged against, shared by the
    /// forward sync and the range scan so the two cannot drift: collect the
    /// peers' answers about the tip, adopt the majority, require it to speak
    /// for every boundary the tip has, build the receipt naming who agreed,
    /// admit it under the cross-check policy, and hand back the endpoints
    /// allowed to serve filters.
    ///
    /// Core's ProcessGetCFCheckPt returns exactly `stopHeight / 1000` headers,
    /// so a shorter list is not a terse peer: it is a list that says nothing
    /// about the boundaries it omits, and every comparison below reads the
    /// reference by index and compares only the heights it mentions. An empty
    /// list once retired every boundary comparison at once and let a sync
    /// report success on a filter-commitment chain no checkpoint ever covered.
    /// A sub-1000-block chain announcing nothing is honest and permitted: the
    /// expectation is the count our own tip implies, which is zero there.
    ///
    /// The receipt is built before the policy is consulted so a refusal can
    /// say what it saw, and the approved set is derived from the same agreeing
    /// peers by construction rather than by two filters that could drift. The
    /// policy runs ahead of every effect a run could have, including its first
    /// `onMatch`.
    func anchoredReference(peers: [PeerConnection], tip: UInt32, tipHash: Data) async throws
        -> (reference: CFCheckptMessage, approved: Set<String>, receipt: CrossCheckReceipt) {
        let checkpoints = try await collectedCheckpoints(from: peers, tipHash: tipHash, tip: tip)
        let reference = try await majorityReference(of: checkpoints).message
        let expected = Int(tip / Self.checkpointInterval)
        guard reference.filterHeaders.count == expected else {
            throw FilterSyncError.checkpointMismatch(
                "cfcheckpt announced \(reference.filterHeaders.count) checkpoints for tip \(tip), expected \(expected)")
        }
        let agreeing = checkpoints.filter { $0.message == reference }
        let receipt = Self.receipt(tipHeight: tip, answer: reference, agreed: agreeing)
        try requireAdmissible(receipt)
        let approved = await Self.endpoints(of: agreeing.map(\.peer))
        return (reference, approved, receipt)
    }

    /// Refuses the run when the agreement does not meet the policy, naming
    /// what was seen rather than what was wanted: "cannot cross-check yet" is
    /// only worth showing someone if it can say how far short the pool fell.
    func requireAdmissible(_ receipt: CrossCheckReceipt) throws {
        guard crossCheckPolicy.admits(receipt) else {
            let peers = receipt.agreed.count
            let classes = receipt.sourceClasses.count
            throw FilterSyncError.crossCheckUnavailable(
                "\(peers) peer\(peers == 1 ? "" : "s") agreed, from \(classes) known source class\(classes == 1 ? "" : "es")")
        }
    }

    /// The run's receipt: the adopted answer, digested, and the peers that
    /// gave it beside the class the pool reached each of them through.
    ///
    /// The class is read from the pool rather than assumed from the seat, and
    /// nil — a peer the pool has no class for — is carried through as nil
    /// rather than guessed at, because `spansDistinctSources` has to be able
    /// to refuse it.
    static func receipt(
        tipHeight: UInt32, answer: CFCheckptMessage,
        agreed: [(peer: PeerConnection, source: PeerSource?, message: CFCheckptMessage)])
        -> CrossCheckReceipt {
        CrossCheckReceipt(
            tipHeight: tipHeight,
            answerDigest: SHA256d.hash(answer.serialized).hex,
            agreed: agreed.map {
                CrossCheckReceipt.Agreement(endpoint: $0.peer.endpoint.description,
                                            source: $0.source)
            })
    }

    /// A branch was replaced, so everything derived from the old one is wrong:
    /// roll back to the lowest fork the header sync saw before reading a
    /// single filter. The caller goes first because it owns the crash marker;
    /// nothing may change in any store until the target height is recorded,
    /// or a crash leaves stores disagreeing with no way to know a rollback was
    /// ever in progress.
    private func rollBackIfForked(_ outcome: HeaderChain.SyncOutcome,
                                  onReorg: (@Sendable (UInt32) async throws -> Void)?) async throws {
        guard let forkHeight = outcome.minForkHeight else { return }
        try await onReorg?(forkHeight)
        try rollBack(to: forkHeight)
    }

    /// Step 2 of a sync: the cfcheckpt comparison, whose adopted answer
    /// decides which peers may serve filters and whether anything already
    /// pinned has to be rewound before a filter is read.
    private func adoptReference(from peers: [PeerConnection], tipHash: Data, tip: UInt32,
                                onReorg: (@Sendable (UInt32) async throws -> Void)?) async throws
        -> (reference: CFCheckptMessage, approved: Set<String>, receipt: CrossCheckReceipt) {
        let result = try await anchoredReference(peers: peers, tip: tip, tipHash: tipHash)
        try await reconcilePins(with: result.reference, crossSource: result.receipt.spansDistinctSources,
                                tip: tip, onReorg: onReorg)
        return result
    }

    /// Pinned checkpoint headers must match the adopted reference. When one
    /// does not, whose fault it is depends on how the reference was reached.
    /// A reference agreed across source classes outranks the pin: the pin was
    /// made under the same rule with no more evidence — in degraded mode, or
    /// before votes required cross-source agreement — so the wallet rewinds
    /// to the last boundary both agree on and re-verifies from there, through
    /// the same rollback a reorg uses. Before this, a wrongly pinned header
    /// made every later honest answer throw, and the wallet could not sync
    /// with anyone again until it was re-imported. A reference from a single
    /// class, or from a lone peer, rewinds nothing: there the pin keeps the
    /// benefit of the doubt and the sync stops as it always did.
    private func reconcilePins(with reference: CFCheckptMessage, crossSource: Bool, tip: UInt32,
                               onReorg: (@Sendable (UInt32) async throws -> Void)?) async throws {
        guard let disputed = Self.lowestDisputedBoundary(of: progress.filterHeaders,
                                                         against: reference, tip: tip) else { return }
        guard crossSource else {
            throw FilterSyncError.checkpointMismatch("pinned header at \(disputed) disagrees with cfcheckpt")
        }
        let target = disputed - Self.checkpointInterval
        try await onReorg?(target)
        try rollBack(to: target)
    }

    /// The highest block one run may scan: `maxBlocks` blocks from the
    /// frontier, never past the tip. Nil `maxBlocks` means the tip — the
    /// unbounded behaviour of a caller that does not ask to be bounded — and a
    /// nil result means a run with no room, which scans nothing.
    ///
    /// The sum is taken in 64 bits because a caller may reasonably say
    /// `UInt32.max` to mean "as far as you can get", and a 32-bit add would
    /// trap on it.
    static func scanCeiling(frontier: UInt32, maxBlocks: UInt32?, tip: UInt32) -> UInt32? {
        // Progress stores the next height in UInt32. Do not scan a block
        // whose successor cannot be represented; a hostile height cannot wrap.
        let representableTip = min(tip, UInt32.max - 1)
        guard frontier <= representableTip else { return nil }
        guard let maxBlocks else { return representableTip }
        guard maxBlocks > 0 else { return nil }
        return UInt32(min(UInt64(frontier) + UInt64(maxBlocks) - 1, UInt64(representableTip)))
    }

    /// One cfcheckpt answer per peer that answered about our chain tip.
    ///
    /// The reply must answer the question we asked. Without this the stop
    /// hash is only ever compared peer-to-peer in the majority tally, so a
    /// single peer — or peers that agree — could answer about a different
    /// chain entirely and be believed. `pinFilterHeaders` has always checked
    /// its own stop hash; this path had not.
    ///
    /// A mismatch evicts that peer and carries on rather than throwing. The
    /// other peers may be answering honestly, and refusing the whole sync on
    /// one bad reply would hand any single hostile peer a denial of service —
    /// the opposite of what cross-peer comparison is for. An honest peer
    /// cannot trip this: it echoes the stop hash we sent, so a tip that
    /// advances mid-loop simply means we scan to the tip we asked about and
    /// catch the rest on the next run.
    ///
    /// Which peers are asked is `crossSourceSet`'s decision, the same one the
    /// cfheaders layer makes, rather than `prefix` over seating order: this is
    /// the comparison every later check is anchored to, so it is the last
    /// place that should be settled by which peer happened to connect first.
    /// Each answer carries the class the pool reached its peer through, so the
    /// receipt names channels that answered instead of channels that were
    /// dialled.
    func collectedCheckpoints(from peers: [PeerConnection], tipHash: Data, tip: UInt32)
        async throws -> [(peer: PeerConnection, source: PeerSource?, message: CFCheckptMessage)] {
        let sourced = await sourced(peers)
        let classes = Dictionary(
            sourced.compactMap { entry in
                entry.source.map { (entry.peer.endpoint.description, $0) }
            },
            uniquingKeysWith: { first, _ in first })
        let checkpointPeers = Self.crossSourceSet(
            sourced, limit: max(1, min(3, requiredCheckpointPeers)))
        var checkpoints: [(peer: PeerConnection, source: PeerSource?, message: CFCheckptMessage)] = []
        checkpoints.reserveCapacity(checkpointPeers.count)
        for peer in checkpointPeers {
            let response: PeerMessage
            do {
                response = try await peer.request(
                    .getcfcheckpt(GetCFCheckptRequest(stopHash: tipHash)),
                    expecting: ["cfcheckpt"])
            } catch let error as PeerError where error.isTransport {
                // Slow, dropped, or — the case that found this — a peer that
                // hangs up because we asked about a tip it has never seen.
                // Cool it off and ask the others, the same distinction the
                // header sync draws (#82). Throwing here stalled a mainnet
                // sync on the same batch every pass while two honest peers
                // sat idle beside the broken one.
                await pool.transportFailure(peer, reason: error.localizedDescription)
                continue
            }
            guard case let .cfcheckpt(message) = response else {
                throw FilterSyncError.badPeerResponse("expected cfcheckpt")
            }
            guard message.stopHash == tipHash else {
                await pool.misbehaving(peer, reason: "cfcheckpt stop hash mismatch")
                continue
            }
            guard message.filterHeaders.count == Int(tip / Self.checkpointInterval) else {
                await pool.misbehaving(peer, reason: "cfcheckpt count mismatch")
                continue
            }
            checkpoints.append((peer, classes[peer.endpoint.description], message))
        }
        guard !checkpoints.isEmpty else {
            throw FilterSyncError.badPeerResponse(
                "no peer answered the cfcheckpt request for our chain tip")
        }
        return checkpoints
    }

    /// The MAJORITY cfcheckpt answer — never checkpoints[0] by fiat, or a
    /// lying first peer could evict the honest ones and become the sole
    /// reference. Peers outside the majority are disconnected. With no strict
    /// majority (e.g. two peers that disagree) the lie is unattributable, so
    /// every checkpoint peer is dropped and the pool replenishes and retries.
    ///
    /// A lone survivor is accepted in degraded mode. Its commitments are
    /// checked against retained pins, but self-consistency does not establish
    /// correctness: filters are not committed by Bitcoin consensus. Source
    /// diversity reduces correlated failures; it does not prove independence.
    private func majorityReference(
        of checkpoints: [(peer: PeerConnection, source: PeerSource?, message: CFCheckptMessage)])
        async throws -> (message: CFCheckptMessage, crossSource: Bool) {
        guard checkpoints.count > 1 else { return (checkpoints[0].message, false) }
        let answers: [(peer: PeerConnection, value: CFCheckptMessage)] =
            checkpoints.map { (peer: $0.peer, value: $0.message) }
        guard let majority = Self.strictMajority(of: answers) else {
            for entry in checkpoints {
                await pool.misbehaving(entry.peer, reason: "cfcheckpt no majority")
            }
            throw FilterSyncError.checkpointMismatch("no cfcheckpt majority across \(checkpoints.count) peers")
        }
        let agreeing = checkpoints.filter { $0.message == majority.value }.map(\.peer)
        let vote = await sourceSpan(agreeing: agreeing, dissenting: majority.minority)
        guard !vote.disputed else {
            try await refuseDisputedVote(checkpoints.map(\.peer),
                                         reason: "cfcheckpt: one source class outvotes another")
        }
        // A majority the policy is about to refuse is not evidence against
        // the peers that disagreed with it: under `requireDistinctSources` a
        // single-class majority advances nothing, so its dissenters are cooled
        // off rather than struck from the persisted good-peers list on that
        // one channel's word. Only a majority the run can stand on bans.
        await dismissMinority(majority.minority,
                              condemned: vote.crossSource || crossCheckPolicy == .acceptSingleSource)
        return (majority.value, vote.crossSource)
    }

    /// The peers outvoted by a majority: struck when the majority is one the
    /// run can stand on, cooled off when the policy is about to refuse it.
    private func dismissMinority(_ peers: [PeerConnection], condemned: Bool) async {
        for peer in peers {
            if condemned {
                await pool.misbehaving(peer, reason: "cfcheckpt mismatch")
            } else {
                await pool.transportFailure(peer, reason: "cfcheckpt mismatch in a single-class vote")
            }
        }
    }

    /// What a vote's source classes say about it. `crossSource`: the agreeing
    /// peers span more than one class, so the agreement is not one
    /// acquisition channel agreeing with itself. `disputed`: the agreeing
    /// peers are a single class and a peer of another class disagrees — the
    /// pool's diversity rule permits two seats from one class, so a strict
    /// majority alone can be exactly that channel outvoting the only
    /// independent witness, and banning the dissenter would strike it from
    /// the persisted good-peers file on that channel's word.
    private func sourceSpan(agreeing: [PeerConnection], dissenting: [PeerConnection])
        async -> (crossSource: Bool, disputed: Bool) {
        let agreeingClasses = await classes(of: agreeing)
        let dissentingClasses = await classes(of: dissenting)
        let crossSource = agreeingClasses.count > 1
        return (crossSource, !crossSource && !dissentingClasses.isSubset(of: agreeingClasses))
    }

    private func classes(of peers: [PeerConnection]) async -> Set<PeerSource?> {
        var result: Set<PeerSource?> = []
        for peer in peers { result.insert(await pool.source(of: peer.endpoint)) }
        return result
    }

    /// Cools off every peer in a disputed vote and throws. Nobody is banned —
    /// the lie is unattributable — and the cooldown makes the pool seat other
    /// candidates before the next attempt, which is what can break the tie.
    private func refuseDisputedVote(_ peers: [PeerConnection], reason: String) async throws -> Never {
        for peer in peers { await pool.transportFailure(peer, reason: reason) }
        throw FilterSyncError.checkpointMismatch(reason)
    }

    /// The answer more than half of `answers` gave, and the peers that gave
    /// something else — nil when nothing reaches a strict majority (a 1–1
    /// split, or three different answers). One definition shared by the
    /// cfcheckpt and cfheaders layers, so "majority" cannot mean two things.
    /// What to do with the minority, or with no majority at all, is each
    /// caller's judgement: the tally only says who agreed with whom.
    private static func strictMajority<T: Equatable>(
        of answers: [(peer: PeerConnection, value: T)])
        -> (value: T, minority: [PeerConnection])? {
        var tally: [(value: T, count: Int)] = []
        for entry in answers {
            if let index = tally.firstIndex(where: { $0.value == entry.value }) {
                tally[index].count += 1
            } else {
                tally.append((entry.value, 1))
            }
        }
        guard let best = tally.max(by: { $0.count < $1.count }),
              best.count * 2 > answers.count else { return nil }
        return (best.value, answers.filter { $0.value != best.value }.map(\.peer))
    }

    /// Core serves checkpoint headers at heights 1000, 2000, …, ascending
    /// (ProcessGetCFCheckPt: entry i is the header at (i+1)*1000; the stop
    /// block itself is included only when it is a multiple of 1000). The
    /// lowest checkpoint height at which a pinned header differs from the
    /// reference, if any.
    private static func lowestDisputedBoundary(of headers: [String: String],
                                               against reference: CFCheckptMessage,
                                               tip: UInt32) -> UInt32? {
        for (index, header) in reference.filterHeaders.enumerated() {
            let height = UInt32(index + 1) * checkpointInterval
            guard height <= tip else { break }
            if let pinned = filterHeader(at: height, in: headers), pinned != header { return height }
        }
        return nil
    }

    /// The comparison over headers a batch has proposed but not committed,
    /// so the batch can be refused before any of it is applied.
    static func checkPinnedBoundaries(of headers: [String: String],
                                              against reference: CFCheckptMessage,
                                              tip: UInt32) throws {
        if let height = lowestDisputedBoundary(of: headers, against: reference, tip: tip) {
            throw FilterSyncError.checkpointMismatch("pinned header at \(height) disagrees with cfcheckpt")
        }
    }

    // MARK: - Internals

    /// Endpoint descriptions of `connections`, for comparing peer identity
    /// across a pool that may have been replenished underneath us.
    static func endpoints(of connections: [PeerConnection]) async -> Set<String> {
        var result: Set<String> = []
        for connection in connections { result.insert(connection.endpoint.description) }
        return result
    }

    /// The still-connected peers whose cfcheckpt answer we adopted.
    ///
    /// Throws rather than falling back to the full pool: a peer that never had
    /// its checkpoints compared is exactly what the cross-peer check exists to
    /// exclude, so continuing without an approved peer would silently drop the
    /// protection instead of failing closed.
    func approved(peers approvedEndpoints: Set<String>) async throws -> [PeerConnection] {
        var result: [PeerConnection] = []
        for peer in await pool.connectedPeers() {
            if approvedEndpoints.contains(peer.endpoint.description) { result.append(peer) }
        }
        guard !result.isEmpty else { throw FilterSyncError.noPeers }
        return result
    }

    /// Each peer beside the class the pool reached it through, which is what
    /// `crossSourceSet` selects on. Both lanes ask for it, so both ask the
    /// pool the same way; a peer the pool has no class for carries nil rather
    /// than a guess.
    private func sourced(_ peers: [PeerConnection])
        async -> [(peer: PeerConnection, source: PeerSource?)] {
        var result: [(peer: PeerConnection, source: PeerSource?)] = []
        result.reserveCapacity(peers.count)
        for peer in peers {
            result.append((peer, await pool.source(of: peer.endpoint)))
        }
        return result
    }

    /// Picks the cross-check set: up to `limit` peers, spanning as many source
    /// classes as the pool holds. The anchor is the first peer; next comes the
    /// first peer of a *different* class, then any class not yet represented,
    /// and only then are the remaining seats filled in seating order. Fewer
    /// peers than `limit`, or a single class, is the degraded mode — used, not
    /// refused, exactly as a single-peer pool is. Pure so the policy is
    /// testable without a network.
    static func crossSourceSet(_ peers: [(peer: PeerConnection, source: PeerSource?)],
                               limit: Int = 3) -> [PeerConnection]
    {
        guard let anchor = peers.first, limit > 0 else { return [] }
        var chosen = [anchor.peer]
        var classes = [anchor.source]
        let rest = peers.dropFirst()
        for entry in rest where chosen.count < limit && !classes.contains(entry.source) {
            chosen.append(entry.peer)
            classes.append(entry.source)
        }
        for entry in rest where chosen.count < limit && !chosen.contains(where: { $0 === entry.peer }) {
            chosen.append(entry.peer)
        }
        return chosen
    }

    /// Fetches cfheaders for [batchStart, batchStop] and pins the filter
    /// header chain to our block-header chain.
    func pinFilterHeaders(batchStart: UInt32, batchStop: UInt32, stopHash: Data,
                          peers: [PeerConnection],
                          startingFrom storedHeaders: [String: String]) async throws
        -> [String: String]
    {
        // Always cross-check cfheaders across peers when the pool has them
        // (paper §2.7: "fetch cfheaders from ≥2 independent peers and
        // disconnect peers that disagree"). A single-peer pool degrades to one.
        //
        // The set spans source classes when it can (#3). `prefix(2)` took
        // whichever two connected first, and the diversity ceiling permits two
        // seats from one class — so the cross-check could be a DNS seed's
        // answer compared against the same DNS seed's other answer: one
        // acquisition channel agreeing with itself. Same-class sets remain
        // the degraded mode, exactly as a single-peer pool is. Three rather
        // than two because two can only ever tie, and a tie names no liar:
        // the third answer is what turns a disagreement into a verdict (#26).
        var sourced: [(peer: PeerConnection, source: PeerSource?)] = []
        for peer in peers {
            sourced.append((peer, await pool.source(of: peer.endpoint)))
        }
        // A deep rollback may land in pruned history. Reconstruct from the
        // closest surviving pin before scanning, keeping the wallet's logical
        // frontier unchanged so a crash/reopen cannot skip or double-apply it.
        var requestStart = batchStart
        if batchStart > 0, storedHeaders[String(batchStart - 1)] == nil,
           let anchor = storedHeaders.keys.compactMap(UInt32.init).filter({ $0 < batchStart }).max() {
            requestStart = anchor + 1
        }
        var headers = storedHeaders
        let queryPeers = Self.crossSourceSet(sourced)
        while requestStart <= batchStop {
            let requestStop = UInt32(min(UInt64(requestStart) + UInt64(Self.maxRangePerRequest) - 1,
                                         UInt64(batchStop)))
            guard let requestHash = requestStop == batchStop ? stopHash : await chain.blockHash(at: requestStop) else {
                throw FilterSyncError.badPeerResponse("missing reconstruction header")
            }
            let message = try await crossCheckedCFHeaders(
                batchStart: requestStart, batchStop: requestStop, stopHash: requestHash,
                queryPeers: queryPeers)
            try anchorPreviousHeader(of: message, batchStart: requestStart, in: &headers)
            try Self.appendFilterHeaders(message, startingAt: requestStart,
                                         checking: storedHeaders, into: &headers)
            if requestStop == batchStop { break }
            requestStart = requestStop + 1
        }
        return headers
    }

    private static func appendFilterHeaders(_ message: CFHeadersMessage, startingAt start: UInt32,
                                            checking storedHeaders: [String: String],
                                            into headers: inout [String: String]) throws {
        var previous = message.previousFilterHeader
        for (index, filterHash) in message.filterHashes.enumerated() {
            let height = start + UInt32(index)
            let header = SHA256d.hash(filterHash + previous)
            if let pinned = Self.filterHeader(at: height, in: storedHeaders), pinned != header {
                throw FilterSyncError.filterHeaderMismatch(height: height)
            }
            headers[String(height)] = header.hex
            previous = header
        }
    }

    /// One cfheaders answer for the batch, judged by strict majority across
    /// the peers asked — never by seating order. The first version kept the
    /// first reply as the reference and evicted whoever contradicted it
    /// *later*, so the dial race decided blame: a liar that connected first
    /// became the reference and the honest second peer was banned — struck
    /// from the persisted good-peers file — for telling the truth (#26).
    ///
    /// Now every reply is tallied. The majority answer is adopted and only
    /// the peers outside it are evicted: their answer contradicts a majority
    /// that, with the set spanning source classes, includes cross-source
    /// agreement, so the lie is attributable. With no strict majority — a
    /// 1–1 split, or three different answers — nobody can be named, so every
    /// tallied peer is cooled off rather than banned and the batch fails
    /// closed. A ban here would condemn the honest peer alongside the liar;
    /// a cooldown keeps both in the good-peers file while the pool seats
    /// other candidates in the meantime, which is what breaks the tie on the
    /// next pass. A lone answer is accepted, as `majorityReference` accepts
    /// a lone survivor and for the same reason.
    private func crossCheckedCFHeaders(batchStart: UInt32, batchStop: UInt32,
                                       stopHash: Data,
                                       queryPeers: [PeerConnection]) async throws
        -> CFHeadersMessage {
        let answers = try await collectedCFHeaders(batchStart: batchStart, stopHash: stopHash,
                                                   from: queryPeers)
        guard !answers.isEmpty else {
            // Reachable now that a transport error skips a peer instead of
            // aborting the batch: every peer asked may be resting. Same
            // distinction as the top of `sync` (#82).
            let cooling = await pool.coolingEndpoints.count
            throw cooling > 0 ? FilterSyncError.peersCoolingDown(cooling) : FilterSyncError.noPeers
        }
        guard let majority = Self.strictMajority(of: answers) else {
            for (peer, _) in answers {
                await pool.transportFailure(peer, reason: "cfheaders disagree at \(batchStart)")
            }
            throw FilterSyncError.checkpointMismatch("cfheaders disagree at \(batchStart)")
        }
        let agreeing = answers.filter { $0.value == majority.value }.map(\.peer)
        guard await !sourceSpan(agreeing: agreeing, dissenting: majority.minority).disputed else {
            try await refuseDisputedVote(answers.map(\.peer),
                                         reason: "cfheaders at \(batchStart): one source class outvotes another")
        }
        for peer in majority.minority {
            await pool.misbehaving(peer, reason: "cfheaders mismatch at \(batchStart)")
        }
        let message = majority.value
        guard message.filterHashes.count == Int(batchStop - batchStart + 1) else {
            throw FilterSyncError.badPeerResponse("cfheaders count \(message.filterHashes.count) != \(batchStop - batchStart + 1)")
        }
        return message
    }

    /// The batch's cfheaders replies, one per peer that answered about the
    /// block we asked about. Mirrors `collectedCheckpoints`: a transport
    /// error cools that peer off and the others are still asked, and a reply
    /// about a different stop hash evicts the peer that sent it — an honest
    /// peer echoes the hash it was sent, so that fault is attributable on its
    /// own, before any tally.
    private func collectedCFHeaders(batchStart: UInt32, stopHash: Data,
                                    from queryPeers: [PeerConnection]) async throws
        -> [(peer: PeerConnection, value: CFHeadersMessage)] {
        var answers: [(peer: PeerConnection, value: CFHeadersMessage)] = []
        answers.reserveCapacity(queryPeers.count)
        for peer in queryPeers {
            let response: PeerMessage
            do {
                response = try await peer.request(
                    .getcfheaders(GetCFiltersRequest(startHeight: batchStart, stopHash: stopHash)),
                    expecting: ["cfheaders"])
            } catch let error as PeerError where error.isTransport {
                await pool.transportFailure(peer, reason: error.localizedDescription)
                continue
            }
            guard case let .cfheaders(message) = response else {
                throw FilterSyncError.badPeerResponse("expected cfheaders")
            }
            guard message.stopHash == stopHash else {
                await pool.misbehaving(peer, reason: "cfheaders stop hash mismatch at \(batchStart)")
                continue
            }
            answers.append((peer, message))
        }
        return answers
    }

    /// The batch's previous filter header, anchored: zero at genesis, our
    /// pinned header when one exists — or, on fresh progress with a start
    /// height > 0, the peer-supplied value becomes the anchor, cross-checked
    /// between peers where possible and against cfcheckpt at checkpoint
    /// heights.
    private func anchorPreviousHeader(of message: CFHeadersMessage, batchStart: UInt32,
                                      in headers: inout [String: String]) throws {
        if batchStart == 0 {
            // BIP157: the genesis block's previous filter header is zero.
            guard message.previousFilterHeader == Data(repeating: 0, count: 32) else {
                throw FilterSyncError.filterHeaderMismatch(height: batchStart)
            }
        } else if let pinned = Self.filterHeader(at: batchStart - 1, in: headers) {
            // The announced chain must continue our pinned chain exactly.
            guard message.previousFilterHeader == pinned else {
                throw FilterSyncError.filterHeaderMismatch(height: batchStart)
            }
        } else {
            headers[String(batchStart - 1)] = message.previousFilterHeader.hex
        }
    }

    /// Fetches, verifies and matches all filters in [batchStart, batchStop],
    /// a chunk at a time.
    ///
    /// The batch stays the unit of verification and of saving: the cfheaders
    /// cross-check above covers all of it, and the completeness guard below
    /// proves all of it arrived. What the chunks change is the unit of memory.
    /// A 1000-filter burst was held whole until its last message landed, so
    /// peak memory was a batch; a chunk is matched and dropped before the next
    /// one is asked for, so peak memory is a chunk however long the batch is.
    func scanFilters(batchStart: UInt32, batchStop: UInt32, peer: PeerConnection,
                     watchScripts: [Data],
                     filterHeaders: [String: String],
                     onMatch: @Sendable (BlockMatch) async throws -> Void) async throws {
        let count = Int(batchStop - batchStart + 1)
        var seen: Set<UInt32> = []
        var chunkStart = batchStart
        while chunkStart <= batchStop {
            let chunkStop = UInt32(min(UInt64(chunkStart) + UInt64(filtersPerChunk) - 1,
                                       UInt64(batchStop)))
            seen.formUnion(try await scanChunk(chunkStart: chunkStart, chunkStop: chunkStop,
                                               peer: peer, watchScripts: watchScripts,
                                               filterHeaders: filterHeaders, onMatch: onMatch))
            if chunkStop == batchStop { break }
            chunkStart = chunkStop + 1
        }
        guard seen.count == count else {
            throw FilterSyncError.badPeerResponse("missing cfilters: \(seen.count)/\(count)")
        }
    }

    /// One chunk of a batch: the filters for [chunkStart, chunkStop], each
    /// verified against the batch's pinned headers and matched, and all of
    /// them released when this returns. Gives back the heights it accounted
    /// for, which the batch adds up.
    ///
    /// The height map is built per chunk rather than per batch, so a filter
    /// for some other block of the same batch is a mismatch here instead of an
    /// early delivery — a chunk is answered by the chunk that was asked for.
    private func scanChunk(chunkStart: UInt32, chunkStop: UInt32, peer: PeerConnection,
                           watchScripts: [Data],
                           filterHeaders: [String: String],
                           onMatch: @Sendable (BlockMatch) async throws -> Void) async throws
        -> Set<UInt32>
    {
        // Nil unless a restore-only range scan is running, in which case its
        // run deadline is read here rather than only between batches: a batch
        // is a thousand blocks, and a cap checked once per batch would be a
        // cap on batches.
        try checkRangeDeadline()
        guard let stopHash = await chain.blockHash(at: chunkStop) else {
            throw FilterSyncError.badPeerResponse("missing header at \(chunkStop)")
        }
        let count = Int(chunkStop - chunkStart + 1)
        let overlay = peer.endpoint.isOverlay
        let responses = try await readFilterChunk(from: peer, start: chunkStart, stopHash: stopHash,
                                                   count: count, overlay: overlay)

        var heightByHash: [Data: UInt32] = [:]
        for height in chunkStart ... chunkStop {
            if let hash = await chain.blockHash(at: height) { heightByHash[hash] = height }
        }

        // Every filter of the chunk is verified against its pinned header
        // before any of them is matched, so a filter that does not reproduce
        // its header fails the chunk before a match has been delivered.
        var seen: Set<UInt32> = []
        var verified: [(height: UInt32, message: CFilterMessage)] = []
        verified.reserveCapacity(responses.count)
        var chunkBytes = 0
        for response in responses {
            let (height, message) = try verifiedFilter(from: response, heightByHash: heightByHash,
                                                       seen: &seen, filterHeaders: filterHeaders)
            chunkBytes += message.filter.count
            verified.append((height, message))
        }
        peakChunkFilterBytesForTest = max(peakChunkFilterBytesForTest, chunkBytes)
        // The range scan's byte cap, charged for the whole chunk before any of
        // it is matched: the bytes have been read either way, and charging
        // them here means a refusal names everything the run has downloaded
        // so far. A run overshoots its cap by at most one chunk. Nothing is
        // charged, and nothing can refuse, on the forward path.
        try chargeRangeFilterBytes(chunkBytes)
        guard !watchScripts.isEmpty else { return seen }
        try await matchFilters(verified, from: peer, watchScripts: watchScripts, onMatch: onMatch)
        return seen
    }

    private func readFilterChunk(from peer: PeerConnection, start: UInt32, stopHash: Data,
                                  count: Int, overlay: Bool) async throws -> [PeerMessage] {
        do {
            return try await peer.requestMany(
                .getcfilters(GetCFiltersRequest(startHeight: start, stopHash: stopHash)),
                expecting: "cfilter", count: count, maxTotalBytes: Self.chunkByteBound(filters: count),
                timeout: Self.chunkTimeout(filters: count, overlay: overlay))
        } catch let error as PeerError {
            if case .protocolViolation = error {
                await pool.misbehaving(peer, reason: error.localizedDescription)
            }
            throw error
        }
    }

    /// Matches a chunk's verified filters against the watch set and delivers
    /// every hit, reading the run deadline before each filter. Its own
    /// function so `scanChunk` stays inside the complexity budget: the two
    /// halves are one chunk read and then judged, and the split follows the
    /// seam where the range scan's byte cap is charged between them.
    private func matchFilters(_ verified: [(height: UInt32, message: CFilterMessage)],
                              from peer: PeerConnection, watchScripts: [Data],
                              onMatch: @Sendable (BlockMatch) async throws -> Void) async throws {
        for (height, message) in verified {
            // The run deadline again, per filter rather than per chunk.
            // Reading it once before the request bounds how long the run
            // waits for filters and nothing else: every match below fetches a
            // whole block on a 120-second timeout and then awaits the caller's
            // `onMatch`, and at a full watch set BIP158 hands back a false
            // positive every few dozen blocks, so a chunk of 100 can hold a
            // run for far longer than the cap it was given. Nil, and free, on
            // the forward path.
            try checkRangeDeadline()
            let parsed = try message.parsedFilter()
            let filter = try GCSFilter(p: GCSFilter.defaultP, m: GCSFilter.defaultM,
                                       key: Data(message.blockHash.prefix(16)),
                                       n: parsed.n, encoded: parsed.encoded)
            guard filter.containsAny(watchScripts) else { continue }
            try await deliverMatchedBlock(from: peer, height: height,
                                          blockHash: message.blockHash, onMatch: onMatch)
        }
    }

    /// A chunk's deadline, taken from the whole-batch ceiling it replaces:
    /// 120 seconds covered up to `maxRangePerRequest` filters, so a chunk gets
    /// that share of it and never less than 30 seconds, the timeout the
    /// ordinary peer request uses. Sharing it out matters because the deadline
    /// is now per request: at a flat 120 seconds a peer that answered every
    /// chunk just inside it could hold one batch ten times as long as it could
    /// before.
    ///
    /// A Tor or I2P peer gets ten times that share and at least two minutes.
    /// A chunk of mainnet filters is a few megabytes, and an I2P tunnel that
    /// carried the census at about half a megabit a second would miss the
    /// clearnet deadline on every chunk, stalling the scan for good.
    static func chunkTimeout(filters: Int, overlay: Bool = false) -> Duration {
        overlay ? .seconds(max(120, 1_200 * filters / Int(maxRangePerRequest)))
                : .seconds(max(30, 120 * filters / Int(maxRangePerRequest)))
    }

    /// Whole blocks are up to a few megabytes too; an overlay peer gets at
    /// least five minutes.
    static func blockTimeout(_ timeout: Duration, overlay: Bool) -> Duration {
        overlay ? max(timeout, .seconds(300)) : timeout
    }

    /// One cfilter response, verified: the right type, a block we asked
    /// about and have not seen, and a filter that reproduces the pinned
    /// header chain (BIP158): header[h] == SHA256d(SHA256d(filter) || header[h-1]).
    private func verifiedFilter(from response: PeerMessage, heightByHash: [Data: UInt32],
                                seen: inout Set<UInt32>,
                                filterHeaders: [String: String]) throws
        -> (height: UInt32, message: CFilterMessage) {
        guard case let .cfilter(message) = response else {
            throw FilterSyncError.badPeerResponse("expected cfilter")
        }
        guard message.filterType == Self.basicFilterType else {
            throw FilterSyncError.badPeerResponse("unexpected filter type \(message.filterType)")
        }
        guard let height = heightByHash[message.blockHash], !seen.contains(height) else {
            throw FilterSyncError.unexpectedBlockHash
        }
        seen.insert(height)
        let filterHash = GCSFilter.filterHash(message.filter)
        let previous = height == 0
            ? Data(repeating: 0, count: 32)
            : Self.filterHeader(at: height - 1, in: filterHeaders)
        guard let pinned = Self.filterHeader(at: height, in: filterHeaders),
              SHA256d.hash(filterHash + (previous ?? Data(repeating: 0, count: 32))) == pinned
        else {
            throw FilterSyncError.filterHeaderMismatch(height: height)
        }
        return (height, message)
    }

    /// A possible hit (or BIP158 false positive): fetch the full block and
    /// hand it to the caller. The header hash only authenticates the 80-byte
    /// header, so the transaction set must hash to the committed merkle root
    /// before anything is credited from it — otherwise a peer can serve the
    /// real header with a fabricated (or pruned) tx list.
    private func deliverMatchedBlock(from peer: PeerConnection, height: UInt32,
                                     blockHash: Data,
                                     onMatch: @Sendable (BlockMatch) async throws -> Void)
        async throws {
        let block = try await verifiedBlock(from: peer, height: height, blockHash: blockHash)
        try await onMatch(BlockMatch(height: height, blockHash: blockHash, block: block))
        // Serialising a block again is only worth it when a range budget is
        // counting; the forward scan would otherwise pay it on every match for
        // a number it throws away.
        if rangeRun != nil { try chargeRangeBlockBytes(block.serialized.count) }
    }

    private func verifiedBlock(from peer: PeerConnection, height: UInt32, blockHash: Data,
                               timeout: Duration = .seconds(120)) async throws -> Block {
        let limit = Self.blockTimeout(timeout, overlay: peer.endpoint.isOverlay)
        let blockResponse = try await peer.request(
            .getdata(InventoryPayload([InventoryVector(type: .witnessBlock, hash: blockHash)])),
            expecting: ["block", "notfound"], timeout: limit)
        switch blockResponse {
        case let .block(block):
            guard block.hash == blockHash else {
                await pool.misbehaving(peer, reason: "block hash mismatch at \(height)")
                throw FilterSyncError.badPeerResponse("block hash mismatch at \(height)")
            }
            guard block.hasValidMerkleRoot else {
                await pool.misbehaving(peer, reason: "merkle root mismatch at \(height)")
                throw FilterSyncError.badPeerResponse("merkle root mismatch at \(height)")
            }
            return block
        case .notfound:
            throw FilterSyncError.badPeerResponse("peer lost block at \(height)")
        default:
            throw FilterSyncError.badPeerResponse("expected block")
        }
    }

    static func filterHeader(at height: UInt32, in headers: [String: String]) -> Data? {
        headers[String(height)].flatMap { Data(hex: $0) }
    }

    private static func load(storageURL: URL, startHeight: UInt32) throws
        -> (state: PersistenceState, progress: Progress)
    {
        guard let data = try readRecord(at: storageURL, maxBytes: maximumProgressBytes) else {
            return (.missing, Progress(nextScanHeight: startHeight))
        }
        let stored: Progress
        do {
            stored = try JSONDecoder().decode(Progress.self, from: data)
        } catch {
            throw FilterSyncStorageError.damaged("the JSON or a progress field is invalid")
        }
        try validate(progress: stored, startHeight: startHeight)
        return (.loaded, stored)
    }

    /// The bytes of a progress or range record, or nil when there is no file.
    /// Shared with `RangeScanProgress`, which differs only in its byte cap:
    /// size is checked from the file's attributes before anything is mapped,
    /// and again on what was read.
    static func readRecord(at storageURL: URL, maxBytes: Int) throws -> Data? {
        guard FileManager.default.fileExists(atPath: storageURL.path) else { return nil }
        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try FileManager.default.attributesOfItem(atPath: storageURL.path)
        } catch {
            throw FilterSyncStorageError.unreadable
        }
        if let size = attributes[.size] as? NSNumber, size.int64Value > Int64(maxBytes) {
            throw FilterSyncStorageError.tooLarge(maxBytes: maxBytes)
        }
        let data: Data
        do {
            data = try Data(contentsOf: storageURL, options: .mappedIfSafe)
        } catch {
            throw FilterSyncStorageError.unreadable
        }
        guard data.count <= maxBytes else {
            throw FilterSyncStorageError.tooLarge(maxBytes: maxBytes)
        }
        return data
    }

    /// What a file says it is, decoding only the marker so no progress field
    /// is trusted. `RangeScanProgress` writes `recordKind`; forward progress
    /// writes nothing, and a file written before the marker existed names
    /// nothing and still loads, which is what keeps every wallet already on
    /// disk readable.
    static func recordKind(in data: Data) -> String? {
        struct RecordKind: Decodable {
            let record: String?
        }
        return (try? JSONDecoder().decode(RecordKind.self, from: data))?.record
    }

    /// Writes a record atomically, refusing one over the cap before touching
    /// the disk.
    static func writeRecord(_ record: some Encodable, to storageURL: URL, maxBytes: Int) throws {
        let data = try JSONEncoder().encode(record)
        guard data.count <= maxBytes else {
            throw FilterSyncStorageError.tooLarge(maxBytes: maxBytes)
        }
        do {
            try data.write(to: storageURL,
                           options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            throw FilterSyncStorageError.writeFailed
        }
    }

    /// A file that says it belongs to something else is not forward progress.
    ///
    /// The one that can be here by mistake is a range-scan record: it carries
    /// `nextScanHeight` and `filterHeaders` under these exact names, the
    /// decoder ignores the keys it was not asked about, and the validation
    /// below passes on what is left, so a `scanRange` pointed at this wallet's
    /// progress file would come back and be read as the wallet's own frontier.
    private static func validate(progress: Progress, startHeight: UInt32) throws {
        if let kind = progress.record {
            throw FilterSyncStorageError.damaged(
                "the file is a \"\(kind)\" record, not compact-filter progress")
        }
        guard progress.nextScanHeight >= startHeight else {
            throw FilterSyncStorageError.frontierBeforeWallet(
                stored: progress.nextScanHeight, wallet: startHeight)
        }
        try validate(filterHeaders: progress.filterHeaders, below: progress.nextScanHeight,
                     maxPinned: maximumPinnedHeaders)
        try validate(receipt: progress.crossCheck)
    }

    /// Canonical decimal heights (unique dictionary keys), 32-byte headers, and
    /// nothing pinned at or above the frontier the record claims to have
    /// scanned to. Both records are held to it.
    static func validate(filterHeaders: [String: String], below frontier: UInt32,
                         maxPinned: Int) throws {
        guard filterHeaders.count <= maxPinned else {
            throw FilterSyncStorageError.damaged("there are too many pinned filter headers")
        }
        for (key, value) in filterHeaders {
            guard let height = UInt32(key), String(height) == key else {
                throw FilterSyncStorageError.damaged("a filter-header height is not canonical decimal")
            }
            guard height < frontier else {
                throw FilterSyncStorageError.damaged("a pinned filter header is at or beyond the scan frontier")
            }
            guard value.utf8.count == 64, Data(hex: value)?.count == 32 else {
                throw FilterSyncStorageError.damaged("a pinned filter header is not 32 bytes")
            }
        }
    }

    /// The receipt is read back as a claim about who corroborated this
    /// frontier, so it is bounded on the way in like everything else in this
    /// file. Nothing here decides whether the claim is true — it cannot; the
    /// peers are gone — only that the file cannot grow without limit and that
    /// a caller reading the digest gets 32 bytes or an error.
    static func validate(receipt: CrossCheckReceipt?) throws {
        guard let receipt else { return }
        guard receipt.agreed.count <= maximumReceiptEntries else {
            throw FilterSyncStorageError.damaged("the cross-check receipt names too many peers")
        }
        // The shape a pinned filter header is held to, for the same reason:
        // 64 characters of hex, not merely something that decodes to 32 bytes
        // once it has been trimmed.
        guard receipt.answerDigest.utf8.count == 64,
              let digest = Data(hex: receipt.answerDigest), digest.count == 32 else {
            throw FilterSyncStorageError.damaged("the cross-check receipt's answer digest is not 32 bytes")
        }
        let plausible = 1 ... maximumReceiptEndpointBytes
        guard receipt.agreed.allSatisfy({ plausible.contains($0.endpoint.utf8.count) }) else {
            throw FilterSyncStorageError.damaged("a cross-check receipt endpoint is not a plausible length")
        }
    }

    private static func validate(progress: Progress, againstTip tip: UInt32) throws {
        guard UInt64(progress.nextScanHeight) <= UInt64(tip) + 1 else {
            throw FilterSyncStorageError.frontierBeyondTip(
                stored: progress.nextScanHeight, tip: tip)
        }
    }

    /// Rewinds filter progress to a fork height, so scanning resumes from the
    /// first block the surviving branch does not share with the old one.
    ///
    /// A pure function of `forkHeight`, which is what makes the whole rollback
    /// safe to repeat: running it twice is indistinguishable from running it
    /// once, so a crash part-way through needs no partial-state reasoning.
    ///
    /// Pinned filter headers above the fork are dropped rather than kept. They
    /// commit to filters for blocks that are no longer on the chain, and a
    /// later cross-check against them would compare the surviving branch to
    /// the orphaned one and reject honest peers.
    ///
    /// Never moves the frontier forward: a fork at or above the current
    /// frontier means nothing scanned is affected, and advancing here would
    /// skip blocks that have never been read.
    ///
    /// The cross-check receipt is cleared, including when the frontier does
    /// not move. It records agreement about a tip on the branch that was just
    /// replaced, so keeping it would leave the store claiming corroboration
    /// for a chain it is no longer on — and a claim that survives the evidence
    /// is worse than none. The next sync writes a fresh one before it commits
    /// anything.
    public func rollBack(to forkHeight: UInt32) throws {
        let resumeFrom = forkHeight == UInt32.max ? forkHeight : forkHeight + 1
        var candidate = progress
        candidate.nextScanHeight = min(progress.nextScanHeight, resumeFrom)
        candidate.filterHeaders = progress.filterHeaders.filter { key, _ in
            guard let height = UInt32(key) else { return false }
            return height <= forkHeight
        }
        candidate.crossCheck = nil
        guard candidate != progress else { return }
        try persist(candidate)
        progress = candidate
    }

    /// The pinned filter headers a frontier can still be asked for, and
    /// nothing else. Sync prunes to this before every persist, so the store
    /// stops growing with the chain: a genesis-rooted mainnet wallet keeps a
    /// few thousand headers instead of one per block scanned, and the file is
    /// re-encoded and rewritten at that size for the rest of the sync.
    ///
    /// Three classes are kept, and the reason for each is a check that would
    /// otherwise stop running:
    ///
    /// - Every checkpoint boundary, forever. `checkPinnedBoundaries` compares
    ///   each one against `cfcheckpt` on every sync, and it compares only the
    ///   heights that are pinned — dropping a boundary would retire a
    ///   comparison silently rather than fail it. They cost one header per
    ///   1,000 blocks.
    /// - The anchor at `frontier - 1`, which the next batch's
    ///   `anchorPreviousHeader` requires to refuse a peer whose announced
    ///   chain does not continue ours.
    /// - Every height back to the boundary below the last one, so a reorg
    ///   rolled back into that range still finds a pinned anchor at the fork
    ///   instead of taking a peer's word for it. That run is one to two whole
    ///   checkpoint intervals — a thousand blocks at its shallowest, far past
    ///   the depth of normal reorganizations. Below it, cfheaders are rebuilt
    ///   from the closest surviving pin before any filters are scanned.
    /// - The earliest anchor, so a rollback before the first checkpoint still
    ///   retains the original trust boundary.
    ///
    /// Fails closed on the anchor: if `frontier - 1` is not pinned, nothing is
    /// pruned at all. A store already missing its anchor is not one to prune
    /// further — the pruning would be reasoning about a chain it cannot verify
    /// it has, which is the one state this must never produce.
    ///
    /// Pure, so the policy is testable without a network.
    static func prunedFilterHeaders(_ headers: [String: String],
                                    frontier: UInt32) -> [String: String] {
        guard frontier > 0 else { return headers }
        let anchor = frontier - 1
        guard headers[String(anchor)] != nil else { return headers }
        let lastBoundary = (anchor / checkpointInterval) * checkpointInterval
        let keepFrom = lastBoundary < checkpointInterval ? 0 : lastBoundary - checkpointInterval
        let firstAnchor = headers.keys.compactMap(UInt32.init).min()
        return headers.filter { key, _ in
            guard let height = UInt32(key) else { return false }
            return height == firstAnchor || height >= keepFrom || (height > 0 && height % checkpointInterval == 0)
        }
    }

    /// Test seam: sets progress directly so a rollback can be exercised without
    /// running a whole sync against loopback peers.
    func recordProgressForTest(nextScanHeight: UInt32,
                               filterHeaders: [String: String] = [:]) throws {
        let candidate = Progress(nextScanHeight: nextScanHeight, filterHeaders: filterHeaders)
        try persist(candidate)
        progress = candidate
    }

    /// Test seam: the pinned filter headers a rollback prunes.
    var pinnedFilterHeadersForTest: [String: String] { progress.filterHeaders }

    /// Test seam: the most filter bytes this instance has held at once, which
    /// is one chunk's worth. Chunking exists to keep that number off the size
    /// of a batch, and counting is the only way to see it from outside.
    private(set) var peakChunkFilterBytesForTest = 0

    private func persist(_ candidate: Progress) throws {
        guard let storageURL else { return }
        try Self.writeRecord(candidate, to: storageURL, maxBytes: Self.maximumProgressBytes)
    }
}
