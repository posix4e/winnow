import BitcoinCore
import Foundation

public enum FilterSyncError: LocalizedError, Equatable, Sendable {
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

    public var errorDescription: String? {
        switch self {
        case .noPeers:
            "No Bitcoin peers are available for compact-filter synchronization."
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
/// 2. `getcfcheckpt` at the tip from up to 3 peers; peers that disagree with
///    the majority answer are disconnected (BIP157 filters are not
///    consensus-committed — cross-peer comparison is the mitigation).
/// 3. `getcfheaders` per ≤1000-block batch; the announced previous filter
///    header must equal our pinned header at batchStart-1 (zero at genesis),
///    then the filter-hash chain is walked forward and pinned per height. On
///    the first batch of a fresh progress file there is no pinned previous
///    header, so the batch's cfheaders response is required to be byte-identical
///    from two peers when two are available.
/// 4. `getcfilters` (type 0x00) for the batch; each filter must reproduce the
///    pinned header chain given the block hash from our PoW-checked header
///    chain — this is what anchors filters to the block chain.
/// 5. Each filter is matched locally against the watch list with BitcoinCore's
///    GCSFilter; on a hit the full block is fetched (getdata MSG_WITNESS_BLOCK),
///    its hash verified, and handed to `onMatch`.
/// 6. Progress (next scan height + pinned filter headers) is persisted after
///    every batch.
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

    /// Persisted sync progress.
    public struct Progress: Codable, Sendable, Equatable {
        /// Height of the next block whose filter must be scanned.
        public var nextScanHeight: UInt32
        /// Pinned filter headers: decimal height → hex (internal byte order).
        public var filterHeaders: [String: String]

        public init(nextScanHeight: UInt32, filterHeaders: [String: String] = [:]) {
            self.nextScanHeight = nextScanHeight
            self.filterHeaders = filterHeaders
        }
    }

    public let pool: PeerPool
    public let chain: HeaderChain
    /// How many peers to consult for the cfcheckpt comparison (and for the
    /// initial cfheaders cross-check). If fewer are connected, all connected
    /// peers are used and the comparison simply covers those.
    public let requiredCheckpointPeers: Int
    private let storageURL: URL?
    public nonisolated let persistenceState: PersistenceState
    private var progress: Progress

    private static let maximumProgressBytes = 128 * 1_024 * 1_024
    private static let maximumPinnedHeaders = 2_000_000

    public init(pool: PeerPool, chain: HeaderChain, startHeight: UInt32,
                storageURL: URL? = nil, requiredCheckpointPeers: Int = 2) throws {
        self.pool = pool
        self.chain = chain
        self.storageURL = storageURL
        self.requiredCheckpointPeers = requiredCheckpointPeers
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

    public func filterHeader(at height: UInt32) -> Data? {
        progress.filterHeaders[String(height)].flatMap { Data(hex: $0) }
    }

    /// `extraScripts` supplies per-height additions to the watch list (the
    /// silent-payment candidate scripts, which change every block). It is
    /// deliberately fail-closed: a throw aborts the sync before the frontier
    /// advances. Continuing a batch without its extra scripts would let a
    /// forward-only scan skip those payments permanently and invisibly — an
    /// index outage must surface as a sync error instead.
    /// `onReorg` is called with the fork height when the header sync replaced a
    /// branch, and is awaited **before** any filter work resumes.
    ///
    /// The ordering is the requirement, not a convenience. Scanning forward
    /// from a frontier that describes the orphaned branch is precisely the bug
    /// being fixed, so the rollback has to finish first, and a throw from it
    /// aborts the sync rather than proceeding with state that is known stale
    /// (#127).
    public func sync(watchScripts: [Data],
                     extraScripts: (@Sendable (ClosedRange<UInt32>) async throws -> [UInt32: [Data]])? = nil,
                     onReorg: (@Sendable (UInt32) async throws -> Void)? = nil,
                     onMatch: @Sendable (BlockMatch) async throws -> Void) async throws {
        var peers = await pool.connectedPeers()
        guard !peers.isEmpty else {
            // Same distinction as `PeerPool.syncHeaders`: since transport
            // failures cool peers off rather than banning them, an empty pool
            // is routinely a transient state rather than a peerless one, and
            // saying "no peers are available" would be untrue (#82).
            let cooling = await pool.coolingEndpoints.count
            throw cooling > 0 ? FilterSyncError.peersCoolingDown(cooling) : FilterSyncError.noPeers
        }

        // 1. Headers to tip. A stale or broken peer is evicted and the pool
        // retries another peer without discarding already-persisted progress.
        let headerOutcome = try await pool.syncHeaders(chain)

        // 1a. A branch was replaced, so everything derived from the old one is
        // wrong. Roll back to the lowest fork the sync saw before reading a
        // single filter: the frontier below is the thing that would otherwise
        // carry the orphaned branch forward.
        if let forkHeight = headerOutcome.minForkHeight {
            // The caller goes first because it owns the crash marker: nothing
            // may change in any store until the target height is recorded, or
            // a crash leaves stores disagreeing with no way to know a rollback
            // was ever in progress.
            try await onReorg?(forkHeight)
            try rollBack(to: forkHeight)
        }
        peers = await pool.connectedPeers()
        guard !peers.isEmpty else { throw FilterSyncError.noPeers }
        let tip = await chain.height
        let tipHash = await chain.tipHash
        try Self.validate(progress: progress, againstTip: tip)
        guard tip >= progress.nextScanHeight else { return }

        // 2. cfcheckpt cross-peer comparison.
        let checkpointPeers = Array(peers.prefix(max(1, min(3, requiredCheckpointPeers))))
        var checkpoints: [(peer: PeerConnection, message: CFCheckptMessage)] = []
        checkpoints.reserveCapacity(checkpointPeers.count)
        for peer in checkpointPeers {
            let response = try await peer.request(
                .getcfcheckpt(GetCFCheckptRequest(stopHash: tipHash)),
                expecting: ["cfcheckpt"])
            guard case let .cfcheckpt(message) = response else {
                throw FilterSyncError.badPeerResponse("expected cfcheckpt")
            }
            // The reply must answer the question we asked. Without this the
            // stop hash is only ever compared peer-to-peer in the tally below,
            // so a single peer — or peers that agree — could answer about a
            // different chain entirely and be believed. `pinFilterHeaders`
            // has always checked its own stop hash; this path had not.
            //
            // Evict and carry on rather than throw. The other peers may be
            // answering honestly, and refusing the whole sync on one bad reply
            // would hand any single hostile peer a denial of service — the
            // opposite of what cross-peer comparison is for. The majority rule
            // below then runs on whoever answered about the chain we asked
            // about.
            //
            // An honest peer cannot trip this. It echoes the stop hash we sent
            // in `getcfcheckpt`, so a tip that advances mid-loop does not cause
            // a mismatch — we simply scan to the tip we asked about and catch
            // the rest on the next run.
            guard message.stopHash == tipHash else {
                await pool.misbehaving(peer, reason: "cfcheckpt stop hash mismatch")
                continue
            }
            checkpoints.append((peer, message))
        }
        guard !checkpoints.isEmpty else {
            throw FilterSyncError.badPeerResponse(
                "no peer answered the cfcheckpt request for our chain tip")
        }
        // Adopt the MAJORITY cfcheckpt answer — never checkpoints[0] by fiat, or
        // a lying first peer could evict the honest ones and become the sole
        // reference. Peers outside the majority are disconnected. With no strict
        // majority (e.g. two peers that disagree) the lie is unattributable, so
        // we drop every checkpoint peer and let the pool replenish and retry.
        let reference: CFCheckptMessage
        if checkpoints.count == 1 {
            // A lone survivor is accepted even when more peers were asked for,
            // and that is deliberate — refusing here would be strictly worse.
            //
            // A peer only leaves this set by being evicted, and the two ways
            // out lead somewhere harmless. The stop-hash guard evicts the peer
            // that *replied*, and an honest peer never sends a stop hash we did
            // not ask about, so an attacker spraying garbage only evicts his own
            // peers and hands the sync to one he does not control. Reaching the
            // bad case — his peer as sole survivor — means the honest ones lost
            // the tally, which already requires him to hold a majority; the
            // downgrade adds nothing he did not already have.
            //
            // Refusing, by contrast, would hand him something new: a repeatable
            // abort. Sending one bad reply per attempt would stall every sync
            // indefinitely, which is the denial of service this whole path is
            // written to avoid.
            //
            // Corroboration here is defence in depth rather than the load-
            // bearing check. A sole survivor still cannot fabricate filter
            // commitments past the checkpoint-boundary comparison below or the
            // final guard at the end of this function.
            reference = checkpoints[0].message
        } else {
            var tally: [(message: CFCheckptMessage, count: Int)] = []
            for entry in checkpoints {
                if let index = tally.firstIndex(where: { $0.message == entry.message }) {
                    tally[index].count += 1
                } else {
                    tally.append((entry.message, 1))
                }
            }
            let best = tally.max { $0.count < $1.count }!
            guard best.count * 2 > checkpoints.count else {
                for (peer, _) in checkpoints {
                    await pool.misbehaving(peer, reason: "cfcheckpt no majority")
                }
                throw FilterSyncError.checkpointMismatch("no cfcheckpt majority across \(checkpoints.count) peers")
            }
            for (peer, message) in checkpoints where message != best.message {
                await pool.misbehaving(peer, reason: "cfcheckpt mismatch")
            }
            reference = best.message
        }

        // Only peers whose cfcheckpt matched the answer we adopted may go on to
        // serve filters, and `peers` has to be rebuilt from them.
        //
        // Two separate problems are being solved here. The list was captured
        // before any eviction, and the batch loop sends to `peers[0]` and the
        // first two entries — so evicting a liar that sat at the front tore
        // down the connection the next request used, and a sync that correctly
        // identified the liar died on a transport timeout anyway.
        //
        // But simply re-reading the pool is not sound either: `misbehaving`
        // triggers `replenish`, so `connectedPeers()` can hand back brand-new
        // peers that never went through this comparison at all. Serving filters
        // from those bypasses the only multi-peer checkpoint consensus the
        // client has — the eviction would be cosmetic, replacing a known liar
        // with an unvetted stranger. Hence the intersection rather than a
        // refresh.
        let approvedEndpoints = await Self.endpoints(
            of: checkpoints.filter { $0.message == reference }.map(\.peer))
        peers = try await approved(peers: approvedEndpoints)
        // Core serves checkpoint headers at heights 1000, 2000, …, ascending
        // (ProcessGetCFCheckPt: entry i is the header at (i+1)*1000; the stop
        // block itself is included only when it is a multiple of 1000).
        // Any already-pinned header at a checkpoint height must match.
        for (index, header) in reference.filterHeaders.enumerated() {
            let height = UInt32(index + 1) * Self.checkpointInterval
            guard height <= tip else { break }
            if let pinned = filterHeader(at: height), pinned != header {
                throw FilterSyncError.checkpointMismatch("pinned header at \(height) disagrees with cfcheckpt")
            }
        }

        // 3+4+5. Batches of ≤1000 blocks.
        while progress.nextScanHeight <= tip {
            let batchStart = progress.nextScanHeight
            let batchStop = min(batchStart + Self.maxRangePerRequest - 1, tip)
            guard let stopHash = await chain.blockHash(at: batchStop) else {
                throw FilterSyncError.badPeerResponse("missing header at \(batchStop)")
            }
            let proposedHeaders = try await pinFilterHeaders(
                batchStart: batchStart, batchStop: batchStop,
                stopHash: stopHash, peers: peers,
                startingFrom: progress.filterHeaders)
            let extras = try await extraScripts?(batchStart ... batchStop) ?? [:]
            try await scanFilters(batchStart: batchStart, batchStop: batchStop,
                                  peer: peers[0], watchScripts: watchScripts,
                                  extraScripts: extras, filterHeaders: proposedHeaders,
                                  onMatch: onMatch)
            var candidate = progress
            candidate.filterHeaders = proposedHeaders
            candidate.nextScanHeight = batchStop + 1
            try persist(candidate)
            progress = candidate
            // Same intersection as above, for the same reason: a long sync
            // must not drift onto replacements dialled mid-scan whose
            // checkpoints were never compared against anyone's. If every
            // approved peer has gone, stop rather than continue unvetted —
            // the next `sync` redoes the comparison from scratch.
            peers = try await approved(peers: approvedEndpoints)
        }

        // Final guard: the highest checkpoint header we computed must equal
        // the one the checkpoint peers announced (Core's last cfcheckpt entry
        // is the header at the greatest multiple of 1000 ≤ tip).
        let lastCheckpoint = (tip / Self.checkpointInterval) * Self.checkpointInterval
        if lastCheckpoint > 0, let pinned = filterHeader(at: lastCheckpoint),
           let announced = reference.filterHeaders.last, pinned != announced {
            throw FilterSyncError.checkpointMismatch("checkpoint filter header at \(lastCheckpoint) disagrees with cfcheckpt")
        }
    }

    // MARK: - Internals

    /// Endpoint descriptions of `connections`, for comparing peer identity
    /// across a pool that may have been replenished underneath us.
    private static func endpoints(of connections: [PeerConnection]) async -> Set<String> {
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
    private func approved(peers approvedEndpoints: Set<String>) async throws -> [PeerConnection] {
        var result: [PeerConnection] = []
        for peer in await pool.connectedPeers() {
            if approvedEndpoints.contains(peer.endpoint.description) { result.append(peer) }
        }
        guard !result.isEmpty else { throw FilterSyncError.noPeers }
        return result
    }

    /// Fetches cfheaders for [batchStart, batchStop] and pins the filter
    /// header chain to our block-header chain.
    private func pinFilterHeaders(batchStart: UInt32, batchStop: UInt32, stopHash: Data,
                                  peers: [PeerConnection],
                                  startingFrom storedHeaders: [String: String]) async throws
        -> [String: String]
    {
        // Always cross-check cfheaders between two peers when the pool has
        // them (paper §2.7: "fetch cfheaders from ≥2 independent peers and
        // disconnect peers that disagree"). A single-peer pool degrades to one.
        let queryPeers = Array(peers.prefix(min(2, peers.count)))

        var decoded: CFHeadersMessage?
        for peer in queryPeers {
            let response = try await peer.request(
                .getcfheaders(GetCFiltersRequest(startHeight: batchStart, stopHash: stopHash)),
                expecting: ["cfheaders"])
            guard case let .cfheaders(message) = response else {
                throw FilterSyncError.badPeerResponse("expected cfheaders")
            }
            guard message.stopHash == stopHash else {
                throw FilterSyncError.badPeerResponse("cfheaders stop hash mismatch")
            }
            if let existing = decoded, existing != message {
                await pool.misbehaving(peer, reason: "cfheaders mismatch at \(batchStart)")
                throw FilterSyncError.checkpointMismatch("cfheaders disagree at \(batchStart)")
            }
            decoded = message
        }
        guard let message = decoded else { throw FilterSyncError.noPeers }
        guard message.filterHashes.count == Int(batchStop - batchStart + 1) else {
            throw FilterSyncError.badPeerResponse("cfheaders count \(message.filterHashes.count) != \(batchStop - batchStart + 1)")
        }

        var headers = storedHeaders
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
            // Fresh progress with a start height > 0: no pinned previous
            // exists, so the peer-supplied previous header is the anchor —
            // cross-checked byte-for-byte between two peers above when
            // possible, and verified against cfcheckpt at checkpoint heights.
            headers[String(batchStart - 1)] = message.previousFilterHeader.hex
        }

        // Walk the BIP158 header chain: header[h] = SHA256d(filterHash[h] || header[h-1]).
        var previous = message.previousFilterHeader
        for (index, filterHash) in message.filterHashes.enumerated() {
            let header = SHA256d.hash(filterHash + previous)
            headers[String(batchStart + UInt32(index))] = header.hex
            previous = header
        }
        return headers
    }

    /// Fetches, verifies and matches all filters in [batchStart, batchStop].
    private func scanFilters(batchStart: UInt32, batchStop: UInt32, peer: PeerConnection,
                             watchScripts: [Data], extraScripts: [UInt32: [Data]] = [:],
                             filterHeaders: [String: String],
                             onMatch: @Sendable (BlockMatch) async throws -> Void) async throws {
        guard let stopHash = await chain.blockHash(at: batchStop) else {
            throw FilterSyncError.badPeerResponse("missing header at \(batchStop)")
        }
        let count = Int(batchStop - batchStart + 1)
        let responses = try await peer.requestMany(
            .getcfilters(GetCFiltersRequest(startHeight: batchStart, stopHash: stopHash)),
            expecting: "cfilter", count: count, timeout: .seconds(120))

        var heightByHash: [Data: UInt32] = [:]
        for height in batchStart ... batchStop {
            if let hash = await chain.blockHash(at: height) { heightByHash[hash] = height }
        }

        var seen: Set<UInt32> = []
        for response in responses {
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

            // The filter must reproduce the pinned header chain (BIP158):
            // header[h] == SHA256d(SHA256d(filter) || header[h-1]).
            let filterHash = GCSFilter.filterHash(message.filter)
            let previous = height == 0
                ? Data(repeating: 0, count: 32)
                : Self.filterHeader(at: height - 1, in: filterHeaders)
            guard let pinned = Self.filterHeader(at: height, in: filterHeaders),
                  SHA256d.hash(filterHash + (previous ?? Data(repeating: 0, count: 32))) == pinned
            else {
                throw FilterSyncError.filterHeaderMismatch(height: height)
            }

            let scripts = watchScripts + (extraScripts[height] ?? [])
            guard !scripts.isEmpty else { continue }
            let parsed = try message.parsedFilter()
            let filter = try GCSFilter(p: GCSFilter.defaultP, m: GCSFilter.defaultM,
                                       key: Data(message.blockHash.prefix(16)),
                                       n: parsed.n, encoded: parsed.encoded)
            guard filter.containsAny(scripts) else { continue }

            // Possible hit (or BIP158 false positive): fetch the full block.
            let blockResponse = try await peer.request(
                .getdata(InventoryPayload([InventoryVector(type: .witnessBlock, hash: message.blockHash)])),
                expecting: ["block", "notfound"], timeout: .seconds(120))
            switch blockResponse {
            case let .block(block):
                guard block.hash == message.blockHash else {
                    await pool.misbehaving(peer, reason: "block hash mismatch at \(height)")
                    throw FilterSyncError.badPeerResponse("block hash mismatch at \(height)")
                }
                // The header hash only authenticates the 80-byte header. Verify
                // the transaction set hashes to the header's committed merkle
                // root before crediting anything from it — otherwise a peer can
                // serve the real header with a fabricated (or pruned) tx list.
                guard block.hasValidMerkleRoot else {
                    await pool.misbehaving(peer, reason: "merkle root mismatch at \(height)")
                    throw FilterSyncError.badPeerResponse("merkle root mismatch at \(height)")
                }
                try await onMatch(BlockMatch(height: height, blockHash: message.blockHash, block: block))
            case .notfound:
                throw FilterSyncError.badPeerResponse("peer lost block at \(height)")
            default:
                throw FilterSyncError.badPeerResponse("expected block")
            }
        }
        guard seen.count == count else {
            throw FilterSyncError.badPeerResponse("missing cfilters: \(seen.count)/\(count)")
        }
    }

    private static func filterHeader(at height: UInt32, in headers: [String: String]) -> Data? {
        headers[String(height)].flatMap { Data(hex: $0) }
    }

    private static func load(storageURL: URL, startHeight: UInt32) throws
        -> (state: PersistenceState, progress: Progress)
    {
        guard FileManager.default.fileExists(atPath: storageURL.path) else {
            return (.missing, Progress(nextScanHeight: startHeight))
        }
        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try FileManager.default.attributesOfItem(atPath: storageURL.path)
        } catch {
            throw FilterSyncStorageError.unreadable
        }
        if let size = attributes[.size] as? NSNumber,
           size.int64Value > Int64(maximumProgressBytes) {
            throw FilterSyncStorageError.tooLarge(maxBytes: maximumProgressBytes)
        }
        let data: Data
        do {
            data = try Data(contentsOf: storageURL, options: .mappedIfSafe)
        } catch {
            throw FilterSyncStorageError.unreadable
        }
        guard data.count <= maximumProgressBytes else {
            throw FilterSyncStorageError.tooLarge(maxBytes: maximumProgressBytes)
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

    private static func validate(progress: Progress, startHeight: UInt32) throws {
        guard progress.nextScanHeight >= startHeight else {
            throw FilterSyncStorageError.frontierBeforeWallet(
                stored: progress.nextScanHeight, wallet: startHeight)
        }
        guard progress.filterHeaders.count <= maximumPinnedHeaders else {
            throw FilterSyncStorageError.damaged("there are too many pinned filter headers")
        }
        var parsedHeights = Set<UInt32>()
        parsedHeights.reserveCapacity(progress.filterHeaders.count)
        for (key, value) in progress.filterHeaders {
            guard let height = UInt32(key), String(height) == key else {
                throw FilterSyncStorageError.damaged("a filter-header height is not canonical decimal")
            }
            guard parsedHeights.insert(height).inserted else {
                throw FilterSyncStorageError.damaged("two filter-header keys name the same height")
            }
            guard height < progress.nextScanHeight else {
                throw FilterSyncStorageError.damaged("a pinned filter header is at or beyond the scan frontier")
            }
            guard value.utf8.count == 64,
                  let header = Data(hex: value), header.count == 32 else {
                throw FilterSyncStorageError.damaged("a pinned filter header is not 32 bytes")
            }
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
    public func rollBack(to forkHeight: UInt32) throws {
        let resumeFrom = forkHeight == UInt32.max ? forkHeight : forkHeight + 1
        var candidate = progress
        candidate.nextScanHeight = min(progress.nextScanHeight, resumeFrom)
        candidate.filterHeaders = progress.filterHeaders.filter { key, _ in
            guard let height = UInt32(key) else { return false }
            return height <= forkHeight
        }
        guard candidate != progress else { return }
        try persist(candidate)
        progress = candidate
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

    private func persist(_ candidate: Progress) throws {
        guard let storageURL else { return }
        let data = try JSONEncoder().encode(candidate)
        guard data.count <= Self.maximumProgressBytes else {
            throw FilterSyncStorageError.tooLarge(maxBytes: Self.maximumProgressBytes)
        }
        do {
            try data.write(to: storageURL,
                           options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        } catch {
            throw FilterSyncStorageError.writeFailed
        }
    }
}
