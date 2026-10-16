import Foundation

/// Why a restore-only range scan refused.
///
/// Every case is a refusal, never a truncation: a scan that has run out of a
/// cap throws rather than returning a short answer that reads like a complete
/// one. What separates them is whether the caller can resume. The two spending
/// caps (`filterBytesExhausted`, `runTimedOut`) leave the range record holding
/// every batch that committed before them, so the next call carries on from
/// there with a fresh budget. The shape refusals (`invalidRange`,
/// `rangeTooWide`, `tooManyScripts`, `tooManyIterations`, `rangeBelowChain`,
/// `rangeAboveChain`, `rangeSpansNoCheckpoint`) are decided before any peer is
/// asked, and they mean the caller must change what it asked for; retrying the
/// same call reproduces them exactly.
public enum RangeScanError: LocalizedError, Equatable, Sendable {
    /// `from` is above `to`, or `to` is `UInt32.max`: a completed record has
    /// to be able to name the height after the last one it scanned.
    case invalidRange(from: UInt32, to: UInt32)
    /// A scan with nothing to look for. It would read every filter in the
    /// range and match nothing, which is the whole cost with none of the
    /// answer.
    case noWatchScripts
    case rangeTooWide(blocks: UInt64, limit: UInt32)
    case tooManyScripts(count: Int, limit: Int)
    case tooManyIterations(count: Int, limit: Int)
    case filterBytesExhausted(read: Int, limit: Int)
    case runTimedOut(limit: Duration)
    /// The range starts below the first block the header chain holds. On a
    /// checkpoint-rooted mainnet chain that floor is the pinned checkpoint
    /// (the network's pinned checkpoint): filters are fetched by block hash, and there is no
    /// header below the base to name one.
    case rangeBelowChain(from: UInt32, start: UInt32)
    case rangeAboveChain(to: UInt32, tip: UInt32)
    /// The blocks still to scan hold no checkpoint boundary, and the record
    /// holds no verified filter header below them to anchor on. Nothing would
    /// judge the filter chain a peer announced for those blocks: the anchor
    /// would be that peer's word, every header above it derives from the
    /// anchor by hash chain, the boundary comparison would find no boundary to
    /// compare, and a lone cfheaders answer is accepted by design. The range
    /// is refused rather than scanned on one peer's say-so. Widen it up to the
    /// next multiple of `FilterSync.checkpointInterval`, or run the pass that
    /// pins the header below `from` first.
    case rangeSpansNoCheckpoint(from: UInt32, to: UInt32)
    case recordUnreadable
    case recordTooLarge(maxBytes: Int)
    case recordDamaged(String)
    case recordWriteFailed

    /// The range record's reading of a storage failure. The shared file
    /// helpers speak `FilterSyncStorageError`; the two frontier cases are the
    /// forward scan's and cannot arise from a range record.
    init(storage error: FilterSyncStorageError) {
        switch error {
        case .unreadable: self = .recordUnreadable
        case let .tooLarge(maxBytes): self = .recordTooLarge(maxBytes: maxBytes)
        case let .damaged(reason): self = .recordDamaged(reason)
        case .writeFailed: self = .recordWriteFailed
        case .frontierBeforeWallet, .frontierBeyondTip:
            self = .recordDamaged(error.errorDescription ?? "the frontier disagrees")
        }
    }

    public var errorDescription: String? {
        switch self {
        // MARK: The request
        case let .invalidRange(from, to):
            "Winnow was asked to scan blocks \(from) to \(to), which is not a range it can scan."
        case .noWatchScripts:
            "A block range scan needs at least one script to look for."
        case let .rangeTooWide(blocks, limit):
            "That restore would scan \(blocks) blocks, past the \(limit)-block limit for one range."
        case let .tooManyScripts(count, limit):
            "That restore looks for \(count) scripts, past the limit of \(limit)."
        case let .tooManyIterations(count, limit):
            "That restore has already rescanned its range \(limit) time\(limit == 1 ? "" : "s") and asked for pass \(count)."
        case let .rangeBelowChain(from, start):
            "The restore scan starts at block \(from), below block \(start), which is the first block Winnow holds a header for."
        case let .rangeAboveChain(to, tip):
            "The restore scan ends at block \(to), above the validated chain tip \(tip)."
        case let .rangeSpansNoCheckpoint(from, to):
            "Blocks \(from) to \(to) hold no filter checkpoint, and Winnow has no verified filter header below them, so nothing could check what a peer sent. Scan a wider range."
        // MARK: The budget
        case let .filterBytesExhausted(read, limit):
            "The restore scan reached its data limit (\(read) of \(limit) bytes of compact filters). It can be resumed."
        case let .runTimedOut(limit):
            "The restore scan reached its time limit (\(limit)). It can be resumed."
        // MARK: The progress file
        case .recordUnreadable:
            "Winnow could not read the restore scan's progress file. The scan is stopped so a payment is not skipped."
        case let .recordTooLarge(maxBytes):
            "The restore scan's progress file is unexpectedly large (limit: \(maxBytes) bytes). The scan is stopped."
        case let .recordDamaged(reason):
            "The restore scan's progress file is damaged (\(reason)). The scan is stopped; Winnow will not replace it automatically."
        case .recordWriteFailed:
            "Winnow could not safely save the restore scan's progress. Nothing was recorded for this batch."
        }
    }
}

/// What bounds one restore-only range scan, and what bounds the restore it is
/// part of.
///
/// This is an opt-in recovery primitive with finite resource limits. Ordinary
/// synchronization remains forward-only:
/// a wallet scans from its birthday to the tip and never back, because a
/// historical back-scan on a phone is unbounded work on a radio the customer
/// pays for. A restore that has a mnemonic and no wallet file has no birthday
/// to scan forward from, so the caller may choose a bounded back-scan. Every
/// dimension of it is capped, by a number that cannot be raised past a hard
/// maximum stated here.
///
/// Each value is clamped to its ceiling on the way in rather than validated,
/// so a caller cannot loosen a cap by asking for more; asking for less always
/// works. The ceilings are:
///
/// - `blocksCeiling`, five years of mainnet blocks at 52,560 a year. A restore
///   range is [birthday, frontier]. The caller chooses its recovery birthday;
///   this ceiling refuses an unbounded scan of the whole chain.
/// - `scriptsCeiling`, 200 windows of the 100-index restore gap. Matching is
///   linear in the script set for every filter in the range, so this is the
///   cap that decides how much CPU a pass costs.
/// - `filterBytesCeiling`, 1 GiB in one run. What it counts is every byte the
///   run reads off the wire and keeps: the compact filters of the blocks it
///   scans, plus the full blocks their matches pull down. Both are charged to
///   the one budget, because on a restore the blocks are the larger half. A
///   mainnet filter runs 15-20 KB a block and a matched block is up to 4 MB,
///   so the default 64 MiB is roughly 3,500 blocks when nothing matches and
///   fewer as matches accumulate: BIP158 false positives alone are about 1 in
///   40 blocks against a 20,000-script set. `RangeScanOutcome` reports the two
///   halves separately so a caller can see which one it spent.
///
///   The cap is charged after the bytes have arrived, so a run ends slightly
///   past it. The exact worst case is one chunk of filters plus one block:
///   a chunk's filters are charged once the whole chunk has been read and
///   verified, before any of it is matched, which
///   `FilterSync.chunkByteBound(filters:)` bounds at `filtersPerChunk` times
///   1.25 MB (125 MB at the default 100), and a matched block is charged once
///   it has been verified and delivered, bounded by the 4 MB a block message
///   may carry. A real chunk of 100 mainnet filters is under 2 MB.
/// - `durationCeiling`, an hour. Read between batches, before every chunk
///   request, and before every matched block is fetched, so a run overshoots
///   by at most one outstanding peer request; this bounds how long a restore
///   may hold the pool, not how long a request takes.
/// - `iterationsCeiling`, 50 passes over the range. A pass is one fixed-point
///   step: the caller derives more scripts from what the last pass found and
///   scans the range again. Honest restores converge in two or three.
///
/// What bounds the whole restore, rather than one run, is `maxBlocks` and
/// `maxIterations` together. A run that refuses on bytes or time resumes from
/// the last batch that committed, so what it re-reads is the batch it died
/// inside and never the range: the filter traffic of a whole restore is the
/// range read `maxIterations` times, plus one batch for each interruption.
public struct RangeScanLimits: Sendable, Equatable {
    public static let blocksCeiling: UInt32 = 262_800
    public static let scriptsCeiling = 20_000
    public static let filterBytesCeiling = 1_024 * 1_024 * 1_024
    public static let durationCeiling: Duration = .seconds(3_600)
    public static let iterationsCeiling = 50

    /// Blocks in [from, to], inclusive.
    public let maxBlocks: UInt32
    /// Watch scripts one pass may look for.
    public let maxScripts: Int
    /// Bytes one run may read before it refuses: compact filters and the
    /// blocks their matches fetched, added together. The name is the cap's
    /// oldest half and stayed for the callers already spelling it, but a
    /// restore spends most of this budget on blocks.
    public let maxFilterBytes: Int
    /// Wall-clock time one run may take before it refuses.
    public let maxDuration: Duration
    /// Passes over the range one record may accumulate.
    public let maxIterations: Int

    public init(maxBlocks: UInt32 = 105_120,
                maxScripts: Int = 2_000,
                maxFilterBytes: Int = 64 * 1_024 * 1_024,
                maxDuration: Duration = .seconds(300),
                maxIterations: Int = 10) {
        self.maxBlocks = min(maxBlocks, Self.blocksCeiling)
        self.maxScripts = min(max(0, maxScripts), Self.scriptsCeiling)
        self.maxFilterBytes = min(max(0, maxFilterBytes), Self.filterBytesCeiling)
        self.maxDuration = min(max(.zero, maxDuration), Self.durationCeiling)
        self.maxIterations = min(max(0, maxIterations), Self.iterationsCeiling)
    }
}

/// A range scan's persisted, resumable progress. Its own record, in its own
/// file: nothing here is the forward scan frontier, and a range scan never
/// reads or writes that frontier.
///
/// The record names the range and the script set it describes, because both
/// decide what resuming means. Same range and same scripts is a resumption,
/// and it starts at `nextScanHeight`. Same range and a different script set is
/// the next fixed-point pass, so the frontier goes back to `from` and
/// `iteration` counts up; the pinned headers below `from` are kept, since the
/// anchor at `from - 1` is what refuses a peer whose announced filter chain
/// does not continue the one an earlier pass verified. A different range is a
/// different scan and replaces the record, because a record can describe only
/// one range and keeping the old one would resume the wrong blocks.
///
/// The file says which kind of record it is, and both loaders check. Without
/// that, the two records are interchangeable by accident: this one carries
/// `nextScanHeight` and `filterHeaders` under the same names the forward
/// progress file uses, `JSONDecoder` ignores the keys it was not asked about,
/// and the forward loader's validation passes on the rest. A caller that hands
/// `scanRange` the wallet's own progress file would then have its restore
/// quietly rewrite the forward frontier, which is the one thing this whole
/// file exists not to do. `record` is that marker: the forward loader refuses
/// a file that carries it, this loader refuses a file that does not, and a
/// forward file written before the marker existed carries no key and still
/// loads.
public struct RangeScanProgress: Codable, Sendable, Equatable {
    /// What this file is. Written on every save, required on every load.
    public static let recordKind = "range"

    /// The marker, checked by both loaders. Never anything but `recordKind`:
    /// it is decoded so a file that names some other kind is refused by name
    /// rather than by a missing key.
    public private(set) var record = RangeScanProgress.recordKind
    /// First height of the range, inclusive.
    public var from: UInt32
    /// Last height of the range, inclusive.
    public var to: UInt32
    /// Next height inside the range whose filter must be read. `to + 1` when
    /// the range is finished.
    public var nextScanHeight: UInt32
    /// SHA256d over the sorted watch scripts this record was scanned with.
    public var watchFingerprint: String
    /// Which fixed-point pass over the range this is, counting from one.
    public var iteration: Int
    /// Pinned filter headers: decimal height to hex (internal byte order),
    /// pruned exactly as the forward scan prunes its own.
    public var filterHeaders: [String: String]
    /// Which peers corroborated the checkpoint answer the pass is anchored
    /// to, beside the class the pool reached each of them through. Written
    /// on every batch commit like the forward frontier's, so what the record
    /// stands on is never a receipt from an older run; cleared by a restart,
    /// since the next pass earns its own. Optional so a record written before
    /// it existed still loads.
    public var crossCheck: FilterSync.CrossCheckReceipt?

    public init(from: UInt32, to: UInt32, nextScanHeight: UInt32,
                watchFingerprint: String, iteration: Int,
                filterHeaders: [String: String] = [:],
                crossCheck: FilterSync.CrossCheckReceipt? = nil) {
        self.from = from
        self.to = to
        self.nextScanHeight = nextScanHeight
        self.watchFingerprint = watchFingerprint
        self.iteration = iteration
        self.filterHeaders = filterHeaders
        self.crossCheck = crossCheck
    }

    /// Whether every block in [from, to] has been scanned by this pass.
    public var isComplete: Bool { nextScanHeight > to }

    /// Highest height this pass has scanned, or nil when it has committed no
    /// batch yet.
    public var scannedThrough: UInt32? { nextScanHeight > from ? nextScanHeight - 1 : nil }

    /// The record for the next fixed-point pass: the same range, read again
    /// from the start with a larger script set.
    func restarted(fingerprint: String) -> RangeScanProgress {
        let start = from
        return RangeScanProgress(
            from: from, to: to, nextScanHeight: from,
            watchFingerprint: fingerprint, iteration: iteration + 1,
            filterHeaders: filterHeaders.filter { key, _ in
                guard let height = UInt32(key) else { return false }
                return height < start
            })
    }

    /// One identity for a watch set, independent of order and of repeats: the
    /// distinct scripts as sorted hex, newline-separated, hashed. A different
    /// set means a different pass over the range, and this is what tells the
    /// two apart across a process that stopped in between.
    public static func fingerprint(of watchScripts: [Data]) -> String {
        var joined = Data()
        for script in Set(watchScripts.map(\.hex)).sorted() {
            joined.append(contentsOf: Array(script.utf8))
            joined.append(0x0A)
        }
        return SHA256d.hash(joined).hex
    }

    /// The record stored at `storageURL`, or nil when there is none. Damage is
    /// reported, never repaired: a record that cannot be read is not replaced
    /// with a fresh one, because "start over" and "resume" differ by exactly
    /// the blocks a restore would then skip.
    ///
    /// The file is decoded once. A forward progress file lacks the range
    /// fields and fails that decode, and a file that carries every field under
    /// a foreign marker passes it; either way the marker is read only to name
    /// what the file is instead of calling it damaged, and no progress field
    /// is trusted before `validate()`.
    public static func load(storageURL: URL?) throws -> RangeScanProgress? {
        guard let storageURL else { return nil }
        let data: Data
        do {
            guard let read = try FilterSync.readRecord(
                at: storageURL, maxBytes: FilterSync.rangeRecordMaxBytes) else { return nil }
            data = read
        } catch let error as FilterSyncStorageError {
            throw RangeScanError(storage: error)
        }
        let stored: RangeScanProgress
        do {
            stored = try JSONDecoder().decode(RangeScanProgress.self, from: data)
        } catch {
            throw notRangeRecord(in: data) ?? RangeScanError.recordDamaged(
                "the JSON or a progress field is invalid")
        }
        guard stored.record == recordKind else {
            throw notRangeRecord(in: data) ?? RangeScanError.recordDamaged(
                "the file is not a range-scan record")
        }
        try stored.validate()
        return stored
    }

    /// The refusal for a file whose marker is not `recordKind`, or nil when it
    /// is, which means the file is a range record that is damaged some other way.
    private static func notRangeRecord(in data: Data) -> RangeScanError? {
        let kind = FilterSync.recordKind(in: data)
        guard kind != recordKind else { return nil }
        return .recordDamaged(
            "the file is not a range-scan record (it is marked \(kind.map { "\"\($0)\"" } ?? "nothing"))")
    }

    func validate() throws {
        guard from <= to, nextScanHeight >= from,
              UInt64(nextScanHeight) <= UInt64(to) + 1 else {
            throw RangeScanError.recordDamaged("the range and its frontier disagree")
        }
        guard (1 ... RangeScanLimits.iterationsCeiling).contains(iteration) else {
            throw RangeScanError.recordDamaged("the pass number is out of range")
        }
        guard Data(hex: watchFingerprint)?.count == 32 else {
            throw RangeScanError.recordDamaged("the watch-script fingerprint is not 32 bytes")
        }
        do {
            try FilterSync.validate(filterHeaders: filterHeaders, below: nextScanHeight,
                                    maxPinned: FilterSync.rangeRecordMaxPinnedHeaders)
            try FilterSync.validate(receipt: crossCheck)
        } catch let error as FilterSyncStorageError {
            throw RangeScanError(storage: error)
        }
    }

    func persist(to storageURL: URL?) throws {
        guard let storageURL else { return }
        do {
            try FilterSync.writeRecord(self, to: storageURL, maxBytes: FilterSync.rangeRecordMaxBytes)
        } catch let error as FilterSyncStorageError {
            throw RangeScanError(storage: error)
        }
    }

    /// The record a run starts from: the stored one resumed, the stored one
    /// restarted for a new script set, or a fresh one. The pass cap is
    /// checked here, before any peer is asked.
    static func resumed(stored: RangeScanProgress?, from: UInt32, to: UInt32,
                        fingerprint: String, limits: RangeScanLimits) throws -> RangeScanProgress {
        var record = RangeScanProgress(from: from, to: to, nextScanHeight: from,
                                       watchFingerprint: fingerprint, iteration: 1)
        if let stored, stored.from == from, stored.to == to {
            record = stored.watchFingerprint == fingerprint
                ? stored
                : stored.restarted(fingerprint: fingerprint)
        }
        guard record.iteration <= limits.maxIterations else {
            throw RangeScanError.tooManyIterations(count: record.iteration,
                                                   limit: limits.maxIterations)
        }
        return record
    }
}

/// What one range-scan run has spent and how much it has left. Held on the
/// actor for the length of a run so the filter-chunk loop can be refused from
/// inside, which is what makes the byte and time caps bounds on a run rather
/// than on a batch.
struct RangeScanRun: Sendable {
    let deadline: ContinuousClock.Instant
    let maxDuration: Duration
    let maxFilterBytes: Int
    private(set) var filterBytesRead = 0
    private(set) var blockBytesRead = 0
    private(set) var matchedHeights: [UInt32] = []

    /// What the byte cap is spent against: the filters and the blocks together.
    var bytesRead: Int { filterBytesRead + blockBytesRead }

    init(limits: RangeScanLimits, now: ContinuousClock.Instant = .now) {
        deadline = now.advanced(by: limits.maxDuration)
        maxDuration = limits.maxDuration
        maxFilterBytes = limits.maxFilterBytes
    }

    func checkDeadline(now: ContinuousClock.Instant = .now) throws {
        guard now < deadline else { throw RangeScanError.runTimedOut(limit: maxDuration) }
    }

    /// Charges a chunk's filter bytes and refuses if that took the run past
    /// its cap. Charged after the chunk has arrived and been matched, so the
    /// overshoot is one chunk, which `FilterSync.chunkByteBound(filters:)`
    /// already bounds on the wire.
    mutating func charge(filterBytes: Int) throws {
        filterBytesRead += filterBytes
        try checkBudget()
    }

    /// Charges a matched block against the same budget. On a restore these
    /// are the bytes that matter: a block is up to 4 MB where a filter is
    /// tens of kilobytes, and at a full watch set BIP158 hands back a false
    /// positive every few dozen blocks, so a cap that counted only filters
    /// was not a cap on what the run downloaded. Charged once the block has
    /// been verified and delivered, so the overshoot here is one block.
    mutating func charge(blockBytes: Int) throws {
        blockBytesRead += blockBytes
        try checkBudget()
    }

    private func checkBudget() throws {
        guard bytesRead <= maxFilterBytes else {
            throw RangeScanError.filterBytesExhausted(read: bytesRead,
                                                      limit: maxFilterBytes)
        }
    }

    mutating func note(matchAt height: UInt32) {
        matchedHeights.append(height)
    }
}

/// What one range-scan run did. The blocks themselves go to `onMatch` as they
/// are found, exactly as the forward scan delivers them, because a restore
/// range can match more blocks than a phone should hold at once; what comes
/// back here is the bookkeeping a caller needs to decide whether to run again.
public struct RangeScanOutcome: Sendable, Equatable {
    public let from: UInt32
    public let to: UInt32
    /// Heights delivered to `onMatch` by THIS run. A resumed run reports what
    /// it found, not what earlier runs found.
    public let matchedHeights: [UInt32]
    /// Highest height the record has scanned to, over every run of this pass.
    public let scannedThrough: UInt32?
    /// Whether [from, to] is now covered by this pass.
    public let isComplete: Bool
    /// Which fixed-point pass this run belonged to.
    public let iteration: Int
    /// Compact-filter bytes this run read.
    public let filterBytesRead: Int
    /// Bytes of matched blocks this run downloaded. Reported beside the
    /// filters rather than added into them because the two say different
    /// things about a restore: filters scale with the range, blocks scale
    /// with what the watch set hit. The byte cap is spent against their sum.
    public let blockBytesRead: Int
    /// Which peers corroborated the checkpoint answer the record stands on,
    /// from its last committed batch. Nil only for a record that has
    /// committed nothing yet, which a completed outcome never is.
    public let crossCheck: FilterSync.CrossCheckReceipt?
}

extension FilterSync {
    /// The most bytes a range record's file may be. Pruning holds a record to
    /// a few thousand pinned headers, which is a couple of hundred kilobytes;
    /// this is far above that and far below anything that would matter to
    /// memory, and it exists so a replaced or corrupted file is refused
    /// rather than decoded.
    public static let rangeRecordMaxBytes = 16 * 1_024 * 1_024
    /// The most pinned headers a range record may carry, for the same reason
    /// the forward progress file has one.
    public static let rangeRecordMaxPinnedHeaders = 2_000_000

    /// Scans [from, to] for `watchScripts` without moving the forward scan
    /// frontier: the restore-only back-scan, and the one entry point in this
    /// file that a caller uses.
    ///
    /// This exists for one situation. A customer restores from a mnemonic and
    /// has no wallet file, so there is no history to verify forward from and
    /// no birthday to start at. The caller picks a floor (a recovery record's
    /// birthday, or the frozen launch height), derives a gap of scripts, scans
    /// the range for them, derives more from what came back, and scans again
    /// until a pass finds nothing new. This call is one pass, or one run of
    /// one pass; the loop and the decision to run it again belong to the
    /// caller, and `RangeScanLimits` is what stops the loop being unbounded.
    ///
    /// **The header chain is read, never advanced.** There is no `syncHeaders`
    /// here, so a caller that wants the back-scan pinned to a frozen recovery
    /// checkpoint simply hands over a chain it does not sync. The range must
    /// be inside what that chain holds: below `chain.startHeight` there are no
    /// headers, and filters are fetched by block hash, so a range that reaches
    /// under the base is refused with `rangeBelowChain` rather than failing
    /// later as a missing header. On mainnet that floor is the pinned
    /// network-specific checkpoint.
    ///
    /// Everything a batch is judged by is the forward path's, unchanged: the
    /// cfcheckpt majority across peers, the announced-count guard tied to the
    /// tip, the cross-check policy over who agreed (a run refused by
    /// `CrossCheckPolicy.requireDistinctSources` throws `crossCheckUnavailable`
    /// before any filter is fetched, exactly as `sync` does, because the coins
    /// a restore finds are the spend-relevant state that policy exists to
    /// hold back), the cfheaders cross-check per batch, the checkpoint-boundary
    /// comparison before a batch has any effect, the per-filter header
    /// reproduction, and the chunked fetch with its byte bound. A batch that
    /// fails any of them commits nothing and the record stays where it was.
    /// The receipt naming who corroborated the run is persisted with every
    /// batch and returned on the outcome.
    ///
    /// **The range has to reach a checkpoint boundary, or resume from a
    /// verified anchor.** That list is only worth what the boundary
    /// comparison is worth, and the comparison judges the heights a batch
    /// pins that `cfcheckpt` also speaks for: every positive multiple of
    /// `FilterSync.checkpointInterval`. A batch that pins none of them is
    /// compared against nothing. The forward path cannot be in that position
    /// (it starts from a frontier whose header it has verified, or from
    /// genesis, whose previous filter header is zero by consensus), but a
    /// caller here picks both ends of the range, and a range that fits between
    /// two boundaries has no anchor at all: `anchorPreviousHeader` would take
    /// the peer's announced previous header on trust, every header above it
    /// derives from that by hash chain, and a lone cfheaders answer is
    /// accepted by design. So a run whose first batch would be anchored on a
    /// peer's word is refused with `rangeSpansNoCheckpoint` before anything is
    /// asked of anyone, unless the blocks it still has to scan reach a
    /// boundary. A resumed pass, or the next fixed-point pass, is not in that
    /// position: its record holds the header below its frontier, pinned by a
    /// pass that did reach a boundary, and it runs.
    ///
    /// The one case the guard cannot cover is a chain whose tip is below the
    /// first boundary, where no range reaches one because none exists. There
    /// the announced-count guard requires an empty `cfcheckpt` and there is
    /// nothing for any comparison on either path to use, so the scan is
    /// permitted and it is a peer's word. That is a chain shorter than 1,000
    /// blocks: regtest and a brand-new signet, never a network a restore runs
    /// against.
    ///
    /// Progress goes to `storageURL`, which is not the forward progress file:
    /// the two records name themselves in the file (`RangeScanProgress.record`)
    /// and each loader refuses the other's, so passing the wallet's own
    /// progress file here fails rather than rewrites it. Nil keeps the whole
    /// scan in memory, which means an interrupted run starts over.
    ///
    /// A run interrupted by a cap or a peer fault leaves the record at the
    /// last batch that committed, so the blocks of the batch it died inside
    /// are read again by the next run and their matches delivered again.
    /// `onMatch` must therefore be idempotent per height, which is the same
    /// contract the forward scan's already has.
    ///
    /// A record describes the chain it was scanned against, and nothing here
    /// rolls one back. If the header chain is replaced under a record between
    /// two runs — which takes a caller advancing it, since this call never
    /// does — the pinned anchor below the resumed frontier no longer continues
    /// what a peer announces, and the first batch of the next run fails closed
    /// with `filterHeaderMismatch` rather than reading blocks off a branch
    /// that is gone. Starting a fresh restore means deleting the record, not
    /// scanning over it.
    ///
    /// One run at a time, and it shares that rule with `sync`: both take the
    /// same flag, so a range scan while a forward sync is running (or the
    /// other way round) throws `busy` having changed nothing.
    /// They would otherwise share one pool, and peer replies go to whichever
    /// collector expects the command first.
    @discardableResult
    public func scanRange(from: UInt32, to: UInt32,
                          watchScripts: [Data],
                          limits: RangeScanLimits = RangeScanLimits(),
                          storageURL: URL? = nil,
                          onMatch: @Sendable (BlockMatch) async throws -> Void) async throws
        -> RangeScanOutcome
    {
        try beginRequest()
        defer {
            endRequest()
            rangeRun = nil
        }
        try Self.checkShape(from: from, to: to, watchScripts: watchScripts, limits: limits)
        // Same refusal as `sync`, for the same reason: a pool holding seats so
        // a signed payment can go out is not a pool to read a restore over.
        // Asked here as well as inside `rangeReference` so the refusal lands
        // before the record is read off disk.
        guard await pool.mode == .full else { throw FilterSyncError.relayOnly }
        let (tip, tipHash) = await chain.tipSnapshot
        try Self.checkChain(from: from, to: to, start: await chain.startHeight, tip: tip)

        var record = try RangeScanProgress.resumed(
            stored: RangeScanProgress.load(storageURL: storageURL),
            from: from, to: to,
            fingerprint: RangeScanProgress.fingerprint(of: watchScripts),
            limits: limits)
        // Still before a peer is asked anything: the record came off disk and
        // the tip off our own header chain. It goes here rather than in
        // `checkShape` because whether the blocks left to scan need a boundary
        // depends on what the record already holds below them.
        try Self.checkCheckpointAnchor(of: record, to: to, tip: tip)
        rangeRun = RangeScanRun(limits: limits)
        if !record.isComplete {
            record = try await runRange(record, tip: tip, tipHash: tipHash, watchScripts: watchScripts,
                                        storageURL: storageURL, onMatch: onMatch)
        }
        return RangeScanOutcome(from: from, to: to,
                                matchedHeights: rangeRun?.matchedHeights ?? [],
                                scannedThrough: record.scannedThrough,
                                isComplete: record.isComplete,
                                iteration: record.iteration,
                                filterBytesRead: rangeRun?.filterBytesRead ?? 0,
                                blockBytesRead: rangeRun?.blockBytesRead ?? 0,
                                crossCheck: record.crossCheck)
    }

    /// The batch loop, which is the forward scan's with the range's own record
    /// in place of the frontier and no reorg handling (the chain is not being
    /// advanced, so nothing can fork underneath it).
    private func runRange(_ initial: RangeScanProgress, tip: UInt32, tipHash: Data,
                          watchScripts: [Data], storageURL: URL?,
                          onMatch: @Sendable (BlockMatch) async throws -> Void) async throws
        -> RangeScanProgress
    {
        let (reference, approvedEndpoints, receipt) = try await rangeReference(tip: tip, tipHash: tipHash)
        try Self.checkPinnedBoundaries(of: initial.filterHeaders, against: reference, tip: tip)
        var peers = try await approved(peers: approvedEndpoints)
        var record = initial
        let collect: @Sendable (BlockMatch) async throws -> Void = { match in
            await self.note(matchAt: match.height)
            try await onMatch(match)
        }
        while record.nextScanHeight <= record.to {
            try checkRangeDeadline()
            let batchStart = record.nextScanHeight
            let batchStop = UInt32(min(UInt64(batchStart) + UInt64(Self.maxRangePerRequest) - 1,
                                       UInt64(record.to)))
            guard let stopHash = await chain.blockHash(at: batchStop) else {
                throw FilterSyncError.badPeerResponse("missing header at \(batchStop)")
            }
            // Whether this batch has an anchor of its own, read before the
            // peer is asked: `pinFilterHeaders` writes the peer's announced
            // previous header into `proposed` when the record holds none, so
            // afterwards the two cases look identical.
            let anchored = batchStart == 0 || record.filterHeaders[String(batchStart - 1)] != nil
            let proposed = try await pinFilterHeaders(
                batchStart: batchStart, batchStop: batchStop, stopHash: stopHash,
                peers: peers, startingFrom: record.filterHeaders)
            // Before the batch has any effect, exactly as the forward path
            // does it: a batch whose checkpoint boundaries disagree with the
            // announced cfcheckpt delivers no match and persists nothing.
            try Self.checkPinnedBoundaries(of: proposed, against: reference, tip: tip)
            // And the same comparison must have had something to compare.
            // `checkCheckpointAnchor` refuses this run's first batch before
            // the run starts, and a full batch spans a boundary by
            // arithmetic, so reaching this is a bug rather than a peer. It
            // fails closed anyway: a batch anchored on a peer's word and
            // pinning no boundary is exactly the shape a fabricated filter
            // chain has, and the cost of the check is a dictionary lookup.
            if !anchored {
                try Self.requireComparedBoundary(in: proposed, batchStart: batchStart,
                                                 batchStop: batchStop, tip: tip)
            }
            // Re-derived because the cross-check may have just disconnected
            // the peer at the front of the list.
            peers = try await approved(peers: approvedEndpoints)
            try await scanFilters(batchStart: batchStart, batchStop: batchStop, peer: peers[0],
                                  watchScripts: watchScripts, filterHeaders: proposed,
                                  onMatch: collect)
            var candidate = record
            candidate.nextScanHeight = batchStop + 1
            candidate.filterHeaders = Self.prunedRangeHeaders(
                proposed, frontier: candidate.nextScanHeight, rangeStart: initial.from)
            candidate.crossCheck = receipt
            try candidate.persist(to: storageURL)
            record = candidate
        }
        return record
    }

    /// The cfcheckpt reference for a range scan, the peers that gave it, and
    /// the receipt naming them: `anchoredReference`, exactly as the forward
    /// scan runs it, against the chain as it stands rather than one just
    /// synced. The coins a restore finds are spend-relevant state, so the
    /// cross-check policy is applied here by the same code, before any
    /// filter is fetched. The tip and its hash are the pair `scanRange` read
    /// in one job: a header sync a caller runs alongside, against the rule,
    /// would otherwise move them apart and have honest peers banned for
    /// announcing the count the newer tip implies.
    private func rangeReference(tip: UInt32, tipHash: Data) async throws
        -> (reference: CFCheckptMessage, approved: Set<String>, receipt: FilterSync.CrossCheckReceipt)
    {
        let peers = try await peersForReading()
        return try await anchoredReference(peers: peers, tip: tip, tipHash: tipHash)
    }

    /// Everything about the request that can be judged before a peer is
    /// asked anything.
    static func checkShape(from: UInt32, to: UInt32, watchScripts: [Data],
                           limits: RangeScanLimits) throws {
        guard from <= to, to < UInt32.max else {
            throw RangeScanError.invalidRange(from: from, to: to)
        }
        guard !watchScripts.isEmpty else { throw RangeScanError.noWatchScripts }
        let blocks = UInt64(to) - UInt64(from) + 1
        guard blocks <= UInt64(limits.maxBlocks) else {
            throw RangeScanError.rangeTooWide(blocks: blocks, limit: limits.maxBlocks)
        }
        guard watchScripts.count <= limits.maxScripts else {
            throw RangeScanError.tooManyScripts(count: watchScripts.count, limit: limits.maxScripts)
        }
    }

    /// The range must be inside the headers we hold. Both ends are refused by
    /// name rather than left to fail as a missing block hash mid-batch.
    static func checkChain(from: UInt32, to: UInt32, start: UInt32, tip: UInt32) throws {
        guard from >= start else {
            throw RangeScanError.rangeBelowChain(from: from, start: start)
        }
        guard to <= tip else { throw RangeScanError.rangeAboveChain(to: to, tip: tip) }
    }

    /// The run must be able to check what a peer tells it. Either the record
    /// already holds the filter header below the first block still to scan, or
    /// what is left to scan reaches a checkpoint boundary the announced
    /// `cfcheckpt` speaks for. With neither, every header the run pins comes
    /// from one peer's announced anchor and nothing compares it to anything;
    /// see `scanRange`, which names the two ways out.
    ///
    /// Permitted when the chain holds no boundary at all, which is a tip below
    /// `FilterSync.checkpointInterval`. No range there could satisfy this, so
    /// refusing would ban the scan outright rather than protect it, and the
    /// forward path reads such a chain on the same terms.
    static func checkCheckpointAnchor(of record: RangeScanProgress, to: UInt32,
                                      tip: UInt32) throws {
        let frontier = record.nextScanHeight
        guard frontier <= to else { return }
        if frontier == 0 || record.filterHeaders[String(frontier - 1)] != nil { return }
        guard tip >= checkpointInterval else { return }
        // From the anchor height rather than the frontier: the first batch
        // pins the header below its start, and `checkPinnedBoundaries`
        // compares every boundary height in what it pins, so a range starting
        // one block above a boundary is checked at that boundary.
        guard boundary(from: frontier - 1, through: to, tip: tip) == nil else { return }
        throw RangeScanError.rangeSpansNoCheckpoint(from: frontier, to: to)
    }

    /// Defence in depth for the same rule, one batch at a time: the headers a
    /// batch proposes must include a boundary inside its span or at the anchor
    /// just below it, since those are the heights `checkPinnedBoundaries`
    /// compares against the cfcheckpt reference.
    static func requireComparedBoundary(in headers: [String: String], batchStart: UInt32,
                                        batchStop: UInt32, tip: UInt32) throws {
        guard tip >= checkpointInterval else { return }
        let low = batchStart > 0 ? batchStart - 1 : 0
        guard let height = boundary(from: low, through: batchStop, tip: tip),
              headers[String(height)] != nil else {
            throw FilterSyncError.checkpointMismatch(
                "blocks \(batchStart) to \(batchStop) pin no checkpoint the cfcheckpt reference covers")
        }
    }

    /// The lowest positive multiple of `checkpointInterval` inside
    /// [low, high] that the tip reaches, or nil when the span holds none.
    /// In 64 bits because the round-up overflows `UInt32` near the top of the
    /// range and a caller may name any height the chain has.
    static func boundary(from low: UInt32, through high: UInt32, tip: UInt32) -> UInt32? {
        let interval = UInt64(checkpointInterval)
        let ceiling = UInt64(min(high, tip))
        let floor = max(UInt64(low), interval)
        let first = ((floor + interval - 1) / interval) * interval
        guard first <= ceiling else { return nil }
        return UInt32(first)
    }

    /// The forward scan's pruning, plus the one header a range record needs
    /// that a forward frontier does not: the filter header below the range's
    /// own first block.
    ///
    /// Pruning keeps what the *next* batch can be asked for, so it drops
    /// anything below the last checkpoint boundary but one, and the anchor at
    /// `from - 1` falls out of that window as soon as the range is wider than
    /// about two intervals. The next fixed-point pass restarts at `from` and
    /// would then re-anchor on whatever a peer announced, which is the state
    /// this file's own doc says the kept anchor prevents. Keeping it costs one
    /// header, and `validate()` already permits it: it sits below
    /// `nextScanHeight` like every other pinned height.
    static func prunedRangeHeaders(_ headers: [String: String], frontier: UInt32,
                                   rangeStart: UInt32) -> [String: String] {
        var pruned = prunedFilterHeaders(headers, frontier: frontier)
        guard rangeStart > 0, let anchor = headers[String(rangeStart - 1)] else { return pruned }
        pruned[String(rangeStart - 1)] = anchor
        return pruned
    }

    // MARK: - The run's budget, consulted from the filter-chunk loop

    /// No-ops on the forward path, where `rangeRun` is nil and the caller's
    /// `maxBlocks` is the bound instead.
    func checkRangeDeadline() throws {
        try rangeRun?.checkDeadline()
    }

    func chargeRangeFilterBytes(_ bytes: Int) throws {
        try rangeRun?.charge(filterBytes: bytes)
    }

    func chargeRangeBlockBytes(_ bytes: Int) throws {
        try rangeRun?.charge(blockBytes: bytes)
    }

    private func note(matchAt height: UInt32) {
        rangeRun?.note(matchAt: height)
    }
}
