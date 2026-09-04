import BitcoinP2P
import BlockchainBackend
import Foundation

/// Where a transaction is on its way out of the phone (issue #51).
///
/// Distinct from relay state: `TxBroadcaster` knows which peer asked for the
/// bytes, and the wallet knows whether the spend is committed. The receipt
/// knows which route was chosen, what the provider said, whether the user
/// changed their mind, and — from the block path alone — whether it confirmed.
public enum SubmissionState: String, Codable, Sendable, CaseIterable {
    /// Signed and recorded; nothing has been sent yet (or the route is export).
    case constructed
    /// A submit request to a miner has been made; the answer is not yet known.
    case submitted
    /// A Bitcoin peer asked for and received the transaction.
    case relayed
    /// The miner admitted the transaction to its mempool.
    case accepted
    /// The miner refused it.
    case rejected
    /// A replacement (fee bump) was committed for the same inputs.
    case replaced
    /// Seen in a block Winnow verified itself.
    case confirmed
    /// The user stopped tracking it. Bookkeeping only: wallet state is untouched.
    case abandoned

    /// Nothing further will happen to a receipt in these states unless a
    /// block or a reorg says otherwise.
    public var isTerminal: Bool {
        switch self {
        case .confirmed, .abandoned, .replaced: true
        case .constructed, .submitted, .relayed, .accepted, .rejected: false
        }
    }

    /// The transitions the coordinator may make. `confirmed` is reachable
    /// from every state because the block path is authoritative — a
    /// rejected, abandoned or replaced transaction can still be mined by
    /// someone who had its bytes. The reverse edge, out of `confirmed`, is
    /// reserved for `rollBack` and is not a transition.
    public static func allows(_ from: SubmissionState, to: SubmissionState) -> Bool {
        if to == .confirmed { return from != .confirmed }
        return switch (from, to) {
        case (.constructed, .submitted), (.constructed, .relayed),
             (.constructed, .replaced), (.constructed, .abandoned):
            true
        case (.submitted, .accepted), (.submitted, .rejected), (.submitted, .relayed),
             (.submitted, .replaced), (.submitted, .abandoned):
            true
        case (.relayed, .replaced), (.relayed, .abandoned):
            true
        // A miner can evict what it admitted; a later poll reports that.
        case (.accepted, .relayed), (.accepted, .submitted), (.accepted, .rejected),
             (.accepted, .replaced), (.accepted, .abandoned):
            true
        case (.rejected, .submitted), (.rejected, .relayed),
             (.rejected, .replaced), (.rejected, .abandoned):
            true
        default:
            false
        }
    }
}

/// What produced the transaction. Shapes what the receipt view offers: a
/// wallet send can be fee-bumped, a foreign transaction cannot.
public enum SubmissionOrigin: Codable, Equatable, Sendable {
    case walletSend
    case vaultSpend(vaultID: String)
    case feeBump(original: Data)
    case cpfpChild(parent: Data)
    case foreign
}

/// One explicit route change, in order. "Never silently" is a property of
/// this array: every entry was a tap on a confirmation alert.
public struct RouteApproval: Codable, Equatable, Sendable {
    public let approvedAt: Date
    public let from: SubmissionRoute
    public let to: SubmissionRoute

    public init(approvedAt: Date, from: SubmissionRoute, to: SubmissionRoute) {
        self.approvedAt = approvedAt
        self.from = from
        self.to = to
    }
}

/// The provider's most recent word, kept verbatim so the UI can show it and
/// a bug report can carry it. Advisory: it never moves `state` to confirmed.
public struct ProviderStatusSnapshot: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable { case pending, confirmed, rejected, notFound }
    public let kind: Kind
    public let message: String?
    public let position: Int?
    public let inclusionOdds: String?
    public let reportedHeight: UInt32?
    public let observedAt: Date

    public init(kind: Kind, message: String?, position: Int?, inclusionOdds: String?,
                reportedHeight: UInt32?, observedAt: Date)
    {
        self.kind = kind
        self.message = message
        self.position = position
        self.inclusionOdds = inclusionOdds
        self.reportedHeight = reportedHeight
        self.observedAt = observedAt
    }

    public init(_ status: MinerReportedStatus, observedAt: Date) {
        switch status {
        case let .pending(position, odds, message):
            self.init(kind: .pending, message: message, position: position, inclusionOdds: odds,
                      reportedHeight: nil, observedAt: observedAt)
        case let .confirmed(height, _):
            self.init(kind: .confirmed, message: nil, position: nil, inclusionOdds: nil,
                      reportedHeight: height, observedAt: observedAt)
        case let .rejected(reason):
            self.init(kind: .rejected, message: reason, position: nil, inclusionOdds: nil,
                      reportedHeight: nil, observedAt: observedAt)
        case .notFound:
            self.init(kind: .notFound, message: nil, position: nil, inclusionOdds: nil,
                      reportedHeight: nil, observedAt: observedAt)
        }
    }
}

/// Why a provider refused. `policy` separates a compliance or standardness
/// refusal from a fee problem, because only the latter is fixed by bumping.
public struct SubmissionRejection: Codable, Equatable, Sendable {
    public let reason: String
    public let policy: Bool
    public let observedAt: Date

    public init(reason: String, policy: Bool, observedAt: Date) {
        self.reason = reason
        self.policy = policy
        self.observedAt = observedAt
    }
}

public struct SubmissionReceipt: Codable, Equatable, Sendable, Identifiable {
    public struct TimelineEntry: Codable, Equatable, Sendable {
        public let state: SubmissionState
        public let at: Date
    }

    public var id: Data { txid }

    public let txid: Data
    public let origin: SubmissionOrigin
    /// Idempotency and audit handle. Carries nothing about the user.
    public let requestID: UUID
    public private(set) var route: SubmissionRoute
    public private(set) var routeHistory: [RouteApproval]
    public private(set) var state: SubmissionState
    public private(set) var timeline: [TimelineEntry]
    public internal(set) var submittedAt: Date?
    public internal(set) var lastPolledAt: Date?
    public internal(set) var nextPollAt: Date?
    public internal(set) var pollAttempt: Int
    public internal(set) var submitAttempt: Int
    public internal(set) var nextSubmitAt: Date?
    public internal(set) var providerStatus: ProviderStatusSnapshot?
    public internal(set) var rejection: SubmissionRejection?
    /// The most recent transport failure, for the receipt view. Never a
    /// credential: `MinerClientError` messages are written without one.
    public internal(set) var lastError: String?
    public internal(set) var replacedBy: Data?
    public internal(set) var replaces: Data?
    /// For a package submission, every txid that went with this one.
    public internal(set) var packageTxids: [Data]?
    /// Confirmation tombstone, mirroring `TxBroadcaster` (#157): held for the
    /// reorg horizon so a disconnected block can put the receipt back in flight.
    public internal(set) var confirmedAtHeight: UInt32?
    public let feeRateSatPerVByte: Double?
    /// Kept for every route so a re-route never has to go looking for the
    /// bytes. Withdrawn from the UI once confirmed, as `TxBroadcaster` does.
    public let rawTransaction: Data

    public init(txid: Data, origin: SubmissionOrigin, route: SubmissionRoute,
                feeRateSatPerVByte: Double?, rawTransaction: Data, at now: Date,
                requestID: UUID = UUID())
    {
        self.txid = txid
        self.origin = origin
        self.requestID = requestID
        self.route = route
        routeHistory = []
        state = .constructed
        timeline = [TimelineEntry(state: .constructed, at: now)]
        pollAttempt = 0
        submitAttempt = 0
        self.feeRateSatPerVByte = feeRateSatPerVByte
        self.rawTransaction = rawTransaction
    }

    public var createdAt: Date { timeline.first?.at ?? .distantPast }

    /// Whether the miner half of this route is still waiting on a schedule.
    public var isDeliveryUnconfirmed: Bool {
        state == .submitted && nextSubmitAt == nil && submitAttempt > 0
    }

    /// The states from which the user may pick another route. A relayed
    /// transaction is public already and needs no second route; a terminal
    /// receipt has nothing left to route.
    public var canReroute: Bool {
        switch state {
        case .constructed, .rejected, .accepted: true
        case .submitted: isDeliveryUnconfirmed
        case .relayed, .replaced, .confirmed, .abandoned: false
        }
    }

    // MARK: - Mutation (coordinator only)

    mutating func transition(to next: SubmissionState, at now: Date) throws {
        guard SubmissionState.allows(state, to: next) else {
            throw SubmissionError.illegalTransition(from: state, to: next)
        }
        state = next
        timeline.append(TimelineEntry(state: next, at: now))
    }

    /// The reorg edge: not a transition, a restoration. The receipt returns
    /// to the last state before it confirmed, and its timeline says so.
    mutating func revertConfirmation(at now: Date) {
        guard state == .confirmed else { return }
        let previous = timeline.last(where: { $0.state != .confirmed })?.state ?? .constructed
        confirmedAtHeight = nil
        state = previous
        timeline.append(TimelineEntry(state: previous, at: now))
    }

    mutating func recordRoute(_ approval: RouteApproval) {
        routeHistory.append(approval)
        route = approval.to
    }
}

public enum SubmissionError: LocalizedError, Equatable, Sendable {
    case stopped
    case relayUnavailable
    case malformedTransaction(String)
    case unknownTransaction
    case illegalTransition(from: SubmissionState, to: SubmissionState)
    case notReroutable(SubmissionState)
    case providerUnavailable(MinerProviderID, reason: String)
    case duplicateSubmission(route: SubmissionRoute)
    case packageUnsupported(SubmissionRoute)

    public var errorDescription: String? {
        switch self {
        case .stopped:
            "This submission session has stopped. Reconnect before changing submission state."
        case .relayUnavailable:
            "The peer relay is not running. Nothing was sent."
        case let .malformedTransaction(reason):
            "The signed transaction could not be read (\(reason)). Nothing was sent."
        case .unknownTransaction:
            "Winnow has no submission record for this transaction."
        case let .illegalTransition(from, to):
            "A submission cannot move from \(from.rawValue) to \(to.rawValue)."
        case let .notReroutable(state):
            "A \(state.rawValue) submission cannot be routed again."
        case let .providerUnavailable(provider, reason):
            "\(provider.rawValue) is not available: \(reason). Nothing was sent."
        case let .duplicateSubmission(route):
            "This transaction already has a submission via \(route.label)."
        case let .packageUnsupported(route):
            "\(route.label) cannot submit a package of transactions."
        }
    }
}
