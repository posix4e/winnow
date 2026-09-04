import Foundation

/// Identifies a direct-submission provider in receipts and settings. Stable
/// strings, never display names: a receipt written today must still name its
/// provider after the display name changes.
public struct MinerProviderID: RawRepresentable, Hashable, Codable, Sendable,
    CustomStringConvertible
{
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }
    public var description: String { rawValue }

    /// MARA Slipstream (https://slipstream.mara.com), mainnet only.
    public static let slipstream = MinerProviderID(rawValue: "slipstream")
    /// Any Bitcoin Core node reachable over JSON-RPC: the user's own, or one
    /// a miner exposes to a customer.
    public static let coreRPC = MinerProviderID(rawValue: "core-rpc")
}

/// One or more signed transactions, topologically sorted with every parent
/// before its child. A single transaction is a package of one. Multi-parent
/// packages are representable but nothing in Winnow builds them yet.
public struct SubmissionPackage: Equatable, Sendable {
    public let rawTransactions: [Data]

    public init(rawTransactions: [Data]) {
        self.rawTransactions = rawTransactions
    }

    public init(_ rawTransaction: Data) {
        rawTransactions = [rawTransaction]
    }

    public var isSingle: Bool { rawTransactions.count == 1 }
}

/// What a provider's API can do. Checked before offering a feature in the UI
/// rather than discovered by a failed request.
public struct MinerCapabilities: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    /// Accepts a multi-transaction package in one request.
    public static let packages = MinerCapabilities(rawValue: 1 << 0)
    /// Reports the status of a submitted transaction by txid.
    public static let statusByTxid = MinerCapabilities(rawValue: 1 << 1)
    /// Publishes a minimum submission fee rate.
    public static let rates = MinerCapabilities(rawValue: 1 << 2)
    /// Can validate a transaction without admitting it.
    public static let mempoolTest = MinerCapabilities(rawValue: 1 << 3)
}

/// The provider's answer to a submission, read from the response body rather
/// than the HTTP status line: at least one provider answers 200 with an error
/// envelope and 400 with the same shape.
public enum MinerSubmitOutcome: Equatable, Sendable {
    /// The provider admitted the transaction(s).
    case accepted(txids: [Data], providerMessage: String?)
    /// The provider already had them — an idempotent resubmit after a lost
    /// response, which counts as accepted.
    case alreadyKnown(txids: [Data])
    /// The provider refused. `policy` distinguishes a compliance or
    /// standardness refusal from a fee problem, because only one of those is
    /// fixed by bumping the fee.
    case rejected(reason: String, policy: Bool)
}

/// What a provider reports about a transaction it was given. **Advisory
/// only**: Winnow treats a transaction as confirmed when its own block path
/// sees it in a verified block, never because a provider said so.
public enum MinerReportedStatus: Equatable, Sendable {
    case pending(position: Int?, inclusionOdds: String?, message: String?)
    case confirmed(height: UInt32, blockHash: Data?)
    case rejected(reason: String)
    case notFound
}

/// A provider's published fee expectations. Displayed next to the reviewed
/// rate and never enforced locally: a quote fetched a minute ago is less
/// authoritative than the provider's answer to the actual submission.
public struct MinerRateQuote: Equatable, Sendable {
    public let minimumSubmitSatPerVByte: Double
    public let marketSatPerVByte: Double?
    public let premiumMultiplier: Double?
    public let fetchedAt: Date

    public init(minimumSubmitSatPerVByte: Double, marketSatPerVByte: Double?,
                premiumMultiplier: Double?, fetchedAt: Date)
    {
        self.minimumSubmitSatPerVByte = minimumSubmitSatPerVByte
        self.marketSatPerVByte = marketSatPerVByte
        self.premiumMultiplier = premiumMultiplier
        self.fetchedAt = fetchedAt
    }
}

/// The settings screen's `Check` result. Fetching it is a disclosure (the
/// provider learns an IP address and a timestamp), so it happens on a tap and
/// never automatically.
public struct MinerHealth: Equatable, Sendable {
    public let reachable: Bool
    public let height: UInt32?
    public let floorSatPerVByte: Double?
    public let version: String?

    public init(reachable: Bool, height: UInt32?, floorSatPerVByte: Double?, version: String?) {
        self.reachable = reachable
        self.height = height
        self.floorSatPerVByte = floorSatPerVByte
        self.version = version
    }
}

/// What every direct-submission provider speaks, whatever its wire format.
///
/// Implementations are wire-level and carry no policy: they do not decide
/// whether to fall back, retry, or relay to peers, and they never touch
/// wallet state. Constructing one performs no request.
public protocol DirectMinerClient: Sendable {
    var providerID: MinerProviderID { get }
    var capabilities: MinerCapabilities { get }
    /// The host named in warning copy. Never the credential.
    var endpointHost: String { get }

    func submit(_ package: SubmissionPackage) async throws -> MinerSubmitOutcome
    func status(txid: Data) async throws -> MinerReportedStatus
    func rates() async throws -> MinerRateQuote?
    func health() async throws -> MinerHealth
}

/// Transport and shape failures, distinct from a provider's decision (which
/// is a `MinerSubmitOutcome`). Every message is written for the person
/// reading it, and none can carry a credential: the client truncates and
/// sanitises anything echoed from a response before it gets here.
public enum MinerClientError: LocalizedError, Equatable, Sendable {
    case unreachable(host: String)
    case httpStatus(Int)
    case unexpectedResponse(shape: String)
    case credentialRejected
    case rateLimited(retryAfterSeconds: Int?)
    case packageUnsupported(minimum: Int, maximum: Int)

    public var errorDescription: String? {
        switch self {
        case let .unreachable(host):
            "\(host) could not be reached. Delivery is unconfirmed; the transaction is still held and can be submitted again."
        case let .httpStatus(code):
            "The provider answered with HTTP \(code) and no readable result. Delivery is unconfirmed; the transaction is still held."
        case let .unexpectedResponse(shape):
            "The provider's API answered in a shape Winnow does not recognise (\(shape)). The API may have changed; update Winnow before relying on this route."
        case .credentialRejected:
            "The provider rejected the stored credential. Check it in Settings."
        case let .rateLimited(seconds):
            if let seconds {
                "The provider is rate-limiting requests. Winnow will try again in \(seconds) seconds."
            } else {
                "The provider is rate-limiting requests. Winnow will try again shortly."
            }
        case let .packageUnsupported(minimum, maximum):
            "This provider accepts packages of \(minimum) to \(maximum) transactions."
        }
    }
}
