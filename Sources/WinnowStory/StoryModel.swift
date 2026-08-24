import Foundation

public enum StoryModelError: LocalizedError, Equatable {
    case invalidRunID(String)
    case runExists(String)
    case runMissing(String)
    case unsupportedVersion(Int)
    case invalidTransition(String)
    case unsafeArtifact(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidRunID(value): "Invalid run name “\(value)”; use letters, numbers, dots, dashes, or underscores."
        case let .runExists(value): "Story run “\(value)” already exists; use resume instead."
        case let .runMissing(value): "Story run “\(value)” does not exist; use start first."
        case let .unsupportedVersion(version): "Story state version \(version) is not supported."
        case let .invalidTransition(reason): "Invalid checkpoint transition: \(reason)"
        case let .unsafeArtifact(reason): "Publication stopped because an artifact may contain a secret: \(reason)"
        }
    }
}

public struct StoryPersona: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let name: String
    public let organization: String?
    public let role: String
    public let themeName: String
    public let themeHex: String

    public init(id: String, name: String, organization: String? = nil, role: String,
                themeName: String, themeHex: String) {
        self.id = id
        self.name = name
        self.organization = organization
        self.role = role
        self.themeName = themeName
        self.themeHex = themeHex
    }

    public static let cast: [StoryPersona] = [
        .init(id: "sofia", name: "Sofía Cruz", organization: "Brisa Café",
              role: "shop owner · single-signature hot wallet", themeName: "sunrise amber", themeHex: "#E59B3A"),
        .init(id: "lina", name: "Lina Vega", role: "privacy-minded customer",
              themeName: "violet night", themeHex: "#6F5BD3"),
        .init(id: "elena", name: "Elena Rivera", role: "Sofía’s family steward · cold-vault personal key",
              themeName: "heirloom blue", themeHex: "#315A8A"),
        .init(id: "leo", name: "Leo Santos", organization: "Harbor Exchange",
              role: "exchange custodian", themeName: "custody cobalt", themeHex: "#356FC4"),
        .init(id: "marina", name: "Marina Ortiz", organization: "Ceiba Trust",
              role: "trust officer · next-of-kin authentication", themeName: "trust sage", themeHex: "#62896B"),
        .init(id: "mateo", name: "Mateo Rivera", role: "next generation",
              themeName: "reserve teal", themeHex: "#2E8B88"),
    ]
}

public enum StoryCheckpoint: String, Codable, CaseIterable, Sendable {
    public static let interfaceVersion = 1

    case preflight
    case sofiaOnboarding = "sofia-onboarding"
    case customerFunding = "customer-funding"
    case supplierRBF = "supplier-rbf"
    case inheritanceVault = "inheritance-vault"
    case jointReserve = "joint-reserve"
    case replacementPhone = "replacement-phone"
    case privacyTour = "privacy-tour"
    case publish

    public var title: String {
        switch self {
        case .preflight: "Preflight and public peers"
        case .sofiaOnboarding: "Sofía opens Brisa Café’s wallet"
        case .customerFunding: "First customer payment"
        case .supplierRBF: "Supplier payment and fee replacement"
        case .inheritanceVault: "Brisa Café’s Rivera cold reserve"
        case .jointReserve: "Rivera joint reserve"
        case .replacementPhone: "Backup and replacement phone"
        case .privacyTour: "Trust and privacy tour"
        case .publish: "Finish and publish"
        }
    }

    public var primaryPersonaID: String {
        switch self {
        case .inheritanceVault, .jointReserve: "elena"
        default: "sofia"
        }
    }

    public var instruction: String {
        switch self {
        case .preflight:
            "Confirm the app builds, the simulator boots, and Winnow connects to public signet peers. No local Bitcoin node is used."
        case .sofiaOnboarding:
            "Create Sofía’s wallet, interrupt during backup, resume it, finish backup, and reach the empty Brisa Café wallet. Do not record recovery words."
        case .customerFunding:
            "Keep Receive open, fund the displayed address once, capture unconfirmed detection, then mark this checkpoint waiting until signet confirms it."
        case .supplierRBF:
            "Pay Lina’s standard address, capture review and relay, replace the fee immediately, and verify the replacement confirms."
        case .inheritanceVault:
            "Sweep Brisa Café savings from Sofía’s hot wallet into the Elena/Leo/Marina 2-of-3 cold reserve. Return operating money with Elena+Leo, then exercise Leo+Marina recovery toward the family reserve."
        case .jointReserve:
            "Fund Elena and Mateo’s 2-of-2 MuSig2 reserve from the preceding cold/recovery flow, complete nonce and signature rounds without leaving the signing screen, then confirm."
        case .replacementPhone:
            "Export safely, import into Sofía’s replacement-phone namespace, verify forward history and balance."
        case .privacyTour:
            "Capture public peers, server/privacy warnings, manual-peer controls, and bundled design papers without switching to mainnet."
        case .publish:
            "Review every clip for secrets, finish the run, and publish only the redacted report, manifest, screenshots, and approved clips."
        }
    }
}

/// Versioned public facts emitted by Winnow while `WINNOW_E2E=1`.
/// Secret-bearing values are intentionally not representable as dedicated
/// fields; publication still runs the redaction gate over serialized events.
public struct StoryEvent: Codable, Sendable, Equatable {
    public static let currentVersion = 1

    public let version: Int
    public let timestamp: Date
    public let name: String
    public let persona: String?
    public let fields: [String: String]

    public init(timestamp: Date = Date(), name: String, persona: String? = nil,
                fields: [String: String] = [:]) {
        version = Self.currentVersion
        self.timestamp = timestamp
        self.name = name
        self.persona = persona
        self.fields = fields
    }
}

public enum StoryCheckpointStatus: String, Codable, Sendable {
    case pending
    case active
    case waiting
    /// Intentionally postponed so later independent checkpoints can run.
    /// It remains incomplete and therefore still blocks final publication.
    case deferred
    case passed
    case failed
}

public struct StoryCheckpointRecord: Codable, Sendable, Equatable {
    public var status: StoryCheckpointStatus
    public var startedAt: Date?
    public var completedAt: Date?
    public var note: String?
    public var transactionIDs: [String]
    public var confirmationHeights: [UInt32]

    public init(status: StoryCheckpointStatus = .pending, startedAt: Date? = nil,
                completedAt: Date? = nil, note: String? = nil,
                transactionIDs: [String] = [], confirmationHeights: [UInt32] = []) {
        self.status = status
        self.startedAt = startedAt
        self.completedAt = completedAt
        self.note = note
        self.transactionIDs = transactionIDs
        self.confirmationHeights = confirmationHeights
    }
}

public struct StoryEnvironment: Codable, Sendable, Equatable {
    public var gitCommit: String
    public var swiftVersion: String
    public var xcodeVersion: String
    public var simulatorUDID: String?
    public var simulatorName: String?
    public var simulatorRuntime: String?
    public var gitDirty: Bool?

    public init(gitCommit: String, swiftVersion: String, xcodeVersion: String,
                simulatorUDID: String? = nil, simulatorName: String? = nil,
                simulatorRuntime: String? = nil, gitDirty: Bool? = nil) {
        self.gitCommit = gitCommit
        self.swiftVersion = swiftVersion
        self.xcodeVersion = xcodeVersion
        self.simulatorUDID = simulatorUDID
        self.simulatorName = simulatorName
        self.simulatorRuntime = simulatorRuntime
        self.gitDirty = gitDirty
    }
}

public struct StorySecretIdentity: Codable, Sendable, Equatable {
    public let personaID: String
    public let seedHex: String
}

public enum StoryTransactionEvidenceStatus: String, Codable, Sendable {
    case observed
    case confirmationClaimed
    case verified
    case failed
}

/// A public, versioned proof record for one story transaction. It intentionally
/// contains only chain-public facts. Parent txids are extracted from the
/// merkle-authenticated transaction after block verification and let the final
/// audit prove that the hot wallet, cold reserve, recovery, and MuSig2 scenes
/// form one connected money trail.
public struct StoryTransactionEvidence: Codable, Sendable, Equatable, Identifiable {
    public static let currentVersion = 1

    public var version: Int
    public var label: String
    public var checkpoint: StoryCheckpoint
    public var personaID: String
    public var txid: String
    public var status: StoryTransactionEvidenceStatus
    public var firstObservedAt: Date
    public var confirmationHeight: UInt32?
    public var blockHash: String?
    public var parentTransactionIDs: [String]
    public var verifiedAt: Date?
    public var failure: String?

    public var id: String { "\(checkpoint.rawValue):\(txid)" }

    public init(label: String, checkpoint: StoryCheckpoint, personaID: String,
                txid: String, status: StoryTransactionEvidenceStatus = .observed,
                firstObservedAt: Date = Date(), confirmationHeight: UInt32? = nil,
                blockHash: String? = nil, parentTransactionIDs: [String] = [],
                verifiedAt: Date? = nil, failure: String? = nil) {
        version = Self.currentVersion
        self.label = label
        self.checkpoint = checkpoint
        self.personaID = personaID
        self.txid = txid
        self.status = status
        self.firstObservedAt = firstObservedAt
        self.confirmationHeight = confirmationHeight
        self.blockHash = blockHash
        self.parentTransactionIDs = parentTransactionIDs
        self.verifiedAt = verifiedAt
        self.failure = failure
    }
}

/// A protected, resumable companion-wallet send. The raw transaction and
/// BIP352 tweak point are public chain data, but they stay in private run
/// state until the transaction is explicitly promoted into story evidence.
/// Saving the prepared transaction before relay makes retries idempotent: a
/// resumed command re-announces these exact bytes instead of selecting coins
/// or randomizing change placement again.
public struct StoryCompanionTransaction: Codable, Sendable, Equatable {
    public static let currentVersion = 2

    public var version: Int
    public var label: String
    public var personaID: String
    public var txid: String
    public var rawTransaction: String
    public var amount: Int64
    public var fee: Int64
    public var relayPeerCount: Int
    /// The transaction this one fee-replaces, when it is a prepared BIP125
    /// replacement. Optional so protected v1 run state remains readable.
    public var replaces: String?

    public init(label: String, personaID: String, txid: String,
                rawTransaction: String,
                amount: Int64, fee: Int64, relayPeerCount: Int = 0,
                replaces: String? = nil) {
        version = Self.currentVersion
        self.label = label
        self.personaID = personaID
        self.txid = txid
        self.rawTransaction = rawTransaction
        self.amount = amount
        self.fee = fee
        self.relayPeerCount = relayPeerCount
        self.replaces = replaces
    }
}

/// A stable fingerprint of one screenshot or recording that a person reviewed.
/// Paths are relative to the publishable artifacts directory and contain no
/// wallet data. Recomputing the inventory at finish time prevents media from
/// being added or changed after approval.
public struct StoryMediaArtifact: Codable, Sendable, Equatable, Comparable {
    public let path: String
    public let byteCount: Int64
    public let sha256: String

    public init(path: String, byteCount: Int64, sha256: String) {
        self.path = path
        self.byteCount = byteCount
        self.sha256 = sha256
    }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.path < rhs.path }
}

/// Human assertion recorded only after every image and every video frame has
/// been inspected. It is safe to publish: it contains hashes, not media or
/// wallet secrets.
public struct StoryMediaReview: Codable, Sendable, Equatable {
    public static let currentVersion = 1

    public let version: Int
    public let reviewedAt: Date
    public let artifacts: [StoryMediaArtifact]

    public init(reviewedAt: Date = Date(), artifacts: [StoryMediaArtifact]) {
        version = Self.currentVersion
        self.reviewedAt = reviewedAt
        self.artifacts = artifacts.sorted()
    }
}

public struct StoryRunState: Codable, Sendable, Equatable {
    public static let currentVersion = 5
    public static let currentScenario = "whole-app-public-signet-v5"

    public var version: Int
    public var scenario: String
    public var runID: String
    public var createdAt: Date
    public var updatedAt: Date
    public var environment: StoryEnvironment
    public var personas: [StoryPersona]
    public var secrets: [StorySecretIdentity]
    public var checkpoints: [String: StoryCheckpointRecord]
    public var activeCheckpoint: StoryCheckpoint
    public var recordingPID: Int32?
    public var recordingStage: String?
    public var musigSecretNonces: [String: String]
    /// Exact public PSBTs for Mateo's current/completed nonce session. Keeping
    /// these beside the protected nonces makes both CLI rounds idempotent:
    /// resume returns the same bytes instead of generating fresh nonces or
    /// attempting to sign twice.
    public var musigNoncePSBT: String?
    public var musigPartialPSBT: String?
    public var transactionEvidence: [StoryTransactionEvidence]?
    public var companionTransactions: [String: StoryCompanionTransaction]?
    public var mediaReview: StoryMediaReview?

    public init(runID: String, environment: StoryEnvironment, secrets: [StorySecretIdentity],
                now: Date = Date()) {
        version = Self.currentVersion
        scenario = Self.currentScenario
        self.runID = runID
        createdAt = now
        updatedAt = now
        self.environment = environment
        personas = StoryPersona.cast
        self.secrets = secrets
        checkpoints = Dictionary(uniqueKeysWithValues: StoryCheckpoint.allCases.map {
            ($0.rawValue, StoryCheckpointRecord())
        })
        activeCheckpoint = .preflight
        recordingPID = nil
        recordingStage = nil
        musigSecretNonces = [:]
        musigNoncePSBT = nil
        musigPartialPSBT = nil
        transactionEvidence = []
        companionTransactions = [:]
        mediaReview = nil
    }

    public mutating func transition(_ checkpoint: StoryCheckpoint, to status: StoryCheckpointStatus,
                                    note: String? = nil, txid: String? = nil,
                                    height: UInt32? = nil, label: String? = nil,
                                    personaID: String? = nil, now: Date = Date()) throws {
        var record = checkpoints[checkpoint.rawValue] ?? StoryCheckpointRecord()
        if record.status == .passed, status != .passed, checkpoint != .publish {
            throw StoryModelError.invalidTransition("\(checkpoint.rawValue) has already passed")
        }
        if record.startedAt == nil, status != .pending { record.startedAt = now }
        record.status = status
        if let note { record.note = note }
        if let txid, !record.transactionIDs.contains(txid) { record.transactionIDs.append(txid) }
        if let height, !record.confirmationHeights.contains(height) { record.confirmationHeights.append(height) }
        if let evidenceTxid = txid ?? (height == nil ? nil : record.transactionIDs.last) {
            try upsertTransactionEvidence(txid: evidenceTxid, checkpoint: checkpoint,
                                          height: height, label: label,
                                          personaID: personaID, now: now)
        }
        if status == .passed { record.completedAt = now }
        checkpoints[checkpoint.rawValue] = record
        activeCheckpoint = StoryCheckpoint.allCases.first {
            let status = checkpoints[$0.rawValue]?.status
            return status != .passed && status != .deferred
        } ?? .publish
        if activeCheckpoint != checkpoint {
            var next = checkpoints[activeCheckpoint.rawValue] ?? StoryCheckpointRecord()
            if next.status == .pending {
                next.status = .active
                next.startedAt = next.startedAt ?? now
                checkpoints[activeCheckpoint.rawValue] = next
            }
        }
        updatedAt = now
    }

    public mutating func markTransactionVerified(txid: String, checkpoint: StoryCheckpoint,
                                                 height: UInt32, blockHash: String,
                                                 parentTransactionIDs: [String],
                                                 now: Date = Date()) throws {
        guard var values = transactionEvidence,
              let index = values.firstIndex(where: { $0.txid == txid && $0.checkpoint == checkpoint })
        else {
            throw StoryModelError.invalidTransition("no transaction evidence for \(txid)")
        }
        values[index].status = .verified
        values[index].confirmationHeight = height
        values[index].blockHash = blockHash
        values[index].parentTransactionIDs = parentTransactionIDs
        values[index].verifiedAt = now
        values[index].failure = nil
        transactionEvidence = values
        updatedAt = now
    }

    public mutating func markTransactionVerificationFailed(txid: String,
                                                           checkpoint: StoryCheckpoint,
                                                           reason: String) throws {
        guard var values = transactionEvidence,
              let index = values.firstIndex(where: { $0.txid == txid && $0.checkpoint == checkpoint })
        else {
            throw StoryModelError.invalidTransition("no transaction evidence for \(txid)")
        }
        values[index].status = .failed
        values[index].failure = reason
        transactionEvidence = values
        updatedAt = Date()
    }

    private mutating func upsertTransactionEvidence(txid: String, checkpoint: StoryCheckpoint,
                                                    height: UInt32?, label: String?,
                                                    personaID: String?, now: Date) throws {
        let normalized = txid.lowercased()
        guard normalized.count == 64, normalized.allSatisfy(\.isHexDigit) else {
            throw StoryModelError.invalidTransition("transaction IDs must be 32-byte hex")
        }
        var values = transactionEvidence ?? []
        if let index = values.firstIndex(where: { $0.txid == normalized && $0.checkpoint == checkpoint }) {
            if let height {
                values[index].confirmationHeight = height
                values[index].status = .confirmationClaimed
            }
            if let label { values[index].label = label }
            if let personaID { values[index].personaID = personaID }
            values[index].failure = nil
        } else {
            let defaultLabel = "\(checkpoint.rawValue)-\(values.filter { $0.checkpoint == checkpoint }.count + 1)"
            values.append(StoryTransactionEvidence(
                label: label ?? defaultLabel,
                checkpoint: checkpoint,
                personaID: personaID ?? checkpoint.primaryPersonaID,
                txid: normalized,
                status: height == nil ? .observed : .confirmationClaimed,
                firstObservedAt: now,
                confirmationHeight: height))
        }
        transactionEvidence = values
    }

    public static func validate(runID: String) throws {
        guard !runID.isEmpty, runID.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil else {
            throw StoryModelError.invalidRunID(runID)
        }
    }

    private static func stableHash(_ text: String) -> Int {
        text.utf8.reduce(2_166_136_261) { (value, byte) in
            Int((UInt32(truncatingIfNeeded: value) ^ UInt32(byte)) &* 16_777_619)
        }
    }
}

public struct StoryPublicManifest: Codable, Sendable, Equatable {
    public let version: Int
    public let scenario: String
    public let runID: String
    public let createdAt: Date
    public let finishedAt: Date
    public let environment: StoryEnvironment
    public let personas: [StoryPersona]
    public let checkpoints: [String: StoryCheckpointRecord]
    public let transactionEvidence: [StoryTransactionEvidence]
    public let humanMediaReviewRequired: Bool
    public let humanMediaReview: StoryMediaReview?

    public init(state: StoryRunState, finishedAt: Date = Date()) {
        version = state.version
        scenario = state.scenario
        runID = state.runID
        createdAt = state.createdAt
        self.finishedAt = finishedAt
        environment = state.environment
        personas = state.personas
        checkpoints = state.checkpoints
        transactionEvidence = state.transactionEvidence ?? []
        humanMediaReviewRequired = true
        humanMediaReview = state.mediaReview
    }
}

/// Preferred public interface name. The longer legacy name remains source
/// compatible with the first prototype.
public typealias StoryManifest = StoryPublicManifest

public struct StoryFailureSummary: Codable, Sendable, Equatable {
    public let version: Int
    public let generatedAt: Date
    public let scenario: String
    public let runID: String
    public let activeCheckpoint: StoryCheckpoint
    public let failedCheckpoint: StoryCheckpoint
    public let record: StoryCheckpointRecord
    public let environment: StoryEnvironment
    public let transactionEvidence: [StoryTransactionEvidence]

    public init(state: StoryRunState, checkpoint: StoryCheckpoint, now: Date = Date()) {
        version = 1
        generatedAt = now
        scenario = state.scenario
        runID = state.runID
        activeCheckpoint = state.activeCheckpoint
        failedCheckpoint = checkpoint
        record = state.checkpoints[checkpoint.rawValue] ?? StoryCheckpointRecord()
        environment = state.environment
        transactionEvidence = state.transactionEvidence ?? []
    }
}
