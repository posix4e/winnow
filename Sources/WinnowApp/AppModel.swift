import VaultKit
import WalletCore
import Foundation
import LocalAuthentication
import SwiftUI
import UIKit

@MainActor
protocol DeviceAuthenticating {
    func authenticate(reason: String) async throws
}

/// Device-owner authentication through LocalAuthentication. The check that
/// passes is handed to `keychain`, so the Keychain read the operation goes
/// on to make reuses it instead of asking a second time (`KeychainStore`).
struct LocalDeviceAuthenticator: DeviceAuthenticating {
    let keychain: KeychainAuthentication

    func authenticate(reason: String) async throws {
        let context = LAContext()
        var unavailable: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &unavailable) else {
            throw AppModel.AppError.deviceAuthUnavailable
        }
        let passed = try await context.evaluatePolicy(
            .deviceOwnerAuthentication, localizedReason: reason)
        guard passed else { throw AppModel.AppError.deviceAuthFailed }
        keychain.grant(context)
    }
}

/// The one app model: owns the wallet, the P2P sync stack and the vault
/// store, and drives sync-while-active (docs/read-side.md: the read path is
/// BIP157/158 compact filters over P2P; nothing runs in the background, so
/// the app requests no background modes).
@MainActor
@Observable
final class AppModel {
    enum Stage: Equatable {
        case loading
        case onboarding
        case ready
        case storageDamaged(String)
    }

    enum PersistedWalletOpenResult {
        case missing
        case opened(Wallet)
        case damaged(String)
    }

    enum AppError: LocalizedError {
        case noWallet
        case noStack
        case noPeers
        case mnemonicUnavailable
        case rootKeyUnavailable
        case feeDecisionRequired(rate: Double, floor: Double)
        case invalidPeer(String)
        case wrongNetwork(String)
        case duplicateVault
        case sendReviewChanged
        case storageDamaged(String)
        case deviceAuthUnavailable
        case deviceAuthFailed
        case spendAlreadyInFlight
        /// The transaction was broadcast but the vault's coins could not be
        /// updated; carries the txid so the user has the receipt.
        case vaultSpendNotRecorded(txid: Data, reason: String)
        /// No storage directory, so a rollback target cannot be recorded.
        case noStorage
        case paymentDetailsUnavailable
        case personCannotBePaid
        case personCannotCoOwn(String)

        var errorDescription: String? {
            switch self {
            // MARK: Wallet
            case .noWallet: "No wallet is open."
            case .mnemonicUnavailable: "The new wallet's mnemonic could not be read back from the Keychain."
            case .rootKeyUnavailable: "This wallet's signing key is limited to its own account and cannot authorize this operation."
            case .duplicateVault: "A vault with this descriptor already exists."
            case let .storageDamaged(message): message
            case .noStorage: "Winnow could not reach its storage, so a chain reorganisation could not be recorded. Syncing has stopped rather than continue on stale data."
            // MARK: Payments
            case .paymentDetailsUnavailable: "Payment details aren’t available on this phone."
            case .personCannotBePaid: "This person has no pay-to key or address yet. Ask them for their Winnow card."
            case let .personCannotCoOwn(name): "\(name) has no signer key yet. Ask them for their Winnow card before creating savings together."
            case let .feeDecisionRequired(rate, floor):
                "Connected peers require at least \(floor) sat/vB to relay this payment, above the selected \(rate) sat/vB. "
                    + "Enter an explicit rate of at least \(floor) sat/vB, or wait for the floor to change. "
                    + "Winnow will not raise an automatic rate that far on its own."
            case .sendReviewChanged: "The available coins, fee, or change changed. Review the payment again before signing."
            case let .vaultSpendNotRecorded(txid, reason):
                "The payment was sent (\(txid.displayHex)) but this account's coins could not be updated (\(reason)). "
                    + "Reopen the account before spending from it again."
            // MARK: Connection
            case .noStack: "The sync stack is not running."
            case .noPeers: "No peers reachable. Check the network connection or add a manual peer in Settings."
            case let .invalidPeer(text): "Invalid peer “\(text)” — use host:port."
            case let .wrongNetwork(network): "This bundle is for \(network); switch the network in Settings first."
            // MARK: Authorization
            case .deviceAuthUnavailable: "Set a device passcode first — sensitive wallet actions require device authentication."
            case .deviceAuthFailed: "Device authentication failed."
            case .spendAlreadyInFlight: "Another payment is already being signed and broadcast. Wait for it to finish."
            }
        }
    }

    /// UI-facing snapshot of wallet + sync state (refreshed after syncs and
    /// mutations; the wallet itself is an actor).
    struct Status: Equatable {
        var balance: Int64 = 0
        var utxoCount = 0
        var history: [HistoryEntry] = []
        var feeBumpableTxids: [Data] = []
        var observedFeeRates: [Double] = []
        var peerCount = 0
        var tipHeight: UInt32 = 0
        var nextScanHeight: UInt32 = 0
        var syncing = false
        var lastSyncError: String?
        /// A damaged relay store was set aside so sync could continue (#150).
        /// Distinct from `lastSyncError`: sync is fine, relay lost its queue.
        var relayStoreQuarantined: String?
        /// BIP133 feefilter floor across connected peers (sat/vB).
        var feeFloorSatPerVByte: Double?
    }

    /// The per-network backend stack: peer pool, header chain, filter sync
    /// (created once a wallet exists — its start height is the wallet's) and
    /// the transaction broadcaster.
    struct SyncStack {
        let pool: PeerPool
        let chain: HeaderChain
        var filters: FilterSync?
        let broadcaster: TxBroadcaster
    }

    /// Coarse-grained live sync phase for the UI (polled from the actors once
    /// a second while active; drives the status line in Home/Onboarding).
    enum SyncPhase: Equatable {
        case idle
        case connecting(connected: Int, target: Int)
        case headers(synced: UInt32, tipEstimate: UInt32)
        case filters(scanned: UInt32, tip: UInt32)
        case synced
        /// Peer discovery ran out of candidates with zero connections.
        case peerDiscoveryFailed

        /// Whether a transaction built right now would stamp an `nLockTime`
        /// from a header tip that may lag the network's (#151).
        ///
        /// Core stamps the current height on ~90% of transactions and never
        /// reaches back more than 100 blocks, so a locktime far below the
        /// confirming block is a fingerprint Core essentially never produces —
        /// it discloses that the sender was mid-sync, and by how much. The
        /// lag exists only while the *header* chain is behind: in `.filters`
        /// the headers are already at the network tip and only the scan
        /// trails, and in `.synced` a periodic sync keeps the tip within the
        /// couple of blocks Core's own distribution covers. Everything
        /// earlier — idle, connecting, mid-header-sync, discovery failure —
        /// can be arbitrarily far behind, and honestly saying so at review
        /// time was the behaviour #151 settled on: the send proceeds, and the
        /// disclosure is informed rather than silent.
        var headerTipMayLagNetwork: Bool {
            switch self {
            case .filters, .synced: false
            case .idle, .connecting, .headers, .peerDiscoveryFailed: true
            }
        }

        /// The one line a beginner reads. Everything but "reachable" and
        /// "done" is syncing: `.idle` is transient while foregrounded, and a
        /// running scan is progress, not a state to name.
        enum Summary: Equatable {
            case syncing
            case synced
            case peersUnavailable
        }

        static func summary(phase: SyncPhase, syncing: Bool) -> Summary {
            switch phase {
            case .peerDiscoveryFailed: .peersUnavailable
            case .synced where !syncing: .synced
            case .idle, .connecting, .headers, .filters, .synced: .syncing
            }
        }


        /// Where the filter scan has actually reached, or `nil` when there is
        /// no honest number to give.
        ///
        /// Outside a running scan the only source is the committed wallet
        /// snapshot, and for a wallet that has never scanned that is zeroed --
        /// which is where "block 0 of 0" came from. #87 fixed the phase the
        /// report came from; the same string was still reachable in every
        /// other phase (#99), because `status` is refreshed by events rather
        /// than by the once-a-second phase poll.
        ///
        /// Rendering a zero as progress is worse than rendering nothing: the
        /// status line above already says what the wallet is doing, so the
        /// screen is not silent when this returns nil.
        func filterScanText(fallbackScanned: UInt32, fallbackTip: UInt32) -> String? {
            let progress: (scanned: UInt32, tip: UInt32)
            switch self {
            case let .filters(scanned, tip):
                progress = (scanned, tip)
            case .synced:
                // The scan finished, so the snapshot is the truth -- and it is
                // the durable readout, since the status line above disappears
                // at .synced.
                progress = (fallbackScanned, fallbackTip)
            case .idle, .connecting, .headers, .peerDiscoveryFailed:
                // No scan is running, so the snapshot is either zeroed (never
                // scanned) or a completed scan from a previous launch. Neither
                // is this scan's position. `.idle` means there is no stack at
                // all, so there is nothing to report by construction.
                return nil
            }
            // A tip of zero is the same absence one step further in: the chain
            // height has not been read yet, so there is no denominator.
            guard progress.tip > 0 else { return nil }
            return "block \(min(progress.scanned, progress.tip).formatted()) of \(progress.tip.formatted())"
        }
    }

    /// One-line rendering of `syncPhase`; nil when there is nothing to show.
    var syncSummary: SyncPhase.Summary { SyncPhase.summary(phase: syncPhase, syncing: status.syncing) }

    /// What Simple mode shows under the balance. Advanced shows every error.
    var simpleSyncError: String? {
        Self.simpleSyncError(lastError: status.lastSyncError, transientError: transientSyncError,
                             failures: transientSyncFailures)
    }

    /// A peer dropping mid-scan is routine, and the next pass recovers on
    /// another peer, so one or two in a row stay quiet and a third is said
    /// in plain words. Any other error shows at once.
    static func simpleSyncError(lastError: String?, transientError: String?, failures: Int) -> String? {
        guard let lastError else { return nil }
        guard lastError == transientError else { return lastError }
        return failures >= 3 ? "Winnow keeps losing its connection to Bitcoin peers. It will keep trying." : nil
    }

    /// Failures of the link rather than of a peer's answers: the pool moves
    /// to another peer and the next pass usually succeeds.
    static func isTransientSyncError(_ error: any Error) -> Bool {
        switch error {
        case let peer as PeerError:
            return peer.isTransport
        case let sync as FilterSyncError:
            if case .peersCoolingDown = sync { return true }
            // The pool has not seated peers of enough classes yet; the next
            // pass asks again as the pool changes.
            if case .crossCheckUnavailable = sync { return true }
            return sync == .noPeers
        default:
            return false
        }
    }

    var syncStatusText: String? {
        switch syncPhase {
        case .idle, .synced:
            nil
        case let .connecting(connected, target):
            "Connecting to peers (\(connected) of \(target))…"
        case let .headers(synced, tipEstimate):
            "Headers \(synced.formatted()) of ~\(tipEstimate.formatted())"
        case let .filters(scanned, tip):
            "Filters \(min(scanned, tip).formatted()) of \(tip.formatted())"
        case .peerDiscoveryFailed:
            "Couldn't find filter-serving peers — check your connection."
        }
    }

    /// Opens a bounded mempool window (docs/read-side.md §2.8) on the pool.
    /// The caller owns the lifecycle: `start()` when the screen appears,
    /// `stop()` when it disappears or the app backgrounds. nil without a stack.
    func makeMempoolWindow(watchScripts: Set<Data>) -> MempoolWindow? {
        guard let stack else { return nil }
        return MempoolWindow(pool: stack.pool, watchScripts: watchScripts)
    }

    private(set) var stage: Stage = .loading
    private(set) var status = Status()
    private(set) var syncPhase: SyncPhase = .idle
    // Keep the derived savings cache current at each input, including local
    // mutations that do not trigger a network refresh.
    private(set) var vaults: [VaultRecord] = [] {
        didSet {
            recomputeSharedSavings()
            guard vaults != oldValue else { return }
            ownedVaultScripts = Set(vaults.flatMap { record in
                let vault = try? Vault(record.descriptor, network: network)
                let count = max(record.nextReceiveIndex, record.nextChangeIndex) + Wallet.gapLimit
                return (try? vault?.watchScripts(upTo: count)) ?? []
            })
        }
    }
    private var ownedVaultScripts: Set<Data> = []
    private(set) var people: [PersonRecord] = [] {
        didSet {
            recomputeSharedSavings()
            guard people != oldValue else { return }
            recipientByScript = people.reduce(into: [:]) { result, person in
                let scripts = try? person.payTo?.scripts(upTo: person.nextPaymentIndex + Wallet.gapLimit, network: network)
                for script in scripts ?? [] where result[script] == nil { result[script] = person }
            }
        }
    }
    private(set) var recipientByScript: [Data: PersonRecord] = [:]
    /// Txid display hex → person id, mirrored from the people store so a
    /// received payment can name its sender without an actor hop.
    private(set) var senderByTxid: [String: String] = [:]
    private(set) var sharedSavings: [SharedSavings] = []
    /// Notes about this wallet's own addresses, kept apart from people.
    private(set) var receiveAddressLabels: [Data: String] = [:]
    private(set) var receiveLabelStorageNotice: String?
    private var receiveLabelStore: ReceiveAddressLabelStore?
    /// Set when `people.json` could not be read. Shown in the recipient picker;
    /// the store refuses mutations meanwhile. Never blocks boot.
    private(set) var peopleStorageNotice: String?
    /// The wallet's own watched scripts, cached so a shared-savings review can
    /// label an output "pays you" without an actor hop.
    private(set) var ownWatchScripts: Set<Data> = []
    private(set) var wallet: Wallet?
    private(set) var stack: SyncStack?
    /// Copies of the wallet's id/descriptor for synchronous access (the Wallet
    /// actor's members need an await across the module boundary).
    private(set) var walletID: String? {
        didSet {
            if walletID != oldValue {
                receiveLabelStore = nil
                receiveAddressLabels = [:]
                receiveLabelStorageNotice = nil
            }
        }
    }
    private var walletDescriptor: Descriptor? {
        didSet { recomputeSharedSavings() }
    }

    /// Secrets (the BIP39 mnemonic) live in the Keychain, this device only,
    /// behind the Keychain's own user-presence check. E2E test mode (E2EMode)
    /// uses a separate Keychain service so test runs never touch a real
    /// wallet's secrets, and no user-presence check, since nobody is there.
    let keyStore: any KeyStore
    /// The device-owner check the sensitive action in progress passed, held
    /// for the Keychain read that follows it; dropped when that action ends
    /// and when the app leaves the screen.
    let keychainAuthentication = KeychainAuthentication()
    let vaultStore: VaultStore
    let peopleStore: PeopleStore
    let cloudBackups: CloudBackupController
    private let allowsCloudBackup: Bool
    private var cloudPreparationTask: Task<Void, Never>?
    private var cloudPreparationEpoch = UUID()
    private var attemptedCloudPreparation: Set<String> = []
    private(set) var cloudRestoreNotice: String?
    private let defaults: UserDefaults
    /// The HTTP client behind seed lookups and the consented
    /// explorer lookup. Suspending networking cancels it, so a request that
    /// was in flight fails rather than finishing in the background; the next
    /// activation makes a new one.
    private(set) var httpClient = RoutedHTTPClient()
    private(set) var gatewaySettings: PeerGatewaySettings
    private(set) var activePeerGateways = PeerGatewayConfiguration()
    private(set) var discoveringGateways = false
    private let discoverGateways: @Sendable () async -> PeerGatewayConfiguration
    private var gatewayDiscoveryTask: Task<PeerGatewayConfiguration, Never>?
    private var preparedGatewayGeneration: UInt64?
    /// Bumps on every suspend, network switch and rebuild. Async work reads
    /// it before starting and again after each await, and drops its result
    /// when the generation it started in is over.
    private(set) var networkGeneration: UInt64 = 0
    /// Set once, on the first launch after the Tor option was removed, for
    /// an installation that had Tor on: it is about to connect directly for
    /// the first time and is told so. Cleared when the notice is dismissed.
    var torRemovedNotice = false
    private var changingNetwork = false
    private var peersToAvoid: Set<PeerEndpoint> = []
    private let deviceAuthenticator: any DeviceAuthenticating

    /// Non-nil only when launched with WINNOW_E2E=1 (XCUITest runs).
    let e2e: E2EMode?

    // Settings (UserDefaults-persisted; see the mutating methods below).
    private(set) var network: BitcoinNetwork {
        didSet { recomputeSharedSavings() }
    }
    private(set) var manualPeers: [String] // "host:port"
    private(set) var esploraURLString: String
    private(set) var explorerProvider: ExplorerProvider

    /// The warned external block explorer. Presets cover the common sites;
    /// `custom` uses whatever Esplora-compatible URL the owner typed. It is
    /// contacted directly only on an explicit, warned tap — "Infer sender"
    /// on a received payment, or an opened link — never in the background.
    enum ExplorerProvider: String, CaseIterable {
        case blockstream
        case mempool
        case custom
    }
    /// Off by default: a fresh chain starts from the shipped checkpoint (#89).
    /// On means re-derive every block's work from block 0, which is what the
    /// app did before the checkpoint existed.
    private(set) var verifyFromGenesis: Bool
    /// Off by default. Gates the network picker and every other control a
    /// beginner should never have to read. Global, not per network: it is a
    /// statement about the user, not the chain.
    private(set) var advancedMode: Bool

    private var syncTask: Task<Void, Never>?
    private var phaseTask: Task<Void, Never>?
    private var broadcasterEventTask: Task<Void, Never>?
    private var isActive = false
    private var bootTask: Task<Void, Never>?
    /// A BGTask's scan. Foreground networking and a background check never
    /// run together: returning to the app cancels this before `activate()`.
    private var backgroundRun: Task<Bool, Never>?
    private var networkShutdown: Task<Void, Never>?
    private(set) var backgroundRunning = false
    /// When a scan last reached the tip, in the foreground or the background.
    private(set) var lastCompleteCheck: Date?
    /// Sync passes in a row that a dropped or slow peer ended, and the
    /// message the last one left. See `simpleSyncError`.
    private var transientSyncFailures = 0
    private var transientSyncError: String?
    private var buildingStack = false
    /// Prevents the E2E journal from repeating an identical wallet/vault
    /// snapshot every time SwiftUI asks for a refresh.
    private var lastE2ESnapshotFingerprint: String?
    private var lastE2EPeerFingerprint: String?

    enum DefaultsKey {
        static let network = "network"
        /// Peer and explorer settings are per network, the way storage
        /// already is. A signet node dialed first on mainnet spends the pool's
        /// opening attempts on a peer that rejects the handshake, and a signet
        /// explorer answers mainnet queries with confidently wrong data.
        /// See #81.
        static func manualPeers(_ network: BitcoinNetwork) -> String { "manualPeers.\(network.rawValue)" }
        static func lastCompleteCheck(_ network: BitcoinNetwork) -> String { "sync.lastComplete.\(network.rawValue)" }
        /// Whether Automatic routing last reached peers through Tor or I2P
        /// in the foreground. See `backgroundRoutingAllowed`.
        static let automaticUsedGateways = "peerGateways.automaticUsedGateways"
        static func esploraURL(_ network: BitcoinNetwork) -> String { "esploraURL.\(network.rawValue)" }
        static func explorerProvider(_ network: BitcoinNetwork) -> String { "explorerProvider.\(network.rawValue)" }
        /// The pre-#81 flat keys, migrated once into the active network.
        static let legacyManualPeers = "manualPeers"
        static let legacyEsploraURL = "esploraURL"
        /// The removed Tor option (0.6–0.7.0), cleared once at launch.
        static let legacyTorEnabled = "torEnabled"
        /// Deliberately global: a preference, not a chain-specific endpoint.
        static let verifyFromGenesis = "verifyFromGenesis"
        /// Deliberately global, like verifyFromGenesis.
        static let advancedMode = "advancedMode"
        /// The name on the card this wallet shares. Global: it is the user's.
        static let ownDisplayName = "ownDisplayName"
        /// Legacy phrase-checklist flag, cleared when opening an existing wallet.
        static func backupPending(_ walletID: String) -> String { "backupPending.\(walletID)" }
    }

    init(deviceAuthenticator: (any DeviceAuthenticating)? = nil,
         e2e: E2EMode? = E2EMode.current, defaults: UserDefaults = .standard,
         storeKeys: (any StoreKeyVault)? = nil, keyStore: (any KeyStore)? = nil,
         cloudBackups: CloudBackupController? = nil,
         discoverGateways: @escaping @Sendable () async -> PeerGatewayConfiguration = {
             await TailnetGatewayDiscovery().discover()
         }) {
        self.discoverGateways = discoverGateways
        self.cloudBackups = cloudBackups ?? CloudBackupController()
        allowsCloudBackup = e2e == nil || cloudBackups != nil
        self.deviceAuthenticator = deviceAuthenticator
            ?? LocalDeviceAuthenticator(keychain: keychainAuthentication)
        self.e2e = e2e
        e2e?.wipeIfRequested()
        let keychainService = e2e?.keychainService ?? KeychainStore.defaultService
        self.keyStore = keyStore ?? KeychainStore(
            service: keychainService,
            protection: e2e == nil ? .userPresence : .deviceOnly,
            authentication: keychainAuthentication)
        // The people and vault files' seal keys sit under the same service,
        // so the E2E wipe covers them along with the wallet secret.
        let storeKeys = storeKeys ?? KeychainStoreKeyVault(service: keychainService)
        vaultStore = VaultStore(keys: storeKeys)
        peopleStore = PeopleStore(keys: storeKeys)
        let defaults = e2e?.defaults ?? defaults
        self.defaults = defaults
        let initialGatewaySettings: PeerGatewaySettings
        if defaults.object(forKey: "peerGatewaySettings") != nil {
            initialGatewaySettings = defaults.data(forKey: "peerGatewaySettings").flatMap {
                try? JSONDecoder().decode(PeerGatewaySettings.self, from: $0)
            } ?? .init(mode: .manual, manual: .init(networks: []))
        } else { initialGatewaySettings = .init() }
        gatewaySettings = initialGatewaySettings
        let initialGateways = initialGatewaySettings.mode == .manual ? initialGatewaySettings.manual : PeerGatewayConfiguration()
        activePeerGateways = initialGateways
        httpClient = RoutedHTTPClient(gateways: initialGateways)
        // 0.7.0 and earlier shipped an opt-in Tor route (`torEnabled`). It
        // is gone with 0.7.1; an installation that had it on is told once
        // rather than silently connecting directly.
        if defaults.object(forKey: DefaultsKey.legacyTorEnabled) != nil {
            torRemovedNotice = defaults.bool(forKey: DefaultsKey.legacyTorEnabled)
            defaults.removeObject(forKey: DefaultsKey.legacyTorEnabled)
        }
        // Mainnet is the default (#9). The E2E harness is a custom-signet
        // fixture, so a test launch that names no network still gets signet.
        let selectedNetwork = e2e?.forcedNetwork
            ?? BitcoinNetwork(rawValue: defaults.string(forKey: DefaultsKey.network) ?? "")
            ?? (e2e != nil ? .signet : Self.defaultNetwork)
        network = selectedNetwork
        if e2e?.forcedNetwork != nil {
            defaults.set(selectedNetwork.rawValue, forKey: DefaultsKey.network)
        }
        Self.migrateLegacyNetworkSettings(defaults: defaults, into: selectedNetwork)
        let scoped = Self.networkScopedSettings(defaults: defaults, network: selectedNetwork)
        manualPeers = scoped.manualPeers
        esploraURLString = scoped.esploraURL
        lastCompleteCheck = defaults.object(forKey: DefaultsKey.lastCompleteCheck(selectedNetwork)) as? Date
        // Provider default is blockstream.info; an installation that had
        // already typed a custom explorer URL keeps it by migrating to
        // `.custom` rather than silently switching sites.
        if let stored = defaults.string(forKey: DefaultsKey.explorerProvider(selectedNetwork)),
           let provider = ExplorerProvider(rawValue: stored) {
            explorerProvider = provider
        } else {
            explorerProvider = scoped.esploraURL.isEmpty ? .blockstream : .custom
        }
        verifyFromGenesis = defaults.bool(forKey: DefaultsKey.verifyFromGenesis)
        advancedMode = defaults.bool(forKey: DefaultsKey.advancedMode) || e2e?.advancedMode == true
        // Test mode preconfigures the local node as the (only) manual peer;
        // custom signets have no DNS seeds.
        if let peer = e2e?.peer, !manualPeers.contains(peer) {
            manualPeers = [peer]
            defaults.set(manualPeers, forKey: DefaultsKey.manualPeers(selectedNetwork))
        }
        e2e?.journal("app.initialized", fields: ["network": network.rawValue])
    }

    /// What a Paste button reads: the runner's control file under the UI
    /// test harness, so a story can hand the app a card or a request without
    /// relaunching it or crossing the system pasteboard; the pasteboard
    /// otherwise.
    func pasteboardText() -> String? {
        e2e?.control()?.clipboard ?? UIPasteboard.general.string
    }

    // MARK: - Lifecycle

    /// Opens the persisted wallet for the current network, if any.
    /// The window's `.task` and a cold background launch can both ask; both
    /// wait for the one open rather than reading the wallet twice.
    func boot() async {
        if let bootTask { await bootTask.value; return }
        let opening = Task { await openWalletForBoot() }
        bootTask = opening
        await opening.value
        bootTask = nil
    }

    private func openWalletForBoot() async {
        // A crash with the export sheet open skips its cleanup; the staging
        // file may carry the recovery phrase, so it does not wait for tmp.
        ExportStagingFile.sweep()
        guard stage == .loading else { return }
        if let clipboard = e2e?.clipboard {
            UIPasteboard.general.string = clipboard
        }
        if case let .damaged(message) = await vaultStore.configure(
            storageURL: vaultsURL(), network: network)
        {
            stage = .storageDamaged(message)
            return
        }
        await configurePeople()
        guard let walletURL = walletURL() else {
            stage = .storageDamaged(
                "Winnow could not access its protected local storage. No wallet files or keys were changed.")
            return
        }
        switch Self.openPersistedWallet(at: walletURL, keyStore: keyStore) {
        case let .opened(wallet):
            self.wallet = wallet
            walletID = await wallet.id
            walletDescriptor = await wallet.descriptor
            upgradeKeyProtection()
            defaults.removeObject(forKey: DefaultsKey.backupPending(walletID ?? ""))
            stage = .ready
        case .missing:
            stage = .onboarding
        case let .damaged(details):
            stage = .storageDamaged(details)
            return
        }
        e2e?.journal("app.booted", fields: [
            "stage": stage == .ready ? "ready" : "onboarding",
            "walletID": walletID ?? "",
        ])
        await refresh()
        if isActive { await activate() }
    }

    /// A wallet stored by 0.7.1 or earlier has its secret behind the
    /// protection class alone; this puts the Keychain's user-presence check
    /// on it in place (`KeychainStore.upgradeProtection`). Attributes only,
    /// no prompt. Best effort: a failure leaves the secret as it was and the
    /// next launch tries again, and the app-layer check still gates every
    /// read meanwhile.
    private func upgradeKeyProtection() {
        guard let walletID else { return }
        do {
            if try keyStore.upgradeProtection(walletID: walletID) {
                e2e?.journal("keychain.protectionUpgraded", fields: ["walletID": walletID])
            }
        } catch {
            e2e?.journal("keychain.protectionUpgradeFailed",
                         fields: ["walletID": walletID, "error": String(describing: error)])
        }
    }

    static func openPersistedWallet(at url: URL,
                                    keyStore: any KeyStore) -> PersistedWalletOpenResult {
        guard FileManager.default.fileExists(atPath: url.path) else { return .missing }
        do {
            return .opened(try Wallet.open(storageURL: url, keyStore: keyStore))
        } catch {
            return .damaged(
                "Winnow found local wallet data but could not safely read it. The files and protected key were left untouched. Retry; if this continues, restore from a known-good wallet bundle or ask for help before changing anything.")
        }
    }

    func retryWalletOpen() async {
        guard case .storageDamaged = stage else { return }
        stage = .loading
        await boot()
    }

    /// The stack runs while the scene is foreground, and for bounded
    /// background checks iOS schedules. The two never overlap.
    func scenePhaseChanged(_ phase: ScenePhase) async {
        e2e?.journal("app.scenePhase", fields: ["phase": String(describing: phase)])
        switch phase {
        case .active:
            if !isActive { attemptedCloudPreparation.removeAll() }
            isActive = true
            await cancelBackgroundSync()
            await networkShutdown?.value
            lastCompleteCheck = defaults.object(forKey: DefaultsKey.lastCompleteCheck(network)) as? Date
            await activate()
        case .background:
            isActive = false
            cloudPreparationTask?.cancel()
            cloudPreparationTask = nil
            cloudBackups.suspend()
            keychainAuthentication.revoke()
            BackgroundSyncScheduler.shared.schedule()
            // A cold BGTask launch can deliver the initial scene phase after
            // its handler started. That phase must not tear down its own scan.
            if backgroundRun != nil { return }
            suspendNetworking()
            let shutdown = Task { await stopNetworking() }
            networkShutdown = shutdown
            await shutdown.value
        default:
            break // .inactive: still foreground — keep syncing
        }
    }

    private func activate() async {
        // Boot must attach the saved wallet before a stack chooses its filters.
        guard stage != .loading, isActive, !backgroundRunning, !changingNetwork,
              storageDirectory() != nil else { return }
        if case .storageDamaged = stage { return }
        scheduleAutomaticCloudPreparation()
        let epoch = networkGeneration
        resumeHTTPClient()
        await buildStackIfNeeded()
        guard epoch == networkGeneration, isActive else { return }
        startPhasePolling()
        await stack?.pool.start()
        guard epoch == networkGeneration, isActive else { return }
        startSyncLoop()
    }

    /// Ends the current networking generation: every HTTP request in flight
    /// fails, and async work that started before this call discards its
    /// result. Callers then stop the pool; `activate()` starts the next one.
    private func suspendNetworking() {
        gatewayDiscoveryTask?.cancel()
        gatewayDiscoveryTask = nil
        discoveringGateways = false
        networkGeneration &+= 1
        httpClient.cancel()
    }

    private func resumeHTTPClient() {
        if httpClient.isCancelled { httpClient = RoutedHTTPClient(gateways: activePeerGateways) }
    }

    /// Called only by the registered BGTask handler: one bounded scan with
    /// the same routing, peers and checks as the foreground, then teardown.
    func runBackgroundSync() async -> Bool {
        guard !isActive, !changingNetwork, backgroundRun == nil else { return false }
        let run = Task { @MainActor in await runBackgroundCheck() }
        backgroundRun = run
        let complete = await run.value
        backgroundRun = nil
        return complete
    }

    private func runBackgroundCheck() async -> Bool {
        await networkShutdown?.value
        guard !isActive, !Task.isCancelled else { return false }
        backgroundRunning = true
        if stage == .loading { await boot() }
        let complete = await scanInBackground()
        // The next foreground resolves routing afresh, as after backgrounding;
        // Tailscale may have come or gone since this check.
        suspendNetworking()
        await stopNetworking()
        backgroundRunning = false
        e2e?.journal("background.completed", fields: ["complete": String(complete)])
        return complete
    }

    private func scanInBackground() async -> Bool {
        guard stage == .ready, storageDirectory() != nil, !Task.isCancelled else { return false }
        resumeHTTPClient()
        await preparePeerGateways()
        guard backgroundRoutingAllowed(), !Task.isCancelled else { return false }
        await buildStackIfNeeded()
        guard !Task.isCancelled else { return false }
        await stack?.pool.start()
        return await syncOnce()
    }

    /// Automatic routing falls back to direct connections when no gateway
    /// answers, and the foreground says so with a banner. A background check
    /// has no banner, so after the foreground last used Tor or I2P it waits
    /// for the app to open rather than connecting directly.
    private func backgroundRoutingAllowed() -> Bool {
        Self.backgroundRoutingAllowed(mode: gatewaySettings.mode, resolved: activePeerGateways,
                                      foregroundUsedGateways: defaults.bool(forKey: DefaultsKey.automaticUsedGateways))
    }

    static func backgroundRoutingAllowed(mode: PeerGatewaySettings.Mode, resolved: PeerGatewayConfiguration,
                                         foregroundUsedGateways: Bool) -> Bool {
        mode != .automatic || !resolved.networks.contains(.clearnet) || !foregroundUsedGateways
    }

    func cancelBackgroundSync() async {
        guard let run = backgroundRun else { return }
        run.cancel()
        // Closing sockets interrupts pending peer reads before the OS deadline.
        await stack?.pool.stop()
        _ = await run.value
    }

    /// Retries peer discovery after the pool reported exhaustion (the UI's
    /// Retry button). Rebuilds the stack when it never came up.
    func retryPeerDiscovery() async {
        if gatewaySettings.mode == .automatic {
            await reconnect()
            return
        }
        if let stack {
            await stack.pool.retry()
        } else {
            await activate()
        }
        await refresh()
    }

    /// Polls the sync actors once a second so the UI can show live
    /// connecting/headers/filters progress instead of a bare spinner.
    private func startPhasePolling() {
        guard phaseTask == nil else { return }
        phaseTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.updateSyncPhase()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// The highest start-height any connected peer advertised, floored at
    /// our own tip — the denominator the header-sync progress is shown
    /// against.
    private func bestAdvertisedTip(in stack: SyncStack, atLeast tip: UInt32) async -> UInt32 {
        var estimate = tip
        for peer in await stack.pool.connectedPeers() {
            let advertised = await peer.peerStartHeight
            if advertised > 0, UInt32(advertised) > estimate { estimate = UInt32(advertised) }
        }
        return estimate
    }

    private func updateSyncPhase() async {
        guard let stack else {
            if syncPhase != .idle { syncPhase = .idle }
            return
        }
        let connection = await stack.pool.connectionStatus
        await journalPeerStatusIfChanged(connection)
        // The snapshot is rebuilt only around a sync pass; over Tor and I2P a
        // pass is long enough that its starting count of zero read as no peers.
        if status.peerCount != connection.connected { status.peerCount = connection.connected }
        if connection.connected == 0 {
            // No peers at all: still dialing, or the round ran dry.
            syncPhase = connection.exhausted
                ? .peerDiscoveryFailed
                : .connecting(connected: 0, target: connection.target)
            return
        }
        if connection.connected < connection.target, connection.dialing {
            syncPhase = .connecting(connected: connection.connected, target: connection.target)
            return
        }
        // At least one peer: one is enough to sync — show the real progress.
        let tip = await stack.chain.height
        let estimate = await bestAdvertisedTip(in: stack, atLeast: tip)
        if estimate > tip + 1 {
            syncPhase = .headers(synced: tip, tipEstimate: estimate)
        } else if let filters = stack.filters {
            let next = await filters.nextScanHeight
            syncPhase = next > tip ? .synced : .filters(scanned: next, tip: tip)
        } else {
            syncPhase = .synced
        }
    }

    /// GUI diagnostics use this safe event to show that sync reached
    /// multiple public peers. Endpoints and user agents are public connection
    /// metadata; wallet scripts, addresses, and keys are never included.
    private func journalPeerStatusIfChanged(_ connection: PeerPool.ConnectionStatus) async {
        guard let e2e, let stack else { return }
        var descriptions: [String] = []
        for peer in await stack.pool.connectedPeers() {
            let endpoint = await peer.endpoint.description
            // Empty until the peer's version message lands, and the journal
            // reads better with a word than with a blank column.
            let advertised = await peer.peerUserAgent
            let userAgent = advertised.isEmpty ? "unknown" : advertised
            descriptions.append("\(endpoint) \(userAgent)")
        }
        descriptions.sort()
        // Why peers were dropped, so a journal that shows "connected 0,
        // exhausted" also says what the pool held against each endpoint.
        let rejections = await stack.pool.rejectionReasons
            .map { "\($0.key.description): \($0.value)" }
            .sorted()
        let fields = [
            "connected": String(connection.connected),
            "target": String(connection.target),
            "dialing": String(connection.dialing),
            "exhausted": String(connection.exhausted),
            "peers": descriptions.joined(separator: ","),
            "rejected": rejections.joined(separator: " | "),
        ]
        let fingerprint = fields.keys.sorted().map { "\($0)=\(fields[$0] ?? "")" }
            .joined(separator: "|")
        guard fingerprint != lastE2EPeerFingerprint else { return }
        lastE2EPeerFingerprint = fingerprint
        e2e.journal("peers.status", fields: fields)
    }

    /// Opens the stored header chain, rebuilding from scratch only on a
    /// start mismatch: the stored chain starts somewhere this setting does
    /// not ask for — the user just changed the setting. The file is not
    /// damaged, it simply answers the other question, so rebuild rather
    /// than try to reconcile the two. Every other error stays fatal.
    nonisolated private static func openOrRebuildChain(params: NetworkParams, storageURL: URL,
                                           start: HeaderChain.Start) throws -> HeaderChain {
        do {
            return try HeaderChain(params: params, storageURL: storageURL, start: start)
        } catch let error as HeaderChainError {
            guard case .startMismatch = error else { throw error }
            try? FileManager.default.removeItem(at: storageURL)
            return try HeaderChain(params: params, storageURL: storageURL, start: start)
        }
    }

    private func makePeerPool(params: NetworkParams, directory dir: URL) -> PeerPool {
        PeerPool(params: params, peerCount: e2e?.peerCount ?? 3, manualPeers: parsedManualPeers(),
                                peersFileURL: dir.appending(path: "peers.json"),
                                relayPreference: true,
                                dialTimeout: activePeerGateways.networks == [.clearnet] ? .seconds(5) : .seconds(30),
                                seedResolver: .routed(client: httpClient),
                                censusCatalog: network == .mainnet ? CensusCatalog.bundled : nil,
                                gateways: activePeerGateways,
                                avoidOnReset: peersToAvoid)
    }

    private func waitForStackBuild() async {
        while stack == nil, buildingStack, !Task.isCancelled {
            try? await Task.sleep(for: .milliseconds(50))
        }
    }

    private func buildStackIfNeeded() async {
        guard stack == nil, let dir = storageDirectory() else { return }
        if buildingStack {
            await waitForStackBuild()
            return
        }
        let epoch = networkGeneration
        buildingStack = true
        defer { buildingStack = false }
        // Wallet creation/import can request the stack before activation has
        // finished. Every entry point must wait for the same routing decision.
        await preparePeerGateways()
        guard epoch == networkGeneration, isActive || backgroundRunning, !Task.isCancelled else { return }
        do {
            let params = e2e?.networkParams ?? NetworkParams.params(for: network)
            // relayPreference: peers inv us relayed transactions so bounded
            // mempool windows (§2.8) can open on live connections without a
            // reconnect. With no window open the invs are dropped unanswered —
            // the window bounds the expensive part (getdata of every tx).
            let pool = makePeerPool(params: params, directory: dir)
            let headersURL = dir.appending(path: "headers.bin")
            // A public signet snapshot is ~25 MB and validating every stored
            // header's linkage/work is intentionally CPU-heavy. Keep that
            // validation intact but off the MainActor so relaunching during
            // backup never freezes the onboarding sheet.
            let start = await chainStart()
            let chain = try await Task.detached(priority: .userInitiated) {
                try Self.openOrRebuildChain(params: params, storageURL: headersURL, start: start)
            }.value
            guard epoch == networkGeneration, isActive || backgroundRunning else { await pool.stop(); return }
            let broadcaster = try makeBroadcaster(
                pool: pool, storageURL: dir.appending(path: "broadcast.json"))
            var newStack = SyncStack(pool: pool, chain: chain, filters: nil, broadcaster: broadcaster)
            if let wallet {
                newStack.filters = try await makeFilterSync(pool: pool, chain: chain,
                                                            startHeight: wallet.nextScanHeight)
            }
            guard epoch == networkGeneration, isActive || backgroundRunning else {
                await pool.stop(); await broadcaster.shutdown(); return
            }
            stack = newStack
            observeBroadcasterFailures(broadcaster)
            // Before anything scans: a marker here means a previous rollback
            // was interrupted, and the state it was repairing is exactly the
            // state a scan would otherwise build on.
            //
            // Fails closed. Swallowing this would leave the marker stuck and
            // then scan on state already known to be stale, which is the one
            // thing every other damaged-state path in this app refuses to do.
            try await resumeInterruptedRollback()
        } catch {
            status.lastSyncError = error.localizedDescription
            e2e?.journal("network.stackFailed", fields: ["error": error.localizedDescription])
        }
    }

    /// Where a quarantined relay store is set aside. A fixed name, so the most
    /// recent damaged file is kept and older ones do not accumulate unbounded
    /// in a directory the user cannot see.
    static let quarantinedRelayStoreName = "broadcast.damaged.json"

    /// Builds the transaction broadcaster, setting a damaged store aside
    /// rather than letting it take the whole sync stack down with it.
    ///
    /// The three stores are not equally important, and constructing this one
    /// inside the stack build inverted their priority. Rebroadcast state is
    /// best-effort -- it exists so a pending transaction keeps being
    /// announced, and the wallet's own history remains the source of truth for
    /// balance and confirmations. Headers and filters are what make the wallet
    /// work at all. So one damaged record in the least important store stopped
    /// the most important functions, and because nothing repaired the file,
    /// every relaunch failed identically until the user deleted it by hand --
    /// which they had no way of knowing to do, since it surfaced as a sync
    /// error (#150).
    ///
    /// The file is renamed rather than deleted. It is the only evidence of
    /// what went wrong, and it may hold transactions worth recovering by hand.
    ///
    /// Deliberately not solved by making `load` skip bad records and keep the
    /// rest: the record most likely to carry a corrupt field is the
    /// longest-pending transaction, the one most in need of rebroadcast, so
    /// "keep the rest" would quietly discard exactly the record that mattered
    /// most. The loader stays strict; the call site stops being brittle.
    func makeBroadcaster(pool: PeerPool, storageURL: URL) throws -> TxBroadcaster {
        do {
            return try TxBroadcaster(pool: pool, storageURL: storageURL)
        } catch let error as TxBroadcasterStorageError {
            let quarantine = storageURL.deletingLastPathComponent()
                .appending(path: Self.quarantinedRelayStoreName)
            try? FileManager.default.removeItem(at: quarantine)
            do {
                try FileManager.default.moveItem(at: storageURL, to: quarantine)
            } catch {
                // The file could not be moved, so a fresh broadcaster would
                // read the same damage next launch. Better to fail loudly than
                // to loop: rethrow the original storage error.
                throw error
            }
            status.relayStoreQuarantined =
                "Pending transactions could not be read (\(error.localizedDescription)). "
                + "The file was set aside as \(Self.quarantinedRelayStoreName) and relay started fresh. "
                + "Your balance and history are unaffected."
            return try TxBroadcaster(pool: pool, storageURL: storageURL)
        }
    }

    /// Names the height an interrupted rollback was heading for.
    static let rollbackMarkerName = "rollback.height"

    /// Rolls the wallet and vaults back to a fork height, recording the target
    /// before touching either.
    ///
    /// The four stores persist independently -- wallet JSON, vaults.json,
    /// filters.json, broadcast.json -- so a crash mid-rollback leaves them
    /// disagreeing. Because a rollback is a pure function of the height, it is
    /// idempotent, and that turns recovery into a redo rather than a repair:
    /// write the target first, roll each store back, clear the target once the
    /// whole sync has finished. A surviving marker at launch means run it
    /// again, and running it twice is indistinguishable from running it once.
    ///
    /// The marker is deliberately not cleared here. Filter progress rewinds
    /// after this returns, and clearing before that would leave a window where
    /// a crash loses the rollback that had already started.
    func rollBackStores(to forkHeight: UInt32) async throws {
        // Throwing, and first. `try?` here defeated the whole mechanism: a
        // failed write proceeded into the rollbacks unprotected, and a crash
        // then left the stores disagreeing with no marker to trigger the redo
        // -- precisely the state the marker exists to prevent. If the target
        // cannot be recorded, nothing may change.
        guard let marker = storageDirectory()?.appending(path: Self.rollbackMarkerName) else {
            throw AppError.noStorage
        }
        try Data(String(forkHeight).utf8).write(
            to: marker, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        try await wallet?.rollBack(to: forkHeight)
        try await vaultStore.rollBack(to: forkHeight)
        // Reactivates any own send whose confirming block fell (#157): the
        // wallet just re-reserved its inputs, and this makes sure the network
        // hears the transaction again instead of only our bookkeeping.
        try await stack?.broadcaster.rollBack(to: forkHeight)
    }

    /// Clears the marker once a sync that included a rollback has completed.
    func finishRollback() {
        guard let marker = storageDirectory()?.appending(path: Self.rollbackMarkerName) else { return }
        try? FileManager.default.removeItem(at: marker)
    }

    /// Redoes a rollback that a crash interrupted.
    ///
    /// Runs before any scanning, because the state it repairs is exactly the
    /// state scanning would otherwise build on.
    func resumeInterruptedRollback() async throws {
        guard let marker = storageDirectory()?.appending(path: Self.rollbackMarkerName),
              let text = try? String(contentsOf: marker, encoding: .utf8),
              let forkHeight = UInt32(text.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return }
        try await wallet?.rollBack(to: forkHeight)
        try await vaultStore.rollBack(to: forkHeight)
        // The same stores `rollBackStores` rewinds, plus the filter frontier.
        // Without this, a crash between the marker and the broadcaster's
        // rewind leaves an own send whose block fell parked forever, so the
        // network never hears it again.
        try await stack?.broadcaster.rollBack(to: forkHeight)
        try await stack?.filters?.rollBack(to: forkHeight)
        finishRollback()
    }

    /// The signed bytes of a still-pending transaction, hex-encoded.
    ///
    /// Winnow relays over its own peer connections and has no fallback
    /// submission path. When relay is not working, the transaction itself is
    /// the only thing that can leave the device, so the user is given it
    /// rather than left with a txid for something no one has seen.
    ///
    /// nil once it confirms and leaves the pending set -- at that point it is
    /// on the chain and the txid is the useful handle.
    func rawTransactionHex(_ txid: Data) async -> String? {
        guard let broadcaster = stack?.broadcaster else { return nil }
        return await broadcaster.rawTransaction(txid)?.hex
    }

    /// Scheduled relay retries happen independently of the foreground send
    /// sheet. Keep storage failures visible at the app level even when that
    /// sheet is closed; otherwise relay could be halted with no explanation.
    private func observeBroadcasterFailures(_ broadcaster: TxBroadcaster) {
        broadcasterEventTask?.cancel()
        broadcasterEventTask = Task { [weak self] in
            for await event in await broadcaster.events() {
                guard !Task.isCancelled else { return }
                if case let .persistenceFailed(reason) = event {
                    self?.status.lastSyncError = reason
                }
            }
        }
    }

    /// Where the header chain should begin for the wallet we actually have.
    /// The rule itself lives in `HeaderChain.Start.forWallet` so it can be
    /// tested; this only supplies the wallet's birthday.
    private func chainStart() async -> HeaderChain.Start {
        var birthday: UInt32?
        if let wallet { birthday = min(await wallet.creationHeight, await wallet.nextScanHeight) }
        return .forWallet(birthday: birthday,
                          checkpoint: NetworkParams.params(for: network).checkpoint,
                          verifyFromGenesis: verifyFromGenesis)
    }

    private func makeFilterSync(pool: PeerPool, chain: HeaderChain, startHeight: UInt32) throws -> FilterSync {
        try FilterSync(pool: pool, chain: chain, startHeight: startHeight,
                       storageURL: storageDirectory()?.appending(path: "filters.json"))
    }

    private func startSyncLoop() {
        guard syncTask == nil, wallet != nil, stack?.filters != nil else { return }
        let interval = e2e?.syncInterval ?? .seconds(45)
        syncTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.syncOnce()
                try? await Task.sleep(for: interval)
            }
        }
    }

    /// One combined scan pass: the wallet's and all vaults' scripts in a
    /// single filter stream (a vault is just more watched scripts). Matched
    /// blocks update the wallet, the vault store, and confirm pending
    /// broadcasts.
    func syncNow() async {
        await syncOnce()
    }

    /// True when the scan reached the tip. A background run stops after a
    /// bounded number of blocks and resumes from the saved frontier next time.
    @discardableResult
    private func syncOnce() async -> Bool {
        guard !status.syncing, let wallet, let stack, let filters = stack.filters else { return false }
        var complete = false
        status.syncing = true
        defer { status.syncing = false }
        do {
            var scripts = try await wallet.watchScripts()
            scripts.append(contentsOf: try await vaultStore.watchScripts(network: network))
            let broadcaster = stack.broadcaster
            let network = network
            let vaultStore = vaultStore
            try await filters.sync(watchScripts: scripts, maxBlocks: backgroundRunning ? 2_000 : nil,
                                   onReorg: { [weak self] forkHeight in
                guard let self else { return }
                try await self.rollBackStores(to: forkHeight)
            }) { match in
                let walletEffect = try await wallet.apply(match: match)
                for discarded in walletEffect.discardedReplacements {
                    try await broadcaster.cancel(discarded)
                }
                try await vaultStore.apply(match: match, network: network)
                let pending = await broadcaster.pendingTxids
                for tx in match.block.transactions where pending.contains(tx.txid) {
                    // The height rides along so the entry becomes a held
                    // tombstone a reorg can resurrect, rather than being
                    // deleted with its raw transaction (#157).
                    try await broadcaster.markConfirmed(tx.txid, atHeight: match.height)
                }
            }
            // apply() does not move the wallet frontier — FilterSync is
            // authoritative here. Persist it so exportBundle() and the next
            // launch's startHeight match what the UI already shows.
            try await persistScanFrontier(of: filters, to: wallet)
            // Held confirmation tombstones age out on the same 100-block
            // horizon spent-coin tombstones do (#157).
            try await broadcaster.pruneConfirmed(scannedTo: await filters.nextScanHeight)
            // Every store that a rollback touches has now been rewound and the
            // scan that followed it has finished, so the target is no longer
            // needed. Cleared only on the success path: a sync that threw may
            // have left the rollback half-applied, and the marker is what gets
            // it redone at the next launch.
            finishRollback()
            status.lastSyncError = nil
            transientSyncFailures = 0
            transientSyncError = nil
            complete = await filters.nextScanHeight > stack.chain.height
            if complete {
                let now = Date()
                lastCompleteCheck = now
                defaults.set(now, forKey: DefaultsKey.lastCompleteCheck(network))
            }
        } catch {
            // A later batch may have thrown after earlier ones persisted
            // in FilterSync. Those earlier batches each passed their own
            // checkpoint comparison before anything above ran for them, so
            // their progress is verified and worth keeping — the batch that
            // threw applied nothing. Keep WalletState from lagging it.
            try? await persistScanFrontier(of: filters, to: wallet)
            // Backgrounding, a network switch or an expired background check
            // cancels the scan and closes its peers. Nothing failed.
            recordSyncFailure(error)
        }
        await refresh()
        return complete
    }

    /// Writes the filter scan's frontier into the wallet file, so the wallet's
    /// recorded height never lags what FilterSync has verified.
    private func persistScanFrontier(of filters: FilterSync, to wallet: Wallet) async throws {
        let frontier = await filters.frontier()
        try await wallet.recordScanHeight(frontier.nextScanHeight,
                                          scannedThroughHash: frontier.scannedThroughHash)
    }

    private func recordSyncFailure(_ error: Error) {
        if !Task.isCancelled, !(error is CancellationError) {
            status.lastSyncError = error.localizedDescription
            let transient = Self.isTransientSyncError(error)
            transientSyncFailures = transient ? transientSyncFailures + 1 : 0
            transientSyncError = transient ? error.localizedDescription : nil
        }
    }

    /// Keep replaced originals beside the payment that superseded them.
    /// The whole group follows its final transaction from pending to confirmed.
    static func historyForDisplay(_ history: [HistoryEntry]) -> [HistoryEntry] {
        let positions = Dictionary(history.enumerated().map { ($0.element.txid, $0.offset) },
                                   uniquingKeysWith: { _, last in last })
        let ranked = history.enumerated().map { index, entry in
            var current = index
            var visited = Set<Int>()
            while let replacement = history[current].replacedBy,
                  let next = positions[replacement],
                  visited.insert(current).inserted {
                current = next
            }
            let final = history[current]
            let block = final.height == 0 && final.replacedBy == nil ? UInt32.max : final.height
            return (entry: entry, block: block, group: current, distance: visited.count)
        }
        return ranked.sorted {
            if $0.block != $1.block { return $0.block > $1.block }
            if $0.group != $1.group { return $0.group > $1.group }
            return $0.distance < $1.distance
        }.map(\.entry)
    }

    /// Rebuilds the UI-facing snapshot from the actors.
    func refresh() async {
        var snapshot = Status()
        if let wallet {
            snapshot.balance = await wallet.balance
            let utxos = await wallet.utxos
            snapshot.utxoCount = utxos.count
            snapshot.history = Self.historyForDisplay(await wallet.history)
            snapshot.feeBumpableTxids = await wallet.feeBumpableTxids
            snapshot.observedFeeRates = await wallet.observedFeeRates
            snapshot.nextScanHeight = await wallet.nextScanHeight
            ownWatchScripts = Set((try? await wallet.watchScripts()) ?? [])
        }
        if let stack {
            snapshot.peerCount = await stack.pool.connectedPeers().count
            snapshot.tipHeight = await stack.chain.height
            if let filters = stack.filters {
                snapshot.nextScanHeight = await filters.nextScanHeight
            }
            snapshot.feeFloorSatPerVByte = await stack.pool.feeFilterFloorSatPerVByte()
        }
        snapshot.syncing = status.syncing
        snapshot.lastSyncError = status.lastSyncError
        // Carried like lastSyncError: `refresh` rebuilds the snapshot from the
        // stores, and a quarantine is a fact about the launch rather than
        // something any store reports. Dropping it here would wipe the notice
        // on the refresh that runs moments after the stack is built, leaving
        // the user's relay queue silently gone.
        snapshot.relayStoreQuarantined = status.relayStoreQuarantined
        status = snapshot
        vaults = await vaultStore.all
        people = await peopleStore.all
        senderByTxid = await peopleStore.senderLabels
        configureReceiveAddressLabels()
        journalSnapshotIfChanged()
        scheduleCloudBackup()
        scheduleAutomaticCloudPreparation()
    }

    // MARK: - Wallet creation / import (onboarding)

    /// A fresh wallet has no history, so its birthday is "now" — there is
    /// nothing to find before it exists. Anchoring to the *peer* tip rather
    /// than the local header height is what makes that true in practice: on a
    /// first launch headers have not synced yet, so `chain.height` is genesis,
    /// and a birthday of 0 sends filter scanning through the entire chain
    /// looking for a descriptor generated seconds ago.
    ///
    /// Scanning still starts at or below the tip, so a payment made while the
    /// user is writing down the phrase is covered.
    /// The validated header-chain tip, which is what a newly built transaction
    /// stamps as its `nLockTime` (#139).
    ///
    /// Deliberately the local chain height rather than any peer's advertised
    /// one: a locktime above the real tip is not final and would not relay, so
    /// the only safe error is to be behind. A wallet with no stack cannot
    /// broadcast anyway -- `broadcast` refuses without one -- so the zero here
    /// is never what actually goes out.
    var chainTipHeight: UInt32 {
        get async {
            guard let stack else { return 0 }
            return await stack.chain.height
        }
    }

    private func creationHeightForNewWallet() async -> UInt32 {
        guard let stack else { return 0 }
        let local = await stack.chain.height
        var advertised: UInt32 = 0
        for peer in await stack.pool.connectedPeers() {
            let height = await peer.peerStartHeight
            if height > 0, UInt32(height) > advertised { advertised = UInt32(height) }
        }
        // Back off a little: peers can advertise a tip we would reorg away
        // from, and rescanning a few hundred blocks is cheap insurance.
        let margin: UInt32 = 500
        let peerBirthday = advertised > margin ? advertised - margin : 0
        // Never go backwards from what we have already validated locally, and
        // fall back to it entirely when no peer has advertised a height yet.
        return max(local, peerBirthday)
    }

    /// Creates a fresh wallet immediately, dated at the current chain tip.
    /// Peer/header catch-up continues through the regular sync loop while the
    /// user backs up the phrase.
    func createWallet() async throws {
        try await authenticateSensitiveAction(reason: "Create and protect your wallet")
        defer { keychainAuthentication.revoke() }
        try Task.checkCancellation()
        await buildStackIfNeeded()
        guard stack != nil else { throw AppError.noStack }
        let knownHeight = await creationHeightForNewWallet()
        guard let walletURL = walletURL() else { throw AppError.noWallet }
        let wallet = try Wallet.create(network: network, keyStore: keyStore,
                                       storageURL: walletURL, entropy: e2e?.entropy,
                                       creationHeight: knownHeight)
        try await adopt(wallet: wallet)
        guard let walletID, case let .mnemonic(words) = try keyStore.load(walletID: walletID) else {
            throw AppError.mnemonicUnavailable
        }
        e2e?.journal("wallet.created", fields: [
            "walletID": walletID,
            "height": String(knownHeight),
            "headersContinueInBackground": "true",
        ])
        await prepareCloudBackup(words: words)
        finishOnboarding()
    }

    /// Imports a wallet bundle (docs/import.md): the state starts as
    /// the bundle claims and is then verified by forward-scanning from the
    /// bundle height. Returns the verification report, or nil when no peers
    /// were reachable yet — the regular sync loop covers the same ground.
    @discardableResult
    func importWallet(bundleJSON: String) async throws -> ImportReport? {
        let bundle = try ImportBundle.decode(json: bundleJSON)
        return try await importWallet(bundle: bundle, authenticate: true)
    }

    private func importWallet(bundle: ImportBundle, authenticate: Bool,
                              afterCommit: (@MainActor (String) async throws -> Void)? = nil) async throws -> ImportReport? {
        try VaultStore.validate(bundle.vaults ?? [], network: network)
        guard bundle.network == network.rawValue else { throw AppError.wrongNetwork(bundle.network) }
        if authenticate, bundle.mnemonic != nil {
            try await authenticateSensitiveAction(
                reason: "Import this wallet's recovery phrase")
        }
        defer { keychainAuthentication.revoke() }
        // Do not cross the Keychain/storage commit boundary after the view
        // that requested a seed-bearing import has been invalidated.
        try Task.checkCancellation()
        e2e?.journal("import.started", fields: [
            "bundleVersion": String(bundle.version),
            "seedBearing": String(bundle.mnemonic != nil),
            "lastKnownHeight": String(bundle.lastKnownHeight),
            "utxoCount": String(bundle.utxos.count),
            "historyCount": String(bundle.transactions.count),
        ])
        guard let walletURL = walletURL() else { throw AppError.noWallet }
        let wallet = try Wallet.importing(bundle, keyStore: keyStore, storageURL: walletURL)
        // Verification below runs its own one-shot filter sync; the regular
        // sync loop must not run concurrently with it (two sync() passes on
        // the same FilterSync/HeaderChain race — crossed getheaders/getcfilter
        // responses on the shared peer). The loop starts on the way out.
        try await adopt(wallet: wallet, startSync: false)
        try await vaultStore.restore(bundle.vaults ?? [])
        vaults = await vaultStore.all
        defer { if isActive { startSyncLoop() } }
        if let afterCommit { try await afterCommit(wallet.id) }
        else { await prepareImportedCloudBackup(bundle) }
        await buildStackIfNeeded()
        guard let filters = stack?.filters else {
            e2e?.journal("import.verificationWaiting", fields: ["reason": "sync stack unavailable"])
            return nil
        }
        await stack?.pool.start()
        guard (try? await waitForPeer(timeout: .seconds(60))) != nil else {
            e2e?.journal("import.verificationWaiting", fields: ["reason": "public peers unavailable"])
            return nil
        }
        // A verification failure (e.g. a peer serving a bad filter) is a real
        // error for the user, not the "no peers yet" soft path.
        let restoredStore = vaultStore
        let restoredNetwork = network
        let report = try await wallet.verifyImport(
            bundle, using: filters,
            additionalScripts: restoredStore.watchScripts(network: network)) { match in
                try await restoredStore.apply(match: match, network: restoredNetwork)
            }
        await refresh()
        e2e?.journal("import.verified", fields: [
            "scannedFromHeight": String(report.scannedFromHeight),
            "scannedToHeight": report.scannedToHeight.map(String.init) ?? "waiting",
            "matchesBundle": String(report.matchesBundle),
            "confirmedUTXOCount": String(report.confirmedUTXOs.count),
            "spentSinceBundleCount": String(report.spentSinceBundle.count),
            "discoveredUTXOCount": String(report.discoveredUTXOs.count),
            "balance": String(status.balance),
            "utxoCount": String(status.utxoCount),
            "historyCount": String(status.history.count),
            "nextScanHeight": String(status.nextScanHeight),
        ])
        return report
    }

    /// Live wallet as a v2 import-bundle JSON string (docs/import.html).
    /// Watch-only unless `includeMnemonic` is set; an xprv-only wallet
    /// throws ``WalletError/mnemonicUnavailable`` rather than a fake seed.
    func exportWalletBundle(includeMnemonic: Bool) async throws -> String {
        guard let wallet else { throw AppError.noWallet }
        if includeMnemonic {
            try await authenticateSensitiveAction(
                reason: "Export this wallet with its recovery phrase")
        }
        defer { if includeMnemonic { keychainAuthentication.revoke() } }
        try Task.checkCancellation()
        // The UI snapshot already prefers filters.nextScanHeight; export
        // must too, in case the last persist was skipped (failed pass).
        if let filters = stack?.filters {
            try await persistScanFrontier(of: filters, to: wallet)
        }
        var bundle = try await wallet.exportBundle(includeMnemonic: includeMnemonic)
        bundle.vaults = try await vaultStore.backupRecords()
        let serialized = try bundle.serialized()
        e2e?.journal("wallet.exported", fields: [
            "bundleVersion": String(bundle.version),
            "seedBearing": String(bundle.mnemonic != nil),
            "lastKnownHeight": String(bundle.lastKnownHeight),
            "utxoCount": String(bundle.utxos.count),
            "historyCount": String(bundle.transactions.count),
        ])
        return serialized
    }

    /// Switches to a just-created/imported wallet: anything chain-facing from
    /// a previous wallet (filter progress, pending broadcasts, vault records)
    /// is that wallet's view and is reset; the new wallet's scan starts from
    /// its own scan height. The stage stays `.onboarding` until the UI calls
    /// `finishOnboarding` completes creation independently of backup availability.
    /// `startSync: false` defers the sync loop (import verifies first).
    private func adopt(wallet: Wallet, startSync: Bool = true) async throws {
        cloudPreparationTask?.cancel()
        cloudPreparationTask = nil
        cloudBackups.configure(directory: nil, walletID: nil)
        syncTask?.cancel()
        syncTask = nil
        await stack?.broadcaster.shutdown()
        broadcasterEventTask?.cancel()
        broadcasterEventTask = nil
        // people.json is deliberately not in this list: the address book is
        // the user's, not one wallet's view of the chain, and holds only
        // public keys.
        if let dir = storageDirectory() {
            for name in ["filters.json", "broadcast.json", "vaults.json", "receive-labels.json", "cloud-backup.json"] {
                try? FileManager.default.removeItem(at: dir.appending(path: name))
            }
        }
        if case let .damaged(message) = await vaultStore.configure(
            storageURL: vaultsURL(), network: network)
        {
            throw AppError.storageDamaged(message)
        }
        await configurePeople()
        receiveLabelStore = nil
        self.wallet = wallet
        walletID = await wallet.id
        walletDescriptor = await wallet.descriptor
        if let existingStack = stack {
            // The old stack is unusable after shutdown. Clear the property
            // before any throwing rebuild step so a failure cannot strand a
            // stopped broadcaster behind a seemingly valid stack.
            stack = nil
            // An imported wallet can be older than the chain we are holding —
            // its filters live in blocks a checkpoint start skipped, and those
            // filters are fetched by block hash, so they are simply not
            // reachable. Drop the stack and rebuild from genesis rather than
            // scan a range that cannot answer.
            if await existingStack.chain.startHeight > (await wallet.nextScanHeight) {
                await existingStack.pool.stop()
                await buildStackIfNeeded()
            } else {
                let filters = try await makeFilterSync(pool: existingStack.pool,
                                                       chain: existingStack.chain,
                                                       startHeight: wallet.nextScanHeight)
                guard let dir = storageDirectory() else { throw AppError.noStack }
                let broadcaster = try TxBroadcaster(
                    pool: existingStack.pool, storageURL: dir.appending(path: "broadcast.json"))
                self.stack = SyncStack(pool: existingStack.pool, chain: existingStack.chain,
                                       filters: filters, broadcaster: broadcaster)
                observeBroadcasterFailures(broadcaster)
            }
        }
        await refresh()
        if startSync, isActive { startSyncLoop() }
    }

    /// Installs a wallet and stack the way `adopt` does, without the storage
    /// reset, the onboarding stage and the networking `adopt` also brings.
    ///
    /// For tests of the paths that only run on a booted model. On a fresh one
    /// `wallet` and `stack` are nil, so every optional-chained rewind in
    /// `resumeInterruptedRollback` is a no-op and a test of it proves only
    /// the marker. `observeBroadcasterFailures` is deliberately not started:
    /// it surfaces persistence failures to the status line, nothing on the
    /// rollback path reads it, and its `for await` would hold the broadcaster
    /// until a `shutdown` no test issues.
    func installForTesting(wallet: Wallet, stack: SyncStack) async {
        precondition(self.stack == nil && self.wallet == nil, "installForTesting is for a fresh model")
        self.wallet = wallet
        walletID = await wallet.id
        walletDescriptor = await wallet.descriptor
        self.stack = stack
    }

    /// Wallet usability is independent of cloud availability or manual backup.
    func finishOnboarding() {
        if let walletID {
            let wasBackupPending = defaults.bool(forKey: DefaultsKey.backupPending(walletID))
            defaults.removeObject(forKey: DefaultsKey.backupPending(walletID))
            e2e?.journal(wasBackupPending ? "backup.completed" : "import.onboardingCompleted",
                         fields: ["walletID": walletID])
        }
        if wallet != nil {
            stage = .ready
            e2e?.journal("wallet.ready", fields: [
                "walletID": walletID ?? "",
                "balance": String(status.balance),
                "utxoCount": String(status.utxoCount),
                "historyCount": String(status.history.count),
                "nextScanHeight": String(status.nextScanHeight),
            ])
        }
    }

    /// Settings → Backup → Show recovery phrase: the words, behind
    /// device-owner authentication (passcode or biometrics). Fail-closed —
    /// no passcode set means no reveal, not a silent skip. E2E test mode
    /// bypasses the prompt (simulators have no passcode); an xprv-only wallet
    /// throws `WalletError.mnemonicUnavailable`.
    func revealMnemonic() async throws -> String {
        guard let walletID else { throw AppError.noWallet }
        try await authenticateSensitiveAction(reason: "Reveal this wallet's recovery phrase")
        defer { keychainAuthentication.revoke() }
        try Task.checkCancellation()
        guard case let .mnemonic(words) = try keyStore.load(walletID: walletID) else {
            throw WalletError.mnemonicUnavailable
        }
        e2e?.journal("backup.phraseRevealReady", fields: [
            "deviceAuthenticationRequired": String(e2e?.requireDeviceAuthentication == true),
        ])
        return words
    }

    /// Settings → irreversibly deletes this network's wallet so another can be
    /// created or imported. Behind device-owner authentication, like the
    /// phrase reveal: this destroys the key, and without a backup the money
    /// goes with it.
    ///
    /// Deleted: the Keychain secret, the wallet and vault files, and the
    /// filter scan progress. **The scan progress must go** — `FilterSync`
    /// prefers stored progress over the start height it is constructed with,
    /// so leaving it would make the next wallet inherit this one's scan
    /// position and silently skip its own history.
    ///
    /// Kept: headers and known peers. Those describe the chain, not the
    /// wallet, so a re-import does not pay for a fresh header sync.
    func destroyWallet() async throws {
        cloudBackups.suspend()
        guard let walletID else { throw AppError.noWallet }
        try await authenticateSensitiveAction(reason: "Delete this wallet from this device")
        defer { keychainAuthentication.revoke() }

        syncTask?.cancel()
        syncTask = nil
        await stack?.pool.stop()
        await stack?.broadcaster.shutdown()
        broadcasterEventTask?.cancel()
        broadcasterEventTask = nil
        stack = nil

        // Key first: a throw after this must not leave a wallet file whose
        // secret is already gone, which would look like a wallet and be
        // unusable. Deleting an absent ID is a no-op, so retrying is safe.
        try keyStore.delete(walletID: walletID)

        // Same per-wallet set `adopt(wallet:)` clears when taking a wallet on,
        // plus the wallet file itself. Keep the two lists together: anything
        // that is one wallet's view must not survive into the next one.
        // people.json stays, on purpose: see `adopt(wallet:)`.
        if let dir = storageDirectory() {
            for name in ["wallet.json", "filters.json", "broadcast.json", "vaults.json", "receive-labels.json", "cloud-backup.json"] {
                try? FileManager.default.removeItem(at: dir.appending(path: name))
            }
        }
        defaults.removeObject(forKey: DefaultsKey.backupPending(walletID))

        cloudBackups.configure(directory: nil, walletID: nil)
        wallet = nil
        self.walletID = nil
        walletDescriptor = nil
        status = Status()
        syncPhase = .idle
        if case let .damaged(message) = await vaultStore.configure(
            storageURL: vaultsURL(), network: network)
        {
            stage = .storageDamaged(message)
            throw AppError.storageDamaged(message)
        }
        vaults = await vaultStore.all
        await configurePeople()
        stage = .onboarding
        e2e?.journal("wallet.destroyed", fields: ["walletID": walletID])

        if isActive { await activate() }
        await refresh()
    }

    /// Polls the pool until a peer completes the handshake (or the timeout
    /// fires) — onboarding's create/import flows need one peer to ask for the
    /// chain tip.
    private func waitForPeer(timeout: Duration) async throws -> PeerConnection {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            if let peer = await stack?.pool.randomPeer() { return peer }
            try? await Task.sleep(for: .seconds(1))
        }
        throw AppError.noPeers
    }

    // MARK: - Addresses, fees, sending

    /// The receive address currently shown (peeked — marked used only when a
    /// payment to it arrives, or via `freshReceiveAddress`).
    func currentReceiveAddress() async throws -> String {
        guard let wallet else { throw AppError.noWallet }
        let address = try await wallet.address(chain: .receive, index: wallet.nextReceiveIndex)
        configureReceiveAddressLabels()
        e2e?.journal("address.receive", fields: ["address": address])
        return address
    }

    /// Marks the current receive address used and returns the next one.
    func freshReceiveAddress() async throws -> String {
        guard let wallet else { throw AppError.noWallet }
        // Core returns the address it just reserved. Receive has already
        // shown that address; the button must show the next unused one.
        _ = try await wallet.freshReceiveAddress()
        let address = try await wallet.address(chain: .receive, index: wallet.nextReceiveIndex)
        await refresh()
        return address
    }

    private func configureReceiveAddressLabels() {
        guard let walletID else {
            receiveLabelStore = nil
            receiveAddressLabels = [:]
            receiveLabelStorageNotice = nil
            return
        }
        let url = storageDirectory()?.appending(path: "receive-labels.json")
        if receiveLabelStore?.walletID != walletID || receiveLabelStore?.network != network
            || receiveLabelStore?.storageURL != url {
            receiveLabelStore = ReceiveAddressLabelStore(storageURL: url, walletID: walletID, network: network)
        }
        receiveAddressLabels = receiveLabelStore?.labels ?? [:]
        receiveLabelStorageNotice = receiveLabelStore?.notice
    }

    func receiveAddressLabel(for address: String) -> String? {
        guard let script = try? AddressDecoder.scriptPubKey(for: address, network: network) else { return nil }
        return receiveAddressLabels[script]
    }

    func setReceiveAddressLabel(_ label: String, address: String) async throws {
        guard let wallet else { throw AppError.noWallet }
        let script = try AddressDecoder.scriptPubKey(for: address, network: network)
        let watched = try await wallet.watchScripts()
        try Task.checkCancellation()
        guard self.wallet === wallet, watched.contains(script) else { throw AppError.noWallet }
        configureReceiveAddressLabels()
        guard let receiveLabelStore else { throw AppError.noWallet }
        try receiveLabelStore.setLabel(label, address: address)
        receiveAddressLabels = receiveLabelStore.labels
    }

    struct LabeledReceiveOutput: Identifiable {
        let id: Int
        let address: String
        let label: String
        let amount: Int64
    }

    func labeledReceiveOutputs(_ entry: HistoryEntry) -> [LabeledReceiveOutput] {
        Self.labeledReceiveOutputs(entry, labels: receiveAddressLabels,
                                   owned: ownWatchScripts, network: network)
    }

    static func labeledReceiveOutputs(_ entry: HistoryEntry, labels: [Data: String],
                                      owned: Set<Data>, network: BitcoinNetwork) -> [LabeledReceiveOutput] {
        guard entry.received > 0, let transaction = try? entry.transaction() else { return [] }
        return transaction.outputs.enumerated().compactMap { index, output in
            guard output.value > 0, owned.contains(output.scriptPubKey),
                  let label = labels[output.scriptPubKey],
                  let address = AddressDecoder.address(for: output.scriptPubKey, network: network)
            else { return nil }
            return LabeledReceiveOutput(id: index, address: address, label: label, amount: output.value)
        }
    }

    /// The resolved feerate (sat/vB): user override, then the wallet's own
    /// observed feerates, then the static presets — clamped from below by the
    /// peers' BIP133 floor
    /// (FeePolicy, docs/write-side.md §4).
    func resolvedFeeRate(priority: FeePolicy.Priority, override: Double?) async -> Double {
        await resolvedFee(priority: priority, override: override).rate
    }

    private func resolvedFee(priority: FeePolicy.Priority, override: Double?) async -> FeePolicy.Resolution {
        let observed = await wallet?.observedFeeRates ?? []
        return FeePolicy.resolution(priority: priority, override: override,
                                    observed: observed, floorSatPerVByte: status.feeFloorSatPerVByte)
    }

    static func requireRelayFee(rate: Double, floor: Double?) throws {
        if let floor, rate < floor { throw AppError.feeDecisionRequired(rate: rate, floor: floor) }
    }

    /// An override typed outside the band coin selection accepts is refused
    /// where it was typed, not silently replaced by a preset.
    static func requireUsableOverride(_ override: Double?) throws {
        if let override, !FeePolicy.acceptsRate(override) {
            throw CoinSelectionError.invalidFeeRate(override)
        }
    }

    /// The live relay floors a rate must clear before anything is signed or
    /// announced: the seat majority, which prices the quote, and the most
    /// lenient connected peer, below which nobody connected would relay. The
    /// second keeps a lone connected peer's floor from being outvoted by
    /// empty seats into a payment that goes nowhere. No stack means no floor
    /// to compare, as before.
    func requireRelayFloors(rate: Double) async throws {
        guard let pool = stack?.pool else { return }
        try Self.requireRelayFee(rate: rate, floor: await pool.feeFilterFloorSatPerVByte())
        try Self.requireRelayFee(rate: rate, floor: await pool.feeFilterFloorSatPerVByte(aggregation: .mostLenient))
    }

    /// What a send will look like at the resolved feerate (coin selection run
    /// without committing — `Wallet.send` itself commits on success).
    /// The fee measured against the payment it is paying for.
    ///
    /// Winnow refuses a payment below dust and refuses a fee rate outside its
    /// band, but nothing looked at the relationship *between* the two. A
    /// one-input, two-output Taproot spend is 143 vB, so at an unremarkable
    /// 5 sat/vB it costs 715 sat -- and a 500 sat payment clears dust, at a
    /// cheap market rate, with coin selection succeeding and value conserved.
    /// Every guard passes; the composition is what produces a transaction
    /// nobody would knowingly authorise (#140).
    struct FeeProportion: Equatable, Sendable {
        let fee: Int64
        let amount: Int64

        /// The fee costs at least half as much as the payment delivers.
        ///
        /// A ratio rather than a number of sats, so it scales with the fee
        /// market: the same transaction at 50 sat/vB costs 7,150 sat and the
        /// threshold has to move with it. Half is deliberately loose -- a
        /// payment smaller than its own fee must be caught, one several times
        /// its fee must not be nagged about, and everything between is a
        /// judgement about false positives on small deliberate sends, which
        /// are legitimate. Integer arithmetic, so there is no rounding at the
        /// boundary the tests pin.
        var isDisproportionate: Bool { fee * 2 >= amount }

        /// Whether it costs more to send than it delivers.
        var exceedsAmount: Bool { fee > amount }

        /// Fee as a percentage of the amount, rounded, for display.
        var percentOfAmount: Int {
            guard amount > 0 else { return 0 }
            return Int((Double(fee) / Double(amount) * 100).rounded())
        }

        /// Names the actual numbers: a generic caution tells the user nothing
        /// they can act on. `sats` is injected so the sentence is composed with
        /// the same formatter the rest of the screen uses.
        func message(sats: (Int64) -> String) -> String {
            exceedsAmount
                ? "This costs more to send than it delivers: sending \(sats(amount)) costs \(sats(fee)) in fees — \(percentOfAmount)% of the amount."
                : "The fee is \(percentOfAmount)% of the amount: sending \(sats(amount)) costs \(sats(fee)) in fees."
        }
    }

    struct SendPreview: Equatable {
        enum Source: Equatable {
            case wallet
            case vault(VaultRecord, PSBT)
        }

        var source: Source = .wallet
        struct ReviewedOutpoint: Equatable {
            var txid: Data
            var vout: UInt32
        }

        /// The normalized address/code that produced the actual payment.
        /// Review UI renders this immutable value, never live text-field state.
        var destination: String
        var payments: [Payment]
        var feeRateSatPerVByte: Double
        var fee: Int64
        var changeAmount: Int64?
        var inputCount: Int
        /// Authorization-relevant state that is not useful to render in the
        /// simple UI but must remain identical when the wallet signs.
        var selectedOutpoints: [ReviewedOutpoint]
        var change: Payment?
        /// Captured at preview time: the locktime this send will carry comes
        /// from a header tip that may lag the network (#151). Rendered on the
        /// review screen so the disclosure is informed; defaulted so direct
        /// constructions in tests describe an ordinary synced send.
        var locktimeLagsTip: Bool = false
        /// The person this pays, for the review label only. `destination`
        /// stays the address: the authorization boundary is unchanged.
        var recipient: Recipient?

        struct Recipient: Equatable {
            var personID: String
            var name: String
            /// The receive-chain index the address was derived at; nil for a
            /// person who gave one fixed address.
            var paymentIndex: UInt32?
            var hasUnverifiedFundingDestination = false

            var derivesFreshAddresses: Bool { paymentIndex != nil }
        }

        /// The total leaving the wallet as payment, excluding change and fee.
        var amountSent: Int64 {
            payments.map(\.amount).reduce(0, +)
        }

        /// How large the fee is next to what is actually being sent, when that
        /// ratio is worth saying out loud (#140).
        ///
        /// `nil` when the send is ordinary, so the review screen can render it
        /// or not without repeating the rule.
        var feeProportion: FeeProportion? {
            let amount = amountSent
            guard amount > 0 else { return nil }
            let proportion = FeeProportion(fee: fee, amount: amount)
            return proportion.isDisproportionate ? proportion : nil
        }

        /// Whether `built` is the transaction that was reviewed.
        ///
        func authorizes(_ built: BuiltTransaction) -> Bool {
            guard built.fee == fee,
                  built.changeAmount == changeAmount,
                  built.transaction.inputs.map({
                      ReviewedOutpoint(txid: $0.previousOutput.txid, vout: $0.previousOutput.vout)
                  }) == selectedOutpoints
            else { return false }

            // The reviewed outputs must account for the transaction exactly:
            // every reviewed one present, and nothing else there.
            //
            // Presence alone is not enough. Fee and inputs are pinned above,
            // which fixes the total output value but says nothing about who
            // receives it, so a build could pay the reviewed amount to a
            // different script, or pay the right script one satoshi. And
            // exhaustion is not enough on its own either: an output the
            // reviewer never saw must fail even when every reviewed one is
            // present, which is why the count is pinned and `unmatched` has to
            // end empty rather than merely contain the change.
            //
            // Matching is order-independent throughout: `TransactionBuilder`
            // inserts change at a random position to avoid a chain-analysis
            // fingerprint, so nothing may assume payments-then-change.
            var expected = payments
            if let change { expected.append(change) }
            guard built.transaction.outputs.count == expected.count else { return false }

            var unmatched = built.transaction.outputs
            for payment in expected {
                guard let index = unmatched.firstIndex(where: {
                    $0.value == payment.amount && $0.scriptPubKey == payment.scriptPubKey
                }) else { return false }
                unmatched.remove(at: index)
            }
            guard unmatched.isEmpty else { return false }
            return (change == nil) == (changeAmount == nil)
        }
    }

    /// Parses the destination (any standard address) and previews coin
    /// selection at the resolved feerate.
    func previewSend(destination: String, amount: Int64, priority: FeePolicy.Priority,
                     override: Double?, accountID: String? = nil) async throws -> SendPreview {
        try Self.requireUsableOverride(override)
        let resolution = await resolvedFee(priority: priority, override: override)
        try Self.requireRelayFee(rate: resolution.rate, floor: resolution.clampedFloor)
        try await requireRelayFloors(rate: resolution.rate)
        let feeRate = resolution.rate
        let trimmed = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        let payments = [try Payment(amount: amount, address: trimmed, network: network)]
        if let accountID {
            guard let record = vaults.first(where: { $0.id == accountID }) else { throw VaultSpendError.unknownVault }
            return try previewVaultSend(record: record, destination: trimmed, payment: payments[0], feeRate: feeRate)
        }
        guard let wallet else { throw AppError.noWallet }
        let utxos = await wallet.spendableUtxos
        let changeScript = try await wallet.scriptPubKey(chain: .change, index: wallet.nextChangeIndex)
        let selection = try CoinSelection.select(utxos: utxos, payments: payments,
                                                 changeScriptPubKey: changeScript,
                                                 feeRateSatPerVByte: feeRate)
        let change = selection.changeAmount.map { Payment(amount: $0, scriptPubKey: changeScript) }
        return SendPreview(destination: trimmed, payments: payments,
                           feeRateSatPerVByte: feeRate, fee: selection.fee,
                           changeAmount: selection.changeAmount, inputCount: selection.selected.count,
                           selectedOutpoints: selection.selected.map {
                               .init(txid: $0.txid, vout: $0.vout)
                           }, change: change,
                           locktimeLagsTip: syncPhase.headerTipMayLagNetwork)
    }

    /// A payment to a person in the address book: the next fresh address is
    /// peeked here and the counter moves only when the send commits.
    func previewSend(to person: PersonRecord, amount: Int64, priority: FeePolicy.Priority,
                     override: Double?, accountID: String? = nil) async throws -> SendPreview {
        let (address, index) = try nextPaymentAddress(for: person)
        var preview = try await previewSend(destination: address, amount: amount,
                                            priority: priority, override: override, accountID: accountID)
        preview.recipient = SendPreview.Recipient(
            personID: person.id, name: person.name,
            paymentIndex: person.derivesFreshAddresses ? index : nil,
            hasUnverifiedFundingDestination: person.hasUnverifiedFundingDestination)
        return preview
    }

    private func previewVaultSend(record: VaultRecord, destination: String, payment: Payment,
                                  feeRate: Double) throws -> SendPreview {
        let (psbt, lagsTip) = try createVaultSpend(record: record, payment: payment, feeRateSatPerVByte: feeRate)
        let reviewed = try reviewVaultSpend(psbt, record: record)
        let transaction = try psbt.unsignedTransaction()
        let remaining = reviewed.outputTotal - payment.amount
        let changeScript = try vault(for: record).scriptPubKey(index: record.nextChangeIndex, choice: 1)
        return SendPreview(source: .vault(record, psbt), destination: destination, payments: [payment],
                           feeRateSatPerVByte: feeRate, fee: reviewed.fee,
                           changeAmount: remaining > 0 ? remaining : nil, inputCount: transaction.inputs.count,
                           selectedOutpoints: transaction.inputs.map {
                               .init(txid: $0.previousOutput.txid, vout: $0.previousOutput.vout)
                           }, change: remaining > 0 ? Payment(amount: remaining, scriptPubKey: changeScript) : nil,
                           locktimeLagsTip: lagsTip)
    }

    /// Keep the reviewed proposal intact when handing it to the approval screen.
    /// Reserve a card's address only once the user proceeds past review.
    func prepareVaultApproval(_ preview: SendPreview) async throws {
        try await exclusively(.spending) {
            guard case let .vault(original, psbt) = preview.source,
                  let record = vaults.first(where: { $0.id == original.id && $0.descriptor == original.descriptor })
            else { throw AppError.sendReviewChanged }
            let reviewed = try reviewVaultSpend(psbt, record: record)
            let remaining = reviewed.outputTotal - preview.amountSent
            let built = try BuiltTransaction(psbt: psbt, transaction: psbt.unsignedTransaction(),
                                             fee: reviewed.fee, changeAmount: remaining > 0 ? remaining : nil)
            guard preview.authorizes(built) else { throw AppError.sendReviewChanged }
            if let recipient = preview.recipient, let index = recipient.paymentIndex {
                guard people.first(where: { $0.id == recipient.personID })?.nextPaymentIndex == index
                else { throw AppError.sendReviewChanged }
                try await peopleStore.advancePaymentIndex(id: recipient.personID, past: index)
                people = await peopleStore.all
            }
            journalApproval("approval.requested", vaultID: record.id, fields: ["base64": psbt.base64])
        }
    }

    /// Builds, signs and broadcasts the previewed send. Returns the txid
    /// (internal byte order).
    /// Operations that move money and must never interleave.
    ///
    /// `send` and `bumpFee` are `@MainActor` but not atomic: each releases the
    /// main actor at every await — device authentication, build, broadcast,
    /// commit — so a second entry can begin in any of those gaps. Disabling a
    /// button is presentation, not a guarantee; this is the guarantee. Both
    /// share one gate because both spend from the same UTXO set and both
    /// commit wallet state, so a fee bump racing a send is as dangerous as
    /// two sends racing each other.
    enum ExclusiveOperation: String, Sendable {
        case spending
    }

    private var operationsInFlight: Set<ExclusiveOperation> = []

    /// Runs `body` unless the same operation is already in flight. The check
    /// and the claim happen with no await between them, so two callers cannot
    /// both observe an idle gate.
    func exclusively<T>(_ operation: ExclusiveOperation,
                        _ body: () async throws -> T) async throws -> T {
        guard !operationsInFlight.contains(operation) else {
            throw AppError.spendAlreadyInFlight
        }
        operationsInFlight.insert(operation)
        defer { operationsInFlight.remove(operation) }
        return try await body()
    }

    func send(preview: SendPreview) async throws -> Data {
        try await exclusively(.spending) {
        guard case .wallet = preview.source else { throw AppError.sendReviewChanged }
        guard let wallet else { throw AppError.noWallet }
        try await authenticateSensitiveAction(reason: "Sign and send this Bitcoin transaction")
        defer { keychainAuthentication.revoke() }
        // Build and sign WITHOUT touching wallet state, hand the tx to the
        // broadcaster, and only then commit the selection. If broadcast throws
        // (no stack, disk error), nothing was spent locally — no stranded UTXOs.
        let prepared = try await wallet.buildSend(payments: preview.payments,
                                                  feeRateSatPerVByte: preview.feeRateSatPerVByte,
                                                  chainTip: await chainTipHeight)
        guard preview.authorizes(prepared.built) else { throw AppError.sendReviewChanged }
        let txid = try await broadcast(prepared.built.transaction,
                                       feeRateSatPerVByte: preview.feeRateSatPerVByte)
        try await wallet.commit(prepared)
        if let recipient = preview.recipient {
            if let index = recipient.paymentIndex {
                await advancePersonPaymentIndex(id: recipient.personID, past: index)
            }
            e2e?.journal("person.paid", fields: [
                "name": recipient.name,
                "paymentIndex": recipient.paymentIndex.map(String.init) ?? "fixed",
                "txid": txid.displayHex,
            ])
        }
        await refresh()
        e2e?.journal("transaction.sent", fields: [
            "txid": txid.displayHex,
            "raw": prepared.built.transaction.serialized(includeWitness: true).hex,
        ])
        return txid
        }
    }

    func pendingFeeRate(txid: Data) async throws -> Double {
        guard let wallet else { throw AppError.noWallet }
        return try await wallet.pendingFeeRate(txid: txid)
    }

    func previewFeeBump(txid: Data, feeRateSatPerVByte: Double) async throws -> FeeBumpPreview {
        guard let wallet else { throw AppError.noWallet }
        // Refused at review, before Face ID and signing; `broadcast` asks
        // again against the live floor as the final gate.
        try await requireRelayFloors(rate: feeRateSatPerVByte)
        return try await wallet.previewFeeBump(txid: txid,
                                               feeRateSatPerVByte: feeRateSatPerVByte)
    }

    /// Broadcasts a replacement first, commits its wallet-state swap second,
    /// and cancels the original relay only after both succeed. If commit fails,
    /// the new broadcaster entry is removed and the old transaction keeps
    /// relaying, preserving the same rollback boundary as a first send.
    func bumpFee(preview: FeeBumpPreview) async throws -> Data {
        try await exclusively(.spending) {
        guard let wallet else { throw AppError.noWallet }
        guard let broadcaster = stack?.broadcaster else { throw AppError.noStack }
        try await authenticateSensitiveAction(reason: "Sign a replacement Bitcoin transaction")
        defer { keychainAuthentication.revoke() }
        let prepared = try await wallet.buildFeeBump(
            txid: preview.originalTxid, feeRateSatPerVByte: preview.feeRateSatPerVByte)
        guard preview.authorizes(prepared.built) else { throw AppError.sendReviewChanged }
        let replacementVSize = TransactionBuilder.vsize(of: prepared.built.transaction)
        let replacementRate = Double(prepared.built.fee) / Double(replacementVSize)
        let replacementTxid = try await broadcast(
            prepared.built.transaction, feeRateSatPerVByte: replacementRate)
        do {
            try await wallet.commitFeeBump(prepared)
        } catch {
            try await broadcaster.cancel(replacementTxid)
            throw error
        }
        try await broadcaster.cancel(preview.originalTxid)
        await refresh()
        e2e?.journal("transaction.replaced", fields: [
            "original": preview.originalTxid.displayHex,
            "replacement": replacementTxid.displayHex,
            "raw": prepared.built.transaction.serialized(includeWitness: true).hex,
        ])
        return replacementTxid
        }
    }

    /// Broadcasts a fully-signed transaction via P2P relay. Block-explorer
    /// settings are links only and are never used as a broadcast backend.
    /// `feeRateSatPerVByte` (known from the send preview) enables the
    /// broadcaster's BIP133 fee-floor events.
    func broadcast(_ transaction: WalletCore.Transaction, feeRateSatPerVByte: Double? = nil) async throws -> Data {
        guard let stack else { throw AppError.noStack }
        let broadcaster = stack.broadcaster
        if let rate = feeRateSatPerVByte {
            try await requireRelayFloors(rate: rate)
        }
        let raw = transaction.serialized(includeWitness: true)
        let txid = try await broadcaster.broadcast(raw, feeRateSatPerVByte: feeRateSatPerVByte)
        e2e?.journal("transaction.broadcast", fields: ["txid": txid.displayHex, "raw": raw.hex])
        return txid
    }

    /// What a fresh install runs on.
    static let defaultNetwork: BitcoinNetwork = .mainnet

    /// Whether the network picker is shown. Signet is an Advanced-mode
    /// concern, but a wallet that is already on signet must always be able
    /// to get back: hiding the picker behind a flag the user just turned off
    /// would strand it there.
    var showsNetworkPicker: Bool {
        // A forced E2E network needs no clause of its own: a forced signet
        // differs from the default and shows the row through that, and a
        // forced mainnet should look exactly like production.
        advancedMode || network != Self.defaultNetwork
    }

    /// The same rule for every control that owns persisted state: shown in
    /// Advanced mode, and shown while that state is non-default, so turning
    /// the flag off hides a control but never strands what it set.
    var showsManualPeers: Bool { advancedMode || !manualPeers.isEmpty }
    var showsChainVerification: Bool { advancedMode || verifyFromGenesis }
    var showsExplorerSettings: Bool { advancedMode || !esploraURLString.isEmpty }

    /// "0.6.0 (123)", from the bundle the app shipped in.
    static let appVersionText: String = {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "?"
        let build = info["CFBundleVersion"] as? String ?? "?"
        return "\(version) (\(build))"
    }()

    func setAdvancedMode(_ enabled: Bool) {
        guard enabled != advancedMode else { return }
        advancedMode = enabled
        defaults.set(enabled, forKey: DefaultsKey.advancedMode)
        e2e?.journal("setting.advancedMode", fields: ["enabled": String(enabled)])
    }

    // MARK: - Vaults

    /// This wallet's cosigner key expression for vault creation:
    /// `[fp/86'/coin'/0']xpub…`, with the `/<0;1>/*` multipath suffix for
    /// multi_a leaves (musig() participants carry no own suffix, BIP390).
    func ownKeyExpression(multipathSuffix: Bool) throws -> String {
        guard let walletDescriptor else { throw AppError.noWallet }
        guard case let .tr(.single(key), nil) = walletDescriptor.expression,
              let origin = key.origin,
              case let .extended(accountKey, hdNetwork) = key.base
        else { throw AppError.noWallet }
        let path = origin.path.map { step in
            step >= HDKey.hardenedOffset ? "\(step - HDKey.hardenedOffset)'" : "\(step)"
        }.joined(separator: "/")
        let base = "[\(String(format: "%08x", origin.fingerprint))/\(path)]\(accountKey.serialized(network: hdNetwork))"
        return multipathSuffix ? base + "/<0;1>/*" : base
    }

    func addVault(name: String, descriptor: Descriptor) async throws -> VaultRecord {
        var height: UInt32 = 0
        if let filters = stack?.filters {
            height = await filters.nextScanHeight
        } else if let wallet {
            height = await wallet.nextScanHeight
        }
        let record = try await vaultStore.add(name: name, descriptor: descriptor, createdAtHeight: height)
        vaults = await vaultStore.all
        e2e?.journal("vault.created", fields: [
            "name": name,
            "descriptor": descriptor.serialized(),
            "height": String(height),
        ])
        return record
    }

    func removeVault(id: String) async {
        try? await vaultStore.remove(id: id)
        vaults = await vaultStore.all
    }

    // MARK: - People and shared savings

    /// A vault read as savings shared with people: who co-owns it, judged by
    /// derived signer keys, never by a stored mapping.
    struct SharedSavings: Equatable, Identifiable {
        var record: VaultRecord
        var coOwners: [PersonRecord]
        var includesYou: Bool
        var threshold: Int
        var signerCount: Int
        /// Every key the descriptor carries, in descriptor order, with who it
        /// is known as. A key that is nobody in the address book is the case
        /// no validation can show, so its fingerprint goes on screen.
        var signers: [Signer]

        var id: String { record.id }

        struct Signer: Equatable, Identifiable {
            var fingerprint: String
            /// The person whose signer key this is; nil for a key that is
            /// not in the address book.
            var name: String?
            var isYou: Bool

            var id: String { fingerprint }
        }
    }

    /// Who each of a vault's keys is, by the same derived identities
    /// `recomputeSharedSavings` matches on.
    private static func signers(of keys: [Data], identities: [(person: PersonRecord, key: Data)],
                                ownKey: Data?) -> [SharedSavings.Signer] {
        keys.map { key in
            SharedSavings.Signer(fingerprint: PersonKeys.fingerprint(ofIdentity: key),
                                 name: identities.first { $0.key == key }?.person.name,
                                 isYou: key == ownKey)
        }
    }

    /// The fingerprint of a person's signer key, to compare with the one
    /// their own phone shows on its card.
    func signerFingerprint(of person: PersonRecord) -> String? {
        person.signerKey.flatMap { try? PersonKeys.signerFingerprint($0, network: network) }
    }

    /// The fingerprint of this wallet's own signer key, as a co-owner's phone
    /// shows it next to this wallet's name.
    var ownSignerFingerprint: String? {
        (try? ownSignerIdentity()).map(PersonKeys.fingerprint(ofIdentity:))
    }

    /// Reads the address book file for the current network. Damage is a
    /// notice, not a stage: the wallet must keep working without its people.
    private func configurePeople() async {
        switch await peopleStore.configure(storageURL: peopleURL(), network: network) {
        case let .damaged(message):
            peopleStorageNotice = message
        case .missing, .loaded:
            peopleStorageNotice = nil
        }
        people = await peopleStore.all
        senderByTxid = await peopleStore.senderLabels
        vaults = await vaultStore.all
    }

    /// Pairs every script-path vault with the people whose signer keys it
    /// carries. Order-independent (`sortedmulti_a`), self-healing for vaults
    /// made from pasted keys, and impossible to leave dangling when a person
    /// is removed.
    private func recomputeSharedSavings() {
        var identities: [(person: PersonRecord, key: Data)] = []
        for person in people {
            guard let signerKey = person.signerKey,
                  let key = try? PersonKeys.signerIdentity(signerKey, network: network)
            else { continue }
            identities.append((person, key))
        }
        let ownKey = try? ownSignerIdentity()
        sharedSavings = vaults.compactMap { record in
            guard let vault = try? Vault(record.descriptor, network: network), vault.isScriptPath,
                  let signerKeys = try? vault.signerKeys()
            else { return nil }
            let coOwners = identities.filter { signerKeys.contains($0.key) }.map(\.person)
            let includesYou = ownKey.map { signerKeys.contains($0) } ?? false
            return SharedSavings(record: record, coOwners: coOwners, includesYou: includesYou,
                                 threshold: vault.threshold, signerCount: vault.signerCount,
                                 signers: Self.signers(of: signerKeys, identities: identities, ownKey: ownKey))
        }
    }

    func ownSignerIdentity() throws -> Data {
        try PersonKeys.signerIdentity(try ownKeyExpression(multipathSuffix: true), network: network)
    }

    var ownDisplayName: String {
        defaults.string(forKey: DefaultsKey.ownDisplayName) ?? ""
    }

    func setOwnDisplayName(_ name: String) {
        defaults.set(name.trimmingCharacters(in: .whitespacesAndNewlines), forKey: DefaultsKey.ownDisplayName)
    }

    /// The card this wallet shares: its own account key as both pay-to key
    /// and signer key. Public material only.
    func ownPersonCard(name: String) throws -> PersonCard {
        let signer = try ownKeyExpression(multipathSuffix: true)
        let payTo = try PersonPayTo.descriptor("tr(\(signer))", network: network)
        return PersonCard(network: network, name: name, payTo: payTo.text, signerKey: signer)
    }

    func journalCardShared() {
        e2e?.journal("card.shared", fields: ["hasSignerKey": "true"])
    }

    func journalApproval(_ name: String, vaultID: String, fields: [String: String]) {
        e2e?.journal(name, fields: fields.merging(["vaultID": vaultID]) { current, _ in current })
    }

    /// Moves a person's payment counter past `index` once an address at that
    /// index has left this phone: a committed send, or a request shared with
    /// co-owners. Never for a preview that was cancelled.
    func advancePersonPaymentIndex(id: String, past index: UInt32) async {
        try? await peopleStore.advancePaymentIndex(id: id, past: index)
        people = await peopleStore.all
    }

    @discardableResult
    func addPerson(name: String, payTo: PersonPayTo?, signerKey: String?,
                   provenance: PersonRecord.DestinationProvenance? = nil, source: String? = nil) async throws -> PersonRecord {
        let record = try await peopleStore.add(name: name, payTo: payTo, signerKey: signerKey, provenance: provenance, source: source)
        people = await peopleStore.all
        e2e?.journal("person.added", fields: [
            "name": record.name,
            "payToKind": record.payTo.map { $0.derivesFreshAddresses ? "descriptor" : "address" } ?? "none",
            "hasSignerKey": String(record.canCoOwnSavings),
        ])
        return record
    }

    func attachDestination(id: String, payTo: PersonPayTo, provenance: PersonRecord.DestinationProvenance,
                           source: String? = nil) async throws {
        try await peopleStore.attachDestination(id: id, payTo: payTo, provenance: provenance, source: source)
        people = await peopleStore.all
    }

    var savedRecipients: [PersonRecord] { people.filter(\.isSavedRecipient) }

    func updateRecipient(id: String, name: String? = nil, saved: Bool) async throws {
        try await peopleStore.updateRecipient(id: id, name: name, saved: saved)
        people = await peopleStore.all
    }

    /// The person a received payment is labelled as coming from, if anyone.
    func receivedSender(_ entry: HistoryEntry) -> PersonRecord? {
        guard let personID = senderByTxid[entry.txid.displayHex] else { return nil }
        return people.first { $0.id == personID }
    }

    /// One address a received payment was funded from, as reconstructed and
    /// stored while the full transaction — witnesses included — was in hand
    /// (WalletCore's `FundingSources`; `HistoryEntry.fundingScripts`).
    /// Entries from before this record, or whose inputs reveal nothing —
    /// taproot key-path, coinbase, bare legacy scripts — yield no candidate.
    struct SenderCandidate: Identifiable, Equatable {
        /// Position in the entry's distinct funding scripts.
        var id: Int
        var address: String
        var scriptPubKey: Data
    }

    func senderCandidates(for entry: HistoryEntry) -> [SenderCandidate] {
        Self.senderCandidates(entry, network: network)
    }

    /// Pure, like `paymentRecipients`: the entry's stored funding scripts,
    /// each with its rendered address.
    static func senderCandidates(_ entry: HistoryEntry, network: BitcoinNetwork) -> [SenderCandidate] {
        entry.fundingScripts.enumerated().compactMap { index, script in
            guard let address = AddressDecoder.address(for: script, network: network) else { return nil }
            return SenderCandidate(id: index, address: address, scriptPubKey: script)
        }
    }

    /// Labels who a received payment came from. The store refuses unknown
    /// people; the mirror follows it.
    func labelReceivedSender(txid: Data, personID: String) async throws {
        try await peopleStore.labelSender(txidHex: txid.displayHex, personID: personID)
        people = await peopleStore.all
        senderByTxid = await peopleStore.senderLabels
        e2e?.journal("person.senderLabeled", fields: ["txid": txid.displayHex, "personID": personID])
    }

    func removeReceivedSenderLabel(txid: Data) async {
        await peopleStore.removeSenderLabel(txidHex: txid.displayHex)
        people = await peopleStore.all
        senderByTxid = await peopleStore.senderLabels
    }

    struct PaymentRecipient: Identifiable {
        var id: Int
        var address: String
        var amount: Int64
        var person: PersonRecord?
    }

    func paymentRecipients(_ entry: HistoryEntry) -> [PaymentRecipient] {
        Self.paymentRecipients(entry, owned: ownWatchScripts.union(ownedVaultScripts),
                               people: recipientByScript, network: network)
    }

    static func paymentRecipients(_ entry: HistoryEntry, owned: Set<Data>,
                                  people: [Data: PersonRecord], network: BitcoinNetwork) -> [PaymentRecipient] {
        guard entry.spent > 0, let transaction = try? entry.transaction() else { return [] }
        return transaction.outputs.enumerated().compactMap { index, output in
            guard !owned.contains(output.scriptPubKey),
                  let address = AddressDecoder.address(for: output.scriptPubKey, network: network) else { return nil }
            return PaymentRecipient(id: index, address: address, amount: output.value,
                                    person: people[output.scriptPubKey])
        }
    }

    func loadPaymentDetails(_ entry: HistoryEntry) async throws {
        guard entry.rawTransaction == nil, let wallet, let stack else { return }
        let transaction: WalletCore.Transaction
        if let raw = await stack.broadcaster.rawTransaction(entry.txid) {
            transaction = try WalletCore.Transaction.decode(raw)
        } else if entry.height > 0, let filters = stack.filters {
            transaction = try await filters.transaction(entry.txid, at: entry.height)
        } else {
            throw AppError.paymentDetailsUnavailable
        }
        try Task.checkCancellation()
        guard self.wallet === wallet else { return }
        try await wallet.rememberTransaction(transaction)
        await refresh()
    }

    /// The address the next payment to `person` derives, peeked without
    /// advancing anything: the counter moves only when a send commits.
    func nextPaymentAddress(for person: PersonRecord) throws -> (address: String, index: UInt32) {
        guard let payTo = person.payTo else { throw AppError.personCannotBePaid }
        return (try payTo.address(index: person.nextPaymentIndex, network: network), person.nextPaymentIndex)
    }

    /// Every script a person could have been paid at so far, for labelling
    /// the outputs of a shared-savings spend.
    func personScripts() -> [Data: String] { recipientByScript.mapValues(\.name) }

    /// Builds the k-of-n vault behind "Savings with Alice, Bob": the chosen
    /// people's signer keys plus this wallet's own, and files it as a vault.
    @discardableResult
    func createSharedSavings(name: String, coOwners: [PersonRecord], threshold: Int) async throws -> VaultRecord {
        let keys = try coOwners.map { person -> String in
            guard let key = person.signerKey else { throw AppError.personCannotCoOwn(person.name) }
            return key
        }
        let descriptor = try Vault.multiADescriptor(threshold: threshold,
                                                    cosigners: [try ownKeyExpression(multipathSuffix: true)] + keys)
        let record = try await addVault(name: name, descriptor: descriptor)
        e2e?.journal("savings.created", fields: [
            "name": name,
            "descriptor": descriptor.serialized(),
            "coOwners": coOwners.map(\.name).joined(separator: ","),
        ])
        return record
    }

    /// Adds savings someone else created, from their card. Validated as a
    /// vault for this network before it is filed.
    @discardableResult
    func addSharedSavings(card text: String) async throws -> VaultRecord {
        let (card, vault) = try SharedSavingsCard.decode(text, network: network)
        let record = try await addVault(name: card.name, descriptor: vault.descriptor)
        e2e?.journal("savings.added", fields: ["name": card.name, "descriptor": vault.descriptor.serialized()])
        return record
    }

    func sharedSavingsCard(for record: VaultRecord) -> SharedSavingsCard {
        SharedSavingsCard(network: network, name: record.name, descriptor: record.descriptor)
    }

    func approvalRequest(for record: VaultRecord, psbt: PSBT) -> ApprovalRequest {
        ApprovalRequest(network: network, vault: record.id, name: record.name, psbt: psbt)
    }

    // MARK: - Vault spends (shared by the expert and the savings screens)

    enum VaultSpendError: LocalizedError {
        case unknownVault

        var errorDescription: String? {
            switch self {
            case .unknownVault: "This vault is no longer on this phone."
            }
        }
    }

    /// The descriptor coordinates a spend may legitimately pay back into:
    /// every coin's own, plus the next receive and change slots. Rebuilt from
    /// trusted local state every time; PSBT metadata never decides ownership.
    func vaultAuthorizationCoordinates(for record: VaultRecord) -> [Vault.OutputCoordinate] {
        var coordinates = record.utxos.map { Vault.OutputCoordinate(choice: $0.chain.rawValue, index: $0.index) }
        coordinates.append(Vault.OutputCoordinate(choice: AddressChain.receive.rawValue, index: record.nextReceiveIndex))
        coordinates.append(Vault.OutputCoordinate(choice: AddressChain.change.rawValue, index: record.nextChangeIndex))
        return coordinates
    }

    func vault(for record: VaultRecord) throws -> Vault {
        try Vault(record.descriptor, network: network)
    }

    /// Proves a proposal is an exact, safe spend of the vault's known coins.
    func reviewVaultSpend(_ psbt: PSBT, record: VaultRecord) throws -> Vault.SpendReview {
        try vault(for: record).reviewSpend(psbt, knownUTXOs: record.utxos,
                                           ownedOutputCoordinates: vaultAuthorizationCoordinates(for: record),
                                           chainTip: status.tipHeight)
    }

    /// Builds the spend PSBT (creator role). `lagsTip` says the locktime came
    /// from a header tip still catching up (#151), as the ordinary send path
    /// discloses.
    func createVaultSpend(record: VaultRecord, payment: Payment,
                          feeRateSatPerVByte: Double) throws -> (psbt: PSBT, lagsTip: Bool) {
        let vault = try vault(for: record)
        let psbt = try vault.createSpend(utxos: record.utxos, payments: [payment],
                                         changeIndex: record.nextChangeIndex,
                                         feeRateSatPerVByte: feeRateSatPerVByte,
                                         chainTip: status.tipHeight)
        journalPSBT(stage: "vault-spend-created", psbt: psbt)
        return (psbt, syncPhase.headerTipMayLagNetwork)
    }

    /// Adds this device's script-path signature to every input, after the
    /// review that decides what the signature authorizes.
    /// Under the same `spending` gate as a wallet send: the review binds the
    /// signature, but two spends from one vault racing each other could
    /// still commit conflicting bookkeeping.
    func partialSignVaultSpend(_ psbt: PSBT, record: VaultRecord, reason: String) async throws -> PSBT {
        try await exclusively(.spending) {
            let vault = try vault(for: record)
            let coordinates = vaultAuthorizationCoordinates(for: record)
            let tip = status.tipHeight
            let signed = try await withMasterKey(reason: reason) { master in
                var candidate = psbt
                try vault.partialSign(&candidate, master: master, knownUTXOs: record.utxos,
                                      ownedOutputCoordinates: coordinates, chainTip: tip)
                return candidate
            }
            journalPSBT(stage: "multi-a-partial-signed", psbt: signed)
            return signed
        }
    }

    /// Finalizes a fully-signed spend, broadcasts it, and commits it to the
    /// vault's coins (inputs out, change in pending — the `Wallet.send` rule).
    func finalizeAndBroadcastVaultSpend(_ psbt: PSBT, record: VaultRecord) async throws -> Data {
        let vault = try vault(for: record)
        var working = psbt
        let transaction = try vault.finalizeSpend(&working, knownUTXOs: record.utxos,
                                                  ownedOutputCoordinates: vaultAuthorizationCoordinates(for: record),
                                                  chainTip: status.tipHeight)
        return try await broadcastVaultSpend(transaction, vault: vault, record: record)
    }

    /// The fee rate of a spend whose inputs are all coins the record knows,
    /// or nil when one is not: the review that admits a spend has already
    /// refused that shape, so nil here only means there is nothing to gate.
    static func feeRate(of transaction: WalletCore.Transaction, spending coins: [WalletUTXO]) -> Double? {
        var inputs: Int64 = 0
        for input in transaction.inputs {
            guard let coin = coins.first(where: {
                $0.txid == input.previousOutput.txid && $0.vout == input.previousOutput.vout
            }) else { return nil }
            inputs += coin.amount
        }
        let fee = inputs - transaction.outputs.reduce(0) { $0 + $1.value }
        let vsize = TransactionBuilder.vsize(of: transaction)
        guard fee > 0, vsize > 0 else { return nil }
        return Double(fee) / Double(vsize)
    }

    /// Broadcasts a finalized vault spend and commits it, under the
    /// `spending` gate. A commit that fails after the broadcast is reported,
    /// not swallowed: the transaction is out, and a spent coin left in the
    /// record could be selected again by the next spend.
    func broadcastVaultSpend(_ transaction: WalletCore.Transaction, vault: Vault,
                             record: VaultRecord) async throws -> Data {
        try await exclusively(.spending) {
            // The rate is known from the record's own coins, so the live
            // relay-floor gate a wallet send passes applies here too: a spend
            // every co-owner approved must not go out below a floor that rose
            // while they were approving it, and sit reserved for nothing.
            let txid = try await broadcast(transaction,
                                           feeRateSatPerVByte: Self.feeRate(of: transaction,
                                                                            spending: record.utxos))
            let changeIndex = record.nextChangeIndex
            let changeScript = try? vault.scriptPubKey(index: changeIndex, choice: AddressChain.change.rawValue)
            do {
                _ = try await recordVaultSpend(id: record.id, transaction: transaction,
                                               changeScriptPubKey: changeScript, changeIndex: changeIndex)
            } catch {
                throw AppError.vaultSpendNotRecorded(txid: txid, reason: error.localizedDescription)
            }
            return txid
        }
    }

    func advanceVaultReceiveIndex(id: String) async {
        try? await vaultStore.advanceReceiveIndex(id: id)
        vaults = await vaultStore.all
    }

    /// Commits a broadcast vault spend to the vault's local UTXO set. `false`
    /// means there was nothing to record (already recorded, or no known
    /// input); a store failure throws rather than reading as `false`.
    @discardableResult
    func recordVaultSpend(id: String, transaction: WalletCore.Transaction, changeScriptPubKey: Data?,
                          changeIndex: UInt32) async throws -> Bool {
        let recorded: Bool
        do {
            recorded = try await vaultStore.recordSpend(
                id: id, transaction: transaction,
                changeScriptPubKey: changeScriptPubKey, changeIndex: changeIndex)
        } catch {
            vaults = await vaultStore.all
            throw error
        }
        vaults = await vaultStore.all
        guard recorded else { return false }
        e2e?.journal("vault.spendRecorded", fields: [
            "vaultID": id,
            "txid": transaction.txid.displayHex,
            "changeIndex": String(changeIndex),
            "hasChange": String(changeScriptPubKey != nil),
        ])
        journalSnapshotIfChanged()
        return true
    }

    /// Records only the public PSBT exchanged with cosigners. Secret MuSig2
    /// nonces never enter a PSBT and remain in `MuSig2SignView` memory.
    func journalPSBT(stage: String, psbt: PSBT) {
        e2e?.journal("psbt.generated", fields: [
            "stage": stage,
            "base64": psbt.base64,
            "inputCount": String(psbt.inputs.count),
            "outputCount": String(psbt.outputs.count),
        ])
    }

    /// Safe, public automation facts emitted only in E2E mode. The complete
    /// txid/height and vault UTXO summaries let a debugging session compare an
    /// original and replacement phone and notice confirmations after resume.
    private func journalSnapshotIfChanged() {
        guard let e2e, wallet != nil else { return }
        let confirmed = status.history.filter { $0.height > 0 }.map {
            "\($0.txid.displayHex)@\($0.height)"
        }.joined(separator: ",")
        let pending = status.history.filter { $0.height == 0 && $0.replacedBy == nil }
            .map { $0.txid.displayHex }.joined(separator: ",")
        let replacements = status.history.compactMap { entry in
            entry.replacedBy.map { "\(entry.txid.displayHex)>\($0.displayHex)" }
        }.joined(separator: ",")
        let vaultSummary = vaults.map { record in
            let confirmedCount = record.utxos.filter { $0.height > 0 }.count
            return "\(record.id):\(record.balance):\(record.utxos.count):\(confirmedCount)"
        }.joined(separator: ",")
        let fields = [
            "walletID": walletID ?? "",
            "balance": String(status.balance),
            "utxoCount": String(status.utxoCount),
            "historyCount": String(status.history.count),
            "nextScanHeight": String(status.nextScanHeight),
            "tipHeight": String(status.tipHeight),
            "peerCount": String(status.peerCount),
            "confirmedTransactions": confirmed,
            "pendingTransactions": pending,
            "replacements": replacements,
            "vaults": vaultSummary,
        ]
        let fingerprint = fields.keys.sorted().map { "\($0)=\(fields[$0] ?? "")" }
            .joined(separator: "|")
        guard fingerprint != lastE2ESnapshotFingerprint else { return }
        lastE2ESnapshotFingerprint = fingerprint
        e2e.journal("wallet.snapshot", fields: fields)
    }

    /// Loads the wallet's master key for one vault signing operation.
    func withMasterKey<T>(reason: String, _ body: (HDKey) throws -> T) async throws -> T {
        guard let walletID else { throw AppError.noWallet }
        try await authenticateSensitiveAction(reason: reason)
        defer { keychainAuthentication.revoke() }
        try Task.checkCancellation()
        let master: HDKey
        switch try keyStore.load(walletID: walletID) {
        case let .mnemonic(words): master = try HDKey(seed: BIP39.seed(mnemonic: words))
        case let .masterKey(xprv): master = try HDKey.deserialize(xprv)
        case .accountKey: throw AppError.rootKeyUnavailable
        }
        return try body(master)
    }

    /// One fail-closed authorization boundary for every secret-revealing or
    /// signing operation. Automated Debug runs may bypass it explicitly;
    /// PR #106 removes that bypass and its environment parser from Release.
    ///
    /// The check that passes is left in `keychainAuthentication` for the
    /// Keychain read the operation goes on to make. Every caller revokes it
    /// when the operation ends, whichever way — `defer` right after this
    /// call — so an operation that throws before its read, or never reads
    /// (deleting the wallet), leaves nothing behind for other code to use.
    func authenticateSensitiveAction(reason: String) async throws {
        if e2e != nil, e2e?.requireDeviceAuthentication != true { return }
        try await deviceAuthenticator.authenticate(reason: reason)
    }

    // MARK: - Settings

    /// Per-network wallets: switching network opens that network's own state
    /// (or onboarding when it has none) with a freshly built stack.
    /// Moves any pre-#81 flat peer/explorer settings into the
    /// network that was active when the app last wrote them, then removes the
    /// flat keys so the migration runs once.
    ///
    /// Attributing them to the active network is the only honest choice: the
    /// old keys carry no record of which chain they were entered for, and the
    /// active network is the chain the user was on when they set them.
    static func migrateLegacyNetworkSettings(defaults: UserDefaults, into network: BitcoinNetwork) {
        if let peers = defaults.stringArray(forKey: DefaultsKey.legacyManualPeers) {
            if defaults.stringArray(forKey: DefaultsKey.manualPeers(network)) == nil {
                defaults.set(peers, forKey: DefaultsKey.manualPeers(network))
            }
            defaults.removeObject(forKey: DefaultsKey.legacyManualPeers)
        }
        if let explorer = defaults.string(forKey: DefaultsKey.legacyEsploraURL) {
            if defaults.string(forKey: DefaultsKey.esploraURL(network)) == nil {
                defaults.set(explorer, forKey: DefaultsKey.esploraURL(network))
            }
            defaults.removeObject(forKey: DefaultsKey.legacyEsploraURL)
        }
    }

    /// What a given network's peer and explorer settings are.
    /// Pure, so the isolation between networks can be tested without a model.
    static func networkScopedSettings(defaults: UserDefaults, network: BitcoinNetwork)
        -> (manualPeers: [String], esploraURL: String)
    {
        (manualPeers: defaults.stringArray(forKey: DefaultsKey.manualPeers(network)) ?? [],
         esploraURL: defaults.string(forKey: DefaultsKey.esploraURL(network)) ?? "")
    }

    /// Re-reads the per-network settings after `network` changes. These are
    /// held in memory, so scoping the storage keys alone would leave the old
    /// chain's peer and endpoints live for the rest of the session — the half
    /// of #81 that a storage-only fix would miss.
    func loadNetworkScopedSettings() {
        let settings = Self.networkScopedSettings(defaults: defaults, network: network)
        manualPeers = settings.manualPeers
        esploraURLString = settings.esploraURL
        lastCompleteCheck = defaults.object(forKey: DefaultsKey.lastCompleteCheck(network)) as? Date
    }

    func switchNetwork(to newNetwork: BitcoinNetwork) async {
        await cancelBackgroundSync()
        cloudBackups.suspend()
        guard e2e?.forcedNetwork == nil || e2e?.forcedNetwork == newNetwork else { return }
        guard newNetwork != network else { return }
        suspendNetworking()
        syncTask?.cancel()
        syncTask = nil
        await stack?.pool.stop()
        await stack?.broadcaster.shutdown()
        broadcasterEventTask?.cancel()
        broadcasterEventTask = nil
        stack = nil
        wallet = nil
        walletID = nil
        walletDescriptor = nil
        network = newNetwork
        defaults.set(newNetwork.rawValue, forKey: DefaultsKey.network)
        loadNetworkScopedSettings()
        if case let .damaged(message) = await vaultStore.configure(
            storageURL: vaultsURL(), network: network)
        {
            stage = .storageDamaged(message)
            return
        }
        await configurePeople()
        guard let walletURL = walletURL() else {
            stage = .storageDamaged(
                "Winnow could not access its protected local storage. No wallet files or keys were changed.")
            return
        }
        switch Self.openPersistedWallet(at: walletURL, keyStore: keyStore) {
        case let .opened(wallet):
            self.wallet = wallet
            walletID = await wallet.id
            walletDescriptor = await wallet.descriptor
            upgradeKeyProtection()
            defaults.removeObject(forKey: DefaultsKey.backupPending(walletID ?? ""))
            stage = .ready
        case .missing:
            stage = .onboarding
        case let .damaged(details):
            stage = .storageDamaged(details)
            return
        }
        await refresh()
        if isActive { await activate() }
    }

    static func parsePeer(_ text: String) throws -> PeerEndpoint {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: ":")
        guard parts.count == 2, !parts[0].isEmpty,
              let port = UInt16(parts[1]), port > 0
        else { throw AppError.invalidPeer(text) }
        return PeerEndpoint(host: String(parts[0]), port: port)
    }

    func addManualPeer(_ text: String) throws {
        let endpoint = try Self.parsePeer(text)
        guard !manualPeers.contains(endpoint.description) else { return }
        manualPeers.append(endpoint.description)
        defaults.set(manualPeers, forKey: DefaultsKey.manualPeers(network))
    }

    func removeManualPeers(at offsets: IndexSet) {
        manualPeers.remove(atOffsets: offsets)
        defaults.set(manualPeers, forKey: DefaultsKey.manualPeers(network))
    }

    private func stopNetworking() async {
        syncTask?.cancel(); syncTask = nil
        phaseTask?.cancel(); phaseTask = nil
        broadcasterEventTask?.cancel(); broadcasterEventTask = nil
        let previous = stack
        stack = nil
        await previous?.pool.stop()
        await previous?.broadcaster.shutdown()
    }

    /// Resolve once per foreground generation. No address discovered on one
    /// tailnet is persisted or reused when the next foreground starts.
    func preparePeerGateways() async {
        let epoch = networkGeneration
        guard preparedGatewayGeneration != epoch else { return }
        let config: PeerGatewayConfiguration
        switch gatewaySettings.mode {
        case .direct: config = .init()
        case .manual: config = gatewaySettings.manual
        case .automatic:
            // UI journeys never probe the developer's real tailnet, except
            // the live gateway journey that asks to.
            if let e2e, !e2e.liveGateways { config = .init(); break }
            if gatewayDiscoveryTask == nil {
                discoveringGateways = true
                gatewayDiscoveryTask = Task { [discoverGateways] in await discoverGateways() }
            }
            guard let task = gatewayDiscoveryTask else { return }
            config = await task.value
        }
        guard epoch == networkGeneration, !Task.isCancelled else { return }
        preparedGatewayGeneration = epoch
        gatewayDiscoveryTask = nil
        discoveringGateways = false
        if gatewaySettings.mode == .automatic, isActive {
            defaults.set(!config.networks.contains(.clearnet), forKey: DefaultsKey.automaticUsedGateways)
        }
        if activePeerGateways == config, !httpClient.isCancelled { return }
        activePeerGateways = config
        httpClient.cancel()
        httpClient = RoutedHTTPClient(gateways: config)
    }

    func setPeerGatewaySettings(_ settings: PeerGatewaySettings) async throws {
        guard settings.mode != .manual || settings.manual.isValid else {
            throw PeerGatewayConfiguration.Invalid.configuration
        }
        let data = try JSONEncoder().encode(settings)
        suspendNetworking()
        gatewaySettings = settings
        defaults.set(data, forKey: "peerGatewaySettings")
        activePeerGateways = settings.mode == .manual ? settings.manual : .init()
        // Apply returns promptly; connection and discovery continue in the
        // foreground. The old networking generation cannot install a result.
        await stopNetworking()
        Task { [weak self] in await self?.activate() }
    }

    /// Rebuilds the stack so changed peer settings take effect.
    func reconnect() async {
        suspendNetworking()
        await stopNetworking()
        await activate()
        await refresh()
    }


    /// "977 candidates", for the peer-list notice: the entries on the
    /// networks the current routing may dial.
    static func candidateCount(_ catalog: CensusCatalog,
                               networks: Set<PeerNetwork> = [.clearnet]) -> String {
        let count = networks.reduce(0) { $0 + (catalog.networks[$1.rawValue]?.count ?? 0) }
        return "\(count) \(count == 1 ? "candidate" : "candidates")"
    }

    /// Reset learned peers while preserving the shipped list and settings.
    func resetPeers() async {
        let pool = stack?.pool
        peersToAvoid = []
        for peer in await pool?.connectedPeers() ?? [] {
            peersToAvoid.insert(await peer.endpoint)
        }
        suspendNetworking()
        await stopNetworking()
        do {
            if let pool { try await pool.forgetKnownGood() }
            else if let dir = storageDirectory() {
                let file = dir.appending(path: "peers.json")
                if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
            }
        } catch { status.lastSyncError = error.localizedDescription; return }
        e2e?.journal("peers.reset", fields: [:])
        await activate()
        await refresh()
    }

    /// Switching where the chain starts cannot be applied to a chain already
    /// on disk, so this tears the stack down and rebuilds it. Turning the
    /// setting on discards the stored headers and re-derives from block 0,
    /// which takes minutes; turning it off keeps them, since a chain validated
    /// from genesis already satisfies anything a checkpoint start would claim.
    func setVerifyFromGenesis(_ enabled: Bool) async {
        guard enabled != verifyFromGenesis else { return }
        verifyFromGenesis = enabled
        defaults.set(enabled, forKey: DefaultsKey.verifyFromGenesis)
        e2e?.journal("setting.verifyFromGenesis", fields: ["enabled": String(enabled)])
        await reconnect()
    }




    func setEsploraURL(_ text: String) {
        esploraURLString = text.trimmingCharacters(in: .whitespacesAndNewlines)
        defaults.set(esploraURLString, forKey: DefaultsKey.esploraURL(network))
    }

    func setExplorerProvider(_ provider: ExplorerProvider) {
        explorerProvider = provider
        defaults.set(provider.rawValue, forKey: DefaultsKey.explorerProvider(network))
    }

    /// The selected external block-explorer website. Winnow contacts it
    /// directly only when the user taps "Infer sender" on a received
    /// payment, after the privacy warning; URLs derived here open only
    /// after a tap accepts the same warning. Never in the background.
    var esploraBaseURL: URL {
        Self.explorerBaseURL(provider: explorerProvider,
                             customURLString: esploraURLString, network: network)
    }

    /// Whether a URL host names this device: the one place a plaintext
    /// explorer cannot be observed or forged in transit.
    static func isLoopback(_ host: String) -> Bool {
        let lowered = host.lowercased()
        return lowered == "localhost" || lowered == "::1" || lowered == "[::1]"
            || lowered.hasPrefix("127.")
    }

    /// Pure resolution, so the per-network preset table is testable without
    /// an app model. blockstream.info serves no signet explorer, so the
    /// blockstream preset resolves to mempool.space's signet site there —
    /// visible in Settings' "Selected:" line rather than a 404 on tap. A
    /// custom entry that fails to parse falls back to the default preset.
    static func explorerBaseURL(provider: ExplorerProvider,
                                customURLString: String,
                                network: BitcoinNetwork) -> URL {
        if provider == .custom {
            // HTTPS for any host off this device: the sender lookup sends a
            // txid and the device IP to this host, and a plaintext answer
            // could be forged on the path. Loopback has no path, so a local
            // explorer — or the UI journeys' stub — may stay plain.
            if let url = URL(string: customURLString), let host = url.host,
               url.scheme?.lowercased() == "https"
                || (url.scheme?.lowercased() == "http" && Self.isLoopback(host)) {
                return url
            }
            return explorerBaseURL(provider: .blockstream, customURLString: "", network: network)
        }
        switch (provider, network) {
        case (.blockstream, .mainnet):
            return URL(string: "https://blockstream.info")!
        case (.mempool, .mainnet):
            return URL(string: "https://mempool.space")!
        default:
            return URL(string: "https://mempool.space/signet")!
        }
    }

    func esploraTransactionURL(_ txid: Data) -> URL {
        esploraBaseURL
            .appending(path: "tx")
            .appending(path: txid.displayHex)
    }

    func esploraAddressURL(_ address: String) -> URL {
        esploraBaseURL
            .appending(path: "address")
            .appending(path: address)
    }

    /// A consented explorer fetch for funding addresses of `txid`, resolved
    /// at the selected explorer. Called only from the received explicit
    /// destination-selection flow, after its privacy warning — never in the
    /// background, never retried, never cached. The consent is tied to the
    /// networking generation it was given in: a lookup that outlives a
    /// suspend or a network switch is refused, not sent.
    struct ExplorerLookupConsent: Equatable {
        let txid: Data
        let baseURL: URL
        let network: BitcoinNetwork
        let generation: UInt64
        var disclosure: String {
            "The explorer receives this transaction ID and your IP address over a direct connection."
        }
    }

    func senderLookupConsent(txid: Data) -> ExplorerLookupConsent {
        ExplorerLookupConsent(txid: txid, baseURL: esploraBaseURL, network: network, generation: networkGeneration)
    }

    func lookupSenderOnline(consent: ExplorerLookupConsent) async throws -> [String] {
        guard isActive, consent == senderLookupConsent(txid: consent.txid) else {
            throw SenderLookupError.unavailable("The network connection changed. Review the lookup warning again.")
        }
        let addresses = try await EsploraSenderLookup.fundingAddresses(txid: consent.txid, baseURL: consent.baseURL,
                                                                      network: consent.network, client: httpClient)
        try Task.checkCancellation()
        guard isActive, consent == senderLookupConsent(txid: consent.txid) else { throw CancellationError() }
        e2e?.journal("sender.lookupOnline", fields: ["txid": consent.txid.displayHex, "explorer": consent.baseURL.host ?? ""])
        return addresses
    }

    // MARK: - Storage

    /// Application Support/BTCSwift/<network>/ — wallet state, headers, filter
    /// progress, peers, broadcasts, vaults. Excluded from backup: no secrets
    /// here (those are Keychain-only), and even the public state stays on the
    /// device.
    func storageDirectory() -> URL? {
        guard let base = try? FileManager.default.url(for: .applicationSupportDirectory,
                                                      in: .userDomainMask,
                                                      appropriateFor: nil, create: true)
        else { return nil }
        var root = base.appending(path: e2e?.storageDirectoryName ?? "BTCSwift",
                                  directoryHint: .isDirectory)
        let dir = root.appending(path: network.rawValue, directoryHint: .isDirectory)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try root.setResourceValues(values)
            return dir
        } catch {
            return nil
        }
    }

    private func walletURL() -> URL? {
        storageDirectory()?.appending(path: "wallet.json")
    }

    private func vaultsURL() -> URL? {
        storageDirectory()?.appending(path: "vaults.json")
    }

    private func peopleURL() -> URL? {
        storageDirectory()?.appending(path: "people.json")
    }

    private func parsedManualPeers() -> [PeerEndpoint] {
        manualPeers.compactMap { try? Self.parsePeer($0) }
    }
}


extension AppModel {
    func discoverCloudBackups() async {
        guard allowsCloudBackup, walletID == nil else { return }
        await cloudBackups.discover(network: network.rawValue)
    }

    func setAutomaticCloudBackup(_ enabled: Bool) async {
        guard let walletID else { return }
        cloudBackups.configure(directory: storageDirectory(), walletID: walletID)
        do {
            try cloudBackups.setAutomatic(enabled)
            if enabled {
                attemptedCloudPreparation.remove(walletID)
                scheduleAutomaticCloudPreparation()
                scheduleCloudBackup()
            }
        } catch { cloudBackups.reportPreparationFailure(error) }
    }

    private func prepareImportedCloudBackup(_ bundle: ImportBundle) async {
        if let words = bundle.mnemonic { await prepareCloudBackup(words: words) }
    }

    private func cloudContents(words: String, walletID: String) async throws -> CloudBackupContents {
        let selectedNetwork = network
        var bundle = try ImportBundle.decode(json: await exportWalletBundle(includeMnemonic: false))
        bundle.mnemonic = words
        let state = try await cloudAppState(for: bundle)
        try Task.checkCancellation()
        guard self.walletID == walletID, network == selectedNetwork else { throw CancellationError() }
        return try CloudBackupContents(bundle: bundle, appState: state.encoded())
    }

    /// Stage only ciphertext while creation/import authentication is valid.
    /// Network availability never determines whether onboarding finishes.
    private func prepareCloudBackup(words: String, account: String? = nil) async {
        guard allowsCloudBackup, let walletID else { return }
        attemptedCloudPreparation.insert(walletID)
        cloudBackups.configure(directory: storageDirectory(), walletID: walletID)
        guard cloudBackups.needsPreparation else { return }
        do {
            let contents = try await cloudContents(words: words, walletID: walletID)
            try cloudBackups.prepare(contents: contents, walletID: walletID, account: account)
            scheduleCloudBackup()
        } catch is CancellationError { }
        catch { cloudBackups.reportPreparationFailure(error) }
    }

    private func scheduleAutomaticCloudPreparation() {
        guard allowsCloudBackup, isActive, stage == .ready, let walletID, cloudPreparationTask == nil else { return }
        cloudBackups.configure(directory: storageDirectory(), walletID: walletID)
        guard cloudBackups.needsPreparation, !attemptedCloudPreparation.contains(walletID) else { return }
        attemptedCloudPreparation.insert(walletID)
        let selectedNetwork = network
        let epoch = UUID()
        cloudPreparationEpoch = epoch
        cloudPreparationTask = Task { [weak self] in
            guard let self else { return }
            await self.prepareExistingCloudBackup(walletID: walletID, network: selectedNetwork)
            if self.cloudPreparationEpoch == epoch { self.cloudPreparationTask = nil }
        }
    }

    private func acceptsCloudPreparation(_ walletID: String, network: BitcoinNetwork) -> Bool {
        self.walletID == walletID && self.network == network && isActive && cloudBackups.needsPreparation
    }

    private func cloudRecoveryWords(walletID: String) throws -> String {
        do {
            guard case let .mnemonic(words) = try keyStore.load(walletID: walletID) else {
                throw ICloudBackupError.unsupportedWallet
            }
            return words
        } catch KeyStoreError.notFound { throw ICloudBackupError.unsupportedWallet }
    }

    private func prepareExistingCloudBackup(walletID: String, network: BitcoinNetwork) async {
        do {
            let account = try await cloudBackups.accountForPreparation()
            try Task.checkCancellation()
            guard acceptsCloudPreparation(walletID, network: network) else { return }
            try await authenticateSensitiveAction(reason: "Protect your wallet with automatic iCloud backup")
            defer { keychainAuthentication.revoke() }
            try Task.checkCancellation()
            guard acceptsCloudPreparation(walletID, network: network) else { return }
            let words = try cloudRecoveryWords(walletID: walletID)
            await prepareCloudBackup(words: words, account: account)
        } catch is CancellationError { }
        catch {
            guard acceptsCloudPreparation(walletID, network: network) else { return }
            cloudBackups.reportPreparationFailure(error)
        }
    }

    func restoreCloudBackup(_ id: UUID) async throws -> ImportReport? {
        guard walletID == nil, allowsCloudBackup else { throw AppError.noWallet }
        let selectedNetwork = network
        cloudRestoreNotice = nil
        try await authenticateSensitiveAction(reason: "Restore your wallet and signing key from iCloud")
        defer { keychainAuthentication.revoke() }
        try Task.checkCancellation()
        let restoration = try await cloudBackups.restoreContents(id)
        let bundle = restoration.contents.bundle
        var appState = try CloudAppState.decode(restoration.contents.appState, for: bundle)
        if let saved = appState { appState?.people = try await peopleStore.planRestore(saved.people) }
        try Task.checkCancellation()
        guard walletID == nil, network == selectedNetwork else { throw CancellationError() }
        let validatedState = appState
        return try await importWallet(bundle: bundle, authenticate: false) { restoredID in
            try Task.checkCancellation()
            guard self.walletID == restoredID, self.network == selectedNetwork else { throw CancellationError() }
            if let validatedState { try await self.applyCloudAppState(validatedState) }
            else {
                self.cloudRestoreNotice = "This older backup restores your wallet and key, but does not contain saved people or address labels."
            }
            self.cloudBackups.configure(directory: self.storageDirectory(), walletID: restoredID)
            do {
                let current = try await self.cloudAppState(for: bundle)
                try self.cloudBackups.resume(contents: CloudBackupContents(bundle: bundle, appState: current.encoded()),
                                             walletID: restoredID, account: restoration.account)
            } catch { self.cloudBackups.reportResumeFailure(error) }
            await self.refresh()
        }
    }

    private func scheduleCloudBackup() {
        guard e2e == nil else { return }
        cloudBackups.configure(directory: storageDirectory(), walletID: walletID)
        guard isActive, let walletID else { return }
        let selectedNetwork = network
        cloudBackups.schedule { [weak self] in
            guard let self, self.walletID == walletID, self.network == selectedNetwork else {
                throw CancellationError()
            }
            let bundle = try ImportBundle.decode(json: await self.exportWalletBundle(includeMnemonic: false))
            let state = try await self.cloudAppState(for: bundle)
            guard self.walletID == walletID, self.network == selectedNetwork else { throw CancellationError() }
            return try CloudBackupContents(bundle: bundle, appState: state.encoded())
        }
    }

    private func cloudAppState(for bundle: ImportBundle) async throws -> CloudAppState {
        configureReceiveAddressLabels()
        guard let receiveLabelStore else { throw AppError.noWallet }
        let state = try await CloudAppState(network: bundle.network, descriptor: bundle.descriptor,
                                           people: peopleStore.backup(), receiveLabels: receiveLabelStore.backup(),
                                           ownDisplayName: ownDisplayName, advancedMode: advancedMode)
        try state.validate(for: bundle)
        return state
    }

    private func applyCloudAppState(_ state: CloudAppState) async throws {
        try await peopleStore.restore(state.people)
        configureReceiveAddressLabels()
        guard let receiveLabelStore else { throw AppError.noWallet }
        try receiveLabelStore.restore(state.receiveLabels)
        setOwnDisplayName(state.ownDisplayName)
        setAdvancedMode(state.advancedMode)
    }
}
