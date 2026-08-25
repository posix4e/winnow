import BitcoinCore
import BitcoinP2P
import BlockchainBackend
import Foundation
import LocalAuthentication
import SwiftUI
import UIKit
import WalletCore

@MainActor
protocol DeviceAuthenticating {
    func authenticate(reason: String) async throws
}

struct LocalDeviceAuthenticator: DeviceAuthenticating {
    func authenticate(reason: String) async throws {
        let context = LAContext()
        var unavailable: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &unavailable) else {
            throw AppModel.AppError.deviceAuthUnavailable
        }
        let passed = try await context.evaluatePolicy(
            .deviceOwnerAuthentication, localizedReason: reason)
        guard passed else { throw AppModel.AppError.deviceAuthFailed }
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
        case invalidPeer(String)
        case wrongNetwork(String)
        case duplicateVault
        case sendReviewChanged
        case storageDamaged(String)
        case deviceAuthUnavailable
        case deviceAuthFailed
        case spendAlreadyInFlight
        /// No storage directory, so a rollback target cannot be recorded.
        case noStorage

        var errorDescription: String? {
            switch self {
            case .noWallet: "No wallet is open."
            case .noStack: "The sync stack is not running."
            case .noPeers: "No peers reachable. Check the network connection or add a manual peer in Settings."
            case .mnemonicUnavailable: "The new wallet's mnemonic could not be read back from the Keychain."
            case let .invalidPeer(text): "Invalid peer “\(text)” — use host:port."
            case let .wrongNetwork(network): "This bundle is for \(network); switch the network in Settings first."
            case .duplicateVault: "A vault with this descriptor already exists."
            case .sendReviewChanged: "The available coins, fee, or change changed. Review the payment again before signing."
            case let .storageDamaged(message): message
            case .deviceAuthUnavailable: "Set a device passcode first — sensitive wallet actions require device authentication."
            case .deviceAuthFailed: "Device authentication failed."
            case .spendAlreadyInFlight: "Another payment is already being signed and broadcast. Wait for it to finish."
            case .noStorage: "Winnow could not reach its storage, so a chain reorganisation could not be recorded. Syncing has stopped rather than continue on stale data."
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
    private(set) var vaults: [VaultRecord] = []
    private(set) var wallet: Wallet?
    private(set) var stack: SyncStack?
    /// Copies of the wallet's id/descriptor for synchronous access (the Wallet
    /// actor's members need an await across the module boundary).
    private(set) var walletID: String?
    private var walletDescriptor: Descriptor?

    /// Secrets (the BIP39 mnemonic) live in the Keychain, this device only.
    /// E2E test mode (E2EMode) uses a separate Keychain service so test runs
    /// never touch a real wallet's secrets.
    let keyStore: any KeyStore
    let vaultStore = VaultStore()
    private let defaults: UserDefaults
    private let deviceAuthenticator: any DeviceAuthenticating

    /// Non-nil only when launched with WINNOW_E2E=1 (XCUITest runs).
    let e2e: E2EMode?

    // Settings (UserDefaults-persisted; see the mutating methods below).
    private(set) var network: BitcoinNetwork
    private(set) var manualPeers: [String] // "host:port"
    private(set) var esploraURLString: String
    /// Off by default: a fresh chain starts from the shipped checkpoint (#89).
    /// On means re-derive every block's work from block 0, which is what the
    /// app did before the checkpoint existed.
    private(set) var verifyFromGenesis: Bool

    private var syncTask: Task<Void, Never>?
    private var phaseTask: Task<Void, Never>?
    private var broadcasterEventTask: Task<Void, Never>?
    private var isActive = false
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
        static func esploraURL(_ network: BitcoinNetwork) -> String { "esploraURL.\(network.rawValue)" }
        /// The pre-#81 flat keys, migrated once into the active network.
        static let legacyManualPeers = "manualPeers"
        static let legacyEsploraURL = "esploraURL"
        /// Deliberately global: a preference, not a chain-specific endpoint.
        static let verifyFromGenesis = "verifyFromGenesis"
        /// Set at wallet creation, cleared only by the backup sheet's
        /// confirmed Done — a relaunch in between resumes the backup.
        static func backupPending(_ walletID: String) -> String { "backupPending.\(walletID)" }
    }

    init(deviceAuthenticator: any DeviceAuthenticating = LocalDeviceAuthenticator()) {
        self.deviceAuthenticator = deviceAuthenticator
        let e2e = E2EMode.current
        self.e2e = e2e
        e2e?.wipeIfRequested()
        keyStore = e2e.map { KeychainStore(service: $0.keychainService) } ?? KeychainStore()
        let defaults = e2e?.defaults ?? .standard
        self.defaults = defaults
        let selectedNetwork = e2e?.forcedNetwork
            ?? BitcoinNetwork(rawValue: defaults.string(forKey: DefaultsKey.network) ?? "")
            ?? .signet
        network = selectedNetwork
        if e2e?.forcedNetwork != nil {
            defaults.set(selectedNetwork.rawValue, forKey: DefaultsKey.network)
        }
        Self.migrateLegacyNetworkSettings(defaults: defaults, into: selectedNetwork)
        let scoped = Self.networkScopedSettings(defaults: defaults, network: selectedNetwork)
        manualPeers = scoped.manualPeers
        esploraURLString = scoped.esploraURL
        verifyFromGenesis = defaults.bool(forKey: DefaultsKey.verifyFromGenesis)
        // Test mode preconfigures the local node as the (only) manual peer;
        // custom signets have no DNS seeds.
        if let peer = e2e?.peer, !manualPeers.contains(peer) {
            manualPeers = [peer]
            defaults.set(manualPeers, forKey: DefaultsKey.manualPeers(selectedNetwork))
        }
        e2e?.journal("app.initialized", fields: ["network": network.rawValue])
    }

    // MARK: - Lifecycle

    /// Opens the persisted wallet for the current network, if any.
    func boot() async {
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
            // A wallet whose backup was never confirmed re-enters onboarding:
            // the backup sheet resumes from the Keychain (#5).
            let backupPending = hasPendingBackup
            stage = backupPending ? .onboarding : .ready
            if backupPending {
                e2e?.journal("backup.pendingResumed", fields: ["walletID": walletID ?? ""])
            }
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
        if isActive { await activate() }
    }

    /// Sync-while-active: the stack runs only while the scene is foreground.
    func scenePhaseChanged(_ phase: ScenePhase) {
        switch phase {
        case .active:
            isActive = true
            Task { await activate() }
        case .background:
            isActive = false
            syncTask?.cancel()
            syncTask = nil
            phaseTask?.cancel()
            phaseTask = nil
            Task { await stack?.pool.stop() }
        default:
            break // .inactive: still foreground — keep syncing
        }
    }

    private func activate() async {
        if case .storageDamaged = stage { return }
        await buildStackIfNeeded()
        startPhasePolling()
        await stack?.pool.start()
        startSyncLoop()
    }

    /// Retries peer discovery after the pool reported exhaustion (the UI's
    /// Retry button). Rebuilds the stack when it never came up.
    func retryPeerDiscovery() async {
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

    private func updateSyncPhase() async {
        guard let stack else {
            if syncPhase != .idle { syncPhase = .idle }
            return
        }
        let connection = await stack.pool.connectionStatus
        await journalPeerStatusIfChanged(connection)
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
        var estimate = tip
        for peer in await stack.pool.connectedPeers() {
            let advertised = await peer.peerStartHeight
            if advertised > 0, UInt32(advertised) > estimate { estimate = UInt32(advertised) }
        }
        if estimate > tip + 1 {
            syncPhase = .headers(synced: tip, tipEstimate: estimate)
        } else if let filters = stack.filters {
            let next = await filters.nextScanHeight
            syncPhase = next > tip ? .synced : .filters(scanned: next, tip: tip)
        } else {
            syncPhase = .synced
        }
    }

    /// The story runner uses this safe event to prove that preflight reached
    /// multiple public peers. Endpoints and user agents are public connection
    /// metadata; wallet scripts, addresses, and keys are never included.
    private func journalPeerStatusIfChanged(_ connection: PeerPool.ConnectionStatus) async {
        guard let e2e, let stack else { return }
        var descriptions: [String] = []
        for peer in await stack.pool.connectedPeers() {
            let endpoint = await peer.endpoint.description
            let userAgent = await peer.peerUserAgent ?? "unknown"
            descriptions.append("\(endpoint) \(userAgent)")
        }
        descriptions.sort()
        let fields = [
            "connected": String(connection.connected),
            "target": String(connection.target),
            "dialing": String(connection.dialing),
            "exhausted": String(connection.exhausted),
            "peers": descriptions.joined(separator: ","),
        ]
        let fingerprint = fields.keys.sorted().map { "\($0)=\(fields[$0] ?? "")" }
            .joined(separator: "|")
        guard fingerprint != lastE2EPeerFingerprint else { return }
        lastE2EPeerFingerprint = fingerprint
        e2e.journal("peers.status", fields: fields)
    }

    private func buildStackIfNeeded() async {
        guard stack == nil else { return }
        if buildingStack {
            while stack == nil, buildingStack {
                try? await Task.sleep(for: .milliseconds(50))
            }
            return
        }
        guard let dir = storageDirectory() else { return }
        buildingStack = true
        defer { buildingStack = false }
        do {
            let params = e2e?.networkParams ?? NetworkParams.params(for: network)
            // relayPreference: peers inv us relayed transactions so bounded
            // mempool windows (§2.8) can open on live connections without a
            // reconnect. With no window open the invs are dropped unanswered —
            // the window bounds the expensive part (getdata of every tx).
            let pool = PeerPool(params: params, manualPeers: parsedManualPeers(),
                                peersFileURL: dir.appending(path: "peers.json"),
                                relayPreference: true)
            let headersURL = dir.appending(path: "headers.bin")
            // A public signet snapshot is ~25 MB and validating every stored
            // header's linkage/work is intentionally CPU-heavy. Keep that
            // validation intact but off the MainActor so relaunching during
            // backup never freezes the onboarding sheet.
            let start = await chainStart()
            let chain = try await Task.detached(priority: .userInitiated) {
                do {
                    return try HeaderChain(params: params, storageURL: headersURL, start: start)
                } catch let error as HeaderChainError {
                    // The stored chain starts somewhere this setting does not
                    // ask for — the user just changed the setting. The file is
                    // not damaged, it simply answers the other question, so
                    // rebuild rather than try to reconcile the two.
                    guard case .startMismatch = error else { throw error }
                    try? FileManager.default.removeItem(at: headersURL)
                    return try HeaderChain(params: params, storageURL: headersURL, start: start)
                }
            }.value
            let broadcaster = try makeBroadcaster(
                pool: pool, storageURL: dir.appending(path: "broadcast.json"))
            var newStack = SyncStack(pool: pool, chain: chain, filters: nil, broadcaster: broadcaster)
            if let wallet {
                newStack.filters = try await makeFilterSync(pool: pool, chain: chain,
                                                            startHeight: wallet.nextScanHeight)
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
        try Data(String(forkHeight).utf8).write(to: marker, options: .atomic)
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
        syncTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.syncOnce()
                try? await Task.sleep(for: .seconds(45))
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

    private func syncOnce() async {
        guard let wallet, let stack, let filters = stack.filters else { return }
        status.syncing = true
        defer { status.syncing = false }
        do {
            var scripts = try await wallet.watchScripts()
            scripts.append(contentsOf: try await vaultStore.watchScripts(network: network))
            let broadcaster = stack.broadcaster
            let network = network
            let vaultStore = vaultStore
            try await filters.sync(watchScripts: scripts,
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
            try await wallet.recordScanHeight(await filters.nextScanHeight)
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
        } catch {
            // A later batch may have thrown after earlier ones persisted
            // in FilterSync. Keep WalletState from lagging that progress.
            try? await wallet.recordScanHeight(await filters.nextScanHeight)
            status.lastSyncError = error.localizedDescription
        }
        await refresh()
    }

    /// Rebuilds the UI-facing snapshot from the actors.
    func refresh() async {
        var snapshot = Status()
        if let wallet {
            snapshot.balance = await wallet.balance
            let utxos = await wallet.utxos
            snapshot.utxoCount = utxos.count
            // Active pending entries first, then newest blocks, with replaced
            // height-0 originals last instead of pinning them as pending.
            snapshot.history = await wallet.history.sorted {
                let lhsPending = $0.height == 0 && $0.replacedBy == nil
                let rhsPending = $1.height == 0 && $1.replacedBy == nil
                if lhsPending != rhsPending { return lhsPending }
                return $0.height > $1.height
            }
            snapshot.feeBumpableTxids = await wallet.feeBumpableTxids
            snapshot.observedFeeRates = await wallet.observedFeeRates
            snapshot.nextScanHeight = await wallet.nextScanHeight
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
        journalSnapshotIfChanged()
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
    func createWallet() async throws -> String {
        try await authenticateSensitiveAction(reason: "Create and reveal a new wallet recovery phrase")
        try Task.checkCancellation()
        await buildStackIfNeeded()
        guard let stack else { throw AppError.noStack }
        let knownHeight = await creationHeightForNewWallet()
        guard let walletURL = walletURL() else { throw AppError.noWallet }
        let wallet = try Wallet.create(network: network, keyStore: keyStore,
                                       storageURL: walletURL, entropy: e2e?.entropy,
                                       creationHeight: knownHeight)
        // Flag BEFORE adopt(): the wallet is already in the Keychain, so a
        // throw below must not leave it unflagged — the next boot would land
        // on .ready with the backup silently skipped, the exact bug class #5
        // kills. A stuck-true flag merely re-presents the sheet: fail-safe.
        defaults.set(true, forKey: DefaultsKey.backupPending(await wallet.id))
        try await adopt(wallet: wallet)
        guard let walletID, case let .mnemonic(words) = try keyStore.load(walletID: walletID) else {
            throw AppError.mnemonicUnavailable
        }
        e2e?.journal("wallet.created", fields: [
            "walletID": walletID,
            "height": String(knownHeight),
            "headersContinueInBackground": "true",
        ])
        return words
    }

    /// Imports a wallet bundle (docs/import.md): the state starts as
    /// the bundle claims and is then verified by forward-scanning from the
    /// bundle height. Returns the verification report, or nil when no peers
    /// were reachable yet — the regular sync loop covers the same ground.
    @discardableResult
    func importWallet(bundleJSON: String) async throws -> ImportReport? {
        let bundle = try ImportBundle.decode(json: bundleJSON)
        guard bundle.network == network.rawValue else { throw AppError.wrongNetwork(bundle.network) }
        if bundle.mnemonic != nil {
            try await authenticateSensitiveAction(
                reason: "Import this wallet's recovery phrase")
        }
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
        defer { if isActive { startSyncLoop() } }
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
        let report = try await wallet.verifyImport(bundle, using: filters)
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
        try Task.checkCancellation()
        // The UI snapshot already prefers filters.nextScanHeight; export
        // must too, in case the last persist was skipped (failed pass).
        if let filters = stack?.filters {
            try await wallet.recordScanHeight(await filters.nextScanHeight)
        }
        let bundle = try await wallet.exportBundle(includeMnemonic: includeMnemonic)
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
    /// `finishOnboarding` (the mnemonic backup must be confirmed first).
    /// `startSync: false` defers the sync loop (import verifies first).
    private func adopt(wallet: Wallet, startSync: Bool = true) async throws {
        syncTask?.cancel()
        syncTask = nil
        await stack?.broadcaster.shutdown()
        broadcasterEventTask?.cancel()
        broadcasterEventTask = nil
        if let dir = storageDirectory() {
            for name in ["filters.json", "broadcast.json", "vaults.json"] {
                try? FileManager.default.removeItem(at: dir.appending(path: name))
            }
        }
        if case let .damaged(message) = await vaultStore.configure(
            storageURL: vaultsURL(), network: network)
        {
            throw AppError.storageDamaged(message)
        }
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

    /// Leaves onboarding once the backup flow (or import report) is done.
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

    /// The mnemonic of a wallet created but never backup-confirmed — non-nil
    /// only between `createWallet()` and the backup sheet's Done. Read from
    /// the Keychain on demand so a relaunch mid-backup resumes the sheet with
    /// the same words.
    /// UI-readable without touching the Keychain. The phrase itself remains
    /// behind `pendingBackupMnemonic()` and device-owner authentication.
    var hasPendingBackup: Bool {
        guard let walletID else { return false }
        return defaults.bool(forKey: DefaultsKey.backupPending(walletID))
    }

    func pendingBackupMnemonic() async throws -> String? {
        guard let walletID, hasPendingBackup else { return nil }
        try await authenticateSensitiveAction(
            reason: "Resume this wallet's recovery-phrase backup")
        try Task.checkCancellation()
        guard case let .mnemonic(words) = try keyStore.load(walletID: walletID) else {
            throw AppError.mnemonicUnavailable
        }
        return words
    }

    /// Settings → Backup → Show recovery phrase: the words, behind
    /// device-owner authentication (passcode or biometrics). Fail-closed —
    /// no passcode set means no reveal, not a silent skip. E2E test mode
    /// bypasses the prompt (simulators have no passcode); an xprv-only wallet
    /// throws `WalletError.mnemonicUnavailable`.
    func revealMnemonic() async throws -> String {
        guard let walletID else { throw AppError.noWallet }
        try await authenticateSensitiveAction(reason: "Reveal this wallet's recovery phrase")
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
        guard let walletID else { throw AppError.noWallet }
        try await authenticateSensitiveAction(reason: "Delete this wallet from this device")

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
        if let dir = storageDirectory() {
            for name in ["wallet.json", "filters.json", "broadcast.json", "vaults.json"] {
                try? FileManager.default.removeItem(at: dir.appending(path: name))
            }
        }
        defaults.removeObject(forKey: DefaultsKey.backupPending(walletID))

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
        e2e?.journal("address.receive", fields: ["address": address])
        return address
    }

    /// Marks the current receive address used and returns the next one.
    func freshReceiveAddress() async throws -> String {
        guard let wallet else { throw AppError.noWallet }
        let address = try await wallet.freshReceiveAddress()
        await refresh()
        return address
    }

    /// The resolved feerate (sat/vB): user override, then the wallet's own
    /// observed feerates, then the static presets — clamped from below by the
    /// peers' BIP133 floor
    /// (FeePolicy, docs/write-side.md §4).
    func resolvedFeeRate(priority: FeePolicy.Priority, override: Double?) async -> Double {
        let observed = await wallet?.observedFeeRates ?? []
        return FeePolicy.resolve(priority: priority, override: override,
                                 observed: observed, floorSatPerVByte: status.feeFloorSatPerVByte)
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
                     override: Double?) async throws -> SendPreview {
        guard let wallet else { throw AppError.noWallet }
        let feeRate = await resolvedFeeRate(priority: priority, override: override)
        let trimmed = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        var payments: [Payment] = []
        payments.append(try Payment(amount: amount, address: trimmed, network: network))
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
        guard let wallet else { throw AppError.noWallet }
        try await authenticateSensitiveAction(reason: "Sign and send this Bitcoin transaction")
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
    func broadcast(_ transaction: BitcoinTransaction, feeRateSatPerVByte: Double? = nil) async throws -> Data {
        guard let broadcaster = stack?.broadcaster else { throw AppError.noStack }
        let raw = transaction.serialized(includeWitness: true)
        let txid = try await broadcaster.broadcast(raw, feeRateSatPerVByte: feeRateSatPerVByte)
        e2e?.journal("transaction.broadcast", fields: ["txid": txid.displayHex, "raw": raw.hex])
        return txid
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

    func advanceVaultReceiveIndex(id: String) async {
        try? await vaultStore.advanceReceiveIndex(id: id)
        vaults = await vaultStore.all
    }

    /// Commits a broadcast vault spend to the vault's local UTXO set.
    @discardableResult
    func recordVaultSpend(id: String, transaction: BitcoinTransaction, changeScriptPubKey: Data?,
                          changeIndex: UInt32) async -> Bool {
        let recorded = (try? await vaultStore.recordSpend(
            id: id, transaction: transaction,
            changeScriptPubKey: changeScriptPubKey, changeIndex: changeIndex)) ?? false
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
    /// nonces never enter a PSBT and remain in `VaultSignView` memory.
    func journalPSBT(stage: String, psbt: PSBT) {
        e2e?.journal("psbt.generated", fields: [
            "stage": stage,
            "base64": psbt.base64,
            "inputCount": String(psbt.inputs.count),
            "outputCount": String(psbt.outputs.count),
        ])
    }

    /// Safe, public automation facts emitted only in E2E mode. The complete
    /// txid/height and vault UTXO summaries let the story runner compare an
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
        try Task.checkCancellation()
        let master: HDKey
        switch try keyStore.load(walletID: walletID) {
        case let .mnemonic(words): master = try HDKey(seed: BIP39.seed(mnemonic: words))
        case let .masterKey(xprv): master = try HDKey.deserialize(xprv)
        }
        return try body(master)
    }

    /// One fail-closed authorization boundary for every secret-revealing or
    /// signing operation. Automated Debug runs may bypass it explicitly;
    /// PR #106 removes that bypass and its environment parser from Release.
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
    }

    func switchNetwork(to newNetwork: BitcoinNetwork) async {
        guard e2e?.forcedNetwork == nil || e2e?.forcedNetwork == newNetwork else { return }
        guard newNetwork != network else { return }
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
            // A wallet whose backup was never confirmed re-enters onboarding:
            // the backup sheet resumes from the Keychain (#5).
            stage = hasPendingBackup ? .onboarding : .ready
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

    /// Rebuilds the stack so changed peer settings take effect.
    func reconnect() async {
        syncTask?.cancel()
        syncTask = nil
        await stack?.pool.stop()
        await stack?.broadcaster.shutdown()
        broadcasterEventTask?.cancel()
        broadcasterEventTask = nil
        stack = nil
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

    /// The selected external block-explorer website. Winnow never contacts it
    /// in the background; URLs derived here are opened only after a user taps
    /// a link and accepts the privacy warning.
    var esploraBaseURL: URL {
        if let url = URL(string: esploraURLString),
           ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
           url.host != nil {
            return url
        }
        let defaultURL = network == .mainnet
            ? "https://mempool.space"
            : "https://mempool.space/signet"
        return URL(string: defaultURL)!
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

    private func parsedManualPeers() -> [PeerEndpoint] {
        manualPeers.compactMap { try? Self.parsePeer($0) }
    }
}
