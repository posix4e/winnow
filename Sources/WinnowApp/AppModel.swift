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
            }
        }
    }

    /// UI-facing snapshot of wallet + sync state (refreshed after syncs and
    /// mutations; the wallet itself is an actor).
    struct Status: Equatable {
        var balance: Int64 = 0
        var utxoCount = 0
        var silentUTXOCount = 0
        var history: [HistoryEntry] = []
        var feeBumpableTxids: [Data] = []
        var observedFeeRates: [Double] = []
        var peerCount = 0
        var tipHeight: UInt32 = 0
        var nextScanHeight: UInt32 = 0
        var syncing = false
        var lastSyncError: String?
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

        /// The filter row uses actor-polled progress while a scan is active,
        /// falling back to the last committed wallet snapshot in other phases.
        func filterScanText(fallbackScanned: UInt32, fallbackTip: UInt32) -> String {
            let progress: (scanned: UInt32, tip: UInt32)
            switch self {
            case let .filters(scanned, tip):
                progress = (scanned, tip)
            default:
                progress = (fallbackScanned, fallbackTip)
            }
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
    private(set) var spReceiveEnabled: Bool
    private(set) var spIndexURLString: String
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
        /// Peer, explorer and tweak-index settings are per network, the way
        /// storage already is. A signet node dialed first on mainnet spends
        /// the pool's opening attempts on a peer that rejects the handshake,
        /// and a signet explorer or tweak index answers mainnet queries with
        /// confidently wrong data. See #81.
        static func manualPeers(_ network: BitcoinNetwork) -> String { "manualPeers.\(network.rawValue)" }
        static func esploraURL(_ network: BitcoinNetwork) -> String { "esploraURL.\(network.rawValue)" }
        static func spIndexURL(_ network: BitcoinNetwork) -> String { "spIndexURL.\(network.rawValue)" }
        /// The pre-#81 flat keys, migrated once into the active network.
        static let legacyManualPeers = "manualPeers"
        static let legacyEsploraURL = "esploraURL"
        static let legacySpIndexURL = "spIndexURL"
        /// Deliberately global: a preference, not a chain-specific endpoint.
        /// With no tweak index for the current network the sync fails visibly
        /// and tells the user to set one, rather than skipping heights.
        static let spReceiveEnabled = "spReceiveEnabled"
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
        spReceiveEnabled = defaults.bool(forKey: DefaultsKey.spReceiveEnabled)
        verifyFromGenesis = defaults.bool(forKey: DefaultsKey.verifyFromGenesis)
        spIndexURLString = scoped.spIndexURL
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
            let broadcaster = try TxBroadcaster(
                pool: pool, storageURL: dir.appending(path: "broadcast.json"))
            var newStack = SyncStack(pool: pool, chain: chain, filters: nil, broadcaster: broadcaster)
            if let wallet {
                newStack.filters = try await makeFilterSync(pool: pool, chain: chain,
                                                            startHeight: wallet.nextScanHeight)
            }
            stack = newStack
            observeBroadcasterFailures(broadcaster)
        } catch {
            status.lastSyncError = error.localizedDescription
        }
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
            // Silent payments ride the same filter stream. Deliberately
            // fail-closed: enabled without a server, or with one that errors,
            // aborts the sync visibly instead of silently skipping heights a
            // forward-only scan would never revisit (see FilterSync.sync).
            var extraScripts: (@Sendable (ClosedRange<UInt32>) async throws -> [UInt32: [Data]])?
            if spReceiveEnabled {
                guard let baseURL = spIndexBaseURL else {
                    status.lastSyncError = "Silent payments: set the tweak-index server URL in Settings."
                    return
                }
                let index = TweakIndexHTTPClient(baseURL: baseURL)
                extraScripts = { range in
                    try await wallet.silentPaymentCandidateScripts(range: range, index: index)
                }
            }
            let broadcaster = stack.broadcaster
            let network = network
            let vaultStore = vaultStore
            try await filters.sync(watchScripts: scripts, extraScripts: extraScripts) { match in
                let walletEffect = try await wallet.apply(match: match)
                for discarded in walletEffect.discardedReplacements {
                    try await broadcaster.cancel(discarded)
                }
                try await vaultStore.apply(match: match, network: network)
                let pending = await broadcaster.pendingTxids
                for tx in match.block.transactions where pending.contains(tx.txid) {
                    try await broadcaster.markConfirmed(tx.txid)
                }
            }
            // apply() does not move the wallet frontier — FilterSync is
            // authoritative here. Persist it so exportBundle() and the next
            // launch's startHeight match what the UI already shows.
            try await wallet.recordScanHeight(await filters.nextScanHeight)
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
            snapshot.silentUTXOCount = utxos.filter { $0.silentPaymentTweak != nil }.count
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

    /// The wallet's static silent payment address. Shown only while the
    /// silent-payments opt-in is on — payments to it are only *found* via the
    /// tweak index, so handing it out with the toggle off invites losses.
    func currentSilentPaymentAddress() async throws -> String {
        guard let wallet else { throw AppError.noWallet }
        let address = try await wallet.silentPaymentAddress()
        e2e?.journal("address.silent", fields: ["address": address])
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
    struct SendPreview: Equatable {
        struct ReviewedOutpoint: Equatable {
            var txid: Data
            var vout: UInt32
        }

        /// The normalized address/code that produced the actual payment.
        /// Review UI renders this immutable value, never live text-field state.
        var destination: String
        var payments: [Payment]
        var silentPayments: [SilentPayment]
        var feeRateSatPerVByte: Double
        var fee: Int64
        var changeAmount: Int64?
        var inputCount: Int
        /// Authorization-relevant state that is not useful to render in the
        /// simple UI but must remain identical when the wallet signs.
        var selectedOutpoints: [ReviewedOutpoint]
        var change: Payment?

        func authorizes(_ built: BuiltTransaction) -> Bool {
            guard built.fee == fee,
                  built.changeAmount == changeAmount,
                  built.transaction.inputs.map({
                      ReviewedOutpoint(txid: $0.previousOutput.txid, vout: $0.previousOutput.vout)
                  }) == selectedOutpoints
            else { return false }
            // Every reviewed payment must actually appear in the transaction.
            // Fee and inputs are pinned above, which fixes the total output
            // value but says nothing about who receives it: without this a
            // build could pay the reviewed amount to a different script, or
            // pay the right script one satoshi, and still satisfy every other
            // constraint. Outputs are consumed as they are matched so one
            // output cannot satisfy two reviewed entries.
            var unmatched = built.transaction.outputs
            for payment in payments {
                guard let index = unmatched.firstIndex(where: {
                    $0.value == payment.amount && $0.scriptPubKey == payment.scriptPubKey
                }) else { return false }
                unmatched.remove(at: index)
            }
            switch change {
            case nil:
                return changeAmount == nil
            case let expected?:
                return unmatched.contains {
                    $0.value == expected.amount && $0.scriptPubKey == expected.scriptPubKey
                }
            }
        }
    }

    /// Parses the destination (any standard address, or an sp1…/tsp1… silent
    /// payment code) and previews coin selection at the resolved feerate.
    func previewSend(destination: String, amount: Int64, priority: FeePolicy.Priority,
                     override: Double?) async throws -> SendPreview {
        guard let wallet else { throw AppError.noWallet }
        let feeRate = await resolvedFeeRate(priority: priority, override: override)
        let trimmed = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        var payments: [Payment] = []
        var silentPayments: [SilentPayment] = []
        // Sizing placeholder for the fee math: silent payment outputs are
        // always P2TR; the real script is derived at signing time (BIP352).
        let sizing = Data([0x51, 0x20]) + Data(repeating: 0, count: 32)
        if trimmed.lowercased().hasPrefix("sp1") || trimmed.lowercased().hasPrefix("tsp1") {
            silentPayments.append(try SilentPayment(amount: amount, address: trimmed, network: network))
        } else {
            payments.append(try Payment(amount: amount, address: trimmed, network: network))
        }
        let sizingPayments = payments + silentPayments.map { Payment(amount: $0.amount, scriptPubKey: sizing) }
        let utxos = await wallet.spendableUtxos
        let changeScript = try await wallet.scriptPubKey(chain: .change, index: wallet.nextChangeIndex)
        let selection = try CoinSelection.select(utxos: utxos, payments: sizingPayments,
                                                 changeScriptPubKey: changeScript,
                                                 feeRateSatPerVByte: feeRate)
        let change = selection.changeAmount.map { Payment(amount: $0, scriptPubKey: changeScript) }
        return SendPreview(destination: trimmed, payments: payments, silentPayments: silentPayments,
                           feeRateSatPerVByte: feeRate, fee: selection.fee,
                           changeAmount: selection.changeAmount, inputCount: selection.selected.count,
                           selectedOutpoints: selection.selected.map {
                               .init(txid: $0.txid, vout: $0.vout)
                           }, change: change)
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
                                                  silentPayments: preview.silentPayments)
        guard preview.authorizes(prepared.built) else { throw AppError.sendReviewChanged }
        let txid = try await broadcast(prepared.built.transaction,
                                       feeRateSatPerVByte: preview.feeRateSatPerVByte)
        try await wallet.commit(prepared)
        await refresh()
        e2e?.journal("transaction.sent", fields: [
            "txid": txid.displayHex,
            "raw": prepared.built.transaction.serialized(includeWitness: true).hex,
            "silent": String(!preview.silentPayments.isEmpty),
            "tweakData": prepared.silentPaymentTweakData?.hex ?? "",
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
            "silentUTXOCount": String(status.silentUTXOCount),
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
    /// Moves any pre-#81 flat peer/explorer/tweak-index settings into the
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
        if let index = defaults.string(forKey: DefaultsKey.legacySpIndexURL) {
            if defaults.string(forKey: DefaultsKey.spIndexURL(network)) == nil {
                defaults.set(index, forKey: DefaultsKey.spIndexURL(network))
            }
            defaults.removeObject(forKey: DefaultsKey.legacySpIndexURL)
        }
    }

    /// What a given network's peer, explorer and tweak-index settings are.
    /// Pure, so the isolation between networks can be tested without a model.
    static func networkScopedSettings(defaults: UserDefaults, network: BitcoinNetwork)
        -> (manualPeers: [String], esploraURL: String, spIndexURL: String)
    {
        (manualPeers: defaults.stringArray(forKey: DefaultsKey.manualPeers(network)) ?? [],
         esploraURL: defaults.string(forKey: DefaultsKey.esploraURL(network)) ?? "",
         spIndexURL: defaults.string(forKey: DefaultsKey.spIndexURL(network)) ?? "")
    }

    /// Re-reads the per-network settings after `network` changes. These are
    /// held in memory, so scoping the storage keys alone would leave the old
    /// chain's peer and endpoints live for the rest of the session — the half
    /// of #81 that a storage-only fix would miss.
    func loadNetworkScopedSettings() {
        let settings = Self.networkScopedSettings(defaults: defaults, network: network)
        manualPeers = settings.manualPeers
        esploraURLString = settings.esploraURL
        spIndexURLString = settings.spIndexURL
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

    func setSilentPaymentsEnabled(_ enabled: Bool) {
        spReceiveEnabled = enabled
        defaults.set(enabled, forKey: DefaultsKey.spReceiveEnabled)
        e2e?.journal("setting.silentPayments", fields: ["enabled": String(enabled)])
    }

    func setSilentPaymentIndexURL(_ text: String) {
        spIndexURLString = text.trimmingCharacters(in: .whitespacesAndNewlines)
        defaults.set(spIndexURLString, forKey: DefaultsKey.spIndexURL(network))
        let host = URL(string: spIndexURLString)?.host?.lowercased()
        e2e?.journal("setting.silentIndex", fields: [
            "configured": String(!spIndexURLString.isEmpty),
            "localFixture": String(host == "127.0.0.1" || host == "localhost"),
        ])
    }

    /// The tweak-index base URL. Unlike esplora there is no public default to
    /// fall back to (yet) — the user's own instance is required, and sync
    /// fails closed while the toggle is on without one.
    var spIndexBaseURL: URL? {
        guard let url = URL(string: spIndexURLString), url.scheme != nil else { return nil }
        return url
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
    private func storageDirectory() -> URL? {
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
