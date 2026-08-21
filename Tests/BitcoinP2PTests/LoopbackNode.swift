import BitcoinCore
import Foundation
import Network
@testable import BitcoinP2P

/// A loopback fake full node speaking just enough of the P2P protocol to test
/// PeerConnection / HeaderChain / FilterSync / TxBroadcaster without touching
/// the network: version handshake, ping/pong, feefilter push, getheaders,
/// and BIP157 getcfcheckpt/getcfheaders/getcfilters/getdata served from a
/// synthetic chain.
actor LoopbackNode {
    enum NodeError: Error {
        case failed(String)
    }

    let params: NetworkParams
    let services: UInt64
    /// Height-indexed blocks served over getheaders/getdata (empty: headers-disabled node).
    let chain: [Block]
    /// When set, the filter served for this height is bit-flipped (lying node).
    let corruptFilterAtHeight: Int?
    /// Serves filter *commitments* that disagree with the honest chain while
    /// keeping block headers honest — a peer lying about BIP157 filter
    /// headers rather than about the chain itself. This is the shape the
    /// cfcheckpt majority rule exists to defend against.
    let lieAboutFilterCommitments: Bool
    /// When set, the node answers inv announcements of transactions with a
    /// getdata after this delay (nil = never request, the silent peer).
    let autoRequestDelay: Duration?
    /// Optional delay before the node sends its version message. Tests use
    /// this to make pool connection order deterministic.
    let versionDelay: Duration
    /// The node's mempool: transactions it serves over getdata (MSG_TX /
    /// MSG_WITNESS_TX) — unknown tx hashes get a notfound.
    let transactions: [Data: Transaction] // keyed by txid (internal order)

    private var listener: NWListener?
    private var connection: NWConnection?
    private var framer: MessageFramer
    private(set) var port: UInt16 = 0
    /// The BIP37 relay flag from the client's version handshake.
    private(set) var clientRelay: Bool?

    /// All decoded post-handshake messages received from the client.
    private var inbox: [PeerMessage] = []

    // BIP158 data derived from `chain` on start.
    private var filters: [Data] = [] // NBytes per height
    private var filterHashes: [Data] = []
    private var filterHeaders: [Data] = []

    init(params: NetworkParams, services: UInt64 = PeerConnection.nodeCompactFilters,
         chain: [Block] = [], corruptFilterAtHeight: Int? = nil,
         lieAboutFilterCommitments: Bool = false,
         autoRequestDelay: Duration? = nil, transactions: [Transaction] = [],
         listenPort: UInt16? = nil, versionDelay: Duration = .zero) {
        self.params = params
        self.services = services
        self.chain = chain
        self.corruptFilterAtHeight = corruptFilterAtHeight
        self.lieAboutFilterCommitments = lieAboutFilterCommitments
        self.autoRequestDelay = autoRequestDelay
        self.transactions = Dictionary(uniqueKeysWithValues: transactions.map { ($0.txid, $0) })
        self.versionDelay = versionDelay
        self.listenPort = listenPort
        framer = MessageFramer(magic: params.magic)
    }

    private let listenPort: UInt16?

    var endpoint: PeerEndpoint { PeerEndpoint(host: "127.0.0.1", port: port) }

    func start() async throws {
        let listener = try NWListener(using: .tcp,
                                      on: listenPort.flatMap { NWEndpoint.Port(rawValue: $0) } ?? .any)
        self.listener = listener
        listener.newConnectionHandler = { connection in
            Task { await self.handle(connection) }
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let resumeOnce = ResumeOnce(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // Drop the handler before resuming: it must not outlive
                    // the wait. The ResumeOnce guard covers an update that was
                    // already in flight before the handler was cleared.
                    listener.stateUpdateHandler = nil
                    // Hop onto the actor so `port` is assigned before the
                    // continuation resumes — reading it earlier races to 0.
                    Task { await self.capturePortAndResume(resumeOnce) }
                case let .failed(error):
                    listener.stateUpdateHandler = nil
                    resumeOnce.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: DispatchQueue(label: "org.winnow.tests.loopback"))
        }
        computeFilters()
    }

    func stop() {
        connection?.cancel()
        listener?.cancel()
    }

    private func capturePortAndResume(_ resumeOnce: ResumeOnce) {
        port = listener?.port?.rawValue ?? 0
        resumeOnce.resume()
    }

    /// Sends any message from the node side (e.g. feefilter, getdata).
    func send(_ message: PeerMessage) async throws {
        guard let connection else { throw NodeError.failed("no connection") }
        let framed = MessageFramer.frame(command: message.command, payload: message.payload, magic: params.magic)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: framed, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }

    /// Removes and returns the first received message with this command,
    /// waiting up to `timeout` for it to arrive.
    func nextMessage(command: String, timeout: Duration = .seconds(10)) async -> PeerMessage? {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            if let index = inbox.firstIndex(where: { $0.command == command }) {
                return inbox.remove(at: index)
            }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return nil
    }

    // MARK: - Internals

    private func computeFilters() {
        var previous = Data(repeating: 0, count: 32)
        for block in chain {
            // BIP158 basic items; synthetic blocks have no spent-prevout data.
            let items = block.transactions
                .flatMap { $0.outputs.map(\.scriptPubKey) }
                .filter { !$0.isEmpty && $0.first != 0x6A }
            let filter = try! GCSFilter(items: items, key: block.hash.prefix(16)).serialized
            let filterHash = GCSFilter.filterHash(filter)
            let filterHeader = SHA256d.hash(filterHash + previous)
            filters.append(filter)
            filterHashes.append(filterHash)
            filterHeaders.append(filterHeader)
            previous = filterHeader
        }
        guard lieAboutFilterCommitments else { return }
        // Recompute a self-consistent but wrong commitment chain, so the lie
        // survives the client's own internal checks and can only be caught by
        // comparing against another peer.
        var lyingPrevious = Data(repeating: 0, count: 32)
        for index in filterHashes.indices {
            filterHashes[index][0] ^= 0xFF
            let header = SHA256d.hash(filterHashes[index] + lyingPrevious)
            filterHeaders[index] = header
            lyingPrevious = header
        }
    }

    private func handle(_ connection: NWConnection) async {
        self.connection = connection
        framer = MessageFramer(magic: params.magic)
        do {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                let resumeOnce = ResumeOnce(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        // Resume exactly once. Clearing the handler is not
                        // enough on its own: a .failed that was already in
                        // flight (e.g. ECONNRESET when the client drops the
                        // connection right after connect) is still delivered —
                        // the ResumeOnce guard makes that second resume a
                        // no-op instead of a fatal continuation misuse.
                        connection.stateUpdateHandler = nil
                        resumeOnce.resume()
                    case let .failed(error):
                        connection.stateUpdateHandler = nil
                        resumeOnce.resume(throwing: error)
                    default: break
                    }
                }
                connection.start(queue: DispatchQueue(label: "org.winnow.tests.loopback.conn"))
            }
            // A real node sends its version immediately on connect. The
            // optional test delay only controls deterministic pool ordering.
            if versionDelay > .zero { try await Task.sleep(for: versionDelay) }
            try await send(.version(nodeVersion()))
            while true {
                let chunk = try await receive(connection)
                framer.append(chunk)
                while let (command, payload) = try framer.nextMessage() {
                    let message = try PeerMessage.decode(command: command, payload: payload)
                    if case let .version(version) = message {
                        clientRelay = version.relay
                        try await send(.verack)
                        continue
                    }
                    inbox.append(message)
                    if case let .inv(payload) = message, let autoRequestDelay {
                        let vectors = payload.vectors.filter { $0.type.baseType == .tx }
                        if !vectors.isEmpty {
                            Task {
                                try? await Task.sleep(for: autoRequestDelay)
                                try? await self.send(.getdata(InventoryPayload(vectors)))
                            }
                        }
                    }
                    try await respond(to: message)
                }
            }
        } catch {
            // Client went away; nothing to do.
        }
    }

    private func nodeVersion() -> VersionMessage {
        VersionMessage(version: PeerConnection.protocolVersion,
                       services: services,
                       timestamp: Int64(Date().timeIntervalSince1970),
                       receiver: .unspecified,
                       sender: .unspecified,
                       nonce: 0x0102_0304_0506_0708,
                       userAgent: "/loopback-node:0.1/",
                       startHeight: Int32(max(0, chain.count - 1)),
                       relay: false)
    }

    private func receive(_ connection: NWConnection) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 22) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                } else if isComplete {
                    continuation.resume(throwing: NodeError.failed("closed"))
                } else {
                    continuation.resume(throwing: NodeError.failed("empty read"))
                }
            }
        }
    }

    private func height(ofHash hash: Data) -> Int? {
        chain.firstIndex { $0.hash == hash }
    }

    private func respond(to message: PeerMessage) async throws {
        switch message {
        case let .ping(nonce):
            try await send(.pong(nonce))

        case let .getheaders(request):
            // First matching locator wins; no match → from height 1.
            var start = 1
            for hash in request.locatorHashes {
                if let height = height(ofHash: hash) {
                    start = height + 1
                    break
                }
            }
            let end = min(start + HeaderChain.maxHeadersPerRequest, chain.count)
            let batch = start < end ? Array(chain[start ..< end].map(\.header)) : []
            try await send(.headers(batch))

        case let .getcfcheckpt(request):
            guard let stop = height(ofHash: request.stopHash) else { return }
            // Core's ProcessGetCFCheckPt: headers at heights 1000, 2000, …
            // ascending, capped at the stop height — the stop block itself is
            // included only when it is a checkpoint multiple.
            var headers: [Data] = []
            var height = Int(FilterSync.checkpointInterval)
            while height <= stop, height < filterHeaders.count {
                headers.append(filterHeaders[height])
                height += Int(FilterSync.checkpointInterval)
            }
            try await send(.cfcheckpt(CFCheckptMessage(stopHash: request.stopHash, filterHeaders: headers)))

        case let .getcfheaders(request):
            guard let stop = height(ofHash: request.stopHash) else { return }
            let start = Int(request.startHeight)
            guard start <= stop else { return }
            let previous = start == 0 ? Data(repeating: 0, count: 32) : filterHeaders[start - 1]
            try await send(.cfheaders(CFHeadersMessage(stopHash: request.stopHash,
                                                       previousFilterHeader: previous,
                                                       filterHashes: Array(filterHashes[start ... stop]))))

        case let .getcfilters(request):
            guard let stop = height(ofHash: request.stopHash) else { return }
            let start = Int(request.startHeight)
            guard start <= stop else { return }
            for height in start ... stop {
                var filter = filters[height]
                if height == corruptFilterAtHeight, !filter.isEmpty {
                    filter[filter.count - 1] ^= 0xFF // serve a lying filter
                }
                try await send(.cfilter(CFilterMessage(blockHash: chain[height].hash,
                                                       filter: filter)))
            }

        case let .getdata(payload):
            var notFound: [InventoryVector] = []
            for vector in payload.vectors {
                if vector.type.baseType == .block, let height = height(ofHash: vector.hash) {
                    try await send(.block(chain[height]))
                } else if vector.type.baseType == .tx {
                    if let transaction = transactions[vector.hash] {
                        try await send(.tx(transaction))
                    } else {
                        notFound.append(vector)
                    }
                }
            }
            if !notFound.isEmpty {
                try await send(.notfound(InventoryPayload(notFound)))
            }

        default:
            break
        }
    }
}
