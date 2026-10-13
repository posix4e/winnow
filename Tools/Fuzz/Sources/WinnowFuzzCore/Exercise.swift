import WalletCore
import Foundation

/// The parsing surfaces the harness mutates inputs for. The raw values are
/// the `--target` names and the `Tests/ToolsTests/Cases/` directories.
public enum FuzzTarget: String, CaseIterable, Sendable {
    case psbt
    case descriptor
    case transaction
    case block
    case messages
    case framing
    case filter
    case address
    case importBundle = "import"
    // The parsers added after the August audit (IR-030). What the harness
    // cannot reach: `PeopleStore`, `ReceiveAddressLabelStore` and
    // `SealedStoreFile` live in the app target, and `PersistedPeers` is
    // internal to WalletCore; those are covered by AppTests and the package
    // suite with hand-written hostile inputs instead.
    case census
    case dnsJSON = "dns-json"
    case fundingSources = "funding-sources"
    case controlBlock = "control-block"
    case personPaste = "person-paste"
}

/// The harness's generator. `exercise` draws from it too, to vary how the
/// framing target feeds bytes in, so it lives beside the invariants.
public struct SplitMix64 {
    public var state: UInt64

    public init(state: UInt64) {
        self.state = state
    }

    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }

    public mutating func index(_ upperBound: Int) -> Int {
        guard upperBound > 0 else { return 0 }
        return Int(next() % UInt64(upperBound))
    }
}

/// A parser accepted an input and its canonical form then changed meaning,
/// or a result broke a bound the wallet relies on. Refusing to parse is not
/// one of these; a trap is not either, it is a crash.
public struct InvariantFailure: Error, CustomStringConvertible {
    public let description: String
}

private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw InvariantFailure(description: message) }
}

/// Feeds `data` to one target's parser and checks that target's invariant.
/// Throws on an invariant failure; the harness and the regression tests treat
/// any error from here as a finding.
public func exercise(_ target: FuzzTarget, data: Data, rng: inout SplitMix64) throws {
    switch target {
    case .psbt:
        if let parsed = try? PSBT(serialized: data) {
            try require(try PSBT(serialized: parsed.serialized) == parsed, "PSBT canonical round trip changed semantics")
            try require(try PSBT(base64: parsed.base64) == parsed, "PSBT Base64 round trip changed semantics")
        }
    case .descriptor:
        if let parsed = try? Descriptor(String(decoding: data, as: UTF8.self)) {
            try require(try Descriptor(parsed.serialized()) == parsed, "descriptor canonical round trip changed semantics")
            // Derivation is where a parseable-but-malformed descriptor used to
            // trap (a second multipath element narrower than the first). A
            // throw is an acceptable answer here; a crash is not.
            _ = try? parsed.derived(index: 0)
        }
    case .transaction:
        if let parsed = try? Transaction.decode(data) {
            try require(try Transaction.decode(parsed.serialized(includeWitness: true)) == parsed,
                        "transaction canonical round trip changed semantics")
        }
    case .block:
        if let parsed = try? Block.decode(data) {
            try require(try Block.decode(parsed.serialized) == parsed, "block canonical round trip changed semantics")
        }
    case .messages:
        let commands = ["version", "verack", "ping", "pong", "sendheaders", "feefilter", "inv", "getdata",
                        "notfound", "tx", "block", "getheaders", "headers", "getcfilters", "cfilter",
                        "getcfheaders", "cfheaders", "getcfcheckpt", "cfcheckpt", "addr", "getaddr"]
        for command in commands {
            if let parsed = try? PeerMessage.decode(command: command, payload: data) {
                try require(try PeerMessage.decode(command: parsed.command, payload: parsed.payload) == parsed,
                            "\(command) message canonical round trip changed semantics")
            }
        }
    case .framing:
        var framer = MessageFramer(magic: Data([0x0A, 0x03, 0xCF, 0x40]))
        var offset = 0
        while offset < data.count {
            let length = min(data.count - offset, 1 + rng.index(31))
            framer.append(data.subdata(in: offset ..< offset + length))
            offset += length
        }
        var decoded = 0
        while true {
            let next: (command: String, payload: Data)?
            do {
                next = try framer.nextMessage()
            } catch {
                break
            }
            guard let message = next else { break }
            let reframed = MessageFramer.frame(command: message.command, payload: message.payload, magic: framer.magic)
            var check = MessageFramer(magic: framer.magic)
            check.append(reframed)
            let roundTrip = try check.nextMessage()
            try require(roundTrip?.command == message.command && roundTrip?.payload == message.payload,
                        "framed message did not round trip")
            decoded += 1
            if decoded == 32 { break }
        }
    case .filter:
        var reader = ByteReader(data)
        if let count = try? reader.readVarInt(), count <= UInt64(UInt32.max) {
            let encoded = data.subdata(in: data.startIndex + reader.offset ..< data.endIndex)
            if let filter = try? GCSFilter(key: Data(repeating: 0, count: 16), n: UInt32(count), encoded: encoded) {
                _ = filter.matchAny([data.prefix(32), Data([0]), Data()])
                try require(filter.serialized == data, "GCS filter canonical round trip changed bytes")
            }
        }
    case .address:
        let string = String(decoding: data, as: UTF8.self)
        for network in [BitcoinNetwork.mainnet, .signet] {
            if let script = try? AddressDecoder.scriptPubKey(for: string, network: network) {
                try require(script.count <= 42, "address produced an oversized standard script")
            }
        }
    case .importBundle:
        guard data.count <= 4_000_000, let bundle = try? JSONDecoder().decode(ImportBundle.self, from: data) else { return }
        let serialized = try bundle.serialized()
        try require(try JSONDecoder().decode(ImportBundle.self, from: Data(serialized.utf8)) == bundle,
                    "import bundle canonical round trip changed semantics")
        _ = try? bundle.claimedUTXOs()
    case .census:
        // Freshness is a matter of the clock, not of parsing, so any
        // observation date is admitted here.
        if let catalog = try? CensusCatalog.decode(data) {
            let encoded = try JSONEncoder().encode(catalog)
            try require(try CensusCatalog.decode(encoded) == catalog,
                        "census catalog canonical round trip changed semantics")
        }
    case .dnsJSON:
        _ = try? DNSJSON.hosts(from: data)
    case .fundingSources:
        if let parsed = try? Transaction.decode(data) {
            _ = FundingSources.sources(of: parsed)
            _ = FundingSources.fundingScripts(of: parsed)
        }
    case .controlBlock:
        if let parsed = try? Taproot.ControlBlock(serialized: data) {
            try require(parsed.serialized == data, "control block canonical round trip changed bytes")
        }
    case .personPaste:
        let text = String(decoding: data, as: UTF8.self)
        for network in [BitcoinNetwork.mainnet, .signet] {
            _ = try? PersonPaste.parse(text, network: network)
            _ = try? SharedSavingsCard.decode(text, network: network)
        }
        if let card = try? PersonCard.decode(text) {
            try require(try PersonCard.decode(card.serialized()) == card,
                        "person card canonical round trip changed semantics")
        }
    }
}
