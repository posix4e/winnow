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
    /// BIP352 codes: bech32m up to 1023 characters, two compressed keys.
    case silentPaymentAddress = "silent-payment-address"
    // What a Ledger sends: Bluetooth frames, client commands answered from
    // committed data, and yielded signatures. A hostile device must not crash
    // the app or draw an answer longer than one APDU.
    case ledger
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

func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw InvariantFailure(description: message) }
}

/// Feeds `data` to one target's parser and checks that target's invariant.
/// Throws on an invariant failure; the harness and the regression tests treat
/// any error from here as a finding. Each target's check is its own function,
/// so this one only routes.
public func exercise(_ target: FuzzTarget, data: Data, rng: inout SplitMix64) throws {
    switch target {
    case .psbt: try exercisePSBT(data)
    case .descriptor: try exerciseDescriptor(data)
    case .transaction: try exerciseTransaction(data)
    case .block: try exerciseBlock(data)
    case .messages: try exerciseMessages(data)
    case .framing: try exerciseFraming(data, rng: &rng)
    case .filter: try exerciseFilter(data)
    case .address: try exerciseAddress(data)
    case .importBundle: try exerciseImportBundle(data)
    case .census: try exerciseCensus(data)
    case .dnsJSON: _ = try? DNSJSON.hosts(from: data)
    case .fundingSources: exerciseFundingSources(data)
    case .controlBlock: try exerciseControlBlock(data)
    case .personPaste: try exercisePersonPaste(data)
    case .silentPaymentAddress: try exerciseSilentPaymentAddress(data)
    case .ledger: try exerciseLedger(data, rng: &rng)
    }
}

private func exercisePSBT(_ data: Data) throws {
    if let parsed = try? PSBT(serialized: data) {
        try require(try PSBT(serialized: parsed.serialized) == parsed, "PSBT canonical round trip changed semantics")
        try require(try PSBT(base64: parsed.base64) == parsed, "PSBT Base64 round trip changed semantics")
    }
}

private func exerciseDescriptor(_ data: Data) throws {
    if let parsed = try? Descriptor(String(decoding: data, as: UTF8.self)) {
        try require(try Descriptor(parsed.serialized()) == parsed, "descriptor canonical round trip changed semantics")
        // Derivation is where a parseable-but-malformed descriptor used to
        // trap (a second multipath element narrower than the first). A
        // throw is an acceptable answer here; a crash is not.
        _ = try? parsed.derived(index: 0)
    }
}

private func exerciseTransaction(_ data: Data) throws {
    if let parsed = try? Transaction.decode(data) {
        try require(try Transaction.decode(parsed.serialized(includeWitness: true)) == parsed,
                    "transaction canonical round trip changed semantics")
    }
}

private func exerciseBlock(_ data: Data) throws {
    if let parsed = try? Block.decode(data) {
        try require(try Block.decode(parsed.serialized) == parsed, "block canonical round trip changed semantics")
    }
}

private func exerciseMessages(_ data: Data) throws {
    let commands = ["version", "verack", "ping", "pong", "sendheaders", "feefilter", "inv", "getdata",
                    "notfound", "tx", "block", "getheaders", "headers", "getcfilters", "cfilter",
                    "getcfheaders", "cfheaders", "getcfcheckpt", "cfcheckpt", "addr", "getaddr"]
    for command in commands {
        if let parsed = try? PeerMessage.decode(command: command, payload: data) {
            try require(try PeerMessage.decode(command: parsed.command, payload: parsed.payload) == parsed,
                        "\(command) message canonical round trip changed semantics")
        }
    }
}

private func exerciseFraming(_ data: Data, rng: inout SplitMix64) throws {
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
}

private func exerciseFilter(_ data: Data) throws {
    var reader = ByteReader(data)
    if let count = try? reader.readVarInt(), count <= UInt64(UInt32.max) {
        let encoded = data.subdata(in: data.startIndex + reader.offset ..< data.endIndex)
        if let filter = try? GCSFilter(key: Data(repeating: 0, count: 16), n: UInt32(count), encoded: encoded) {
            _ = filter.matchAny([data.prefix(32), Data([0]), Data()])
            try require(filter.serialized == data, "GCS filter canonical round trip changed bytes")
        }
    }
}

private func exerciseAddress(_ data: Data) throws {
    let string = String(decoding: data, as: UTF8.self)
    for network in [BitcoinNetwork.mainnet, .signet] {
        if let script = try? AddressDecoder.scriptPubKey(for: string, network: network) {
            try require(script.count <= 42, "address produced an oversized standard script")
        }
    }
}

/// A code that parses must re-encode to itself (lower-cased: bech32m accepts
/// either case) and carry two 33-byte keys; the decoder's length bound is the
/// BIP352 one, not BIP173's 90 characters.
private func exerciseSilentPaymentAddress(_ data: Data) throws {
    let text = String(decoding: data, as: UTF8.self)
    if let parsed = try? SilentPaymentAddress(text) {
        try require(parsed.scanKey.count == 33 && parsed.spendKey.count == 33, "silent payment code with malformed keys")
        try require(try parsed.encoded == text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                    "silent payment code did not round-trip")
        try require(text.count <= SilentPaymentAddress.maxAddressLength, "silent payment code over the length bound")
    }
}

private func exerciseImportBundle(_ data: Data) throws {
    guard data.count <= 4_000_000, let bundle = try? JSONDecoder().decode(ImportBundle.self, from: data) else { return }
    let serialized = try bundle.serialized()
    try require(try JSONDecoder().decode(ImportBundle.self, from: Data(serialized.utf8)) == bundle,
                "import bundle canonical round trip changed semantics")
    _ = try? bundle.claimedUTXOs()
}

/// Freshness is a matter of the clock, not of parsing, so any observation
/// date is admitted here.
private func exerciseCensus(_ data: Data) throws {
    if let catalog = try? CensusCatalog.decode(data) {
        let encoded = try JSONEncoder().encode(catalog)
        try require(try CensusCatalog.decode(encoded) == catalog,
                    "census catalog canonical round trip changed semantics")
    }
}

private func exerciseFundingSources(_ data: Data) {
    if let parsed = try? Transaction.decode(data) {
        _ = FundingSources.sources(of: parsed)
        _ = FundingSources.fundingScripts(of: parsed)
    }
}

private func exerciseControlBlock(_ data: Data) throws {
    if let parsed = try? Taproot.ControlBlock(serialized: data) {
        try require(parsed.serialized == data, "control block canonical round trip changed bytes")
    }
}

private func exercisePersonPaste(_ data: Data) throws {
    let text = String(decoding: data, as: UTF8.self)
    for network in [BitcoinNetwork.mainnet, .signet] {
        _ = try? PersonPaste.parse(text, network: network)
    }
    if let card = try? PersonCard.decode(text) {
        try require(try PersonCard.decode(card.serialized()) == card,
                    "person card canonical round trip changed semantics")
    }
}

/// A committed preimage, list and map for the interpreter to answer from.
private func ledgerInterpreter() -> LedgerClientCommandInterpreter {
    var interpreter = LedgerClientCommandInterpreter()
    interpreter.addKnownPreimage(Data("winnow".utf8))
    interpreter.addKnownPreimage(Data(repeating: 0x5A, count: 600))
    interpreter.addKnownList((0 ..< 100).map { Data([UInt8($0)]) })
    interpreter.addKnownMapping([PSBT.KeyValue(type: 0x01, value: Data(repeating: 7, count: 300))])
    return interpreter
}

private func exerciseLedger(_ data: Data, rng: inout SplitMix64) throws {
    // Notifications cut wherever the generator says.
    var reassembler = LedgerBluetoothFraming.Reassembler()
    var offset = 0
    while offset < data.count {
        let length = min(data.count - offset, 1 + rng.index(40))
        if let reply = try? reassembler.receive(data.subdata(in: offset ..< offset + length)) {
            try require(reply.count <= Int(UInt16.max), "a reassembled reply longer than its length field")
        }
        offset += length
    }
    // The input as one client command, then as the follow-up requests the
    // device would send to drain a queue.
    var interpreter = ledgerInterpreter()
    var request = data
    for _ in 0 ..< 12 {
        guard let answer = try? interpreter.execute(request) else { break }
        try require(answer.count <= LedgerClientCommandInterpreter.maximumResponse,
                    "a client-command answer longer than one APDU")
        request = Data([0xA0])
    }
    if let signature = try? LedgerBitcoinClient.signature(fromYield: data, inputCount: 4) {
        try require(signature.inputIndex < 4, "a yielded signature for an input that does not exist")
        try require([32, 33].contains(signature.publicKey.count) || signature.leafHash?.count == 32,
                    "a yielded signature with a malformed key")
    }
}
