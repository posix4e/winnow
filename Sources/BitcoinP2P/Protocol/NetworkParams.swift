import Foundation

/// Bitcoin network identifier. Regtest is omitted intentionally: this client
/// targets mainnet and the public default signet (BIP325).
public enum BitcoinNetwork: String, Sendable, CaseIterable {
    case mainnet
    case signet
}

/// Static per-network parameters, sourced from Bitcoin Core's
/// `src/kernel/chainparams.cpp` (v28.0). All hashes are stored in internal
/// (little-endian) byte order — the order they appear on the wire.
public struct NetworkParams: Sendable, Equatable {
    public let network: BitcoinNetwork
    /// 4-byte message-start magic prefixing every frame.
    public let magic: Data
    public let defaultPort: UInt16
    /// Genesis block header fields (used to derive the genesis hash).
    public let genesisTime: UInt32
    public let genesisBits: UInt32
    public let genesisNonce: UInt32
    public let genesisMerkleRoot: Data
    /// Expected genesis block hash (chainparams.cpp assert), for self-checks.
    public let genesisHash: Data
    /// Consensus powLimit (maximum valid target), 32-byte internal byte order.
    public let powLimit: Data
    public let dnsSeeds: [String]
    /// Hardcoded last-resort peers (IP literals, verified filter-serving —
    /// see the per-network value's comment). Dialed alongside the DNS-seed
    /// results so a fresh launch works even when seed results are dead.
    public let fallbackPeers: [PeerEndpoint]
    /// Optional trusted start for header sync (#89). Present only where
    /// syncing from genesis is slow enough to matter, which today is mainnet.
    public let checkpoint: Checkpoint?

    /// A header far enough back to be settled, with the cumulative work of
    /// everything before it — the one number that cannot be recomputed from a
    /// chain that does not contain those headers.
    ///
    /// Starting here means trusting these bytes instead of deriving them.
    /// Everything after the checkpoint is validated exactly as before, and the
    /// constant is auditable: sync from genesis and compare.
    public struct Checkpoint: Sendable, Equatable {
        public let height: UInt32
        /// The 80-byte header, serialized.
        public let header: Data
        /// Cumulative chainwork through `height`, big-endian.
        public let chainwork: Data

        public init(height: UInt32, header: Data, chainwork: Data) {
            precondition(header.count == 80 && chainwork.count == 32)
            self.height = height
            self.header = header
            self.chainwork = chainwork
        }
    }

    public init(network: BitcoinNetwork, magic: Data, defaultPort: UInt16,
                genesisTime: UInt32, genesisBits: UInt32, genesisNonce: UInt32,
                genesisMerkleRoot: Data, genesisHash: Data, powLimit: Data,
                dnsSeeds: [String], fallbackPeers: [PeerEndpoint] = [],
                checkpoint: Checkpoint? = nil) {
        self.network = network
        self.magic = magic
        self.defaultPort = defaultPort
        self.genesisTime = genesisTime
        self.genesisBits = genesisBits
        self.genesisNonce = genesisNonce
        self.genesisMerkleRoot = genesisMerkleRoot
        self.genesisHash = genesisHash
        self.powLimit = powLimit
        self.dnsSeeds = dnsSeeds
        self.checkpoint = checkpoint
        self.fallbackPeers = fallbackPeers
    }

    /// Custom BIP325 signets (magic ≠ public signet) may keep RFC1918 /
    /// loopback seed answers — that is how a laptop-hosted signet is reached.
    /// Public networks drop them so a poisoned resolver cannot park the
    /// whole pool on attacker-controlled LAN addresses.
    public var isCustomSignet: Bool {
        network == .signet && magic != Self.signet.magic
    }

    public var allowsPrivateSeedAddresses: Bool { isCustomSignet }

    public static func params(for network: BitcoinNetwork) -> NetworkParams {
        switch network {
        case .mainnet: return .mainnet
        case .signet: return .signet
        }
    }

    /// Parameters for a custom BIP325 signet. All signets share the default
    /// signet's consensus fields (genesis block, powLimit); what changes with
    /// the challenge is the network magic: the first 4 bytes of
    /// SHA256d(compactSize(length) ‖ challenge) (BIP325, chainparams.cpp
    /// SignetParams). Custom signets have no DNS seeds — peers come from
    /// `PeerPool(manualPeers:)`.
    public static func customSignet(challenge: Data, defaultPort: UInt16 = 38_333) -> NetworkParams {
        precondition(!challenge.isEmpty, "signet challenge must not be empty")
        return NetworkParams(
            network: .signet,
            magic: signetMagic(challenge: challenge),
            defaultPort: defaultPort,
            genesisTime: signet.genesisTime,
            genesisBits: signet.genesisBits,
            genesisNonce: signet.genesisNonce,
            genesisMerkleRoot: signet.genesisMerkleRoot,
            genesisHash: signet.genesisHash,
            powLimit: signet.powLimit,
            dnsSeeds: []
        )
    }

    /// BIP325 network magic for a signet challenge: the first 4 bytes of
    /// SHA256d of the script serialized with its compactSize length prefix.
    /// Yields 0A03CF40 for the default challenge — the public signet magic.
    static func signetMagic(challenge: Data) -> Data {
        var serialized = Data()
        serialized.appendCompactSize(UInt64(challenge.count))
        serialized.append(challenge)
        return Data(SHA256d.hash(serialized).prefix(4))
    }

    /// The default BIP325 signet challenge (2-of-2 multisig script).
    /// The signet network magic is defined as the first 4 bytes of the
    /// SHA256d of this script, serialized with its compactSize length prefix.
    public static let signetChallenge = Data([
        0x51, 0x21, 0x03, 0xad, 0x5e, 0x0e, 0xda, 0xd1, 0x8c, 0xb1, 0xf0, 0xfc,
        0x0d, 0x28, 0xa3, 0xd4, 0xf1, 0xf3, 0xe4, 0x45, 0x64, 0x03, 0x37, 0x48,
        0x9a, 0xbb, 0x10, 0x40, 0x4f, 0x2d, 0x1e, 0x08, 0x6b, 0xe4, 0x30, 0x21,
        0x03, 0x59, 0xef, 0x50, 0x21, 0x96, 0x4f, 0xe2, 0x2d, 0x6f, 0x8e, 0x05,
        0xb2, 0x46, 0x3c, 0x95, 0x40, 0xce, 0x96, 0x88, 0x3f, 0xe3, 0xb2, 0x78,
        0x76, 0x0f, 0x04, 0x8f, 0x51, 0x89, 0xf2, 0xe6, 0xc4, 0x52, 0xae,
    ])

    /// Mainnet genesis merkle root (display hex 4a5e1e4b…deda33b), internal order.
    private static let genesisMerkleRoot = Data([
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e,
        0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
        0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
    ])

    public static let mainnet = NetworkParams(
        network: .mainnet,
        magic: Data([0xF9, 0xBE, 0xB4, 0xD9]),
        defaultPort: 8333,
        genesisTime: 1_231_006_505,
        genesisBits: 0x1D00_FFFF,
        genesisNonce: 2_083_236_893,
        genesisMerkleRoot: genesisMerkleRoot,
        genesisHash: Data(displayHex: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
        powLimit: Data(displayHex: "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        dnsSeeds: [
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.net",
            "seed.bitcoin.sprovoost.nl",
            "dnsseed.emzy.de",
            "seed.bitcoin.wiz.biz",
            "seed.mainnet.achownodes.xyz",
        ],
        // Generated at release time rather than curated by hand (#161): a
        // static public list ages from the day it is written, and #159's
        // source ceiling made the bundled class what fills a pool slot on an
        // ordinary launch. See FallbackPeersGenerated.swift for provenance
        // and for what generation deliberately does not claim.
        fallbackPeers: generatedMainnetFallbackPeers,
        // Derived, not asserted. Winnow synced mainnet from genesis on
        // 2026-08-19, proof-of-work-checking every one of the 900,001 headers
        // up to this height, and emitted the three values below. The block hash
        // was then confirmed against three independent mainnet peers, which all
        // returned the same header for height 900,000.
        //
        // Taken from a chain of 963,233 headers whose tip was height 963,232,
        // 000000000000000000016813353d83651497417cc705d1e2caf46a541e81deef.
        //
        // To reproduce, point the generator at a genesis-validated header file
        // and it recomputes all three through the same loading path the app
        // uses (`swift test --filter CheckpointGenerator`, with
        // WINNOW_HEADERS_BIN set — see the test for what it does).
        //
        // Block 900,000 hash, display order:
        //   000000000000000000010538edbfd2d5b809a33dd83f284aeea41c6d0d96968a
        //
        // Note the two hex spellings below are not interchangeable:
        // `Data(hex:)` keeps byte order, `Data(displayHex:)` reverses it. The
        // header is wire bytes and the chainwork is big-endian, so both take
        // `hex:`; using `displayHex:` for the work would store it backwards and
        // every fork-choice comparison against it would be meaningless.
        checkpoint: Checkpoint(
            height: 900_000,
            header: Data(hex:
                "00a0ab20247d4d9f582f9750344cdf62c46d81d046be9603409601000000000000000000"
                + "70f96945530651135839d8adc3f40e595118ec74c7ad81a3d17bb022e554fb0c"
                + "937f4268743702177ad05f92")!,
            chainwork: Data(hex:
                "0000000000000000000000000000000000000000c8bbeae4127a204b0317861c")!
        )
    )

    public static let signet = NetworkParams(
        network: .signet,
        magic: Data([0x0A, 0x03, 0xCF, 0x40]),
        defaultPort: 38333,
        genesisTime: 1_598_918_400,
        genesisBits: 0x1E03_77AE,
        genesisNonce: 52_613_770,
        genesisMerkleRoot: genesisMerkleRoot,
        genesisHash: Data(displayHex: "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"),
        powLimit: Data(displayHex: "00000377ae000000000000000000000000000000000000000000000000000000"),
        dnsSeeds: [
            "seed.signet.bitcoin.sprovoost.nl",
            "seed.signet.achownodes.xyz",
        ]
    )
}

extension Data {
    /// Interprets a display-order (big-endian) hex hash as internal byte order.
    init(displayHex: String) {
        var bytes = Data()
        bytes.reserveCapacity(displayHex.count / 2)
        var index = displayHex.startIndex
        while index < displayHex.endIndex {
            let next = displayHex.index(index, offsetBy: 2)
            bytes.append(UInt8(displayHex[index ..< next], radix: 16)!)
            index = next
        }
        self.init(bytes.reversed())
    }

    /// Internal-order hash rendered as display-order hex.
    public var displayHex: String {
        reversed().map { String(format: "%02x", $0) }.joined()
    }
}
