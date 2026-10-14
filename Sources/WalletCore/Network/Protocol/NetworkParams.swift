import Foundation

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
    public let powTargetTimespan: UInt32
    public let powTargetSpacing: UInt32
    public var difficultyAdjustmentInterval: UInt32 { powTargetTimespan / powTargetSpacing }
    public let dnsSeeds: [String]
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

    public let noRetargeting: Bool

    public init(network: BitcoinNetwork, magic: Data, defaultPort: UInt16,
                genesisTime: UInt32, genesisBits: UInt32, genesisNonce: UInt32,
                genesisMerkleRoot: Data, genesisHash: Data, powLimit: Data,
                dnsSeeds: [String],
                checkpoint: Checkpoint? = nil,
                powTargetTimespan: UInt32 = 14 * 24 * 60 * 60,
                powTargetSpacing: UInt32 = 600, noRetargeting: Bool = false) {
        precondition(powTargetTimespan >= 4 && powTargetTimespan <= UInt32.max / 4)
        precondition(powTargetSpacing > 0 && powTargetTimespan % powTargetSpacing == 0)
        self.noRetargeting = noRetargeting
        self.network = network
        self.magic = magic
        self.defaultPort = defaultPort
        self.genesisTime = genesisTime
        self.genesisBits = genesisBits
        self.genesisNonce = genesisNonce
        self.genesisMerkleRoot = genesisMerkleRoot
        self.genesisHash = genesisHash
        self.powLimit = powLimit
        self.powTargetTimespan = powTargetTimespan
        self.powTargetSpacing = powTargetSpacing
        self.dnsSeeds = dnsSeeds
        self.checkpoint = checkpoint
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
        case .regtest: return .regtest
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
        // Derived, not asserted. Winnow synced mainnet from genesis on
        // 2026-08-19, proof-of-work-checking every header, and on 2026-09-14
        // `winnow-debug generate checkpoint` re-derived the three values below
        // from that same file at height 959,616 — a difficulty-period boundary
        // (476 × 2016), so the first retarget after the checkpoint, at
        // 961,632, is verified exactly rather than only bounded; the previous
        // constant at 900,000 sat mid-period and left 901,152 unverifiable.
        //
        // Taken from a chain of 963,233 headers whose tip was height 963,232,
        // 000000000000000000016813353d83651497417cc705d1e2caf46a541e81deef.
        // The generator proved the genesis-rooted and checkpoint-rooted chains
        // agree through 961,616, work
        // 00000000000000000000000000000000000000013df5cdb426e62d5b7ec17987.
        //
        // To reproduce, point `scripts/refresh-checkpoint` at a genesis-validated
        // header file: `winnow-debug generate checkpoint` recomputes all three through
        // the same loading path the app uses, prints the lines below ready to
        // paste, and proves a chain started from them agrees with the
        // genesis-rooted chain 2,000 blocks on (Tools/Generate/README.md).
        // Those 2,000 headers are the vector `HeaderChainTests` replays.
        //
        // Note the two hex spellings below are not interchangeable:
        // `Data(hex:)` keeps byte order, `Data(displayHex:)` reverses it. The
        // header is wire bytes and the chainwork is big-endian, so both take
        // `hex:`; using `displayHex:` for the work would store it backwards and
        // every fork-choice comparison against it would be meaningless.
        //
        // Block 959,616 hash, display order:
        //   00000000000000000000eec74314bff05daf67223b96a1a2c3452ac418424d13
        checkpoint: Checkpoint(
            height: 959_616,
            header: Data(hex:
                "0000a03d32cf5172fa1b0614ac95b2bd9e965e644866cfc3f71701000000000000000000"
                + "723f3173aa33f0644ab1294973f345eb428455c7d0fd7f50bc4252c1c7300d3f"
                + "da3d656ad43a02170a17b1ae")!,
            chainwork: Data(hex:
                "00000000000000000000000000000000000000013a74dc6d1ab305ff3e4295d7")!
        )
    )

    /// Regtest, as Core's `chainparams.cpp` defines it: the genesis block
    /// shares mainnet's merkle root, its own time, bits and nonce, the
    /// lowest possible difficulty, and no seeds of any kind.
    public static let regtest = NetworkParams(
        network: .regtest,
        magic: Data([0xFA, 0xBF, 0xB5, 0xDA]),
        defaultPort: 18_444,
        genesisTime: 1_296_688_602,
        genesisBits: 0x207F_FFFF,
        genesisNonce: 2,
        genesisMerkleRoot: genesisMerkleRoot,
        genesisHash: Data(displayHex: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"),
        powLimit: Data(displayHex: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        dnsSeeds: [],
        noRetargeting: true
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
