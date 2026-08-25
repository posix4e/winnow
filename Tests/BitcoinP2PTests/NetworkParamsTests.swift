import CryptoKit
import Foundation
import Testing
@testable import BitcoinP2P

/// Network constants against Bitcoin Core chainparams (v28.0), compact-target
/// math against known values, and the genesis chainwork known-answer.
@Suite("Network params & difficulty")
struct NetworkParamsTests {
    @Test("mainnet genesis header hash matches chainparams")
    func mainnetGenesis() {
        let genesis = HeaderChain.genesisHeader(for: .mainnet)
        #expect(genesis.hash == NetworkParams.mainnet.genesisHash)
        #expect(genesis.hash.displayHex ==
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
    }

    @Test("signet genesis header hash matches chainparams")
    func signetGenesis() {
        let genesis = HeaderChain.genesisHeader(for: .signet)
        #expect(genesis.hash == NetworkParams.signet.genesisHash)
        #expect(genesis.hash.displayHex ==
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
    }

    @Test("signet magic derives from the default BIP325 challenge")
    func signetMagicDerivation() {
        // chainparams.cpp: first 4 bytes of SHA256d(compactSize || challenge).
        var serialized = Data()
        serialized.appendCompactSize(UInt64(NetworkParams.signetChallenge.count))
        serialized.append(NetworkParams.signetChallenge)
        #expect(SHA256d.hash(serialized).prefix(4) == NetworkParams.signet.magic)
        #expect(NetworkParams.signet.magic == Data([0x0A, 0x03, 0xCF, 0x40]))
    }

    @Test("custom signet shares consensus fields, derives magic from its challenge")
    func customSignetParams() {
        // The BIP325 magic derivation applied to the default challenge must
        // reproduce the public signet magic.
        #expect(NetworkParams.signetMagic(challenge: NetworkParams.signetChallenge)
            == NetworkParams.signet.magic)

        // The differential fixture's challenge (scripts/signet-fixture).
        let challenge = Data(hex: "512102d4d3dfe322ab358061c7e08beebb48dc06a4c175342b975ecd0d55a79e6d6cdc51ae")!
        let custom = NetworkParams.customSignet(challenge: challenge, defaultPort: 38_401)
        // Verified against a live node running this challenge: the differential
        // suite completes a handshake with it, which it could not do if this
        // derivation and the node's own magic disagreed.
        #expect(custom.magic == Data(hex: "25a1f709"))
        #expect(custom.defaultPort == 38_401)
        #expect(custom.network == .signet)
        #expect(custom.genesisHash == NetworkParams.signet.genesisHash)
        #expect(custom.powLimit == NetworkParams.signet.powLimit)
        #expect(custom.dnsSeeds.isEmpty)
        #expect(HeaderChain.genesisHeader(for: custom).hash == custom.genesisHash)
    }

    @Test("default ports and magic", arguments: [
        (NetworkParams.mainnet, UInt16(8333), Data([0xF9, 0xBE, 0xB4, 0xD9])),
        (NetworkParams.signet, UInt16(38_333), Data([0x0A, 0x03, 0xCF, 0x40])),
    ])
    func portsAndMagic(params: NetworkParams, port: UInt16, magic: Data) {
        #expect(params.defaultPort == port)
        #expect(params.magic == magic)
        #expect(!params.dnsSeeds.isEmpty)
    }

    @Test("mainnet fallback peers are IP literals on :8333; signet has none")
    func fallbackPeersShape() {
        #expect(NetworkParams.mainnet.fallbackPeers.count >= 4)
        for peer in NetworkParams.mainnet.fallbackPeers {
            #expect(peer.port == 8_333)
            // Hardcoded entries must be public IP literals, never hostnames.
            // `netblock` is the pool's own parse: nil for a hostname and nil
            // for a non-public address, and unlike the old character check it
            // accepts the IPv6 literals the release-time generator (#161)
            // legitimately produces — hex digits broke a digits-and-dots test.
            #expect(peer.netblock != nil, "\(peer.host) is not a public IP literal")
        }
        #expect(NetworkParams.signet.fallbackPeers.isEmpty)
    }

    @Test("bits → target known values", arguments: [
        // (bits, big-endian target hex)
        (UInt32(0x1D00_FFFF), "00000000ffff0000000000000000000000000000000000000000000000000000"),
        (UInt32(0x1E03_77AE), "00000377ae000000000000000000000000000000000000000000000000000000"),
        (UInt32(0x207F_FFFF), "7fffff0000000000000000000000000000000000000000000000000000000000"),
        (UInt32(0x0100_3456), "0000000000000000000000000000000000000000000000000000000000000000"),
        (UInt32(0x0108_0000), "0000000000000000000000000000000000000000000000000000000000000008"),
    ])
    func bitsToTarget(bits: UInt32, expectedHex: String) {
        let target = UInt256.target(compact: bits)
        #expect(target?.bigEndianData.hex == expectedHex)
    }

    @Test("negative and overflowing compact targets are rejected", arguments: [
        UInt32(0x1D80_FFFF), // sign bit set
        UInt32(0x2300_0001), // size 35 > 34
        UInt32(0x2200_0100), // mantissa > 0xFF with size 34
        UInt32(0x2101_0000), // mantissa > 0xFFFF with size 33
    ])
    func invalidBits(bits: UInt32) {
        #expect(UInt256.target(compact: bits) == nil)
    }

    @Test("genesis chainwork is the known 0x0100010001")
    func genesisChainwork() async throws {
        let chain = try HeaderChain(params: .mainnet)
        #expect(await chain.height == 0)
        let work = await chain.tipWork
        #expect(work.hex == "0000000000000000000000000000000000000000000000000000000100010001")
    }

    @Test("block work arithmetic matches Core GetBlockProof")
    func blockWork() throws {
        let target = try #require(UInt256.target(compact: 0x1D00_FFFF))
        let work = try #require(UInt256.blockWork(target: target))
        #expect(work.bigEndianData.hex ==
            "0000000000000000000000000000000000000000000000000000000100010001")
    }
}
