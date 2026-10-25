import Foundation
import Testing
@testable import WalletCore

/// Legacy per-output signing data must never be silently discarded. Keep the
/// literal serialized key in these fixtures so removing its decoder guard fails.
@Suite("Unsupported wallet data")
struct UnsupportedWalletDataTests {
    private func stateJSON(tweak: String? = nil) -> Data {
        let field = tweak.map { #","silentPaymentTweak":\#($0)"# } ?? ""
        return Data("""
        {"descriptor":"tr(tpub)","network":"signet","creationHeight":100,
         "nextReceiveIndex":1,"nextChangeIndex":0,"nextScanHeight":200,
         "utxos":[{"txid":"\(String(repeating: "cd", count: 32))","vout":0,"amount":150000,
                   "scriptPubKey":"5120\(String(repeating: "ef", count: 32))",
                   "chain":0,"index":0,"height":101\(field)}],
         "history":[],"observedFeeRates":[]}
        """.utf8)
    }

    @Test("legacy wallet signing data is refused, even null or malformed",
          arguments: [#""abababababababababababababababababababababababababababababababab""#,
                      "null", "{}"])
    func legacyWalletIsRefused(tweak: String) throws {
        #expect(throws: WalletError.unsupportedWalletData) {
            _ = try JSONDecoder().decode(WalletState.self, from: stateJSON(tweak: tweak))
        }
    }

    @Test("ordinary wallet state opens and round-trips without legacy metadata")
    func ordinaryWalletOpens() throws {
        let state = try JSONDecoder().decode(WalletState.self, from: stateJSON())
        #expect(state.utxos.count == 1)
        #expect(state.nextScanHeight == 200)
        let encoded = try JSONEncoder().encode(state)
        #expect(!String(decoding: encoded, as: UTF8.self).contains("silentPaymentTweak"))
        let restored = try JSONDecoder().decode(WalletState.self, from: encoded)
        #expect(restored.utxos == state.utxos)
    }

    @Test("import bundles with legacy signing data are refused", arguments: [1, 2])
    func bundleIsRefused(version: Int) throws {
        let json = """
        {"version":\(version),"descriptor":"tr(tpub)","network":"signet","lastKnownHeight":200,
         "nextReceiveIndex":1,"nextChangeIndex":0,
         "utxos":[{"txid":"\(String(repeating: "cd", count: 32))","vout":0,"amount":150000,
                   "scriptPubKey":"5120\(String(repeating: "ef", count: 32))",
                   "chain":0,"index":0,"height":101,
                   "silentPaymentTweak":"\(String(repeating: "ab", count: 32))"}],
         "transactions":[]}
        """
        let bundle = try JSONDecoder().decode(ImportBundle.self, from: Data(json.utf8))
        #expect(throws: WalletError.unsupportedWalletData) {
            _ = try bundle.claimedUTXOs()
        }
    }

    @Test("unsupported destinations cannot become payment scripts",
          arguments: ["bc1qnotarealaddress", "not-an-address"])
    func unsupportedDestinationIsRefused(address: String) throws {
        for network in [BitcoinNetwork.mainnet, .signet] {
            #expect(throws: AddressError.self) {
                _ = try Payment(amount: 1_000, address: address, network: network)
            }
        }
    }

    /// A silent payment code is not an address: `Payment` still refuses it,
    /// because its script does not exist until the paying inputs are chosen.
    /// It is a `SilentPayment`, on the network its prefix names.
    @Test("a silent payment code is a silent payment, not an address")
    func silentPaymentCodeIsASilentPayment() throws {
        let mainnet = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
        let signet = "tsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
        for code in [mainnet, signet] {
            for network in [BitcoinNetwork.mainnet, .signet] {
                #expect(throws: AddressError.self) {
                    _ = try Payment(amount: 1_000, address: code, network: network)
                }
            }
        }
        #expect(try SilentPayment(amount: 1_000, address: mainnet, network: .mainnet).amount == 1_000)
        #expect(throws: SilentPaymentAddressError.wrongHRP(expected: "tsp", actual: "sp")) {
            _ = try SilentPayment(amount: 1_000, address: mainnet, network: .signet)
        }
        // The test code's checksum is for a different HRP: a code that does not
        // verify is refused before any key is read.
        #expect(throws: SilentPaymentAddressError.self) {
            _ = try SilentPayment(amount: 1_000, address: signet, network: .signet)
        }
    }
}
