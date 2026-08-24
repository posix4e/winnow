import BitcoinCore
import BitcoinP2P
import Foundation
import Testing
@testable import WalletCore

/// A wallet holding a silent-payment coin is refused, not opened.
///
/// Silent payments moved to the `alpha` branch. A coin received that way
/// carries a per-output tweak that is *required* to derive its signing key —
/// there is no fallback, because the key does not exist anywhere else.
///
/// The dangerous removal is the obvious one. `JSONDecoder` ignores keys it does
/// not know, so simply dropping `silentPaymentTweak` from `CodingKeys` would
/// let such a wallet open with the tweak silently discarded, leaving a coin
/// that looks ordinary, is signed down the BIP86 path, and produces a
/// valid-looking signature that can never be spent. The balance would be
/// wrong in the direction that costs money and says nothing.
///
/// So the field is still decoded here, for the sole purpose of refusing. That
/// is the whole reason the key survives in a build with no BIP352 code.
@Suite("Silent-payment wallet refusal")
struct SilentPaymentRefusalTests {
    private func stateJSON(withTweak: Bool) -> Data {
        let tweak = withTweak
            ? #","silentPaymentTweak":"\#(String(repeating: "ab", count: 32))""#
            : ""
        return Data("""
        {"descriptor":"tr(tpub)","network":"signet","creationHeight":100,
         "nextReceiveIndex":1,"nextChangeIndex":0,"nextScanHeight":200,
         "utxos":[{"txid":"\(String(repeating: "cd", count: 32))","vout":0,"amount":150000,
                   "scriptPubKey":"5120\(String(repeating: "ef", count: 32))",
                   "chain":0,"index":0,"height":101\(tweak)}],
         "history":[],"observedFeeRates":[]}
        """.utf8)
    }

    /// The refusal itself, and that it names something the user can act on.
    @Test("a wallet holding a silent-payment coin refuses to open")
    func silentPaymentWalletIsRefused() throws {
        var thrown: (any Error)?
        do {
            _ = try JSONDecoder().decode(WalletState.self, from: stateJSON(withTweak: true))
        } catch {
            thrown = error
        }
        let error = try #require(thrown as? WalletError)
        #expect(error == .silentPaymentWalletNeedsAlphaBuild)
        let message = try #require(error.errorDescription)
        #expect(message.lowercased().contains("alpha"),
                "the message must tell the user where the wallet can be opened")
    }

    /// The control. An ordinary wallet is untouched by any of this — if this
    /// failed, the refusal above would be proving nothing but a broken decoder.
    @Test("an ordinary wallet still opens")
    func ordinaryWalletOpens() throws {
        let state = try JSONDecoder().decode(WalletState.self, from: stateJSON(withTweak: false))
        #expect(state.utxos.count == 1)
        #expect(state.nextScanHeight == 200)
    }

    /// An import bundle carrying one is refused for the same reason: restoring
    /// it would recreate the unspendable coin in a fresh wallet.
    @Test("an import bundle claiming a silent-payment UTXO is refused")
    func bundleIsRefused() throws {
        let json = """
        {"version":2,"descriptor":"tr(tpub)","network":"signet","lastKnownHeight":200,
         "nextReceiveIndex":1,"nextChangeIndex":0,
         "utxos":[{"txid":"\(String(repeating: "cd", count: 32))","vout":0,"amount":150000,
                   "scriptPubKey":"5120\(String(repeating: "ef", count: 32))",
                   "chain":0,"index":0,"height":101,
                   "silentPaymentTweak":"\(String(repeating: "ab", count: 32))"}],
         "transactions":[]}
        """
        let bundle = try JSONDecoder().decode(ImportBundle.self, from: Data(json.utf8))
        #expect(throws: WalletError.silentPaymentWalletNeedsAlphaBuild) {
            _ = try bundle.claimedUTXOs()
        }
    }

    /// Paying *to* a silent-payment address is the one place a user meets the
    /// removal head-on, and the generic decoder called it invalid — which is
    /// false. The address is well-formed; this build just cannot pay it.
    @Test("an sp1 destination is named as a silent payment, not called invalid",
          arguments: ["sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
                      "tsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"])
    func silentPaymentDestinationIsNamed(address: String) throws {
        for network in [BitcoinNetwork.mainnet, .signet] {
            var thrown: (any Error)?
            do { _ = try AddressDecoder.scriptPubKey(for: address, network: network) }
            catch { thrown = error }
            let error = try #require(thrown as? AddressError)
            #expect(error == .silentPaymentAddress(address),
                    "got \(error) — an sp1 code reported as invalid tells the user a falsehood")
            let message = try #require(error.errorDescription)
            #expect(message.lowercased().contains("alpha"),
                    "the message must say where the feature went")
        }
    }

    /// The control: a genuinely malformed address must still be called
    /// invalid, or the case above is just swallowing every failure.
    @Test("a malformed address is still invalid")
    func malformedAddressStillInvalid() throws {
        var thrown: (any Error)?
        do { _ = try AddressDecoder.scriptPubKey(for: "bc1qnotarealaddress", network: .mainnet) }
        catch { thrown = error }
        #expect(thrown as? AddressError != nil)
        #expect((thrown as? AddressError).map { if case .silentPaymentAddress = $0 { false } else { true } } == true)
    }
}
