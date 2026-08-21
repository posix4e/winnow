import BitcoinCore
import Foundation
import Testing
@testable import WalletCore

/// Bounds and decoding semantics for imported bundles
/// (epic #100, invariants S7 and S10).
///
/// A bundle is the one input a user is actively invited to paste from
/// anywhere. Two of the properties it relies on are Foundation's, not
/// Winnow's: `JSONDecoder` refuses deeply nested JSON, and it resolves a
/// duplicate key to its *first* occurrence. Both are undocumented defaults.
/// They are pinned here so that a Foundation change cannot quietly alter what
/// a bundle means — a duplicate `network` key silently flipping from `signet`
/// to `mainnet` would change which chain a restored wallet believes it is on.
///
/// The explicit size bounds are what Foundation does not provide at all.
@Suite("Import bundle bounds")
struct ImportBundleBoundsTests {
    static func bundle(utxos: String = "", transactions: String = "", extra: String = "") -> String {
        """
        {"version":2,"network":"signet","lastKnownHeight":1\(extra),\
        "utxos":[\(utxos)],"transactions":[\(transactions)]}
        """
    }

    static let coin = #"{"txid":"aa","vout":0,"amount":1,"scriptPubKey":"51","chain":0,"index":0,"height":1}"#

    // MARK: - Decoding semantics that belong to Foundation

    /// A duplicate key resolves to its first occurrence. This is the safer of
    /// the two possible answers — it matches what a person reading the file
    /// top to bottom sees — but it is worth a test precisely because nothing
    /// in the format guarantees it.
    @Test("a duplicate key resolves to its first occurrence")
    func duplicateKeyTakesTheFirstValue() throws {
        let json = #"""
        {"version":2,"network":"signet","network":"mainnet","lastKnownHeight":1,"utxos":[],"transactions":[]}
        """#
        let bundle = try ImportBundle.decode(json: json)
        #expect(bundle.network == "signet",
                "a later duplicate key must not silently change the bundle's network")
    }

    /// Deeply nested JSON is refused rather than exhausting the stack. The
    /// descriptor parser needed its own bound for exactly this reason
    /// (`SEC-010`); this records that the JSON path already has one.
    @Test("deeply nested JSON is refused", arguments: [512, 20_000])
    func deeplyNestedJSONRefused(_ depth: Int) {
        let nested = String(repeating: "[", count: depth) + String(repeating: "]", count: depth)
        let json = Self.bundle(extra: ",\"junk\":\(nested)")
        #expect(throws: (any Error).self) {
            _ = try ImportBundle.decode(json: json)
        }
    }

    // MARK: - Bounds Winnow has to impose itself

    /// Foundation will decode a bundle of any size. Every declared coin is
    /// then materialised and scanned, so the count is bounded before the
    /// allocation rather than after it.
    @Test("a bundle above the entry limit is refused")
    func tooManyEntriesRefused() throws {
        let coins = Array(repeating: Self.coin, count: ImportBundle.maximumEntries + 1)
            .joined(separator: ",")
        #expect(throws: WalletError.self) {
            _ = try ImportBundle.decode(json: Self.bundle(utxos: coins))
        }
    }

    @Test("a bundle above the byte limit is refused")
    func tooLargeRefused() throws {
        let filler = String(repeating: "a", count: ImportBundle.maximumSerializedBytes)
        let json = Self.bundle(extra: ",\"descriptor\":\"\(filler)\"")
        #expect(json.utf8.count > ImportBundle.maximumSerializedBytes)
        #expect(throws: WalletError.self) {
            _ = try ImportBundle.decode(json: json)
        }
    }

    /// Positive controls: ordinary bundles, and one right at the entry limit,
    /// still decode. Without these the refusals above could be explained by
    /// the decoder rejecting everything.
    @Test("an ordinary bundle decodes")
    func ordinaryBundleDecodes() throws {
        let bundle = try ImportBundle.decode(json: Self.bundle(utxos: Self.coin))
        #expect(bundle.network == "signet")
        #expect(bundle.utxos.count == 1)
    }

    @Test("a bundle exactly at the entry limit is accepted")
    func atTheLimitAccepted() throws {
        let coins = Array(repeating: Self.coin, count: ImportBundle.maximumEntries)
            .joined(separator: ",")
        let bundle = try ImportBundle.decode(json: Self.bundle(utxos: coins))
        #expect(bundle.utxos.count == ImportBundle.maximumEntries)
    }

    /// Malformed input still fails as an error rather than anything worse.
    @Test("truncated JSON is refused")
    func truncatedJSONRefused() {
        #expect(throws: (any Error).self) {
            _ = try ImportBundle.decode(json: #"{"version":2,"network":"sig"#)
        }
    }
}
