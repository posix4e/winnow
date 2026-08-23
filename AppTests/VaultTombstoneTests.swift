@testable import WinnowApp
import Foundation
import WalletCore
import XCTest

/// Vault coins are marked spent rather than deleted (#127, groundwork).
///
/// The vault store had the same destructive removal as the wallet, in two
/// places, and one extra hazard: `VaultDetailView` passes `record.utxos`
/// straight into `createSpend`. So the filter has to live on the accessor
/// rather than at the call sites, or a spent vault coin is one forgotten
/// filter away from being selected for a spend.
final class VaultTombstoneTests: XCTestCase {
    private func coin(vout: UInt32, amount: Int64, spent: WalletUTXO.SpentMarker? = nil) -> WalletUTXO {
        WalletUTXO(txid: Data(repeating: 0xAB, count: 32), vout: vout, amount: amount,
                   scriptPubKey: Data([0x51, 0x20] + repeatElement(0xCD, count: 32)),
                   chain: .receive, index: 0, height: 101, spent: spent)
    }

    private func record(_ coins: [WalletUTXO]) -> VaultRecord {
        VaultRecord(id: "abcdef12", name: "Vault", descriptor: "tr(...)",
                    createdAtHeight: 100, nextReceiveIndex: 1, nextChangeIndex: 0,
                    allUtxos: coins)
    }

    func testSpentVaultCoinIsNotVisibleOrSpendable() {
        let marker = WalletUTXO.SpentMarker(spentBy: Data(repeating: 0x11, count: 32), height: 150)
        let vault = record([coin(vout: 0, amount: 10_000, spent: marker),
                            coin(vout: 1, amount: 25_000)])

        XCTAssertEqual(vault.utxos.count, 1, "a spent vault coin is not a coin")
        XCTAssertEqual(vault.utxos.first?.vout, 1)
        XCTAssertEqual(vault.balance, 25_000, "a spent coin must not be counted as money")
        XCTAssertEqual(vault.allUtxos.count, 2, "the row survives for a rollback to restore")
    }

    /// An in-flight vault spend carries no height, for the same reason as the
    /// wallet's: the transaction is still being relayed, so the coin must stay
    /// reserved even while confirmed spends are being restored.
    func testInFlightVaultSpendHasNoHeight() {
        let marker = WalletUTXO.SpentMarker(spentBy: Data(repeating: 0x11, count: 32), height: nil)
        let vault = record([coin(vout: 0, amount: 10_000, spent: marker)])

        XCTAssertTrue(vault.utxos.isEmpty)
        XCTAssertEqual(vault.balance, 0)
        XCTAssertNil(vault.allUtxos[0].spent?.height)
    }

    /// The on-disk key is unchanged, so a vaults.json written before this
    /// loads with every row live — that build deleted the spent ones.
    func testLegacyVaultsFileLoads() throws {
        let json = """
        [{"id":"abcdef12","name":"Vault","descriptor":"tr(...)","createdAtHeight":100,
          "nextReceiveIndex":1,"nextChangeIndex":0,
          "utxos":[{"txid":"\(String(repeating: "ab", count: 32))","vout":0,"amount":10000,
                    "scriptPubKey":"5120\(String(repeating: "cd", count: 32))",
                    "chain":0,"index":0,"height":101}]}]
        """
        let records = try JSONDecoder().decode([VaultRecord].self, from: Data(json.utf8))
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].utxos.count, 1, "an old row is a live coin")
        XCTAssertEqual(records[0].balance, 10_000)
    }

    /// …and a record still encodes under the same key, so an older build could
    /// read a file this one wrote.
    func testEncodesUnderTheOriginalKey() throws {
        let encoded = try JSONEncoder().encode(record([coin(vout: 0, amount: 10_000)]))
        let text = String(decoding: encoded, as: UTF8.self)
        XCTAssertTrue(text.contains("\"utxos\""))
        XCTAssertFalse(text.contains("allUtxos"))
    }
}
