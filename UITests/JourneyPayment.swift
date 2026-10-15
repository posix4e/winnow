import Foundation
import TestSupport
import VaultKit
import WalletCore
import XCTest

@MainActor
struct JourneyPayment {
    let vault: Vault
    let fundingTxid: String
    let fundingVout: UInt32
    let address: String
    let destination: String
    let fee: Int64

    func verifyAccepted(txid: String) throws {
        _ = try BitcoinCLI.runObject(["getmempoolentry", txid])
        let transaction = try BitcoinCLI.runObject(["getrawtransaction", txid, "true"])
        XCTAssertEqual(try BitcoinCLI.string(transaction, "txid"), txid)
        let inputs = try XCTUnwrap(transaction["vin"] as? [[String: Any]])
        XCTAssertEqual(inputs.count, 1)
        let input = try XCTUnwrap(inputs.first)
        XCTAssertEqual(try BitcoinCLI.string(input, "txid"), fundingTxid)
        XCTAssertEqual(try BitcoinCLI.int(input, "vout"), Int(fundingVout))
        XCTAssertEqual(try AddressDecoder.scriptPubKey(for: address, network: .signet),
                       try vault.scriptPubKey(index: 0))

        let destinationScript = try AddressDecoder.scriptPubKey(for: destination, network: .signet)
        let changeScript = try vault.scriptPubKey(index: 0, choice: 1)
        let outputs = try XCTUnwrap(transaction["vout"] as? [[String: Any]])
        XCTAssertEqual(outputs.count, 2)
        let amountsAndScripts = try outputs.map { output -> (amount: Int64, script: String) in
            let script = try XCTUnwrap(output["scriptPubKey"] as? [String: Any])
            return (try BitcoinCLI.sats(XCTUnwrap(output["value"])), try BitcoinCLI.string(script, "hex"))
        }
        let payments = amountsAndScripts.filter { $0.script == destinationScript.hex }
        let changes = amountsAndScripts.filter { $0.script == changeScript.hex }
        XCTAssertEqual(payments.count, 1)
        XCTAssertEqual(changes.count, 1)
        XCTAssertEqual(try XCTUnwrap(payments.first).amount, 1_000_000)
        XCTAssertGreaterThan(fee, 0)
        XCTAssertEqual(try XCTUnwrap(changes.first).amount, 4_000_000 - fee)
        XCTAssertEqual(5_000_000 - amountsAndScripts.reduce(0) { $0 + $1.amount }, fee)

        let body = try XCTUnwrap(vault.descriptor.serialized().split(separator: "#").first)
        let changeDescriptor = try Descriptor(String(body).replacingOccurrences(of: "/<0;1>/*", with: "/1/*"))
        let coreChange = try XCTUnwrap(BitcoinCLI.runJSON(
            ["deriveaddresses", changeDescriptor.serialized(), "[0,0]"]) as? [String])
        XCTAssertEqual(coreChange, [try XCTUnwrap(AddressDecoder.address(for: changeScript, network: .signet))])

        let witness = try XCTUnwrap(input["txinwitness"] as? [String])
        if vault.isScriptPath {
            XCTAssertEqual(witness.count, 5)
            XCTAssertEqual(witness.prefix(3).filter { $0.count == 128 }.count, 2)
            XCTAssertEqual(witness.prefix(3).filter(\.isEmpty).count, 1)
        } else {
            XCTAssertEqual(witness.count, 1)
            XCTAssertEqual(try XCTUnwrap(witness.first).count, 128)
        }
    }

    func verifyConfirmed(txid: String) throws {
        let transaction = try BitcoinCLI.runObject(["getrawtransaction", txid, "true"])
        XCTAssertGreaterThan(try BitcoinCLI.int(transaction, "confirmations"), 0)
        let spent = try BitcoinCLI.runJSON(["gettxout", fundingTxid, String(fundingVout)])
        XCTAssertTrue(spent == nil || spent is NSNull, "the funded output was not spent")

        let bank = try BitcoinCLI.runObject(["gettransaction", txid], wallet: "ui-bank")
        XCTAssertGreaterThan(try BitcoinCLI.int(bank, "confirmations"), 0)
        let details = try XCTUnwrap(bank["details"] as? [[String: Any]])
        let receipts = details.filter {
            $0["category"] as? String == "receive" && $0["address"] as? String == destination
        }
        XCTAssertEqual(receipts.count, 1)
        let receipt = try XCTUnwrap(receipts.first)
        XCTAssertEqual(try BitcoinCLI.sats(XCTUnwrap(receipt["amount"])), 1_000_000)
    }

    func verifyChange(txid: String, signers: [CoreSigner]) throws -> (vout: Int, height: Int) {
        XCTAssertFalse(signers.isEmpty)
        let changeScript = try vault.scriptPubKey(index: 0, choice: 1)
        let changeAddress = try XCTUnwrap(AddressDecoder.address(for: changeScript, network: .signet))
        let transaction = try BitcoinCLI.runObject(["getrawtransaction", txid, "true"])
        let blockHash = try BitcoinCLI.string(transaction, "blockhash")
        let height = try BitcoinCLI.int(BitcoinCLI.runObject(["getblockheader", blockHash]), "height")
        XCTAssertGreaterThan(height, 0)
        let outputs = try XCTUnwrap(transaction["vout"] as? [[String: Any]])
        let changes = outputs.filter {
            ($0["scriptPubKey"] as? [String: Any])?["hex"] as? String == changeScript.hex
        }
        XCTAssertEqual(changes.count, 1)
        let change = try XCTUnwrap(changes.first)
        let changeVout = try BitcoinCLI.int(change, "n")
        XCTAssertEqual(try BitcoinCLI.sats(XCTUnwrap(change["value"])), 4_000_000 - fee)
        let addresses = String(decoding: try JSONEncoder().encode([address, changeAddress]), as: UTF8.self)

        for signer in signers {
            let coins = try XCTUnwrap(BitcoinCLI.runJSON(
                ["listunspent", "0", "9999999", addresses], wallet: signer.wallet) as? [[String: Any]])
            XCTAssertFalse(coins.contains {
                $0["txid"] as? String == fundingTxid && ($0["vout"] as? NSNumber)?.uint32Value == fundingVout
            }, "\(signer.wallet) still lists the spent funding output")
            let matches = coins.filter {
                $0["txid"] as? String == txid && ($0["vout"] as? NSNumber)?.intValue == changeVout
            }
            XCTAssertEqual(matches.count, 1, "\(signer.wallet) did not discover the exact change output")
            let coin = try XCTUnwrap(matches.first)
            XCTAssertEqual(try BitcoinCLI.string(coin, "address"), changeAddress)
            XCTAssertEqual(try BitcoinCLI.sats(XCTUnwrap(coin["amount"])), 4_000_000 - fee)
            XCTAssertGreaterThan(try BitcoinCLI.int(coin, "confirmations"), 0)
        }
        return (changeVout, height)
    }
}
