import BitcoinCore
import Foundation
import Testing

/// Only BitcoinCore is a dependency. The mnemonic is a public BIP86 vector;
/// the invented outpoint cannot represent spendable funds.
@Suite("Standalone offline wallet consumer")
struct OfflineWalletTests {
    @Test("derive the reference address, select coins, build and sign offline")
    func completeOfflinePayment() throws {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        try BIP39.validate(mnemonic: mnemonic)
        let master = try HDKey(seed: BIP39.seed(mnemonic: mnemonic))
        let account = try BIP86.accountKey(from: master)
        let receivingKey = try account.child(at: 0).child(at: 0)
        let internalKey = BIP86.xonlyPublicKey(of: receivingKey)
        #expect(try BIP86.address(internalKey: internalKey)
            == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
        let coin = WalletUTXO(
            txid: Data(repeating: 0x42, count: 32), vout: 0, amount: 100_000,
            scriptPubKey: try BIP86.scriptPubKey(internalKey: internalKey),
            chain: .receive, index: 0, height: 839_900)
        let destination = try account.neutered.child(at: 0).child(at: 10)
        let payment = Payment(
            amount: 50_000,
            scriptPubKey: try BIP86.scriptPubKey(internalKey: BIP86.xonlyPublicKey(of: destination)))
        let changeKey = try account.neutered.child(at: 1).child(at: 0)
        let changeScript = try BIP86.scriptPubKey(internalKey: BIP86.xonlyPublicKey(of: changeKey))
        let selection = try CoinSelection.select(
            utxos: [coin], payments: [payment], changeScriptPubKey: changeScript, feeRateSatPerVByte: 2)
        let changeAmount = try #require(selection.changeAmount)
        #expect(selection.fee == 308)
        #expect(changeAmount == 49_692)
        var tx = try TransactionBuilder.build(
            inputs: selection.selected.map(\.outpoint), payments: [payment],
            change: Payment(amount: changeAmount, scriptPubKey: changeScript),
            changePosition: 1, locktime: 840_000)
        let unsignedBytes = tx.serialized(includeWitness: false)
        let secret = try BIP86.tweakedPrivateKey(#require(receivingKey.privateKey))
        try Signer.sign(tx: &tx, spentOutputs: selection.selected.map(\.spentOutput)) { script in
            script == coin.scriptPubKey ? secret : nil
        }
        #expect(tx.serialized(includeWitness: false) == unsignedBytes)
        #expect(tx.inputs[0].witness.first?.count == 64)
        #expect(TransactionBuilder.vsize(of: tx) == 154)
        #expect(try Transaction.decode(tx.serialized(includeWitness: true)) == tx)
    }
}
