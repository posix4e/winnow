import BitcoinCore
import BitcoinP2P
import Foundation
import P256K
import Testing
@testable import WalletCore

/// Wallet-level silent payment sends (BIP352): the output scripts are derived
/// from the selected inputs' tweaked keys at signing time.
@Suite("Silent payment sends")
struct SilentPaymentSendTests {
    private func makeWallet(keyStore: KeyStore = InMemoryKeyStore()) async throws -> Wallet {
        try await Wallet.create(network: .signet, keyStore: keyStore, entropy: testEntropy,
                                creationHeight: 100)
    }

    /// Funds the wallet's receive index 0 with `amount`; returns the funding tx.
    @discardableResult
    private func fund(_ wallet: Wallet, amount: Int64) async throws -> Transaction {
        let script = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let funding = Transaction(version: 2, inputs: [coinbaseInput()], outputs: [
            Transaction.Output(value: amount, scriptPubKey: script),
        ], locktime: 0)
        try await wallet.apply(match: fakeMatch(height: 100, transactions: [funding]))
        try await matureCoinbase(wallet, height: 100)
        return funding
    }

    /// The BIP86 tweaked private key at m/86'/1'/0'/0/0 (the wallet's receive 0).
    private func tweakedReceiveKey0() throws -> Data {
        let key = try testMaster().derived(path: "m/86'/1'/0'/0/0")
        return try BIP86.tweakedPrivateKey(key.privateKey!)
    }

    /// A throwaway recipient address (valid keys, unknown secrets).
    private func recipient(network: BitcoinNetwork = .signet) throws -> SilentPaymentAddress {
        let scanKey = try P256K.Signing.PrivateKey().publicKey.dataRepresentation
        let spendKey = try P256K.Signing.PrivateKey().publicKey.dataRepresentation
        return try SilentPaymentAddress(scanKey: scanKey, spendKey: spendKey,
                                        hrp: SilentPayment.hrp(for: network))
    }

    @Test("send to a silent payment address derives the BIP352 output script")
    func send() async throws {
        let wallet = try await makeWallet()
        let funding = try await fund(wallet, amount: 150_000)
        let address = try recipient()

        let built = try await wallet.send(payments: [], feeRateSatPerVByte: 2,
                                          silentPayments: [SilentPayment(amount: 100_000, address: address)], chainTip: testChainTip, randomness: { 0.5 })
        let tx = built.transaction
        #expect(tx.inputs.count == 1)
        #expect(tx.inputs[0].witness.count == 1) // signed
        #expect(built.changeAmount != nil)

        // Independently re-derive the expected output script from the spent input.
        let spentScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let input = SilentPaymentSending.Input(txid: funding.txid, vout: 0,
                                               prevoutScriptPubKey: spentScript,
                                               privateKey: try tweakedReceiveKey0())
        let expected = try SilentPaymentSending.outputScripts(inputs: [input], recipients: [address])
        #expect(tx.outputs.contains { $0.value == 100_000 && $0.scriptPubKey == expected[0] })
        // The derived output is a plain P2TR script and not our change.
        #expect(expected[0].count == 34)
        #expect(expected[0] != (try await wallet.scriptPubKey(chain: .change, index: 0)))
    }

    @Test("paying the same address twice produces two distinct outputs")
    func sameAddressTwice() async throws {
        let wallet = try await makeWallet()
        let funding = try await fund(wallet, amount: 250_000)
        let address = try recipient()

        let built = try await wallet.send(payments: [], feeRateSatPerVByte: 2,
                                          silentPayments: [SilentPayment(amount: 100_000, address: address),
                                                           SilentPayment(amount: 50_000, address: address)], chainTip: testChainTip, randomness: { 0.5 })
        let spentScript = try await wallet.scriptPubKey(chain: .receive, index: 0)
        let input = SilentPaymentSending.Input(txid: funding.txid, vout: 0,
                                               prevoutScriptPubKey: spentScript,
                                               privateKey: try tweakedReceiveKey0())
        let expected = try SilentPaymentSending.outputScripts(inputs: [input],
                                                              recipients: [address, address])
        #expect(expected[0] != expected[1])
        let tx = built.transaction
        #expect(tx.outputs.contains { $0.value == 100_000 && $0.scriptPubKey == expected[0] })
        #expect(tx.outputs.contains { $0.value == 50_000 && $0.scriptPubKey == expected[1] })
    }

    @Test("mixed regular and silent payments in one transaction")
    func mixed() async throws {
        let wallet = try await makeWallet()
        _ = try await fund(wallet, amount: 250_000)
        let address = try recipient()
        let destination = Data([0x51, 0x20] + repeatElement(0x99, count: 32))

        let built = try await wallet.send(
            payments: [Payment(amount: 40_000, scriptPubKey: destination)],
            feeRateSatPerVByte: 2,
            silentPayments: [SilentPayment(amount: 100_000, address: address)], chainTip: testChainTip, randomness: { 0.5 })
        let tx = built.transaction
        #expect(tx.outputs.contains { $0.value == 40_000 && $0.scriptPubKey == destination })
        #expect(tx.outputs.contains { $0.value == 100_000 && $0.scriptPubKey != destination })
        #expect(tx.inputs.allSatisfy { $0.witness.count == 1 })
    }

    @Test("address network is enforced; empty send still rejected")
    func validation() async throws {
        let wallet = try await makeWallet()
        // A mainnet sp1 address is not payable on signet.
        let mainnetAddress = try recipient(network: .mainnet)
        #expect(throws: SilentPaymentAddressError.wrongHRP(expected: "tsp", actual: "sp")) {
            try SilentPayment(amount: 1_000, address: mainnetAddress.encoded, network: .signet)
        }
        _ = try await fund(wallet, amount: 150_000)
        // The string initializer accepts the matching network.
        let signetAddress = try recipient(network: .signet)
        _ = try SilentPayment(amount: 1_000, address: signetAddress.encoded, network: .signet)
        do {
            _ = try await wallet.send(payments: [], feeRateSatPerVByte: 2, silentPayments: [], chainTip: testChainTip, randomness: { 0.5 })
            Issue.record("expected WalletError.noPayments")
        } catch {
            #expect(error as? WalletError == .noPayments)
        }
    }
}
