import BitcoinCore
import BitcoinP2P
import Foundation
import Testing
@testable import WalletCore

/// `decoderawtransaction` (Core 31) vs our serialization/parsing — field-level
/// agreement on transactions we serialize, both unsigned and signed.
@Suite("decoderawtransaction differential", .enabled(if: diffEnabled))
struct TransactionDiffTests {
    /// A throwaway BIP86 address key (m/86'/1'/0'/0/0 of the test mnemonic).
    private func keyPair() throws -> (secret: Data, internalKey: Data, script: Data) {
        let key = try testMaster().derived(path: "m/86'/1'/0'/0/0")
        let internalKey = BIP86.xonlyPublicKey(of: key)
        return (try #require(key.privateKey), internalKey, try BIP86.scriptPubKey(internalKey: internalKey))
    }

    /// Asserts Core's decode agrees with our model, field by field.
    private func expectAgreement(_ tx: Transaction, label: String) throws {
        let rawHex = tx.serialized(includeWitness: true).hex
        let decoded = try BitcoinCLI.runObject(["decoderawtransaction", rawHex])

        #expect(try BitcoinCLI.string(decoded, "txid") == tx.txid.displayHex, "\(label) txid")
        if tx.isSegwit {
            #expect(try BitcoinCLI.string(decoded, "hash") == tx.wtxid.displayHex, "\(label) wtxid")
        }
        #expect(try BitcoinCLI.int(decoded, "size") == rawHex.count / 2, "\(label) size")
        #expect(try BitcoinCLI.int(decoded, "vsize") == TransactionBuilder.vsize(of: tx), "\(label) vsize")
        #expect(try BitcoinCLI.int(decoded, "version") == Int(tx.version), "\(label) version")
        #expect(try BitcoinCLI.int(decoded, "locktime") == Int(tx.locktime), "\(label) locktime")

        let vin = try BitcoinCLI.array(decoded, "vin")
        #expect(vin.count == tx.inputs.count, "\(label) vin count")
        for (index, input) in tx.inputs.enumerated() {
            let coreIn = vin[index] as! [String: Any]
            #expect(coreIn["txid"] as? String == input.previousOutput.txid.displayHex,
                    "\(label) vin[\(index)] txid")
            #expect(coreIn["vout"] as? Int == Int(input.previousOutput.vout),
                    "\(label) vin[\(index)] vout")
            #expect((coreIn["sequence"] as? NSNumber)?.uint32Value == input.sequence,
                    "\(label) vin[\(index)] sequence")
            let witness = coreIn["txinwitness"] as? [String] ?? []
            #expect(witness == input.witness.map(\.hex), "\(label) vin[\(index)] witness")
        }

        let vout = try BitcoinCLI.array(decoded, "vout")
        #expect(vout.count == tx.outputs.count, "\(label) vout count")
        for (index, output) in tx.outputs.enumerated() {
            let coreOut = vout[index] as! [String: Any]
            #expect(coreOut["n"] as? Int == index, "\(label) vout[\(index)] n")
            #expect(try BitcoinCLI.sats(coreOut["value"]!) == output.value, "\(label) vout[\(index)] value")
            let script = coreOut["scriptPubKey"] as! [String: Any]
            #expect(script["hex"] as? String == output.scriptPubKey.hex, "\(label) vout[\(index)] script")
        }

        // Round-trip: Core's hex parse must equal our own decode of the same bytes.
        let reparsed = try Transaction.decode(Data(hex: rawHex)!)
        #expect(reparsed == tx, "\(label) self round-trip")
    }

    @Test("unsigned transaction")
    func unsigned() throws {
        let (_, _, ownScript) = try keyPair()
        let otherScript = try BIP86.scriptPubKey(
            internalKey: BIP86.xonlyPublicKey(of: testMaster().derived(path: "m/86'/1'/0'/0/1")))
        let tx = try TransactionBuilder.build(
            inputs: [Transaction.Outpoint(txid: Data(hex: String(repeating: "11", count: 32))!, vout: 1)],
            payments: [Payment(amount: 50_000, scriptPubKey: otherScript)],
            change: Payment(amount: 49_000, scriptPubKey: ownScript),
            changePosition: 0)
        try expectAgreement(tx, label: "unsigned")
    }

    @Test("signed key-path transaction")
    func signed() throws {
        let (secret, internalKey, ownScript) = try keyPair()
        let tx = try TransactionBuilder.build(
            inputs: [Transaction.Outpoint(txid: Data(hex: String(repeating: "22", count: 32))!, vout: 0)],
            payments: [Payment(amount: 40_000, scriptPubKey: ownScript)])
        var psbt = try PSBT(unsignedTx: tx, inputs: [
            PSBT.InputInfo(spentOutput: SighashBIP341.SpentOutput(amount: 50_000, scriptPubKey: ownScript),
                           key: PSBT.TaprootKey(internalKey: internalKey, masterFingerprint: 0,
                                                path: [0x8000_0056])),
        ], outputs: [PSBT.OutputInfo(key: nil)])
        try psbt.signKeyPath(input: 0, tweakedPrivateKey: BIP86.tweakedPrivateKey(secret))
        try psbt.finalize()
        try expectAgreement(try psbt.extractedTransaction(), label: "signed")
    }
}

/// PSBT interop with Core 31.1: `decodepsbt` field agreement, `combinepsbt`,
/// and Core's `finalizepsbt` reproducing our finalizer's transaction.
///
/// NOTE: Core 31.1 still sets PSBT_HIGHEST_VERSION = 0 (src/psbt.h) — its
/// generic PSBT RPCs reject PSBTv2 ("Unsupported version number", verified
/// against this node with a hand-crafted minimal BIP370 PSBT). The checks
/// below therefore convert our PSBTv2 into the equivalent BIP174 v0 envelope
/// (same tx, same input/output maps minus the v2-only keys) before handing it
/// to Core. Everything semantic — witness utxos, tap key fields, signatures,
/// finalization — is still compared against Core byte-for-byte.
@Suite("PSBT differential", .enabled(if: diffEnabled))
struct PSBTDiffTests {
    /// BIP174 v0 serialization of one of our PSBTv2s: global map carries the
    /// unsigned transaction; per-input/output maps keep every pair except the
    /// BIP370-only ones (previous txid / output index / sequence on inputs,
    /// amount / script on outputs).
    private func fixture() throws -> (secret: Data, internalKey: Data, script: Data, tx: Transaction) {
        let key = try testMaster().derived(path: "m/86'/1'/0'/0/0")
        let internalKey = BIP86.xonlyPublicKey(of: key)
        let script = try BIP86.scriptPubKey(internalKey: internalKey)
        let tx = try TransactionBuilder.build(
            inputs: [Transaction.Outpoint(txid: Data(hex: String(repeating: "33", count: 32))!, vout: 2)],
            payments: [Payment(amount: 40_000, scriptPubKey: script)],
            change: Payment(amount: 9_000, scriptPubKey: script))
        return (try #require(key.privateKey), internalKey, script, tx)
    }

    private func unsignedPSBT(_ tx: Transaction, script: Data, internalKey: Data) throws -> PSBT {
        try PSBT(unsignedTx: tx, inputs: [
            PSBT.InputInfo(spentOutput: SighashBIP341.SpentOutput(amount: 50_000, scriptPubKey: script),
                           key: PSBT.TaprootKey(internalKey: internalKey, masterFingerprint: 0x1234_5678,
                                                path: [0x8000_0056, 0x8000_0001, 0x8000_0000, 0, 0])),
        ], outputs: [PSBT.OutputInfo(key: nil), PSBT.OutputInfo(key: nil)])
    }

    @Test("this Core build rejects PSBTv2 outright (premise of the v0 conversion)")
    func coreRejectsV2() throws {
        let (_, internalKey, script, tx) = try fixture()
        let psbt = try unsignedPSBT(tx, script: script, internalKey: internalKey)
        do {
            _ = try BitcoinCLI.run(["decodepsbt", psbt.base64])
            Issue.record("decodepsbt accepted PSBTv2 — drop the v0 conversion and diff the v2 directly")
        } catch let error as BitcoinCLI.CLIError {
            #expect(error.output.contains("Unsupported version number"), "unexpected rejection: \(error.output)")
        }
    }

    @Test("decodepsbt agrees with our PSBT fields (unsigned, signed, finalized)")
    func decodePSBT() throws {
        let (secret, internalKey, script, tx) = try fixture()
        var psbt = try unsignedPSBT(tx, script: script, internalKey: internalKey)

        // Unsigned: Core reconstructs the same transaction and sees our fields.
        let decoded = try BitcoinCLI.runObject(["decodepsbt", v0Envelope(psbt)])
        let coreTx = decoded["tx"] as! [String: Any]
        #expect(coreTx["txid"] as? String == tx.txid.displayHex, "unsigned txid")
        let coreVin = coreTx["vin"] as! [[String: Any]]
        #expect(coreVin[0]["txid"] as? String == tx.inputs[0].previousOutput.txid.displayHex)
        #expect(coreVin[0]["vout"] as? Int == 2)
        let input = (decoded["inputs"] as! [[String: Any]])[0]
        let witnessUTXO = input["witness_utxo"] as! [String: Any]
        #expect(try BitcoinCLI.sats(witnessUTXO["amount"]!) == 50_000, "witness utxo amount")
        #expect((witnessUTXO["scriptPubKey"] as! [String: Any])["hex"] as? String == script.hex)
        #expect(input["taproot_internal_key"] as? String == internalKey.hex, "tap internal key")
        let derivations = input["taproot_bip32_derivs"] as! [[String: Any]]
        #expect(derivations[0]["master_fingerprint"] as? String == "12345678")
        #expect(derivations[0]["path"] as? String == "m/86h/1h/0h/0/0", "derivation path")

        // Signed (not finalized): Core sees the key-path signature.
        try psbt.signKeyPath(input: 0, tweakedPrivateKey: BIP86.tweakedPrivateKey(secret))
        let signedDecoded = try BitcoinCLI.runObject(["decodepsbt", v0Envelope(psbt)])
        let signedInput = (signedDecoded["inputs"] as! [[String: Any]])[0]
        let keySig = try #require(signedInput["taproot_key_path_sig"] as? String, "taproot_key_path_sig missing")
        #expect(keySig == psbt.inputs[0].tapKeySignature?.hex, "taproot_key_path_sig bytes")

        // Finalized: Core sees the final witness.
        var finalized = psbt
        try finalized.finalize()
        let finalDecoded = try BitcoinCLI.runObject(["decodepsbt", v0Envelope(finalized)])
        let finalInput = (finalDecoded["inputs"] as! [[String: Any]])[0]
        let finalWitness = finalInput["final_scriptwitness"] as? [String]
        #expect(finalWitness == psbt.inputs[0].tapKeySignature.map { [$0.hex] }, "final witness")
    }

    @Test("combinepsbt merges our unsigned + signed PSBTs")
    func combinePSBT() throws {
        let (secret, internalKey, script, tx) = try fixture()
        let unsigned = try unsignedPSBT(tx, script: script, internalKey: internalKey)
        var signed = unsigned
        try signed.signKeyPath(input: 0, tweakedPrivateKey: BIP86.tweakedPrivateKey(secret))

        let combinedBase64 = try BitcoinCLI.run(["combinepsbt",
                                                 "[\"\(v0Envelope(unsigned))\",\"\(v0Envelope(signed))\"]"])
        // The combined result is v0 (Core's envelope); inspect it via Core.
        let decoded = try BitcoinCLI.runObject(["decodepsbt", combinedBase64])
        let input = (decoded["inputs"] as! [[String: Any]])[0]
        #expect(input["taproot_key_path_sig"] as? String == signed.inputs[0].tapKeySignature?.hex,
                "Core-combined PSBT carries our signature")
        let witnessUTXO = input["witness_utxo"] as! [String: Any]
        #expect(try BitcoinCLI.sats(witnessUTXO["amount"]!) == 50_000)

        // Our own combiner agrees on the same pair (v2 side).
        let ours = try unsigned.combined(with: [signed])
        #expect(ours.inputs[0].tapKeySignature == signed.inputs[0].tapKeySignature)
        #expect(try ours.unsignedTransaction() == unsigned.unsignedTransaction())
    }

    @Test("Core finalizepsbt reproduces our finalizer's transaction")
    func finalizePSBT() throws {
        let (secret, internalKey, script, tx) = try fixture()
        var psbt = try unsignedPSBT(tx, script: script, internalKey: internalKey)
        try psbt.signKeyPath(input: 0, tweakedPrivateKey: BIP86.tweakedPrivateKey(secret))

        let result = try BitcoinCLI.runObject(["finalizepsbt", v0Envelope(psbt)])
        #expect(result["complete"] as? Bool == true, "Core finalizepsbt incomplete")
        let coreHex = result["hex"] as! String

        var ours = psbt
        try ours.finalize()
        let extracted = try ours.extractedTransaction()
        #expect(coreHex == extracted.serialized(includeWitness: true).hex,
                "Core-finalized tx differs from ours")
    }
}
