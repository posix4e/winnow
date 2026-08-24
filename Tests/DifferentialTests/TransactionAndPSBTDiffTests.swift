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

    // MARK: - Corpus

    /// Deterministic generator so a failure names a seed and an index that
    /// reproduce it exactly, the way `CoinSelectionPropertyTests` does. A
    /// differential failure you cannot re-run is a rumour.
    private struct SeededRandom {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9E37_79B9_7F4A_7C15
            var value = state
            value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
            value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
            return value ^ (value >> 31)
        }
        mutating func below(_ bound: Int) -> Int { bound <= 0 ? 0 : Int(next() % UInt64(bound)) }
        mutating func pick<T>(_ options: [T]) -> T { options[below(options.count)] }
        mutating func bytes(_ count: Int) -> Data {
            Data((0 ..< count).map { _ in UInt8(next() & 0xFF) })
        }
    }

    /// Every output shape the wallet can pay, plus the ones only a third party
    /// creates. The last two are the interesting ones: an OP_RETURN carrying
    /// more than `MAX_SCRIPT_SIZE`, which is consensus-legal and which we
    /// refused to parse until `SEC-024`, and a bare multisig, which nothing in
    /// the wallet produces but any block may contain.
    private static func outputScript(kind: Int, random: inout SeededRandom) -> Data {
        switch kind {
        case 0: return Data([0x76, 0xA9, 0x14]) + random.bytes(20) + Data([0x88, 0xAC])   // P2PKH
        case 1: return Data([0xA9, 0x14]) + random.bytes(20) + Data([0x87])               // P2SH
        case 2: return Data([0x00, 0x14]) + random.bytes(20)                              // P2WPKH
        case 3: return Data([0x00, 0x20]) + random.bytes(32)                              // P2WSH
        case 4: return Data([0x51, 0x20]) + random.bytes(32)                              // P2TR
        case 5:                                                                            // bare multisig
            return Data([0x51, 0x21]) + random.bytes(33) + Data([0x51, 0xAE])
        default:                                                                           // OP_RETURN
            let size = random.pick([1, 80, 10_001])
            return Data([0x6A]) + random.bytes(size)
        }
    }

    /// A larger corpus than three hand-written transactions.
    ///
    /// S9 asks to "cross-check a larger transaction corpus against Bitcoin
    /// Core". The three cases above are a smoke test: they exercise the shapes
    /// we happened to think of, which is the same blind spot that let `SEC-024`
    /// sit in the parser until real chain data hit it. This sweeps the axes
    /// Core can adjudicate — version, input and output counts, every standard
    /// script type, dust and boundary amounts, sequences, locktimes, and
    /// witness stacks including items past the old script bound — and holds
    /// Core's decode as the oracle rather than our own builder.
    @Test("a generated corpus decodes identically in Core", arguments: [0x5749_4E4E_4F57_3039 as UInt64])
    func generatedCorpus(seed: UInt64) throws {
        // Forty, not four hundred: each transaction costs a `bitcoin-cli`
        // process, and breadth across the axes is what finds disagreements —
        // more draws from the same axes mostly re-check the same code.
        var random = SeededRandom(state: seed)
        for index in 0 ..< 40 {
            let inputCount = 1 + random.below(4)
            var inputs: [Transaction.Input] = []
            for _ in 0 ..< inputCount {
                let witnessItems = random.below(4)
                var witness: [Data] = []
                for _ in 0 ..< witnessItems {
                    // Includes stacks past MAX_SCRIPT_SIZE: witness items were
                    // always allowed 4 MB here, and that asymmetry with the
                    // script fields is what SEC-024 turned out to be.
                    witness.append(random.bytes(random.pick([0, 1, 33, 64, 72, 520, 10_001])))
                }
                inputs.append(Transaction.Input(
                    previousOutput: Transaction.Outpoint(txid: random.bytes(32),
                                                         vout: UInt32(random.pick([0, 1, 7, 0xFFFF_FFFF]))),
                    scriptSig: witness.isEmpty ? random.bytes(random.pick([0, 1, 25, 106])) : Data(),
                    sequence: UInt32(random.pick([0, 1, 0xFFFF_FFFD, 0xFFFF_FFFE, 0xFFFF_FFFF])),
                    witness: witness))
            }
            let outputCount = 1 + random.below(4)
            var outputs: [Transaction.Output] = []
            for _ in 0 ..< outputCount {
                outputs.append(Transaction.Output(
                    value: Int64(random.pick([0, 1, 294, 546, 1_000, 100_000, 2_100_000_000_000_000])),
                    scriptPubKey: Self.outputScript(kind: random.below(7), random: &random)))
            }
            let tx = Transaction(version: Int32(random.pick([1, 2, 3])),
                                 inputs: inputs, outputs: outputs,
                                 locktime: UInt32(random.pick([0, 1, 500_000, 499_999_999, 1_700_000_000])))
            try expectAgreement(tx, label: "corpus seed \(String(seed, radix: 16)) index \(index)")
        }
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

/// Whether the envelope conversion Core forces on us loses anything (#58, S8).
///
/// #58 requires that "unsupported fields and policy mismatches fail without
/// lossy conversion". That clause had no teeth until the interop work made it
/// concrete: Core 31.1 cannot read PSBTv2 and our parser will not read the v0
/// it returns, so *every* exchange with Core is converted in both directions.
/// A conversion nobody has audited is exactly where a field goes quietly
/// missing.
///
/// The conversion drops five key types — `PSBT_IN_PREVIOUS_TXID` (0x0E),
/// `PSBT_IN_OUTPUT_INDEX` (0x0F), `PSBT_IN_SEQUENCE` (0x10),
/// `PSBT_OUT_AMOUNT` (0x03) and `PSBT_OUT_SCRIPT` (0x04). The claim under test
/// is that this is relocation rather than loss: each of those is carried by
/// the unsigned transaction that BIP174 puts in the global map, so the v0
/// envelope holds the same information in a different place.
@Suite("PSBT envelope conversion is lossless", .enabled(if: diffEnabled))
struct PSBTConversionDiffTests {
    private func fixturePSBT() throws -> PSBT {
        let key = try testMaster().derived(path: "m/86'/1'/0'/0/0")
        let internalKey = BIP86.xonlyPublicKey(of: key)
        let script = try BIP86.scriptPubKey(internalKey: internalKey)
        let other = try BIP86.scriptPubKey(
            internalKey: BIP86.xonlyPublicKey(of: testMaster().derived(path: "m/86'/1'/0'/0/1")))
        let tx = try TransactionBuilder.build(
            inputs: [Transaction.Outpoint(txid: Data(hex: String(repeating: "3a", count: 32))!, vout: 3),
                     Transaction.Outpoint(txid: Data(hex: String(repeating: "5c", count: 32))!, vout: 0)],
            payments: [Payment(amount: 30_000, scriptPubKey: other)],
            change: Payment(amount: 19_000, scriptPubKey: script),
            changePosition: 1)
        return try PSBT(unsignedTx: tx, inputs: [
            PSBT.InputInfo(spentOutput: SighashBIP341.SpentOutput(amount: 25_000, scriptPubKey: script),
                           key: PSBT.TaprootKey(internalKey: internalKey, masterFingerprint: 0,
                                                path: [0x8000_0056])),
            PSBT.InputInfo(spentOutput: SighashBIP341.SpentOutput(amount: 25_000, scriptPubKey: script),
                           key: PSBT.TaprootKey(internalKey: internalKey, masterFingerprint: 0,
                                                path: [0x8000_0056])),
        ], outputs: [PSBT.OutputInfo(key: nil), PSBT.OutputInfo(key: nil)])
    }

    /// Everything the conversion drops must be recoverable from the unsigned
    /// transaction it writes into the global map. If any of these disagree the
    /// conversion is lossy and #58's clause is violated.
    @Test("the dropped v2 fields are all carried by the unsigned transaction")
    func droppedFieldsSurviveInTheTransaction() throws {
        let psbt = try fixturePSBT()
        let unsigned = try psbt.unsignedTransaction()
        for (index, input) in psbt.inputs.enumerated() {
            let previousTxid = try #require(input.pairs.first { $0.type == 0x0E }?.value)
            let outputIndex = try #require(input.pairs.first { $0.type == 0x0F }?.value)
            #expect(previousTxid == unsigned.inputs[index].previousOutput.txid,
                    "input \(index): PSBT_IN_PREVIOUS_TXID is not what the transaction says")
            #expect(outputIndex.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
                == unsigned.inputs[index].previousOutput.vout,
                "input \(index): PSBT_IN_OUTPUT_INDEX is not what the transaction says")
            if let sequence = input.pairs.first(where: { $0.type == 0x10 })?.value {
                #expect(sequence.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
                    == unsigned.inputs[index].sequence,
                    "input \(index): PSBT_IN_SEQUENCE is not what the transaction says")
            }
        }
        for (index, output) in psbt.outputs.enumerated() {
            if let amount = output.pairs.first(where: { $0.type == 0x03 })?.value {
                #expect(amount.withUnsafeBytes { $0.loadUnaligned(as: Int64.self) }
                    == unsigned.outputs[index].value,
                    "output \(index): PSBT_OUT_AMOUNT is not what the transaction says")
            }
            if let script = output.pairs.first(where: { $0.type == 0x04 })?.value {
                #expect(script == unsigned.outputs[index].scriptPubKey,
                        "output \(index): PSBT_OUT_SCRIPT is not what the transaction says")
            }
        }
    }

    /// The other direction: nothing *except* those five types is dropped, so a
    /// field we do not recognise cannot vanish silently on the way to Core.
    @Test("no unrecognised field is dropped by the conversion")
    func onlyTheRelocatedTypesAreDropped() throws {
        var psbt = try fixturePSBT()
        // A key type neither we nor Core assign meaning to. If the conversion
        // filters by anything other than the five relocated types, this goes
        // missing without a word — which is precisely the failure #58 names.
        let sentinel = PSBT.KeyValue(type: 0x7E, value: Data([0xDE, 0xAD, 0xBE, 0xEF]))
        psbt.inputs[0].pairs.append(sentinel)
        let envelope = try v0Envelope(psbt)
        let maps = try v0InputMaps(base64: envelope, inputCount: psbt.inputs.count)
        #expect(maps[0].contains { $0.key == sentinel.key && $0.value == sentinel.value },
                "an unrecognised input field was silently dropped converting to v0")

        let dropped: Set<UInt8> = [0x0E, 0x0F, 0x10]
        let expected = psbt.inputs[0].pairs.filter { !dropped.contains($0.type) }
        #expect(maps[0].count == expected.count,
                "the conversion dropped \(expected.count - maps[0].count) field(s) beyond the relocated three")
    }

    /// Core must accept what the conversion produces. A lossless envelope that
    /// Core rejects would be no use, and this is the assertion that would fail
    /// if a future field made the envelope malformed.
    @Test("Core parses the converted envelope and agrees about the inputs")
    func coreAcceptsTheEnvelope() throws {
        let psbt = try fixturePSBT()
        let decoded = try BitcoinCLI.runObject(["decodepsbt", try v0Envelope(psbt)])
        let inputs = try BitcoinCLI.array(decoded, "inputs")
        #expect(inputs.count == psbt.inputs.count, "Core sees a different number of inputs")
        let tx = try #require(decoded["tx"] as? [String: Any], "no unsigned transaction in the envelope")
        let vin = try BitcoinCLI.array(tx, "vin")
        let unsigned = try psbt.unsignedTransaction()
        for (index, input) in unsigned.inputs.enumerated() {
            let coreIn = try #require(vin[index] as? [String: Any])
            #expect(coreIn["txid"] as? String == input.previousOutput.txid.displayHex,
                    "input \(index): Core read a different previous txid")
            #expect(coreIn["vout"] as? Int == Int(input.previousOutput.vout),
                    "input \(index): Core read a different output index")
        }
    }
}
