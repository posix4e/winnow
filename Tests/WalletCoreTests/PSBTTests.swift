import Foundation
import P256K
import Testing
import TestSupport
@testable import BitcoinCore
@testable import WalletCore

/// PSBTv2 (BIP370) + BIP371 Taproot fields: creator → signer → finalizer →
/// extractor, wire round-trips, and generic-map preservation of unknown pairs.
@Suite("PSBT")
struct PSBTTests {
    struct Fixture {
        let master: HDKey
        let tx: Transaction
        let inputs: [PSBT.InputInfo]
        let outputs: [PSBT.OutputInfo]
        let tweakedKeys: [Data]

        init() throws {
            master = try testMaster()
            var inputs: [PSBT.InputInfo] = []
            var tweakedKeys: [Data] = []
            var outpoints: [Transaction.Outpoint] = []
            for index: UInt32 in [0, 1] {
                let key = try master.derived(path: "m/86'/1'/0'/0/\(index)")
                let internalKey = BIP86.xonlyPublicKey(of: key)
                let script = try BIP86.scriptPubKey(internalKey: internalKey)
                outpoints.append(Transaction.Outpoint(txid: Data(repeating: UInt8(0x40 + index), count: 32),
                                                      vout: index))
                inputs.append(PSBT.InputInfo(
                    spentOutput: .init(amount: Int64(100_000 + index * 10_000), scriptPubKey: script),
                    key: .init(internalKey: internalKey, masterFingerprint: master.fingerprint,
                               path: [86, 1, 0].map { $0 + HDKey.hardenedOffset } + [0, index])))
                tweakedKeys.append(try BIP86.tweakedPrivateKey(key.privateKey!))
            }
            let paymentScript = Data([0x51, 0x20] + repeatElement(0x77, count: 32))
            let changeKey = try master.derived(path: "m/86'/1'/0'/1/0")
            let changeInternal = BIP86.xonlyPublicKey(of: changeKey)
            tx = try TransactionBuilder.build(
                inputs: outpoints,
                payments: [Payment(amount: 100_000, scriptPubKey: paymentScript)],
                change: Payment(amount: 99_500, scriptPubKey: BIP86.scriptPubKey(internalKey: changeInternal)),
                changePosition: 1)
            let outputInfo = [PSBT.OutputInfo(key: nil),
                              PSBT.OutputInfo(key: .init(internalKey: changeInternal,
                                                         masterFingerprint: master.fingerprint,
                                                         path: [86, 1, 0].map { $0 + HDKey.hardenedOffset } + [1, 0]))]
            self.inputs = inputs
            outputs = outputInfo
            self.tweakedKeys = tweakedKeys
        }
    }

    @Test("creator emits the BIP370 v2 fields and BIP371 Taproot fields")
    func creatorFields() throws {
        let fixture = try Fixture()
        let psbt = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)

        #expect(psbt.version == 2)
        #expect(psbt.txVersion == 2)
        #expect(psbt.inputs.count == 2 && psbt.outputs.count == 2)
        for (index, input) in psbt.inputs.enumerated() {
            #expect(input.previousTxid == fixture.tx.inputs[index].previousOutput.txid)
            #expect(input.outputIndex == fixture.tx.inputs[index].previousOutput.vout)
            #expect(input.sequence == 0xFFFF_FFFD)
            #expect(input.sighashType == 0) // SIGHASH_DEFAULT, explicit
            #expect(input.witnessUTXO == fixture.inputs[index].spentOutput)
            #expect(input.tapInternalKey == fixture.inputs[index].key?.internalKey)
            let origin = try #require(input.tapBIP32Derivation[fixture.inputs[index].key!.internalKey])
            #expect(origin.leafHashes.isEmpty) // key-path only
            #expect(origin.masterFingerprint == fixture.master.fingerprint)
            #expect(origin.path.count == 5)
        }
        #expect(psbt.outputs[0].amount == 100_000)
        #expect(psbt.outputs[0].tapInternalKey == nil) // external payment
        #expect(psbt.outputs[1].tapInternalKey != nil) // change, ours
        #expect(try psbt.unsignedTransaction() == fixture.tx)
    }

    @Test("signer refuses a non-output-committing sighash type")
    func signerRefusesNonCommittingSighash() throws {
        // A malicious PSBT creator sets SIGHASH_NONE/SINGLE/ANYONECANPAY to
        // collect signatures that don't commit to the outputs, then rewrites
        // them. The signer must refuse every such type; DEFAULT/ALL still sign.
        for badType: UInt32 in [0x02, 0x03, 0x81, 0x82, 0x83] {
            let fixture = try Fixture()
            var psbt = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
            psbt.inputs[0].sighashType = badType
            #expect(throws: PSBTError.self) {
                try psbt.signKeyPath(input: 0, tweakedPrivateKey: fixture.tweakedKeys[0])
            }
        }
        for okType: UInt32 in [0x00, 0x01] {
            let fixture = try Fixture()
            var psbt = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
            psbt.inputs[0].sighashType = okType
            #expect(throws: Never.self) {
                try psbt.signKeyPath(input: 0, tweakedPrivateKey: fixture.tweakedKeys[0])
            }
        }
    }

    @Test("serialize → parse round trip preserves everything, Base64 included")
    func wireRoundTrip() throws {
        let fixture = try Fixture()
        var psbt = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
        // An unknown proprietary pair (Phase 5 will define real ones) must survive.
        psbt.inputs[0].pairs.append(PSBT.KeyValue(type: 0xFC, keyData: Data("acme".utf8), value: Data([1, 2, 3])))

        let parsed = try PSBT(serialized: psbt.serialized)
        #expect(parsed == psbt)
        #expect(parsed.inputs[0].pairs.contains { $0.type == 0xFC && $0.value == Data([1, 2, 3]) })
        #expect(try PSBT(base64: psbt.base64) == psbt)
    }

    @Test("wire map order is normalized without changing PSBT semantics")
    func mapOrderNormalization() throws {
        // Minimized deterministic-fuzz regression: the valid global fields
        // arrive in reverse-ish order (version before tx version/counts).
        let wire = try #require(Data(hex:
            "70736274ff01fb0402000000010204029f0000010401000105010000"))
        let parsed = try PSBT(serialized: wire)
        let canonical = parsed.serialized
        #expect(canonical != wire)
        #expect(try PSBT(serialized: canonical) == parsed)
        #expect(try PSBT(base64: parsed.base64) == parsed)
    }

    @Test("signer → finalizer → extractor produces the fully-signed raw tx")
    func roles() throws {
        let fixture = try Fixture()
        var psbt = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
        for index in fixture.tweakedKeys.indices {
            try psbt.signKeyPath(input: index, tweakedPrivateKey: fixture.tweakedKeys[index],
                                 auxiliaryRand: Data(repeating: 0, count: 32))
        }
        #expect(psbt.inputs.allSatisfy { $0.tapKeySignature?.count == 64 })

        try psbt.finalize()
        // Finalizer clears the in-progress fields (BIP174).
        #expect(psbt.inputs.allSatisfy { $0.tapKeySignature == nil && $0.finalScriptWitness?.count == 1 })

        let signed = try psbt.extractedTransaction()
        #expect(signed.isSegwit)

        // Every witness verifies against the spent output key.
        let spentOutputs = fixture.inputs.map(\.spentOutput)
        for index in signed.inputs.indices {
            let sighash = try SighashBIP341.sighash(tx: signed, inputIndex: index,
                                                    spentOutputs: spentOutputs, hashType: .default)
            let outputKey = P256K.Schnorr.XonlyKey(dataRepresentation: spentOutputs[index].scriptPubKey.suffix(32))
            let signature = try P256K.Schnorr.SchnorrSignature(dataRepresentation: signed.inputs[index].witness[0])
            var message = [UInt8](sighash)
            #expect(outputKey.isValid(signature, for: &message))
        }

        // The extracted tx is exactly what direct signing produces (aux = 0).
        var direct = fixture.tx
        try Signer.sign(tx: &direct, spentOutputs: spentOutputs,
                        auxiliaryRand: Data(repeating: 0, count: 32)) { script in
            fixture.inputs.firstIndex { $0.spentOutput.scriptPubKey == script }
                .map { fixture.tweakedKeys[$0] }
        }
        #expect(signed == direct)
    }

    @Test("finalizer verifies key-path signatures and fails atomically")
    func finalizerRejectsInvalidKeyPathSignature() throws {
        let fixture = try Fixture()
        var psbt = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
        for index in fixture.tweakedKeys.indices {
            try psbt.signKeyPath(input: index, tweakedPrivateKey: fixture.tweakedKeys[index],
                                 auxiliaryRand: Data(repeating: 0, count: 32))
        }
        var corrupt = try #require(psbt.inputs[1].tapKeySignature)
        corrupt[corrupt.startIndex] ^= 0x01
        psbt.inputs[1].tapKeySignature = corrupt
        let before = psbt

        #expect(throws: PSBTError.self) { try psbt.finalize() }
        #expect(psbt == before, "a failed later input must not finalize or erase earlier input fields")

        var unsafe = before
        var encodedDefault = try #require(unsafe.inputs[0].tapKeySignature)
        encodedDefault.append(0x00) // 65-byte DEFAULT encoding is invalid under BIP341.
        unsafe.inputs[0].tapKeySignature = encodedDefault
        #expect(throws: PSBTError.self) { try unsafe.finalize() }
    }

    @Test("unsignedTransaction/extractor enforce presence of required fields")
    func validation() throws {
        let fixture = try Fixture()
        let psbt = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
        #expect(throws: PSBTError.self) { _ = try psbt.extractedTransaction() } // nothing signed yet
        var mutable = psbt
        #expect(throws: PSBTError.self) { try mutable.finalize() }

        // Bad magic, incomplete v0 PSBT, duplicate keys.
        #expect(throws: PSBTError.invalidMagic) { _ = try PSBT(serialized: Data([1, 2, 3, 4, 5])) }
        var v0Globals = Data([0x70, 0x73, 0x62, 0x74, 0xFF])
        v0Globals.append(contentsOf: [0x01, 0xFB, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]) // version = 0
        #expect(throws: PSBTError.missingField("v0 unsigned transaction")) { _ = try PSBT(serialized: v0Globals) }
        var duplicate = Data([0x70, 0x73, 0x62, 0x74, 0xFF])
        duplicate.append(contentsOf: [0x01, 0xFB, 0x01, 0x02, 0x01, 0xFB, 0x01, 0x02, 0x00])
        #expect(throws: PSBTError.duplicateKey(Data([0xFB]))) { _ = try PSBT(serialized: duplicate) }
    }

    @Test("v0 exchange preserves the payment, signing data, and unknown fields")
    func v0Exchange() throws {
        let fixture = try Fixture()
        var tx = fixture.tx
        tx.locktime = 4321
        var psbt = try PSBT(unsignedTx: tx, inputs: fixture.inputs, outputs: fixture.outputs)
        let unknown = PSBT.KeyValue(type: 0xFC, keyData: Data([7]), value: Data([8, 9]))
        psbt.globals.append(unknown)
        psbt.inputs[0].pairs.append(unknown)
        psbt.outputs[1].pairs.append(unknown)
        try psbt.signKeyPath(input: 0, tweakedPrivateKey: fixture.tweakedKeys[0])
        let restored = try PSBT(base64: psbt.base64V0())
        #expect(try restored == PSBT(serialized: psbt.serialized))
        #expect(try restored.unsignedTransaction() == tx)
        #expect(restored.inputs[0].tapKeySignature == psbt.inputs[0].tapKeySignature)
        var final = restored
        try final.signKeyPath(input: 1, tweakedPrivateKey: fixture.tweakedKeys[1])
        try final.finalize()
        let finalRestored = try PSBT(base64: final.base64V0())
        #expect(try finalRestored.extractedTransaction() == final.extractedTransaction())
    }

    @Test("v0 import rejects ambiguous transaction fields and signed unsigned-transactions")
    func invalidV0Exchange() throws {
        let fixture = try Fixture()
        let original = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
        // Construct raw envelopes independently of the exporter.
        func envelope(_ tx: Transaction) -> PSBT {
            PSBT(globals: [.init(type: 0x00, value: tx.serialized(includeWitness: true))],
                 inputs: original.inputs.map { .init(pairs: $0.pairs.filter { ![0x0E, 0x0F, 0x10].contains($0.type) }) },
                 outputs: original.outputs.map { .init(pairs: $0.pairs.filter { ![0x03, 0x04].contains($0.type) }) })
        }
        let valid = envelope(fixture.tx)
        #expect(try PSBT(serialized: valid.serialized) == original)
        var repeatedType = valid
        repeatedType.globals.append(.init(type: 0x00, keyData: Data([1]), value: Data([2])))
        #expect(throws: PSBTError.self) { _ = try PSBT(serialized: repeatedType.serialized) }
        for type: UInt8 in [0x02, 0x03, 0x04, 0x05, 0x06] {
            var bad = valid
            bad.globals.append(.init(type: type, value: Data([0])))
            #expect(throws: PSBTError.self) { _ = try PSBT(serialized: bad.serialized) }
        }
        for type: UInt8 in [0x0E, 0x0F, 0x10, 0x11, 0x12] {
            var bad = valid
            bad.inputs[0].pairs.append(.init(type: type, value: Data(repeating: 0, count: type == 0x0E ? 32 : 4)))
            #expect(throws: PSBTError.self) { _ = try PSBT(serialized: bad.serialized) }
        }
        for type: UInt8 in [0x03, 0x04] {
            var bad = valid
            bad.outputs[0].pairs.append(.init(type: type, value: Data(repeating: 0, count: 8)))
            #expect(throws: PSBTError.self) { _ = try PSBT(serialized: bad.serialized) }
        }
        var signed = fixture.tx
        signed.inputs[0].scriptSig = Data([0x51])
        #expect(throws: PSBTError.self) { _ = try PSBT(serialized: envelope(signed).serialized) }
        signed.inputs[0].scriptSig = Data()
        signed.inputs[0].witness = [Data([1])]
        #expect(throws: PSBTError.self) { _ = try PSBT(serialized: envelope(signed).serialized) }
        var requirements = original
        requirements.inputs[0].pairs.append(.init(type: 0x11, value: PSBT.uint32le(1234)))
        #expect(throws: PSBTError.self) { _ = try requirements.base64V0() }
    }

    @Test("hostile PSBT lengths and fixed-width fields fail closed")
    func hostileLengths() throws {
        let oversized = Data(repeating: 0, count: PSBT.maxSerializedSize + 1)
        #expect(throws: PSBTError.malformed("document exceeds \(PSBT.maxSerializedSize) bytes")) {
            _ = try PSBT(serialized: oversized)
        }
        let oversizedBase64 = String(repeating: "A", count: PSBT.maxBase64Length + 1)
        #expect(throws: PSBTError.malformed("Base64 text exceeds \(PSBT.maxBase64Length) bytes")) {
            _ = try PSBT(base64: oversizedBase64)
        }

        // A CompactSize UInt64.max used to trap while converting to Int.
        var impossibleKey = Data([0x70, 0x73, 0x62, 0x74, 0xFF, 0xFF])
        impossibleKey.append(contentsOf: repeatElement(UInt8(0xFF), count: 8))
        #expect(throws: PSBTError.malformed("map key length \(UInt64.max) is out of bounds")) {
            _ = try PSBT(serialized: impossibleKey)
        }

        // Fixed-width fields are validated before any computed property can
        // load beyond the supplied bytes.
        var badVersion = Data([0x70, 0x73, 0x62, 0x74, 0xFF])
        badVersion.append(contentsOf: [0x01, PSBT.GlobalType.version, 0x00, 0x00])
        #expect(throws: PSBTError.malformed("global version must be four bytes")) {
            _ = try PSBT(serialized: badVersion)
        }

        let fixture = try Fixture()
        var malformedInput = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
        let outputIndex = try #require(malformedInput.inputs[0].pairs.firstIndex {
            $0.type == PSBT.InType.outputIndex
        })
        malformedInput.inputs[0].pairs[outputIndex].value = Data()
        #expect(malformedInput.inputs[0].outputIndex == nil)
        #expect(throws: PSBTError.malformed("input field \(PSBT.InType.outputIndex) must be 4 bytes")) {
            _ = try PSBT(serialized: malformedInput.serialized)
        }

        // Public in-memory construction and mutable pairs cannot turn a
        // short fixed-width field into an out-of-bounds load either.
        func replaceInput(_ type: UInt8, with value: Data, in psbt: inout PSBT) throws {
            let index = try #require(psbt.inputs[0].pairs.firstIndex { $0.type == type })
            psbt.inputs[0].pairs[index].value = value
        }
        var shortFields = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
        try replaceInput(PSBT.InType.previousTxid, with: Data(repeating: 0, count: 31), in: &shortFields)
        try replaceInput(PSBT.InType.sequence, with: Data(repeating: 0, count: 3), in: &shortFields)
        try replaceInput(PSBT.InType.sighashType, with: Data(repeating: 0, count: 3), in: &shortFields)
        let amountIndex = try #require(shortFields.outputs[0].pairs.firstIndex {
            $0.type == PSBT.OutType.amount
        })
        shortFields.outputs[0].pairs[amountIndex].value = Data(repeating: 0, count: 7)
        #expect(shortFields.inputs[0].previousTxid == nil)
        #expect(shortFields.inputs[0].sequence == nil)
        #expect(shortFields.inputs[0].sighashType == nil)
        #expect(shortFields.outputs[0].amount == nil)
    }

    @Test("a map at the field-count limit parses without quadratic duplicate scans")
    func denseMapBudget() throws {
        let fixture = try Fixture()
        var psbt = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
        let existingCount = psbt.inputs[0].pairs.count
        for index in 0 ..< (PSBT.maxMapPairs - existingCount) {
            let keyData = Data([
                UInt8(truncatingIfNeeded: index),
                UInt8(truncatingIfNeeded: index >> 8),
                UInt8(truncatingIfNeeded: index >> 16),
                UInt8(truncatingIfNeeded: index >> 24),
            ])
            psbt.inputs[0].pairs.append(.init(type: 0xFC, keyData: keyData, value: Data()))
        }

        let parsed = try PSBT(serialized: psbt.serialized)
        #expect(parsed.inputs[0].pairs.count == PSBT.maxMapPairs)
    }

    @Test("setting an optional field to nil removes its pair instead of writing an empty value")
    func nilSettersRemovePairs() throws {
        let fixture = try Fixture()
        var psbt = try PSBT(unsignedTx: fixture.tx, inputs: fixture.inputs, outputs: fixture.outputs)
        #expect(psbt.inputs[0].tapInternalKey != nil)

        psbt.inputs[0].tapInternalKey = nil
        #expect(psbt.inputs[0].pair(type: PSBT.InType.tapInternalKey) == nil)
        #expect(psbt.inputs[0].tapInternalKey == nil)
        // Clearing a field that was never set must not create an empty pair.
        psbt.inputs[0].tapKeySignature = nil
        #expect(psbt.inputs[0].pair(type: PSBT.InType.tapKeySignature) == nil)
        psbt.inputs[0].finalScriptWitness = nil
        #expect(psbt.inputs[0].pair(type: PSBT.InType.finalScriptWitness) == nil)
        psbt.outputs[0].tapInternalKey = nil
        #expect(psbt.outputs[0].pair(type: PSBT.OutType.tapInternalKey) == nil)

        // No empty fixed-width pair was left behind for the parser to reject.
        #expect(try PSBT(serialized: psbt.serialized) == psbt)
    }

}
