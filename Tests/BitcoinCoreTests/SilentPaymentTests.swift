import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// BIP352 silent payments, send side: the official sending vectors from
/// bip-0352/send_and_receive_test_vectors.json (fetched once into Vectors/),
/// plus address round-trips and validation negatives.
@Suite("BIP352 silent payments")
struct SilentPaymentTests {
    struct Vin {
        let txid: Data // internal byte order
        let vout: UInt32
        let scriptSig: Data
        let witness: [Data]
        let prevoutScript: Data
        let privateKey: Data
    }

    struct SendingCase {
        let comment: String
        let vins: [Vin]
        let addresses: [String] // recipients expanded by `count`
        let scanKeys: [String]
        let spendKeys: [String]
        let expectedOutputs: [Set<String>] // all valid output sets (x-only hex)
        let sharedSecrets: [String?]
        let privateKeySum: String?
        let inputPubKeys: [String]
    }

    /// Parses the witness stack serialization used by the vectors (CompactSize
    /// item count, then CompactSize-length-prefixed items).
    static func witnessStack(from hex: String) throws -> [Data] {
        let data = Data(hex: hex) ?? Data()
        guard !data.isEmpty else { return [] } // empty serialization = no witness
        var offset = data.startIndex
        func readVarInt() throws -> Int {
            guard offset < data.endIndex else { throw VectorError.malformed("witness varint eof") }
            let first = data[offset]
            offset += 1
            switch first {
            case ..<0xFD: return Int(first)
            case 0xFD:
                guard offset + 2 <= data.endIndex else { throw VectorError.malformed("witness varint16 eof") }
                defer { offset += 2 }
                return Int(data[offset]) | Int(data[offset + 1]) << 8
            default: throw VectorError.malformed("witness varint too large")
            }
        }
        var stack: [Data] = []
        let itemCount = try readVarInt()
        for _ in 0 ..< itemCount {
            let length = try readVarInt()
            guard offset + length <= data.endIndex else { throw VectorError.malformed("witness item eof") }
            stack.append(data.subdata(in: offset ..< offset + length))
            offset += length
        }
        guard offset == data.endIndex else { throw VectorError.malformed("witness trailing bytes") }
        return stack
    }

    static func sendingCases() throws -> [SendingCase] {
        let json = try JSONSerialization.jsonObject(
            with: Vectors.data("bip352-send-receive-vectors.json", in: .module)) as! [[String: Any]]
        return try json.flatMap { entry -> [SendingCase] in
            let comment = entry["comment"] as! String
            return try (entry["sending"] as! [[String: Any]]).map { sending in
                let given = sending["given"] as! [String: Any]
                let expected = sending["expected"] as! [String: Any]
                let vins = try (given["vin"] as! [[String: Any]]).map { vin in
                    let scriptSigHex = vin["scriptSig"] as! String
                    guard let txid = Data(hex: vin["txid"] as! String),
                          let prevout = vin["prevout"] as? [String: Any],
                          let spk = prevout["scriptPubKey"] as? [String: Any],
                          let script = Data(hex: spk["hex"] as! String),
                          let key = Data(hex: vin["private_key"] as! String),
                          let scriptSig = scriptSigHex.isEmpty ? Data() : Data(hex: scriptSigHex)
                    else { throw VectorError.badHex(comment) }
                    // JSON txids are display (big-endian) order.
                    return Vin(txid: Data(txid.reversed()), vout: vin["vout"] as! UInt32,
                               scriptSig: scriptSig,
                               witness: try witnessStack(from: vin["txinwitness"] as! String),
                               prevoutScript: script, privateKey: key)
                }
                var addresses: [String] = []
                var scanKeys: [String] = []
                var spendKeys: [String] = []
                for recipient in given["recipients"] as! [[String: Any]] {
                    let count = recipient["count"] as? Int ?? 1
                    for _ in 0 ..< count {
                        addresses.append(recipient["address"] as! String)
                        scanKeys.append(recipient["scan_pub_key"] as! String)
                        spendKeys.append(recipient["spend_pub_key"] as! String)
                    }
                }
                let outputs = (expected["outputs"] as! [[String]]).map { Set($0) }
                return SendingCase(comment: comment, vins: vins,
                                   addresses: addresses, scanKeys: scanKeys, spendKeys: spendKeys,
                                   expectedOutputs: outputs,
                                   sharedSecrets: expected["shared_secrets"] as! [String?],
                                   privateKeySum: expected["input_private_key_sum"] as? String,
                                   inputPubKeys: expected["input_pub_keys"] as! [String])
            }
        }
    }

    static func inputs(of testCase: SendingCase) -> [SilentPaymentSending.Input] {
        testCase.vins.map {
            SilentPaymentSending.Input(txid: $0.txid, vout: $0.vout,
                                       prevoutScriptPubKey: $0.prevoutScript,
                                       scriptSig: $0.scriptSig, witness: $0.witness,
                                       privateKey: $0.privateKey)
        }
    }

    /// Every sending case of every vector: eligibility decisions, private key
    /// sum, shared secrets and the exact output set (BIP352 §Test Vectors).
    @Test("official sending vectors")
    func sendingVectors() throws {
        let cases = try Self.sendingCases()
        #expect(cases.count == 28)
        for testCase in cases {
            let inputs = Self.inputs(of: testCase)
            let recipients = try testCase.addresses.map {
                try SilentPaymentAddress($0, expectedHRP: "sp")
            }
            // Recipient addresses decode to the vector's stated keys.
            for (index, recipient) in recipients.enumerated() {
                #expect(recipient.scanKey.hex == testCase.scanKeys[index], Comment(rawValue: testCase.comment))
                #expect(recipient.spendKey.hex == testCase.spendKeys[index], Comment(rawValue: testCase.comment))
            }
            // Input eligibility exactly matches the reference extraction.
            let eligible = inputs.compactMap { SilentPaymentSending.eligiblePublicKey(of: $0) }
            #expect(eligible.map(\.hex) == testCase.inputPubKeys, Comment(rawValue: testCase.comment))

            if testCase.expectedOutputs == [[]] {
                // Failure cases: no eligible inputs / zero key sum / K_max.
                if testCase.inputPubKeys.isEmpty {
                    #expect(throws: SilentPaymentSendingError.noEligibleInputs,
                            Comment(rawValue: testCase.comment)) {
                        try SilentPaymentSending.outputScripts(inputs: inputs, recipients: recipients)
                    }
                } else if testCase.privateKeySum == nil {
                    #expect(throws: SilentPaymentSendingError.inputKeysSumToZero,
                            Comment(rawValue: testCase.comment)) {
                        try SilentPaymentSending.outputScripts(inputs: inputs, recipients: recipients)
                    }
                } else {
                    #expect(throws: SilentPaymentSendingError.tooManyRecipientsPerGroup,
                            Comment(rawValue: testCase.comment)) {
                        try SilentPaymentSending.outputScripts(inputs: inputs, recipients: recipients)
                    }
                }
                continue
            }

            let context = try SilentPaymentSending.context(inputs: inputs)
            #expect(context.privateKeySum.hex == testCase.privateKeySum, Comment(rawValue: testCase.comment))
            #expect(context.eligiblePublicKeys.map(\.hex) == testCase.inputPubKeys,
                    Comment(rawValue: testCase.comment))
            for (index, recipient) in recipients.enumerated() {
                let secret = try SilentPaymentSending.sharedSecret(context: context,
                                                                   scanKey: recipient.scanKey)
                #expect(secret.hex == testCase.sharedSecrets[index], Comment(rawValue: testCase.comment))
            }
            let scripts = try SilentPaymentSending.outputScripts(inputs: inputs, recipients: recipients)
            #expect(scripts.count == recipients.count, Comment(rawValue: testCase.comment))
            #expect(scripts.allSatisfy { $0.count == 34 && $0.prefix(2).elementsEqual([0x51, 0x20]) },
                    Comment(rawValue: testCase.comment))
            let outputSet = Set(scripts.map { $0.dropFirst(2).hex })
            #expect(testCase.expectedOutputs.contains(outputSet), Comment(rawValue: testCase.comment))
        }
    }

    @Test("address round-trip: decode then re-encode is the identity")
    func addressRoundTrip() throws {
        let cases = try Self.sendingCases()
        var seen = Set<String>()
        for testCase in cases {
            for string in testCase.addresses where seen.insert(string).inserted {
                let address = try SilentPaymentAddress(string, expectedHRP: "sp")
                #expect(try address.encoded == string)
                // Rebuilding from the decoded keys gives the same address.
                let rebuilt = try SilentPaymentAddress(scanKey: address.scanKey,
                                                       spendKey: address.spendKey, hrp: "sp")
                #expect(try rebuilt.encoded == string)
                #expect(rebuilt == address)
            }
        }
        #expect(!seen.isEmpty)
    }

    @Test("address validation negatives")
    func addressValidation() throws {
        let valid = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"
        let decoded = try SilentPaymentAddress(valid, expectedHRP: "sp")

        // Network enforcement: an sp address is not a tsp address.
        #expect(throws: SilentPaymentAddressError.wrongHRP(expected: "tsp", actual: "sp")) {
            try SilentPaymentAddress(valid, expectedHRP: "tsp")
        }
        // Corrupted checksum (last character flipped q → p): the bech32m
        // failure is reported as "not a code", never as a raw encoding error.
        #expect(throws: SilentPaymentAddressError.invalidEncoding) {
            try SilentPaymentAddress(String(valid.dropLast()) + "p")
        }
        // A 117-char address exceeds BIP173's 90-char default limit…
        #expect(throws: Bech32Error.tooLong) { _ = try Bech32.decode(valid) }
        // …but decodes under the BIP352 1023-char limit.
        #expect(try SilentPaymentAddress(valid) == decoded)

        // bech32 (not bech32m) checksums are rejected even for version 0.
        let payload = try SegwitAddress.convertBits(Array(decoded.scanKey + decoded.spendKey),
                                                    from: 8, to: 5, pad: true)
        let bech32Address = try Bech32.encode(hrp: "sp", data: [0] + payload, encoding: .bech32,
                                              maxLength: SilentPaymentAddress.maxAddressLength)
        #expect(throws: SilentPaymentAddressError.invalidEncoding) {
            try SilentPaymentAddress(bech32Address)
        }
        // Versions other than 0 are rejected (v1…v31 are reserved, BIP352).
        let version1 = try Bech32.encode(hrp: "sp", data: [1] + payload, encoding: .bech32m,
                                         maxLength: SilentPaymentAddress.maxAddressLength)
        #expect(throws: SilentPaymentAddressError.unsupportedVersion(1)) {
            try SilentPaymentAddress(version1)
        }
        // A 65-byte payload (truncated keys) is rejected.
        let truncated = try Bech32.encode(hrp: "sp",
                                          data: [0] + SegwitAddress.convertBits(
                                              Array((decoded.scanKey + decoded.spendKey).prefix(65)),
                                              from: 8, to: 5, pad: true),
                                          encoding: .bech32m,
                                          maxLength: SilentPaymentAddress.maxAddressLength)
        #expect(throws: SilentPaymentAddressError.invalidDataLength(65)) {
            try SilentPaymentAddress(truncated)
        }
        // Keys that are not valid curve points are rejected (x ≥ p here).
        let badKey = Data([0x02]) + Data(repeating: 0xFF, count: 32)
        #expect(throws: SilentPaymentAddressError.invalidPublicKey) {
            try SilentPaymentAddress(scanKey: badKey, spendKey: decoded.spendKey, hrp: "sp")
        }
        let badKeyAddress = try Bech32.encode(hrp: "sp",
                                              data: [0] + SegwitAddress.convertBits(
                                                  Array(badKey + decoded.spendKey),
                                                  from: 8, to: 5, pad: true),
                                              encoding: .bech32m,
                                              maxLength: SilentPaymentAddress.maxAddressLength)
        #expect(throws: SilentPaymentAddressError.invalidPublicKey) {
            try SilentPaymentAddress(badKeyAddress)
        }
        // Mixed case never parses (BIP173).
        #expect(throws: SilentPaymentAddressError.invalidEncoding) {
            try SilentPaymentAddress("sp1QQ" + valid.dropFirst(4))
        }
        // The shape check routes codes to this parser and nothing else.
        #expect(SilentPaymentAddress.looksLikeCode(" " + valid.uppercased()))
        #expect(SilentPaymentAddress.looksLikeCode("tsp1qqexample"))
        #expect(!SilentPaymentAddress.looksLikeCode("bc1p" + valid.dropFirst(4)))
        #expect(!SilentPaymentAddress.looksLikeCode("tb1qexample"))
    }

    @Test("same address twice yields two distinct outputs (k index)")
    func sameAddressTwice() throws {
        // Vector case "Multiple outputs: multiple outputs, same recipient".
        let testCase = try Self.sendingCases().first { $0.addresses.count == 2
            && $0.addresses[0] == $0.addresses[1] && $0.expectedOutputs != [[]] }!
        let inputs = Self.inputs(of: testCase)
        let address = try SilentPaymentAddress(testCase.addresses[0], expectedHRP: "sp")
        let scripts = try SilentPaymentSending.outputScripts(inputs: inputs,
                                                             recipients: [address, address])
        #expect(scripts.count == 2)
        #expect(scripts[0] != scripts[1])
        #expect(testCase.expectedOutputs.contains(Set(scripts.map { $0.dropFirst(2).hex })))
    }

    @Test("sender-side eligibility: unsigned P2TR key-path inputs count")
    func senderEligibility() throws {
        // The wallet derives outputs before signing, so its P2TR inputs carry
        // no witness yet — they are eligible as intended key-path spends.
        let outputKey = try BIP86.tweakedOutputKey(
            internalKey: Data(hex: "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")!)
        let input = SilentPaymentSending.Input(
            txid: Data(repeating: 1, count: 32), vout: 0,
            prevoutScriptPubKey: Data([0x51, 0x20]) + outputKey,
            privateKey: Data(repeating: 0, count: 31) + Data([0x01]))
        #expect(SilentPaymentSending.eligiblePublicKey(of: input) == Data([0x02]) + outputKey)
        // A script-path spend with the BIP341 NUMS internal key H is skipped.
        let numsControlBlock = Data([0xC1]) + Taproot.unspendableInternalKey
        let scriptPath = SilentPaymentSending.Input(
            txid: Data(repeating: 1, count: 32), vout: 0,
            prevoutScriptPubKey: Data([0x51, 0x20]) + outputKey,
            witness: [Data(repeating: 0, count: 64), Data([0xAB]), numsControlBlock],
            privateKey: Data(repeating: 0, count: 31) + Data([0x01]))
        #expect(SilentPaymentSending.eligiblePublicKey(of: scriptPath) == nil)
        // Unknown witness versions (v2+) are never eligible (BIP352).
        let future = SilentPaymentSending.Input(
            txid: Data(repeating: 1, count: 32), vout: 0,
            prevoutScriptPubKey: Data([0x52, 0x20]) + outputKey,
            privateKey: Data(repeating: 0, count: 31) + Data([0x01]))
        #expect(SilentPaymentSending.eligiblePublicKey(of: future) == nil)
    }

    @Test("P2PKH scriptSig window finds the key on a nonzero-startIndex slice")
    func p2pkhScriptSigSlice() throws {
        let pubkey = try SilentPaymentSending.publicKeyPoint(
            Data(repeating: 0, count: 31) + Data([0x01]))
        let hash = SilentPaymentSending.hash160(pubkey)
        var script = Data([0x76, 0xA9, 0x14])
        script.append(hash)
        script.append(contentsOf: [0x88, 0xAC])
        // Canonical P2PKH scriptSig: <push dummy-sig> <push compressed-key>.
        var scriptSig = Data([0x47]) + Data(repeating: 0x30, count: 71) + Data([0x21]) + pubkey
        #expect(SilentPaymentSending.eligiblePublicKey(
            prevoutScriptPubKey: script, scriptSig: scriptSig, witness: []) == pubkey)

        let padded = Data([0xAA, 0xBB]) + scriptSig + Data([0xCC])
        let sliced = padded.dropFirst(2).dropLast()
        #expect(sliced.startIndex != 0)
        #expect(sliced.count == scriptSig.count)
        #expect(SilentPaymentSending.eligiblePublicKey(
            prevoutScriptPubKey: script, scriptSig: sliced, witness: []) == pubkey)
    }
}
