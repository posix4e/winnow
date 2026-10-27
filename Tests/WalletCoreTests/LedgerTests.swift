import CryptoKit
import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// The Ledger Bitcoin app client: Ledger's own published vectors for policy
/// ids and Taproot addresses, an independent Merkle oracle, Bluetooth framing,
/// the client-command interpreter, and whole pairings and spends against the
/// device simulator in TestSupport.
@Suite("Ledger client")
struct LedgerTests {
    struct LedgerVectors: Decodable {
        struct Registration: Decodable {
            var name: String
            var walletName: String
            var template: String
            var keys: [String]
            var walletID: String
        }

        struct Address: Decodable {
            var name: String
            var template: String
            var keys: [String]
            var change: Int
            var index: UInt32
            var address: String
        }

        var source: String
        var register: [Registration]
        var addresses: [Address]
    }

    static func vectors() throws -> LedgerVectors {
        try Vectors.decode(LedgerVectors.self, "ledger-bitcoin-app.json", in: .module)
    }

    /// The template with each `@i/**` replaced by its key and `/<0;1>/*`.
    static func descriptor(template: String, keys: [String]) throws -> Descriptor {
        var text = template
        for index in keys.indices.reversed() {
            text = text.replacingOccurrences(of: "@\(index)/**", with: keys[index] + "/<0;1>/*")
                .replacingOccurrences(of: "@\(index)/<", with: keys[index] + "/<")
        }
        return try Descriptor(text)
    }

    // MARK: - Ledger's published vectors

    @Test("policy ids match Ledger's register_wallet vectors")
    func policyIDs() throws {
        let cases = try Self.vectors().register
        #expect(cases.count >= 10)
        for vector in cases {
            let policy = try LedgerWalletPolicy(name: vector.walletName, template: vector.template, keys: vector.keys)
            #expect(policy.id.hex == vector.walletID, "\(vector.name)")
        }
    }

    @Test("Taproot addresses match Ledger's get_wallet_address vectors, including sorted multi_a")
    func taprootAddresses() throws {
        let cases = try Self.vectors().addresses
        #expect(cases.contains { $0.template.contains("sortedmulti_a") })
        for vector in cases {
            let derived = try Self.descriptor(template: vector.template, keys: vector.keys)
                .derived(index: vector.index, bitcoinNetwork: .signet)[vector.change].address
            #expect(derived == vector.address, "\(vector.name)")
        }
    }

    // MARK: - Merkle commitments

    @Test("Merkle roots and proofs match an independent oracle")
    func merkle() throws {
        let expected = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a",
            "3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688",
            "9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb",
            "b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f",
            "bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8",
            "3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3",
            "ef7f49b620f6c7ea9b963a214da34b5021c6ded8ed57734380a311ab726aa907",
            "162a21c2230e0284ea38cb8739ee4bb75947a1acd5d529c638ec068969fb3c4a",
        ]
        for count in 0 ..< expected.count {
            let leaves = (0 ..< count).map { LedgerMerkle.elementHash(Data([UInt8($0)])) }
            #expect(LedgerMerkle.root(leaves).hex == expected[count], "\(count) leaves")
        }
        let seven = (0 ..< 7).map { LedgerMerkle.elementHash(Data([UInt8($0)])) }
        #expect(LedgerMerkle.proof(seven, index: 5).map(\.hex) == [
            "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
            "40d88127d4d31a3891f41598eeed41174e5bc89b1eb9bbd66a8cbfc09956a3fd",
            "9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb",
        ])
    }

    // MARK: - Framing

    @Test("Bluetooth frames round-trip at any frame size and refuse a broken sequence")
    func framing() throws {
        for length in [5, 15, 16, 17, 150, 260] {
            let apdu = Data((0 ..< length).map { UInt8($0 & 0xFF) })
            for frameSize in [20, 23, 156] {
                let frames = try LedgerBluetoothFraming.frames(for: apdu, frameSize: frameSize)
                #expect(frames.allSatisfy { $0.count <= frameSize && $0.first == 0x05 })
                var reassembler = LedgerBluetoothFraming.Reassembler()
                var reply: Data?
                for frame in frames { reply = try reassembler.receive(frame) }
                #expect(reply == apdu, "\(length) bytes in \(frameSize)-byte frames")
            }
        }
        let frames = try LedgerBluetoothFraming.frames(for: Data(repeating: 7, count: 100), frameSize: 20)
        var reassembler = LedgerBluetoothFraming.Reassembler()
        _ = try reassembler.receive(frames[0])
        #expect(throws: LedgerError.self) { _ = try reassembler.receive(frames[2]) }
        #expect(LedgerBluetoothFraming.frameSize(fromMTUResponse: Data([0x08, 0, 0, 0, 1, 153])) == 153)
        #expect(LedgerBluetoothFraming.frameSize(fromMTUResponse: Data([0x05, 0, 0, 0, 1, 153])) == nil)
    }

    // MARK: - Client commands

    @Test("long preimages and deep proofs are served across GET_MORE_ELEMENTS; unknown data is refused")
    func interpreter() throws {
        var interpreter = LedgerClientCommandInterpreter()
        let long = Data((0 ..< 300).map { UInt8($0 & 0xFF) })
        interpreter.addKnownPreimage(long)
        var request = Data([0x40, 0x00]) + LedgerSimulatorHash.sha256(long)
        var reader = ByteReader(try interpreter.execute(request))
        #expect(try reader.readVarInt() == 300)
        var received = try reader.readBytes(Int(try reader.readUInt8()))
        while received.count < 300 {
            var more = ByteReader(try interpreter.execute(Data([0xA0])))
            let count = Int(try more.readUInt8())
            #expect(try more.readUInt8() == 1)
            received += try more.readBytes(count)
        }
        #expect(received == long)

        let elements = (0 ..< 200).map { Data("key \($0)".utf8) }
        interpreter.addKnownList(elements)
        let leaves = elements.map(LedgerMerkle.elementHash)
        let root = LedgerMerkle.root(leaves)
        request = Data([0x41]) + root + Data([0xC8, 0x9B]) // 200 leaves, index 155
        reader = ByteReader(try interpreter.execute(request))
        #expect(try reader.readBytes(32) == leaves[155])
        let proofLength = Int(try reader.readUInt8())
        let sent = Int(try reader.readUInt8())
        #expect(proofLength == LedgerMerkle.proof(leaves, index: 155).count && sent == 6)
        #expect(throws: LedgerError.self) { _ = try interpreter.execute(Data([0x40, 0x00]) + Data(count: 32)) }
        // Drain the queued proof hashes before the next request.
        while true {
            var more = ByteReader(try interpreter.execute(Data([0xA0])))
            let count = Int(try more.readUInt8())
            _ = try more.readBytes(Int(try more.readUInt8()) * count)
            if count < 7 { break }
        }
        #expect(try interpreter.execute(Data([0x42]) + root + leaves[42]) == Data([0x01, 42]))
        #expect(try interpreter.execute(Data([0x42]) + root + Data(count: 32)) == Data([0x00, 0x00]))
        #expect(throws: LedgerError.self) { _ = try interpreter.execute(Data([0x42]) + Data(count: 64)) }

        var fresh = LedgerClientCommandInterpreter()
        #expect(throws: LedgerError.self) { _ = try fresh.execute(Data([0x40, 0x00]) + Data(count: 32)) }
        #expect(throws: LedgerError.self) { _ = try fresh.execute(Data([0x41]) + root + Data([0xC8, 0x00])) }
        #expect(throws: LedgerError.self) { _ = try fresh.execute(Data([0x99])) }
        #expect(try fresh.execute(Data([0x10, 0x01, 0x02])).isEmpty)
        #expect(fresh.yielded == [Data([0x01, 0x02])])
    }

    // MARK: - Against the device simulator

    struct Pairing {
        var account: MultisigAccount
        var registration: LedgerRegistration
        var client: LedgerBitcoinClient
        var simulator: LedgerSimulator
        var phone: HDKey
    }

    static func pair(transport wrap: (LedgerSimulator) -> any LedgerTransport = { $0 }) async throws -> Pairing {
        let masters = try TestKeys.masters()
        let simulator = LedgerSimulator(master: masters[1])
        let client = LedgerBitcoinClient(transport: wrap(simulator))
        let (ledgerKey, fingerprint) = try await LedgerMultisig.signerExpression(client: client, network: .signet)
        #expect(ledgerKey.hasPrefix(String(format: "[%08x/87'/1'/0']tpub", masters[1].fingerprint)))
        let descriptor = try MultisigAccount.descriptor(
            threshold: 2, signers: [try TestKeys.keyExpression(master: masters[0]), ledgerKey], network: .signet)
        let account = try MultisigAccount(descriptor: descriptor, network: .signet)
        let registration = try await LedgerMultisig.register(account, name: "Winnow 2-of-2", fingerprint: fingerprint,
                                                             client: client)
        return Pairing(account: account, registration: registration, client: client, simulator: simulator,
                       phone: masters[0])
    }

    static func spend(_ account: MultisigAccount) throws -> (PSBT, [WalletUTXO]) {
        let utxos = try (0 ..< 2).map { index in
            try WalletUTXO(txid: Data(repeating: 0x40 + UInt8(index), count: 32), vout: 0, amount: 60_000,
                           scriptPubKey: account.scriptPubKey(index: UInt32(index)), chain: .receive,
                           index: UInt32(index), height: 100)
        }
        let payment = Payment(amount: 90_000, scriptPubKey: Data([0x51, 0x20] + repeatElement(0x77, count: 32)))
        let psbt = try account.createSpend(utxos: utxos, payments: [payment], changeIndex: 0,
                                           feeRateSatPerVByte: 2, chainTip: 200, randomness: { 0.5 })
        return (psbt, utxos)
    }

    @Test("pair, register, show an address, then phone and Ledger both sign a two-input spend")
    func pairAndSpend() async throws {
        let pairing = try await Self.pair()
        #expect(await pairing.simulator.registeredNames == ["Winnow 2-of-2"])
        #expect(pairing.registration.policyID == (try LedgerWalletPolicy(name: "Winnow 2-of-2", account: pairing.account)).id)

        let shown = try await LedgerMultisig.displayAddress(pairing.account, registration: pairing.registration,
                                                            index: 4, client: pairing.client)
        #expect(shown == (try pairing.account.address(index: 4)))
        #expect(await pairing.simulator.displayedAddresses == [shown])

        let owned = [MultisigAccount.OutputCoordinate(choice: 1, index: 0)]
        var (psbt, utxos) = try Self.spend(pairing.account)
        try pairing.account.sign(&psbt, signingKey: pairing.phone, knownUTXOs: utxos, ownedOutputCoordinates: owned,
                                 chainTip: 200)
        #expect(try pairing.account.approvals(of: psbt, knownUTXOs: utxos) == [0])
        let added = try await LedgerMultisig.sign(&psbt, account: pairing.account, registration: pairing.registration,
                                                  client: pairing.client)
        #expect(added == 2)
        #expect(try pairing.account.approvals(of: psbt, knownUTXOs: utxos) == [0, 1])
        let transaction = try pairing.account.finalizeSpend(&psbt, knownUTXOs: utxos, ownedOutputCoordinates: owned,
                                                            chainTip: 200)
        #expect(transaction.inputs.allSatisfy { $0.witness.count == 4 })
    }

    @Test("a stored registration must be the account's own policy and name one of its signers")
    func storedRegistration() async throws {
        let pairing = try await Self.pair()
        var record = MultisigAccountRecord(id: pairing.account.id, name: "Winnow 2-of-2",
                                           descriptor: pairing.account.descriptor.serialized(), createdAtHeight: 0,
                                           ledger: pairing.registration)
        try record.checkLedgerRegistration(for: pairing.account)
        let encoded = try JSONEncoder().encode(record)
        #expect(try JSONDecoder().decode(MultisigAccountRecord.self, from: encoded) == record)

        for tamper: (inout LedgerRegistration) -> Void in [
            { $0.policyID = Data(repeating: 1, count: 32) },
            { $0.policyName = "Renamed" },
            { $0.masterFingerprint ^= 1 },
            { $0.keyPath = [HDKey.hardenedOffset + 86, HDKey.hardenedOffset + 1, HDKey.hardenedOffset] },
            { $0.hmac = Data(count: 31) },
        ] {
            var registration = pairing.registration
            tamper(&registration)
            record.ledger = registration
            #expect(throws: MultisigAccountError.self) { try record.checkLedgerRegistration(for: pairing.account) }
        }
        record.ledger = nil
        try record.checkLedgerRegistration(for: pairing.account)
    }

    @Test("two Winnows and a Ledger: 2-of-3 now, the Ledger alone after 10 blocks")
    func twoOfThreeWithRecovery() async throws {
        let masters = try TestKeys.masters()
        let simulator = LedgerSimulator(master: masters[1])
        let client = LedgerBitcoinClient(transport: simulator)
        let (ledgerKey, fingerprint) = try await LedgerMultisig.signerExpression(client: client, network: .signet)
        let descriptor = try MultisigAccount.descriptor(
            threshold: 2,
            signers: [try TestKeys.keyExpression(master: masters[0]), try TestKeys.keyExpression(master: masters[2]),
                      ledgerKey],
            recovery: .fewerSigners(threshold: 1, blocks: 10), network: .signet)
        let account = try MultisigAccount(descriptor: descriptor, network: .signet)
        let policy = try LedgerWalletPolicy(name: "Family 2-of-3", account: account)
        #expect(policy.template
            == "tr(@0/**,{sortedmulti_a(2,@1/**,@2/**,@3/**),and_v(v:multi_a(1,@1/<2;3>/*,@2/<2;3>/*,@3/<2;3>/*),older(10))})")
        #expect(policy.keys.count == 4)
        let registration = try await LedgerMultisig.register(account, name: "Family 2-of-3", fingerprint: fingerprint,
                                                             client: client)
        _ = try await LedgerMultisig.displayAddress(account, registration: registration, choice: 1, index: 3,
                                                    client: client)

        let coin = try WalletUTXO(txid: Data(repeating: 0x61, count: 32), vout: 0, amount: 90_000,
                                  scriptPubKey: account.scriptPubKey(index: 0), chain: .receive, index: 0, height: 100)
        let owned = [MultisigAccount.OutputCoordinate(choice: 1, index: 0)]
        let payment = Payment(amount: 50_000, scriptPubKey: Data([0x51, 0x20] + repeatElement(0x77, count: 32)))
        // The builder sorts signers by key, so `approvals` names each signer
        // by its position in the account, not in the list above.
        let phoneKey = try masters[0].derived(path: "m/86'/1'/0'").publicKey
        let phone = try #require(account.signers.firstIndex { signer in
            if case let .extended(xpub, _) = signer.base { return xpub.publicKey == phoneKey }
            return false
        })
        let ledger = try #require(account.signers.firstIndex { signer in
            signer.origin?.fingerprint == registration.masterFingerprint && signer.origin?.path == registration.keyPath
        })
        // Now: one Winnow and the Ledger.
        var now = try account.createSpend(utxos: [coin], payments: [payment], changeIndex: 0, feeRateSatPerVByte: 2,
                                          chainTip: 101, randomness: { 0.5 })
        try account.sign(&now, signingKey: masters[0], knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: 101)
        try await LedgerMultisig.sign(&now, account: account, registration: registration, client: client)
        #expect(try account.approvals(of: now, knownUTXOs: [coin]) == [phone, ledger])
        _ = try account.finalizeSpend(&now, knownUTXOs: [coin], ownedOutputCoordinates: owned, chainTip: 101)

        // After the delay: the Ledger alone.
        var later = try account.createSpend(utxos: [coin], payments: [payment], changeIndex: 0, feeRateSatPerVByte: 2,
                                            chainTip: 109, path: .recovery, randomness: { 0.5 })
        try await LedgerMultisig.sign(&later, account: account, registration: registration, client: client)
        #expect(try account.approvals(of: later, knownUTXOs: [coin], path: .recovery) == [ledger])
        let transaction = try account.finalizeSpend(&later, knownUTXOs: [coin], ownedOutputCoordinates: owned,
                                                    chainTip: 109)
        #expect(transaction.inputs[0].sequence == 10)
    }

    @Test("the Ledger may sign first; the phone's signature completes the spend")
    func ledgerSignsFirst() async throws {
        let pairing = try await Self.pair()
        let owned = [MultisigAccount.OutputCoordinate(choice: 1, index: 0)]
        var (psbt, utxos) = try Self.spend(pairing.account)
        try await LedgerMultisig.sign(&psbt, account: pairing.account, registration: pairing.registration,
                                      client: pairing.client)
        #expect(try pairing.account.approvals(of: psbt, knownUTXOs: utxos) == [1])
        try pairing.account.sign(&psbt, signingKey: pairing.phone, knownUTXOs: utxos, ownedOutputCoordinates: owned,
                                 chainTip: 200)
        _ = try pairing.account.finalizeSpend(&psbt, knownUTXOs: utxos, ownedOutputCoordinates: owned, chainTip: 200)
    }

    @Test("a refusal on the device, another account's registration and a bad signature leave the PSBT alone")
    func refusals() async throws {
        let pairing = try await Self.pair()
        var (psbt, _) = try Self.spend(pairing.account)
        let untouched = psbt

        await pairing.simulator.setDecision(.reject)
        await #expect(throws: LedgerError.rejectedOnDevice) {
            try await LedgerMultisig.sign(&psbt, account: pairing.account, registration: pairing.registration,
                                          client: pairing.client)
        }
        #expect(psbt == untouched)
        await pairing.simulator.setDecision(.approve)

        var other = pairing.registration
        other.policyName = "Another account"
        await #expect(throws: LedgerError.self) {
            try await LedgerMultisig.sign(&psbt, account: pairing.account, registration: other, client: pairing.client)
        }

        let tampering = try await Self.pair { TamperingTransport(inner: $0) }
        var (tamperedPSBT, _) = try Self.spend(tampering.account)
        let before = tamperedPSBT
        await #expect(throws: LedgerError.mismatch("a Ledger signature does not verify")) {
            try await LedgerMultisig.sign(&tamperedPSBT, account: tampering.account,
                                          registration: tampering.registration, client: tampering.client)
        }
        #expect(tamperedPSBT == before)
    }

    @Test("a Ledger key for another path or network is refused when pairing")
    func wrongKeyRefused() async throws {
        let simulator = LedgerSimulator(master: try TestKeys.masters()[1])
        let client = LedgerBitcoinClient(transport: simulator)
        await #expect(throws: LedgerError.self) {
            _ = try await LedgerMultisig.signerExpression(client: client, network: .mainnet)
        }
        #expect(LedgerWalletPolicy.isValidName("Savings"))
        for bad in ["", " leading", "trailing ", String(repeating: "x", count: 65), "caf\u{E9}"] {
            #expect(!LedgerWalletPolicy.isValidName(bad), "\(bad)")
        }
    }
}

/// Flips one bit in every signature the device yields.
struct TamperingTransport: LedgerTransport {
    let inner: LedgerSimulator

    func exchange(_ apdu: Data) async throws -> Data {
        var reply = try await inner.exchange(apdu)
        let bytes = Array(reply)
        if bytes.count > 70, bytes.first == 0x10, bytes.suffix(2) == [0xE0, 0x00] {
            reply[reply.startIndex + bytes.count - 3] ^= 0x01
        }
        return reply
    }
}

enum LedgerSimulatorHash {
    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}
