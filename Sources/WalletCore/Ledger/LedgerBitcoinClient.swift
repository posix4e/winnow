import Foundation

/// Carries one APDU to the device and returns its whole reply, status word
/// included. The app implements it over Bluetooth; tests use a simulator.
public protocol LedgerTransport: Sendable {
    func exchange(_ apdu: Data) async throws -> Data
}

/// A signature the device yielded while signing a PSBT.
public struct LedgerSignature: Equatable, Sendable {
    public var inputIndex: Int
    /// 33-byte compressed (segwit v0), 32-byte x-only (key path or leaf).
    public var publicKey: Data
    /// Present for a script-path signature: the leaf it signs for.
    public var leafHash: Data?
    /// 64 bytes, or 65 with a sighash byte.
    public var signature: Data
}

/// Ledger's Bitcoin app (version 2.1.2 or later), command by command, ported
/// from the app's own Python client. Every answer the device gives is
/// checked where the phone can check it; nothing is trusted because the
/// device said it.
public struct LedgerBitcoinClient: Sendable {
    let transport: any LedgerTransport

    public init(transport: any LedgerTransport) {
        self.transport = transport
    }

    public func masterFingerprint() async throws -> UInt32 {
        let data = try await request(.bitcoin(.getMasterFingerprint))
        guard data.count == 4 else { throw LedgerError.protocolViolation("a fingerprint that is not four bytes") }
        return data.reduce(0) { $0 << 8 | UInt32($1) }
    }

    /// The extended public key at `path`. Paths the app calls non-standard
    /// are only answered with `display`, after the user confirms on the device.
    public func extendedPublicKey(path: [UInt32], display: Bool) async throws -> String {
        guard path.count <= 8 else { throw LedgerError.protocolViolation("a path deeper than the app accepts") }
        var data = Data([display ? 1 : 0, UInt8(path.count)])
        for step in path { data.appendUInt32BigEndian(step) }
        let reply = try await request(.bitcoin(.getExtendedPublicKey, data))
        guard let text = String(data: reply, encoding: .ascii), (try? HDKey.deserialize(text)) != nil else {
            throw LedgerError.protocolViolation("an extended key that does not parse")
        }
        return text
    }

    /// Registers `policy` after the user approves it on the device. The id
    /// the device returns must be the policy's own.
    public func register(_ policy: LedgerWalletPolicy) async throws -> (id: Data, hmac: Data) {
        var interpreter = LedgerClientCommandInterpreter()
        policy.register(in: &interpreter)
        var data = Data()
        data.appendCompactSize(UInt64(policy.serialized.count))
        data += policy.serialized
        let reply = try await request(.bitcoin(.registerWallet, data), interpreter: &interpreter)
        guard reply.count == 64 else { throw LedgerError.protocolViolation("a registration that is not 64 bytes") }
        let id = Data(reply.prefix(32))
        guard id == policy.id else { throw LedgerError.mismatch("the registered policy is not the one this phone sent") }
        return (id, Data(reply.suffix(32)))
    }

    /// The address at (change, index), shown on the device when `display`.
    public func address(_ policy: LedgerWalletPolicy, hmac: Data, change: Bool, index: UInt32,
                        display: Bool) async throws -> String {
        guard hmac.count == 32 else { throw LedgerError.protocolViolation("an HMAC that is not 32 bytes") }
        var interpreter = LedgerClientCommandInterpreter()
        policy.register(in: &interpreter)
        var data = Data([display ? 1 : 0]) + policy.id + hmac
        data.append(change ? 1 : 0)
        data.appendUInt32BigEndian(index)
        let reply = try await request(.bitcoin(.getWalletAddress, data), interpreter: &interpreter)
        guard let address = String(data: reply, encoding: .ascii) else {
            throw LedgerError.protocolViolation("an address that is not text")
        }
        return address
    }

    /// Asks the device to sign every input it can, after the user reviews
    /// the payment on its screen; returns the signatures it yields.
    public func signPSBT(_ psbt: PSBT, policy: LedgerWalletPolicy, hmac: Data) async throws -> [LedgerSignature] {
        guard psbt.version == 2 else { throw LedgerError.protocolViolation("the app signs PSBTv2 only") }
        guard hmac.count == 32 else { throw LedgerError.protocolViolation("an HMAC that is not 32 bytes") }
        var interpreter = LedgerClientCommandInterpreter()
        policy.register(in: &interpreter)
        interpreter.addKnownMapping(psbt.globals)
        for input in psbt.inputs { interpreter.addKnownMapping(input.pairs) }
        for output in psbt.outputs { interpreter.addKnownMapping(output.pairs) }
        let inputCommitments = psbt.inputs.map { LedgerMerkle.mapCommitment($0.pairs) }
        let outputCommitments = psbt.outputs.map { LedgerMerkle.mapCommitment($0.pairs) }
        interpreter.addKnownList(inputCommitments)
        interpreter.addKnownList(outputCommitments)

        var data = LedgerMerkle.mapCommitment(psbt.globals)
        data.appendCompactSize(UInt64(psbt.inputs.count))
        data += LedgerMerkle.root(inputCommitments.map(LedgerMerkle.elementHash))
        data.appendCompactSize(UInt64(psbt.outputs.count))
        data += LedgerMerkle.root(outputCommitments.map(LedgerMerkle.elementHash))
        data += policy.id + hmac
        _ = try await request(.bitcoin(.signPSBT, data), interpreter: &interpreter)
        return try interpreter.yielded.compactMap { try Self.signature(fromYield: $0, inputCount: psbt.inputs.count) }
    }

    /// Decodes one yielded value. MuSig2 nonces and partial signatures, and
    /// tags this client does not know, are skipped: this client asks for
    /// script-path signatures only.
    public static func signature(fromYield value: Data, inputCount: Int) throws -> LedgerSignature? {
        var reader = ByteReader(value)
        do {
            let tag = try reader.readVarInt()
            if tag >= 0x8000_0000 { return nil }
            guard tag < UInt64(inputCount) else { throw LedgerError.protocolViolation("a signature for an input that does not exist") }
            let keyLength = Int(try reader.readUInt8())
            let augmented = try reader.readBytes(keyLength)
            let signature = try reader.readBytes(reader.remaining)
            guard signature.count == 64 || signature.count == 65 || (keyLength == 33 && (9 ... 73).contains(signature.count))
            else { throw LedgerError.protocolViolation("a signature of the wrong length") }
            switch keyLength {
            case 64:
                return LedgerSignature(inputIndex: Int(tag), publicKey: Data(augmented.prefix(32)),
                                       leafHash: Data(augmented.suffix(32)), signature: signature)
            case 32, 33:
                return LedgerSignature(inputIndex: Int(tag), publicKey: augmented, leafHash: nil, signature: signature)
            default:
                throw LedgerError.protocolViolation("a signing key of the wrong length")
            }
        } catch let error as LedgerError {
            throw error
        } catch {
            throw LedgerError.protocolViolation("a malformed yielded signature")
        }
    }

    // MARK: - Exchange

    private func request(_ apdu: LedgerAPDU) async throws -> Data {
        var interpreter = LedgerClientCommandInterpreter()
        return try await request(apdu, interpreter: &interpreter)
    }

    /// Sends `apdu`, answers every interruption from `interpreter`, and
    /// returns the final data once the device reports success.
    private func request(_ apdu: LedgerAPDU, interpreter: inout LedgerClientCommandInterpreter) async throws -> Data {
        var response = try LedgerResponse(try await transport.exchange(apdu.serialized()))
        var rounds = 0
        while response.status == LedgerResponse.interrupted {
            rounds += 1
            // A hostile or broken device could ask forever; a real PSBT needs
            // a few thousand rounds at most.
            guard rounds <= 100_000 else { throw LedgerError.protocolViolation("a command that never finishes") }
            let answer = try interpreter.execute(response.data)
            response = try LedgerResponse(try await transport.exchange(LedgerAPDU.continueInterrupted(answer).serialized()))
        }
        guard response.status == LedgerResponse.ok else { throw LedgerError.from(status: response.status) }
        return response.data
    }
}

extension Data {
    mutating func appendUInt32BigEndian(_ value: UInt32) {
        append(contentsOf: [UInt8(value >> 24), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)])
    }
}
