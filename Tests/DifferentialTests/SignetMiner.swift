import BitcoinCore
import BitcoinP2P
import CryptoKit
import Foundation
import P256K

/// BIP325 signet miner for the dev node. Core 31.1's `generatetoaddress`
/// builds blocks but does NOT sign them for custom signets (no signet
/// signing path in rpc/mining.cpp — the node rejects them with
/// bad-signet-blksig), so the harness runs the whole cycle itself:
/// getblocktemplate → build coinbase → BIP325 block signature (legacy
/// SIGHASH_ALL against the challenge) → PoW grind → submitblock.
///
/// Copied into UITests/SignetMiner.swift (the SPM test target and the Xcode
/// UI-test target are separate worlds; keep them in sync). Both copies mine
/// against the same node, so a grep over one directory undercounts the call
/// sites — which is how #28's exposure analysis came in 102 draws short.
enum SignetMiner {
    enum MinerError: Error, Equatable {
        case wallet(String)
        case rejected(String)
    }

    private static func sha256d(_ data: Data) -> Data {
        Data(SHA256.hash(data: Data(SHA256.hash(data: data))))
    }

    /// The challenge's signing secret, from the miner wallet's private
    /// descriptor (WIF inside `multi(1,<wif>)`). Never printed.
    private static func signingSecret() throws -> Data {
        let result = try BitcoinCLI.runObject(["listdescriptors", "true"], wallet: "miner")
        let descriptors = try BitcoinCLI.array(result, "descriptors")
        guard let descriptor = (descriptors.first as? [String: Any])?["desc"] as? String,
              let open = descriptor.firstIndex(of: "("), let close = descriptor.lastIndex(of: ")")
        else { throw MinerError.wallet("miner wallet has no private descriptor") }
        let wif = String(descriptor[descriptor.index(after: open) ..< close]
            .split(separator: ",").last ?? "")
        let payload = try Base58Check.decode(wif)
        guard payload.count == 34, payload.first == 0xEF, payload.last == 0x01 else {
            throw MinerError.wallet("unexpected WIF payload")
        }
        return payload.dropFirst().dropLast()
    }

    /// CScript-style data push (handles PUSHDATA1 for the ~80-byte section).
    private static func push(_ data: Data) -> Data {
        switch data.count {
        case 0: return Data([0x00])
        case 1 ... 75: return Data([UInt8(data.count)]) + data
        default: return Data([0x4C, UInt8(data.count)]) + data
        }
    }

    /// BIP34 height as a minimally-encoded script number push.
    /// BIP34's height, encoded the way Core *checks* it.
    ///
    /// Core builds its expectation as `CScript() << nHeight`, and that operator
    /// does not always emit a data push: for 1...16 it emits the single small
    /// integer opcode OP_1...OP_16, and for 0 it emits OP_0. Only outside that
    /// range does it serialize a CScriptNum and push it. A miner that always
    /// pushes gets `bad-cb-height` for exactly the first sixteen blocks of a
    /// chain and is correct from 17 onwards — so this is invisible on an
    /// established fixture and fatal when rebuilding one from genesis.
    private static func heightPush(_ height: Int) -> Data {
        // Two consensus rules meet here. BIP34 checks only that the scriptSig
        // *begins with* the expected encoding, so trailing bytes are legal;
        // and a coinbase scriptSig must be 2...100 bytes. For 1...16 the
        // opcode is a single byte, so it needs one byte of padding or the
        // block is rejected `bad-cb-length` instead. Real miners never notice:
        // their extranonce already pads it.
        if height == 0 { return Data([0x00, 0x00]) }           // OP_0, padded
        if height >= 1, height <= 16 {
            return Data([UInt8(0x50 + height), 0x00])          // OP_1...OP_16, padded
        }
        var bytes: [UInt8] = []
        var value = height
        while value > 0 { bytes.append(UInt8(value & 0xFF)); value >>= 8 }
        if let last = bytes.last, last & 0x80 != 0 { bytes.append(0) }
        return push(Data(bytes))
    }

    /// Bitcoin merkle root over internal-order hashes (duplicates the last
    /// hash on odd levels).
    private static func merkleRoot(_ hashes: [Data]) -> Data {
        var level = hashes
        while level.count > 1 {
            if level.count % 2 == 1 { level.append(level[level.count - 1]) }
            level = stride(from: 0, to: level.count, by: 2).map { sha256d(level[$0] + level[$0 + 1]) }
        }
        return level[0]
    }

    /// `submitblock` answers for a block the node accepted but did not connect
    /// as the tip — valid, just not on the most-work chain. That is a lost race
    /// against the node's background miner, not a broken block.
    private static let offChainAnswers: Set<String> = ["inconclusive", "duplicate-inconclusive"]

    /// One `key=value` line per mining draw, on stderr. Emitted on the
    /// success path as well as the failure one: a lost race that the retry
    /// then won used to leave no trace at all, so a quiet log said nothing
    /// about whether races were being lost — and a retry bound nobody can
    /// measure is a bound nobody can justify (#28). `lost=0` means no race
    /// was lost.
    ///
    /// **Every exit traces: `won`, `exhausted`, `threw`.** The third was
    /// missing until CI run 31987164939, where `submitMinedBlock` threw at its
    /// first `getblocktemplate` and `mineOntoTip` returned through an
    /// untraced path — the call ran, entered the loop, and printed nothing.
    /// The comment here previously claimed no output meant the code had not
    /// run, and that run is the counterexample. Silence is only meaningful
    /// once all exits are covered, which is what `result=threw` restores.
    ///
    /// The remaining caveat is delivery, not coverage: this writes to the
    /// process's fd 2. `swift test` relays that to the step log (observed).
    /// The `UITests` copy runs inside the iOS-simulator test runner, whose
    /// fd 2 relay is **unverified** — simulator `print` (fd 1) is known to
    /// arrive, fd 2 has never been observed either way. So absent output from
    /// the UI leg is a delivery question first and a coverage question second.
    private static func trace(_ fields: String) {
        FileHandle.standardError.write(Data("signet-miner: \(fields)\n".utf8))
    }

    /// A duration as bare decimal seconds, so the trace lines aggregate with
    /// awk without unit-stripping. The lines carry their own durations because
    /// log timestamps do not: CI stamped all 102 lines of the first
    /// instrumented run within 10ms of step end, so they are capture times,
    /// not emit times, and every draw looked instantaneous.
    ///
    /// Two fields, because they answer different questions and only coincide
    /// when no race is lost. `call_s` is the whole call — every attempt plus
    /// the tip re-read between them. `draws_s` is `submitMinedBlock` time
    /// only, summed over completed draws, which is the *exposure window*: a
    /// competitor takes the tip only between our `getblocktemplate` and our
    /// `submitblock`. Dividing `call_s` instead folds in the `bestBlockHash`
    /// check, which sits outside the window and overstates it.
    ///
    /// **Divide by `drawn`, never by `attempts`.** They are equal on `won`
    /// and `exhausted`, and they diverge on `threw` — where `attempts` alone
    /// cannot tell you by how much, because two throw sources share the
    /// label. `submitMinedBlock` throwing leaves the in-flight draw
    /// uncounted (`drawn == attempts - 1`); a throw from the later
    /// `bestBlockHash` leaves it counted (`drawn == attempts`). `drawn`
    /// resolves which, so `draws_s / drawn` and `lost / Σ drawn` are exact
    /// on every line shape instead of exact on two of three.
    private static func seconds(_ duration: Duration) -> String {
        String(format: "%.3f", Double(duration.components.seconds)
            + Double(duration.components.attoseconds) * 1e-18)
    }

    /// An error as a single space-free token, because the trace lines are
    /// parsed by splitting on spaces — a message like "bitcoin-cli not found"
    /// would break every field after it. The type name is enough to route a
    /// reader to the cause; the full text is already in the test failure.
    private static func label(_ error: Error) -> String {
        String(describing: type(of: error))
    }

    /// Mines one block paying the subsidy (+fees) to `payoutScript`. Returns
    /// the accepted block hash (display hex) whether or not it became the tip;
    /// callers that need the tip use `mineOntoTip`.
    ///
    /// `result=connected-at-submit` is exactly what a nil `submitblock` answer
    /// licenses — the node accepted the block and connected it *then*. It is
    /// not a tip claim: this path never re-reads `bestBlockHash`, so a block
    /// reorged out a moment later still traces as connected-at-submit.
    ///
    /// `call_s` and `draws_s` are equal here by construction — the call is
    /// exactly one draw and does nothing else. Both are emitted anyway so one
    /// awk recipe reads either trace line.
    @discardableResult
    static func mineBlock(payingTo payoutScript: Data) async throws -> String {
        let start = ContinuousClock.now
        let submission: (hash: String, answer: String?)
        do {
            submission = try await submitMinedBlock(payingTo: payoutScript)
        } catch {
            // draws_s=0.000, not "-": no draw completed, so no exposure was
            // accrued, and keeping the field numeric everywhere means one awk
            // recipe reads every line shape without special cases.
            trace("mineBlock result=threw attempts=1 drawn=0"
                + " call_s=\(seconds(ContinuousClock.now - start)) draws_s=0.000"
                + " error=\(label(error))")
            throw error
        }
        let draw = ContinuousClock.now - start
        trace("mineBlock result=\(submission.answer == nil ? "connected-at-submit" : "offchain")"
            + " attempts=1 drawn=1 call_s=\(seconds(draw)) draws_s=\(seconds(draw))"
            + " answer=\(submission.answer ?? "-")")
        return submission.hash
    }

    /// Mines until one of our blocks is the tip. The dev node's background
    /// miner produces a block every ~10 minutes, so losing a race is expected:
    /// re-mine on the winner rather than failing the test.
    ///
    /// `maxAttempts` bounds one tip win, but the suites need long unbroken
    /// runs of them — 101 in `FullLoopDiffTests`, 102 across the UI e2e — so
    /// at a per-race loss probability `p` a suite survives with probability
    /// `(1 - p^maxAttempts)^101`: 4.05% at p = 0.5 on the old bound of 5, and
    /// 99.99% at 20. Extra attempts cost nothing on runs that lose no race,
    /// which is what makes raising the bound safe *before* the measurement it
    /// is waiting on; size it for real once the traces above give a p (#28).
    ///
    /// First measurement, uncontended: 0 losses in 101 draws, so p ≤ 2.9% at
    /// 95% confidence. That is the regime with one suite on the node. The
    /// contended p — two suites mining together — is still unobserved, and it
    /// is the one this bound has to survive.
    @discardableResult
    static func mineOntoTip(payingTo payoutScript: Data,
                            maxAttempts: Int = 20) async throws -> String {
        let start = ContinuousClock.now
        var draws = Duration.zero
        var drawn = 0
        var lastAnswer = "connected-then-reorged"
        var lost = 0
        for attempt in 0 ..< maxAttempts {
            let drawStart = ContinuousClock.now
            let submission: (hash: String, answer: String?)
            let isTip: Bool
            do {
                submission = try await submitMinedBlock(payingTo: payoutScript)
                // Both counters move here, together, after the draw returns:
                // an incomplete draw is neither exposure nor a draw.
                draws += ContinuousClock.now - drawStart
                drawn += 1
                isTip = try BitcoinCLI.bestBlockHash() == submission.hash
            } catch {
                trace("mineOntoTip result=threw attempts=\(attempt + 1) max=\(maxAttempts)"
                    + " drawn=\(drawn) lost=\(lost) call_s=\(seconds(ContinuousClock.now - start))"
                    + " draws_s=\(seconds(draws)) error=\(label(error))")
                throw error
            }
            if isTip {
                trace("mineOntoTip result=won attempts=\(attempt + 1) max=\(maxAttempts)"
                    + " drawn=\(drawn) lost=\(lost) call_s=\(seconds(ContinuousClock.now - start))"
                    + " draws_s=\(seconds(draws))"
                    + " last=\(lost == 0 ? "-" : lastAnswer)")
                return submission.hash
            }
            lost += 1
            if let answer = submission.answer { lastAnswer = answer }
        }
        trace("mineOntoTip result=exhausted attempts=\(maxAttempts) max=\(maxAttempts)"
            + " drawn=\(drawn) lost=\(lost) call_s=\(seconds(ContinuousClock.now - start))"
            + " draws_s=\(seconds(draws)) last=\(lastAnswer)")
        throw MinerError.rejected("lost \(maxAttempts) block races (last: \(lastAnswer))")
    }

    /// The mining cycle itself: the block hash plus the node's `submitblock`
    /// answer, which is nil when the block connected as the new tip.
    private static func submitMinedBlock(payingTo payoutScript: Data) async throws
        -> (hash: String, answer: String?)
    {
        let template = try BitcoinCLI.runObject(["getblocktemplate", #"{"rules":["segwit","signet"]}"#])
        let height = try BitcoinCLI.int(template, "height")
        let bitsText = try BitcoinCLI.string(template, "bits")
        let bits = UInt32(bitsText, radix: 16)!
        let time = UInt32(try BitcoinCLI.int(template, "curtime"))
        let version = Int32(bitPattern: UInt32(try BitcoinCLI.int(template, "version")))
        let previousHash = Data(Data(hex: try BitcoinCLI.string(template, "previousblockhash"))!.reversed())
        let coinbaseValue = Int64(try BitcoinCLI.int(template, "coinbasevalue"))
        let reserved = Data(repeating: 0, count: 32)

        let entries = try BitcoinCLI.array(template, "transactions").compactMap { $0 as? [String: Any] }
        let txs = try entries.map { try Transaction.decode(Data(hex: BitcoinCLI.string($0, "data"))!) }
        let txids = try entries.map { Data(Data(hex: try BitcoinCLI.string($0, "txid"))!.reversed()) }
        let wtxids = try entries.map { Data(Data(hex: try BitcoinCLI.string($0, "hash"))!.reversed()) }

        // Coinbase: BIP34 height, witness reserved value, subsidy output and
        // the BIP141 witness commitment (signet section appended post-signing).
        let witnessRoot = merkleRoot([Data(repeating: 0, count: 32)] + wtxids)
        let commitment = Data([0xAA, 0x21, 0xA9, 0xED]) + sha256d(witnessRoot + reserved)
        func makeCoinbase(_ commitmentScript: Data) -> Transaction {
            Transaction(version: 1, inputs: [Transaction.Input(
                previousOutput: Transaction.Outpoint(txid: Data(repeating: 0, count: 32),
                                                     vout: 0xFFFF_FFFF),
                scriptSig: heightPush(height), sequence: 0xFFFF_FFFF, witness: [reserved])],
                outputs: [Transaction.Output(value: coinbaseValue, scriptPubKey: payoutScript),
                          Transaction.Output(value: 0, scriptPubKey: commitmentScript)],
                locktime: 0)
        }
        let unsignedCommitment = Data([0x6A]) + push(commitment)
        // BIP325: the signed-over signet merkle root is computed over the
        // coinbase whose commitment script carries ONLY the 4-byte
        // SIGNET_HEADER push — Core's FetchAndClearCommitmentSection replaces
        // the whole section push with push(header) (erase from
        // begin()+header.size() to end(), then re-push), which is also what
        // the reference miner signs (contrib/signet/miner). Verified
        // empirically against the live default-signet tip.
        let signetHeader = Data([0xEC, 0xC7, 0xDA, 0xA2])
        let coinbase = makeCoinbase(unsignedCommitment + push(signetHeader))

        let signetMerkle = merkleRoot([coinbase.txid] + txids)
        var blockData = Data()
        blockData.appendUInt32LE(UInt32(bitPattern: version))
        blockData.append(previousHash)
        blockData.append(signetMerkle)
        blockData.appendUInt32LE(time)

        // tx_to_spend: version 0, locktime 0, in(prevout null/0xFFFFFFFF,
        // scriptSig = OP_0 push(blockData), seq 0), out(0, challenge).
        var toSpend = Data()
        toSpend.appendUInt32LE(0)
        toSpend.appendVarInt(1)
        toSpend.append(Data(repeating: 0, count: 32))
        toSpend.appendUInt32LE(0xFFFF_FFFF)
        toSpend.appendVarData(Data([0x00]) + push(blockData))
        toSpend.appendUInt32LE(0)
        toSpend.appendVarInt(1)
        toSpend.appendUInt64LE(0)
        toSpend.appendVarData(BitcoinCLI.challenge)
        toSpend.appendUInt32LE(0)
        let toSpendTxid = sha256d(toSpend)

        // Legacy SIGHASH_ALL preimage of tx_spending spending the challenge.
        var preimage = Data()
        preimage.appendUInt32LE(0)
        preimage.appendVarInt(1)
        preimage.append(toSpendTxid)
        preimage.appendUInt32LE(0)
        preimage.appendVarData(BitcoinCLI.challenge)
        preimage.appendUInt32LE(0)
        preimage.appendVarInt(1)
        preimage.appendUInt64LE(0)
        preimage.appendVarData(Data([0x6A])) // OP_RETURN
        preimage.appendUInt32LE(0)
        preimage.appendUInt32LE(1) // SIGHASH_ALL
        let sighash = SHA256.hash(data: Data(SHA256.hash(data: preimage)))

        // The challenge is 1 <pubkey> 1 OP_CHECKMULTISIG — a bare legacy
        // script, so the solution lives in tx_spending's scriptSig (the
        // witness stack is ignored for non-witness scriptPubKeys):
        // OP_0 (CHECKMULTISIG dummy, NULLDUMMY) || push(sig); empty witness.
        let secret = try signingSecret()
        let signature = try P256K.Signing.PrivateKey(dataRepresentation: secret)
            .signature(for: sighash).derRepresentation + Data([0x01])
        let solutionScriptSig = Data([0x00]) + push(signature)
        var section = signetHeader
        section.appendVarData(solutionScriptSig) // tx_spending scriptSig
        section.appendVarInt(0) // tx_spending witness stack (empty)

        let finalCoinbase = makeCoinbase(unsignedCommitment + push(section))
        let merkle = merkleRoot([finalCoinbase.txid] + txids)

        // PoW: grind the nonce with bitcoin-util (multithreaded SHA256 —
        // ~2^22 expected hashes per block at signet difficulty).
        let header = BlockHeader(version: version, previousHash: previousHash,
                                 merkleRoot: merkle, time: time, bits: bits, nonce: 0)
        guard let util = BitcoinCLI.bitcoinUtilPath else {
            throw MinerError.rejected("bitcoin-util not found next to bitcoin-cli")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: util)
        process.arguments = ["-signet", "-signetchallenge=\(BitcoinCLI.challengeHex)",
                             "grind", header.serialized.hex]
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        let groundHex = String(decoding: stdout.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard process.terminationStatus == 0, let groundHeader = Data(hex: groundHex),
              groundHeader.count == BlockHeader.serializedSize
        else { throw MinerError.rejected("bitcoin-util grind failed") }
        let ground = try BlockHeader.decode(groundHeader)

        var block = ground.serialized
        block.appendVarInt(UInt64(txs.count + 1))
        block.append(finalCoinbase.serialized(includeWitness: true))
        for tx in txs { block.append(tx.serialized(includeWitness: true)) }

        let result = try BitcoinCLI.runJSON(["submitblock", block.hex])
        if let answer = result as? String {
            guard offChainAnswers.contains(answer) else { throw MinerError.rejected(answer) }
            return (ground.hash.displayHex, answer)
        }
        return (ground.hash.displayHex, nil)
    }
}

private extension Data {
    /// Little-endian fixed-width appends (BitcoinP2P's are module-internal).
    mutating func appendUInt32LE(_ value: UInt32) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }

    mutating func appendUInt64LE(_ value: UInt64) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }

    mutating func appendVarData(_ bytes: Data) {
        appendVarInt(UInt64(bytes.count))
        append(bytes)
    }
}
