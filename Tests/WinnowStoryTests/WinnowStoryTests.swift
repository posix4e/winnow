import BitcoinCore
import BitcoinP2P
import Foundation
import Testing
import WalletCore
@testable import WinnowStory

@Suite("Winnow story framework")
struct WinnowStoryTests {
    private func repository() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "winnow-story-tests-\(UUID().uuidString)", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func environment() -> StoryEnvironment {
        StoryEnvironment(gitCommit: "abc123", swiftVersion: "Swift test",
                         xcodeVersion: "Xcode test", simulatorUDID: "SIM", simulatorName: "iPhone")
    }

    private func deterministicState() -> StoryRunState {
        var state = StoryRunState(runID: "test-run", environment: environment(), secrets: [])
        let bytes: [String: UInt8] = [
            "sofia": 0x10, "lina": 0x20, "elena": 0x30,
            "leo": 0x40, "marina": 0x50, "mateo": 0x60,
        ]
        state.secrets = StoryPersona.cast.map {
            let count = ["sofia", "lina", "elena"].contains($0.id) ? 16 : 32
            return StorySecretIdentity(personaID: $0.id,
                                       seedHex: Data(repeating: bytes[$0.id]!, count: count).hex)
        }
        return state
    }

    private func testMovieData(duration: UInt32 = 1_200, samples: UInt32 = 3) -> Data {
        func be32(_ value: UInt32) -> [UInt8] {
            [UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
             UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
        }
        // Minimal structural mvhd + stsz boxes. The review gate reads only the
        // standard timing and sample-count fields and does not decode pixels.
        var result = Data(be32(28) + Array("mvhd".utf8))
        result.append(contentsOf: [0, 0, 0, 0]) // version + flags
        result.append(contentsOf: be32(0)) // creation
        result.append(contentsOf: be32(0)) // modification
        result.append(contentsOf: be32(600))
        result.append(contentsOf: be32(duration))
        result.append(contentsOf: be32(20) + Array("stsz".utf8))
        result.append(contentsOf: [0, 0, 0, 0]) // version + flags
        result.append(contentsOf: be32(0)) // variable sample sizes
        result.append(contentsOf: be32(samples))
        return result
    }

    @Test("checkpoint transitions are resumable and idempotent")
    func checkpointResume() throws {
        var state = deterministicState()
        let txid = String(repeating: "a1", count: 32)
        try state.transition(.preflight, to: .passed, txid: txid, height: 123,
                             label: "preflight-proof", personaID: "sofia")
        try state.transition(.preflight, to: .passed, txid: txid, height: 123,
                             label: "preflight-proof", personaID: "sofia")
        #expect(state.checkpoints[StoryCheckpoint.preflight.rawValue]?.transactionIDs == [txid])
        #expect(state.checkpoints[StoryCheckpoint.preflight.rawValue]?.confirmationHeights == [123])
        #expect(state.transactionEvidence?.count == 1)
        #expect(state.transactionEvidence?.first?.label == "preflight-proof")
        #expect(state.transactionEvidence?.first?.status == .confirmationClaimed)
        #expect(state.activeCheckpoint == .sofiaOnboarding)
        #expect(state.checkpoints[StoryCheckpoint.sofiaOnboarding.rawValue]?.status == .active)
        #expect(state.checkpoints[StoryCheckpoint.sofiaOnboarding.rawValue]?.startedAt != nil)
        #expect(throws: StoryModelError.self) {
            try state.transition(.preflight, to: .failed)
        }
    }

    @Test("a deferred checkpoint advances but still blocks publication")
    func deferredCheckpoint() throws {
        var state = deterministicState()
        try state.transition(.preflight, to: .passed)
        try state.transition(.sofiaOnboarding, to: .passed)
        try state.transition(.customerFunding, to: .passed)
        try state.transition(.supplierRBF, to: .passed)
        try state.transition(.silentPayments, to: .deferred,
                             note: "Held for a later experimental run")

        #expect(state.checkpoints[StoryCheckpoint.silentPayments.rawValue]?.status == .deferred)
        #expect(state.activeCheckpoint == .inheritanceVault)
        #expect(state.checkpoints[StoryCheckpoint.inheritanceVault.rawValue]?.status == .active)
        let incomplete = StoryCheckpoint.allCases.dropLast().filter {
            state.checkpoints[$0.rawValue]?.status != .passed
        }
        #expect(incomplete.contains(.silentPayments))
    }

    @Test("older states migrate and private state is owner-only")
    func migrationAndPermissions() throws {
        let repository = try repository()
        defer { try? FileManager.default.removeItem(at: repository) }
        for oldVersion in [0, 1, 2, 3, 4] {
            let store = StoryStore(repository: repository, runID: "migration-\(oldVersion)")
            var state = try store.create(environment: environment())
            state.version = oldVersion
            state.scenario = "whole-app-public-signet-v\(oldVersion)"
            state.transactionEvidence = nil
            let migratedTxid = String(repeating: "ab", count: 32)
            state.checkpoints[StoryCheckpoint.customerFunding.rawValue]?.transactionIDs = [migratedTxid]
            state.checkpoints[StoryCheckpoint.customerFunding.rawValue]?.confirmationHeights = [321]
            try store.save(state)
            let migrated = try store.load()
            #expect(migrated.version == StoryRunState.currentVersion)
            #expect(migrated.scenario == StoryRunState.currentScenario)
            #expect(migrated.personas == StoryPersona.cast)
            #expect(migrated.transactionEvidence?.first?.txid == migratedTxid)
            #expect(migrated.transactionEvidence?.first?.confirmationHeight == 321)
            #expect(migrated.transactionEvidence?.first?.status == .confirmationClaimed)
            let attributes = try FileManager.default.attributesOfItem(atPath: store.paths.privateState.path)
            #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        }
    }

    @Test("block evidence authenticates the transaction and records its parents")
    func transactionEvidenceInspection() throws {
        let parent = Data(repeating: 0x31, count: 32)
        let input = Transaction.Input(
            previousOutput: Transaction.Outpoint(txid: parent, vout: 2),
            scriptSig: Data(), sequence: 0xFFFF_FFFD)
        let output = Transaction.Output(value: 42_000, scriptPubKey: Data([0x51]))
        let transaction = Transaction(version: 2, inputs: [input], outputs: [output], locktime: 0)
        let header = BlockHeader(version: 1, previousHash: Data(repeating: 0, count: 32),
                                 merkleRoot: transaction.txid, time: 1_700_000_000,
                                 bits: 0x1D00_FFFF, nonce: 7)
        let block = Block(header: header, transactions: [transaction])
        let verified = try StoryEvidenceVerifier.inspect(
            block: block, expectedBlockHash: block.hash, txid: transaction.txid,
            txidText: transaction.txid.displayHex, height: 222)
        #expect(verified.txid == transaction.txid.displayHex)
        #expect(verified.blockHash == block.hash.displayHex)
        #expect(verified.parentTransactionIDs == [parent.displayHex])
    }

    @Test("the audit proves the café hot-to-cold-to-joint money trail")
    func evidenceLineageAudit() throws {
        var state = deterministicState()
        let txid: (UInt8) -> String = { String(repeating: String(format: "%02x", $0), count: 32) }

        func add(_ byte: UInt8, _ checkpoint: StoryCheckpoint, _ parents: [String] = []) throws {
            let id = txid(byte)
            try state.transition(checkpoint, to: .passed, txid: id,
                                 height: 1_000 + UInt32(byte), label: "proof-\(byte)")
            try state.markTransactionVerified(txid: id, checkpoint: checkpoint,
                                              height: 1_000 + UInt32(byte),
                                              blockHash: txid(byte &+ 100),
                                              parentTransactionIDs: parents)
        }

        try add(1, .customerFunding)
        try add(2, .supplierRBF)
        try add(3, .silentPayments)
        try add(4, .silentPayments)
        try add(5, .inheritanceVault, [txid(1)])
        try add(6, .inheritanceVault, [txid(5)])
        try add(7, .inheritanceVault, [txid(6)])
        try add(8, .jointReserve, [txid(7)])
        try add(9, .jointReserve, [txid(8)])

        #expect(StoryEvidenceAudit.evaluate(state).passed)
    }

    @Test("public report excludes protected identities and rejects secret text")
    func redaction() throws {
        let repository = try repository()
        defer { try? FileManager.default.removeItem(at: repository) }
        let store = StoryStore(repository: repository, runID: "redaction")
        var state = try store.create(environment: environment())
        for checkpoint in StoryCheckpoint.allCases.dropLast() {
            try state.transition(checkpoint, to: .passed)
        }
        let txid = String(repeating: "ab", count: 32)
        state.checkpoints[StoryCheckpoint.customerFunding.rawValue]?.transactionIDs = [txid]
        try store.finish(state)
        let manifest = try String(contentsOf: store.paths.artifacts.appending(path: "public-manifest.json"),
                                  encoding: .utf8)
        #expect(!manifest.contains("seedHex"))
        #expect(!state.secrets.contains { manifest.contains($0.seedHex) })
        let report = try String(contentsOf: store.paths.artifacts.appending(path: "report.md"),
                                encoding: .utf8)
        #expect(report.contains("https://explorer.bc-2.jp/tx/\(txid)"))
        #expect(!report.contains("mempool.space"))

        let unsafe = store.paths.artifacts.appending(path: "unsafe.txt")
        try "mnemonic: never publish this".write(to: unsafe, atomically: true, encoding: .utf8)
        #expect(throws: StoryModelError.self) {
            try store.scanPublishableText(in: store.paths.artifacts, secrets: state.secrets.map(\.seedHex))
        }

        try FileManager.default.removeItem(at: unsafe)
        let recoveryWords = try BIP39.mnemonic(entropy: Data(hex: state.secrets[0].seedHex)!)
        try recoveryWords.write(to: unsafe, atomically: true, encoding: .utf8)
        #expect(throws: StoryModelError.self) {
            try store.scanPublishableText(in: store.paths.artifacts, secrets: state.secrets.map(\.seedHex))
        }

        try FileManager.default.removeItem(at: unsafe)
        let nested = store.paths.artifacts.appending(path: "diagnostics", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
        try "privateKey: nested secret".write(to: nested.appending(path: "app.log"),
                                               atomically: true, encoding: .utf8)
        #expect(throws: StoryModelError.self) {
            try store.scanPublishableText(in: store.paths.artifacts, secrets: state.secrets.map(\.seedHex))
        }
    }

    @Test("media approval covers every stage and is invalidated by any changed file")
    func mediaReviewGate() throws {
        let repository = try repository()
        defer { try? FileManager.default.removeItem(at: repository) }
        let store = StoryStore(repository: repository, runID: "media-review")
        var state = try store.create(environment: environment())
        for checkpoint in StoryCheckpoint.allCases where checkpoint != .publish {
            for suffix in ["mp4", "png"] {
                let url = store.paths.artifacts.appending(path: "\(checkpoint.rawValue).\(suffix)")
                let data = suffix == "mp4" ? testMovieData() : Data("\(checkpoint.rawValue)-png".utf8)
                try data.write(to: url)
            }
        }

        let listed = try FileManager.default.contentsOfDirectory(
            at: store.paths.artifacts, includingPropertiesForKeys: nil)
        #expect(listed.count == 18)
        let inventory = try store.mediaInventory()
        #expect(inventory.count == 18)
        #expect(try store.mediaReviewViolations(nil).contains {
            $0.contains("has not been approved")
        })

        let review = StoryMediaReview(reviewedAt: Date(timeIntervalSince1970: 123),
                                      artifacts: inventory)
        #expect(try store.mediaReviewViolations(review).isEmpty)
        let checklist = try store.writeMediaReviewChecklist(inventory, review: review)
        let checklistText = try String(contentsOf: checklist, encoding: .utf8)
        #expect(checklistText.contains("Status: approved"))
        #expect(checklistText.contains(inventory[0].sha256))
        let page = try store.writeMediaReviewPage(inventory, review: review)
        let pageText = try String(contentsOf: page, encoding: .utf8)
        #expect(pageText.contains("<video controls"))
        #expect(pageText.contains("<img loading"))
        #expect(pageText.contains(inventory[0].sha256))
        state.mediaReview = review
        try store.finish(state)
        let manifestData = try Data(contentsOf: store.paths.artifacts.appending(path: "public-manifest.json"))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(StoryPublicManifest.self, from: manifestData)
        #expect(manifest.humanMediaReview == review)

        try Data("changed after approval".utf8).write(
            to: store.paths.artifacts.appending(path: "privacy-tour.png"))
        #expect(try store.mediaReviewViolations(review).contains {
            $0.contains("changed after human review")
        })

        try testMovieData(duration: 40, samples: 1).write(
            to: store.paths.artifacts.appending(path: "preflight.mp4"))
        let badMovieReview = StoryMediaReview(artifacts: try store.mediaInventory())
        let badMovieViolations = try store.mediaReviewViolations(badMovieReview)
        #expect(badMovieViolations.contains { $0.contains("not a multi-frame video") })
    }

    @Test("a failed redaction scan cannot create a false passing report")
    func redactionPrecedesPublicationWrite() throws {
        let repository = try repository()
        defer { try? FileManager.default.removeItem(at: repository) }
        let store = StoryStore(repository: repository, runID: "redaction-order")
        let state = try store.create(environment: environment())
        try "secretNonce: do not publish".write(
            to: store.paths.artifacts.appending(path: "unsafe.log"),
            atomically: true, encoding: .utf8)

        #expect(throws: StoryModelError.self) { try store.finish(state) }
        #expect(!FileManager.default.fileExists(
            atPath: store.paths.artifacts.appending(path: "public-manifest.json").path))
        #expect(!FileManager.default.fileExists(
            atPath: store.paths.artifacts.appending(path: "report.md").path))
    }

    @Test("publication requires safe journal proof of device-authenticated recovery")
    func recoveryEvidenceGate() throws {
        let repository = try repository()
        defer { try? FileManager.default.removeItem(at: repository) }
        let store = StoryStore(repository: repository, runID: "recovery-evidence")
        _ = try store.create(environment: environment())
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601

        let basic = ["wallet.created", "backup.completed", "wallet.ready"].map {
            StoryEvent(name: $0, persona: "sofia")
        }
        let sofiaData = try basic.reduce(into: Data()) { result, event in
            result.append(try encoder.encode(event)); result.append(0x0A)
        }
        try sofiaData.write(to: store.paths.artifacts.appending(path: "sofia-events.jsonl"))
        #expect(store.recoveryEvidenceViolations().contains {
            $0.contains("device-authenticated recovery reveal")
        })

        let authenticated = StoryEvent(
            name: "backup.phraseRevealReady", persona: "sofia-replacement",
            fields: ["deviceAuthenticationRequired": "true"])
        var replacementData = try encoder.encode(authenticated)
        replacementData.append(0x0A)
        try replacementData.write(
            to: store.paths.artifacts.appending(path: "sofia-replacement-events.jsonl"))
        #expect(store.recoveryEvidenceViolations().isEmpty)
    }

    @Test("verbose child commands cannot deadlock the story runner")
    func commandOutputIsDrained() throws {
        let repository = try repository()
        defer { try? FileManager.default.removeItem(at: repository) }
        let input = repository.appending(path: "large-output.txt")
        let data = Data(repeating: 0x78, count: 1_000_000)
        try data.write(to: input)
        let result = try StorySystem(repository: repository).run("/bin/cat", [input.path])
        #expect(result.status == 0)
        #expect(result.stdout.utf8.count == data.count)
    }

    @Test("silent index serves exactly the documented height endpoint")
    func silentIndexContract() throws {
        let repository = try repository()
        defer { try? FileManager.default.removeItem(at: repository) }
        let store = StoryStore(repository: repository, runID: "index")
        _ = try store.create(environment: environment())
        let point = "02" + String(repeating: "11", count: 32)
        try store.addTweak(height: 321, hex: point)
        let fixture = SilentIndexFixture(tweaksURL: store.paths.tweaks)
        let response = String(decoding: fixture.response(path: "/tweaks/321"), as: UTF8.self)
        #expect(response.contains("200 OK"))
        #expect(response.contains(point))
        #expect(String(decoding: fixture.response(path: "/address/query"), as: UTF8.self).contains("404 Not Found"))
    }

    @Test("companion creates a signed silent send Lina cannot regenerate differently on resume")
    func companionSilentSend() async throws {
        let state = deterministicState()
        let companion = StoryCompanion(state: state)
        let recipient = try await companion.silentAddress(for: "sofia")
        let inputTxid = String(repeating: "42", count: 32)
        let prepared = try await companion.prepareSilentSend(
            label: "lina-to-sofia-silent", from: "lina",
            inputTxid: inputTxid, inputVout: 0,
            inputAmount: 50_000, inputHeight: 321,
            recipient: recipient, amount: 20_000,
            feeRateSatPerVByte: 2)

        let raw = try #require(Data(hex: prepared.rawTransaction))
        let transaction = try Transaction.decode(raw)
        #expect(transaction.txid.displayHex == prepared.txid)
        #expect(prepared.tweakData.count == 66)
        #expect(prepared.fee > 0)

        let scan = try SilentPaymentReceiving.scanKey(
            from: companion.master(for: "sofia"), coinType: 1, account: 0)
        let spend = try SilentPaymentReceiving.spendKey(
            from: companion.master(for: "sofia"), coinType: 1, account: 0)
        let shared = try SilentPaymentReceiving.sharedSecret(
            scanPrivateKey: try #require(scan.privateKey),
            tweakData: try #require(Data(hex: prepared.tweakData)))
        let outputKeys = transaction.outputs.compactMap { output -> Data? in
            guard output.scriptPubKey.count == 34,
                  output.scriptPubKey.prefix(2).elementsEqual([0x51, 0x20]) else { return nil }
            return Data(output.scriptPubKey.dropFirst(2))
        }
        let matches = try SilentPaymentReceiving.scan(
            outputs: outputKeys, sharedSecret: shared,
            spendPublicKey: spend.publicKey)
        #expect(matches.count == 1)
        #expect(transaction.outputs.contains {
            $0.value == 20_000 && outputKeys.contains(Data($0.scriptPubKey.dropFirst(2)))
        })
    }

    @Test("silent companion fee bump preserves the BIP352 output and is deterministic")
    func companionSilentFeeBump() async throws {
        let state = deterministicState()
        let companion = StoryCompanion(state: state)
        let recipient = try await companion.silentAddress(for: "sofia")
        let original = try await companion.prepareSilentSend(
            label: "lina-to-sofia-silent", from: "lina",
            inputTxid: String(repeating: "42", count: 32), inputVout: 0,
            inputAmount: 50_000, inputHeight: 321,
            recipient: recipient, amount: 20_000,
            feeRateSatPerVByte: 2)

        let replacement = try await companion.prepareSilentFeeBump(
            label: "lina-to-sofia-silent-rbf", replacing: original,
            recipientPersonaID: "sofia", feeRateSatPerVByte: 10)
        let repeated = try await companion.prepareSilentFeeBump(
            label: "lina-to-sofia-silent-rbf", replacing: original,
            recipientPersonaID: "sofia", feeRateSatPerVByte: 10)
        #expect(replacement == repeated)
        #expect(replacement.replaces == original.txid)
        #expect(replacement.tweakData == original.tweakData)
        #expect(replacement.fee > original.fee)
        #expect(replacement.relayPeerCount == 0)

        let originalTransaction = try Transaction.decode(
            try #require(Data(hex: original.rawTransaction)))
        let replacementTransaction = try Transaction.decode(
            try #require(Data(hex: replacement.rawTransaction)))
        #expect(replacementTransaction.inputs.map(\.previousOutput)
            == originalTransaction.inputs.map(\.previousOutput))
        let silentOutput = try #require(originalTransaction.outputs.first {
            $0.value == original.amount
        })
        #expect(replacementTransaction.outputs.contains(silentOutput))
        #expect(replacement.fee >= original.fee
            + Int64(TransactionBuilder.vsize(of: replacementTransaction)))
    }

    @Test("named inheritance companions produce a finalizable 2-of-3 spend")
    func inheritanceCompanions() throws {
        let state = deterministicState()
        let companion = StoryCompanion(state: state)
        let vault = try Vault(descriptor: companion.inheritanceDescriptor(), network: .signet)
        let utxo = try WalletUTXO(txid: Data(repeating: 0x71, count: 32), vout: 0, amount: 120_000,
                                  scriptPubKey: vault.scriptPubKey(index: 0, choice: 0),
                                  chain: .receive, index: 0, height: 100)
        let destination = Data([0x51, 0x20] + repeatElement(0x77, count: 32))
        let created = try vault.createSpend(utxos: [utxo],
                                            payments: [Payment(amount: 60_000, scriptPubKey: destination)],
                                            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        let leo = try PSBT(base64: companion.partialSignInheritance(psbtBase64: created.base64, as: "leo"))
        let marina = try PSBT(base64: companion.partialSignInheritance(psbtBase64: created.base64, as: "marina"))
        var combined = try leo.combined(with: [marina])
        let ownedCoordinates = [Vault.OutputCoordinate(choice: 1, index: 0)]
        let transaction = try vault.finalizeSpend(
            &combined, knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates)
        #expect(transaction.inputs[0].witness.count >= 4)
    }

    @Test("Mateo companion completes both MuSig2 rounds and consumes its nonce")
    func musigCompanion() throws {
        var state = deterministicState()
        var companion = StoryCompanion(state: state)
        let vault = try Vault(descriptor: companion.jointReserveDescriptor(), network: .signet)
        let utxo = try WalletUTXO(txid: Data(repeating: 0x72, count: 32), vout: 0, amount: 100_000,
                                  scriptPubKey: vault.scriptPubKey(index: 0, choice: 0),
                                  chain: .receive, index: 0, height: 100)
        let destination = Data([0x51, 0x20] + repeatElement(0x78, count: 32))
        let created = try vault.createSpend(utxos: [utxo],
                                            payments: [Payment(amount: 50_000, scriptPubKey: destination)],
                                            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
        let context = try vault.muSig2Context(choice: 0, index: 0)

        var elenaNonce = created
        let ownedCoordinates = [Vault.OutputCoordinate(choice: 1, index: 0)]
        var elenaSecrets = try vault.muSig2AttachNonce(
            &elenaNonce, input: 0, context: context, master: companion.master(for: "elena"),
            knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates)
        let mateoNonce = try companion.attachMateoNonces(psbtBase64: created.base64)
        let repeatedNonce = try StoryCompanion(state: mateoNonce.state)
            .attachMateoNonces(psbtBase64: created.base64)
        #expect(repeatedNonce.psbt == mateoNonce.psbt)
        #expect(repeatedNonce.state.musigSecretNonces == mateoNonce.state.musigSecretNonces)
        state = mateoNonce.state
        companion = StoryCompanion(state: state)
        let withNonces = try elenaNonce.combined(with: [PSBT(base64: mateoNonce.psbt)])

        var elenaSigned = withNonces
        try vault.muSig2Sign(&elenaSigned, input: 0, context: context,
                             master: companion.master(for: "elena"), secretNonces: &elenaSecrets,
                             knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates)
        let mateoSigned = try companion.signMateo(psbtBase64: withNonces.base64)
        #expect(mateoSigned.state.musigSecretNonces.isEmpty)
        let repeatedSigned = try StoryCompanion(state: mateoSigned.state)
            .signMateo(psbtBase64: withNonces.base64)
        #expect(repeatedSigned.psbt == mateoSigned.psbt)
        var combined = try elenaSigned.combined(with: [PSBT(base64: mateoSigned.psbt)])
        try vault.muSig2Aggregate(&combined, input: 0, context: context,
                                  knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates)
        let transaction = try vault.finalizeSpend(
            &combined, knownUTXOs: [utxo], ownedOutputCoordinates: ownedCoordinates)
        #expect(transaction.inputs[0].witness.count == 1)
        #expect(transaction.inputs[0].witness[0].count == 64)
    }
}

/// A plausible validated tip for story tests that build a vault spend, paired
/// with a fixed draw so the resulting transaction is byte-stable (#139).
let testChainTip: UInt32 = 840_000
