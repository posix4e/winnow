import Darwin
import BitcoinP2P
import Foundation
import WalletCore

@main
public enum WinnowStoryCLI {
    public static func main() async {
        do {
            try await execute(Array(CommandLine.arguments.dropFirst()))
        } catch {
            FileHandle.standardError.write(Data(("error: \(error.localizedDescription)\n").utf8))
            exit(1)
        }
    }

    private static func execute(_ arguments: [String]) async throws {
        guard let command = arguments.first else { return usage() }
        let repository = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let system = StorySystem(repository: repository)

        if ["help", "--help", "-h"].contains(command) {
            usage()
            return
        }

        if command == "doctor" {
            for (name, passed, detail) in system.doctor() {
                print("\(passed ? "✓" : "✗") \(name): \(detail)")
            }
            return
        }

        guard let runID = option("--run", in: arguments) else {
            throw StoryModelError.invalidRunID("missing --run")
        }
        try StoryRunState.validate(runID: runID)
        let store = StoryStore(repository: repository, runID: runID)

        switch command {
        case "start":
            var state = try store.create(environment: system.environment())
            let simulator = try system.selectSimulator(runID: state.runID)
            state.environment.simulatorUDID = simulator.udid
            state.environment.simulatorName = simulator.name
            state.environment.simulatorRuntime = simulator.runtime
            // Persist the device choice before boot/build so a failed
            // preflight resumes on the same isolated simulator.
            try store.save(state)
            try system.boot(simulator.udid)
            try system.buildAndInstall(udid: simulator.udid)
            try state.transition(.preflight, to: .active,
                                 note: "Built and installed without a local Bitcoin node; checking public peers")
            try store.save(state)
            try launchActive(state, system: system, reset: true)
            let peerCount = await waitForPublicPeers(state, system: system)
            if peerCount >= 2 {
                try state.transition(.preflight, to: .passed,
                                     note: "Built without a local Bitcoin node and connected to \(peerCount) public peers")
            } else {
                try state.transition(.preflight, to: .waiting,
                                     note: "Waiting for at least two public signet peers; resume later")
            }
            try store.save(state)
            printSummary(state, store: store)

        case "resume":
            var state = try store.load()
            if state.environment.gitDirty == nil {
                state.environment.gitDirty = system.environment().gitDirty
            }
            if state.checkpoints[state.activeCheckpoint.rawValue]?.status == .pending {
                try state.transition(state.activeCheckpoint, to: .active)
            }
            let simulator: (udid: String, name: String, runtime: String)
            if let recorded = state.environment.simulatorUDID,
               let installed = try system.simulator(udid: recorded) {
                simulator = installed
            } else {
                simulator = try system.selectSimulator(runID: state.runID)
                state.environment.simulatorUDID = simulator.udid
                state.environment.simulatorName = simulator.name
                state.environment.simulatorRuntime = simulator.runtime
                try store.save(state)
            }
            try system.boot(simulator.udid)
            try system.buildAndInstall(udid: simulator.udid)
            try store.save(state)
            try launchActive(state, system: system, reset: false)
            if state.checkpoints[StoryCheckpoint.preflight.rawValue]?.status != .passed {
                let peerCount = await waitForPublicPeers(state, system: system)
                if peerCount >= 2 {
                    try state.transition(.preflight, to: .passed,
                                         note: "Built without a local Bitcoin node and connected to \(peerCount) public peers")
                } else {
                    try state.transition(.preflight, to: .waiting,
                                         note: "Waiting for at least two public signet peers; resume later")
                }
                try store.save(state)
            }
            printSummary(state, store: store)

        case "status":
            printSummary(try store.load(), store: store)

        case "launch-role":
            let state = try store.load()
            let namespace = option("--persona", in: arguments) ?? "sofia"
            let allowed = ["sofia", "elena", "sofia-replacement"]
            guard allowed.contains(namespace) else {
                throw StoryModelError.invalidTransition(
                    "launch-role persona must be sofia, elena, or sofia-replacement")
            }
            let tab = option("--tab", in: arguments) ?? "wallet"
            guard ["wallet", "send", "vaults", "settings"].contains(tab) else {
                throw StoryModelError.invalidTransition(
                    "launch-role tab must be wallet, send, vaults, or settings")
            }
            let identity = namespace == "sofia-replacement" ? "sofia" : namespace
            guard let seed = state.secrets.first(where: { $0.personaID == identity })?.seedHex else {
                throw StoryModelError.invalidTransition("missing seed for \(identity)")
            }
            let udid = try simulatorUDID(state)
            let resetRole = arguments.contains("--reset")
            if resetRole {
                // Let the app perform its namespaced Keychain/defaults wipe,
                // then stop it before a full public-header redownload. The
                // second launch reuses only Sofía's validated public header
                // snapshot; no wallet or key material crosses role stores.
                try system.launch(udid: udid, runID: state.runID, personaID: namespace,
                                  seedHex: seed, reset: true, initialTab: tab)
                try await Task.sleep(for: .seconds(1))
                system.terminate(udid: udid)
                _ = try system.shareSignetHeaders(udid: udid, runID: state.runID,
                                                  destinationPersonaID: namespace)
            } else {
                _ = try system.shareSignetHeaders(udid: udid, runID: state.runID,
                                                  destinationPersonaID: namespace)
            }
            try system.launch(udid: udid, runID: state.runID, personaID: namespace,
                              seedHex: seed, reset: false,
                              clipboard: option("--clipboard", in: arguments),
                              initialTab: tab)
            print("Launched \(namespace) on the \(tab) tab\(resetRole ? " with a fresh role store" : "").")

        case "checkpoint":
            var state = try store.load()
            let checkpoint = try checkpointArgument(arguments)
            let status: StoryCheckpointStatus
            if arguments.contains("--pass") { status = .passed }
            else if arguments.contains("--waiting") { status = .waiting }
            else if arguments.contains("--defer") { status = .deferred }
            else if arguments.contains("--fail") { status = .failed }
            else if arguments.contains("--active") { status = .active }
            else { throw StoryModelError.invalidTransition("choose --pass, --waiting, --defer, --fail, or --active") }
            try state.transition(checkpoint, to: status, note: option("--note", in: arguments),
                                 txid: option("--txid", in: arguments),
                                 height: option("--height", in: arguments).flatMap(UInt32.init),
                                 label: option("--label", in: arguments),
                                 personaID: option("--persona", in: arguments))
            try store.save(state)
            if status == .failed {
                let diagnostics = store.paths.artifacts.appending(path: "diagnostics",
                                                                   directoryHint: .isDirectory)
                try store.writeFailureSummary(state, checkpoint: checkpoint, to: diagnostics)
                try system.collectDiagnostics(udid: simulatorUDID(state), runID: state.runID,
                                              personaID: activeNamespace(state),
                                              checkpoint: checkpoint, destination: diagnostics)
                try store.scanPublishableText(in: diagnostics, secrets: state.secrets.map(\.seedHex))
                print("Captured failure diagnostics in \(diagnostics.path)")
            }
            printSummary(state, store: store)

        case "capture":
            var state = try store.load()
            let stage = try checkpointArgument(arguments)
            let udid = try simulatorUDID(state)
            // Any recording start can truncate or replace a reviewed clip.
            // The next finish therefore requires a fresh human assertion.
            state.mediaReview = nil
            if system.isAlive(pid: state.recordingPID) {
                guard state.recordingStage == stage.rawValue else {
                    throw StorySystemError.recordingAlreadyRunning(
                        state.recordingStage ?? "unknown stage")
                }
                try system.stopRecording(pid: state.recordingPID!)
                let screenshot = store.paths.artifacts.appending(path: "\(stage.rawValue).png")
                try system.screenshot(udid: udid, destination: screenshot)
                print("Stopped \(state.recordingStage ?? stage.rawValue); saved \(screenshot.path)")
                state.recordingPID = nil
                state.recordingStage = nil
                let inventory = try store.mediaInventory()
                _ = try store.writeMediaReviewChecklist(inventory, review: nil)
                _ = try store.writeMediaReviewPage(inventory, review: nil)
            } else {
                // Invalidate a previously approved checklist before simctl
                // starts replacing the movie on disk.
                let inventory = try store.mediaInventory()
                _ = try store.writeMediaReviewChecklist(inventory, review: nil)
                _ = try store.writeMediaReviewPage(inventory, review: nil)
                let movie = store.paths.artifacts.appending(path: "\(stage.rawValue).mp4")
                state.recordingPID = try system.startRecording(udid: udid, destination: movie)
                state.recordingStage = stage.rawValue
                print("Recording \(stage.title). Run the same capture command again to stop.")
            }
            state.updatedAt = Date()
            try store.save(state)

        case "review-media":
            var state = try store.load()
            guard !system.isAlive(pid: state.recordingPID) else {
                throw StoryModelError.invalidTransition(
                    "stop the active stage recording before reviewing media")
            }
            let inventory = try store.mediaInventory()
            let structural = try store.mediaReviewViolations(
                StoryMediaReview(artifacts: inventory)).filter { !$0.contains("changed after") }
            guard structural.isEmpty else {
                print("Media is not ready for review:")
                for violation in structural { print("- \(violation)") }
                throw StoryModelError.invalidTransition("capture every required stage before media review")
            }
            print("Review every video from start to finish and inspect every screenshot:")
            for artifact in inventory {
                print("- \(artifact.path) · \(artifact.byteCount) bytes · sha256 \(artifact.sha256.prefix(12))…")
            }
            if arguments.contains("--approve") {
                let review = StoryMediaReview(artifacts: inventory)
                state.mediaReview = review
                state.updatedAt = Date()
                try store.save(state)
                let checklist = try store.writeMediaReviewChecklist(inventory, review: review)
                let page = try store.writeMediaReviewPage(inventory, review: review)
                print("Human media review recorded. Any changed or added media will invalidate it.")
                print("Checklist: \(checklist.path)")
                print("Review page: \(page.path)")
            } else {
                let checklist = try store.writeMediaReviewChecklist(inventory, review: nil)
                let page = try store.writeMediaReviewPage(inventory, review: nil)
                print("After completing that human review, rerun with --approve.")
                print("Checklist: \(checklist.path)")
                print("Review page: \(page.path)")
            }

        case "address":
            let state = try store.load()
            let persona = option("--persona", in: arguments) ?? "lina"
            let companion = StoryCompanion(state: state)
            print(try companion.standardAddress(for: persona))

        case "keys":
            let companion = StoryCompanion(state: try store.load())
            print("Brisa Café cold reserve · 2-of-3")
            for id in ["elena", "leo", "marina"] {
                print("\(id): \(try companion.keyExpression(for: id, multipath: true))")
            }
            print("\nJoint reserve · 2-of-2 MuSig2")
            for id in ["elena", "mateo"] {
                print("\(id): \(try companion.keyExpression(for: id, multipath: false))")
            }

        case "cosign-inheritance":
            let state = try store.load()
            let signer = option("--as", in: arguments) ?? "leo"
            let psbt = try readInput(option("--psbt", in: arguments))
            print(try StoryCompanion(state: state).partialSignInheritance(psbtBase64: psbt, as: signer))

        case "musig-nonce":
            let state = try store.load()
            let result = try StoryCompanion(state: state).attachMateoNonces(
                psbtBase64: readInput(option("--psbt", in: arguments)))
            try store.save(result.state)
            print(result.psbt)

        case "musig-sign":
            let state = try store.load()
            let result = try StoryCompanion(state: state).signMateo(
                psbtBase64: readInput(option("--psbt", in: arguments)))
            try store.save(result.state)
            print(result.psbt)

        case "verify":
            var state = try store.load()
            let pending = (state.transactionEvidence ?? []).filter {
                $0.confirmationHeight != nil && $0.status != .verified
            }
            if !pending.isEmpty {
                let headers = try system.signetHeadersURL(
                    udid: simulatorUDID(state), runID: state.runID, personaID: "sofia")
                guard FileManager.default.fileExists(atPath: headers.path) else {
                    print("Waiting: Winnow has not saved a public-signet header snapshot yet. Resume after sync.")
                    return
                }
                let chain = try HeaderChain(params: .signet, storageURL: headers)
                let peersURL = store.paths.runDirectory.appending(path: "verification-peers.json")
                let pool = PeerPool(params: .signet, peersFileURL: peersURL)
                await pool.start()
                do {
                    try await pool.syncHeaders(chain, timeoutPerPeer: .seconds(45))
                } catch {
                    await pool.stop()
                    print("Waiting: public-signet evidence peers are unavailable right now. \(error.localizedDescription)")
                    return
                }
                do {
                    for evidence in pending {
                        do {
                            let verified = try await StoryEvidenceVerifier.verifyConnected(
                                evidence, chain: chain, pool: pool)
                            try state.markTransactionVerified(
                                txid: evidence.txid, checkpoint: evidence.checkpoint,
                                height: verified.height, blockHash: verified.blockHash,
                                parentTransactionIDs: verified.parentTransactionIDs)
                            try store.save(state)
                            print("✓ \(evidence.label): authenticated in signet block \(verified.height)")
                        } catch let error as StoryEvidenceError {
                            if case .transactionNotInBlock = error {
                                try state.markTransactionVerificationFailed(
                                    txid: evidence.txid, checkpoint: evidence.checkpoint,
                                    reason: error.localizedDescription)
                                try store.save(state)
                                throw error
                            }
                            print("Waiting: \(evidence.label) could not be authenticated yet. \(error.localizedDescription)")
                        }
                    }
                    await pool.stop()
                } catch {
                    await pool.stop()
                    throw error
                }
            }
            let audit = StoryEvidenceAudit.evaluate(state)
            if audit.passed {
                print("✓ All currently required public-signet transaction evidence and money links are proven.")
            } else {
                print("Evidence still needed:")
                for violation in audit.violations { print("- \(violation)") }
            }

        case "finish":
            var state = try store.load()
            if system.isAlive(pid: state.recordingPID) {
                try system.stopRecording(pid: state.recordingPID!)
                state.recordingPID = nil
                state.recordingStage = nil
            }
            if let udid = state.environment.simulatorUDID {
                try system.collectRunEvidence(udid: udid, runID: state.runID,
                                              destination: store.paths.artifacts)
            }
            let incomplete = StoryCheckpoint.allCases.dropLast().filter {
                state.checkpoints[$0.rawValue]?.status != .passed
            }
            let evidenceAudit = StoryEvidenceAudit.evaluate(state)
            let mediaViolations = try store.mediaReviewViolations(state.mediaReview)
            let recoveryViolations = store.recoveryEvidenceViolations()
            if incomplete.isEmpty, evidenceAudit.passed, mediaViolations.isEmpty,
               recoveryViolations.isEmpty {
                try state.transition(.publish, to: .passed,
                                     note: "Automated redaction and hash-locked human media review passed")
            } else {
                let reasons = [
                    incomplete.isEmpty ? nil : "incomplete: \(incomplete.map(\.rawValue).joined(separator: ", "))",
                    evidenceAudit.passed ? nil : "evidence: \(evidenceAudit.violations.joined(separator: "; "))",
                    mediaViolations.isEmpty ? nil : "media: \(mediaViolations.joined(separator: "; "))",
                    recoveryViolations.isEmpty ? nil : "recovery: \(recoveryViolations.joined(separator: "; "))",
                ].compactMap { $0 }
                try state.transition(.publish, to: .failed,
                                     note: reasons.joined(separator: " · "))
            }
            // Generate and redaction-check public output before committing a
            // passing publication state. A rejected artifact stays resumable.
            try store.finish(state)
            try store.save(state)
            print("Wrote \(store.paths.artifacts.appending(path: "report.md").path)")
            if mediaViolations.isEmpty {
                print("Human media review is hash-locked in the public manifest.")
            } else {
                print("Human media review is still required before publication.")
            }
            guard state.checkpoints[StoryCheckpoint.publish.rawValue]?.status == .passed else {
                throw StoryModelError.invalidTransition(
                    "publication gates did not pass; the failed report is resumable at \(store.paths.artifacts.path)")
            }

        default:
            usage()
        }
    }

    private static func launchActive(_ state: StoryRunState, system: StorySystem, reset: Bool) throws {
        let udid = try simulatorUDID(state)
        let namespace = activeNamespace(state)
        let personaID = namespace == "elena" ? "elena" : "sofia"
        guard let seed = state.secrets.first(where: { $0.personaID == personaID })?.seedHex else {
            throw StoryModelError.invalidTransition("missing seed for \(personaID)")
        }
        system.terminate(udid: udid)
        if !reset {
            _ = try system.shareSignetHeaders(udid: udid, runID: state.runID,
                                              destinationPersonaID: namespace)
        }
        try system.launch(udid: udid, runID: state.runID, personaID: namespace,
                          seedHex: seed, reset: reset,
                          initialTab: [.inheritanceVault, .jointReserve].contains(state.activeCheckpoint)
                              ? "vaults" : "wallet")
    }

    private static func waitForPublicPeers(_ state: StoryRunState, system: StorySystem,
                                           minimum: Int = 2,
                                           timeout: Duration = .seconds(20)) async -> Int {
        guard let udid = state.environment.simulatorUDID else { return 0 }
        let deadline = ContinuousClock.now + timeout
        var count = 0
        while ContinuousClock.now < deadline {
            count = (try? system.publicPeerCount(udid: udid, runID: state.runID)) ?? 0
            if count >= minimum { return count }
            try? await Task.sleep(for: .milliseconds(500))
        }
        return count
    }

    private static func activeNamespace(_ state: StoryRunState) -> String {
        switch state.activeCheckpoint {
        case .inheritanceVault, .jointReserve: "elena"
        case .replacementPhone: "sofia-replacement"
        default: "sofia"
        }
    }

    private static func simulatorUDID(_ state: StoryRunState) throws -> String {
        guard let udid = state.environment.simulatorUDID else { throw StorySystemError.noSimulator }
        return udid
    }

    private static func checkpointArgument(_ arguments: [String]) throws -> StoryCheckpoint {
        guard arguments.count > 1, let checkpoint = StoryCheckpoint(rawValue: arguments[1]) else {
            throw StoryModelError.invalidTransition("use one of: \(StoryCheckpoint.allCases.map(\.rawValue).joined(separator: ", "))")
        }
        return checkpoint
    }

    private static func option(_ name: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: name), arguments.indices.contains(index + 1) else { return nil }
        return arguments[index + 1]
    }

    private static func readInput(_ path: String?) throws -> String {
        let value: String
        if let path, path != "-" {
            value = try String(contentsOfFile: path, encoding: .utf8)
        } else {
            value = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
        }
        return value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func printSummary(_ state: StoryRunState, store: StoryStore) {
        print("\nWinnow story · \(state.runID)")
        print("Scenario: \(state.scenario)")
        print("State: \(store.paths.privateState.path)")
        print("Artifacts: \(store.paths.artifacts.path)\n")
        for checkpoint in StoryCheckpoint.allCases {
            let status = state.checkpoints[checkpoint.rawValue]?.status ?? .pending
            print("\(checkpoint == state.activeCheckpoint ? "→" : " ") [\(status.rawValue)] \(checkpoint.title)")
        }
        print("\nNext: \(state.activeCheckpoint.instruction)")
        if state.activeCheckpoint == .sofiaOnboarding {
            print("Recovery check: enter the simulator passcode when Winnow asks, or choose Features → Face ID → Enrolled and then Matching Face. Never record the words.")
        }
    }

    private static func usage() {
        print("""
        Winnow whole-app public-signet story

          ./scripts/winnow-story doctor
          ./scripts/winnow-story start --run NAME
          ./scripts/winnow-story resume --run NAME
          ./scripts/winnow-story status --run NAME
          ./scripts/winnow-story launch-role --run NAME --persona sofia|elena|sofia-replacement --tab wallet|send|vaults|settings [--clipboard TEXT] [--reset]
          ./scripts/winnow-story capture CHECKPOINT --run NAME
          ./scripts/winnow-story review-media --run NAME [--approve]
          ./scripts/winnow-story checkpoint CHECKPOINT --pass|--waiting|--defer|--fail --run NAME [--note TEXT] [--txid ID] [--height N] [--label TEXT] [--persona ID]
          ./scripts/winnow-story verify --run NAME
          ./scripts/winnow-story address --run NAME --persona lina
          ./scripts/winnow-story keys --run NAME
          ./scripts/winnow-story cosign-inheritance --run NAME --as leo|marina --psbt FILE
          ./scripts/winnow-story musig-nonce|musig-sign --run NAME --psbt FILE
          ./scripts/winnow-story finish --run NAME
        """)
    }
}
