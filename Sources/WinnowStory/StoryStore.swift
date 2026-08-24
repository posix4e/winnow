import BitcoinCore
import CryptoKit
import Foundation

public struct StoryPaths: Sendable, Equatable {
    public let repository: URL
    public let root: URL
    public let runDirectory: URL
    public let privateState: URL
    public let artifacts: URL

    public init(repository: URL, runID: String) {
        self.repository = repository
        root = repository.appending(path: ".build/winnow-story/runs", directoryHint: .isDirectory)
        runDirectory = root.appending(path: runID, directoryHint: .isDirectory)
        privateState = runDirectory.appending(path: "private.json")
        artifacts = runDirectory.appending(path: "artifacts", directoryHint: .isDirectory)
    }
}

public struct StoryStore: Sendable {
    public let paths: StoryPaths

    public init(repository: URL, runID: String) {
        paths = StoryPaths(repository: repository, runID: runID)
    }

    public var exists: Bool { FileManager.default.fileExists(atPath: paths.privateState.path) }

    public func create(environment: StoryEnvironment, now: Date = Date()) throws -> StoryRunState {
        try StoryRunState.validate(runID: paths.runDirectory.lastPathComponent)
        guard !exists else { throw StoryModelError.runExists(paths.runDirectory.lastPathComponent) }
        try secureDirectory(paths.runDirectory)
        try secureDirectory(paths.artifacts)
        let secrets = StoryPersona.cast.map { persona in
            StorySecretIdentity(personaID: persona.id, seedHex: randomHex(byteCount: walletSeedBytes(persona.id)))
        }
        let state = StoryRunState(runID: paths.runDirectory.lastPathComponent,
                                  environment: environment, secrets: secrets, now: now)
        try save(state)
        return state
    }

    public func load() throws -> StoryRunState {
        guard exists else { throw StoryModelError.runMissing(paths.runDirectory.lastPathComponent) }
        let data = try Data(contentsOf: paths.privateState)
        var state = try Self.decoder.decode(StoryRunState.self, from: data)
        let legacy = state.version < StoryRunState.currentVersion
        switch state.version {
        case 0, 1, 2, 3, 4:
            // v0/v1 used compatible state fields; v2 joined the demonstrations
            // into one Brisa Café trail. v3 added paired public transaction
            // evidence. v4 adds a hash-locked human media review; v5 records
            // the exact public PSBTs around the protected MuSig2 nonce round.
            state.version = StoryRunState.currentVersion
            state.scenario = StoryRunState.currentScenario
            state.personas = StoryPersona.cast
            state.mediaReview = nil
            state.musigNoncePSBT = nil
            state.musigPartialPSBT = nil
        case StoryRunState.currentVersion:
            break
        default:
            throw StoryModelError.unsupportedVersion(state.version)
        }
        if state.transactionEvidence == nil || (legacy && state.transactionEvidence?.isEmpty == true) {
            state.transactionEvidence = StoryCheckpoint.allCases.flatMap { checkpoint in
                let record = state.checkpoints[checkpoint.rawValue] ?? StoryCheckpointRecord()
                return record.transactionIDs.enumerated().compactMap {
                    (entry: (offset: Int, element: String)) -> StoryTransactionEvidence? in
                    let (index, txid) = entry
                    let normalized = txid.lowercased()
                    guard normalized.count == 64, normalized.allSatisfy(\.isHexDigit) else { return nil }
                    let height = record.confirmationHeights.indices.contains(index)
                        ? record.confirmationHeights[index]
                        : (record.transactionIDs.count == 1 ? record.confirmationHeights.last : nil)
                    return StoryTransactionEvidence(
                        label: "migrated-\(checkpoint.rawValue)-\(index + 1)",
                        checkpoint: checkpoint, personaID: checkpoint.primaryPersonaID,
                        txid: normalized,
                        status: height == nil ? .observed : .confirmationClaimed,
                        firstObservedAt: record.startedAt ?? state.createdAt,
                        confirmationHeight: height)
                }
            }
        }
        // Older scenarios had no authenticated block/lineage gate. A prior
        // publish result therefore cannot carry forward as a v3 pass.
        if legacy, state.checkpoints[StoryCheckpoint.publish.rawValue]?.status == .passed {
            state.checkpoints[StoryCheckpoint.publish.rawValue]?.status = .pending
            state.checkpoints[StoryCheckpoint.publish.rawValue]?.completedAt = nil
            state.checkpoints[StoryCheckpoint.publish.rawValue]?.note = "Migrated run requires v3 public-signet evidence verification"
            state.activeCheckpoint = .publish
        }
        return state
    }

    public func save(_ state: StoryRunState) throws {
        try secureDirectory(paths.runDirectory)
        let data = try Self.encoder.encode(state)
        try data.write(to: paths.privateState, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: paths.privateState.path)
    }

    public func finish(_ state: StoryRunState, now: Date = Date()) throws {
        let manifest = StoryPublicManifest(state: state, finishedAt: now)
        let manifestURL = paths.artifacts.appending(path: "public-manifest.json")
        let reportURL = paths.artifacts.appending(path: "report.md")

        // Validate existing journals/diagnostics before replacing the public
        // summary. This prevents a failed scan from leaving behind a report
        // that incorrectly says publication passed.
        try scanPublishableText(in: paths.artifacts, secrets: state.secrets.map(\.seedHex),
                                excluding: [manifestURL, reportURL])
        let manifestData = try Self.encoder.encode(manifest)
        let reportText = report(for: manifest)
        try validatePublishableText(String(decoding: manifestData, as: UTF8.self),
                                    named: manifestURL.lastPathComponent,
                                    secrets: state.secrets.map(\.seedHex))
        try validatePublishableText(reportText, named: reportURL.lastPathComponent,
                                    secrets: state.secrets.map(\.seedHex))

        try manifestData.write(to: manifestURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: manifestURL.path)
        try reportText.write(to: reportURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: reportURL.path)
    }

    public func mediaInventory() throws -> [StoryMediaArtifact] {
        let extensions = Set(["jpeg", "jpg", "mov", "mp4", "png"])
        let keys: [URLResourceKey] = [.isRegularFileKey, .fileSizeKey]
        var result: [StoryMediaArtifact] = []
        let relativePaths = try FileManager.default.subpathsOfDirectory(atPath: paths.artifacts.path)
        for relativePath in relativePaths {
            let file = paths.artifacts.appending(path: relativePath)
            guard extensions.contains(file.pathExtension.lowercased()) else { continue }
            let values = try file.resourceValues(forKeys: Set(keys))
            guard values.isRegularFile == true else { continue }
            let data = try Data(contentsOf: file, options: .mappedIfSafe)
            let digest = Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
            result.append(StoryMediaArtifact(
                path: relativePath,
                byteCount: Int64(values.fileSize ?? data.count), sha256: digest))
        }
        return result.sorted()
    }

    public func mediaReviewViolations(_ review: StoryMediaReview?) throws -> [String] {
        let inventory = try mediaInventory()
        var violations: [String] = []
        for checkpoint in StoryCheckpoint.allCases where checkpoint != .publish {
            for suffix in ["mp4", "png"] {
                let expected = "\(checkpoint.rawValue).\(suffix)"
                if !inventory.contains(where: { $0.path == expected && $0.byteCount > 0 }) {
                    violations.append("missing non-empty \(expected)")
                }
            }
        }
        for artifact in inventory where ["mov", "mp4"].contains(
            URL(fileURLWithPath: artifact.path).pathExtension.lowercased()) {
            let movieURL = paths.artifacts.appending(path: artifact.path)
            let data = try Data(contentsOf: movieURL, options: .mappedIfSafe)
            guard let samples = movieSampleCount(data), samples >= 2 else {
                violations.append("\(artifact.path) is not a multi-frame video")
                continue
            }
            guard let duration = movieDurationSeconds(data), duration >= 1 else {
                violations.append("\(artifact.path) is shorter than one second")
                continue
            }
        }
        guard let review else {
            violations.append("human media review has not been approved")
            return violations
        }
        if review.version != StoryMediaReview.currentVersion {
            violations.append("human media review version is unsupported")
        }
        if review.artifacts != inventory {
            violations.append("media changed after human review; review it again")
        }
        return violations
    }

    /// Safe journal facts required before the report can claim onboarding and
    /// authenticated recovery passed. No phrase or key material is read.
    public func recoveryEvidenceViolations() -> [String] {
        func events(in fileName: String) -> [StoryEvent] {
            let url = paths.artifacts.appending(path: fileName)
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
            return text.split(whereSeparator: \.isNewline).compactMap { line in
                try? Self.decoder.decode(StoryEvent.self, from: Data(line.utf8))
            }
        }

        let sofia = events(in: "sofia-events.jsonl")
        let replacement = events(in: "sofia-replacement-events.jsonl")
        var violations: [String] = []
        for required in ["wallet.created", "backup.completed", "wallet.ready"]
            where !sofia.contains(where: { $0.name == required }) {
            violations.append("safe Sofía journal is missing \(required)")
        }
        let authenticatedReveal = (sofia + replacement).contains { event in
            event.name == "backup.phraseRevealReady"
                && event.fields["deviceAuthenticationRequired"] == "true"
        }
        if !authenticatedReveal {
            violations.append("safe journal does not yet prove a device-authenticated recovery reveal")
        }
        return violations
    }

    /// Reads ISO base-media `stsz` sample counts. Simulator recordings use
    /// one sample per visible video frame; duplicate static frames may be
    /// omitted, so requiring more than one catches accidental one-frame clips.
    private func movieSampleCount(_ data: Data) -> UInt32? {
        boxValues(named: "stsz", in: data, minimumSize: 20).compactMap { offset, end -> UInt32? in
            guard offset + 16 <= end else { return nil }
            return uint32BE(data, at: offset + 12)
        }.max()
    }

    /// Reads the movie-header timescale/duration without external tools.
    private func movieDurationSeconds(_ data: Data) -> Double? {
        boxValues(named: "mvhd", in: data, minimumSize: 28).compactMap { offset, end -> Double? in
            guard offset + 5 <= end else { return nil }
            let version = data[data.index(data.startIndex, offsetBy: offset + 4)]
            if version == 0 {
                guard offset + 24 <= end,
                      let scale = uint32BE(data, at: offset + 16), scale > 0,
                      let duration = uint32BE(data, at: offset + 20) else { return nil }
                return Double(duration) / Double(scale)
            }
            if version == 1 {
                guard offset + 36 <= end,
                      let scale = uint32BE(data, at: offset + 24), scale > 0,
                      let duration = uint64BE(data, at: offset + 28) else { return nil }
                return Double(duration) / Double(scale)
            }
            return nil
        }.max()
    }

    /// Returns verified `(typeOffset, boxEnd)` pairs. The four bytes before a
    /// type are the big-endian box size, which prevents payload text from being
    /// mistaken for an MP4 table.
    private func boxValues(named name: String, in data: Data,
                           minimumSize: Int) -> [(Int, Int)] {
        let needle = Data(name.utf8)
        var results: [(Int, Int)] = []
        var searchStart = data.startIndex
        while searchStart < data.endIndex,
              let range = data.range(of: needle, in: searchStart ..< data.endIndex) {
            let offset = data.distance(from: data.startIndex, to: range.lowerBound)
            if offset >= 4, let size = uint32BE(data, at: offset - 4) {
                let boxStart = offset - 4
                let boxEnd = boxStart + Int(size)
                if size >= minimumSize, boxEnd <= data.count {
                    results.append((offset, boxEnd))
                }
            }
            searchStart = range.upperBound
        }
        return results
    }

    private func uint32BE(_ data: Data, at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= data.count else { return nil }
        return (0 ..< 4).reduce(UInt32.zero) { value, index in
            let byte = data[data.index(data.startIndex, offsetBy: offset + index)]
            return (value << 8) | UInt32(byte)
        }
    }

    private func uint64BE(_ data: Data, at offset: Int) -> UInt64? {
        guard offset >= 0, offset + 8 <= data.count else { return nil }
        return (0 ..< 8).reduce(UInt64.zero) { value, index in
            let byte = data[data.index(data.startIndex, offsetBy: offset + index)]
            return (value << 8) | UInt64(byte)
        }
    }

    @discardableResult
    public func writeMediaReviewChecklist(_ inventory: [StoryMediaArtifact],
                                          review: StoryMediaReview?) throws -> URL {
        let destination = paths.artifacts.appending(path: "media-review-checklist.md")
        var lines = [
            "# Winnow story media review",
            "",
            "Run: `\(paths.runDirectory.lastPathComponent)`",
            "",
            "Watch every video from start to finish and inspect every screenshot. Confirm that no recovery words, private keys, secret nonces, clipboard overlays, authentication prompts, or unrelated personal information appear.",
            "",
        ]
        if let review {
            lines.append("Status: approved at \(ISO8601DateFormatter().string(from: review.reviewedAt)); hashes are locked in the public manifest.")
        } else {
            lines.append("Status: awaiting human approval. Run `./scripts/winnow-story review-media --run \(paths.runDirectory.lastPathComponent) --approve` only after completing the review.")
        }
        lines += ["", "## Artifacts", ""]
        lines += inventory.map {
            "- [\(review == nil ? " " : "x")] `\($0.path)` · \($0.byteCount) bytes · SHA-256 `\($0.sha256)`"
        }
        lines.append("")
        let text = lines.joined(separator: "\n")
        try validatePublishableText(text, named: destination.lastPathComponent, secrets: [])
        try text.write(to: destination, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: destination.path)
        return destination
    }

    @discardableResult
    public func writeMediaReviewPage(_ inventory: [StoryMediaArtifact],
                                     review: StoryMediaReview?) throws -> URL {
        let destination = paths.artifacts.appending(path: "media-review.html")
        let cards = inventory.map { artifact -> String in
            let escapedPath = htmlEscaped(artifact.path)
            let source = artifact.path.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)
                ?? artifact.path
            let preview: String
            if ["mov", "mp4"].contains(URL(fileURLWithPath: artifact.path).pathExtension.lowercased()) {
                preview = "<video controls preload=\"metadata\" src=\"\(source)\"></video>"
            } else {
                preview = "<img loading=\"lazy\" src=\"\(source)\" alt=\"\(escapedPath)\">"
            }
            return """
            <article>
              <h2>\(escapedPath)</h2>
              \(preview)
              <label><input type="checkbox" data-hash="\(artifact.sha256)"> I reviewed this entire artifact</label>
              <p>\(artifact.byteCount) bytes · SHA-256 <code>\(artifact.sha256)</code></p>
            </article>
            """
        }.joined(separator: "\n")
        let status = review.map {
            "Approved at \(ISO8601DateFormatter().string(from: $0.reviewedAt)); hashes are locked in the public manifest."
        } ?? "Not approved. Review every item below, then run the approval command shown here."
        let runID = htmlEscaped(paths.runDirectory.lastPathComponent)
        let html = """
        <!doctype html>
        <html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Winnow story media review</title>
        <style>
        body{font:16px system-ui,sans-serif;max-width:900px;margin:auto;padding:24px;background:#f5f5f7;color:#171719}
        article{background:white;border-radius:14px;padding:18px;margin:20px 0;box-shadow:0 1px 5px #0002}
        video,img{display:block;max-width:100%;max-height:720px;margin:12px auto;border-radius:10px;background:#111}
        label{display:block;font-weight:650;margin:14px 0}code{overflow-wrap:anywhere}#progress{font-weight:700}
        </style></head><body>
        <h1>Winnow story media review</h1>
        <p>Run <code>\(runID)</code>. Watch every video from start to finish and inspect every screenshot. Look for recovery words, signing secrets, clipboard overlays, authentication prompts, or unrelated personal information.</p>
        <p><strong>Status:</strong> \(htmlEscaped(status))</p>
        <p id="progress"></p>
        <p>After all items are reviewed, run <code>./scripts/winnow-story review-media --run \(runID) --approve</code>.</p>
        \(cards)
        <script>
        const boxes=[...document.querySelectorAll('input[data-hash]')];
        const key='winnow-media-review:'+document.title+':\(runID)';
        const saved=new Set(JSON.parse(localStorage.getItem(key)||'[]'));
        for(const box of boxes){box.checked=saved.has(box.dataset.hash);box.onchange=()=>{const done=boxes.filter(x=>x.checked).map(x=>x.dataset.hash);localStorage.setItem(key,JSON.stringify(done));render()}}
        function render(){document.querySelector('#progress').textContent=`Reviewed ${boxes.filter(x=>x.checked).length} of ${boxes.length}`}
        render();
        </script></body></html>
        """
        try validatePublishableText(html, named: destination.lastPathComponent, secrets: [])
        try html.write(to: destination, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: destination.path)
        return destination
    }

    private func htmlEscaped(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    public func writeFailureSummary(_ state: StoryRunState, checkpoint: StoryCheckpoint,
                                    to directory: URL, now: Date = Date()) throws {
        try secureDirectory(directory)
        let timestamp = ISO8601DateFormatter().string(from: now)
            .replacingOccurrences(of: ":", with: "-")
        let destination = directory.appending(path: "\(checkpoint.rawValue)-\(timestamp)-checkpoint.json")
        try writeJSON(StoryFailureSummary(state: state, checkpoint: checkpoint, now: now),
                      to: destination, permissions: 0o600)
    }

    public func scanPublishableText(in directory: URL, secrets: [String],
                                    excluding excludedURLs: Set<URL> = []) throws {
        let excludedPaths = Set(excludedURLs.map(\.standardizedFileURL.path))
        let enumerator = FileManager.default.enumerator(at: directory,
                                                        includingPropertiesForKeys: [.isRegularFileKey])
        let files = enumerator?.compactMap { $0 as? URL } ?? []
        for file in files where ["html", "json", "md", "txt", "log"].contains(file.pathExtension.lowercased()) {
            guard !excludedPaths.contains(file.standardizedFileURL.path) else { continue }
            let text = (try? String(contentsOf: file, encoding: .utf8)) ?? ""
            try validatePublishableText(text, named: file.lastPathComponent, secrets: secrets)
        }
    }

    private func validatePublishableText(_ text: String, named fileName: String,
                                         secrets: [String]) throws {
        let forbiddenKeys = ["seedHex", "entropy", "mnemonic", "privateKey", "secretNonce"]
        let protectedTexts = secrets.flatMap { secret -> [String] in
            var values = [secret]
            if let entropy = Data(hex: secret),
               let words = try? BIP39.mnemonic(entropy: entropy) {
                values.append(words)
            }
            return values
        }
        if let key = forbiddenKeys.first(where: { text.localizedCaseInsensitiveContains($0) }) {
            throw StoryModelError.unsafeArtifact("\(fileName) contains \(key)")
        }
        if let secret = protectedTexts.first(where: { !$0.isEmpty && text.localizedCaseInsensitiveContains($0) }) {
            throw StoryModelError.unsafeArtifact("\(fileName) contains protected run identity \(secret.prefix(8))…")
        }
    }

    private func report(for manifest: StoryPublicManifest) -> String {
        // This explorer is checked by the story runner on public signet and
        // has working transaction pages. It is evidence convenience only;
        // Winnow never uses it for wallet reads, sync, fees, or broadcast.
        let transactionExplorer = "https://explorer.bc-2.jp/tx/"
        var lines = [
            "# Winnow whole-app signet story",
            "",
            "Run: `\(manifest.runID)`  ",
            "Scenario: `\(manifest.scenario)`  ",
            "Git: `\(manifest.environment.gitCommit)`\(manifest.environment.gitDirty == true ? " (working tree had changes)" : "")  ",
            "Swift: `\(manifest.environment.swiftVersion.replacingOccurrences(of: "\n", with: " · "))`  ",
            "Xcode: `\(manifest.environment.xcodeVersion.replacingOccurrences(of: "\n", with: " · "))`  ",
            "Simulator: `\(manifest.environment.simulatorName ?? "unknown")` · `\(manifest.environment.simulatorRuntime ?? "unknown runtime")`  ",
            "Public signet only; no local Bitcoin node or RPC dependency.",
            "",
            "## Story thread",
            "",
            "Sofía runs Brisa Café from a small hot wallet, sweeps savings into the Rivera 2-of-3 cold reserve, receives operating liquidity back through Elena + Leo, and demonstrates recovery through Leo + Marina into Elena and Mateo’s joint reserve.",
            "",
            "## Cast",
            "",
        ]
        lines += manifest.personas.map {
            "- \($0.name)\($0.organization.map { " — \($0)" } ?? ""): \($0.role) · \($0.themeName) `\($0.themeHex)`"
        }
        lines += ["", "## Checkpoints", ""]
        for checkpoint in StoryCheckpoint.allCases {
            let record = manifest.checkpoints[checkpoint.rawValue] ?? StoryCheckpointRecord()
            var line = "- [\(record.status == .passed ? "x" : " ")] **\(checkpoint.title)** — \(record.status.rawValue)"
            if !record.transactionIDs.isEmpty {
                line += " · tx: " + record.transactionIDs.map {
                    "[\($0)](\(transactionExplorer)\($0))"
                }.joined(separator: ", ")
            }
            if !record.confirmationHeights.isEmpty {
                line += " · block: " + record.confirmationHeights.map(String.init).joined(separator: ", ")
            }
            if let started = record.startedAt, let completed = record.completedAt {
                line += String(format: " · duration: %.1fs", max(0, completed.timeIntervalSince(started)))
            }
            if let note = record.note { line += " · \(note)" }
            lines.append(line)
        }
        lines += ["", "## Public-signet transaction evidence", ""]
        if manifest.transactionEvidence.isEmpty {
            lines.append("No transactions were recorded.")
        } else {
            for evidence in manifest.transactionEvidence {
                var line = "- **\(evidence.label)** · \(evidence.checkpoint.title) · [\(evidence.txid)](\(transactionExplorer)\(evidence.txid)) · \(evidence.status.rawValue)"
                if let height = evidence.confirmationHeight { line += " · block \(height)" }
                if let blockHash = evidence.blockHash { line += " · block hash `\(blockHash)`" }
                if !evidence.parentTransactionIDs.isEmpty {
                    line += " · parents: " + evidence.parentTransactionIDs.joined(separator: ", ")
                }
                if let failure = evidence.failure { line += " · \(failure)" }
                lines.append(line)
            }
        }
        lines += ["", "## Publication gate", ""]
        if let review = manifest.humanMediaReview {
            lines.append("Automated text redaction passed. Human media review approved at \(ISO8601DateFormatter().string(from: review.reviewedAt)); \(review.artifacts.count) artifact hashes were locked.")
        } else {
            lines.append("Automated text redaction passed. Human media review is still required before publication.")
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }

    private func walletSeedBytes(_ personaID: String) -> Int {
        ["sofia", "lina", "elena"].contains(personaID) ? 16 : 32
    }

    private func randomHex(byteCount: Int) -> String {
        var generator = SystemRandomNumberGenerator()
        return (0 ..< byteCount).map { _ in String(format: "%02x", UInt8.random(in: .min ... .max, using: &generator)) }.joined()
    }

    private func secureDirectory(_ url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }

    private func writeJSON<T: Encodable>(_ value: T, to url: URL, permissions: Int) throws {
        let data = try Self.encoder.encode(value)
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
