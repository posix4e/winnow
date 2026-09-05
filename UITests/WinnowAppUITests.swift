import BitcoinCore
import Foundation
import WalletCore
import XCTest

/// Smoke probe: the whole suite hinges on the iOS-simulator test runner
/// being able to spawn host processes (bitcoin-cli mining, pasteboard
/// copies). Runs first (alphabetical) and fails fast.
@MainActor
final class HostProcessProbeTests: XCTestCase {
    func test00CanSpawnHostProcesses() throws {
        let echo = try HostProcess.run("/bin/echo", ["host-spawn-ok"])
        XCTAssertEqual(echo.status, 0)
        XCTAssertEqual(echo.stdout.trimmingCharacters(in: .whitespacesAndNewlines), "host-spawn-ok")
        let node = try BitcoinCLI.run(["getblockcount"])
        XCTAssertGreaterThan(Int(node) ?? 0, 0, "local signet node unreachable")
    }
}

/// End-to-end UI tests against the local custom-signet node (default datadir
/// ~/.bitcoin-mysignet, P2P 127.0.0.1:38401 — overridable via the
/// WINNOW_NODE_HOST/WINNOW_P2P_PORT/WINNOW_RPC_PORT/WINNOW_DATADIR
/// environment variables, see UITests/BitcoinCLI.swift). The app is launched with
/// WINNOW_E2E=1 (see Sources/WinnowApp/E2EMode.swift): throwaway storage
/// and Keychain namespace, custom-signet params, the node as manual peer, and
/// a fixed wallet entropy for reproducible screenshots.
///
/// The suite is deliberately ordered (test01…test06 — XCTest runs a class's
/// methods alphabetically): 01 creates the wallet, 02 funds it, 03 spends,
/// 06 imports a bundle built from the funding data.
@MainActor
final class WinnowAppUITests: XCTestCase {
    /// Fixed 16-byte entropy → the same mnemonic/addresses every run.
    static let entropyHex = "000102030405060708090a0b0c0d0e0f"
    static let mnemonic = try! BIP39.mnemonic(entropy: Data(hex: entropyHex)!)

    /// Facts about the funding coinbase, captured in test02, reused in 06.
    /// Persisted to the runner's temp dir because a crashed/restarted runner
    /// process loses statics.
    struct FundingInfo: Codable {
        var txid: String // display hex
        var amount: Int64
        var scriptPubKey: String // hex
        var height: Int
        var index: UInt32 // receive-chain index of the funded address
    }
    nonisolated(unsafe) static var funding: FundingInfo?

    static var fundingFile: URL {
        FileManager.default.temporaryDirectory.appending(path: "winnow-e2e-funding.json")
    }

    static func saveFunding(_ info: FundingInfo) {
        funding = info
        try? JSONEncoder().encode(info).write(to: fundingFile)
    }

    static func loadFunding() -> FundingInfo? {
        if let funding { return funding }
        guard let data = try? Data(contentsOf: fundingFile) else { return nil }
        funding = try? JSONDecoder().decode(FundingInfo.self, from: data)
        return funding
    }

    override func setUp() {
        super.setUp()
        executionTimeAllowance = 600
    }

    // MARK: - Launch

    /// Launches the app in E2E mode against the local node and waits for the
    /// wallet shell (balance visible) unless onboarding is expected.
    @discardableResult
    func launchApp(run: String = "main", reset: Bool = false, clipboard: String? = nil,
                   expectOnboarding: Bool = false,
                   configureLocalNode: Bool = true,
                   advanced: Bool = false) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment = [
            "WINNOW_E2E": "1",
            "WINNOW_E2E_RUN": run,
            "WINNOW_E2E_ENTROPY": Self.entropyHex,
        ]
        // Advanced mode on from the first frame, so a test can reach the
        // expert controls without tapping through Settings.
        if advanced { app.launchEnvironment["WINNOW_E2E_ADVANCED"] = "1" }
        if configureLocalNode {
            app.launchEnvironment["WINNOW_E2E_PEER"] =
                "\(BitcoinCLI.nodeHost):\(BitcoinCLI.p2pPort)"
            app.launchEnvironment["WINNOW_E2E_CHALLENGE"] = BitcoinCLI.challengeHex
        }
        if reset { app.launchEnvironment["WINNOW_E2E_RESET"] = "1" }
        if let clipboard { app.launchEnvironment["WINNOW_E2E_CLIPBOARD"] = clipboard }
        app.launch()
        if expectOnboarding {
            XCTAssertTrue(app.buttons["createWalletButton"].waitForExistence(timeout: 120),
                          "onboarding did not appear")
        } else {
            XCTAssertTrue(app.staticTexts["balanceText"].waitForExistence(timeout: 120),
                          "wallet home did not appear")
        }
        return app
    }

    /// Text of the balance label ("12,345 sats").
    func balanceText(_ app: XCUIApplication) -> String {
        (app.staticTexts["balanceText"].value as? String) ?? ""
    }

    /// Taps "Sync now" when idle to nudge a scan pass.
    func nudgeSync(_ app: XCUIApplication) {
        let button = app.buttons["syncNowButton"]
        if button.exists, button.isEnabled { button.tap() }
    }

    /// Scrolls the topmost scroll view until `element` exists (SwiftUI
    /// Forms materialize rows lazily — `exists` is false below the fold).
    /// Uses screen-coordinate drags: a TabView keeps every tab's list in the
    /// accessibility tree, so element-based swipes can hit a hidden tab's
    /// list instead of the visible form.
    @discardableResult
    func scrollUntilExists(_ app: XCUIApplication, _ element: XCUIElement,
                           maxSwipes: Int = 10, up: Bool = false) -> Bool {
        for _ in 0 ... maxSwipes {
            if element.waitForExistence(timeout: 2) { return true }
            let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: up ? 0.30 : 0.62))
            let end = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: up ? 0.62 : 0.30))
            start.press(forDuration: 0.05, thenDragTo: end)
        }
        return element.exists
    }

    // MARK: - 01 Onboarding

    func test01OnboardingCreateWallet() throws {
        let app = launchApp(reset: true, expectOnboarding: true)
        Screenshots.capture(app, "01-onboarding", testCase: self)

        let createStart = Date()
        app.buttons["createWalletButton"].tap()
        // Backup is deliberately independent of peer/header catch-up.
        let toggle = app.switches["writtenDownToggle"]
        XCTAssertTrue(toggle.waitForExistence(timeout: 30), "backup sheet did not appear promptly")
        XCTAssertTrue(app.buttons["backupCopyPhraseButton"].exists,
                      "backup sheet does not offer an explicit phrase copy")
        Timings.record("onboarding", step: "wallet-create", from: createStart)
        Screenshots.capture(app, "02-backup-mnemonic", testCase: self)

        // iOS 26: the toggle is a container switch element wrapping the real
        // UISwitch as a child — tapping the container/label does nothing.
        // Tap the child switch (right side of the row).
        let toggleThumb = toggle.children(matching: .switch).firstMatch
        let done = app.buttons["backupDoneButton"]
        let enabled = poll(timeout: 20, interval: 1, "backup Done button enabled") {
            if done.isEnabled { return true }
            if toggleThumb.exists {
                toggleThumb.tap()
            } else {
                toggle.coordinate(withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)).tap()
            }
            return done.isEnabled
        }
        if !enabled {
            Screenshots.capture(app, "debug-01-backup", testCase: self)
            print("E2E debug: writtenDownToggle value = \(toggle.value ?? "nil")")
            print(app.debugDescription)
        }
        let backupStart = Date()
        done.tap()
        XCTAssertTrue(app.staticTexts["balanceText"].waitForExistence(timeout: 60),
                      "wallet home did not appear after backup")
        Timings.record("onboarding", step: "backup→home", from: backupStart)
    }

    // MARK: - 02 Receive + funding

    func test02ReceiveAndFunding() async throws {
        let app = launchApp()

        let receiveStart = Date()
        app.buttons["receiveButton"].tap()
        let addressElement = app.staticTexts["receiveAddress"]
        XCTAssertTrue(addressElement.waitForExistence(timeout: 30), "no receive address")
        Timings.record("receive", step: "address-shown", from: receiveStart)
        Screenshots.capture(app, "03-receive", testCase: self)
        guard let address = addressElement.value as? String, address.hasPrefix("tb1") else {
            XCTFail("could not read the receive address from the UI")
            return
        }
        app.buttons["Done"].tap()

        // Which receive-chain index did the app show? (It advances once an
        // address is used, so resolve it rather than assuming 0.)
        var fundingIndex: UInt32?
        for i: UInt32 in 0 ..< 10
        where try Self.walletReceiveAddress(index: i) == address { fundingIndex = i }
        guard let fundingIndex else {
            XCTFail("the displayed address is not index 0..<10 of the fixed-entropy wallet")
            return
        }

        // Fund it from the host: 100 blocks total. The funding block is
        // confirmation one, so 99 more reach the exact consensus boundary.
        let script = try AddressDecoder.scriptPubKey(for: address, network: .signet)
        let mineStart = Date()
        let firstHash = try await SignetMiner.mineOntoTip(payingTo: script)
        let fundingTxid = try BitcoinCLI.coinbaseTxid(blockHash: firstHash)
        let output = try BitcoinCLI.outputZero(txid: fundingTxid)
        // Read the height back rather than assuming tip+1: a block race lost
        // to the node's background miner is re-mined one or more blocks higher,
        // and test06 rebuilds its import bundle from this height.
        Self.saveFunding(FundingInfo(txid: fundingTxid, amount: output.amount,
                                     scriptPubKey: output.scriptPubKey,
                                     height: try BitcoinCLI.blockHeight(of: firstHash),
                                     index: fundingIndex))
        for _ in 0 ..< 99 {
            try await SignetMiner.mineOntoTip(payingTo: script)
        }
        Timings.record("funding", step: "mine-100-blocks", from: mineStart)

        // Filters see blocks, not the mempool: poll (nudging "Sync now")
        // until the confirmed balance shows.
        let detectStart = Date()
        poll(timeout: 300, interval: 5, "confirmed balance after funding") {
            self.nudgeSync(app)
            return self.balanceText(app) != "0 sats" && self.balanceText(app) != ""
        }
        Timings.record("funding", step: "mined→detected-by-filters", from: detectStart)
        // A history entry must be there too.
        XCTAssertTrue(app.staticTexts["Received"].waitForExistence(timeout: 60),
                      "no history entry after funding")
        Screenshots.capture(app, "04-home-funded", testCase: self)
    }

    // MARK: - 03 Send

    func test03Send() async throws {
        // Send 0.01 BTC back out to a fixture address derived in-process
        // (the node's "miner" wallet is a signing-only wallet with no
        // keypool — it can't hand out receive addresses). Typed, not pasted:
        // cross-process pasteboard consent prompts proved flaky.
        let destination = try Self.fixtureAddress(0xC3)
        let app = launchApp()
        XCTAssertTrue(poll(timeout: 120, "persisted funded balance") {
            self.balanceText(app) != "0 sats" && self.balanceText(app) != ""
        })

        app.tabBars.buttons["Send"].tap()
        app.typeInto("destinationField", destination)
        app.typeInto("amountField", "1000000")
        Screenshots.capture(app, "05-send-form", testCase: self)

        app.buttons["reviewButton"].tap()
        // The Review section is appended below the fold; SwiftUI Forms
        // materialize rows lazily, so scroll it into existence.
        let sendButton = app.buttons["sendButton"]
        if !scrollUntilExists(app, sendButton, maxSwipes: 5) {
            Screenshots.capture(app, "debug-03-scrolled", testCase: self)
            print("E2E debug buttons after scroll: \(app.buttons.allElementsBoundByIndex.map(\.identifier))")
            app.buttons["reviewButton"].tap() // in case the tap was eaten by the keyboard
            _ = scrollUntilExists(app, sendButton, maxSwipes: 5)
        }
        if !sendButton.exists {
            _ = scrollUntilExists(app, app.staticTexts["sendError"], up: true)
            if app.staticTexts["sendError"].exists {
                print("E2E send error: \(app.staticTexts["sendError"].label)")
            }
            Screenshots.capture(app, "debug-03-send", testCase: self)
        }
        XCTAssertTrue(sendButton.exists, "no review section")
        Screenshots.capture(app, "06-send-review", testCase: self)

        let mempoolBefore = Set(try BitcoinCLI.mempoolTxids())
        let broadcastStart = Date()
        app.buttons["sendButton"].tap()
        XCTAssertTrue(poll(timeout: 60, "broadcast status") {
            app.staticTexts["broadcastPending"].exists || app.staticTexts["broadcastConfirmed"].exists
        })
        Timings.record("send", step: "form→broadcast", from: broadcastStart)
        Screenshots.capture(app, "07-send-broadcast", testCase: self)

        // Wait until the node actually has the tx (inv → getdata relay takes
        // a moment after the UI reports the broadcast), THEN mine.
        let relayStart = Date()
        poll(timeout: 60, interval: 1, "tx relayed into the node's mempool") {
            ((try? Set(BitcoinCLI.mempoolTxids()).isSubset(of: mempoolBefore)) ?? true) == false
        }
        Timings.record("send", step: "broadcast→echo/relay", from: relayStart)
        let payout = try AddressDecoder.scriptPubKey(for: Self.fixtureAddress(0xD4), network: .signet)
        let confirmStart = Date()
        try await SignetMiner.mineOntoTip(payingTo: payout)

        // The "Seen in block N" label is a lazily-materialized row below the
        // fold — nudge syncs from the Wallet tab, then scroll to it.
        poll(timeout: 240, interval: 5, "send confirmation") {
            app.tabBars.buttons["Wallet"].tap()
            self.nudgeSync(app)
            app.tabBars.buttons["Send"].tap()
            return self.scrollUntilExists(app, app.staticTexts["broadcastConfirmed"], maxSwipes: 3)
        }
        Timings.record("send", step: "mine→confirmed", from: confirmStart)
        Screenshots.capture(app, "08-send-confirmed", testCase: self)

        app.tabBars.buttons["Wallet"].tap()
        self.nudgeSync(app)
        XCTAssertTrue(app.staticTexts["Sent"].waitForExistence(timeout: 60),
                      "no sent entry in history")
        Screenshots.capture(app, "09-home-after-send", testCase: self)
    }

    // MARK: - 04 Vaults

    /// A deterministic cosigner key expression ([fp/86'/1'/0']tpub…/<0;1>/*)
    /// from a one-byte repeated seed — a fixture, not a real cosigner.
    static func fixtureCosigner(_ byte: UInt8) throws -> String {
        let master = try HDKey(seed: Data(repeating: byte, count: 64))
        let account = try BIP86.accountKey(from: master, coinType: 1, account: 0)
        let fingerprint = String(format: "%08x", master.fingerprint)
        return "[\(fingerprint)/86'/1'/0']\(account.neutered.serialized(network: .testnet))/<0;1>/*"
    }

    /// The fixed-entropy test wallet's own key expression — the same text
    /// "Add this device's key" produced in test04 (AppModel.ownKeyExpression).
    static func deviceKeyExpression() throws -> String {
        let master = try HDKey(seed: BIP39.seed(mnemonic: mnemonic))
        let account = try BIP86.accountKey(from: master, coinType: 1, account: 0)
        let fingerprint = String(format: "%08x", master.fingerprint)
        return "[\(fingerprint)/86'/1'/0']\(account.neutered.serialized(network: .testnet))/<0;1>/*"
    }

    /// A deterministic signet P2TR address from a one-byte repeated seed
    /// (fixture send destination / block payout).
    static func fixtureAddress(_ byte: UInt8) throws -> String {
        let master = try HDKey(seed: Data(repeating: byte, count: 64))
        let account = try BIP86.accountKey(from: master, coinType: 1, account: 0)
        return try BIP86.address(internalKey: account.publicKey.dropFirst(), hrp: "tb")
    }

    /// The fixed-entropy test wallet's receive address at `index`
    /// (m/86'/1'/0'/0/index, signet).
    static func walletReceiveAddress(index: UInt32) throws -> String {
        let master = try HDKey(seed: BIP39.seed(mnemonic: mnemonic))
        let account = try BIP86.accountKey(from: master, coinType: 1, account: 0)
        let key = try account.derived(path: "0/\(index)")
        return try BIP86.address(internalKey: key.publicKey.dropFirst(), hrp: "tb")
    }

    func test04VaultCreate() throws {
        // The raw vault tools live in the Vaults section of the People tab,
        // in Advanced mode; beginners see the same records as shared savings.
        let app = launchApp(advanced: true)
        app.tabBars.buttons["People"].tap()
        let createStart = Date()
        let newVault = app.buttons["newVaultButton"]
        XCTAssertTrue(scrollUntilExists(app, newVault), "no Vaults section in Advanced mode")
        newVault.tap()

        app.typeInto("vaultNameField", "E2E Vault")
        // Default policy: 2-of-n script path; three cosigners → 2-of-3.
        app.buttons["addDeviceKeyButton"].tap()
        for byte: UInt8 in [0xA1, 0xB2] {
            app.typeInto("cosignerField", try Self.fixtureCosigner(byte))
            app.buttons["addPastedKeyButton"].tap()
        }
        app.buttons["buildDescriptorButton"].tap()
        // The descriptor preview is a CopyableTextBlock whose Text starts
        // with "tr(" — below the fold, and SwiftUI Forms materialize rows
        // lazily, so scroll it into existence.
        let descriptor = app.staticTexts.matching(
            NSPredicate(format: "label BEGINSWITH 'tr('")).firstMatch
        XCTAssertTrue(scrollUntilExists(app, descriptor), "descriptor preview did not appear")
        app.dismissKeyboard()
        Screenshots.capture(app, "10-vault-create", testCase: self)

        XCTAssertTrue(scrollUntilExists(app, app.buttons["saveVaultButton"]),
                      "save button did not appear")
        app.buttons["saveVaultButton"].tap()
        XCTAssertTrue(app.staticTexts["E2E Vault"].firstMatch.waitForExistence(timeout: 30),
                      "vault was not saved")
        Timings.record("vault", step: "create", from: createStart)
        XCTAssertTrue(scrollUntilExists(app, app.staticTexts["2-of-3 · script path"]),
                      "the Vaults section does not describe the policy")
        Screenshots.capture(app, "11-vault-list", testCase: self)
    }

    // MARK: - 05 Settings

    func test05SettingsPeersAndExplorerWarning() throws {
        // Connected peers and the explorer setting are Advanced-mode rows.
        let app = launchApp(advanced: true)
        app.tabBars.buttons["Settings"].tap()

        // SwiftUI Forms materialize rows lazily: scroll the Connected peers
        // section into existence first.
        let refresh = app.buttons["refreshPeersButton"]
        if !scrollUntilExists(app, refresh) {
            Screenshots.capture(app, "debug-05-settings", testCase: self)
            print(app.debugDescription)
            XCTFail("settings form did not load")
            return
        }
        refresh.tap()
        let localPeer = app.staticTexts.matching(
            NSPredicate(format: "label BEGINSWITH %@", "\(BitcoinCLI.nodeHost):\(BitcoinCLI.p2pPort)")).firstMatch
        poll(timeout: 60, interval: 3, "connected local peer in settings") {
            if localPeer.exists { return true }
            if refresh.exists, refresh.isHittable { refresh.tap() }
            return localPeer.exists
        }
        // Bring the Connected peers section into view for the screenshot.
        if !localPeer.isHittable { app.collectionViews.firstMatch.swipeUp() }
        Screenshots.capture(app, "12-settings-peers", testCase: self)

        // Esplora is a selectable external link only, never a wallet backend.
        let explorerField = app.textFields["esploraURLField"]
        XCTAssertTrue(scrollUntilExists(app, explorerField, up: true), "no explorer URL field")

        // Opening a transaction is the privacy boundary: capture the warning
        // and cancel before iOS contacts the selected endpoint.
        app.tabBars.buttons["Wallet"].tap()
        let explorerLink = app.buttons["explorerTransactionButton"].firstMatch
        XCTAssertTrue(scrollUntilExists(app, explorerLink), "no transaction explorer link")
        explorerLink.tap()
        let alert = app.alerts["Open external block explorer?"]
        XCTAssertTrue(alert.waitForExistence(timeout: 10), "explorer warning did not appear")
        Screenshots.capture(app, "13-esplora-warning", testCase: self)
        alert.buttons["Cancel"].tap()
    }

    // MARK: - 06 Import

    func test06ImportBundleVerification() async throws {
        guard let funding = Self.loadFunding() else {
            XCTFail("no funding info from test02 — run the full suite")
            return
        }
        // Minimal bundle: the fixed mnemonic plus the funding coinbase as the
        // claimed UTXO/history, as of the funding block. Verification scans
        // forward from there and sees test03's spend — the report shows the
        // claimed UTXO as spent-since and the change as discovered.
        let bundle: [String: Any] = [
            "version": 1,
            "network": "signet",
            "mnemonic": Self.mnemonic,
            "lastKnownHeight": funding.height,
            "utxos": [[
                "txid": funding.txid, "vout": 0, "amount": funding.amount,
                "scriptPubKey": funding.scriptPubKey, "chain": 0,
                "index": funding.index, "height": funding.height,
            ]],
            "transactions": [[
                "txid": funding.txid, "height": funding.height,
                "received": funding.amount, "spent": 0,
            ]],
        ]
        let json = String(decoding: try JSONSerialization.data(withJSONObject: bundle), as: UTF8.self)

        // The app puts the bundle on its own pasteboard at boot.
        let app = launchApp(run: "import", reset: true, clipboard: json, expectOnboarding: true)
        app.buttons["importWalletButton"].tap()
        XCTAssertTrue(app.buttons["importPasteButton"].waitForExistence(timeout: 20))
        app.buttons["importPasteButton"].tap()
        // The system may still ask for paste consent — allow it, retry.
        let allowPaste = app.buttons["Allow Paste"]
        let pasted = poll(timeout: 15, interval: 1, "bundle pasted") {
            if allowPaste.exists { allowPaste.tap() }
            if ((app.textViews["importJSONEditor"].value as? String) ?? "").contains("lastKnownHeight") {
                return true
            }
            if app.buttons["importPasteButton"].exists { app.buttons["importPasteButton"].tap() }
            return false
        }
        if !pasted {
            // Fallback: type the JSON into the editor (autocorrect disabled).
            app.typeInto("importJSONEditor", json)
        }

        // Imported JSON may contain the seed. Leaving the active scene must
        // erase it before the app can be foregrounded again.
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.buttons["importPasteButton"].waitForExistence(timeout: 20),
                      "import sheet did not return after activation")
        XCTAssertFalse(((app.textViews["importJSONEditor"].value as? String) ?? "")
            .contains("lastKnownHeight"), "seed-bearing import JSON survived backgrounding")
        app.buttons["importPasteButton"].tap()
        _ = poll(timeout: 15, interval: 1, "bundle re-pasted after lifecycle clearing") {
            if allowPaste.exists { allowPaste.tap() }
            return ((app.textViews["importJSONEditor"].value as? String) ?? "")
                .contains("lastKnownHeight")
        }
        let verifyStart = Date()
        app.buttons["importVerifyButton"].tap()
        let reportVisible = poll(timeout: 300, interval: 3, "verification report") {
            app.staticTexts["Verification report"].exists
        }
        if reportVisible {
            Timings.record("import", step: "verify", from: verifyStart)
        }
        if !reportVisible {
            Screenshots.capture(app, "debug-06-import", testCase: self)
            let texts = app.staticTexts.allElementsBoundByIndex.map(\.label)
            print("E2E debug import staticTexts: \(texts)")
        }
        XCTAssertTrue(reportVisible, "no verification report")
        Screenshots.capture(app, "14-import-report", testCase: self)
        XCTAssertTrue(scrollUntilExists(app, app.buttons["importContinueButton"]),
                      "no Continue button after report")
        app.buttons["importContinueButton"].tap()
        XCTAssertTrue(app.staticTexts["balanceText"].waitForExistence(timeout: 60),
                      "wallet home did not appear after import")
    }

    // MARK: - 07 Approve a request (mines)

    /// The beginner's side of a shared-savings spend, on the "E2E Vault"
    /// from test04 (this device + fixture co-owners 0xA1/0xB2, 2 of 3):
    /// fund it from the wallet, let "Alice" (0xA1, in-process) propose and
    /// approve a spend, approve it here in plain words, and Finish. Real
    /// coins, so the finish broadcasts and a block settles it.
    func test07ApproveRequest() async throws {
        let descriptor = try Vault.multiADescriptor(
            threshold: 2,
            cosigners: try [Self.deviceKeyExpression(), Self.fixtureCosigner(0xA1),
                            Self.fixtureCosigner(0xB2)])
        let vault = try Vault(descriptor: descriptor, network: .signet)
        let recordID = String(descriptor.serialized().split(separator: "#").last!)
        let savingsAddress = try vault.address(index: 0)
        let savingsScript = try vault.scriptPubKey(index: 0)

        // 1. Fund the savings from the wallet, unless a previous run did.
        var app = launchApp()
        app.tabBars.buttons["People"].tap()
        let savingsRow = app.staticTexts["E2E Vault"].firstMatch
        XCTAssertTrue(savingsRow.waitForExistence(timeout: 30),
                      "savings from test04 missing — run the full suite")
        if try BitcoinCLI.unspents(scriptHex: savingsScript.hex).isEmpty {
            app.tabBars.buttons["Send"].tap()
            app.typeInto("destinationField", savingsAddress)
            app.typeInto("amountField", "200000")
            app.dismissKeyboard()
            app.buttons["reviewButton"].tap()
            XCTAssertTrue(app.buttons["sendButton"].waitForExistence(timeout: 60), "no send review")
            app.buttons["sendButton"].tap()
            XCTAssertTrue(poll(timeout: 60, "broadcast into the savings") {
                app.staticTexts["broadcastPending"].exists || app.staticTexts["broadcastConfirmed"].exists
            })
            let payout = try AddressDecoder.scriptPubKey(for: Self.fixtureAddress(0xD4), network: .signet)
            try await SignetMiner.mineOntoTip(payingTo: payout)
        }
        guard let coin = try BitcoinCLI.unspents(scriptHex: savingsScript.hex).first else {
            return XCTFail("the savings were not funded")
        }
        app.tabBars.buttons["People"].tap()
        savingsRow.tap()
        let balance = app.staticTexts["savingsBalance"]
        XCTAssertTrue(poll(timeout: 240, interval: 5, "the savings see their coin") {
            if balance.exists, (balance.value as? String ?? balance.label) != "0 sats" { return true }
            app.tabBars.buttons["Wallet"].tap()
            self.nudgeSync(app)
            app.tabBars.buttons["People"].tap()
            if !savingsRow.exists { app.navigationBars.buttons.firstMatch.tap() }
            if savingsRow.exists { savingsRow.tap() }
            return false
        })

        // 2. Alice proposes 100,000 sats to Carol (0xE5) and approves first.
        let utxo = WalletUTXO(txid: Data(Data(hex: coin.txid)!.reversed()), vout: coin.vout,
                              amount: coin.amount, scriptPubKey: savingsScript,
                              chain: .receive, index: 0, height: coin.height)
        var psbt = try vault.createSpend(
            utxos: [utxo],
            payments: [Payment(amount: 100_000, address: Self.fixtureAddress(0xE5), network: .signet)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: UInt32(try BitcoinCLI.blockCount()),
            randomness: { 0.5 })
        let alice = try HDKey(seed: Data(repeating: 0xA1, count: 64))
        try vault.partialSign(&psbt, master: alice, knownUTXOs: [utxo],
                              ownedOutputCoordinates: [.init(choice: 1, index: 0)])
        let request = try ApprovalRequest(network: .signet, vault: recordID, name: "E2E Vault",
                                          psbt: psbt).serialized()

        // 3. This phone reads it, approves, and finishes.
        app.terminate()
        app = launchApp(clipboard: request)
        app.tabBars.buttons["People"].tap()
        XCTAssertTrue(savingsRow.waitForExistence(timeout: 30))
        savingsRow.tap()
        let approve = app.buttons["approveRequestButton"]
        XCTAssertTrue(scrollUntilExists(app, approve), "savings detail did not load")
        approve.tap()
        XCTAssertTrue(app.buttons["approvalPasteButton"].waitForExistence(timeout: 20),
                      "approval sheet did not appear")
        let reviewStart = Date()
        app.buttons["approvalPasteButton"].tap()
        app.buttons["reviewApprovalButton"].tap()
        let progress = app.staticTexts["approvalProgress"]
        XCTAssertTrue(scrollUntilExists(app, progress), "the request was not reviewed")
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Pays'")).firstMatch.exists,
                      "review lists no payment")
        XCTAssertTrue(app.staticTexts["Back into E2E Vault"].exists, "review lists no output back into the savings")
        XCTAssertTrue(progress.label.contains("1 of 2"), progress.label)
        XCTAssertTrue(progress.label.contains("not in People"), "an unknown co-owner should be named as such: \(progress.label)")
        Timings.record("vault", step: "cosign-review", from: reviewStart)
        Screenshots.capture(app, "15-approve-request", testCase: self)

        app.buttons["approveButton"].tap()
        XCTAssertTrue(poll(timeout: 60, "this phone's approval") { progress.exists && progress.label.contains("2 of 2") })
        XCTAssertTrue(scrollUntilExists(app, app.staticTexts["Share your approval"]), "no approval to share back")
        let finish = app.buttons["finishApprovalButton"]
        XCTAssertTrue(scrollUntilExists(app, finish, up: true) && finish.isEnabled, "Finish is not offered at threshold")
        finish.tap()
        XCTAssertTrue(app.staticTexts["approvalBroadcast"].waitForExistence(timeout: 60), "the finish did not broadcast")
        XCTAssertTrue(poll(timeout: 60, interval: 1, "spend in the node's mempool") {
            (try? BitcoinCLI.mempoolTxids().isEmpty == false) ?? false
        })
        let payout = try AddressDecoder.scriptPubKey(for: Self.fixtureAddress(0xD4), network: .signet)
        try await SignetMiner.mineOntoTip(payingTo: payout)
        XCTAssertTrue(poll(timeout: 120, interval: 5, "the spend leaves the savings' UTXO set") {
            (try? BitcoinCLI.unspents(scriptHex: savingsScript.hex).isEmpty) ?? false
        })

        // Sensitive state is dropped on a background transition.
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertFalse(progress.waitForExistence(timeout: 3), "approval review survived backgrounding")
    }

    // MARK: - 10 People: add, pay a fresh address, refuse a duplicate (mines)

    /// Alice's card is the fixture 0xA1 key. Paying her derives her receive
    /// address 0, and the counter moves once the send commits, so the next
    /// review derives address 1. Adding her again, however her key is
    /// spelled, is refused by name.
    func test10PeopleAddAndPay() async throws {
        let aliceKey = try Self.fixtureCosigner(0xA1)
        let card = try PersonCard(network: .signet, name: "Alice", payTo: "tr(\(aliceKey))",
                                  signerKey: aliceKey).serialized()
        let app = launchApp(clipboard: card)
        app.tabBars.buttons["People"].tap()
        if !app.buttons["personRow-Alice"].exists {
            app.buttons["addPersonButton"].tap()
            XCTAssertTrue(app.buttons["personPasteButton"].waitForExistence(timeout: 20), "no add-person sheet")
            app.buttons["personPasteButton"].tap()
            XCTAssertTrue(app.staticTexts["personPayToSummary"].waitForExistence(timeout: 10), "the card was not understood")
            XCTAssertEqual(app.staticTexts["personPayToSummary"].label, "Fresh address each payment")
            XCTAssertEqual(app.staticTexts["personSignerSummary"].label, "Can co-own savings")
            app.buttons["savePersonButton"].tap()
        }
        let row = app.buttons["personRow-Alice"]
        XCTAssertTrue(row.waitForExistence(timeout: 30), "Alice was not saved")
        Screenshots.capture(app, "24-people", testCase: self)

        // Pay her: the review names her and shows the fresh address.
        row.tap()
        let pay = app.buttons["payPersonButton"]
        XCTAssertTrue(pay.waitForExistence(timeout: 20), "no Pay button on the person")
        pay.tap()
        XCTAssertTrue(app.staticTexts["selectedPersonName"].waitForExistence(timeout: 20), "send sheet has no recipient")
        app.typeInto("amountField", "20000")
        app.dismissKeyboard()
        app.buttons["reviewButton"].tap()
        let recipient = app.staticTexts["reviewRecipient"]
        XCTAssertTrue(scrollUntilExists(app, recipient), "review does not name the person")
        let destination = app.staticTexts["reviewDestination"]
        XCTAssertTrue(destination.exists)
        let firstAddress = destination.label
        XCTAssertTrue(firstAddress.hasPrefix("tb1p"), firstAddress)
        let expectedIndex = try (0 ..< 5).first { index in
            try Self.fixtureReceiveAddress(0xA1, index: UInt32(index)) == firstAddress
        }
        XCTAssertNotNil(expectedIndex, "the review address is not one of Alice's first five")
        XCTAssertFalse(app.staticTexts["addressReuseWarning"].exists, "a card-holder is never warned about reuse")
        Screenshots.capture(app, "25-pay-person-review", testCase: self)

        app.buttons["sendButton"].tap()
        XCTAssertTrue(poll(timeout: 60, "broadcast to Alice") {
            app.staticTexts["broadcastPending"].exists || app.staticTexts["broadcastConfirmed"].exists
        })
        let payout = try AddressDecoder.scriptPubKey(for: Self.fixtureAddress(0xD4), network: .signet)
        try await SignetMiner.mineOntoTip(payingTo: payout)
        app.buttons["sendSheetDoneButton"].tap()

        // The counter moved: the next review derives the next address.
        XCTAssertTrue(pay.waitForExistence(timeout: 20))
        pay.tap()
        XCTAssertTrue(app.staticTexts["selectedPersonName"].waitForExistence(timeout: 20))
        app.typeInto("amountField", "1000")
        app.dismissKeyboard()
        app.buttons["reviewButton"].tap()
        XCTAssertTrue(scrollUntilExists(app, recipient))
        XCTAssertNotEqual(destination.label, firstAddress, "the second payment reused the first address")
        XCTAssertEqual(destination.label, try Self.fixtureReceiveAddress(0xA1, index: UInt32(expectedIndex! + 1)))
        app.buttons["sendSheetDoneButton"].tap()

        // The same key, spelled with h instead of ', is still Alice.
        app.navigationBars.buttons.firstMatch.tap()
        app.buttons["addPersonButton"].tap()
        XCTAssertTrue(app.textFields["personPasteField"].waitForExistence(timeout: 20) || app.textViews["personPasteField"].waitForExistence(timeout: 5))
        app.typeInto("personNameField", "Alice again")
        app.typeInto("personPasteField", aliceKey.replacingOccurrences(of: "'", with: "h"))
        app.dismissKeyboard()
        XCTAssertTrue(scrollUntilExists(app, app.buttons["savePersonButton"]))
        app.buttons["savePersonButton"].tap()
        let error = app.staticTexts["personError"]
        XCTAssertTrue(scrollUntilExists(app, error), "the duplicate was accepted")
        XCTAssertTrue(error.label.contains("already belongs to Alice"), error.label)
    }

    /// Alice's receive address at `index`, as her wallet would derive it from
    /// the fixture 0xA1 account key.
    static func fixtureReceiveAddress(_ byte: UInt8, index: UInt32) throws -> String {
        let master = try HDKey(seed: Data(repeating: byte, count: 64))
        let account = try BIP86.accountKey(from: master, coinType: 1, account: 0)
        let key = try account.derived(path: "0/\(index)")
        return try BIP86.address(internalKey: key.publicKey.dropFirst(), hrp: "tb")
    }

    // MARK: - 11 Beginner shell (mine-free)

    /// A fresh wallet shows four tabs, one line of sync status, and a
    /// Settings screen without the expert rows; the Advanced switch brings
    /// them back and takes them away again without deleting anything.
    func test11BeginnerShellHidesAdvancedControls() throws {
        let app = launchApp(run: "beginner", reset: true, expectOnboarding: true,
                            configureLocalNode: false)
        app.buttons["createWalletButton"].tap()
        XCTAssertTrue(app.switches["writtenDownToggle"].waitForExistence(timeout: 180),
                      "backup sheet did not appear after create")
        app.flipSwitch(app.switches["writtenDownToggle"])
        let backupDone = app.buttons["backupDoneButton"]
        XCTAssertTrue(scrollUntilExists(app, backupDone, maxSwipes: 4))
        backupDone.tap()
        XCTAssertTrue(app.staticTexts["balanceText"].waitForExistence(timeout: 60), "home did not appear")

        XCTAssertTrue(app.tabBars.buttons["People"].exists)
        XCTAssertFalse(app.tabBars.buttons["Vaults"].exists, "beginners never see a Vaults tab")
        XCTAssertTrue(app.otherElements["syncSummaryText"].exists || app.staticTexts["syncSummaryText"].exists
                      || app.buttons["retryPeersButton"].exists, "no one-line sync status")
        XCTAssertFalse(app.staticTexts["Filter scan"].exists, "filter scan detail shown to a beginner")
        XCTAssertTrue(app.buttons["syncNowButton"].exists)

        app.tabBars.buttons["Settings"].tap()
        let toggle = app.switches["advancedModeToggle"]
        XCTAssertTrue(scrollUntilExists(app, toggle), "no Advanced mode switch")
        XCTAssertTrue(app.buttons["exportBundleButton"].exists)
        XCTAssertFalse(scrollUntilExists(app, app.buttons["refreshPeersButton"], maxSwipes: 4),
                       "connected peers shown to a beginner")
        XCTAssertFalse(app.textFields["esploraURLField"].exists, "explorer setting shown to a beginner")
        XCTAssertFalse(app.switches["verifyFromGenesisToggle"].exists, "chain verification shown to a beginner")
        XCTAssertFalse(app.staticTexts["Manual peers"].exists, "manual peers shown with none configured")
        XCTAssertTrue(scrollUntilExists(app, app.buttons["deleteWalletButton"], maxSwipes: 4))
        Screenshots.capture(app, "23-settings-beginner", testCase: self)

        XCTAssertTrue(scrollUntilExists(app, toggle, up: true))
        app.flipSwitch(toggle)
        XCTAssertTrue(scrollUntilExists(app, app.buttons["refreshPeersButton"]), "Advanced mode did not reveal the peers")
        app.tabBars.buttons["People"].tap()
        XCTAssertTrue(scrollUntilExists(app, app.buttons["newVaultButton"]), "Advanced mode did not reveal the Vaults section")
        app.tabBars.buttons["Settings"].tap()
        XCTAssertTrue(scrollUntilExists(app, toggle, up: true))
        app.flipSwitch(toggle)
        XCTAssertFalse(scrollUntilExists(app, app.buttons["refreshPeersButton"], maxSwipes: 4),
                       "turning Advanced off left the peers visible")
    }

    // MARK: - 12 Shared savings from People (mines)

    /// Create "Savings with Alice, Bob" from the address book (2 of 3 with
    /// this phone), share the card, fund it from the wallet, and ask Alice
    /// for approval of a payment to her. The approve-and-finish half is
    /// test07; this is the creation half a beginner does.
    func test12SharedSavingsCreateAndAsk() async throws {
        let aliceKey = try Self.fixtureCosigner(0xA1)
        let bobKey = try Self.fixtureCosigner(0xB2)
        let bobCard = try PersonCard(network: .signet, name: "Bob", payTo: "tr(\(bobKey))",
                                     signerKey: bobKey).serialized()
        var app = launchApp(clipboard: bobCard)
        app.tabBars.buttons["People"].tap()
        if !app.buttons["personRow-Bob"].exists {
            app.buttons["addPersonButton"].tap()
            XCTAssertTrue(app.buttons["personPasteButton"].waitForExistence(timeout: 20))
            app.buttons["personPasteButton"].tap()
            XCTAssertTrue(app.staticTexts["personSignerSummary"].waitForExistence(timeout: 10))
            app.buttons["savePersonButton"].tap()
            XCTAssertTrue(app.buttons["personRow-Bob"].waitForExistence(timeout: 30), "Bob was not saved")
        }
        if !app.buttons["personRow-Alice"].exists {
            let aliceCard = try PersonCard(network: .signet, name: "Alice", payTo: "tr(\(aliceKey))",
                                           signerKey: aliceKey).serialized()
            app.terminate()
            app = launchApp(clipboard: aliceCard)
            app.tabBars.buttons["People"].tap()
            app.buttons["addPersonButton"].tap()
            XCTAssertTrue(app.buttons["personPasteButton"].waitForExistence(timeout: 20))
            app.buttons["personPasteButton"].tap()
            XCTAssertTrue(app.staticTexts["personSignerSummary"].waitForExistence(timeout: 10))
            app.buttons["savePersonButton"].tap()
            XCTAssertTrue(app.buttons["personRow-Alice"].waitForExistence(timeout: 30), "Alice was not saved")
        }

        let savingsName = "Savings with Alice, Bob"
        if !app.staticTexts[savingsName].exists {
            let createStart = Date()
            app.buttons["newSharedSavingsButton"].tap()
            XCTAssertTrue(app.buttons["coOwnerToggle-Alice"].waitForExistence(timeout: 20), "no co-owner picker")
            app.buttons["coOwnerToggle-Alice"].tap()
            app.buttons["coOwnerToggle-Bob"].tap()
            XCTAssertTrue(app.staticTexts["2 of 3"].exists, "the threshold did not settle at 2 of 3")
            XCTAssertTrue(scrollUntilExists(app, app.buttons["createSharedSavingsButton"]))
            app.buttons["createSharedSavingsButton"].tap()
            XCTAssertTrue(app.staticTexts["savingsShareNotice"].waitForExistence(timeout: 60),
                          "creating did not lead to the share step")
            Timings.record("vault", step: "shared-savings-create", from: createStart)
            Screenshots.capture(app, "26-savings-share", testCase: self)
            app.buttons["savingsShareDoneButton"].tap()
            XCTAssertTrue(app.staticTexts[savingsName].waitForExistence(timeout: 30), "the savings were not listed")
        }

        // Fund it from the wallet, then ask Alice for approval of 20,000 to her.
        app.staticTexts[savingsName].firstMatch.tap()
        let addressBlock = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'tb1p'")).firstMatch
        XCTAssertTrue(addressBlock.waitForExistence(timeout: 20), "no receive address on the savings")
        let savingsAddress = addressBlock.label
        let savingsScript = try AddressDecoder.scriptPubKey(for: savingsAddress, network: .signet)
        if try BitcoinCLI.unspents(scriptHex: savingsScript.hex).isEmpty {
            app.tabBars.buttons["Send"].tap()
            app.typeInto("destinationField", savingsAddress)
            app.typeInto("amountField", "50000")
            app.dismissKeyboard()
            app.buttons["reviewButton"].tap()
            XCTAssertTrue(app.buttons["sendButton"].waitForExistence(timeout: 60))
            app.buttons["sendButton"].tap()
            XCTAssertTrue(poll(timeout: 60, "broadcast into the savings") {
                app.staticTexts["broadcastPending"].exists || app.staticTexts["broadcastConfirmed"].exists
            })
            let payout = try AddressDecoder.scriptPubKey(for: Self.fixtureAddress(0xD4), network: .signet)
            try await SignetMiner.mineOntoTip(payingTo: payout)
            app.tabBars.buttons["People"].tap()
            app.staticTexts[savingsName].firstMatch.tap()
        }
        let ask = app.buttons["askApprovalButton"]
        XCTAssertTrue(poll(timeout: 240, interval: 5, "the savings see their coin") {
            if self.scrollUntilExists(app, ask, maxSwipes: 2), ask.isEnabled { return true }
            app.tabBars.buttons["Wallet"].tap()
            self.nudgeSync(app)
            app.tabBars.buttons["People"].tap()
            if !app.staticTexts[savingsName].exists { app.navigationBars.buttons.firstMatch.tap() }
            app.staticTexts[savingsName].firstMatch.tap()
            return false
        })
        ask.tap()
        XCTAssertTrue(app.buttons["askChoosePerson-Alice"].waitForExistence(timeout: 20)
                      || app.buttons["Choose a person"].waitForExistence(timeout: 5), "no person picker")
        if app.buttons["Choose a person"].exists { app.buttons["Choose a person"].tap() }
        app.buttons["askChoosePerson-Alice"].tap()
        app.typeInto("askAmountField", "20000")
        app.dismissKeyboard()
        app.buttons["buildApprovalRequestButton"].tap()
        XCTAssertTrue(scrollUntilExists(app, app.staticTexts.matching(
            NSPredicate(format: "label BEGINSWITH '{\"winnow\":\"approval\"'")).firstMatch),
            "no request was built")
        Screenshots.capture(app, "27-ask-approval", testCase: self)
    }

    // MARK: - 09 Backup resume + recovery-phrase reveal (#5)

    /// Mine-free. Kills the app on the mnemonic backup sheet and asserts the
    /// relaunch resumes it (the backup-pending flag survives restarts), then
    /// completes the backup, proves a further relaunch stays on home, and
    /// reveals the phrase from Settings -> Backup (device auth is bypassed in
    /// E2E mode; simulators have no passcode). Numbered after PR #22's
    /// test08.
    func test09BackupResumeAndReveal() throws {
        let backupEnvironment: [String: String] = [
            "WINNOW_E2E": "1",
            "WINNOW_E2E_RUN": "backup",
            "WINNOW_E2E_ENTROPY": Self.entropyHex,
        ]
        let app = launchApp(run: "backup", reset: true, expectOnboarding: true,
                            configureLocalNode: false)
        app.buttons["createWalletButton"].tap()
        XCTAssertTrue(app.switches["writtenDownToggle"].waitForExistence(timeout: 180),
                      "backup sheet did not appear after create")
        Screenshots.capture(app, "20-backup-sheet", testCase: self)

        // Kill mid-backup, before Done.
        app.terminate()
        let resumed = XCUIApplication()
        resumed.launchEnvironment = backupEnvironment // same run, NO reset
        resumed.launch()
        XCTAssertTrue(resumed.switches["writtenDownToggle"].waitForExistence(timeout: 60),
                      "relaunch did not resume the backup sheet — backup skipped (#5)")
        Screenshots.capture(resumed, "21-backup-resumed", testCase: self)

        // A background transition erases the phrase and dismisses its sheet;
        // resuming requires another explicit action (and production auth).
        XCUIDevice.shared.press(.home)
        resumed.activate()
        XCTAssertFalse(resumed.switches["writtenDownToggle"].waitForExistence(timeout: 3),
                       "onboarding recovery phrase survived backgrounding")
        let resumeBackup = resumed.buttons["resumeBackupButton"]
        XCTAssertTrue(resumeBackup.waitForExistence(timeout: 20),
                      "pending backup has no explicit resume action")
        resumeBackup.tap()
        XCTAssertTrue(resumed.switches["writtenDownToggle"].waitForExistence(timeout: 60),
                      "explicit backup resume did not restore the authenticated flow")

        // Complete the backup: toggle + Done -> wallet home.
        resumed.flipSwitch(resumed.switches["writtenDownToggle"])
        let backupDone = resumed.buttons["backupDoneButton"]
        XCTAssertTrue(scrollUntilExists(resumed, backupDone, maxSwipes: 4),
                      "backup Done button was not reachable after explicit resume")
        backupDone.tap()
        XCTAssertTrue(resumed.staticTexts["balanceText"].waitForExistence(timeout: 60),
                      "home did not appear after backup Done")

        // A confirmed backup must not re-prompt on the next launch.
        resumed.terminate()
        let settled = XCUIApplication()
        settled.launchEnvironment = backupEnvironment
        settled.launch()
        XCTAssertTrue(settled.staticTexts["balanceText"].waitForExistence(timeout: 60),
                      "confirmed backup re-prompted on relaunch")

        // Reveal from Settings -> Backup: the fixed entropy's numbered first
        // word renders in the grid.
        settled.tabBars.buttons["Settings"].tap()
        let revealButton = settled.buttons["revealPhraseButton"]
        XCTAssertTrue(scrollUntilExists(settled, revealButton), "no reveal button in Backup")
        revealButton.tap()
        let firstWord = "1. " + (Self.mnemonic.split(separator: " ").first.map(String.init) ?? "")
        XCTAssertTrue(settled.staticTexts[firstWord].waitForExistence(timeout: 30),
                      "revealed phrase grid missing \(firstWord)")
        XCTAssertTrue(settled.buttons["settingsCopyPhraseButton"].exists,
                      "Settings recovery screen does not offer phrase copy")
        Screenshots.capture(settled, "22-phrase-revealed", testCase: self)
        XCUIDevice.shared.press(.home)
        settled.activate()
        XCTAssertFalse(settled.staticTexts[firstWord].waitForExistence(timeout: 3),
                       "Settings recovery phrase survived backgrounding")
        XCTAssertTrue(scrollUntilExists(settled, revealButton, up: true),
                      "phrase sheet did not dismiss to Settings")

        // A seed-bearing export is staged only for the lifetime of its sheet.
        let exportButton = settled.buttons["exportBundleButton"]
        XCTAssertTrue(scrollUntilExists(settled, exportButton, up: true),
                      "no export button after phrase dismissal")
        exportButton.tap()
        let seedToggle = settled.switches["exportIncludeMnemonicToggle"]
        XCTAssertTrue(seedToggle.waitForExistence(timeout: 20), "no seed-export toggle")
        settled.flipSwitch(seedToggle)
        settled.buttons["exportConfirmButton"].tap()
        let seedAlert = settled.alerts["Include the recovery phrase?"]
        XCTAssertTrue(seedAlert.waitForExistence(timeout: 10), "no seed-export warning")
        seedAlert.buttons["Export with phrase"].tap()
        let shareLink = settled.buttons["exportShareLink"]
        XCTAssertTrue(shareLink.waitForExistence(timeout: 30), "seed export was not staged")
        XCUIDevice.shared.press(.home)
        settled.activate()
        XCTAssertFalse(shareLink.waitForExistence(timeout: 3),
                       "seed-bearing staged export survived backgrounding")
        XCTAssertTrue(scrollUntilExists(settled, exportButton, up: true),
                      "seed export sheet did not dismiss to Settings")
        settled.terminate()

        // Imported JSON can carry the same seed. It is erased immediately on
        // background even before parsing or authentication begins.
        let importApp = launchApp(run: "import-lifecycle", reset: true,
                                  expectOnboarding: true, configureLocalNode: false)
        importApp.buttons["importWalletButton"].tap()
        let privateMarker = "seed-bearing-private-material"
        importApp.typeInto("importJSONEditor", privateMarker)
        XCTAssertTrue(((importApp.textViews["importJSONEditor"].value as? String) ?? "")
            .contains(privateMarker), "import test marker was not entered")
        XCUIDevice.shared.press(.home)
        importApp.activate()
        XCTAssertTrue(importApp.buttons["importPasteButton"].waitForExistence(timeout: 20),
                      "empty import sheet did not remain available")
        XCTAssertFalse(((importApp.textViews["importJSONEditor"].value as? String) ?? "")
            .contains(privateMarker), "import text survived backgrounding")
        importApp.terminate()
    }

    // MARK: - 08 Export bundle (Settings -> Backup, #18)

    /// Walks the export flow on the funded "main" wallet: watch-only by
    /// default (no mnemonic key and no seed words in the preview, which for
    /// watch-only IS the real JSON), the staged share link and its system
    /// share sheet, then the seed path behind the explicit confirm with the
    /// on-screen preview redacted to "<redacted>". The shared file's real
    /// content and deletion lifecycle are unit-tested (ExportStagingFile /
    /// ImportBundle tests); test06 walks the import UI on an equivalent
    /// bundle, closing the round trip.
    func test08ExportBundle() throws {
        let app = launchApp()
        app.tabBars.buttons["Settings"].tap()
        let exportButton = app.buttons["exportBundleButton"]
        XCTAssertTrue(scrollUntilExists(app, exportButton), "no export button in Settings")
        exportButton.tap()

        // Watch-only is the default: no toggle flip, straight to export.
        let confirm = app.buttons["exportConfirmButton"]
        XCTAssertTrue(confirm.waitForExistence(timeout: 20), "no export confirm button")
        XCTAssertEqual(confirm.label, "Export watch-only bundle",
                       "seed export must not be the default")
        confirm.tap()
        let shareLink = app.buttons["exportShareLink"]
        XCTAssertTrue(shareLink.waitForExistence(timeout: 60), "no staged share link after export")
        let preview = app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS %@", "\"version\"")).firstMatch
        XCTAssertTrue(preview.waitForExistence(timeout: 20), "no bundle preview")
        var json = preview.label
        XCTAssertTrue(json.contains("\"descriptor\""), "preview lacks the descriptor")
        XCTAssertTrue(json.contains("\"lastKnownHeight\""), "preview lacks the scan frontier")
        XCTAssertFalse(json.contains("mnemonic"), "watch-only preview has a mnemonic key")
        XCTAssertFalse(json.contains(Self.mnemonic), "watch-only preview contains the seed")
        Screenshots.capture(app, "16-export-watch-only", testCase: self)

        // The share link stages a real file and opens the system share sheet.
        shareLink.tap()
        let sheetTitle = app.staticTexts.matching(
            NSPredicate(format: "label BEGINSWITH %@", "winnow-signet-")).firstMatch
        let shareSheet = poll(timeout: 20, interval: 1, "share sheet") {
            app.otherElements["ActivityListView"].exists || sheetTitle.exists
        }
        XCTAssertTrue(shareSheet, "share sheet did not appear")
        Screenshots.capture(app, "17-export-share-sheet", testCase: self)
        let closeShare = app.buttons["Close"].firstMatch
        if closeShare.waitForExistence(timeout: 5), closeShare.isHittable {
            closeShare.tap()
        } else {
            // Fallback: drag the sheet down to dismiss.
            app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.55))
                .press(forDuration: 0.05, thenDragTo:
                    app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.98)))
        }
        // Back on the export form (the next step's scroll asserts the toggle).

        // Seed path: the toggle resets the export, the alert gates it, and
        // the on-screen preview redacts the phrase.
        let toggle = app.switches["exportIncludeMnemonicToggle"]
        XCTAssertTrue(scrollUntilExists(app, toggle, up: true), "no seed toggle")
        app.flipSwitch(toggle)
        XCTAssertTrue(confirm.waitForExistence(timeout: 10), "toggle did not reset the export")
        confirm.tap()
        let alert = app.alerts["Include the recovery phrase?"]
        XCTAssertTrue(alert.waitForExistence(timeout: 10), "no seed confirm alert")
        Screenshots.capture(app, "18-export-seed-confirm", testCase: self)
        alert.buttons["Export with phrase"].tap()
        XCTAssertTrue(shareLink.waitForExistence(timeout: 60), "no share link after seed export")
        XCTAssertTrue(preview.waitForExistence(timeout: 20), "no seed-export preview")
        json = preview.label
        XCTAssertTrue(json.contains("\"mnemonic\""), "seed preview lacks the mnemonic key")
        XCTAssertTrue(json.contains("<redacted>"), "seed preview is not redacted")
        XCTAssertFalse(json.contains(Self.mnemonic), "on-screen preview shows the real phrase")
        XCTAssertTrue(app.staticTexts["The recovery phrase is in the shared file, not shown here."]
            .exists, "no shared-file note")
        Screenshots.capture(app, "19-export-seed-redacted", testCase: self)

        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertFalse(shareLink.waitForExistence(timeout: 3),
                       "staged seed export survived backgrounding")
        XCTAssertTrue(scrollUntilExists(app, exportButton, up: true),
                      "seed export sheet did not dismiss to Settings")
    }
}
