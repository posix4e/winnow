import Foundation
import XCTest

/// Screenshot capture: XCTAttachment on the test result AND a PNG copy on the
/// host. Destination: $WINNOW_SCREENSHOT_DIR, else ~/src/btc-swift/docs/screenshots
/// (on the host — the runner's own home inside the simulator is a container).
enum Screenshots {
    static let hostHome = ProcessInfo.processInfo.environment["SIMULATOR_HOST_HOME"] ?? NSHomeDirectory()

    static let directory: URL = {
        if let path = ProcessInfo.processInfo.environment["WINNOW_SCREENSHOT_DIR"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        return URL(fileURLWithPath: hostHome)
            .appending(path: "src/btc-swift/docs/screenshots", directoryHint: .isDirectory)
    }()

    @MainActor
    static func capture(_ app: XCUIApplication, _ name: String, testCase: XCTestCase) {
        let screenshot = app.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = "\(name).png"
        attachment.lifetime = .keepAlways
        testCase.add(attachment)

        let destination = directory.appending(path: "\(name).png")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            try screenshot.pngRepresentation.write(to: destination)
        } catch {
            // Direct host-path writes can be refused from the sim container;
            // fall back to host-side mkdir+cp via a spawned process.
            do {
                let staging = URL(fileURLWithPath: NSTemporaryDirectory()).appending(path: "\(name).png")
                try screenshot.pngRepresentation.write(to: staging)
                let mkdir = try HostProcess.run("/bin/mkdir", ["-p", directory.path])
                let copy = try HostProcess.run("/bin/cp", [staging.path, destination.path])
                if mkdir.status != 0 || copy.status != 0 {
                    XCTFail("could not save \(name).png to \(destination.path): \(mkdir.stderr)\(copy.stderr)")
                }
            } catch {
                XCTFail("could not save \(name).png to \(destination.path): \(error.localizedDescription)")
            }
        }
    }
}

extension XCTestCase {
    /// Text of the balance label ("12,345 sats").
    @MainActor
    func balanceText(_ app: XCUIApplication) -> String {
        (app.staticTexts["balanceText"].value as? String) ?? ""
    }

    /// Taps "Sync now" when idle to nudge a scan pass.
    @MainActor
    func nudgeSync(_ app: XCUIApplication) {
        let button = app.buttons["syncNowButton"]
        if button.exists, button.isEnabled { button.tap() }
    }

    /// Scrolls the topmost scroll view until `element` exists (SwiftUI
    /// Forms materialize rows lazily — `exists` is false below the fold).
    /// Uses screen-coordinate drags: a TabView keeps every tab's list in the
    /// accessibility tree, so element-based swipes can hit a hidden tab's
    /// list instead of the visible form.
    @MainActor
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

    /// Polls `condition` until it holds or the deadline passes (explicit
    /// waits, no fixed sleeps — the one allowed exception is the polling
    /// interval itself).
    @discardableResult
    func poll(timeout: TimeInterval, interval: TimeInterval = 2,
              _ message: String = "condition", condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            Thread.sleep(forTimeInterval: interval)
        }
        let result = condition()
        if !result { XCTFail("timed out (\(timeout)s) waiting for: \(message)") }
        return result
    }
}

extension XCUIApplication {
    /// Types into a field (TextField or TextEditor) and dismisses the
    /// software keyboard afterwards.
    @MainActor
    func typeInto(_ identifier: String, _ text: String) {
        var field = textFields[identifier]
        if !field.exists { field = textViews[identifier] }
        XCTAssertTrue(field.waitForExistence(timeout: 20), "no text field \(identifier)")
        field.tap()
        field.typeText(text)
        dismissKeyboard()
    }

    @MainActor
    func dismissKeyboard() {
        guard keyboards.firstMatch.exists else { return }
        let returnKey = keyboards.buttons["return"]
        if returnKey.exists, returnKey.isHittable {
            returnKey.tap()
            return
        }
        // Keypads without a return key get an input-accessory Done button
        // (a toolbar floating above the keyboard).
        let toolbarDone = toolbars.buttons["Done"]
        if toolbarDone.waitForExistence(timeout: 2), toolbarDone.isHittable {
            toolbarDone.tap()
            return
        }
        let doneKey = keyboards.buttons["Done"]
        if doneKey.exists, doneKey.isHittable {
            doneKey.tap()
            return
        }
        // Last resort: tapping the navigation bar dismisses the keyboard
        // without triggering any control.
        navigationBars.firstMatch.tap()
        if keyboards.firstMatch.exists {
            collectionViews.firstMatch.swipeDown()
        }
    }

    /// iOS 26 SwiftUI quirk: a Toggle in a Form/List surfaces as a container
    /// switch element wrapping the real UISwitch child; tapping the container
    /// does nothing. Taps the child switch (or the row's right edge).
    @MainActor
    func flipSwitch(_ container: XCUIElement) {
        let thumb = container.children(matching: .switch).firstMatch
        if thumb.exists {
            thumb.tap()
        } else {
            container.coordinate(withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)).tap()
        }
    }
}
