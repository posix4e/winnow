import Foundation
import TestSupport
import XCTest

/// Screenshot capture: XCTAttachment on the test result AND a PNG copy on the
/// host. CI supplies WINNOW_SCREENSHOT_DIR; local runs use a fresh temporary
/// directory. Captures never write directly into the public website.
enum Screenshots {
    static let directory: URL = {
        if let path = BitcoinCLI.environmentValue("WINNOW_SCREENSHOT_DIR"), !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        return FileManager.default.temporaryDirectory
            .appending(path: "winnow-ui-\(UUID().uuidString)", directoryHint: .isDirectory)
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
    @MainActor
    func balanceText(_ app: XCUIApplication) -> String {
        (app.staticTexts["balanceText"].value as? String) ?? ""
    }

    /// Scrolls the iPhone screen until `element` exists (SwiftUI Forms
    /// materialize rows lazily). Text readers only need its accessible label;
    /// a long payload need not fit on screen. Taps and screenshot framing must
    /// request `fullyVisible` to move the whole row clear of the bars.
    ///
    /// Drags use screen coordinates: a TabView keeps every tab's list in
    /// the accessibility tree, so element-based swipes can hit a hidden
    /// tab's list instead of the visible form. The finger rests before it
    /// lifts, so the form stops where the drag ends. A flung form stops
    /// wherever its momentum ran out — a stepper left half under the
    /// navigation bar took its tap on the bar — or is still moving when
    /// the next tap arrives, which only stops the scroll.
    ///
    /// Each drag moves half the surface. Once a row exists, return immediately
    /// unless the caller asked for it fully in view.
    @MainActor
    @discardableResult
    func scrollUntilExists(_ app: XCUIApplication, _ element: XCUIElement,
                           maxSwipes: Int = 16, up: Bool = false, fullyVisible: Bool = false) -> Bool {
        for _ in 0 ..< maxSwipes {
            // Long enough for a row to materialise after a drag animates on
            // a slow CI VM, short enough that a row several drags down does
            // not cost many seconds of waiting per drag.
            if element.appears(within: 1.5) {
                guard fullyVisible else { return true }
                return reveal(app, element, fullyVisible: fullyVisible)
            }
            let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: up ? 0.25 : 0.75))
            let end = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: up ? 0.75 : 0.25))
            start.press(forDuration: 0.05, thenDragTo: end, withVelocity: .default, thenHoldForDuration: 0.25)
        }
        guard element.appears(within: 1.5) else { return false }
        guard fullyVisible else { return true }
        return reveal(app, element, fullyVisible: fullyVisible)
    }

    /// The vertical band a row is tappable in: below the lowest navigation
    /// bar (a sheet's sits below the screen's), above the tab bar and the
    /// keyboard.
    @MainActor
    private func clearBand(_ app: XCUIApplication, in frame: CGRect) -> ClosedRange<CGFloat>? {
        // A dismissed sheet can remove a navigation bar between an indexed
        // query and its frame read. Read the bars from one immutable snapshot.
        guard let snapshot = try? app.snapshot() else {
            XCTFail("could not snapshot the app's navigation bars")
            return nil
        }
        let top = max(frame.minY, navigationBarBottom(snapshot) ?? frame.minY)
        var bottom = frame.maxY
        // A sheet covers the underlying tab bar; that bar must not shrink
        // the sheet's usable area and cause repeated ineffective drags.
        for cover in [app.tabBars.firstMatch, app.keyboards.firstMatch] where cover.exists && cover.isHittable {
            bottom = min(bottom, cover.frame.minY)
        }
        return top ... max(top, bottom)
    }

    @MainActor
    private func navigationBarBottom(_ snapshot: XCUIElementSnapshot) -> CGFloat? {
        let childBottoms = snapshot.children.compactMap { navigationBarBottom($0) }
        let ownBottom = snapshot.elementType == .navigationBar ? [snapshot.frame.maxY] : []
        return (childBottoms + ownBottom).max()
    }

    /// Drags `element` clear of the bars. A row taller than the band shows
    /// its top; `fullyVisible` requires its whole frame inside the clear area.
    /// Wait for lazy-row geometry before another gesture. An extra downward
    /// drag at the top of a form can dismiss its sheet and abandon signing.
    @MainActor
    private func reveal(_ app: XCUIApplication, _ element: XCUIElement, fullyVisible: Bool) -> Bool {
        let margin: CGFloat = 8
        guard let appFrame = usableFrame(app) else { return false }
        // Each AX frame read resolves the element again. Reuse this geometry
        // within the reveal; the moving row is still reread after every drag.
        guard let band = openBand(app, in: appFrame, margin: margin) else { return false }
        let reach = band.upperBound - band.lowerBound - 2 * margin
        for attempt in 0 ... 3 {
            guard let frame = usableFrame(element, within: 1.5) else { return false }
            let shift = revealShift(frame, in: band, margin: margin, reach: reach)
            if shift == 0 {
                // XCTest can reject a valid visible button's activation point.
                // Verify its bounds here; the shared journey taps its center.
                return !fullyVisible || (frame.minX >= appFrame.minX && frame.maxX <= appFrame.maxX
                    && frame.minY >= band.lowerBound + margin && frame.maxY <= band.upperBound - margin)
            }
            guard attempt < 3 else { return false }
            let midY = (band.lowerBound + band.upperBound) / 2
            let start = app.coordinate(withNormalizedOffset: .zero)
                .withOffset(CGVector(dx: appFrame.width / 2, dy: midY - shift / 2 - appFrame.minY))
            start.press(forDuration: 0.05, thenDragTo: start.withOffset(CGVector(dx: 0, dy: shift)),
                        withVelocity: .default, thenHoldForDuration: 0.25)
        }
        return false
    }

    /// The clear band once it has room for a row. A sheet that is still
    /// closing keeps the lowest navigation bar on screen and leaves no room
    /// below it for a moment; wait for it to go rather than give up.
    @MainActor
    private func openBand(_ app: XCUIApplication, in appFrame: CGRect, margin: CGFloat) -> ClosedRange<CGFloat>? {
        let deadline = Date().addingTimeInterval(5)
        while true {
            guard let band = clearBand(app, in: appFrame) else { return nil }
            let reach = band.upperBound - band.lowerBound - 2 * margin
            if reach.isFinite, reach > 0 { return band }
            guard Date() < deadline else { return nil }
            Thread.sleep(forTimeInterval: 0.2)
        }
    }

    @MainActor
    private func usableFrame(_ element: XCUIElement, within timeout: TimeInterval = 0) -> CGRect? {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            if element.exists {
                let frame = element.frame
                if !frame.isEmpty,
                   [frame.minX, frame.minY, frame.maxX, frame.maxY].allSatisfy(\.isFinite) { return frame }
            }
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { return nil }
            Thread.sleep(forTimeInterval: min(0.2, remaining))
        }
    }

    /// Call after revealing and enabling the element. SwiftUI can replace its
    /// AX element during a button-relative tap, turning a valid center into
    /// the row's corner. Anchor the event to the stable app using fresh bounds.
    @MainActor
    func tapVisibleCenter(_ app: XCUIApplication, _ element: XCUIElement) -> Bool {
        guard let appFrame = usableFrame(app), let frame = usableFrame(element),
              appFrame.contains(frame) else { return false }
        app.coordinate(withNormalizedOffset: .zero)
            .withOffset(CGVector(dx: frame.midX - appFrame.minX, dy: frame.midY - appFrame.minY))
            .tap()
        return true
    }

    private func revealShift(_ frame: CGRect, in band: ClosedRange<CGFloat>,
                             margin: CGFloat, reach: CGFloat) -> CGFloat {
        var shift: CGFloat = 0
        if frame.minY < band.lowerBound + margin {
            shift = band.lowerBound + margin - frame.minY
        } else if frame.maxY > band.upperBound - margin, frame.height <= reach {
            shift = band.upperBound - margin - frame.maxY
        }
        guard shift != 0 else { return 0 }
        // Keep both ends inside the band, but move enough to begin scrolling.
        // A 17-point nudge previously moved nothing three times in a row.
        let distance = min(reach, max(48, abs(shift)))
        return shift < 0 ? -distance : distance
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
    ///
    /// A tap that lands while the previous field's keyboard is still on its
    /// way out can leave nothing focused, and typing then fails with
    /// "neither element nor any descendant has keyboard focus" (seen on the
    /// hosted runners, #84). So the tap is repeated until the field has
    /// the keyboard, and dismissal waits for the keyboard to be gone.
    @MainActor
    func typeInto(_ identifier: String, _ text: String) {
        var field = textFields[identifier]
        if !field.exists { field = textViews[identifier] }
        XCTAssertTrue(field.appears(within: 20), "no text field \(identifier)")
        var focused = false
        for _ in 1...3 where !focused {
            field.tap()
            focused = field.waitForKeyboardFocus(timeout: 3)
        }
        XCTAssertTrue(focused, "\(identifier) never took keyboard focus")
        field.typeText(text)
        dismissKeyboard()
    }

    @MainActor
    func dismissKeyboard() {
        let keyboard = keyboards.firstMatch
        guard keyboard.exists else { return }
        defer {
            // The dismissal animates independently of app idleness; the next
            // tap must not race it.
            _ = keyboard.disappears(within: 5)
        }
        let returnKey = keyboards.buttons["return"]
        if returnKey.exists, returnKey.isHittable {
            returnKey.tap()
            return
        }
        // Keypads without a return key get an input-accessory Done button
        // (a toolbar floating above the keyboard).
        let sendDone = buttons["sendKeyboardDone"]
        if sendDone.exists, sendDone.isHittable {
            sendDone.tap()
            return
        }
        let toolbarDone = toolbars.buttons["Done"]
        if toolbarDone.appears(within: 2), toolbarDone.isHittable {
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
        if keyboard.exists {
            collectionViews.firstMatch.swipeDown()
        }
    }

    /// iOS 26 SwiftUI quirk: a Toggle in a Form/List surfaces as a container
    /// switch element wrapping the real UISwitch child; tapping the container
    /// does nothing. Taps the child switch (or the row's right edge), and
    /// taps again while the value stays put: a synthesized tap now and then
    /// vanishes on a busy simulator, the switch drawn untouched.
    @MainActor
    func flipSwitch(_ container: XCUIElement) {
        let before = switchValue(container)
        for _ in 1 ... 3 {
            let thumb = container.children(matching: .switch).firstMatch
            if thumb.exists {
                thumb.tap()
            } else {
                container.coordinate(withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)).tap()
            }
            guard let before else { return }
            let deadline = Date().addingTimeInterval(3)
            while Date() < deadline {
                if switchValue(container) != before { return }
                Thread.sleep(forTimeInterval: 0.25)
            }
        }
        XCTFail("switch \(container.identifier) stayed at \(before ?? "?") through three taps")
    }

    @MainActor
    private func switchValue(_ container: XCUIElement) -> String? {
        let thumb = container.children(matching: .switch).firstMatch
        return (thumb.exists ? thumb.value : container.value) as? String
    }
}

extension XCUIElement {
    /// Whether this element exists within `timeout`: checked now, then
    /// every fifth of a second until the deadline. `waitForExistence`
    /// answers the same question through XCTWaiter, whose first look at
    /// the element comes a second after the call however quickly it
    /// appeared; in one nightly every one of the suite's six hundred
    /// waits resolved on that first look, a second late each.
    @MainActor
    func appears(within timeout: TimeInterval) -> Bool {
        holds(within: timeout) { $0.exists }
    }

    /// Whether this element is gone within `timeout`: the polling
    /// counterpart of `waitForNonExistence`.
    @MainActor
    func disappears(within timeout: TimeInterval) -> Bool {
        holds(within: timeout) { !$0.exists }
    }

    /// Whether this element holds the keyboard within `timeout`: the
    /// condition `typeText` checks before it synthesizes a keystroke.
    @MainActor
    func waitForKeyboardFocus(timeout: TimeInterval) -> Bool {
        waitUntil(NSPredicate(format: "hasKeyboardFocus == true"), timeout: timeout)
    }

    /// Whether `predicate` holds for this element within `timeout`; the
    /// element is re-queried on each evaluation. The predicate is evaluated
    /// directly rather than through an `XCTNSPredicateExpectation`, for
    /// the reason `appears(within:)` gives.
    @MainActor
    func waitUntil(_ predicate: NSPredicate, timeout: TimeInterval) -> Bool {
        holds(within: timeout) { predicate.evaluate(with: $0) }
    }

    /// Polls `condition` against this element until it holds or the
    /// deadline passes: a check at once, one every 0.2 s, and a last one
    /// at the deadline itself.
    @MainActor
    private func holds(within timeout: TimeInterval, _ condition: (XCUIElement) -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            if condition(self) { return true }
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { return false }
            Thread.sleep(forTimeInterval: min(0.2, remaining))
        }
    }
}
