@testable import WinnowApp
import CoreBluetooth
import WalletCore
import XCTest

/// The Bluetooth transport's decisions, without a radio: what each Bluetooth
/// state means while a connection starts, and how notifications reach the
/// step in flight. The radio itself is only exercised with a real Ledger.
final class LedgerBluetoothTests: XCTestCase {
    func testBluetoothStatesStartFailOrWait() {
        XCTAssertNotNil(try? LedgerBluetoothTransport.readiness(for: .poweredOn)?.get())
        for state in [CBManagerState.poweredOff, .unauthorized, .unsupported] {
            guard case .failure(.transport) = LedgerBluetoothTransport.readiness(for: state) else {
                return XCTFail("state \(state.rawValue) should fail with a step the user can take")
            }
        }
        XCTAssertNil(LedgerBluetoothTransport.readiness(for: .resetting))
        XCTAssertNil(LedgerBluetoothTransport.readiness(for: .unknown))
    }

    func testNotificationsReachOnlyTheStepInFlight() throws {
        var router = LedgerBluetoothTransport.NotificationRouter()
        let mtu = Data([0x08, 0, 0, 0, 1, 153])
        XCTAssertEqual(try router.receive(mtu, during: .frameSize)?.get(), mtu)
        XCTAssertNil(router.receive(Data([0x05, 0, 0, 0, 2, 0x90, 0x00]), during: .frameSize))
        XCTAssertNil(router.receive(mtu, during: .written))
        XCTAssertNil(router.receive(mtu, during: nil))

        let reply = Data(repeating: 0x42, count: 30)
        let frames = try LedgerBluetoothFraming.frames(for: reply, frameSize: 20)
        XCTAssertEqual(frames.count, 2)
        XCTAssertNil(router.receive(frames[0], during: .reply))
        XCTAssertEqual(try router.receive(frames[1], during: .reply)?.get(), reply)

        var fresh = LedgerBluetoothTransport.NotificationRouter()
        guard case .failure = fresh.receive(Data([0x07, 0, 0]), during: .reply) else {
            return XCTFail("a frame without the APDU tag must fail the reply")
        }
    }
}
