import CoreBluetooth
import Foundation
import WalletCore

/// Opens a Ledger connection for one operation. The app uses Bluetooth; the
/// app tests swap in the device simulator.
protocol LedgerConnector: Sendable {
    func connect() async throws -> any LedgerSession
}

/// One open connection: APDUs in, replies out, then closed.
protocol LedgerSession: LedgerTransport {
    func close() async
}

struct LedgerBluetoothConnector: LedgerConnector {
    func connect() async throws -> any LedgerSession {
        let transport = LedgerBluetoothTransport()
        do {
            try await transport.open()
        } catch {
            await transport.close()
            throw error
        }
        return transport
    }
}

/// Ledger devices over Bluetooth Low Energy, as Ledger's own clients reach
/// them: find a device advertising a Ledger service, subscribe to its notify
/// characteristic, ask its frame size, then send APDUs as tagged frames and
/// reassemble the notified reply. iOS handles bonding: the first connection
/// shows a pairing code on the phone and on the Ledger.
///
/// All state lives on one serial queue, and one request is in flight at a
/// time; each step has a timeout and ends when its task is cancelled.
final class LedgerBluetoothTransport: NSObject, LedgerSession, @unchecked Sendable {
    /// The services Nano X, Stax, Flex and Apex advertise. Each has a notify
    /// (…0001…), write (…0002…) and write-without-response (…0003…) characteristic.
    static let serviceIdentifiers = [
        "13D63400-2C97-0004-0000-4C6564676572",
        "13D63400-2C97-6004-0000-4C6564676572",
        "13D63400-2C97-3004-0000-4C6564676572",
        "13D63400-2C97-8004-0000-4C6564676572",
    ]

    static var serviceUUIDs: [CBUUID] { serviceIdentifiers.map { CBUUID(string: $0) } }

    static func characteristic(_ kind: String, of service: CBUUID) -> CBUUID {
        CBUUID(string: service.uuidString.replacingOccurrences(of: "-0000-4C65", with: "-\(kind)-4C65"))
    }

    enum Step {
        case poweredOn, connected, characteristics, notifying, frameSize, written, reply
    }

    /// What a Bluetooth state means for a connection waiting to start: go
    /// ahead, fail with the step the user can take, or keep waiting (nil).
    static func readiness(for state: CBManagerState) -> Result<Data, LedgerError>? {
        switch state {
        case .poweredOn: .success(Data())
        case .poweredOff: .failure(.transport("Bluetooth is off. Turn it on in Control Center"))
        case .unauthorized: .failure(.transport("Bluetooth access is off for Winnow. Turn it on in Settings"))
        case .unsupported: .failure(.transport("this device has no Bluetooth Low Energy"))
        default: nil
        }
    }

    /// Routes one notification to the step in flight: the frame-size reply
    /// while asking for it, reassembled APDU replies while awaiting one, and
    /// nothing otherwise. Returns nil while the step is still waiting.
    struct NotificationRouter {
        var reassembler = LedgerBluetoothFraming.Reassembler()

        mutating func receive(_ value: Data, during step: Step?) -> Result<Data, any Error>? {
            switch step {
            case .frameSize:
                return LedgerBluetoothFraming.frameSize(fromMTUResponse: value) == nil ? nil : .success(value)
            case .reply:
                do {
                    return try reassembler.receive(value).map { .success($0) }
                } catch {
                    return .failure(error)
                }
            default:
                return nil
            }
        }
    }

    private let queue = DispatchQueue(label: "winnow.ledger-bluetooth")
    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var writer: CBCharacteristic?
    private var notifier: CBCharacteristic?
    private var frameSize = LedgerBluetoothFraming.defaultFrameSize
    private var router = NotificationRouter()

    private var waiting: Step?
    private var pending: CheckedContinuation<Data, any Error>?
    private var deadline: DispatchWorkItem?

    func open() async throws {
        try await perform(.poweredOn, timeout: 15) {
            self.central = CBCentralManager(delegate: self, queue: self.queue)
        }
        try await perform(.connected, timeout: 45) {
            guard let central = self.central else { return }
            if let known = central.retrieveConnectedPeripherals(withServices: Self.serviceUUIDs).first {
                self.attach(known)
            } else {
                central.scanForPeripherals(withServices: Self.serviceUUIDs)
            }
        }
        try await perform(.characteristics, timeout: 20) {
            self.peripheral?.discoverServices(Self.serviceUUIDs)
        }
        // Subscribing reaches an encrypted characteristic, which is when iOS
        // asks to pair: give the user time to compare the codes.
        try await perform(.notifying, timeout: 90) {
            guard let notifier = self.notifier else { return }
            self.peripheral?.setNotifyValue(true, for: notifier)
        }
        let reply = try await perform(.frameSize, timeout: 15) {
            self.write(LedgerBluetoothFraming.mtuRequest)
        }
        if let size = LedgerBluetoothFraming.frameSize(fromMTUResponse: reply) {
            queue.sync { self.frameSize = size }
        }
    }

    func close() async {
        queue.async {
            self.fail(LedgerError.transport("the connection was closed"))
            if let peripheral = self.peripheral { self.central?.cancelPeripheralConnection(peripheral) }
            self.central?.stopScan()
            self.peripheral = nil
        }
    }

    func exchange(_ apdu: Data) async throws -> Data {
        let size = queue.sync { () -> Int in
            let limit = peripheral?.maximumWriteValueLength(for: .withResponse) ?? frameSize
            return min(frameSize, limit)
        }
        let frames = try LedgerBluetoothFraming.frames(for: apdu, frameSize: size)
        for frame in frames.dropLast() {
            try await perform(.written, timeout: 15) { self.write(frame) }
        }
        // The reply can wait for the user to review and approve on the Ledger.
        return try await perform(.reply, timeout: 600) {
            self.router = NotificationRouter()
            self.write(frames[frames.count - 1])
        }
    }

    // MARK: - One step at a time

    @discardableResult
    private func perform(_ step: Step, timeout: TimeInterval, start: @escaping @Sendable () -> Void) async throws -> Data {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, any Error>) in
                queue.async {
                    guard self.pending == nil else {
                        continuation.resume(throwing: LedgerError.transport("another Ledger request is still running"))
                        return
                    }
                    self.pending = continuation
                    self.waiting = step
                    // Cancelled as soon as the step ends, so it holds the
                    // transport only while a step is in flight.
                    let deadline = DispatchWorkItem {
                        self.fail(LedgerError.transport("the Ledger did not answer in time"))
                    }
                    self.deadline = deadline
                    self.queue.asyncAfter(deadline: .now() + timeout, execute: deadline)
                    start()
                }
            }
        } onCancel: {
            queue.async { self.fail(CancellationError()) }
        }
    }

    /// On the queue: ends the step in flight, if any.
    private func finish(_ result: Result<Data, any Error>) {
        guard let pending else { return }
        self.pending = nil
        waiting = nil
        deadline?.cancel()
        deadline = nil
        pending.resume(with: result)
    }

    private func fail(_ error: any Error) { finish(.failure(error)) }

    private func attach(_ found: CBPeripheral) {
        peripheral = found
        found.delegate = self
        central?.connect(found)
    }

    private func write(_ frame: Data) {
        guard let peripheral, let writer else {
            fail(LedgerError.transport("the Ledger is not connected"))
            return
        }
        peripheral.writeValue(frame, for: writer, type: .withResponse)
    }
}

extension LedgerBluetoothTransport: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard waiting == .poweredOn, let outcome = Self.readiness(for: central.state) else { return }
        finish(outcome.mapError { $0 as any Error })
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData _: [String: Any], rssi _: NSNumber) {
        guard waiting == .connected, self.peripheral == nil else { return }
        central.stopScan()
        attach(peripheral)
    }

    func centralManager(_: CBCentralManager, didConnect _: CBPeripheral) {
        if waiting == .connected { finish(.success(Data())) }
    }

    func centralManager(_: CBCentralManager, didFailToConnect _: CBPeripheral, error _: (any Error)?) {
        fail(LedgerError.transport("the Ledger refused the connection"))
    }

    func centralManager(_: CBCentralManager, didDisconnectPeripheral _: CBPeripheral, error _: (any Error)?) {
        peripheral = nil
        writer = nil
        notifier = nil
        fail(LedgerError.transport("the Ledger disconnected"))
    }
}

extension LedgerBluetoothTransport: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        guard waiting == .characteristics else { return }
        guard error == nil, let service = peripheral.services?.first(where: { Self.serviceUUIDs.contains($0.uuid) }) else {
            fail(LedgerError.transport("the device offers no Ledger service"))
            return
        }
        peripheral.discoverCharacteristics(nil, for: service)
    }

    func peripheral(_: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: (any Error)?) {
        guard waiting == .characteristics else { return }
        let characteristics = service.characteristics ?? []
        notifier = characteristics.first { $0.uuid == Self.characteristic("0001", of: service.uuid) }
        writer = characteristics.first { $0.uuid == Self.characteristic("0002", of: service.uuid) }
        guard error == nil, notifier != nil, writer != nil else {
            fail(LedgerError.transport("the Ledger service is missing its characteristics"))
            return
        }
        finish(.success(Data()))
    }

    func peripheral(_: CBPeripheral, didUpdateNotificationStateFor _: CBCharacteristic, error: (any Error)?) {
        guard waiting == .notifying else { return }
        if error != nil {
            fail(LedgerError.transport("pairing with the Ledger did not complete"))
        } else {
            finish(.success(Data()))
        }
    }

    func peripheral(_: CBPeripheral, didWriteValueFor _: CBCharacteristic, error: (any Error)?) {
        if error != nil {
            fail(LedgerError.transport("a write to the Ledger failed"))
        } else if waiting == .written {
            finish(.success(Data()))
        }
    }

    func peripheral(_: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: (any Error)?) {
        guard error == nil, let value = characteristic.value, let outcome = router.receive(value, during: waiting) else {
            return
        }
        finish(outcome)
    }
}
