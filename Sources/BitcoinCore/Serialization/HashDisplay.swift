import Foundation

extension Data {
    /// Interprets a display-order (big-endian) hex hash as internal byte order.
    package init(displayHex: String) {
        var bytes = Data()
        bytes.reserveCapacity(displayHex.count / 2)
        var index = displayHex.startIndex
        while index < displayHex.endIndex {
            let next = displayHex.index(index, offsetBy: 2)
            bytes.append(UInt8(displayHex[index ..< next], radix: 16)!)
            index = next
        }
        self.init(bytes.reversed())
    }

    /// Internal-order hash rendered as display-order hex.
    public var displayHex: String {
        reversed().map { String(format: "%02x", $0) }.joined()
    }
}
