import BitcoinCore
import Foundation
import Testing

@Suite("Canonical multi_a parser")
struct MultisigCanonicalShapeTests {
    @Test(arguments: [1, 2, 16, 17, 128, 999])
    func builderRoundTrips(threshold: Int) throws {
        let keys = (0..<max(2, threshold)).map { index in Data(repeating: UInt8(index % 255 + 1), count: 32) }
        let script = try Multisig.script(threshold: threshold, xonlyKeys: keys, sorted: false)
        let parsed = try #require(Multisig.parse(script))
        #expect(parsed.threshold == threshold)
        #expect(parsed.keys == keys)
    }

    @Test(arguments: [
        Data([0x01, 0x00, 0x9c]), // Noncanonical zero threshold.
        Data([0x01, 0x01, 0x9c]), // One must be encoded with OP_1.
        Data([0x53, 0x9c]), // Three signatures cannot come from two keys.
        Data([0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x9c]), // Overlong script number.
    ])
    func rejectsMalformedTrailer(trailer: Data) throws {
        let keys = [Data(repeating: 0x11, count: 32), Data(repeating: 0x22, count: 32)]
        let canonical = try Multisig.script(threshold: 1, xonlyKeys: keys, sorted: false)
        let prefix = Data(canonical.bytes.dropLast(2))
        #expect(Multisig.parse(Script(prefix + trailer)) == nil)
    }
}
