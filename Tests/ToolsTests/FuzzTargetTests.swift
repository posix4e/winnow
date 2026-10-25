import Foundation
import Testing
import WinnowFuzzCore

/// Each fuzz target's check runs under `swift test` too, not only in fuzz
/// campaigns: every target on small inputs.
@Suite("Fuzz targets")
struct FuzzTargetTests {
    @Test("every target takes empty and arbitrary input without a finding", arguments: FuzzTarget.allCases)
    func everyTarget(_ target: FuzzTarget) throws {
        var rng = SplitMix64(state: 7)
        for input in [Data(), Data([0x00]), Data(repeating: 0xFF, count: 64), Data("tr(".utf8)] {
            try exercise(target, data: input, rng: &rng)
        }
    }
}
