import Foundation
import Testing
@testable import BitcoinCore

/// Bounds on hostile descriptor text (epic #100, invariants S7 and S10).
///
/// Descriptors arrive from places the wallet does not control: a string pasted
/// into vault creation, an imported bundle, and — most importantly — persisted
/// vault records, which are parsed while the app is starting up.
///
/// The descriptor parser is recursive descent. Before the depth bound, a tap
/// tree nested about a thousand levels deep exhausted the stack and terminated
/// the process with a signal rather than an error. That failure mode is worse
/// than a rejected descriptor in a specific way: stack exhaustion is not a
/// Swift error, so none of the fail-closed damaged-storage handling can
/// intercept it, and a hostile record would take the app down at every launch.
@Suite("Descriptor input bounds")
struct DescriptorBoundsTests {
    static let key = "xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa"
    static let nums = Taproot.unspendableInternalKey.hex

    /// `{pk, {pk, {pk, …}}}` nested `depth` levels.
    static func nested(depth: Int) -> String {
        var inner = "pk(\(key))"
        for _ in 0 ..< depth { inner = "{\(inner),pk(\(key))}" }
        return "tr(\(nums),\(inner))"
    }

    /// A tree at the BIP341 maximum is legitimate and must still parse.
    /// Without this control, the refusals below could be explained by the
    /// parser rejecting all nesting.
    @Test("a tree at the BIP341 maximum depth parses")
    func maximumDepthAccepted() throws {
        let descriptor = try Descriptor(Self.nested(depth: 128))
        #expect(descriptor.serialized().hasPrefix("tr("))
    }

    /// One level past the consensus maximum is refused. A deeper tree can
    /// never produce a valid control block, so accepting it would only ever
    /// create an unspendable output.
    @Test("a tree one level past the maximum is refused")
    func justOverMaximumRefused() {
        #expect(throws: DescriptorError.treeTooDeep) {
            _ = try Descriptor(Self.nested(depth: 129))
        }
    }

    /// The depth that used to terminate the process. This is the regression
    /// test for the crash: it must now return an error rather than take the
    /// test runner down with it.
    @Test("a tree deep enough to exhaust the stack is refused, not fatal")
    func stackExhaustingDepthRefused() {
        #expect(throws: DescriptorError.treeTooDeep) {
            _ = try Descriptor(Self.nested(depth: 1_000))
        }
    }

    /// Far beyond any plausible input, to show the bound is checked before
    /// recursion rather than after it.
    @Test("an absurdly deep tree is refused promptly", arguments: [5_000, 50_000])
    func absurdDepthRefused(_ depth: Int) {
        #expect(throws: DescriptorError.treeTooDeep) {
            _ = try Descriptor(Self.nested(depth: depth))
        }
    }

    /// Unbalanced nesting fails as a parse error rather than running off the
    /// end of the input.
    @Test("unbalanced nesting is refused")
    func unbalancedNestingRefused() {
        #expect(throws: (any Error).self) {
            _ = try Descriptor("tr(\(Self.nums),\(String(repeating: "{", count: 64))pk(\(Self.key)))")
        }
    }

    /// Ordinary descriptors are unaffected.
    @Test("a shallow descriptor still parses")
    func shallowDescriptorUnaffected() throws {
        let descriptor = try Descriptor(Self.nested(depth: 2))
        #expect(descriptor.serialized().hasPrefix("tr("))
    }
}
