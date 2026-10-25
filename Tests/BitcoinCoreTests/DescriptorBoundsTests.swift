import Foundation
import Testing
import TestSupport
@testable import WalletCore

/// Bounds on hostile descriptor text (epic #100, invariants S7 and S10).
///
/// Descriptors arrive from places the wallet does not control: a string pasted
/// as a person's key or a multisig account, an imported bundle, and persisted
/// account records, which are parsed while the app is starting up.
///
/// The tree parser is recursive descent. Before the depth bound (SEC-010), a
/// tap tree nested about a thousand levels deep exhausted the stack and
/// terminated the process with a signal rather than an error. Stack
/// exhaustion is not a Swift error, so no damaged-storage handling can
/// intercept it, and a hostile record would take the app down at every launch.
@Suite("Descriptor input bounds")
struct DescriptorBoundsTests {
    static let key = "xpub6FC1fXFP1GXQpyRFfSE1vzzySqs3Vg63bzimYLeqtNUYbzA87kMNTcuy9ubr7MmavGRjW2FRYHP4WGKjwutbf1ghgkUW9H7e3ceaPLRcVwa"
    static let nums = Taproot.unspendableInternalKey.hex

    /// `{{{pk,pk},pk},pk}` nested `depth` levels: `depth` opening braces,
    /// the innermost `pk`, then `depth` closing `,pk}`. Built in one pass so
    /// the 50,000-level fixture below is linear in `depth`, not quadratic.
    static func nested(depth: Int) -> String {
        let leaf = "pk(\(key))"
        let inner = String(repeating: "{", count: depth) + leaf
            + String(repeating: ",\(leaf)}", count: depth)
        return "tr(\(nums),\(inner))"
    }

    /// `tr([fp/0/0/...]KEY/<0;1>/*)` with `steps` origin steps: the wallet's
    /// own descriptor shape, so `Wallet.origin(of:)` and an import bundle both
    /// accept the text on every ground except its length.
    static func longOrigin(steps: Int) -> String {
        "tr([73c5da0a\(String(repeating: "/0", count: steps))]\(key)/<0;1>/*)"
    }

    /// A tree at the BIP341 maximum is legitimate and must still parse.
    /// Without this control, the refusals below could be explained by the
    /// parser rejecting all nesting.
    @Test("a tree at the BIP341 maximum depth parses")
    func maximumDepthAccepted() throws {
        let descriptor = try Descriptor(Self.nested(depth: 128))
        #expect(descriptor.serialized().hasPrefix("tr("))
    }

    /// One level past the consensus maximum is refused: a deeper tree can
    /// never produce a valid control block.
    @Test("a tree one level past the maximum is refused")
    func justOverMaximumRefused() {
        #expect(throws: DescriptorError.treeTooDeep) { _ = try Descriptor(Self.nested(depth: 129)) }
    }

    /// The depth that used to terminate the process now returns an error.
    @Test("a tree deep enough to exhaust the stack is refused, not fatal")
    func stackExhaustingDepthRefused() {
        #expect(throws: DescriptorError.treeTooDeep) { _ = try Descriptor(Self.nested(depth: 1_000)) }
    }

    /// Far beyond any plausible input, to show the bound is checked before
    /// recursion rather than after it.
    @Test("an absurdly deep tree is refused promptly", arguments: [5_000, 50_000])
    func absurdDepthRefused(_ depth: Int) {
        #expect(throws: DescriptorError.treeTooDeep) { _ = try Descriptor(Self.nested(depth: depth)) }
    }

    /// Unbalanced nesting fails as a parse error rather than running off the end.
    @Test("unbalanced nesting is refused")
    func unbalancedNestingRefused() {
        #expect(throws: (any Error).self) {
            _ = try Descriptor("tr(\(Self.nums),\(String(repeating: "{", count: 64))pk(\(Self.key)))")
        }
    }

    /// A `multi_a` leaf names at most 999 keys (BIP387); the parser stops
    /// counting there instead of collecting an unbounded list first.
    @Test("a multi_a leaf with more than 999 keys is refused")
    func tooManyLeafKeysRefused() {
        let keys = Array(repeating: Self.key, count: 1_000).joined(separator: ",")
        #expect(throws: DescriptorError.invalidThreshold) {
            _ = try Descriptor("tr(\(Self.nums),multi_a(1,\(keys)))")
        }
    }

    /// A key origin can name at most as many steps as a BIP32 key can be deep.
    /// A long origin parsed happily and terminated the process later, when
    /// signing walked the path (`depth` is a `UInt8` and `child(at:)` computed
    /// `depth + 1`). A hostile import bundle reached that: the descriptor
    /// parsed, the wallet was built, and the first attempt to sign took the
    /// app down. The refusal now lands at the parse, so `Wallet.importing`
    /// reports the parser's own error because the text never becomes a
    /// `Descriptor`.
    ///
    /// The boundary is pinned from both sides: the longest origin a key can
    /// actually have still parses, and the first step past it does not.
    /// Without the passing side the bound could refuse every origin and the
    /// refusal would still pass.
    @Test("an origin path at the maximum depth parses; one step past it is refused")
    func originPathBound() throws {
        let longest = try Descriptor(Self.longOrigin(steps: 255))
        #expect(try Wallet.origin(of: longest).path.count == 255)
        #expect(throws: DescriptorError.originTooDeep) {
            _ = try Descriptor(Self.longOrigin(steps: 256))
        }
        let bundle = ImportBundle(network: "signet", descriptor: Self.longOrigin(steps: 256),
                                  lastKnownHeight: 100)
        #expect(throws: DescriptorError.originTooDeep) {
            _ = try Wallet.importing(bundle, keyStore: InMemoryKeyStore())
        }
        // And an ordinary wallet origin is three steps, nowhere near it.
        #expect(try Wallet.origin(of: Descriptor(Self.longOrigin(steps: 3))).path.count == 3)
    }

    /// The serialized account key names its own depth, and no bound on the
    /// descriptor's text reaches it. Below the account key the wallet still
    /// derives the chain and the index, so a key at depth 254 parses, matches
    /// the wallet shape, and fails at its first address. The refusal belongs
    /// in `Wallet.origin(of:)`, which both `importing` and `open` run before
    /// trusting a file; otherwise a fresh watch-only import writes a wallet
    /// whose every derivation fails and which nothing rolls back.
    @Test("an account key too deep for the wallet's own derivation is refused before anything is written")
    func accountKeyDepthRefused() throws {
        let master = try testMaster()
        func text(depth: UInt8) -> String {
            let account = HDKey(depth: depth, parentFingerprint: master.fingerprint, childIndex: 0,
                                chainCode: master.chainCode, privateKey: nil, publicKey: master.publicKey)
            return "tr([73c5da0a/86'/1'/0']\(account.serialized(network: .testnet))/<0;1>/*)"
        }
        let deep = try Descriptor(text(depth: 254))
        #expect(throws: WalletError.self) { _ = try Wallet.origin(of: deep) }
        let storage = tempFileURL("deep-account.json")
        let bundle = ImportBundle(network: "signet", descriptor: text(depth: 254), lastKnownHeight: 100)
        #expect(throws: WalletError.self) {
            _ = try Wallet.importing(bundle, keyStore: InMemoryKeyStore(), storageURL: storage)
        }
        #expect(!FileManager.default.fileExists(atPath: storage.path), "a refused import must not persist")
        // Derivation through the descriptor itself names the depth rather
        // than reporting a tweak failure.
        #expect(throws: DescriptorError.keyDepthExhausted) { _ = try deep.derived(index: 0, network: .testnet) }

        // The control: the last depth with room for the chain and the index.
        let last = try Descriptor(text(depth: 253))
        #expect(try Wallet.origin(of: last).path.count == 3)
        #expect(try last.derived(index: 0, network: .testnet).count == 2)
    }
}
