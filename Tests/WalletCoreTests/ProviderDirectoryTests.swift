import BitcoinP2P
import BlockchainBackend
import Foundation
import Testing
@testable import WalletCore

/// The provider list is curated, not discovered, so every entry must carry
/// what a reader needs to judge it.
@Suite("Provider directory")
struct ProviderDirectoryTests {
    @Test("every entry is sourced, statused with the paper's words, and scoped to a network")
    func entriesAreComplete() {
        #expect(!ProviderDirectory.entries.isEmpty)
        for entry in ProviderDirectory.entries {
            #expect(!entry.name.isEmpty)
            #expect(!entry.evidence.isEmpty, "\(entry.id) needs an evidence sentence")
            #expect(!entry.disclosure.isEmpty, "\(entry.id) needs disclosure copy")
            #expect(entry.documentationURL.scheme == "https", "\(entry.id) documentation must be https")
            #expect(!entry.networks.isEmpty, "\(entry.id) must name at least one network")
            #expect(ProviderEntry.Status.allCases.contains(entry.status))
        }
        let ids = ProviderDirectory.entries.map(\.id)
        #expect(Set(ids).count == ids.count, "provider ids are unique")
    }

    @Test("Slipstream is mainnet-only and a node is any network")
    func networkScoping() throws {
        let slipstream = try #require(ProviderDirectory.entry(.slipstream))
        #expect(slipstream.networks == [.mainnet])
        #expect(!slipstream.supports(.signet))
        let node = try #require(ProviderDirectory.entry(.coreRPC))
        #expect(node.supports(.signet) && node.supports(.mainnet))
        #expect(node.defaultBaseURL == nil, "the user names their own node")
        #expect(ProviderDirectory.entries(for: .signet).map(\.id) == [.coreRPC])
    }

    @Test("no adapter exists yet, so nothing claims more than planned")
    func nothingClaimsImplemented() {
        for entry in ProviderDirectory.entries {
            #expect(entry.status == .planned, "\(entry.id): flip this only with a tested adapter")
        }
    }
}
