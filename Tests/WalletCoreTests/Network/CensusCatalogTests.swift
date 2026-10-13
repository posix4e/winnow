import Foundation
import Testing
@testable import WalletCore

struct CensusCatalogTests {
    /// The published shape: the census also lists `tor` and `i2p` nodes,
    /// which are retained for use with configured gateways.
    func catalog(_ date: String = "2026-09-13") -> CensusCatalog {
        .init(date: date, tip: 900_000, networks: [
            "clearnet": [.init(host: "8.8.8.8", port: 8333, userAgent: "/Satoshi:30/", startHeight: 900_100)],
            "tor": [.init(host: "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion", port: 8333,
                          userAgent: "/Satoshi:30/", startHeight: 899_900)],
            "i2p": [],
        ])
    }
    /// A list's date says when it was observed; no clock ages it out.
    @Test func datesAndSchema() throws {
        _ = try catalog().validated()
        _ = try catalog("2026-01-01").validated()
        #expect(throws: CensusCatalog.Invalid.date) { try catalog("2026-02-30").validated() }
        var c = catalog(); c.schemaVersion = 2
        #expect(throws: CensusCatalog.Invalid.schema) { try c.validated() }
        c = catalog(); c.networks["clearnet"] = nil
        #expect(throws: CensusCatalog.Invalid.schema) { try c.validated() }
        #expect(CensusCatalog.day("0000-01-01") == nil)
        #expect(throws: CensusCatalog.Invalid.size) { try CensusCatalog.decode(Data(repeating: 0, count: CensusCatalog.maximumBytes + 1)) }
    }
    @Test func aThinListAndMalformedOverlayEntriesAreRefused() throws {
        let validated = try catalog().validated()
        #expect(validated.networks.keys.sorted() == ["clearnet", "i2p", "tor"])
        #expect(throws: CensusCatalog.Invalid.thin) { try catalog().validated(minimumEntries: 2) }
        var c = catalog()
        c.networks["tor"] = [.init(host: "not an onion", port: 0, userAgent: "", startHeight: -1)]
        #expect(throws: CensusCatalog.Invalid.endpoint) { try c.validated(minimumEntries: 1) }
    }
    /// Overlay lists are not capped: a census with thousands of Tor and I2P
    /// peers is kept whole, and only the bound every list has refuses one.
    @Test func largeOverlayListsAreKeptWhole() throws {
        func name(_ index: Int, length: Int) -> String {
            let alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")
            var value = index
            return String((0..<length).map { _ in defer { value /= 32 }; return alphabet[value % 32] })
        }
        func entries(_ count: Int, _ suffix: String, length: Int) -> [CensusCatalog.Entry] {
            (0..<count).map { .init(host: name($0, length: length) + suffix, port: 8333,
                                    userAgent: "/Satoshi:30/", startHeight: 899_900) }
        }
        var c = catalog()
        c.networks["tor"] = entries(5_000, ".onion", length: 56)
        c.networks["i2p"] = entries(3_000, ".b32.i2p", length: 52)
        let validated = try c.validated()
        #expect(validated.networks["tor"]?.count == 5_000)
        #expect(validated.networks["i2p"]?.count == 3_000)
        c.networks["tor"] = entries(CensusCatalog.maximumEntries + 1, ".onion", length: 56)
        #expect(throws: CensusCatalog.Invalid.size) { try c.validated() }
    }
    @Test func extremeHeightsAndAliases() throws {
        #expect(!CensusCatalog.nearTip(.min, tip: .max))
        #expect(!CensusCatalog.nearTip(.max, tip: .min))
        #expect(!CensusCatalog.nearTip(900_101, tip: 900_000))
        #expect(CensusCatalog.canonicalHost("::ffff:8.8.8.8") == "8.8.8.8")
        #expect(CensusCatalog.canonicalHost("2606:4700:0000:0000:0000:0000:0000:1111") == "2606:4700::1111")
        var c = catalog()
        c.networks["clearnet"]!.append(.init(host: "::ffff:8.8.8.8", port: 8333, userAgent: "", startHeight: 900_000))
        #expect(throws: CensusCatalog.Invalid.duplicate) { try c.validated() }
        c.networks["clearnet"]![1].host = "8.8.4.4"
        #expect(throws: CensusCatalog.Invalid.diversity) { try c.validated() }
    }
    @Test func addressPolicies() {
        for host in ["127.0.0.1", "::ffff:127.0.0.1", "example.com", "192.0.2.1", "198.18.1.1",
                     "100.64.1.1", "2001:db8::1", "fe80::1", "fc00::1", "2002:0808:0808::1", "3fff::1",
                     "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion", "name.b32.i2p"] {
            #expect(CensusCatalog.canonicalHost(host) == nil)
        }
        var c = catalog()
        c.networks["clearnet"]![0].host = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
        #expect(throws: CensusCatalog.Invalid.endpoint) { try c.validated() }
    }
}
