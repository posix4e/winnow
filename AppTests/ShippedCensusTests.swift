import WalletCore
import XCTest

/// The census list this build bundles (project.yml, from scripts/import-census)
/// passes the floor the wallet applies and still carries the overlays that
/// Tor- and I2P-only routing draw from.
final class ShippedCensusTests: XCTestCase {
    func testTheShippedListIsAUsableCensus() throws {
        let shipped = try XCTUnwrap(CensusCatalog.bundled, "run scripts/import-census before XcodeGen")
        XCTAssertGreaterThanOrEqual(shipped.networks["clearnet"]?.count ?? 0, CensusCatalog.minimumClearnetEntries)
        XCTAssertFalse(shipped.networks["tor", default: []].isEmpty)
        XCTAssertFalse(shipped.networks["i2p", default: []].isEmpty)
    }
}
