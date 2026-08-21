@testable import WinnowApp
import WalletCore
import XCTest

/// Peer, explorer and tweak-index settings must not cross a network switch
/// (epic #100, invariant S6; bug #81).
///
/// Keys and money were already separated — storage is under `root/<network>/`
/// and derivation is SLIP-44 correct — so no signet key can produce a mainnet
/// address. What leaked was three settings, and each fails in its own way.
/// Manual peers are dialed *first*, so a signet node left configured spends a
/// mainnet pool's opening attempts on a peer that will reject the handshake;
/// that is the "sync looks broken" the bug was reported as. A signet explorer
/// or tweak index is quieter and worse in kind: it answers mainnet queries
/// with confidently wrong data.
@MainActor
final class NetworkScopedSettingsTests: XCTestCase {
    private var defaults: UserDefaults!
    private var suiteName: String!

    override func setUp() {
        super.setUp()
        suiteName = "winnow-network-scope-\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suiteName)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suiteName)
        defaults = nil
        super.tearDown()
    }

    private typealias Key = AppModel.DefaultsKey

    // MARK: - Isolation

    /// The property the bug is about: what one network stores, another must
    /// not see.
    func testSettingsDoNotCrossBetweenNetworks() {
        defaults.set(["127.0.0.1:38333"], forKey: Key.manualPeers(.signet))
        defaults.set("https://signet.example/api", forKey: Key.esploraURL(.signet))
        defaults.set("https://signet.example/tweaks", forKey: Key.spIndexURL(.signet))

        let signet = AppModel.networkScopedSettings(defaults: defaults, network: .signet)
        XCTAssertEqual(signet.manualPeers, ["127.0.0.1:38333"])
        XCTAssertEqual(signet.esploraURL, "https://signet.example/api")
        XCTAssertEqual(signet.spIndexURL, "https://signet.example/tweaks")

        let mainnet = AppModel.networkScopedSettings(defaults: defaults, network: .mainnet)
        XCTAssertEqual(mainnet.manualPeers, [], "a signet peer must not be dialed on mainnet")
        XCTAssertEqual(mainnet.esploraURL, "", "a signet explorer must not answer mainnet queries")
        XCTAssertEqual(mainnet.spIndexURL, "", "a signet tweak index must not drive mainnet recovery")
    }

    /// Each network keeps its own value rather than the last one written
    /// winning.
    func testEachNetworkKeepsItsOwnValues() {
        defaults.set(["10.0.0.1:38333"], forKey: Key.manualPeers(.signet))
        defaults.set(["10.0.0.2:8333"], forKey: Key.manualPeers(.mainnet))

        XCTAssertEqual(AppModel.networkScopedSettings(defaults: defaults, network: .signet).manualPeers,
                       ["10.0.0.1:38333"])
        XCTAssertEqual(AppModel.networkScopedSettings(defaults: defaults, network: .mainnet).manualPeers,
                       ["10.0.0.2:8333"])
    }

    /// The keys themselves must differ; if they collided, every assertion
    /// above would pass for the wrong reason.
    func testScopedKeysDifferPerNetwork() {
        XCTAssertNotEqual(Key.manualPeers(.signet), Key.manualPeers(.mainnet))
        XCTAssertNotEqual(Key.esploraURL(.signet), Key.esploraURL(.mainnet))
        XCTAssertNotEqual(Key.spIndexURL(.signet), Key.spIndexURL(.mainnet))
    }

    // MARK: - Migration of existing installs

    /// An install that predates the fix has flat keys. They belong to whatever
    /// chain the user was on, and must survive the upgrade rather than being
    /// silently dropped.
    func testLegacySettingsMigrateIntoTheActiveNetwork() {
        defaults.set(["127.0.0.1:38333"], forKey: Key.legacyManualPeers)
        defaults.set("https://old.example/api", forKey: Key.legacyEsploraURL)
        defaults.set("https://old.example/tweaks", forKey: Key.legacySpIndexURL)

        AppModel.migrateLegacyNetworkSettings(defaults: defaults, into: .signet)

        let signet = AppModel.networkScopedSettings(defaults: defaults, network: .signet)
        XCTAssertEqual(signet.manualPeers, ["127.0.0.1:38333"])
        XCTAssertEqual(signet.esploraURL, "https://old.example/api")
        XCTAssertEqual(signet.spIndexURL, "https://old.example/tweaks")

        // And they must not appear on the other network.
        let mainnet = AppModel.networkScopedSettings(defaults: defaults, network: .mainnet)
        XCTAssertEqual(mainnet.manualPeers, [])
        XCTAssertEqual(mainnet.esploraURL, "")
    }

    /// The flat keys are removed, so the migration runs once and a later
    /// switch cannot pick them up again.
    func testMigrationRemovesTheLegacyKeys() {
        defaults.set(["127.0.0.1:38333"], forKey: Key.legacyManualPeers)
        defaults.set("https://old.example/api", forKey: Key.legacyEsploraURL)
        defaults.set("https://old.example/tweaks", forKey: Key.legacySpIndexURL)

        AppModel.migrateLegacyNetworkSettings(defaults: defaults, into: .signet)

        XCTAssertNil(defaults.stringArray(forKey: Key.legacyManualPeers))
        XCTAssertNil(defaults.string(forKey: Key.legacyEsploraURL))
        XCTAssertNil(defaults.string(forKey: Key.legacySpIndexURL))
    }

    /// Migrating must not overwrite a value the user has already set under the
    /// new scheme.
    func testMigrationDoesNotClobberExistingScopedValues() {
        defaults.set(["10.0.0.9:38333"], forKey: Key.manualPeers(.signet))
        defaults.set(["127.0.0.1:38333"], forKey: Key.legacyManualPeers)

        AppModel.migrateLegacyNetworkSettings(defaults: defaults, into: .signet)

        XCTAssertEqual(AppModel.networkScopedSettings(defaults: defaults, network: .signet).manualPeers,
                       ["10.0.0.9:38333"])
        XCTAssertNil(defaults.stringArray(forKey: Key.legacyManualPeers))
    }

    /// Running twice is harmless.
    func testMigrationIsIdempotent() {
        defaults.set(["127.0.0.1:38333"], forKey: Key.legacyManualPeers)
        AppModel.migrateLegacyNetworkSettings(defaults: defaults, into: .signet)
        AppModel.migrateLegacyNetworkSettings(defaults: defaults, into: .mainnet)

        XCTAssertEqual(AppModel.networkScopedSettings(defaults: defaults, network: .signet).manualPeers,
                       ["127.0.0.1:38333"])
        XCTAssertEqual(AppModel.networkScopedSettings(defaults: defaults, network: .mainnet).manualPeers,
                       [], "a second run must not re-attribute settings to another chain")
    }

    /// A clean install has nothing to migrate and nothing appears.
    func testNothingToMigrateLeavesEverythingEmpty() {
        AppModel.migrateLegacyNetworkSettings(defaults: defaults, into: .mainnet)
        let mainnet = AppModel.networkScopedSettings(defaults: defaults, network: .mainnet)
        XCTAssertEqual(mainnet.manualPeers, [])
        XCTAssertEqual(mainnet.esploraURL, "")
        XCTAssertEqual(mainnet.spIndexURL, "")
    }
}
