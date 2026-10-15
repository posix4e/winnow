import Testing
@testable import VaultKit

/// The card half of the hostile-input bounds: a pasted card and a name have a
/// ceiling. The file, peer and excerpt bounds are in WalletCore's
/// `HostileInputBoundsTests`.
@Suite("Card input bounds")
struct CardBoundsTests {
    @Test("a card past the byte ceiling is not a card")
    func oversizedCardRefused() throws {
        let card = PersonCard(network: .signet, name: String(repeating: "n", count: WinnowCardCoding.maximumBytes),
                              payTo: nil, signerKey: nil)
        #expect(throws: PersonCardError.notACard) { try PersonCard.decode(try card.serialized()) }
        let small = PersonCard(network: .signet, name: "Ada", payTo: nil, signerKey: nil)
        #expect(try PersonCard.decode(try small.serialized()).name == "Ada")
    }

    @Test("a display name is short, single-line and free of control characters")
    func displayNameBounds() {
        #expect(DisplayName.normalized("  Ada Lovelace ") == "Ada Lovelace")
        #expect(DisplayName.normalized("") == nil)
        #expect(DisplayName.normalized("   ") == nil)
        #expect(DisplayName.normalized("Ada\nsend to bc1q…") == nil)
        #expect(DisplayName.normalized("Ada\u{7}") == nil)
        #expect(DisplayName.normalized(String(repeating: "a", count: DisplayName.maximumLength)) != nil)
        #expect(DisplayName.normalized(String(repeating: "a", count: DisplayName.maximumLength + 1)) == nil)
    }

    @Test("a card's over-long name is dropped rather than stored")
    func cardNameNormalized() throws {
        let long = PersonCard(network: .signet, name: String(repeating: "a", count: DisplayName.maximumLength + 1),
                              payTo: nil, signerKey: nil)
        #expect(try PersonPaste.parse(long.serialized(), network: .signet).name == nil)
    }
}
