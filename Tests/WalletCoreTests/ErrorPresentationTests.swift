import Foundation
import Security
import Testing
@testable import WalletCore

@Suite("Recovery and signing error presentation")
struct ErrorPresentationTests {
    @Test("wallet refusals preserve key privacy and explain how to proceed")
    func walletRefusals() throws {
        let secret = "xprv-private-descriptor-must-stay-off-screen"
        let cases: [(WalletError, String)] = [
            (.invalidDescriptor(secret), "not repeated"),
            (.descriptorMismatch, "mnemonic"), (.accountKeyMismatch, "does not match"),
            (.mnemonicUnavailable, "no recovery phrase"), (.noPayments, "Nothing to send"),
            (.changeOutputMissing, "change output"),
            (.transactionTooLarge(vsize: 100_001, limit: 100_000), "100001"),
            (.exportWhilePending, "Wait for pending"),
            (.invalidTransactionAmounts, "state was not changed"),
            (.invalidBundle("wrong network"), "wrong network"),
            (.unsupportedWalletData, "Keep the original wallet file"),
            (.storageTooLarge(maxBytes: 2_097_152), "2 MB")
        ]
        for (error, guidance) in cases {
            let message = try #require(error.errorDescription)
            #expect(message.localizedCaseInsensitiveContains(guidance))
            #expect(!message.contains(secret))
        }
    }

    @Test("keychain cancellation, lockout and unsupported formats remain distinct and redact secrets")
    func protectedKeyRefusals() throws {
        let cases: [(KeyStoreError, String)] = [
            (.notFound(walletID: "fixture-wallet"), "missing"),
            (.alreadyExists(walletID: "fixture-wallet"), "already contains"),
            (.malformedSecret, "damaged"),
            (.unsupportedSecretVersion("account/2\nxprv-keep-private"), "compatible wallet software"),
            (.keychain(errSecUserCanceled), "cancelled"),
            (.keychain(errSecAuthFailed), "stays locked"),
            (.keychain(errSecInteractionNotAllowed), "on screen"),
            (.keychain(errSecParam), "protected wallet key")
        ]
        for (error, guidance) in cases {
            let message = try #require(error.errorDescription)
            #expect(message.contains(guidance))
            #expect(!message.contains("xprv-keep-private"))
        }
    }

    @Test("scan refusals distinguish resumable budgets from damaged records and unsafe ranges")
    func scanRefusals() throws {
        let cases: [(RangeScanError, String)] = [
            (.invalidRange(from: 12, to: 11), "12 to 11"),
            (.noWatchScripts, "at least one script"),
            (.rangeTooWide(blocks: 500, limit: 100), "100-block limit"),
            (.tooManyScripts(count: 20, limit: 10), "limit of 10"),
            (.tooManyIterations(count: 2, limit: 1), "1 time and asked for pass 2"),
            (.tooManyIterations(count: 3, limit: 2), "2 times and asked for pass 3"),
            (.filterBytesExhausted(read: 101, limit: 100), "can be resumed"),
            (.runTimedOut(limit: .seconds(10)), "can be resumed"),
            (.rangeBelowChain(from: 20, start: 30), "below block 30"),
            (.rangeAboveChain(to: 40, tip: 30), "tip 30"),
            (.rangeSpansNoCheckpoint(from: 10, to: 20), "Scan a wider range"),
            (.recordUnreadable, "payment is not skipped"),
            (.recordTooLarge(maxBytes: 99), "99 bytes"),
            (.recordDamaged("missing commitment"), "will not replace it automatically"),
            (.recordWriteFailed, "Nothing was recorded")
        ]
        for (error, guidance) in cases {
            #expect(try #require(error.errorDescription).contains(guidance))
        }
    }

    @Test("peer errors distinguish absent peers, temporary cooldown and uncorroborated scans")
    func peerRefusals() throws {
        let filters: [(FilterSyncError, String)] = [
            (.busy, "Finishing sync"), (.noPeers, "No Bitcoin peers"),
            (.relayOnly, "Resume syncing"),
            (.peersCoolingDown(1), "1 Bitcoin peer is"),
            (.peersCoolingDown(2), "2 Bitcoin peers are"),
            (.checkpointMismatch("fixture checkpoint"), "fixture checkpoint"),
            (.badPeerResponse("fixture response"), "fixture response"),
            (.filterHeaderMismatch(height: 123), "block 123"),
            (.unexpectedBlockHash, "did not request"),
            (.crossCheckUnavailable("only one source"), "Nothing was scanned")
        ]
        for (error, guidance) in filters {
            #expect(try #require(error.errorDescription).contains(guidance))
        }
        let headers: [(PeerPoolHeaderSyncError, String)] = [
            (.noPeers, "No Bitcoin peers"), (.relayOnly, "Resume syncing"),
            (.exhausted(attempts: 1, lastError: "fixture timeout"), "1 Bitcoin peer,"),
            (.exhausted(attempts: 2, lastError: "fixture timeout"), "2 Bitcoin peers,"),
            (.allPeersCoolingDown(cooling: 1, lastError: "fixture timeout"), "1 Bitcoin peer was"),
            (.allPeersCoolingDown(cooling: 2, lastError: "fixture timeout"), "2 Bitcoin peers were")
        ]
        for (error, guidance) in headers {
            #expect(try #require(error.errorDescription).contains(guidance))
        }
    }
}
