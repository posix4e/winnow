import BitcoinCore
import BitcoinP2P
import Foundation
@testable import WalletCore

/// Test doubles shared across WalletCoreTests.

enum VectorError: Error {
    case missingFile(String)
    case badHex(String)
    case malformed(String)
}

func vectorData(_ name: String) throws -> Data {
    guard let url = Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Vectors") else {
        throw VectorError.missingFile(name)
    }
    return try Data(contentsOf: url)
}

/// The well-known BIP39 all-"abandon" mnemonic's 16-byte entropy.
let testEntropy = Data(repeating: 0, count: 16)
/// …and its mnemonic sentence.
let testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func testMaster(network _: BitcoinNetwork = .signet) throws -> HDKey {
    try HDKey(seed: BIP39.seed(mnemonic: testMnemonic))
}

/// A no-PoW block header — `Wallet.apply` trusts the FilterSync match, so
/// fixtures don't need mining.
func fakeHeader(previousHash: Data = Data(repeating: 0, count: 32), time: UInt32 = 1_700_000_000) -> BlockHeader {
    BlockHeader(version: 2, previousHash: previousHash, merkleRoot: Data(repeating: 0xAA, count: 32),
                time: time, bits: 0x207F_FFFF, nonce: 0)
}

/// A coinbase-like input (never our spend).
func coinbaseInput() -> Transaction.Input {
    Transaction.Input(previousOutput: Transaction.Outpoint(txid: Data(repeating: 0, count: 32),
                                                           vout: 0xFFFF_FFFF),
                      scriptSig: Data([0x01]), sequence: 0xFFFF_FFFF)
}

/// After applying a coinbase at `height`, record a scan frontier that makes it
/// consensus-mature (`Wallet.coinbaseMaturity` confirmations).
func matureCoinbase(_ wallet: Wallet, height: UInt32) async throws {
    try await wallet.recordScanHeight(height + Wallet.coinbaseMaturity)
}

/// A match carrying `transactions` at `height`, wrapped in a fake block.
func fakeMatch(height: UInt32, transactions: [Transaction]) -> BlockMatch {
    let block = Block(header: fakeHeader(time: 1_700_000_000 + height), transactions: transactions)
    return BlockMatch(height: height, blockHash: block.hash, block: block)
}

/// Temporary file URL that is removed on test teardown best-effort.
func tempFileURL(_ name: String) -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("winnow-walletcore-tests-\(UUID().uuidString)")
        .appendingPathComponent(name)
    try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                             withIntermediateDirectories: true)
    return url
}

/// A plausible validated tip for tests that build a send.
///
/// Paired with a fixed draw of 0.5 at the call sites, which misses the
/// one-in-ten lookback branch, so the resulting locktime is exactly this and
/// the transaction is byte-stable across runs. Tests that care about the
/// locktime itself live in "Anti-fee-sniping locktime"; everything else just
/// needs sends to look like real ones (#139).
let testChainTip: UInt32 = 840_000
