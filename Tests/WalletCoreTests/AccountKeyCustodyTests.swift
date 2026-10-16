import Foundation
import P256K
import Testing
import TestSupport
@testable import WalletCore

@Suite("Account-key custody")
struct AccountKeyCustodyTests {
    private struct Pair {
        let root: Wallet
        let scoped: Wallet
        let rootStore: CountingKeyStore
        let scopedStore: CountingKeyStore
        let accountKey: HDKey
        let fingerprint: UInt32
    }

    private static func pair(network: BitcoinNetwork = .signet, account: UInt32 = 0,
                             entropy: Data = testEntropy, storage: URL? = nil) throws -> Pair {
        let rootStore = CountingKeyStore(), scopedStore = CountingKeyStore()
        let root = try Wallet.create(network: network, keyStore: rootStore, entropy: entropy, account: account)
        let master = try HDKey(seed: BIP39.seed(mnemonic: BIP39.mnemonic(entropy: entropy)))
        let key = try BIP86.accountKey(from: master, coinType: Wallet.coinType(for: network), account: account)
        let scoped = try Wallet.create(accountKey: key, masterFingerprint: master.fingerprint,
                                       network: network, keyStore: scopedStore, storageURL: storage,
                                       account: account)
        return Pair(root: root, scoped: scoped, rootStore: rootStore, scopedStore: scopedStore,
                    accountKey: key, fingerprint: master.fingerprint)
    }

    private static func prepare(_ wallet: Wallet) async throws -> Wallet.PreparedSend {
        try await wallet.buildSend(
            payments: [Payment(amount: 600_000, scriptPubKey: TestScripts.p2trDestination)],
            feeRateSatPerVByte: 2, chainTip: testChainTip, randomness: { 0.5 })
    }

    private static func fundForSend(_ wallet: Wallet) async throws {
        try await fund(wallet, amount: 500_000, height: 100)
        try await fund(wallet, amount: 250_000, height: 101, chain: .change, index: 9)
        try await matureCoinbase(wallet, height: 101)
    }

    private static func verify(_ prepared: Wallet.PreparedSend) throws {
        try verify(transaction: prepared.built.transaction, psbt: prepared.built.psbt)
    }

    private static func verify(transaction: Transaction, psbt: PSBT) throws {
        let outputs = try psbt.spentOutputs()
        #expect(transaction.inputs.count == 2)
        for index in transaction.inputs.indices {
            let hash = try SighashBIP341.sighash(tx: transaction, inputIndex: index,
                                                spentOutputs: outputs, hashType: .default)
            var message = [UInt8](hash)
            let key = P256K.Schnorr.XonlyKey(dataRepresentation: outputs[index].scriptPubKey.suffix(32))
            let signature = try P256K.Schnorr.SchnorrSignature(
                dataRepresentation: transaction.inputs[index].witness[0])
            #expect(key.isValid(signature, for: &message), "signature for input \(index)")
        }
    }

    @Test("account and root custody preserve addresses, spends and PSBT origins",
          arguments: [BitcoinNetwork.mainnet, .signet], [UInt32(0), 1, 5, 0x7fff_ffff])
    func equivalentCustody(network: BitcoinNetwork, account: UInt32) async throws {
        let pair = try Self.pair(network: network, account: account)
        let rootID = await pair.root.id, scopedID = await pair.scoped.id
        let rootDescriptor = await pair.root.descriptor.serialized()
        let scopedDescriptor = await pair.scoped.descriptor.serialized()
        let rootKey = await pair.root.accountKey, scopedKey = await pair.scoped.accountKey
        #expect(rootID == scopedID)
        #expect(rootDescriptor == scopedDescriptor)
        #expect(rootKey == scopedKey)
        for chain in [AddressChain.receive, .change] {
            for index in [UInt32(0), 1, 9, 21] {
                let rootAddress = try await pair.root.address(chain: chain, index: index)
                let scopedAddress = try await pair.scoped.address(chain: chain, index: index)
                #expect(rootAddress == scopedAddress)
            }
        }
        for wallet in [pair.root, pair.scoped] { try await Self.fundForSend(wallet) }
        let rootReads = pair.rootStore.loads, scopedReads = pair.scopedStore.loads
        let root = try await Self.prepare(pair.root), scoped = try await Self.prepare(pair.scoped)
        #expect(pair.rootStore.loads - rootReads == 1)
        #expect(pair.scopedStore.loads - scopedReads == 1)
        try Self.verify(root)
        try Self.verify(scoped)
        #expect(root.built.fee == scoped.built.fee)
        #expect(root.built.changeAmount == scoped.built.changeAmount)
        #expect(root.built.transaction.inputs.map(\.previousOutput)
            == scoped.built.transaction.inputs.map(\.previousOutput))
        #expect(root.built.transaction.locktime == scoped.built.transaction.locktime)
        // Witness randomness and the change output's random position may differ.
        #expect(root.built.transaction.outputs.sorted { $0.scriptPubKey.hex < $1.scriptPubKey.hex }
            == scoped.built.transaction.outputs.sorted { $0.scriptPubKey.hex < $1.scriptPubKey.hex })
        for (left, right) in zip(root.built.psbt.inputs, scoped.built.psbt.inputs) {
            #expect(left.tapInternalKey == right.tapInternalKey)
            #expect(left.tapBIP32Derivation == right.tapBIP32Derivation)
            let origin = try #require(right.tapBIP32Derivation.values.first)
            #expect(origin.masterFingerprint == pair.fingerprint)
            #expect(origin.path.prefix(3) == [86, Wallet.coinType(for: network), account]
                .map { $0 + HDKey.hardenedOffset }[...])
        }
        let rootChange = try #require(root.built.psbt.outputs.first { !$0.tapBIP32Derivation.isEmpty })
        let scopedChange = try #require(scoped.built.psbt.outputs.first { !$0.tapBIP32Derivation.isEmpty })
        #expect(rootChange.tapInternalKey == scopedChange.tapInternalKey)
        #expect(rootChange.tapBIP32Derivation == scopedChange.tapBIP32Derivation)
    }

    @Test("BIP86 account import keeps the published first mainnet address")
    func publishedAddress() async throws {
        let pair = try Self.pair(network: .mainnet)
        #expect(try await pair.scoped.address(chain: .receive, index: 0)
            == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
    }

    @Test("wrong account metadata, public keys and foreign root secrets cannot sign")
    func rejectMismatchedSecrets() async throws {
        let pair = try Self.pair(account: 5)
        try await Self.fundForSend(pair.scoped)
        let id = await pair.scoped.id
        let root = try testMaster()
        let foreignWords = try BIP39.mnemonic(entropy: Data(repeating: 0xab, count: 16))
        let foreignRoot = try HDKey(seed: BIP39.seed(mnemonic: foreignWords))
        let foreignAccount = try BIP86.accountKey(from: foreignRoot, coinType: 1, account: 5)
        let neighbour = try BIP86.accountKey(from: root, coinType: 1, account: 6)
        let xprv = pair.accountKey.serialized(network: .testnet)
        let invalid: [WalletSecret] = [
            .accountKey(xprv: xprv, masterFingerprint: pair.fingerprint ^ 1),
            .accountKey(xprv: root.serialized(network: .testnet), masterFingerprint: pair.fingerprint),
            .accountKey(xprv: pair.accountKey.neutered.serialized(network: .testnet), masterFingerprint: pair.fingerprint),
            .accountKey(xprv: neighbour.serialized(network: .testnet), masterFingerprint: pair.fingerprint),
            .accountKey(xprv: foreignAccount.serialized(network: .testnet), masterFingerprint: pair.fingerprint),
            .masterKey(foreignRoot.serialized(network: .testnet)), .mnemonic(foreignWords),
        ]
        let before = await pair.scoped.allUtxos
        let changeIndex = await pair.scoped.nextChangeIndex
        for secret in invalid {
            try pair.scopedStore.delete(walletID: id)
            try pair.scopedStore.store(secret, for: id)
            await #expect(throws: WalletError.accountKeyMismatch) { _ = try await Self.prepare(pair.scoped) }
            #expect(await pair.scoped.allUtxos == before)
            #expect(await pair.scoped.nextChangeIndex == changeIndex)
        }
        try pair.scopedStore.delete(walletID: id)
        try pair.scopedStore.store(.accountKey(xprv: xprv, masterFingerprint: pair.fingerprint), for: id)
        try Self.verify(await Self.prepare(pair.scoped))
    }

    @Test("account custody reopens, refuses a missing session key, and signs after rebinding")
    func reopenAndRebind() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("wallet.json")
        let pair = try Self.pair(account: 5, storage: file)
        try await Self.fundForSend(pair.scoped)
        let reopened = try Wallet.open(storageURL: file, keyStore: pair.scopedStore)
        let reopenedDescriptor = await reopened.descriptor.serialized()
        let originalDescriptor = await pair.scoped.descriptor.serialized()
        #expect(reopenedDescriptor == originalDescriptor)
        let id = await reopened.id
        let secret = try pair.scopedStore.load(walletID: id)
        #expect(secret == .accountKey(xprv: pair.accountKey.serialized(network: .testnet),
                                      masterFingerprint: pair.fingerprint))
        let bytes = try String(contentsOf: file, encoding: .utf8)
        #expect(!bytes.contains(pair.accountKey.serialized(network: .testnet)))
        try pair.scopedStore.delete(walletID: id)
        await #expect(throws: KeyStoreError.notFound(walletID: id)) {
            _ = try await Self.prepare(reopened)
        }
        try pair.scopedStore.store(secret, for: id)
        try Self.verify(await Self.prepare(reopened))
    }

    @Test("account custody never invents recovery words for an export")
    func accountBackup() async throws {
        let pair = try Self.pair()
        let bundle = try await pair.scoped.exportBundle()
        #expect(bundle.mnemonic == nil)
        await #expect(throws: WalletError.mnemonicUnavailable) {
            _ = try await pair.scoped.exportBundle(includeMnemonic: true)
        }
    }

    @Test("account custody preserves fee-bump authorization and same-input signing")
    func accountFeeBump() async throws {
        let pair = try Self.pair(account: 5)
        try await Self.fundForSend(pair.scoped)
        let original = try await Self.prepare(pair.scoped)
        try await pair.scoped.commit(original)
        let txid = original.built.transaction.txid
        let before = await pair.scoped.allUtxos
        let preview = try await pair.scoped.previewFeeBump(txid: txid, feeRateSatPerVByte: 5)
        let reads = pair.scopedStore.loads
        let replacement = try await pair.scoped.buildFeeBump(txid: txid, feeRateSatPerVByte: 5)
        #expect(pair.scopedStore.loads - reads == 1)
        #expect(preview.authorizes(replacement.built))
        #expect(replacement.built.transaction.inputs.map(\.previousOutput)
            == original.built.transaction.inputs.map(\.previousOutput))
        #expect(replacement.built.transaction.outputs.contains {
            $0.value == 600_000 && $0.scriptPubKey == TestScripts.p2trDestination
        })
        try Self.verify(transaction: replacement.built.transaction, psbt: replacement.built.psbt)
        #expect(await pair.scoped.allUtxos == before, "preparing a bump must not commit it")
        try await pair.scoped.commitFeeBump(replacement)
        #expect(await pair.scoped.history.first { $0.txid == txid }?.replacedBy
            == replacement.built.transaction.txid)
    }

    @Test("invalid account keys and hardened account arguments are refused before storage")
    func creationRefusals() throws {
        let root = try testMaster()
        let key = try BIP86.accountKey(from: root, coinType: 1)
        let neighbour = try BIP86.accountKey(from: root, coinType: 1, account: 1)
        for invalid in [root, key.neutered, try key.child(at: 0), neighbour] {
            #expect(throws: WalletError.accountKeyMismatch) {
                _ = try Wallet.create(accountKey: invalid, masterFingerprint: root.fingerprint,
                                      network: .signet, keyStore: InMemoryKeyStore())
            }
        }
        for invalid in [UInt32(0x8000_0000), .max] {
            #expect(throws: BIP32Error.invalidPath) {
                _ = try Wallet.create(accountKey: key, masterFingerprint: root.fingerprint,
                                      network: .signet, keyStore: InMemoryKeyStore(), account: invalid)
            }
        }
        let store = InMemoryKeyStore()
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            .appendingPathComponent("missing/wallet.json")
        #expect(throws: (any Error).self) {
            _ = try Wallet.create(accountKey: key, masterFingerprint: root.fingerprint,
                                  network: .signet, keyStore: store, storageURL: file)
        }
        #expect(throws: KeyStoreError.notFound(walletID: "73c5da0a")) {
            _ = try store.load(walletID: "73c5da0a")
        }
    }
}
