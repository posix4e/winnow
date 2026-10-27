import Foundation

/// What the phone keeps to work with a Ledger signer of one multisig account.
/// None of it is secret: the HMAC only proves to that Ledger that it approved
/// this exact policy before.
public struct LedgerRegistration: Codable, Equatable, Sendable {
    /// The name the Ledger shows for the account.
    public var policyName: String
    public var policyID: Data
    public var hmac: Data
    public var masterFingerprint: UInt32
    /// The Ledger signer's account path, hardened bits included.
    public var keyPath: [UInt32]

    public init(policyName: String, policyID: Data, hmac: Data, masterFingerprint: UInt32, keyPath: [UInt32]) {
        self.policyName = policyName
        self.policyID = policyID
        self.hmac = hmac
        self.masterFingerprint = masterFingerprint
        self.keyPath = keyPath
    }
}

/// A Ledger as the second signer of a `tr(NUMS, sortedmulti_a(…))` account.
/// The phone builds and reviews every spend itself; the Ledger shows the
/// payment on its own screen and adds its signature; the phone keeps a
/// Ledger signature only after verifying it against the recomputed sighash.
public enum LedgerMultisig {
    /// The Ledger's signer key: BIP87 multisig account 0, `m/87'/coin'/0'`,
    /// which the app exports without a warning.
    public static func keyPath(network: BitcoinNetwork) -> [UInt32] {
        let coin: UInt32 = network == .mainnet ? 0 : 1
        return [87 + HDKey.hardenedOffset, coin + HDKey.hardenedOffset, HDKey.hardenedOffset]
    }

    /// The Ledger's signer key expression, `[fp/87'/1'/0']tpub…/<0;1>/*`,
    /// and its fingerprint. The key must sit where its origin says.
    public static func signerExpression(client: LedgerBitcoinClient,
                                        network: BitcoinNetwork) async throws -> (expression: String, fingerprint: UInt32) {
        let fingerprint = try await client.masterFingerprint()
        let path = keyPath(network: network)
        let text = try await client.extendedPublicKey(path: path, display: false)
        let key = try HDKey.deserialize(text)
        let isTestKey = text.hasPrefix("tpub")
        guard isTestKey == (network != .mainnet), Int(key.depth) == path.count, key.childIndex == path.last,
              key.privateKey == nil else {
            throw LedgerError.mismatch("the Ledger's key is for another network or path; open the Bitcoin app for this network")
        }
        let origin = path.map { "\($0 & ~HDKey.hardenedOffset)'" }.joined(separator: "/")
        return ("[\(String(format: "%08x", fingerprint))/\(origin)]\(text)/<0;1>/*", fingerprint)
    }

    /// The account's Ledger signer: the one whose origin is the Ledger's
    /// fingerprint and key path.
    static func ledgerSigner(of account: MultisigAccount, fingerprint: UInt32,
                             path: [UInt32]) -> Descriptor.SingleKey? {
        account.signers.first { $0.origin?.fingerprint == fingerprint && $0.origin?.path == path }
    }

    /// Registers the account on the Ledger after the user approves it there,
    /// then checks that the Ledger derives the same first receive address.
    public static func register(_ account: MultisigAccount, name: String, fingerprint: UInt32,
                                client: LedgerBitcoinClient) async throws -> LedgerRegistration {
        let path = keyPath(network: account.network)
        guard ledgerSigner(of: account, fingerprint: fingerprint, path: path) != nil else {
            throw LedgerError.mismatch("this account has no signer for this Ledger")
        }
        let policy = try LedgerWalletPolicy(name: name, account: account)
        let (id, hmac) = try await client.register(policy)
        let registration = LedgerRegistration(policyName: name, policyID: id, hmac: hmac,
                                              masterFingerprint: fingerprint, keyPath: path)
        let first = try await client.address(policy, hmac: hmac, change: false, index: 0, display: false)
        guard first == (try account.address(index: 0, choice: 0)) else {
            throw LedgerError.mismatch("the Ledger derives a different first address")
        }
        return registration
    }

    static func policy(_ account: MultisigAccount, _ registration: LedgerRegistration) throws -> LedgerWalletPolicy {
        let policy = try LedgerWalletPolicy(name: registration.policyName, account: account)
        guard policy.id == registration.policyID else {
            throw LedgerError.mismatch("the stored Ledger registration belongs to another account")
        }
        return policy
    }

    /// Shows the address at (choice, index) on the Ledger for the user to
    /// compare with the phone's; it must equal the phone's own derivation.
    public static func displayAddress(_ account: MultisigAccount, registration: LedgerRegistration, choice: Int = 0,
                                      index: UInt32, client: LedgerBitcoinClient) async throws -> String {
        let shown = try await client.address(policy(account, registration), hmac: registration.hmac,
                                             change: choice == 1, index: index, display: true)
        let expected = try account.address(index: index, choice: choice)
        guard shown == expected else { throw LedgerError.mismatch("the Ledger shows a different address") }
        return shown
    }

    /// Asks the Ledger to sign `psbt`, which the caller has reviewed. Every
    /// signature it returns must verify for the leaf it names, on its input;
    /// otherwise the PSBT is left untouched. Returns the number of
    /// signatures added. Exercised through the app against the device
    /// simulator, a relabelling device included, by
    /// AppTests/LedgerPairingTests.testPairVerifyAndSpendWithBothSigners.
    @discardableResult
    public static func sign(_ psbt: inout PSBT, account: MultisigAccount, registration: LedgerRegistration,
                            client: LedgerBitcoinClient) async throws -> Int {
        let signatures = try await client.signPSBT(psbt, policy: policy(account, registration), hmac: registration.hmac)
        var signed = psbt
        var added = 0
        for signature in signatures {
            guard let leafHash = signature.leafHash, signature.publicKey.count == 32,
                  signed.inputs.indices.contains(signature.inputIndex) else {
                throw LedgerError.protocolViolation("a signature this account cannot use")
            }
            let id = PSBT.TapScriptSignatureID(publicKey: signature.publicKey, leafHash: leafHash)
            if signed.inputs[signature.inputIndex].tapScriptSignatures[id] == nil { added += 1 }
            signed.inputs[signature.inputIndex].tapScriptSignatures[id] = signature.signature
        }
        let tx = try signed.unsignedTransaction()
        let spentOutputs = try signed.spentOutputs()
        for signature in signatures {
            // Checked on its own leaf: the same key may already hold a valid
            // signature elsewhere, which must not vouch for this one.
            let verified = try signed.verifiedScriptPathSigners(input: signature.inputIndex,
                                                                leafHash: signature.leafHash ?? Data(), tx: tx,
                                                                spentOutputs: spentOutputs)
            guard verified.contains(signature.publicKey) else {
                throw LedgerError.mismatch("a Ledger signature does not verify")
            }
        }
        guard added > 0 else { throw LedgerError.mismatch("the Ledger added no signature") }
        psbt = signed
        return added
    }
}
