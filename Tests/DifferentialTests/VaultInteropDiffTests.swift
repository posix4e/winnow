import BitcoinCore
import BitcoinP2P
import Foundation
import Testing
import WalletCore

/// Mixed-implementation vault interoperability (invariant S8, issue #58).
///
/// Two Winnow installations are not implementation diversity: they share every
/// line of the code being tested. This suite gives one of a 2-of-3 vault's
/// three keys to **Bitcoin Core's descriptor wallet** — a wallet written by
/// other people, from the spec — and requires it to co-sign a script-path
/// spend that then confirms on chain.
///
/// What Core is asked to do, in order: parse `tr(NUMS, sortedmulti_a(...))`
/// with BIP389 multipath key expressions, agree with us about the addresses it
/// derives, hold one private key of three, produce a BIP342 script-path
/// partial signature into a PSBT we built, and let our finalizer combine its
/// signature with ours into a transaction the network accepts.
///
/// Anything Core cannot do is recorded as unsupported rather than skipped —
/// an interop matrix that only lists successes is a marketing document.
@Suite("vault interop with Bitcoin Core", .enabled(if: diffEnabled))
struct VaultInteropDiffTests {
    private let endpoint = PeerEndpoint(host: BitcoinCLI.nodeHost, port: BitcoinCLI.p2pPort)

    /// Core's own key material, taken from a wallet Core generated itself.
    /// Deliberately not derived from our seeds: a cosigner whose key we chose
    /// would prove less.
    private struct CoreParticipant {
        let publicExpression: String   // [fp/86h/1h/0h]tpub…
        let privateExpression: String  // tprv…/86h/1h/0h
    }

    private func coreParticipant(wallet: String) throws -> CoreParticipant {
        if (try? BitcoinCLI.run(["loadwallet", wallet])) == nil,
           (try? BitcoinCLI.runJSON(["listwalletdir"])) != nil {
            _ = try? BitcoinCLI.run(["-named", "createwallet", "wallet_name=\(wallet)"])
        }
        func descriptor(private isPrivate: Bool) throws -> String {
            let listed = try BitcoinCLI.runObject(["listdescriptors", isPrivate ? "true" : "false"],
                                                  wallet: wallet)
            let entries = try BitcoinCLI.array(listed, "descriptors").compactMap { $0 as? [String: Any] }
            guard let entry = entries.first(where: {
                ($0["desc"] as? String)?.hasPrefix("tr(") == true && ($0["internal"] as? Bool) != true
            }), let text = entry["desc"] as? String else {
                throw VaultInteropError.setup("no external tr() descriptor in \(wallet)")
            }
            return text
        }
        // tr(<key expression>/0/*)#checksum → the key expression itself.
        func keyExpression(from descriptor: String) throws -> String {
            guard let open = descriptor.firstIndex(of: "("),
                  let close = descriptor.lastIndex(of: ")") else {
                throw VaultInteropError.setup("unparsable descriptor \(descriptor)")
            }
            let inner = String(descriptor[descriptor.index(after: open) ..< close])
            guard let range = inner.range(of: "/0/*", options: .backwards) else {
                throw VaultInteropError.setup("unexpected key path in \(inner)")
            }
            return String(inner[inner.startIndex ..< range.lowerBound])
        }
        return CoreParticipant(publicExpression: try keyExpression(from: descriptor(private: false)),
                               privateExpression: try keyExpression(from: descriptor(private: true)))
    }

    enum VaultInteropError: Error, CustomStringConvertible {
        case setup(String)
        var description: String {
            switch self { case let .setup(message): "interop setup: \(message)" }
        }
    }

    @Test("Core co-signs a 2-of-3 script-path spend and it confirms")
    func coreCosignsScriptPathSpend() async throws {
        func trace(_ step: String) { FileHandle.standardError.write(Data("interop: \(step)\n".utf8)) }
        let params = NetworkParams.customSignet(challenge: BitcoinCLI.challenge,
                                                defaultPort: BitcoinCLI.p2pPort)

        // 1. One cosigner is Core's; two are ours.
        let core = try coreParticipant(wallet: "interop")
        var ourMasters: [HDKey] = []
        for index: UInt8 in 0 ..< 2 {
            let entropy = Data([0x40 + index] + Data(repeating: 0, count: 15))
            ourMasters.append(try HDKey(seed: BIP39.seed(mnemonic: BIP39.mnemonic(entropy: entropy))))
        }
        func ourExpression(_ master: HDKey) throws -> String {
            let account = try master.derived(path: "m/86'/1'/0'")
            return "[\(String(format: "%08x", master.fingerprint))/86'/1'/0']"
                + "\(account.neutered.serialized(network: .testnet))/<0;1>/*"
        }
        let coreExpression = core.publicExpression + "/<0;1>/*"
        let cosigners = [coreExpression] + (try ourMasters.map(ourExpression))
        let descriptor = try Vault.multiADescriptor(threshold: 2, cosigners: cosigners)
        let vault = try Vault(descriptor: descriptor, network: .signet)
        #expect(vault.usesUnspendableInternalKey, "a vault Core co-signs must be script-path only")

        // 2. Agreement before money: Core must derive the same addresses from
        //    the same descriptor. If this fails nothing later is meaningful.
        let ourAddresses = try (0 ..< 3).map { try vault.address(index: UInt32($0)) }
        // `serialized()` carries our own checksum, so handing it straight to
        // Core also checks that our checksum implementation agrees with theirs
        // — a wrong one is rejected outright rather than silently tolerated.
        let ourText = descriptor.serialized()
        let derived = try BitcoinCLI.runJSON(["deriveaddresses", ourText, "[0,2]"])
        // Multipath descriptors derive one array per chain; receive is first.
        let coreAddresses = ((derived as? [Any])?.first as? [Any])?.compactMap { $0 as? String }
        #expect(coreAddresses == ourAddresses,
                "Core and Winnow disagree about the vault's addresses")
        trace("descriptor agreement over \(ourAddresses.count) addresses")

        // 3. Core imports the same vault, holding exactly one of the three keys.
        let signerWallet = "interop-signer-\(UInt32.random(in: 0 ..< 1_000_000))"
        _ = try BitcoinCLI.run(["-named", "createwallet", "wallet_name=\(signerWallet)", "blank=true"])
        // Core writes hardened steps as `h`, we write them as `'`. Both are
        // BIP380-legal and the vault normalises to the apostrophe form, so the
        // substitution has to be made in our spelling or it silently matches
        // nothing. (`VaultCosignerIdentityTests` already treats the two
        // markers as the same key; this is the same fact seen from outside.)
        let body = String(ourText.split(separator: "#")[0])
        let coreExpressionOurSpelling = coreExpression
            .replacingOccurrences(of: "h/", with: "'/")
            .replacingOccurrences(of: "h]", with: "']")
        let privateText = body.replacingOccurrences(
            of: coreExpressionOurSpelling, with: core.privateExpression + "/<0;1>/*")
        #expect(privateText != body, "Core's leg was not substituted")
        let privateChecksum = try BitcoinCLI.string(
            BitcoinCLI.runObject(["getdescriptorinfo", privateText]), "checksum")
        let imported = try BitcoinCLI.runJSON(
            ["importdescriptors",
             #"[{"desc":"\#(privateText)#\#(privateChecksum)","timestamp":"now","active":true,"range":[0,5]}]"#],
            wallet: signerWallet)
        let importOK = ((imported as? [Any])?.first as? [String: Any])?["success"] as? Bool
        #expect(importOK == true, "Core refused the vault descriptor")
        trace("Core imported the vault holding 1 of 3 keys")
        let addrInfo = try BitcoinCLI.runObject(["getaddressinfo", ourAddresses[0]], wallet: signerWallet)
        trace("Core wallet view of vault addr0: ismine=\(String(describing: addrInfo["ismine"]))"
            + " solvable=\(String(describing: addrInfo["solvable"]))")

        // 4. Fund address 0 and mature it.
        let vaultScript = try vault.scriptPubKey(index: 0)
        let burnScript = try BIP86.scriptPubKey(
            internalKey: BIP86.xonlyPublicKey(of: testMaster().derived(path: "m/86'/1'/9'/0/2")))
        let fundingHash = try await SignetMiner.mineOntoTip(payingTo: vaultScript)
        for _ in 0 ..< 99 { _ = try await SignetMiner.mineOntoTip(payingTo: burnScript) }
        let fundingBlock = try BitcoinCLI.runObject(["getblock", fundingHash, "2"])
        let fundingHeight = try UInt32(BitcoinCLI.int(fundingBlock, "height"))
        #expect(try BitcoinCLI.int(fundingBlock, "confirmations") >= 100, "funding matured")
        let coinbase = try #require(
            (try BitcoinCLI.array(fundingBlock, "tx")).first as? [String: Any])
        let fundingTxid = try BitcoinCLI.string(coinbase, "txid")
        let utxo = WalletUTXO(txid: Data(Data(hex: fundingTxid)!.reversed()), vout: 0,
                              amount: 5_000_000_000, scriptPubKey: vaultScript,
                              chain: .receive, index: 0, height: fundingHeight,
                              isCoinbase: true)
        trace("vault funded at height \(fundingHeight)")

        // 5. We build the spend and sign one leg.
        let payoutScript = try BIP86.scriptPubKey(
            internalKey: BIP86.xonlyPublicKey(of: testMaster().derived(path: "m/86'/1'/9'/0/3")))
        let tip = try UInt32(BitcoinCLI.blockCount())
        var psbt = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 1_000_000, scriptPubKey: payoutScript)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: tip)
        let unsignedBase64 = psbt.base64
        try vault.partialSign(&psbt, master: ourMasters[0], knownUTXOs: [utxo],
                              ownedOutputCoordinates: [.init(choice: 1, index: 0)])
        let ourSignatures = psbt.inputs[0].tapScriptSignatures.count
        #expect(ourSignatures == 1, "our own leg signed")
        trace("Winnow signed 1 leg")

        // 6. Core signs the PSBT we produced. This is the claim under test:
        //    an independent implementation reading our PSBT, finding its own
        //    key in it, and producing a BIP342 script-path signature.
        //    Core cannot read our v2 envelope and we cannot read the v0 it
        //    returns, so the exchange is converted in both directions. The
        //    envelope is incompatible; the signature inside it is what this
        //    test is really asking about.
        let handedToCore = try v0Envelope(psbt)
        // finalize=false is load-bearing. Left at its default, Core signs AND
        // finalizes, folding both partial signatures into a final witness and
        // reporting complete=1 — at which point the tap script sigs are gone
        // and it looks like Core signed nothing. We want its *partial*
        // signature so that our finalizer is the one combining the two.
        let processed = try BitcoinCLI.runObject(
            ["walletprocesspsbt", handedToCore, "true", "DEFAULT", "true", "false"],
            wallet: signerWallet)
        let coreText = try BitcoinCLI.string(processed, "psbt")
        let coreMaps = try v0InputMaps(base64: coreText, inputCount: psbt.inputs.count)
        for (index, map) in coreMaps.enumerated() {
            for pair in map where pair.type == 0x14 { // PSBT_IN_TAP_SCRIPT_SIG
                guard !psbt.inputs[index].pairs.contains(where: { $0.key == pair.key }) else { continue }
                psbt.inputs[index].pairs.append(pair)
            }
        }
        let bothSignatures = psbt.inputs[0].tapScriptSignatures.count
        #expect(bothSignatures == 2,
                "expected our signature plus Core's, got \(bothSignatures)")
        trace("Core signed: \(bothSignatures) script-path signatures present")

        // 7. Our finalizer combines them, and the network is the judge.
        var finalPSBT = psbt
        let transaction = try vault.finalizeSpend(&finalPSBT, knownUTXOs: [utxo],
                                                  ownedOutputCoordinates: [.init(choice: 1, index: 0)])
        let raw = transaction.serialized(includeWitness: true).hex
        let accept = try BitcoinCLI.runJSON(["testmempoolaccept", "[\"\(raw)\"]"])
        let verdict = (accept as? [Any])?.first as? [String: Any]
        #expect(verdict?["allowed"] as? Bool == true,
                "Core rejected the co-signed transaction: \(verdict?["reject-reason"] ?? "unknown")")
        let txid = try BitcoinCLI.run(["sendrawtransaction", raw])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        _ = try await SignetMiner.mineOntoTip(payingTo: burnScript)
        let confirmed = try BitcoinCLI.runObject(["getrawtransaction", txid, "true"])
        #expect(try BitcoinCLI.int(confirmed, "confirmations") >= 1,
                "the co-signed spend did not confirm")
        trace("confirmed \(txid.prefix(16))… — unsigned was \(unsignedBase64.prefix(12))…")
    }
    /// Can Core co-sign a MuSig2 vault? (#58, S8)
    ///
    /// #58 is explicit that MuSig2 compatibility must never be inferred from
    /// ordinary PSBT support, and the script-path result above is exactly the
    /// evidence someone would be tempted to infer it from. So it is asked
    /// separately.
    ///
    /// Key-path MuSig2 needs a two-round protocol: every participant publishes
    /// a public nonce (BIP373 `PSBT_IN_MUSIG2_PUB_NONCE`, 0x1B), then each
    /// partial-signs against the aggregate of those nonces
    /// (`PSBT_IN_MUSIG2_PARTIAL_SIG`, 0x1C). A wallet that can parse a
    /// `musig()` descriptor and call the output solvable has said nothing
    /// about whether it implements either round.
    ///
    /// No mining here on purpose: `walletprocesspsbt` works from the PSBT's
    /// own witness UTXO, so a fabricated one answers the question in a second
    /// rather than in a hundred blocks. If Core ever does contribute, the
    /// on-chain spend becomes worth building — and this test failing is how
    /// we would find out.
    @Test("Core's MuSig2 participation, whatever it currently is")
    func coreMuSig2Participation() async throws {
        func trace(_ step: String) { FileHandle.standardError.write(Data("musig: \(step)\n".utf8)) }
        let core = try coreParticipant(wallet: "interop")
        let ourMaster = try HDKey(seed: BIP39.seed(
            mnemonic: BIP39.mnemonic(entropy: Data([0x60] + Data(repeating: 0, count: 15)))))
        let ourAccount = try ourMaster.derived(path: "m/86'/1'/0'")
        // BIP390: participants carry no derivation of their own when the
        // musig() itself has the suffix.
        let ourBare = "[\(String(format: "%08x", ourMaster.fingerprint))/86'/1'/0']"
            + ourAccount.neutered.serialized(network: .testnet)
        let vault = try Vault("tr(musig(\(core.publicExpression),\(ourBare))/<0;1>/*)",
                              network: .signet)

        // Agreement first, as with the script-path vault.
        let ourText = vault.descriptor.serialized()
        let derived = try BitcoinCLI.runJSON(["deriveaddresses", ourText, "[0,1]"])
        let coreAddresses = ((derived as? [Any])?.first as? [Any])?.compactMap { $0 as? String }
        let ourAddresses = try (0 ..< 2).map { try vault.address(index: UInt32($0)) }
        #expect(coreAddresses == ourAddresses, "Core and Winnow disagree about musig addresses")
        trace("descriptor agreement over \(ourAddresses.count) musig addresses")

        // Core holds one of the two participant keys.
        let wallet = "musig-interop-\(UInt32.random(in: 0 ..< 1_000_000))"
        _ = try BitcoinCLI.run(["-named", "createwallet", "wallet_name=\(wallet)", "blank=true"])
        let body = String(ourText.split(separator: "#")[0])
        let corePublicOurSpelling = core.publicExpression
            .replacingOccurrences(of: "h/", with: "'/").replacingOccurrences(of: "h]", with: "']")
        let privateText = body.replacingOccurrences(of: corePublicOurSpelling,
                                                    with: core.privateExpression)
        #expect(privateText != body, "Core's participant key was not substituted")
        let checksum = try BitcoinCLI.string(
            BitcoinCLI.runObject(["getdescriptorinfo", privateText]), "checksum")
        let imported = try BitcoinCLI.runJSON(
            ["importdescriptors",
             #"[{"desc":"\#(privateText)#\#(checksum)","timestamp":"now","active":true,"range":[0,2]}]"#],
            wallet: wallet)
        let importOK = ((imported as? [Any])?.first as? [String: Any])?["success"] as? Bool
        #expect(importOK == true, "Core refused a musig descriptor holding one private key")
        let addressInfo = try BitcoinCLI.runObject(["getaddressinfo", ourAddresses[0]], wallet: wallet)
        trace("Core wallet: ismine=\(String(describing: addressInfo["ismine"]))"
            + " solvable=\(String(describing: addressInfo["solvable"]))")

        // Round 1 from our side: our nonce goes in, Core's does not yet exist.
        let script = try vault.scriptPubKey(index: 0)
        let utxo = WalletUTXO(txid: Data(repeating: 0x7C, count: 32), vout: 0, amount: 200_000,
                              scriptPubKey: script, chain: .receive, index: 0, height: 500)
        let payout = try BIP86.scriptPubKey(
            internalKey: BIP86.xonlyPublicKey(of: testMaster().derived(path: "m/86'/1'/9'/0/4")))
        var psbt = try vault.createSpend(
            utxos: [utxo], payments: [Payment(amount: 50_000, scriptPubKey: payout)],
            changeIndex: 0, feeRateSatPerVByte: 2, chainTip: 600)
        let context = try vault.muSig2Context(choice: 0, index: 0)
        var secretNonces = try vault.muSig2AttachNonce(
            &psbt, input: 0, context: context, master: ourMaster, knownUTXOs: [utxo],
            ownedOutputCoordinates: [.init(choice: 1, index: 0)])
        _ = secretNonces
        let ourNonces = psbt.inputs[0].pairs.filter { $0.type == 0x1B }.count
        #expect(ourNonces == 1, "we did not attach our own nonce")

        // The question. finalize=false for the same reason as the script-path
        // case: finalizing would consume anything Core added.
        let handed = try v0Envelope(psbt)
        let processed = try BitcoinCLI.runObject(
            ["walletprocesspsbt", handed, "true", "DEFAULT", "true", "false"], wallet: wallet)
        let returned = try BitcoinCLI.string(processed, "psbt")
        let maps = try v0InputMaps(base64: returned, inputCount: psbt.inputs.count)
        let nonces = maps[0].filter { $0.type == 0x1B }.count
        let partials = maps[0].filter { $0.type == 0x1C }.count
        trace("Core returned nonces=\(nonces) partials=\(partials) "
            + "complete=\(String(describing: processed["complete"]))")

        // Core contributes a nonce: BIP373 round 1 is implemented, which
        // ordinary PSBT support would never have told us.
        #expect(nonces == ourNonces + 1, "Core did not contribute a MuSig2 public nonce")
        #expect(partials == 0, "a partial signature before every nonce is in would be a protocol error")

        // And here is exactly where interop stops.
        //
        // BIP373 keys a nonce by <participant pubkey><aggregate pubkey>. We
        // write the *root aggregate* P; Core writes the taproot-*tweaked*
        // output key Q. Same descriptor, same participants, identical
        // addresses — and two nonce entries neither side can look the other's
        // up by, which is why round 2 cannot proceed between us.
        //
        // Which of the two BIP373 actually mandates is a question about the
        // spec text rather than about this run, and is deliberately not
        // settled here. What this establishes is that they disagree, and
        // precisely how — the part that was unknown.
        let outputKey = Data(script.dropFirst(2))
        var ourAggregate: Data?
        var coreAggregate: Data?
        for pair in maps[0] where pair.type == 0x1B {
            let aggregate = Data(pair.key.dropFirst().dropFirst(33))
            if aggregate.dropFirst() == outputKey { coreAggregate = aggregate }
            else { ourAggregate = aggregate }
        }
        let mine = try #require(ourAggregate, "our own nonce went missing from the round trip")
        let theirs = try #require(coreAggregate, "Core's nonce is not keyed by the tweaked output key")
        #expect(mine == context.aggregate, "we key the nonce by the root aggregate")
        #expect(theirs.dropFirst() == outputKey, "Core keys the nonce by the tweaked output key")
        #expect(mine != theirs,
                "the two now agree on the aggregate key: round 2 and an on-chain MuSig2 co-sign are worth building")
        trace("round 1 works on both sides; round 2 is blocked by the aggregate-key encoding")
    }
}
