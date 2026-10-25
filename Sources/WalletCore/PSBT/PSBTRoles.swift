import Foundation
import P256K

/// PSBT roles (BIP370/BIP371): creator (unsigned wallet tx + UTXO data),
/// signer (PSBT_IN_TAP_KEY_SIG for the key path), combiner (union merge of
/// partial PSBTs), finalizer/extractor (witnesses → raw transaction).
extension PSBT {
    /// The Taproot key-origin metadata the creator attaches to an in/output:
    /// the x-only internal key and its full derivation path from the master
    /// fingerprint (BIP371 PSBT_*_TAP_BIP32_DERIVATION with zero leaf hashes).
    public struct TaprootKey: Equatable, Sendable {
        public var internalKey: Data
        public var masterFingerprint: UInt32
        public var path: [UInt32]

        public init(internalKey: Data, masterFingerprint: UInt32, path: [UInt32]) {
            self.internalKey = internalKey
            self.masterFingerprint = masterFingerprint
            self.path = path
        }

        var origin: KeyOrigin {
            KeyOrigin(leafHashes: [], masterFingerprint: masterFingerprint, path: path)
        }
    }

    /// Creator input: the spent output (amount + scriptPubKey → witness utxo)
    /// and, when ours, its Taproot key origin.
    public struct InputInfo: Equatable, Sendable {
        public var spentOutput: SighashBIP341.SpentOutput
        public var key: TaprootKey?

        public init(spentOutput: SighashBIP341.SpentOutput, key: TaprootKey? = nil) {
            self.spentOutput = spentOutput
            self.key = key
        }
    }

    /// Creator output metadata: key origin for wallet-owned (change) outputs.
    public struct OutputInfo: Equatable, Sendable {
        public var key: TaprootKey?

        public init(key: TaprootKey? = nil) {
            self.key = key
        }
    }

    // MARK: - Creator

    /// Creator role: a PSBTv2 from an unsigned transaction plus per-input UTXO
    /// data. Emits the BIP370 v2 fields (previous txid, output index, sequence,
    /// fallback locktime), PSBT_IN_WITNESS_UTXO (amount + scriptPubKey), an
    /// explicit PSBT_IN_SIGHASH_TYPE = SIGHASH_DEFAULT, and the BIP371 Taproot
    /// key fields for wallet-owned in/outputs.
    public init(unsignedTx tx: Transaction, inputs inputInfo: [InputInfo],
                outputs outputInfo: [OutputInfo]) throws {
        guard inputInfo.count == tx.inputs.count else {
            throw PSBTError.inconsistentCounts
        }
        guard outputInfo.count == tx.outputs.count else {
            throw PSBTError.inconsistentCounts
        }
        var globals: [KeyValue] = []
        globals.append(KeyValue(type: GlobalType.version, value: Self.uint32le(2)))
        globals.append(KeyValue(type: GlobalType.txVersion, value: Self.int32le(tx.version)))
        globals.append(KeyValue(type: GlobalType.fallbackLocktime, value: Self.uint32le(tx.locktime)))
        globals.append(KeyValue(type: GlobalType.inputCount, value: Self.compactSize(UInt64(tx.inputs.count))))
        globals.append(KeyValue(type: GlobalType.outputCount, value: Self.compactSize(UInt64(tx.outputs.count))))

        inputs = try zip(tx.inputs, inputInfo).map { input, info in
            guard info.spentOutput.amount >= 0 else { throw PSBTError.malformed("negative amount") }
            var pairs: [KeyValue] = []
            pairs.append(KeyValue(type: InType.previousTxid, value: input.previousOutput.txid))
            pairs.append(KeyValue(type: InType.outputIndex, value: Self.uint32le(input.previousOutput.vout)))
            pairs.append(KeyValue(type: InType.sequence, value: Self.uint32le(input.sequence)))
            pairs.append(KeyValue(type: InType.sighashType, value: Self.uint32le(0))) // SIGHASH_DEFAULT
            var utxo = Data()
            utxo.appendInt64(info.spentOutput.amount)
            utxo.appendVarData(info.spentOutput.scriptPubKey)
            pairs.append(KeyValue(type: InType.witnessUTXO, value: utxo))
            var result = Input(pairs: pairs)
            if let key = info.key {
                result.tapInternalKey = key.internalKey
                result.tapBIP32Derivation = [key.internalKey: key.origin]
            }
            return result
        }

        outputs = zip(tx.outputs, outputInfo).map { output, info in
            var result = Output(pairs: [
                KeyValue(type: OutType.amount, value: Self.int64le(output.value)),
                KeyValue(type: OutType.script, value: output.scriptPubKey),
            ])
            if let key = info.key {
                result.tapInternalKey = key.internalKey
                result.tapBIP32Derivation = [key.internalKey: key.origin]
            }
            return result
        }
        self.globals = globals
        // Canonical key order in memory, matching the wire format.
        self.globals.sort { $0.key.lexicographicallyPrecedes($1.key) }
        for index in inputs.indices { inputs[index].pairs.sort { $0.key.lexicographicallyPrecedes($1.key) } }
        for index in outputs.indices { outputs[index].pairs.sort { $0.key.lexicographicallyPrecedes($1.key) } }
    }

    // MARK: - Unsigned transaction

    /// The unsigned transaction described by the v2 fields (BIP370): inputs
    /// from previous-txid/output-index/sequence (default 0xFFFFFFFF), outputs
    /// from amount/script, version and locktime from the globals.
    public func unsignedTransaction() throws -> Transaction {
        var txInputs: [Transaction.Input] = []
        for (index, input) in inputs.enumerated() {
            guard let txid = input.previousTxid, txid.count == 32 else {
                throw PSBTError.missingField("input \(index) previous txid")
            }
            guard let vout = input.outputIndex else {
                throw PSBTError.missingField("input \(index) output index")
            }
            txInputs.append(Transaction.Input(previousOutput: Transaction.Outpoint(txid: txid, vout: vout),
                                              scriptSig: Data(),
                                              sequence: input.sequence ?? 0xFFFF_FFFF))
        }
        var txOutputs: [Transaction.Output] = []
        for (index, output) in outputs.enumerated() {
            guard let amount = output.amount, let script = output.script else {
                throw PSBTError.missingField("output \(index) amount/script")
            }
            txOutputs.append(Transaction.Output(value: amount, scriptPubKey: script))
        }
        return Transaction(version: txVersion, inputs: txInputs, outputs: txOutputs,
                           locktime: fallbackLocktime)
    }

    /// The spent outputs (amount + scriptPubKey) of every input, from the
    /// witness utxos — the BIP341 sighash inputs.
    public func spentOutputs() throws -> [SighashBIP341.SpentOutput] {
        try inputs.enumerated().map { index, input in
            guard let utxo = input.witnessUTXO else {
                throw PSBTError.missingField("input \(index) witness utxo")
            }
            return utxo
        }
    }

    // MARK: - Signer

    /// Signer role: adds PSBT_IN_TAP_KEY_SIG to input `index` (BIP371). The
    /// hash type comes from PSBT_IN_SIGHASH_TYPE (0/absent = SIGHASH_DEFAULT —
    /// this wallet always writes it explicitly); `tweakedPrivateKey` is the
    /// BIP86 tweaked secret for the input's internal key.
    public mutating func signKeyPath(input index: Int, tweakedPrivateKey: Data,
                                     auxiliaryRand: Data? = nil) throws {
        guard inputs.indices.contains(index) else {
            throw PSBTError.missingField("input \(index)")
        }
        let tx = try unsignedTransaction()
        let spentOutputs = try spentOutputs()
        let rawType = inputs[index].sighashType ?? 0
        guard rawType <= UInt32(UInt8.max) else { throw PSBTError.malformed("sighash type \(rawType)") }
        let hashType = SighashBIP341.HashType(rawValue: UInt8(rawType))
        // This wallet only signs sighash types that commit to every output.
        guard hashType.commitsToAllOutputs else {
            throw PSBTError.malformed("refusing non-DEFAULT/ALL sighash type \(rawType)")
        }
        let witness = try Signer.witness(tx: tx, inputIndex: index, spentOutputs: spentOutputs,
                                         tweakedPrivateKey: tweakedPrivateKey, hashType: hashType,
                                         auxiliaryRand: auxiliaryRand)
        inputs[index].tapKeySignature = witness[0]
    }

    // MARK: - Script-path (multi_a) roles

    /// Creator-side helper: attaches the BIP371 script-path fields for a
    /// multisig input — PSBT_IN_TAP_INTERNAL_KEY (from the control block),
    /// PSBT_IN_TAP_LEAF_SCRIPT, and per-leaf-key PSBT_IN_TAP_BIP32_DERIVATION
    /// entries carrying the tapleaf hash.
    public mutating func attachScriptPath(input index: Int, controlBlock: Taproot.ControlBlock,
                                          leafScript: Script, leafVersion: UInt8 = Taproot.leafVersion,
                                          keyOrigins: [Data: KeyOrigin] = [:]) throws {
        guard inputs.indices.contains(index) else { throw PSBTError.missingField("input \(index)") }
        inputs[index].tapInternalKey = controlBlock.internalKey
        let leaf = TapLeafScript(controlBlock: controlBlock, script: leafScript.bytes, leafVersion: leafVersion)
        inputs[index].tapLeafScripts = [leaf]
        guard !keyOrigins.isEmpty else { return }
        var origins = inputs[index].tapBIP32Derivation
        for (key, origin) in keyOrigins {
            var origin = origin
            origin.leafHashes = [leaf.leafHash]
            origins[key] = origin
        }
        inputs[index].tapBIP32Derivation = origins
    }

    /// Creator-side helper for a tree of leaves: the internal key, one
    /// PSBT_IN_TAP_LEAF_SCRIPT per leaf, and the given origins, whose leaf
    /// hashes the caller sets to the leaves each key appears in.
    public mutating func attachScriptPaths(input index: Int,
                                           leaves: [(controlBlock: Taproot.ControlBlock, script: Script,
                                                     leafVersion: UInt8)],
                                           keyOrigins: [Data: KeyOrigin]) throws {
        guard inputs.indices.contains(index), let first = leaves.first else {
            throw PSBTError.missingField("input \(index)")
        }
        inputs[index].tapInternalKey = first.controlBlock.internalKey
        inputs[index].tapLeafScripts = leaves.map {
            TapLeafScript(controlBlock: $0.controlBlock, script: $0.script.bytes, leafVersion: $0.leafVersion)
        }
        var origins = inputs[index].tapBIP32Derivation
        for (key, origin) in keyOrigins { origins[key] = origin }
        inputs[index].tapBIP32Derivation = origins
    }

    /// Signer role for multi_a leaves (BIP371/BIP387): for every 32-byte
    /// secret whose x-only key appears in the input's leaf script, adds a
    /// PSBT_IN_TAP_SCRIPT_SIG. Plain x-only keys sign with NO taproot tweak.
    /// Each signature is self-verified before being attached; throws when no
    /// provided key matches a leaf key.
    public mutating func signScriptPath(input index: Int, privateKeys: [Data],
                                        auxiliaryRand: Data? = nil) throws {
        let tx = try unsignedTransaction()
        let spentOutputs = try spentOutputs()
        var signatures = inputs[index].tapScriptSignatures
        var signed = 0
        // Every leaf the key is in whose timelock, if any, this input's
        // sequence already meets: a signature on a leaf the transaction
        // cannot use is never made.
        for context in try leafSigningContexts(input: index)
        where Self.lockIsMet(context.policy, input: index, tx: tx) {
            for secret in privateKeys {
                guard let attached = try selfVerifiedLeafSignature(
                    for: secret, input: index, leaf: context.leaf, leafKeys: context.policy.keys,
                    tx: tx, spentOutputs: spentOutputs, hashType: context.hashType,
                    auxiliaryRand: auxiliaryRand) else { continue } // not ours — skip
                signatures[attached.id] = attached.signature
                signed += 1
            }
        }
        guard signed > 0 else { throw PSBTError.missingField("input \(index) matching leaf key") }
        inputs[index].tapScriptSignatures = signatures
    }

    /// Whether the leaf's relative timelock, if it has one, is met by the
    /// input's sequence in this transaction (BIP68/BIP112).
    static func lockIsMet(_ policy: LeafPolicy, input index: Int, tx: Transaction) -> Bool {
        guard let blocks = policy.relativeLock else { return true }
        guard tx.inputs.indices.contains(index) else { return false }
        return RelativeLock.isSatisfied(blocks: blocks, sequence: tx.inputs[index].sequence, txVersion: tx.version)
    }

    /// The keys of one leaf whose script-path signatures on `input` verify
    /// against the recomputed sighash — the finalizer's own test, exposed so
    /// a progress display counts approvals the way the finalizer will, rather
    /// than by the presence of a signature entry. Always per leaf: a key's
    /// valid signature on one leaf says nothing about an entry naming another.
    public func verifiedScriptPathSigners(input index: Int, leafHash: Data, tx: Transaction,
                                          spentOutputs: [SighashBIP341.SpentOutput]) throws -> Set<Data> {
        guard let context = try leafSigningContexts(input: index).first(where: { $0.leaf.leafHash == leafHash }) else {
            return []
        }
        return Set(validScriptPathSignatures(input: index, leaf: context.leaf, tx: tx, spentOutputs: spentOutputs,
                                             leafKeys: context.policy.keys).keys)
    }

    /// The signable leaf and its contract for one input: a leaf script that
    /// parses as multisig, and an output-committing sighash type — a signer
    /// signs only those, so a PSBT creator cannot collect NONE/SINGLE
    /// partials and then rewrite the outputs.
    private func leafSigningContexts(input index: Int) throws
        -> [(leaf: TapLeafScript, policy: LeafPolicy, hashType: SighashBIP341.HashType)] {
        guard inputs.indices.contains(index) else { throw PSBTError.missingField("input \(index)") }
        let leaves = inputs[index].tapLeafScripts
        guard !leaves.isEmpty else { throw PSBTError.missingField("input \(index) tap leaf script") }
        let rawType = inputs[index].sighashType ?? 0
        guard rawType <= UInt32(UInt8.max) else { throw PSBTError.malformed("sighash type \(rawType)") }
        let hashType = SighashBIP341.HashType(rawValue: UInt8(rawType))
        guard hashType.commitsToAllOutputs else {
            throw PSBTError.malformed("refusing non-DEFAULT/ALL sighash type \(rawType)")
        }
        let contexts = leaves.compactMap { leaf in
            Multisig.parsePolicy(Script(leaf.script)).map { (leaf: leaf, policy: $0, hashType: hashType) }
        }
        guard !contexts.isEmpty else { throw PSBTError.malformed("input \(index) leaf script") }
        return contexts
    }

    /// One leaf signature for one secret — or nil when the key is not a
    /// leaf key. The signature is checked against the leaf key with BIP340
    /// verification before it is ever attached.
    private func selfVerifiedLeafSignature(
        for secret: Data, input index: Int, leaf: TapLeafScript, leafKeys: [Data],
        tx: Transaction, spentOutputs: [SighashBIP341.SpentOutput],
        hashType: SighashBIP341.HashType, auxiliaryRand: Data?)
        throws -> (id: TapScriptSignatureID, signature: Data)? {
        guard let key = try? P256K.Schnorr.PrivateKey(dataRepresentation: secret) else {
            throw PSBTError.malformed("invalid private key")
        }
        let xonly = Data(key.xonly.bytes)
        guard leafKeys.contains(xonly) else { return nil }
        let signature = try Signer.scriptPathSignature(tx: tx, inputIndex: index,
                                                       spentOutputs: spentOutputs,
                                                       leafScript: Script(leaf.script),
                                                       leafVersion: leaf.leafVersion,
                                                       hashType: hashType, privateKey: secret,
                                                       auxiliaryRand: auxiliaryRand)
        let sighash = try SighashBIP341.sighash(tx: tx, inputIndex: index, spentOutputs: spentOutputs,
                                                hashType: hashType,
                                                scriptPath: .init(leafScript: Script(leaf.script),
                                                                  leafVersion: leaf.leafVersion))
        var message = [UInt8](sighash)
        let parsed = try P256K.Schnorr.SchnorrSignature(dataRepresentation: signature.prefix(64))
        guard P256K.Schnorr.XonlyKey(dataRepresentation: xonly).isValid(parsed, for: &message) else {
            throw PSBTError.malformed("self-produced signature failed verification")
        }
        return (TapScriptSignatureID(publicKey: xonly, leafHash: leaf.leafHash), signature)
    }

    // MARK: - Combiner

    /// Combiner role (BIP370/BIP174): merges several partial PSBTs of the
    /// same unsigned transaction into one. The merge is the union of the
    /// key-value pairs of every map (globals, inputs, outputs); identical
    /// pairs dedupe, and the same key carrying two different values is a
    /// conflict and throws.
    public func combined(with others: [PSBT]) throws -> PSBT {
        let all = [self] + others
        let reference = try unsignedTransaction()
        guard allSatisfy(all, countsMatch), try allSatisfy(all, { try $0.unsignedTransaction() == reference })
        else { throw PSBTError.inconsistentCounts }

        func merge(_ maps: [[KeyValue]]) throws -> [KeyValue] {
            var merged: [Data: Data] = [:]
            for map in maps {
                for pair in map {
                    if let existing = merged[pair.key], existing != pair.value {
                        throw PSBTError.conflict(pair.key)
                    }
                    merged[pair.key] = pair.value
                }
            }
            return merged.sorted { $0.key.lexicographicallyPrecedes($1.key) }
                .map { KeyValue(key: $0.key, value: $0.value) }
        }

        var mergedInputs: [Input] = []
        var mergedOutputs: [Output] = []
        for index in inputs.indices {
            mergedInputs.append(Input(pairs: try merge(all.map { $0.inputs[index].pairs })))
        }
        for index in outputs.indices {
            mergedOutputs.append(Output(pairs: try merge(all.map { $0.outputs[index].pairs })))
        }
        return try PSBT(globals: merge(all.map(\.globals)), inputs: mergedInputs, outputs: mergedOutputs)
    }

    private func allSatisfy(_ psbts: [PSBT], _ predicate: (PSBT) throws -> Bool) rethrows -> Bool {
        for psbt in psbts where try !predicate(psbt) { return false }
        return true
    }

    private func countsMatch(_ other: PSBT) -> Bool {
        other.inputs.count == inputs.count && other.outputs.count == outputs.count
    }

    // MARK: - Finalizer / extractor

    /// Finalizer role: moves each input's signature data into
    /// PSBT_IN_FINAL_SCRIPTWITNESS and clears the in-progress fields (BIP174:
    /// finalizers remove partial data). Key-path inputs take the single
    /// PSBT_IN_TAP_KEY_SIG, verified against the declared P2TR output first;
    /// script-path inputs build the BIP387 multi_a witness from
    /// PSBT_IN_TAP_SCRIPT_SIG entries (each verified against the script-path
    /// sighash — a wrong-key or corrupt partial is discarded), requiring at
    /// least the leaf's threshold of valid signatures.
    public mutating func finalize() throws {
        let tx = try unsignedTransaction()
        let spentOutputs = try spentOutputs()
        var witnesses: [[Data]] = []
        for index in inputs.indices {
            if let signature = inputs[index].tapKeySignature {
                witnesses.append(try validatedKeyPathWitness(
                    input: index, signature: signature, tx: tx, spentOutputs: spentOutputs))
            } else if !inputs[index].tapLeafScripts.isEmpty {
                var witness: [Data]?
                // A leaf without a timelock first: it spends without waiting.
                let all = inputs[index].tapLeafScripts
                let isLocked = { (leaf: TapLeafScript) in Multisig.parsePolicy(Script(leaf.script))?.relativeLock != nil }
                for leaf in all.filter({ !isLocked($0) }) + all.filter(isLocked) {
                    witness = try finalizedScriptPathWitness(input: index, leaf: leaf,
                                                             tx: tx, spentOutputs: spentOutputs)
                    if witness != nil { break }
                }
                guard let witness else {
                    throw PSBTError.missingField("input \(index) tap script sigs below threshold")
                }
                witnesses.append(witness)
            } else {
                throw PSBTError.missingField("input \(index) tap key sig")
            }
        }
        // Commit only after every input validates. A bad later input must not
        // leave the PSBT half-finalized with earlier partial fields erased.
        for index in inputs.indices {
            inputs[index].finalScriptWitness = witnesses[index]
            inputs[index].pairs.removeAll {
                $0.type == InType.tapKeySignature || $0.type == InType.sighashType
                    || $0.type == InType.tapScriptSignature || $0.type == InType.tapLeafScript
            }
        }
    }

    /// The BIP387 witness for one multi_a leaf, carrying exactly its
    /// threshold of signatures, or nil when fewer valid ones are attached
    /// or the leaf repeats a key. Signatures whose hash type byte (or absence
    /// of one) does not match, or that fail BIP340 verification, are
    /// discarded rather than trusted. Exercised by the signet journey in
    /// UITests/MultisigJourney.swift, where all three signers of a 2-of-3
    /// sign and Core mines the two-signature witness, then a recovery-leaf
    /// one; a surplus on a recovery leaf is in TimelockedMultisigTests.
    private func finalizedScriptPathWitness(input index: Int, leaf: TapLeafScript,
                                            tx: Transaction,
                                            spentOutputs: [SighashBIP341.SpentOutput]) throws -> [Data]? {
        guard leaf.leafVersion == leaf.controlBlock.leafVersion else { return nil }
        let spentScript = spentOutputs[index].scriptPubKey
        guard spentScript.count == 34, spentScript[spentScript.startIndex] == 0x51,
              spentScript[spentScript.index(after: spentScript.startIndex)] == 0x20
        else { throw PSBTError.malformed("input \(index) witness utxo is not P2TR") }
        guard Self.leafCommitsToOutput(leaf, spentScript: spentScript) else { return nil }

        // A repeated key would fill two slots with one signature.
        guard let policy = Multisig.parsePolicy(Script(leaf.script)), Set(policy.keys).count == policy.keys.count,
              Self.lockIsMet(policy, input: index, tx: tx) else { return nil }
        let valid = validScriptPathSignatures(input: index, leaf: leaf, tx: tx,
                                              spentOutputs: spentOutputs, leafKeys: policy.keys)
        // multi_a counts every signature and needs exactly k (BIP387): a
        // surplus one fails OP_NUMEQUAL, so the first k in script order sign
        // and the other slots stay empty.
        var chosen: [Data: Data] = [:]
        for key in policy.keys where chosen.count < policy.threshold {
            chosen[key] = valid[key]
        }
        guard chosen.count == policy.threshold else { return nil }
        return try Signer.multisigWitness(signatures: chosen, leafScript: Script(leaf.script),
                                          controlBlock: leaf.controlBlock)
    }

    /// BIP341's commitment walk: the leaf hash up its merkle path to a
    /// tweaked output key that must equal the spent P2TR output, parity
    /// included — the check that stops a stranger's control block from
    /// dressing another script as this output's.
    private static func leafCommitsToOutput(_ leaf: TapLeafScript, spentScript: Data) -> Bool {
        var merkleRoot = leaf.leafHash
        for sibling in leaf.controlBlock.path {
            guard sibling.count == 32 else { return false }
            merkleRoot = Taproot.branchHash(merkleRoot, sibling)
        }
        guard let committed = try? Taproot.tweakedOutputKey(
            internalKey: leaf.controlBlock.internalKey, merkleRoot: merkleRoot)
        else { return false }
        return committed.key == spentScript.suffix(32)
            && committed.parity == leaf.controlBlock.outputKeyParity
    }

    /// The cryptographically valid script-path signatures for one leaf,
    /// keyed by signer: each must name a leaf key, commit to all outputs,
    /// and verify against the recomputed sighash — anything else is skipped,
    /// never fatal, because a combiner may carry a stranger's noise.
    private func validScriptPathSignatures(input index: Int, leaf: TapLeafScript,
                                           tx: Transaction,
                                           spentOutputs: [SighashBIP341.SpentOutput],
                                           leafKeys: [Data]) -> [Data: Data] {
        var valid: [Data: Data] = [:]
        for (id, signature) in inputs[index].tapScriptSignatures where id.leafHash == leaf.leafHash {
            guard leafKeys.contains(id.publicKey) else { continue }
            // A 64-byte item implies SIGHASH_DEFAULT; 65 bytes append the type.
            let hashType: SighashBIP341.HashType
            switch signature.count {
            case 64: hashType = .default
            case 65: hashType = SighashBIP341.HashType(rawValue: signature.last!)
            default: continue
            }
            guard hashType.commitsToAllOutputs, hashType != .default || signature.count == 64,
                  let sighash = try? SighashBIP341.sighash(tx: tx, inputIndex: index,
                                                           spentOutputs: spentOutputs, hashType: hashType,
                                                           scriptPath: .init(leafScript: Script(leaf.script),
                                                                             leafVersion: leaf.leafVersion)),
                  let parsed = try? P256K.Schnorr.SchnorrSignature(dataRepresentation: signature.prefix(64))
            else { continue }
            var message = [UInt8](sighash)
            guard P256K.Schnorr.XonlyKey(dataRepresentation: id.publicKey).isValid(parsed, for: &message)
            else { continue }
            valid[id.publicKey] = signature
        }
        return valid
    }

    /// Validates an imported key-path signature against the PSBT's declared
    /// P2TR witness UTXO before moving it into the final witness. Trusted
    /// wallet policy must separately bind that declaration to the real coin;
    /// finalization proves document self-consistency, not chain ownership.
    private func validatedKeyPathWitness(input index: Int, signature: Data,
                                         tx: Transaction,
                                         spentOutputs: [SighashBIP341.SpentOutput]) throws -> [Data] {
        let hashType: SighashBIP341.HashType
        switch signature.count {
        case 64:
            hashType = .default
        case 65:
            hashType = SighashBIP341.HashType(rawValue: signature.last!)
        default:
            throw PSBTError.malformed("input \(index) tap key signature length")
        }
        guard hashType.commitsToAllOutputs,
              hashType != .default || signature.count == 64
        else { throw PSBTError.malformed("input \(index) unsafe tap key sighash type") }

        let script = spentOutputs[index].scriptPubKey
        guard script.count == 34, script[script.startIndex] == 0x51,
              script[script.index(after: script.startIndex)] == 0x20
        else { throw PSBTError.malformed("input \(index) witness utxo is not P2TR") }
        let sighash = try SighashBIP341.sighash(
            tx: tx, inputIndex: index, spentOutputs: spentOutputs, hashType: hashType)
        var message = [UInt8](sighash)
        guard let parsed = try? P256K.Schnorr.SchnorrSignature(dataRepresentation: signature.prefix(64)),
              P256K.Schnorr.XonlyKey(dataRepresentation: script.suffix(32)).isValid(parsed, for: &message)
        else { throw PSBTError.malformed("input \(index) invalid tap key signature") }
        return [signature]
    }

    /// Extractor role: the fully-signed raw transaction.
    public func extractedTransaction() throws -> Transaction {
        var tx = try unsignedTransaction()
        for index in tx.inputs.indices {
            guard let witness = inputs[index].finalScriptWitness else {
                throw PSBTError.missingField("input \(index) final witness")
            }
            tx.inputs[index].witness = witness
        }
        return tx
    }

    // MARK: - LE helpers

    static func uint32le(_ value: UInt32) -> Data {
        var data = Data()
        data.appendUInt32(value)
        return data
    }

    static func int32le(_ value: Int32) -> Data {
        var data = Data()
        data.appendInt32(value)
        return data
    }

    static func int64le(_ value: Int64) -> Data {
        var data = Data()
        data.appendInt64(value)
        return data
    }

    static func compactSize(_ value: UInt64) -> Data {
        var data = Data()
        data.appendCompactSize(value)
        return data
    }
}
