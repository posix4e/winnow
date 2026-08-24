import BitcoinP2P
import Foundation

public enum StoryEvidenceError: LocalizedError, Equatable {
    case missingHeight(String)
    case invalidTransactionID(String)
    case heightUnavailable(UInt32)
    case peerUnavailable
    case blockUnavailable(UInt32, String)
    case blockHashMismatch(UInt32)
    case invalidMerkleRoot(UInt32)
    case transactionNotInBlock(String, UInt32)

    public var errorDescription: String? {
        switch self {
        case let .missingHeight(txid):
            "Transaction \(txid) has no claimed confirmation height yet."
        case let .invalidTransactionID(txid):
            "Transaction ID \(txid) is not 32-byte hexadecimal text."
        case let .heightUnavailable(height):
            "The validated public-signet header snapshot has not reached block \(height)."
        case .peerUnavailable:
            "No public signet peer is currently available to provide confirmation evidence."
        case let .blockUnavailable(height, reason):
            "Public signet block \(height) could not be retrieved: \(reason)"
        case let .blockHashMismatch(height):
            "A peer returned the wrong block for public-signet height \(height)."
        case let .invalidMerkleRoot(height):
            "The transactions returned for public-signet block \(height) do not match its committed Merkle root."
        case let .transactionNotInBlock(txid, height):
            "Transaction \(txid) is not in the authenticated public-signet block \(height)."
        }
    }
}

public struct StoryVerifiedTransaction: Sendable, Equatable {
    public let txid: String
    public let height: UInt32
    public let blockHash: String
    public let parentTransactionIDs: [String]
}

public enum StoryEvidenceVerifier {
    /// Fetches the claimed block from a public signet peer, authenticates it
    /// against the locally validated header chain and Merkle root, then proves
    /// the transaction is actually present. No explorer or owner service is
    /// trusted, and no local Bitcoin node is used.
    public static func verify(_ evidence: StoryTransactionEvidence,
                              chain: HeaderChain, pool: PeerPool) async throws
        -> StoryVerifiedTransaction {
        await pool.start()
        do {
            try await pool.syncHeaders(chain, timeoutPerPeer: .seconds(45))
            let verified = try await verifyConnected(evidence, chain: chain, pool: pool)
            await pool.stop()
            return verified
        } catch {
            await pool.stop()
            throw error
        }
    }

    /// Verifies one transaction after the caller has started the pool and
    /// synchronized `chain`. This lets the CLI authenticate a whole run with
    /// one peer session and one header-sync pass.
    public static func verifyConnected(_ evidence: StoryTransactionEvidence,
                                       chain: HeaderChain, pool: PeerPool) async throws
        -> StoryVerifiedTransaction {
        guard let height = evidence.confirmationHeight else {
            throw StoryEvidenceError.missingHeight(evidence.txid)
        }
        guard let txid = internalHash(evidence.txid) else {
            throw StoryEvidenceError.invalidTransactionID(evidence.txid)
        }

        guard let expectedBlockHash = await chain.blockHash(at: height) else {
            throw StoryEvidenceError.heightUnavailable(height)
        }

        var lastFailure = "no connected peer returned the block"
        let peers = await pool.connectedPeers()
        guard !peers.isEmpty else { throw StoryEvidenceError.peerUnavailable }
        for peer in peers {
            do {
                return try await verifyBlock(from: peer, expectedBlockHash: expectedBlockHash,
                                             txid: txid, txidText: evidence.txid, height: height)
            } catch StoryEvidenceError.transactionNotInBlock {
                // A valid Merkle-authenticated block is authoritative: trying
                // another peer cannot make the transaction appear in it.
                throw StoryEvidenceError.transactionNotInBlock(evidence.txid, height)
            } catch {
                lastFailure = error.localizedDescription
                await pool.misbehaving(peer, reason: lastFailure)
            }
        }
        throw StoryEvidenceError.blockUnavailable(height, lastFailure)
    }

    /// Pure block inspection used by tests and by the network verifier after
    /// a peer response has been authenticated against the header chain.
    public static func inspect(block: Block, expectedBlockHash: Data,
                               txid: Data, txidText: String,
                               height: UInt32) throws -> StoryVerifiedTransaction {
        guard block.hash == expectedBlockHash else {
            throw StoryEvidenceError.blockHashMismatch(height)
        }
        guard block.hasValidMerkleRoot else {
            throw StoryEvidenceError.invalidMerkleRoot(height)
        }
        guard let transaction = block.transactions.first(where: { $0.txid == txid }) else {
            throw StoryEvidenceError.transactionNotInBlock(txidText, height)
        }
        let parents = transaction.inputs.map(\.previousOutput.txid)
            .filter { $0 != Data(repeating: 0, count: 32) }
            .map(\.displayHex)
        return StoryVerifiedTransaction(txid: txidText.lowercased(), height: height,
                                        blockHash: block.hash.displayHex,
                                        parentTransactionIDs: Array(Set(parents)).sorted())
    }

    private static func verifyBlock(from peer: PeerConnection,
                                    expectedBlockHash: Data, txid: Data,
                                    txidText: String, height: UInt32) async throws
        -> StoryVerifiedTransaction {
        let response = try await peer.request(
            .getdata(InventoryPayload([
                InventoryVector(type: .witnessBlock, hash: expectedBlockHash),
            ])),
            expecting: ["block", "notfound"], timeout: .seconds(120))
        switch response {
        case let .block(block):
            return try inspect(block: block, expectedBlockHash: expectedBlockHash,
                               txid: txid, txidText: txidText, height: height)
        case .notfound:
            throw StoryEvidenceError.blockUnavailable(height, "peer reported that the block was unavailable")
        default:
            throw StoryEvidenceError.blockUnavailable(height, "peer returned an unexpected message")
        }
    }

    private static func internalHash(_ displayHex: String) -> Data? {
        guard let display = Data(hex: displayHex), display.count == 32 else { return nil }
        return Data(display.reversed())
    }
}

public struct StoryEvidenceAudit: Sendable, Equatable {
    public let violations: [String]
    public var passed: Bool { violations.isEmpty }

    public static func evaluate(_ state: StoryRunState) -> StoryEvidenceAudit {
        let evidence = state.transactionEvidence ?? []
        var violations: [String] = []
        for item in evidence where item.confirmationHeight != nil && item.status != .verified {
            violations.append("\(item.label) has not been authenticated against its claimed signet block")
        }

        let minimumVerified: [StoryCheckpoint: Int] = [
            .customerFunding: 1,
            .supplierRBF: 1,
            .inheritanceVault: 3,
            .jointReserve: 2,
        ]
        for (checkpoint, minimum) in minimumVerified {
            guard state.checkpoints[checkpoint.rawValue]?.status == .passed else { continue }
            let count = evidence.filter { $0.checkpoint == checkpoint && $0.status == .verified }.count
            if count < minimum {
                violations.append("\(checkpoint.title) needs at least \(minimum) verified transaction\(minimum == 1 ? "" : "s"); found \(count)")
            }
        }

        let hotIDs = Set(evidence.filter {
            [.customerFunding, .supplierRBF].contains($0.checkpoint)
                && $0.status == .verified
        }.map(\.txid))
        let cold = evidence.filter { $0.checkpoint == .inheritanceVault && $0.status == .verified }
        if state.checkpoints[StoryCheckpoint.inheritanceVault.rawValue]?.status == .passed,
           !cold.contains(where: { !hotIDs.isDisjoint(with: $0.parentTransactionIDs) }) {
            violations.append("no verified Brisa Café hot-wallet transaction feeds the Rivera cold reserve")
        }

        let coldIDs = Set(cold.map(\.txid))
        let joint = evidence.filter { $0.checkpoint == .jointReserve && $0.status == .verified }
        if state.checkpoints[StoryCheckpoint.jointReserve.rawValue]?.status == .passed,
           !joint.contains(where: { !coldIDs.isDisjoint(with: $0.parentTransactionIDs) }) {
            violations.append("no verified cold/recovery transaction feeds the Rivera joint reserve")
        }
        return StoryEvidenceAudit(violations: violations)
    }
}
