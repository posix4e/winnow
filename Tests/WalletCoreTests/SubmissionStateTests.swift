import BlockchainBackend
import Foundation
import Testing
@testable import WalletCore

/// The receipt lifecycle (issue #51): which moves the coordinator may make.
@Suite("Submission state machine")
struct SubmissionStateTests {
    @Test("confirmed is reachable from every other state, because the block path is authoritative")
    func confirmedFromEverywhere() {
        for state in SubmissionState.allCases where state != .confirmed {
            #expect(SubmissionState.allows(state, to: .confirmed), "\(state) → confirmed")
        }
        #expect(!SubmissionState.allows(.confirmed, to: .confirmed))
    }

    @Test("nothing leaves confirmed by transition — only rollBack restores it")
    func nothingLeavesConfirmed() {
        for state in SubmissionState.allCases {
            #expect(!SubmissionState.allows(.confirmed, to: state), "confirmed → \(state)")
        }
    }

    @Test("terminal states only ever move to confirmed")
    func terminalStatesAreTerminal() {
        for from in [SubmissionState.abandoned, .replaced] {
            for to in SubmissionState.allCases where to != .confirmed {
                #expect(!SubmissionState.allows(from, to: to), "\(from) → \(to)")
            }
        }
    }

    @Test("the documented forward edges are allowed and their reverses are not")
    func forwardEdges() {
        let forward: [(SubmissionState, SubmissionState)] = [
            (.constructed, .submitted), (.constructed, .relayed),
            (.submitted, .accepted), (.submitted, .rejected), (.submitted, .relayed),
            (.accepted, .relayed), (.accepted, .submitted), (.accepted, .rejected),
            (.rejected, .submitted), (.rejected, .relayed),
        ]
        for (from, to) in forward {
            #expect(SubmissionState.allows(from, to: to), "\(from) → \(to)")
        }
        // A relayed transaction is public; it does not go back to a miner.
        #expect(!SubmissionState.allows(.relayed, to: .submitted))
        #expect(!SubmissionState.allows(.relayed, to: .accepted))
        #expect(!SubmissionState.allows(.accepted, to: .constructed))
        #expect(!SubmissionState.allows(.rejected, to: .accepted))
    }

    @Test("every non-terminal state can be replaced or abandoned")
    func replacedAndAbandoned() {
        for state in SubmissionState.allCases where !state.isTerminal && state != .confirmed {
            #expect(SubmissionState.allows(state, to: .replaced), "\(state) → replaced")
            #expect(SubmissionState.allows(state, to: .abandoned), "\(state) → abandoned")
        }
    }

    @Test("a receipt refuses an illegal transition and keeps its timeline honest")
    func receiptTransition() throws {
        let raw = Data([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        var receipt = SubmissionReceipt(txid: Data(repeating: 1, count: 32), origin: .walletSend,
                                        route: .export, feeRateSatPerVByte: 2, rawTransaction: raw,
                                        at: Date(timeIntervalSince1970: 100))
        #expect(receipt.state == .constructed)
        #expect(receipt.canReroute)
        #expect(throws: SubmissionError.self) {
            try receipt.transition(to: .accepted, at: Date(timeIntervalSince1970: 101))
        }
        try receipt.transition(to: .relayed, at: Date(timeIntervalSince1970: 102))
        #expect(receipt.timeline.map(\.state) == [.constructed, .relayed])
        #expect(!receipt.canReroute, "public already; no second route")
        try receipt.transition(to: .confirmed, at: Date(timeIntervalSince1970: 103))
        receipt.revertConfirmation(at: Date(timeIntervalSince1970: 104))
        #expect(receipt.state == .relayed, "a reorg restores the state before confirmation")
        #expect(receipt.timeline.last?.state == .relayed)
    }

    @Test("the route helpers say what each route discloses")
    func routeHelpers() {
        #expect(SubmissionRoute.peers.touchesPeers)
        #expect(!SubmissionRoute.minerOnly(.slipstream).touchesPeers)
        #expect(SubmissionRoute.minerAndPeers(.slipstream).touchesPeers)
        #expect(!SubmissionRoute.export.touchesPeers)
        #expect(SubmissionRoute.minerOnly(.slipstream).isPrivateToMiner)
        #expect(!SubmissionRoute.minerAndPeers(.slipstream).isPrivateToMiner)
        #expect(!SubmissionRoute.export.submits)
        #expect(SubmissionRoute.minerAndPeers(.coreRPC).miner == .coreRPC)
        #expect(SubmissionRoute.peers.miner == nil)
    }

    @Test("backoff is pure and capped")
    func backoff() {
        let base = Duration.seconds(15), cap = Duration.seconds(300)
        #expect(SubmissionCoordinator.backoffInterval(attempt: 0, base: base, cap: cap) == .seconds(15))
        #expect(SubmissionCoordinator.backoffInterval(attempt: 1, base: base, cap: cap) == .seconds(30))
        #expect(SubmissionCoordinator.backoffInterval(attempt: 4, base: base, cap: cap) == .seconds(240))
        #expect(SubmissionCoordinator.backoffInterval(attempt: 5, base: base, cap: cap) == .seconds(300))
        #expect(SubmissionCoordinator.backoffInterval(attempt: 40, base: base, cap: cap) == .seconds(300))
        #expect(SubmissionCoordinator.backoffInterval(attempt: -3, base: base, cap: cap) == .seconds(15))
    }
}
