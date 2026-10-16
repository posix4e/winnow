import Foundation
import Testing
import TestSupport
@testable import WalletCore

@Suite("Explicit fee resolution")
struct FeeResolutionTests {
    @Test("an explicit cap reports a higher peer floor instead of silently pricing below it")
    func cappedFloor() {
        let quote = FeePolicy.resolution(estimated: 10, observed: [5],
                                         floorSatPerVByte: 200, peerFloorCap: 120)
        #expect(quote.rate == 120)
        #expect(quote.clampedFloor == 200)
        let override = FeePolicy.resolution(override: 250, floorSatPerVByte: 200, peerFloorCap: 120)
        #expect(override.rate == 250)
        #expect(override.clampedFloor == nil)
        let observed = FeePolicy.resolution(observed: [300], floorSatPerVByte: 200, peerFloorCap: 120)
        #expect(observed.rate == 300)
        #expect(observed.clampedFloor == nil)
    }

    @Test("estimates cannot undercut our observed median and overrides remain explicit")
    func estimateOrder() {
        #expect(FeePolicy.resolution(estimated: 1, observed: [10, 30]).rate == 20)
        #expect(FeePolicy.resolution(estimated: 40, observed: [10, 30]).rate == 40)
        #expect(FeePolicy.resolution(override: 1, estimated: 40, observed: [30]).rate == 1)
        #expect(FeePolicy.resolution(priority: .high).rate == 12)
    }

    @Test("invalid inputs fall through rather than reaching coin selection",
          arguments: [Double.nan, .infinity, -.infinity, -1, 0, 10_001])
    func invalidRates(_ rate: Double) {
        let quote = FeePolicy.resolution(override: rate, estimated: rate, observed: [rate, 7],
                                         floorSatPerVByte: rate, peerFloorCap: 120)
        #expect(quote.rate == 7)
        #expect(quote.clampedFloor == nil)
        #expect(!FeePolicy.acceptsRate(rate), "and the caller can tell before it substitutes")
    }

    @Test("only nil means uncapped: a cap of zero refuses every automatic increase and says so")
    func explicitCaps() {
        let none = FeePolicy.resolution(priority: .low, floorSatPerVByte: 2_000, peerFloorCap: 0)
        #expect(none.rate == 2)
        #expect(none.clampedFloor == 2_000)
        let negative = FeePolicy.resolution(priority: .low, floorSatPerVByte: 2_000, peerFloorCap: -5)
        #expect(negative == none)
        let huge = FeePolicy.resolution(priority: .low, floorSatPerVByte: 2_000, peerFloorCap: 1e9)
        #expect(huge.rate == 2_000)
        #expect(huge.clampedFloor == nil)
        #expect(FeePolicy.resolution(priority: .low, floorSatPerVByte: 2_000, peerFloorCap: nil).rate == 2_000)
        #expect(FeePolicy.acceptsRate(1) && FeePolicy.acceptsRate(10_000))
    }

    @Test("the shared default caps automatic peer-driven fees and reports a required decision")
    func defaultUnchanged() {
        #expect(FeePolicy.resolution(floorSatPerVByte: 200).rate == 120)
        #expect(FeePolicy.resolution(floorSatPerVByte: 200).clampedFloor == 200)
        #expect(FeePolicy.resolution(floorSatPerVByte: 200, peerFloorCap: nil).rate == 200)
        // The uncapped rule keeps its meaning: never below the reported floor.
        #expect(FeePolicy.resolve(floorSatPerVByte: 200) == 200)
        #expect(FeePolicy.resolve(override: 300, floorSatPerVByte: 200) == 300)
    }

    @Test("the live pool uses configured-seat majority rather than the first or highest report")
    func livePoolMajority() async throws {
        let synthetic = makeSyntheticChain()
        let nodes = (0 ..< 3).map { _ in LoopbackNode(params: synthetic.params, chain: synthetic.blocks) }
        for node in nodes { try await node.start() }
        var endpoints: [PeerEndpoint] = []
        for node in nodes { endpoints.append(await node.endpoint) }
        let pool = PeerPool(params: synthetic.params, peerCount: 3, manualPeers: endpoints)
        await pool.start()
        defer { Task { await pool.stop(); for node in nodes { await node.stop() } } }
        #expect(await pool.connectedPeers().count == 3)
        // Nobody has reported: no majority floor, and nobody connected refuses anything.
        #expect(await pool.feeFilterFloorSatPerVByte() == nil)
        #expect(await pool.feeFilterFloorSatPerVByte(aggregation: .mostLenient) == nil)
        try await nodes[0].send(.feefilter(200_000))
        #expect(await pollUntil(.seconds(3)) { await pool.feeFilterFloorSatPerVByte(aggregation: .strictest) == 200 })
        #expect(await pool.feeFilterFloorSatPerVByte() == nil)
        #expect(await pool.feeFilterFloorSatPerVByte(aggregation: .mostLenient) == nil,
                "two seats have not reported, and each would still relay anything")
        try await nodes[1].send(.feefilter(2_000))
        #expect(await pollUntil(.seconds(3)) { await pool.feeFilterFloorSatPerVByte() == 2 })
        try await nodes[2].send(.feefilter(3_000))
        #expect(await pollUntil(.seconds(3)) { await pool.feeFilterFloorSatPerVByte() == 3 })
        #expect(await pool.feeFilterFloorSatPerVByte(aggregation: .strictest) == 200)
        #expect(await pool.feeFilterFloorSatPerVByte(aggregation: .mostLenient) == 2,
                "the lowest floor anyone connected reports is the rate below which nobody relays")
    }

    @Test("a lone reporting peer cannot impose a floor on a three-seat pool")
    func seatMajority() {
        #expect(FeePolicy.seatMajorityFloor(reported: [200], seats: 3) == nil)
        #expect(FeePolicy.seatMajorityFloor(reported: [2, 200], seats: 3) == 2)
        #expect(FeePolicy.seatMajorityFloor(reported: [2, 3, 200], seats: 3) == 3)
        #expect(FeePolicy.seatMajorityFloor(reported: [200], seats: 1) == 200)
        #expect(FeePolicy.seatMajorityFloor(reported: [], seats: 0) == nil)
        #expect(FeePolicy.seatMajorityFloor(reported: [.nan, 200], seats: 3) == nil)
    }
}
