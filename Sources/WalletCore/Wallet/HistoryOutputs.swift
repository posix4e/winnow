import Foundation

extension HistoryEntry {
    /// A known output breakdown. Wallet-owned receive outputs are omitted;
    /// change contains vouts, and external contains recipients in transaction order.
    public struct Outputs: Equatable, Sendable, Codable {
        public var external: [ExternalOutput]
        public var change: [UInt32]

        public init(external: [ExternalOutput] = [], change: [UInt32] = []) {
            self.external = external
            self.change = change
        }

        private enum CodingKeys: String, CodingKey { case external, change }

        public init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.init(external: try container.decodeIfPresent([ExternalOutput].self, forKey: .external) ?? [],
                      change: try container.decodeIfPresent([UInt32].self, forKey: .change) ?? [])
            try validate()
        }

        func validate() throws {
            let vouts = external.map(\.vout)
            guard zip(vouts, vouts.dropFirst()).allSatisfy({ $0 < $1 }),
                  zip(change, change.dropFirst()).allSatisfy({ $0 < $1 }),
                  Set(vouts).isDisjoint(with: change)
            else { throw WalletError.invalidBundle("history output indices contradict each other") }
            var total: Int64 = 0
            for output in external {
                guard output.amount > 0, output.amount <= BitcoinAmount.maximum - total,
                      !output.scriptPubKey.isEmpty
                else { throw WalletError.invalidBundle("history output has an invalid amount or script") }
                total += output.amount
            }
        }

        /// A breakdown with available transaction bytes must describe those
        /// exact outputs. Without bytes it remains display metadata, never proof
        /// of inclusion or authority to spend a coin.
        func validate(against transaction: Transaction) throws {
            for output in external {
                guard transaction.outputs.indices.contains(Int(output.vout)),
                      transaction.outputs[Int(output.vout)].value == output.amount,
                      transaction.outputs[Int(output.vout)].scriptPubKey == output.scriptPubKey
                else { throw WalletError.invalidBundle("history outputs do not match the transaction") }
            }
            guard change.allSatisfy({ transaction.outputs.indices.contains(Int($0)) })
            else { throw WalletError.invalidBundle("history change index is outside the transaction") }
        }
    }

    public struct ExternalOutput: Equatable, Sendable, Codable {
        public var vout: UInt32
        public var amount: Int64
        /// JSON uses hexadecimal, matching wallet coin scripts.
        public var scriptPubKey: Data

        public init(vout: UInt32, amount: Int64, scriptPubKey: Data) {
            self.vout = vout
            self.amount = amount
            self.scriptPubKey = scriptPubKey
        }

        private enum CodingKeys: String, CodingKey { case vout, amount, scriptPubKey }

        public init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            guard let script = Data(hex: try container.decode(String.self, forKey: .scriptPubKey)) else {
                throw DecodingError.dataCorruptedError(forKey: .scriptPubKey, in: container,
                                                       debugDescription: "bad recipient script hex")
            }
            self.init(vout: try container.decode(UInt32.self, forKey: .vout),
                      amount: try container.decode(Int64.self, forKey: .amount), scriptPubKey: script)
        }

        public func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(vout, forKey: .vout)
            try container.encode(amount, forKey: .amount)
            try container.encode(scriptPubKey.hex, forKey: .scriptPubKey)
        }
    }
}
