import Darwin
import Foundation
import TestSupport

@main
enum WinnowFixture {
    static let usage = """
        usage: swift run winnow-fixture prepare-bank
               swift run winnow-fixture multisig-differential [--seed HEX] [--cases N]
        """

    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        switch arguments.first {
        case "prepare-bank" where arguments.count == 1:
            await prepareBank()
        case "multisig-differential":
            multisigDifferential(Array(arguments.dropFirst()))
        default:
            print(usage)
            exit(arguments == ["--help"] ? 0 : 2)
        }
    }

    static func prepareBank() async {
        let started = Date()
        do {
            try await SignetFixture.prepareBank()
            print("SIGNET_BANK_PREPARATION_SECONDS=\(Date().timeIntervalSince(started))")
        } catch {
            FileHandle.standardError.write(Data("Fixture preparation failed: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }

    static func multisigDifferential(_ arguments: [String]) {
        var options = MultisigDifferential.Options()
        var rest = arguments[...]
        while let flag = rest.popFirst() {
            switch (flag, rest.popFirst()) {
            case let ("--seed", value?) where UInt64(value, radix: 16) != nil:
                options.seed = UInt64(value, radix: 16)!
            case let ("--cases", value?) where Int(value).map({ $0 > 0 }) == true:
                options.cases = Int(value)!
            default:
                print(usage)
                exit(2)
            }
        }
        do {
            let tally = try MultisigDifferential.run(options)
            for (kind, count) in tally.agreed.sorted(by: { $0.key < $1.key }) {
                print("agree  \(count)\t\(kind)")
            }
            for disagreement in tally.disagreements {
                print("DISAGREE \(disagreement)")
            }
            let total = tally.agreed.values.reduce(0, +)
            print("MULTISIG_DIFFERENTIAL agreed=\(total) disagreed=\(tally.disagreements.count) "
                + "seed=\(String(options.seed, radix: 16)) cases=\(options.cases)")
            exit(tally.disagreements.isEmpty ? 0 : 1)
        } catch {
            FileHandle.standardError.write(Data("Multisig differential failed: \(error)\n".utf8))
            exit(1)
        }
    }
}
