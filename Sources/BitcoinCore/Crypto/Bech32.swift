import Foundation

public enum Bech32Error: Error, Equatable {
    case invalidCharacter
    case mixedCase
    case missingSeparator
    case emptyHRP
    case invalidChecksum
    case tooLong
    case invalidDataValue
    case invalidWitnessVersion
    case invalidProgramLength
    case invalidPadding
    case invalidHRP
}

/// Bech32/Bech32m encoding (BIP173/BIP350). Taproot (witness v1+) uses Bech32m.
public enum Bech32 {
    public enum Encoding {
        case bech32
        case bech32m

        var checksumConstant: UInt32 {
            switch self {
            case .bech32: 1
            case .bech32m: 0x2BC8_30A3
            }
        }
    }

    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        let generators: [UInt32] = [0x3B6A_57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3]
        var chk: UInt32 = 1
        for value in values {
            let top = chk >> 25
            chk = (chk & 0x1FF_FFFF) << 5 ^ UInt32(value)
            for i in 0 ..< 5 where (top >> i) & 1 == 1 {
                chk ^= generators[i]
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: [UInt8]) -> [UInt8] {
        hrp.map { $0 >> 5 } + [0] + hrp.map { $0 & 31 }
    }

    /// `maxLength` is the BIP173 90-char limit by default; a scheme that
    /// defines a longer ceiling passes its own.
    public static func encode(hrp: String, data: [UInt8], encoding: Encoding,
                              maxLength: Int = 90) throws -> String {
        guard !hrp.isEmpty, hrp.utf8.allSatisfy({ $0 >= 33 && $0 <= 126 }) else {
            throw Bech32Error.emptyHRP
        }
        let hrpBytes = Array(hrp.lowercased().utf8)
        var checksumInput = hrpExpand(hrpBytes) + data + [UInt8](repeating: 0, count: 6)
        let mod = polymod(checksumInput) ^ encoding.checksumConstant
        checksumInput = (0 ..< 6).map { UInt8((mod >> UInt32(5 * (5 - $0))) & 31) }
        let combined = data + checksumInput
        guard hrpBytes.count + 1 + combined.count <= maxLength else { throw Bech32Error.tooLong }
        return String(bytes: hrpBytes + [0x31] + combined.map { charset[Int($0)] }, encoding: .utf8)!
    }

    public static func decode(_ string: String, maxLength: Int = 90) throws -> (hrp: String, data: [UInt8], encoding: Encoding) {
        guard string.count <= maxLength else { throw Bech32Error.tooLong }
        guard string.range(of: "[A-Z]", options: .regularExpression) == nil ||
            string.range(of: "[a-z]", options: .regularExpression) == nil
        else { throw Bech32Error.mixedCase }
        let lowered = string.lowercased()
        guard lowered.utf8.allSatisfy({ $0 >= 33 && $0 <= 126 }) else { throw Bech32Error.invalidCharacter }
        guard let separator = lowered.lastIndex(of: "1") else { throw Bech32Error.missingSeparator }
        let hrp = String(lowered.prefix(upTo: separator))
        guard !hrp.isEmpty else { throw Bech32Error.emptyHRP }
        let dataPart = lowered.suffix(from: lowered.index(after: separator))
        guard dataPart.count >= 6 else { throw Bech32Error.invalidChecksum }
        var values: [UInt8] = []
        values.reserveCapacity(dataPart.count)
        for char in dataPart.utf8 {
            guard let value = charset.firstIndex(of: char) else { throw Bech32Error.invalidCharacter }
            values.append(UInt8(value))
        }
        let constant = polymod(hrpExpand(Array(hrp.utf8)) + values)
        let encoding: Encoding = switch constant {
        case Encoding.bech32.checksumConstant: .bech32
        case Encoding.bech32m.checksumConstant: .bech32m
        default: throw Bech32Error.invalidChecksum
        }
        return (hrp, Array(values.dropLast(6)), encoding)
    }
}

/// Segwit address encoding/decoding on top of Bech32 (BIP173/BIP350).
public enum SegwitAddress {
    public static func encode(hrp: String, version: Int, program: Data) throws -> String {
        guard version >= 0, version <= 16 else { throw Bech32Error.invalidWitnessVersion }
        guard program.count >= 2, program.count <= 40 else { throw Bech32Error.invalidProgramLength }
        if version == 0, program.count != 20, program.count != 32 {
            throw Bech32Error.invalidProgramLength
        }
        let data = try [UInt8(version)] + convertBits(Array(program), from: 8, to: 5, pad: true)
        return try Bech32.encode(hrp: hrp, data: data, encoding: version == 0 ? .bech32 : .bech32m)
    }

    public static func decode(_ string: String, expectedHRP: String? = nil) throws -> (version: Int, program: Data) {
        let (hrp, values, encoding) = try Bech32.decode(string)
        if let expectedHRP, hrp != expectedHRP { throw Bech32Error.invalidHRP }
        guard let first = values.first, first <= 16 else { throw Bech32Error.invalidWitnessVersion }
        let program = try convertBits(Array(values.dropFirst()), from: 5, to: 8, pad: false)
        guard program.count >= 2, program.count <= 40 else { throw Bech32Error.invalidProgramLength }
        let version = Int(first)
        if version == 0 {
            guard encoding == .bech32 else { throw Bech32Error.invalidChecksum }
            guard program.count == 20 || program.count == 32 else { throw Bech32Error.invalidProgramLength }
        } else if encoding != .bech32m {
            throw Bech32Error.invalidChecksum
        }
        return (version, Data(program))
    }

    static func convertBits(_ input: [UInt8], from: Int, to: Int, pad: Bool) throws -> [UInt8] {
        var accumulator = 0
        var bits = 0
        var output: [UInt8] = []
        let maxValue = (1 << to) - 1
        let maxAccumulator = (1 << (from + to - 1)) - 1
        for value in input {
            guard Int(value) >> from == 0 else { throw Bech32Error.invalidDataValue }
            accumulator = ((accumulator << from) | Int(value)) & maxAccumulator
            bits += from
            while bits >= to {
                bits -= to
                output.append(UInt8((accumulator >> bits) & maxValue))
            }
        }
        if pad {
            if bits > 0 { output.append(UInt8((accumulator << (to - bits)) & maxValue)) }
        } else {
            guard bits < from else { throw Bech32Error.invalidPadding }
            guard (accumulator << (to - bits)) & maxValue == 0 else { throw Bech32Error.invalidPadding }
        }
        return output
    }
}
