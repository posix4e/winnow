import CryptoKit
import Foundation

public enum Base58Error: Error, Equatable {
    case invalidCharacter(Character)
    case invalidChecksum
    case invalidLength
}

/// Base58 / Base58Check encoding (BIP32 xprv/xpub serialization).
public enum Base58 {
    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

    public static func encode(_ data: Data) -> String {
        let leadingZeros = data.prefix { $0 == 0 }.count
        var digits: [UInt8] = []
        for byte in data.dropFirst(leadingZeros) {
            var carry = Int(byte)
            for i in digits.indices {
                carry += Int(digits[i]) << 8
                digits[i] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }
        var result: [UInt8] = Array(repeating: alphabet[0], count: leadingZeros)
        for digit in digits.reversed() { result.append(alphabet[Int(digit)]) }
        return String(bytes: result, encoding: .utf8)!
    }

    public static func decode(_ string: String) throws -> Data {
        let leadingOnes = string.prefix { $0 == "1" }.count
        var bytes: [UInt8] = []
        for char in string.dropFirst(leadingOnes) {
            guard char.isASCII, let value = alphabet.firstIndex(of: char.asciiValue!) else {
                throw Base58Error.invalidCharacter(char)
            }
            var carry = value
            for i in bytes.indices {
                carry += Int(bytes[i]) * 58
                bytes[i] = UInt8(carry & 0xFF)
                carry >>= 8
            }
            while carry > 0 {
                bytes.append(UInt8(carry & 0xFF))
                carry >>= 8
            }
        }
        return Data(Array(repeating: 0, count: leadingOnes) + bytes.reversed())
    }
}

public enum Base58Check {
    public static func encode(_ payload: Data) -> String {
        let checksum = Data(SHA256.hash(data: Data(SHA256.hash(data: payload))).prefix(4))
        return Base58.encode(payload + checksum)
    }

    public static func decode(_ string: String) throws -> Data {
        let decoded = try Base58.decode(string)
        guard decoded.count >= 4 else { throw Base58Error.invalidLength }
        let payload = decoded.prefix(decoded.count - 4)
        let checksum = Data(SHA256.hash(data: Data(SHA256.hash(data: payload))).prefix(4))
        guard checksum == decoded.suffix(4) else { throw Base58Error.invalidChecksum }
        return Data(payload)
    }
}
