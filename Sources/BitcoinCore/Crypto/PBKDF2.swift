import CommonCrypto
import Foundation

public enum PBKDF2Error: Error {
    case derivationFailed(Int32)
}

/// PBKDF2 key derivation via CommonCrypto (BIP39 uses HMAC-SHA512, 2048 rounds).
public enum PBKDF2 {
    public static func hmacSHA512(password: Data, salt: Data, rounds: Int = 2048, keyLength: Int = 64) throws -> Data {
        var derived = Data(count: keyLength)
        let status: Int32 = password.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                derived.withUnsafeMutableBytes { derivedBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress, password.count,
                        saltBytes.baseAddress, salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        UInt32(rounds),
                        derivedBytes.baseAddress, keyLength
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw PBKDF2Error.derivationFailed(status) }
        return derived
    }
}
