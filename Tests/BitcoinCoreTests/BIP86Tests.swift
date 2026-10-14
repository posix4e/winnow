import Foundation
import P256K
import Testing
import TestSupport
@testable import BitcoinCore
@testable import WalletCore

/// BIP86 test vectors parsed from bip-0086.mediawiki.
@Suite("BIP86")
struct BIP86Tests {
    struct AddressVector {
        let path: String
        let xprv: String
        let xpub: String
        let internalKey: Data
        let outputKey: Data
        let scriptPubKey: Data
        let address: String
    }

    struct Vectors {
        let mnemonic: String
        let rootpriv: String
        let rootpub: String
        let accountXprv: String
        let accountXpub: String
        let addresses: [AddressVector]
    }

    static func vectors() throws -> Vectors {
        let text = try TestSupport.Vectors.string("bip-0086.mediawiki", in: .module)
        // The document has several <pre> blocks; the test vectors are the one with the mnemonic.
        var body: Substring?
        for chunk in text.components(separatedBy: "<pre>") {
            guard let end = chunk.range(of: "</pre>") else { continue }
            if chunk.contains("mnemonic =") { body = chunk[..<end.lowerBound] }
        }
        guard let body else { throw VectorError.malformed("no <pre> block with vectors") }

        var mnemonic = "", rootpriv = "", rootpub = "", accountXprv = "", accountXpub = ""
        var addresses: [AddressVector] = []
        var currentPath: String?
        var fields: [String: String] = [:]

        func flush() {
            if let currentPath, let xprv = fields["xprv"], let xpub = fields["xpub"],
               let internalKey = fields["internal_key"].flatMap(Data.init(hex:)),
               let outputKey = fields["output_key"].flatMap(Data.init(hex:)),
               let scriptPubKey = fields["scriptPubKey"].flatMap(Data.init(hex:)),
               let address = fields["address"]
            {
                addresses.append(AddressVector(path: currentPath, xprv: xprv, xpub: xpub,
                                               internalKey: internalKey, outputKey: outputKey,
                                               scriptPubKey: scriptPubKey, address: address))
            }
            currentPath = nil
            fields = [:]
        }

        for rawLine in body.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("//") {
                flush()
                if let eq = line.range(of: "= "), line[eq.upperBound...].hasPrefix("m/") {
                    currentPath = String(line[eq.upperBound...])
                }
            } else if let eq = line.range(of: " = "), !line.hasPrefix("//") {
                let key = String(line[line.startIndex ..< eq.lowerBound]).trimmingCharacters(in: .whitespaces)
                let value = String(line[eq.upperBound...]).trimmingCharacters(in: .whitespaces)
                switch key {
                case "mnemonic": mnemonic = value
                case "rootpriv": rootpriv = value
                case "rootpub": rootpub = value
                default: fields[key] = value
                }
                if key == "xpub", currentPath == "m/86'/0'/0'" {
                    accountXpub = value
                }
                if key == "xprv", currentPath == "m/86'/0'/0'" {
                    accountXprv = value
                }
            }
        }
        flush()
        return Vectors(mnemonic: mnemonic, rootpriv: rootpriv, rootpub: rootpub,
                       accountXprv: accountXprv, accountXpub: accountXpub, addresses: addresses)
    }

    @Test("vector block parsed")
    func parsed() throws {
        let vectors = try Self.vectors()
        #expect(vectors.mnemonic.hasPrefix("abandon abandon"))
        #expect(vectors.addresses.count == 3)
        #expect(!vectors.accountXprv.isEmpty && !vectors.accountXpub.isEmpty)
    }

    @Test("root and account keys")
    func rootAndAccount() throws {
        let vectors = try Self.vectors()
        let seed = try BIP39.seed(mnemonic: vectors.mnemonic)
        let master = try HDKey(seed: seed)
        #expect(master.serialized() == vectors.rootpriv)
        #expect(master.neutered.serialized() == vectors.rootpub)
        let account = try BIP86.accountKey(from: master)
        #expect(account.serialized() == vectors.accountXprv)
        #expect(account.neutered.serialized() == vectors.accountXpub)
    }

    @Test("address derivation: internal key, tweak, scriptPubKey, address")
    func addressDerivation() throws {
        let vectors = try Self.vectors()
        let seed = try BIP39.seed(mnemonic: vectors.mnemonic)
        let master = try HDKey(seed: seed)
        for vector in vectors.addresses {
            let key = try master.derived(path: vector.path)
            #expect(key.serialized() == vector.xprv, "\(vector.path)")
            #expect(key.neutered.serialized() == vector.xpub, "\(vector.path)")

            let internalKey = BIP86.xonlyPublicKey(of: key)
            #expect(internalKey == vector.internalKey, "\(vector.path)")
            #expect(try BIP86.tweakedOutputKey(internalKey: internalKey) == vector.outputKey, "\(vector.path)")
            #expect(try BIP86.scriptPubKey(internalKey: internalKey) == vector.scriptPubKey, "\(vector.path)")
            #expect(try BIP86.address(internalKey: internalKey) == vector.address, "\(vector.path)")

            // The tweaked private key must correspond to the tweaked output key.
            let tweakedSecret = try BIP86.tweakedPrivateKey(key.privateKey!)
            let tweakedXonly = try P256K.Schnorr.PrivateKey(dataRepresentation: tweakedSecret).xonly
            #expect(Data(tweakedXonly.bytes) == vector.outputKey, "\(vector.path)")
        }
    }
}
