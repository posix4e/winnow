import Winnow.Crypto.Bech32
import Winnow.Keys.Secp256k1

/-! # BIP352 silent payment codes: decoding only

The decoding half of `Sources/WalletCore/SilentPayments/SilentPaymentAddress.swift` (upstream 1cf93fb):
history entries may name the code an output was paid to, and a bundle or wallet file naming one that does
not parse is refused (`HistoryEntry.Outputs.validate`). Sending to silent payments (BIP352 output
derivation) is deferred, so there is no encoder and no sending here. -/

namespace Winnow

inductive SilentPaymentAddressError where
  | invalidEncoding
  | wrongHRP (expected actual : String)
  | unsupportedVersion (version : Nat)
  | invalidDataLength (length : Nat)
  | invalidPublicKey
  deriving Inhabited, BEq

def SilentPaymentAddressError.name : SilentPaymentAddressError → String
  | .invalidEncoding => "invalidEncoding" | .wrongHRP .. => "wrongHRP" | .unsupportedVersion _ => "unsupportedVersion"
  | .invalidDataLength _ => "invalidDataLength" | .invalidPublicKey => "invalidPublicKey"

structure SilentPaymentAddress where
  scanKey : ByteArray
  spendKey : ByteArray
  hrp : String
  deriving Inhabited, BEq

namespace SilentPaymentAddress

def version : Nat := 0
def maxAddressLength : Nat := 1023

def isValidPublicKey (key : ByteArray) : Bool := (Keys.parsePublicKey key).toOption.isSome

/-- `SilentPaymentAddress(_:expectedHRP:)`: bech32m, version 0, a 66-byte payload of two valid compressed
public keys. -/
def parse (string : String) (expectedHRP : Option String := none) : Except SilentPaymentAddressError SilentPaymentAddress := do
  let (hrp, data, encoding) ← match Bech32.decode string maxAddressLength with
    | .ok d => pure d
    | .error _ => throw .invalidEncoding
  unless encoding == .bech32m do throw .invalidEncoding
  if let some expected := expectedHRP then
    if hrp != expected then throw (.wrongHRP expected hrp)
  let v := (data.head?.map (·.toNat)).getD 0
  unless v == version do throw (.unsupportedVersion v)
  let payload ← match SegwitAddress.convertBits data.tail 5 8 false with
    | .ok p => pure p
    | .error _ => throw .invalidEncoding
  unless payload.length == 66 do throw (.invalidDataLength payload.length)
  let scanKey := ByteArray.mk (payload.take 33).toArray
  let spendKey := ByteArray.mk (payload.drop 33).toArray
  unless isValidPublicKey scanKey && isValidPublicKey spendKey do throw .invalidPublicKey
  return { scanKey, spendKey, hrp }

end SilentPaymentAddress
end Winnow
