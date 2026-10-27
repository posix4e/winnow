import Winnow.Tx.Script

/-! # Multisig: BIP387 `multi_a` / `sortedmulti_a` tapscripts

Port of `Sources/WalletCore/Script/Multisig.swift`. -/

namespace Winnow

inductive MultisigError where
  | invalidThreshold | tooManyKeys | invalidKey
  deriving Repr, BEq, Inhabited

def MultisigError.name : MultisigError → String
  | .invalidThreshold => "invalidThreshold" | .tooManyKeys => "tooManyKeys" | .invalidKey => "invalidKey"

namespace Multisig

def maxKeys : Nat := 999

/-- `<KEY_1> OP_CHECKSIG <KEY_2> OP_CHECKSIGADD … <KEY_n> OP_CHECKSIGADD <k> OP_NUMEQUAL` from 32-byte
x-only keys, sorted lexicographically first when `sorted`. -/
def script (k : Int) (keys : Array ByteArray) (sorted : Bool) : Except MultisigError Script := do
  unless k ≥ 1 && k ≤ keys.size do throw .invalidThreshold
  unless keys.size ≤ maxKeys do throw .tooManyKeys
  unless keys.all (·.size == 32) do throw .invalidKey
  let ordered := if sorted then sortBytes id keys else keys
  return Script.build fun s => Id.run do
    let mut s := s
    for h : i in [0:ordered.size] do
      s := (s.appendPush ordered[i]).appendOpcode (if i == 0 then Script.Op.checkSig else Script.Op.checkSigAdd)
    return (s.appendScriptNumber k.toNat).appendOpcode Script.Op.numEqual

/-- The `<k> OP_NUMEQUAL` trailer. For k > 16 the push is read as Swift reads it: little-endian into a
64-bit `Int`, bytes past the eighth shifted out (Swift's `<<` by 64 or more gives 0), so a long push can
come back negative. -/
def parseTrailer (b : ByteArray) : Option Int :=
  if !(b.size ≥ 2 && b[b.size - 1]! == Script.Op.numEqual) then none
  else
    let head := b[0]!
    if 0x51 ≤ head && head ≤ 0x60 then
      if b.size == 2 then some (head.toNat - 0x50 : Nat) else none
    else
      let length := head.toNat
      if !(length ≥ 1 && b.size == 2 + length) then none
      else Id.run do
        let mut value : UInt64 := 0
        for i in [0:length] do
          if 8 * i < 64 then value := value ||| (b[1 + i]!.toUInt64 <<< (8 * i).toUInt64)
        let top := b[length]!
        if top == 0 && length > 1 && b[length - 1]! &&& 0x80 == 0 then return none
        if top &&& 0x80 != 0 then return none
        return some value.toInt64.toInt

/-- Threshold and keys, in script order, of a script with exactly the canonical shape `script`
emits; `none` otherwise. -/
def parse (s : Script) : Option (Int × Array ByteArray) := Id.run do
  let mut bytes := s.bytes
  let mut keys : Array ByteArray := #[]
  while bytes.size > 0 do
    if !(bytes[0]! == 0x20 && bytes.size ≥ 34) then return none
    keys := keys.push (bytes.extract 1 33)
    let expected := if keys.size == 1 then Script.Op.checkSig else Script.Op.checkSigAdd
    if bytes[33]! != expected then return none
    bytes := bytes.extract 34 bytes.size
    if keys.size > maxKeys then return none
    if let some k := parseTrailer bytes then return some (k, keys)
  return none

end Multisig
end Winnow
