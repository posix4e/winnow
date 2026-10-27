import Winnow.Keys.Ed25519
import Winnow.Keys.FoundationJSON
import Winnow.Keys.Unicode

/-! # The census publisher's signature (port of `Network/Peers/CensusSignature.swift`)

Ed25519 over a domain tag and the exact bytes of `peers.json`, in a small JSON document
`{"algorithm":"ed25519","publicKey":…,"signature":…}`. Public keys are raw 32-byte Ed25519 keys. -/

namespace Winnow.Keys

/-- WalletCore's `Data(hex:)`: trims whitespace and newlines, then pairs of characters, each parsed as
Swift's `UInt8(_, radix: 16)` (which takes a sign: `+f` is 15, `-0` is 0). -/
def dataOfHex? (s : String) : Option ByteArray := Id.run do
  let cs := (Unicode.trimWhitespace s).toList.toArray
  if cs.isEmpty || cs.size % 2 != 0 then return none
  let digit (c : Char) : Option Nat :=
    if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
    else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
    else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
    else none
  let mut out := ByteArray.empty
  for i in [0:cs.size / 2] do
    let a := cs[2 * i]!
    let b := cs[2 * i + 1]!
    let v : Option Nat := match a, digit a, digit b with
      | _, some x, some y => some (16 * x + y)
      | '+', none, some y => some y
      | '-', none, some 0 => some 0
      | _, _, _ => none
    match v with
    | some x => out := out.push x.toUInt8
    | none => return none
  return some out

/-- Foundation's `JSONEncoder` string escaping (slashes escaped, controls as `\uXXXX`). -/
def foundationJSONString (s : String) : String := Id.run do
  let hexd := "0123456789abcdef".toList.toArray
  let mut out := "\""
  for c in s.toList do
    out := out ++ match c with
      | '"' => "\\\"" | '\\' => "\\\\" | '/' => "\\/"
      | '\x08' => "\\b" | '\x0c' => "\\f" | '\n' => "\\n" | '\r' => "\\r" | '\t' => "\\t"
      | c => if c.toNat < 0x20 then
               "\\u00" ++ String.singleton hexd[c.toNat / 16]! ++ String.singleton hexd[c.toNat % 16]!
             else String.singleton c
  return out ++ "\""

structure CensusSignature where
  algorithm : String
  /-- The signer's public key, 32 bytes hex. -/
  publicKey : String
  /-- 64 bytes hex. -/
  signature : String
  deriving Repr, DecidableEq

namespace CensusSignature

inductive Invalid where
  | malformed | unknownKey | signature | missing
  deriving Repr, DecidableEq

def Invalid.name : Invalid → String
  | .malformed => "malformed" | .unknownKey => "unknownKey" | .signature => "signature" | .missing => "missing"

def Invalid.errorDescription : Invalid → String
  | .malformed => "The census signature is malformed."
  | .unknownKey => "The census was signed with a key this wallet does not trust."
  | .signature => "The census signature does not match the downloaded list."
  | .missing => "The census is not signed, and this wallet requires a signature."

def algorithmName : String := "ed25519"
def maximumBytes : Nat := 1024
def domain : ByteArray := "winnow-census-peers-v1".toUTF8 ++ ByteArray.mk #[0]

def decode (data : ByteArray) : Except Invalid CensusSignature := do
  if data.size > maximumBytes then throw .malformed
  let some ms := FoundationJSON.members data | throw .malformed
  let some algorithm := FoundationJSON.stringField ms "algorithm" | throw .malformed
  let some publicKey := FoundationJSON.stringField ms "publicKey" | throw .malformed
  let some signature := FoundationJSON.stringField ms "signature" | throw .malformed
  if algorithm != algorithmName then throw .malformed
  if (dataOfHex? publicKey).map (·.size) != some 32 then throw .malformed
  if (dataOfHex? signature).map (·.size) != some 64 then throw .malformed
  return { algorithm, publicKey, signature }

/-- `JSONEncoder` with sorted keys, then a newline. -/
def encoded (c : CensusSignature) : ByteArray :=
  ("{\"algorithm\":" ++ foundationJSONString c.algorithm ++ ",\"publicKey\":" ++ foundationJSONString c.publicKey ++
   ",\"signature\":" ++ foundationJSONString c.signature ++ "}\n").toUTF8

/-- Signs with a 32-byte Ed25519 seed (deterministic; CryptoKit's signatures are randomized). -/
def sign (payload seed : ByteArray) : Except Ed25519.Error CensusSignature := do
  let pk ← Ed25519.publicKey seed
  let sig ← Ed25519.sign seed (domain ++ payload)
  return { algorithm := algorithmName, publicKey := hex pk, signature := hex sig }

/-- Verifies `payload` under whichever of `trusted` (raw 32-byte keys) signed it. -/
def verify (c : CensusSignature) (payload : ByteArray) (trusted : List ByteArray) : Except Invalid Unit := do
  let (some keyBytes, some sigBytes) := (dataOfHex? c.publicKey, dataOfHex? c.signature) | throw .malformed
  let some key := trusted.find? (· == keyBytes) | throw .unknownKey
  if !Ed25519.verify key sigBytes (domain ++ payload) then throw .signature

end CensusSignature

namespace CensusPublisher

/-- The publisher key established on 2026-09-18. -/
def trustedKeysHex : List String := ["b999d0881c236f3f38dce334bd373c75b936677bbed952685745486131d32b74"]

def trustedKeys : List ByteArray :=
  trustedKeysHex.filterMap fun h => (dataOfHex? h).filter (·.size == 32)

/-- Requires a signature from an explicitly trusted publisher. -/
def verify (payload : ByteArray) (signature : Option ByteArray) (keys : List ByteArray) :
    Except CensusSignature.Invalid Unit := do
  if keys.isEmpty then throw .unknownKey
  let some sig := signature | throw .missing
  (← CensusSignature.decode sig).verify payload keys

end CensusPublisher
end Winnow.Keys
