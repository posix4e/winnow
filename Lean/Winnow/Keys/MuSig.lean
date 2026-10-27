import Winnow.Keys.BIP32
import Winnow.Keys.Taproot

/-! # BIP327 MuSig2 key aggregation (port of `Descriptors/MuSig.swift`)

Over plain 33-byte compressed public keys, as BIP390's `musig()` key expression requires. -/

namespace Winnow.Keys

inductive MuSigError where
  | invalidPublicKey | aggregationFailed
  deriving Repr, DecidableEq

def MuSigError.name : MuSigError → String
  | .invalidPublicKey => "invalidPublicKey" | .aggregationFailed => "aggregationFailed"

namespace MuSig

/-- secp256k1 curve order n, 32 bytes big-endian. -/
def groupOrder : ByteArray := Secp.toBE32 groupN

/-- BIP328 fixed chaincode for synthetic xpubs: SHA256("MuSig2MuSig2MuSig2"). -/
def aggregateChainCode : ByteArray :=
  ofHex! "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965"

/-- BIP327 KeySort: lexicographic order of the compressed public key bytes. -/
def keySort (keys : List ByteArray) : List ByteArray := keys.mergeSort fun a b => !lexPrecedes b a

/-- Reduces a 32-byte hash modulo the group order (one conditional subtraction). -/
def reduceModGroupOrder (h : ByteArray) : ByteArray :=
  if lexPrecedes h groupOrder then h
  else Secp.toBE32 (Secp.fromBE h - groupN)

/-- The second distinct key of the list, whose KeyAgg coefficient is 1. -/
def secondKey (keys : List ByteArray) : Option ByteArray :=
  match keys with
  | first :: rest => rest.find? (· != first)
  | [] => none

def listHash (keys : List ByteArray) : ByteArray := taggedHash "KeyAgg list" (keys.foldl (· ++ ·) .empty)

/-- BIP327 KeyAgg: Q = Σ a_i·P_i, returned compressed. -/
def aggregate (keys : List ByteArray) : Except MuSigError ByteArray := do
  if keys.isEmpty || !keys.all (fun k => k.size == 33 && (k[0]! == 2 || k[0]! == 3)) then
    throw .invalidPublicKey
  let lh := listHash keys
  let second := secondKey keys
  let mut points : List Point := []
  for key in keys do
    let point ← match parsePublicKey key with
      | .ok p => pure p
      | .error _ => throw .invalidPublicKey
    if second == some key then points := points ++ [point]
    else
      let c := reduceModGroupOrder (taggedHash "KeyAgg coefficient" (lh ++ key))
      match publicMultiply point c with
      | .ok p => points := points ++ [p]
      | .error _ => throw .aggregationFailed
  match combine points with
  | .ok q => pure (serializeCompressed q)
  | .error _ => throw .aggregationFailed

/-- The 32-byte x-only form of the aggregate key. -/
def aggregateXonly (keys : List ByteArray) : Except MuSigError ByteArray := do
  let a ← aggregate keys
  return a.extract 1 a.size

/-- BIP328 synthetic extended public key: depth 0, fixed chaincode, the compressed aggregate key. -/
def syntheticExtendedKey (aggregatePublicKey : ByteArray) : Except MuSigError HDKey := do
  if aggregatePublicKey.size != 33 then throw .invalidPublicKey
  return { depth := 0, parentFingerprint := 0, childIndex := 0, chainCode := aggregateChainCode,
           privateKey := none, publicKey := aggregatePublicKey }

end MuSig
end Winnow.Keys
