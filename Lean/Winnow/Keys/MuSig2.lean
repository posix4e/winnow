import Winnow.Keys.MuSig

/-! # BIP327 MuSig2 signing (port of `Descriptors/MuSig2.swift`)

Two-round signing over the BIP327 serializations: plain keys 33-byte compressed, public nonces 66 bytes,
aggregate nonces 66 bytes (an all-zero 33-byte half is infinity), partial signatures 32 bytes.

The scalar and point helpers are ported as they are, not as clean modular arithmetic: zero operands pass
through unchecked, other operands must be valid nonzero scalars below n (`invalidSecretKey` otherwise),
and a zero sum is refused. Their refusals are part of the behaviour (e.g. a secret nonce half ≥ n). -/

namespace Winnow.Keys

inductive MuSig2Error where
  | invalidPublicKey | invalidNonce | invalidSecretKey | invalidTweak | invalidPartialSignature
  /-- A signer contributed a key/nonce/signature that fails verification. -/
  | invalidContribution (what : String)
  | unknownSigner | secnonceReused | secnonceMismatch
  deriving Repr, DecidableEq

def MuSig2Error.name : MuSig2Error → String
  | .invalidPublicKey => "invalidPublicKey" | .invalidNonce => "invalidNonce"
  | .invalidSecretKey => "invalidSecretKey" | .invalidTweak => "invalidTweak"
  | .invalidPartialSignature => "invalidPartialSignature"
  | .invalidContribution _ => "invalidContribution" | .unknownSigner => "unknownSigner"
  | .secnonceReused => "secnonceReused" | .secnonceMismatch => "secnonceMismatch"

namespace MuSig

abbrev M2 := Except MuSig2Error

/-- BIP327 KeyAgg context: the aggregate point plus gacc and tacc. -/
structure KeyAggContext where
  /-- Q (compressed), after all tweaks so far. -/
  aggregateKey : ByteArray
  /-- gacc as a 32-byte scalar. -/
  parityAccumulator : ByteArray
  /-- tacc as a 32-byte scalar (0 when untweaked). -/
  tweakAccumulator : ByteArray

def KeyAggContext.xonlyAggregateKey (c : KeyAggContext) : ByteArray := c.aggregateKey.extract 1 c.aggregateKey.size
def KeyAggContext.hasEvenY (c : KeyAggContext) : Bool := c.aggregateKey[0]? == some 2

def scalarOne : ByteArray := Secp.toBE32 1
def scalarZero : ByteArray := ByteArray.mk (Array.replicate 32 0)
def groupOrderMinusOne : ByteArray := Secp.toBE32 (groupN - 1)

/-! ## Scalar and point helpers (mod n), as in the Swift original -/

def scalarIsValid (s : ByteArray) : Bool := s.size == 32 && s != scalarZero && lexPrecedes s groupOrder

def scalarAdd (a b : ByteArray) : M2 ByteArray :=
  if a == scalarZero then pure b
  else if b == scalarZero then pure a
  else if !(scalarIsValid a && scalarIsValid b) then throw .invalidSecretKey
  else
    let s := (Secp.fromBE a + Secp.fromBE b) % groupN
    if s == 0 then throw .invalidSecretKey else pure (Secp.toBE32 s)

def scalarMultiply (a b : ByteArray) : M2 ByteArray :=
  if a == scalarZero || b == scalarZero then pure scalarZero
  else if !(scalarIsValid a && scalarIsValid b) then throw .invalidSecretKey
  else pure (Secp.toBE32 ((Secp.fromBE a * Secp.fromBE b) % groupN))

def scalarNegate (s : ByteArray) : M2 ByteArray :=
  if s == scalarZero then pure scalarZero
  else if !scalarIsValid s then throw .invalidSecretKey
  else pure (Secp.toBE32 (groupN - Secp.fromBE s))

def privateToPublic (s : ByteArray) : M2 ByteArray :=
  if !scalarIsValid s then throw .invalidSecretKey
  else match pointOfSecret (Secp.fromBE s) with
    | .ok p => pure (serializeCompressed p)
    | .error _ => throw .invalidSecretKey

def parsePoint (b : ByteArray) : M2 Point :=
  match parsePublicKey b with
  | .ok p => pure p
  | .error _ => throw .invalidPublicKey

/-- cpoint_ext: all-zero bytes are the point at infinity (`none`). -/
def parsePointExt (b : ByteArray) : M2 (Option Point) :=
  if b.toList.all (· == 0) then pure none else some <$> parsePoint b

/-- Point addition with `none` for infinity; an infinite sum is `none`. -/
def addPoints (a b : Option Point) : Option Point :=
  match a, b with
  | none, none => none
  | some p, none => some p
  | none, some p => some p
  | some p, some q => (combine [p, q]).toOption

def addPointList (ps : List Point) : Option Point :=
  if ps.isEmpty then none else (combine ps).toOption

/-- Scalar times point; a zero scalar yields infinity. -/
def multiplyPoint (p : Point) (s : ByteArray) : M2 (Option Point) :=
  if s == scalarZero then pure none
  else if !scalarIsValid s then throw .invalidPublicKey
  else match publicMultiply p s with
    | .ok q => pure (some q)
    | .error _ => throw .invalidPublicKey

/-! ## Key aggregation and tweaks -/

/-- BIP327 KeyAgg as a context (gacc = 1, tacc = 0). -/
def keyAggContext (keys : List ByteArray) : M2 KeyAggContext :=
  match aggregate keys with
  | .ok q => pure { aggregateKey := q, parityAccumulator := scalarOne, tweakAccumulator := scalarZero }
  | .error _ => throw (.invalidContribution "pubkey")

/-- BIP327 ApplyTweak: Q′ = g·Q + t·G with g = −1 when an x-only tweak meets an odd-Y Q. -/
def applyTweak (c : KeyAggContext) (tw : ByteArray) (isXOnly : Bool) : M2 KeyAggContext := do
  if !(tw.size == 32 && lexPrecedes tw groupOrder) then throw .invalidTweak
  let negate := isXOnly && !c.hasEvenY
  let point ← parsePoint c.aggregateKey
  let adjusted := if negate then publicNegate point else point
  let tweaked ← match publicAdd adjusted tw with
    | .ok q => pure q
    | .error _ => throw .invalidTweak
  let g := if negate then groupOrderMinusOne else scalarOne
  let gacc ← scalarMultiply g c.parityAccumulator
  let tacc ← scalarAdd tw (← scalarMultiply g c.tweakAccumulator)
  return { aggregateKey := serializeCompressed tweaked, parityAccumulator := gacc, tweakAccumulator := tacc }

def applyTweaks (c : KeyAggContext) (tweaks : List ByteArray) (isXOnly : List Bool) : M2 KeyAggContext :=
  (tweaks.zip isXOnly).foldlM (fun c (t, x) => applyTweak c t x) c

/-! ## Nonces -/

def maskedRand (rand : ByteArray) (secretKey : Option ByteArray) : ByteArray :=
  match secretKey with
  | none => rand
  | some sk => Secp.xorBytes sk (taggedHash "MuSig/aux" rand)

def lengthPrefixed (message : Option ByteArray) : ByteArray :=
  match message with
  | none => ByteArray.mk #[0]
  | some m => ByteArray.mk #[1] ++ (Secp.toBE32 m.size).extract 24 32 ++ m

/-- BIP327 NonceGen with the randomness given: (secret nonce k1‖k2‖pk, public nonce R1‖R2). -/
def nonceGenerate (secretKey : Option ByteArray := none) (publicKey : ByteArray)
    (aggregateKey : Option ByteArray := none) (message : Option ByteArray := none)
    (extraInput : Option ByteArray := none) (rand : ByteArray) : M2 (ByteArray × ByteArray) := do
  if rand.size != 32 || publicKey.size != 33 then throw .invalidNonce
  if let some sk := secretKey then if sk.size != 32 then throw .invalidSecretKey
  if let some ak := aggregateKey then if ak.size != 32 then throw .invalidNonce
  let r := maskedRand rand secretKey
  let pre := lengthPrefixed message
  let extra := extraInput.getD .empty
  let nonceHash (i : UInt8) : ByteArray :=
    let ak := aggregateKey.getD .empty
    taggedHash "MuSig/nonce" (r ++ ByteArray.mk #[publicKey.size.toUInt8] ++ publicKey ++
      ByteArray.mk #[ak.size.toUInt8] ++ ak ++ pre ++ u32BE extra.size.toUInt32 ++ extra ++ ByteArray.mk #[i])
  let k1 := reduceModGroupOrder (nonceHash 0)
  let k2 := reduceModGroupOrder (nonceHash 1)
  if k1 == scalarZero || k2 == scalarZero then throw .invalidNonce
  let r1 ← privateToPublic k1
  let r2 ← privateToPublic k2
  return (k1 ++ k2 ++ publicKey, r1 ++ r2)

/-- BIP327 NonceAgg: component-wise sums; an infinite component is 33 zero bytes. -/
def nonceAggregate (publicNonces : List ByteArray) : M2 ByteArray := do
  if publicNonces.isEmpty || !publicNonces.all (·.size == 66) then throw .invalidNonce
  let mut out := ByteArray.empty
  for comp in [0, 1] do
    let mut points : List Point := []
    for n in publicNonces do
      match parsePublicKey (n.extract (comp * 33) (comp * 33 + 33)) with
      | .ok p => points := points ++ [p]
      | .error _ => throw (.invalidContribution "pubnonce")
    match addPointList points with
    | some s => out := out ++ serializeCompressed s
    | none => out := out ++ ByteArray.mk (Array.replicate 33 0)
  return out

/-! ## Sessions -/

structure Session where
  aggregateNonce : ByteArray
  publicKeys : List ByteArray
  tweaks : List ByteArray := []
  isXOnlyTweaks : List Bool := []
  message : ByteArray

/-- BIP327 GetSessionValues: the tweaked context, nonce coefficient b, effective nonce R, challenge e. -/
def Session.values (s : Session) : M2 (KeyAggContext × ByteArray × ByteArray × ByteArray) := do
  if s.tweaks.length != s.isXOnlyTweaks.length then throw .invalidTweak
  let ctx ← applyTweaks (← keyAggContext s.publicKeys) s.tweaks s.isXOnlyTweaks
  if s.aggregateNonce.size != 66 then throw .invalidNonce
  let b := reduceModGroupOrder (taggedHash "MuSig/noncecoef" (s.aggregateNonce ++ ctx.xonlyAggregateKey ++ s.message))
  let r1 ← parsePointExt (s.aggregateNonce.extract 0 33)
  let r2 ← parsePointExt (s.aggregateNonce.extract 33 66)
  let r2b ← match r2 with
    | some p => multiplyPoint p b
    | none => pure none
  let noncePoint ← match addPoints r1 r2b with
    | some p => pure (serializeCompressed p)
    | none => privateToPublic scalarOne
  let e := reduceModGroupOrder (taggedHash "BIP0340/challenge"
    (noncePoint.extract 1 33 ++ ctx.xonlyAggregateKey ++ s.message))
  return (ctx, b, noncePoint, e)

/-- The key aggregate coefficient of `publicKey` in this session. -/
def Session.coefficient (s : Session) (publicKey : ByteArray) : M2 ByteArray := do
  if !s.publicKeys.contains publicKey then throw .unknownSigner
  if secondKey s.publicKeys == some publicKey then return scalarOne
  return reduceModGroupOrder (taggedHash "KeyAgg coefficient" (listHash s.publicKeys ++ publicKey))

/-- BIP327 Sign: the 32-byte partial signature. The secret nonce comes back zeroed (the Swift original
zeroes it in place), whatever the outcome. -/
def partialSign (secretNonce secretKey : ByteArray) (s : Session) : M2 ByteArray × ByteArray :=
  (go, ByteArray.mk (Array.replicate secretNonce.size 0))
where go : M2 ByteArray := do
  if secretNonce.size != 97 then throw .invalidNonce
  let (ctx, b, noncePoint, e) ← s.values
  let mut k1 := secretNonce.extract 0 32
  let mut k2 := secretNonce.extract 32 64
  if k1 == scalarZero || k2 == scalarZero then throw .secnonceReused
  if noncePoint[0]! == 3 then
    k1 ← scalarNegate k1
    k2 ← scalarNegate k2
  if !(secretKey.size == 32 && secretKey != scalarZero && lexPrecedes secretKey groupOrder) then
    throw .invalidSecretKey
  let publicKey ← privateToPublic secretKey
  if publicKey != secretNonce.extract 64 97 then throw .secnonceMismatch
  let a ← s.coefficient publicKey
  let mut d := secretKey
  if !ctx.hasEvenY then d ← scalarNegate d
  if ctx.parityAccumulator != scalarOne then d ← scalarNegate d
  let sigPart ← scalarMultiply e (← scalarMultiply a d)
  let bk2 ← scalarMultiply b k2
  scalarAdd k1 (← scalarAdd bk2 sigPart)

/-- BIP327 PartialSigVerify: s·G == R_s + e·a·g·gacc·P. -/
def partialVerify (psig publicNonce publicKey : ByteArray) (s : Session) : M2 Bool := do
  if psig.size != 32 || publicNonce.size != 66 || publicKey.size != 33 then throw .invalidPartialSignature
  if psig == scalarZero || !lexPrecedes psig groupOrder then return false
  let (ctx, b, noncePoint, e) ← s.values
  let (r1, r2) ← match parsePoint (publicNonce.extract 0 33), parsePoint (publicNonce.extract 33 66) with
    | .ok r1, .ok r2 => pure (r1, r2)
    | _, _ => throw (.invalidContribution "pubnonce")
  let mut eff := addPoints (some r1) (← multiplyPoint r2 b)
  if noncePoint[0]! == 3 then eff := eff.map publicNegate
  let point ← parsePoint publicKey
  let a ← s.coefficient publicKey
  let mut factor := ctx.parityAccumulator
  if !ctx.hasEvenY then factor ← scalarNegate factor
  factor ← scalarMultiply e (← scalarMultiply a factor)
  let scaled ← multiplyPoint point factor
  match addPoints eff scaled with
  | none => return false
  | some right => return (← privateToPublic psig) == serializeCompressed right

/-- BIP327 PartialSigAgg: the 64-byte BIP340 signature x(R) ‖ s with s = Σ s_i + e·g·tacc. -/
def partialSigAggregate (psigs : List ByteArray) (s : Session) : M2 ByteArray := do
  let (ctx, _, noncePoint, e) ← s.values
  let mut sum := scalarZero
  for sig in psigs do
    if sig.size != 32 then throw .invalidPartialSignature
    if !lexPrecedes sig groupOrder then throw (.invalidContribution "psig")
    sum ← scalarAdd sum sig
  if ctx.tweakAccumulator != scalarZero then
    let mut factor := ctx.tweakAccumulator
    if !ctx.hasEvenY then factor ← scalarNegate factor
    sum ← scalarAdd sum (← scalarMultiply e factor)
  return noncePoint.extract 1 33 ++ sum

/-- The tweaked compressed aggregate key (with the parity BIP373 needs). -/
def aggregateTweaked (keys : List ByteArray) (tweaks : List ByteArray) (isXOnly : List Bool) : M2 ByteArray := do
  if tweaks.length != isXOnly.length then throw .invalidTweak
  return (← applyTweaks (← keyAggContext keys) tweaks isXOnly).aggregateKey

/-- The x-only aggregate key after the whole tweak chain. -/
def aggregateXonlyTweaked (keys : List ByteArray) (tweaks : List ByteArray) (isXOnly : List Bool) : M2 ByteArray := do
  let a ← aggregateTweaked keys tweaks isXOnly
  return a.extract 1 a.size

/-- The BIP328 plain tweak for one unhardened step from the synthetic aggregate xpub. -/
def bip328Tweak (chainCode aggregatePublicKey : ByteArray) (index : UInt32) : ByteArray :=
  (hmacSha512 chainCode (aggregatePublicKey ++ u32BE index)).extract 0 32

end MuSig
end Winnow.Keys
