import Winnow.Crypto

/-! # Ed25519 (RFC 8032), as WalletCore uses CryptoKit's `Curve25519.Signing`

Keys are 32-byte seeds; signatures are deterministic RFC 8032 (CryptoKit's are randomized, and any
valid signature verifies the same). Verification is RFC 8032 §5.1.7 without the cofactor: `S < L`,
`A` and `R` must decode, and `[S]B = R + [k]A`, compared as encodings of `[S]B - [k]A` and `R`.
Arithmetic is on `Nat` modulo p = 2^255 - 19 in extended coordinates. -/

namespace Winnow.Keys.Ed25519

def p : Nat := 2 ^ 255 - 19
def L : Nat := 2 ^ 252 + 27742317777372353535851937790883648493

def fpow (b e : Nat) : Nat := Id.run do
  let mut r := 1
  let mut x := b % p
  let mut k := e
  while k > 0 do
    if k % 2 == 1 then r := r * x % p
    x := x * x % p
    k := k / 2
  return r

def finv (x : Nat) : Nat := fpow x (p - 2)
def fsub (a b : Nat) : Nat := (a + p - b % p) % p

def d : Nat := fsub 0 121665 * finv 121666 % p
def sqrtM1 : Nat := fpow 2 ((p - 1) / 4)

/-- Extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z. -/
structure Pt where
  X : Nat
  Y : Nat
  Z : Nat
  T : Nat

def Pt.zero : Pt := ⟨0, 1, 1, 0⟩

def Pt.add (P Q : Pt) : Pt :=
  let a := fsub P.Y P.X * fsub Q.Y Q.X % p
  let b := (P.Y + P.X) * (Q.Y + Q.X) % p
  let c := 2 * P.T * Q.T % p * d % p
  let dd := 2 * P.Z * Q.Z % p
  let e := fsub b a
  let f := fsub dd c
  let g := (dd + c) % p
  let h := (b + a) % p
  ⟨e * f % p, g * h % p, f * g % p, e * h % p⟩

def Pt.neg (P : Pt) : Pt := ⟨fsub 0 P.X, P.Y, P.Z, fsub 0 P.T⟩

def Pt.mul (k : Nat) (P : Pt) : Pt := Id.run do
  let mut r := Pt.zero
  let mut q := P
  let mut n := k
  while n > 0 do
    if n % 2 == 1 then r := r.add q
    q := q.add q
    n := n / 2
  return r

def leBytes (n : Nat) (len : Nat) : ByteArray :=
  ⟨(List.range len).toArray.map fun i => UInt8.ofNat (n / 2 ^ (8 * i))⟩

def fromLE (b : ByteArray) : Nat := b.toList.foldr (fun x acc => acc * 256 + x.toNat) 0

def Pt.encode (P : Pt) : ByteArray :=
  let zi := finv P.Z
  let x := P.X * zi % p
  let y := P.Y * zi % p
  leBytes (y + (x % 2) * 2 ^ 255) 32

/-- Recover x from y and the sign bit (RFC 8032 §5.1.3); `none` when there is none. -/
def recoverX (y : Nat) (sign : Nat) : Option Nat :=
  if y ≥ p then none else
  let x2 := fsub (y * y) 1 * finv ((d * y % p * y + 1) % p) % p
  if x2 == 0 then (if sign == 1 then none else some 0) else
  let x := fpow x2 ((p + 3) / 8)
  let x := if (x * x + p - x2) % p == 0 then x else x * sqrtM1 % p
  if (x * x + p - x2) % p != 0 then none
  else some (if x % 2 != sign then p - x else x)

def decode (b : ByteArray) : Option Pt :=
  if b.size != 32 then none else
  let n := fromLE b
  let y := n % 2 ^ 255
  let sign := n / 2 ^ 255
  match recoverX y sign with
  | none => none
  | some x => some ⟨x, y, 1, x * y % p⟩

def gy : Nat := 4 * finv 5 % p
def B : Pt := match recoverX gy 0 with
  | some x => ⟨x, gy, 1, x * gy % p⟩
  | none => Pt.zero

/-- The expanded secret: the clamped scalar and the prefix. -/
def expand (seed : ByteArray) : Nat × ByteArray :=
  let h := sha512 seed
  let a := fromLE (h.extract 0 32)
  let a := (a % 2 ^ 254 - a % 8) ||| 2 ^ 254
  (a, h.extract 32 64)

inductive Error where
  | incorrectKeySize
  deriving Repr, DecidableEq

def Error.name : Error → String
  | .incorrectKeySize => "incorrectKeySize"

/-- `Curve25519.Signing.PrivateKey(rawRepresentation:).publicKey.rawRepresentation`. -/
def publicKey (seed : ByteArray) : Except Error ByteArray :=
  if seed.size != 32 then throw .incorrectKeySize
  else pure ((B.mul (expand seed).1).encode)

/-- RFC 8032 signing. -/
def sign (seed msg : ByteArray) : Except Error ByteArray := do
  let pk ← publicKey seed
  let (a, pre) := expand seed
  let r := fromLE (sha512 (pre ++ msg)) % L
  let R := (B.mul r).encode
  let k := fromLE (sha512 (R ++ pk ++ msg)) % L
  let s := (r + k * a) % L
  return R ++ leBytes s 32

/-- `Curve25519.Signing.PublicKey.isValidSignature(_:for:)` over raw key bytes. -/
def verify (pk sig msg : ByteArray) : Bool :=
  if sig.size != 64 || pk.size != 32 then false else
  let Rb := sig.extract 0 32
  let s := fromLE (sig.extract 32 64)
  if s ≥ L then false else
  match decode pk, decode Rb with
  | some A, some _ =>
    let k := fromLE (sha512 (Rb ++ pk ++ msg)) % L
    ((B.mul s).add (A.mul k).neg).encode == Rb
  | _, _ => false

end Winnow.Keys.Ed25519
