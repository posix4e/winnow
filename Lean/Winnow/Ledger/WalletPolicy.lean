import Winnow.Ledger.APDU
import Winnow.Ledger.Merkle
import Winnow.Wallet.Descriptor

/-! # BIP388 wallet policies as Ledger's Bitcoin app registers them

Port of `Sources/WalletCore/Ledger/LedgerWalletPolicy.swift` (upstream 1cf93fb): a name, a descriptor
template over key placeholders, and the keys. The device keeps nothing; registration returns an HMAC
the phone stores and sends with every later request for this account.

`init(name:account:)` reads a `MultisigAccount`'s descriptor tree, which needs the multisig descriptor
of Phase B (`Descriptor.LeafExpression.timelocked`, `MultisigAccount.signerSuffix`/`recoverySuffix`). It
is ported here over `AccountTree`, a mirror of Swift's account-leaf shapes on the current
`Descriptor.SingleKey` (`ofTree`), plus `ofDescriptor` for what the current Lean descriptor can say
(`tr(K,TREE)` with `pk`/`multi_a`/`sortedmulti_a` leaves). Once `MultisigAccount` lands,
`ofAccount` is `ofTree name internalKey (tree of account.descriptor)`; see `Ledger/Multisig.lean`. -/

namespace Winnow.Ledger
open Keys

/-- `MultisigAccount.signerSuffix`: `/<0;1>/*`. -/
def signerSuffix : Array Descriptor.Element := #[.multipath #[0, 1], .wildcard false]
/-- `MultisigAccount.recoverySuffix`: a signer's second path `/<2;3>/*`, for the recovery leaf only. -/
def recoverySuffix : Array Descriptor.Element := #[.multipath #[2, 3], .wildcard false]

/-- Swift's `Descriptor.LeafExpression` with `TimelockedKeys` spelled out: the leaves an account tree
can hold. -/
inductive AccountLeaf where
  | pk (key : Descriptor.SingleKey)
  | multiA (threshold : Int) (keys : Array Descriptor.SingleKey)
  | sortedMultiA (threshold : Int) (keys : Array Descriptor.SingleKey)
  /-- `and_v(v:pk(KEY),older(N))`. -/
  | timelockedPk (key : Descriptor.SingleKey) (blocks : UInt32)
  /-- `and_v(v:multi_a(k,KEY,…),older(N))`. -/
  | timelockedMultiA (threshold : Int) (keys : Array Descriptor.SingleKey) (blocks : UInt32)
  deriving Inhabited

inductive AccountTree where
  | leaf (l : AccountLeaf)
  | branch (left right : AccountTree)
  deriving Inhabited

/-- A BIP388 wallet policy (`LedgerWalletPolicy`). -/
structure WalletPolicy where
  name : String
  /-- For example `tr(@0/**,sortedmulti_a(2,@1/**,@2/**))`. -/
  template : String
  /-- Key information in placeholder order: `[fingerprint/path]xpub`, or a bare xpub for a key with
  no origin. -/
  keys : Array String
  deriving Inhabited, BEq, Repr

namespace WalletPolicy

/-- Names are shown on the Ledger: 1 to 64 printable ASCII characters, with no space at either end. -/
def isValidName (name : String) : Bool :=
  let bytes := name.toUTF8
  1 ≤ bytes.size && bytes.size ≤ 64 && bytes.data.all (fun b => 0x20 ≤ b && b ≤ 0x7E)
    && bytes[0]! != 0x20 && bytes[bytes.size - 1]! != 0x20

/-- `init(name:template:keys:)`. -/
def make (name template : String) (keys : Array String) : Except LedgerError WalletPolicy := do
  unless isValidName name do
    throw (.mismatch "an account name must be 1 to 64 plain characters with no space at either end")
  unless !keys.isEmpty && keys.size ≤ 252 do throw (.mismatch "a policy needs 1 to 252 keys")
  return { name, template, keys }

/-- `keyInformation(_:)`: `[fingerprint/86'/1'/0']tpub…` with the derivation suffix removed. -/
def keyInformation (key : Descriptor.SingleKey) : Except LedgerError String := do
  let .extended xpub network := key.base
    | throw (.mismatch "every policy key must be an extended public key under /<0;1>/* or /<2;3>/*")
  unless xpub.privateKey.isNone && (key.derivation.elements == signerSuffix || key.derivation.elements == recoverySuffix) do
    throw (.mismatch "every policy key must be an extended public key under /<0;1>/* or /<2;3>/*")
  let mut text := ""
  if let some origin := key.origin then
    text := text ++ "[" ++ Descriptor.hex8 origin.fingerprint
    for step in origin.path do
      text := text ++ s!"/{(step &&& ~~~HDKey.hardenedOffset).toNat}" ++ (if step ≥ HDKey.hardenedOffset then "'" else "")
    text := text ++ "]"
  return text ++ xpub.serialized network

/-- The placeholder of `key`, numbering a new key after the ones seen so far. -/
def placeholder (keys : Array String) (key : Descriptor.SingleKey) : Except LedgerError (Array String × String) := do
  let information ← keyInformation key
  let (keys, index) := match keys.findIdx? (· == information) with
    | some i => (keys, i)
    | none => (keys.push information, keys.size)
  let text := if key.derivation.elements == signerSuffix then s!"@{index}/**" else s!"@{index}/<2;3>/*"
  return (keys, text)

def placeholders (keys : Array String) (leafKeys : Array Descriptor.SingleKey) :
    Except LedgerError (Array String × String) := do
  let mut keys := keys
  let mut texts : Array String := #[]
  for k in leafKeys do
    let (ks, t) ← placeholder keys k
    keys := ks
    texts := texts.push t
  return (keys, ",".intercalate texts.toList)

def leafTemplate (keys : Array String) : AccountLeaf → Except LedgerError (Array String × String)
  | .sortedMultiA t ks => do let (keys, p) ← placeholders keys ks; return (keys, s!"sortedmulti_a({t},{p})")
  | .multiA t ks => do let (keys, p) ← placeholders keys ks; return (keys, s!"multi_a({t},{p})")
  | .timelockedPk k blocks => do
    let (keys, p) ← placeholder keys k
    return (keys, s!"and_v(v:pk({p}),older({blocks}))")
  | .timelockedMultiA t ks blocks => do
    let (keys, p) ← placeholders keys ks
    return (keys, s!"and_v(v:multi_a({t},{p}),older({blocks}))")
  | .pk _ => throw (.mismatch "a plain pk() leaf is not an account leaf")

/-- `init(name:account:)` over the account's internal key and tree: the internal key is `@0`, each
distinct key after it gets the next placeholder in descriptor order, `/<0;1>/*` becomes `/**` and a
reused signer's `/<2;3>/*` stays as it is. -/
def ofTree (name : String) (internalKey : Descriptor.SingleKey) (tree : AccountTree) : Except LedgerError WalletPolicy := do
  let .extended .. := internalKey.base
    | throw (.mismatch "only accounts whose internal key is an extended key can be registered")
  let keys := #[← keyInformation internalKey]
  let (keys, body) ← match tree with
    | .leaf only => leafTemplate keys only
    | .branch (.leaf left) (.leaf right) => do
      let (keys, l) ← leafTemplate keys left
      let (keys, r) ← leafTemplate keys right
      pure (keys, "{" ++ l ++ "," ++ r ++ "}")
    | _ => throw (.mismatch "only one- and two-leaf accounts can be registered")
  make name s!"tr(@0/**,{body})" keys

/-- The current Lean descriptor's leaves as account leaves (it has no timelocked leaf yet). -/
def accountLeaf : Descriptor.Leaf → AccountLeaf
  | .pk k => .pk k
  | .multiA t ks => .multiA t ks
  | .sortedMultiA t ks => .sortedMultiA t ks

def accountTree : Descriptor.ScriptTree → AccountTree
  | .leaf l => .leaf (accountLeaf l)
  | .branch l r => .branch (accountTree l) (accountTree r)

/-- `init(name:account:)` from a descriptor `tr(K,TREE)` the current Lean descriptor can parse. -/
def ofDescriptor (name : String) (d : Descriptor) : Except LedgerError WalletPolicy := do
  let .tr internalKey (some tree) := d.expression
    | throw (.mismatch "only accounts whose internal key is an extended key can be registered")
  ofTree name internalKey (accountTree tree)

/-- Version 2: 0x02 ‖ name length ‖ name ‖ compactSize(template length) ‖ SHA-256(template) ‖
compactSize(key count) ‖ Merkle root of the keys. -/
def serialized (p : WalletPolicy) : ByteArray :=
  let name := p.name.toUTF8
  let template := p.template.toUTF8
  ByteArray.mk #[0x02, name.size.toUInt8] ++ name ++ compactSize template.size.toUInt64 ++ sha256 template
    ++ compactSize p.keys.size.toUInt64 ++ Merkle.root (p.keys.map (Merkle.elementHash ·.toUTF8))

/-- The policy id the device returns on registration: SHA-256 of `serialized`. -/
def id (p : WalletPolicy) : ByteArray := sha256 p.serialized

end WalletPolicy
end Winnow.Ledger
