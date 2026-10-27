import Std.Data.HashSet
import WinnowApp.Real.RecordsSeal

/-! # The three records stores (ports of `VaultStore.swift`, `PeopleStore.swift`,
`ReceiveAddressLabelStore.swift`)

Each Swift store is an actor (or a main-actor class) around an array; here each is an immutable value and
every mutation returns the next value, so "apply to a copy, validate, persist, adopt the copy only when
every step succeeded" is simply "return the new store, or fail and keep the old one". `RecordsStore`
(`Records.lean`) holds the three behind one mutex.

Files, byte for byte with the Swift app:

* `vaults.json`: the sealed `[VaultRecord]` array. Swift writes it with a plain `JSONEncoder()` (key
  order not fixed); this port writes sorted keys. Both read either.
* `people.json`: the sealed `{"people":[…],"senderByTxid":{…}}` envelope with sorted keys and unescaped
  slashes (exactly the Swift bytes); a bare `[PersonRecord]` array (the older shape) still reads.
* `receive-labels.json`: unsealed `{"labels":{script hex: note},"network":…,"version":1,"walletID":…}`,
  sorted keys (exactly the Swift bytes). -/

namespace WinnowApp.RecordsReal
open Winnow SwiftJSON
open Tx (BitcoinNetwork)

/-- What opening a store found (`VaultStorageOpenResult` / `PeopleStorageOpenResult`). -/
inductive OpenResult where
  | missing
  | loaded
  | damaged (message : String)
  deriving Repr, BEq, Inhabited

def isSealFailure : RecordsError → Bool
  | .seal _ => true
  | _ => false

def outpointKey (txid : ByteArray) (vout : UInt32) : String := hex txid ++ ":" ++ toString vout

/-! ## Vaults -/

/-- `VaultStore`. -/
structure VaultStore where
  records : Array VaultRecord := #[]
  path : Option System.FilePath := none
  network : BitcoinNetwork := .signet
  deriving Inhabited

namespace VaultStore

def maximumWatchCount : UInt32 := 10_000
def maximumNextIndex : UInt32 := maximumWatchCount - 2
def maximumFileBytes : Nat := 16 * 1_024 * 1_024
def storeName : String := "vaults"

def damagedStorageMessage : String :=
  "Winnow found local vault data but could not safely read it. The file and protected keys were left untouched. Retry; if this continues, restore from a known-good wallet bundle or ask for help before changing anything."

def unverifiedStorageMessage : String :=
  "Winnow found shared-account data it could not verify: the file was not written by Winnow on this device, or its protected key is gone. The file and protected keys were left untouched. Restore your shared accounts from a known-good wallet bundle, or ask for help before changing anything."

def messageFor (e : RecordsError) : String := if isSealFailure e then unverifiedStorageMessage else damagedStorageMessage

def invalid {α} (reason : String) : RM α := throw (.vaultStorage reason)

def recordId (serialized : String) : String :=
  ((serialized.splitOn "#").getLast?.getD serialized)

/-- The record's own shape: a canonical descriptor whose checksum is its identity, derivable at both
chains, indices in range. -/
def validatedRecordShape (r : VaultRecord) (network : BitcoinNetwork) : RM Vault := do
  unless DisplayName.normalized r.name == some r.name do invalid "a vault has no usable name"
  let descriptor ← RM.lift (fun e => namedError e.name network) (Descriptor.parse r.descriptor)
  let canonical := descriptor.serialized
  unless canonical == r.descriptor && (canonical.splitOn "#").getLast? == some r.id do
    invalid "vault descriptor identifier does not match"
  let vault ← liftVault network (Vault.ofDescriptor descriptor network)
  discard <| liftVault network (vault.scriptPubKey 0 0)
  discard <| liftVault network (vault.scriptPubKey 0 1)
  unless r.nextReceiveIndex ≤ maximumNextIndex && r.nextChangeIndex ≤ maximumNextIndex do
    invalid "vault address index is out of range"
  return vault

def maxMoney : Int := 2_100_000_000_000_000

/-- Every persisted coin re-derived and bounded. -/
def validateRecordCoins (r : VaultRecord) (vault : Vault) (outpoints : Std.HashSet String) (aggregate : Int) :
    RM (Std.HashSet String × Int) := do
  let mut outpoints := outpoints
  let mut aggregate := aggregate
  for u in r.allUtxos do
    unless u.txid.size == 32 && u.amount.toInt > 0 && u.amount.toInt ≤ maxMoney &&
        (u.spent.map (·.spentBy.size == 32)).getD true && u.index < maximumWatchCount do
      invalid "vault output metadata is invalid"
    let nextIndex := if u.chain == .receive then r.nextReceiveIndex else r.nextChangeIndex
    unless u.index < nextIndex do invalid "vault output does not belong to its descriptor"
    unless (← liftVault vault.network (vault.scriptPubKey u.index u.chain.rawValue)) == u.scriptPubKey do
      invalid "vault output does not belong to its descriptor"
    let k := outpointKey u.txid u.vout
    if outpoints.contains k then invalid "duplicate vault output"
    outpoints := outpoints.insert k
    if u.isSpent then continue
    let sum := aggregate + u.amount.toInt
    unless sum ≤ maxMoney do invalid "vault balance is outside Bitcoin's monetary range"
    aggregate := sum
  return (outpoints, aggregate)

def validate (records : Array VaultRecord) (network : BitcoinNetwork) : RM Unit := do
  let mut ids : Std.HashSet String := {}
  let mut outpoints : Std.HashSet String := {}
  let mut aggregate : Int := 0
  for r in records do
    if ids.contains r.id then invalid "duplicate vault identifier"
    ids := ids.insert r.id
    let vault ← validatedRecordShape r network
    (outpoints, aggregate) ← validateRecordCoins r vault outpoints aggregate

def encode (records : Array VaultRecord) : ByteArray := (write (.arr (records.map VaultRecord.toJV))).toUTF8

def decode (payload : ByteArray) : RM (Array VaultRecord) := do
  let some text := String.fromUTF8? payload | throw (.named "dataCorrupted" "The vault file is not valid JSON.")
  RM.lift (fun e => .named e "The vault file could not be decoded.") (decodeText text (asArray VaultRecord.ofJV))

def persist (s : VaultStore) (keys : StoreKeyVault) (writeData : WriteData) : RM Unit := do
  let some p := s.path | return
  ({ store := storeName, keys } : StoreSeal).write (encode s.records) s.network p writeData

/-- `configure(storageURL:network:)`: points the store at its file, loading any existing records. A file
from before sealing is adopted and sealed now (best effort). -/
def configure (keys : StoreKeyVault) (path : Option System.FilePath) (network : BitcoinNetwork)
    (writeData : WriteData := writeAtomically) : IO (VaultStore × OpenResult) := do
  let empty : VaultStore := { path, network }
  let some p := path | return (empty, .missing)
  unless ← fileExists p do return (empty, .missing)
  let attempt : RM (VaultStore × Bool) := do
    let data ← boundedRead p maximumFileBytes (.vaultStorage "vault file too large")
    let (payload, predates) ← ({ store := storeName, keys } : StoreSeal).read data network
    let decoded ← decode payload
    validate decoded network
    return ({ empty with records := decoded }, predates)
  match ← attempt.run with
  | .ok (s, predates) =>
    if predates then discard <| (s.persist keys writeData).run
    return (s, .loaded)
  | .error e => return (empty, .damaged (messageFor e))

def record? (s : VaultStore) (id : String) : Option VaultRecord := s.records.find? (·.id == id)

/-- `backupRecords()`: refused while a vault payment is unconfirmed. -/
def backupRecords (s : VaultStore) : RM (Array VaultRecord) := do
  if s.records.any (fun r => r.allUtxos.any fun u => u.height == 0 || (u.spent.isSome && (u.spent.bind (·.height)).isNone)) then
    throw (.named "invalidBundle"
      (WalletError.invalidBundle "Wait for shared-account payments to confirm before saving a backup.").description)
  return s.records

/-- `restore(_:)`: public account state from a bundle. -/
def restore (s : VaultStore) (keys : StoreKeyVault) (writeData : WriteData) (restored : Array VaultRecord) : RM VaultStore := do
  validate restored s.network
  let next := { s with records := restored }
  next.persist keys writeData
  return next

/-- `add(name:descriptor:createdAtHeight:)`. -/
def add (s : VaultStore) (keys : StoreKeyVault) (writeData : WriteData) (name : String) (descriptor : Descriptor)
    (createdAtHeight : UInt32) : RM (VaultStore × VaultRecord) := do
  unless DisplayName.normalized name == some name do invalid "an account needs a short, single-line name"
  let serialized := descriptor.serialized
  let id := recordId serialized
  if s.records.any (·.id == id) then throw (.app .duplicateVault)
  let record : VaultRecord := { id, name, descriptor := serialized, createdAtHeight }
  let next := { s with records := s.records.push record }
  validate next.records s.network
  next.persist keys writeData
  return (next, record)

def remove (s : VaultStore) (keys : StoreKeyVault) (writeData : WriteData) (id : String) : RM VaultStore := do
  let next := { s with records := s.records.filter (·.id != id) }
  next.persist keys writeData
  return next

/-- Indices `0 ..< max(used receive, used change, 1) + 2` of lookahead. -/
def watchCount (r : VaultRecord) : UInt32 := max (max r.nextReceiveIndex r.nextChangeIndex) 1 + 2

/-- Receive/change scripts of every vault, for the combined filter scan. -/
def watchScripts (s : VaultStore) (network : BitcoinNetwork) : RM (Array ByteArray) := do
  unless network == s.network do invalid "vault network does not match the open wallet"
  let mut out := #[]
  for r in s.records do
    let v ← liftVault network (Vault.parse r.descriptor network)
    out := out ++ (← liftVault network (v.watchScripts (watchCount r)))
  return out

/-- script → (choice, index) for every address the record watches. -/
def ownerMap (r : VaultRecord) (network : BitcoinNetwork) : RM (Std.HashMap ByteArray (Nat × UInt32)) := do
  let v ← liftVault network (Vault.parse r.descriptor network)
  let mut m : Std.HashMap ByteArray (Nat × UInt32) := {}
  for i in [0:(watchCount r).toNat] do
    for choice in [0:2] do
      m := m.insert (← liftVault network (v.scriptPubKey i.toUInt32 choice)) (choice, i.toUInt32)
  return m

def applySpends (r : VaultRecord) (tx : Transaction) (txid : ByteArray) (height : UInt32) : VaultRecord × Bool := Id.run do
  let mut r := r
  let mut changed := false
  for input in tx.inputs do
    let o := input.previousOutput
    if let some i := r.allUtxos.findIdx? (fun u => !u.isSpent && u.txid == o.txid && u.vout == o.vout) then
      r := { r with allUtxos := r.allUtxos.modify i fun u => { u with spent := some { spentBy := txid, height := some height } } }
      changed := true
    else if let some i := r.allUtxos.findIdx? (fun u => u.spent.isSome && (u.spent.bind (·.height)).isNone &&
        u.txid == o.txid && u.vout == o.vout) then
      r := { r with allUtxos := r.allUtxos.modify i fun u => { u with spent := some { spentBy := txid, height := some height } } }
      changed := true
  return (r, changed)

def applyOutputs (r : VaultRecord) (tx : Transaction) (txid : ByteArray) (owner : Std.HashMap ByteArray (Nat × UInt32))
    (height : UInt32) (isCoinbase : Bool) : RM (VaultRecord × Bool) := do
  let mut r := r
  let mut changed := false
  for h : vout in [0:tx.outputs.size] do
    let output := tx.outputs[vout]
    let some (choice, index) := owner[output.scriptPubKey]? | continue
    if vout > 0xFFFF_FFFF then invalid "transaction output index is out of range"
    if let some i := r.allUtxos.findIdx? (fun u => u.txid == txid && u.vout == vout.toUInt32) then
      r := { r with allUtxos := r.allUtxos.modify i fun u => { u with height } }
    else
      r := { r with allUtxos := r.allUtxos.push {
        txid, vout := vout.toUInt32, amount := output.value, scriptPubKey := output.scriptPubKey,
        chain := if choice == 1 then .change else .receive, index, height, isCoinbase } }
    changed := true
    if choice == 0 && index ≥ r.nextReceiveIndex then r := { r with nextReceiveIndex := index + 1 }
    if choice == 1 && index ≥ r.nextChangeIndex then r := { r with nextChangeIndex := index + 1 }
  return (r, changed)

/-- `apply(match:network:)`: one matched block, like `Wallet.apply`. -/
def apply (s : VaultStore) (keys : StoreKeyVault) (writeData : WriteData) (m : Net.BlockMatch) (network : BitcoinNetwork) :
    RM VaultStore := do
  unless network == s.network do invalid "vault network does not match the open wallet"
  let mut records := s.records
  let mut changed := false
  for ri in [0:records.size] do
    let owner ← ownerMap records[ri]! network
    let mut txIndex := 0
    for tx in m.block.transactions do
      let txid := tx.txid
      let (r1, c1) := applySpends records[ri]! tx txid m.height
      let (r2, c2) ← applyOutputs r1 tx txid owner m.height (txIndex == 0)
      records := records.set! ri r2
      changed := changed || c1 || c2
      txIndex := txIndex + 1
  if !changed then return s
  let next := { s with records }
  validate records network
  next.persist keys writeData
  return next

/-- `advanceReceiveIndex(id:)` ("New address"). -/
def advanceReceiveIndex (s : VaultStore) (keys : StoreKeyVault) (writeData : WriteData) (id : String) : RM VaultStore := do
  let some i := s.records.findIdx? (·.id == id) | return s
  unless s.records[i]!.nextReceiveIndex < maximumNextIndex do invalid "receive address index is out of range"
  let next := { s with records := s.records.modify i fun r => { r with nextReceiveIndex := r.nextReceiveIndex + 1 } }
  next.persist keys writeData
  return next

/-- `recordSpend(id:transaction:changeScriptPubKey:changeIndex:)`: after a vault spend is broadcast, its
inputs leave the set (tombstoned without a height) and its change enters pending. False when there was
nothing to record (already recorded, or no known input). -/
def recordSpend (s : VaultStore) (keys : StoreKeyVault) (writeData : WriteData) (id : String) (tx : Transaction)
    (changeScriptPubKey : Option ByteArray) (changeIndex : UInt32) : RM (VaultStore × Bool) := do
  let some index := s.records.findIdx? (·.id == id) | return (s, false)
  let r := s.records[index]!
  let vault ← liftVault s.network (Vault.parse r.descriptor s.network)
  if let some change := changeScriptPubKey then
    unless changeIndex ≤ maximumNextIndex && (← liftVault s.network (vault.scriptPubKey changeIndex 1)) == change do
      invalid "vault change output does not belong to this vault"
    let found := (tx.outputs.zipIdx).filter (·.1.scriptPubKey == change)
    unless found.size == 1 && found[0]!.2 ≤ 0xFFFF_FFFF && found[0]!.1.value.toInt > 0 &&
        found[0]!.1.value.toInt ≤ maxMoney do
      invalid "vault change output is missing or invalid"
  let spendsKnown := tx.inputs.any fun input =>
    r.utxos.any fun u => u.txid == input.previousOutput.txid && u.vout == input.previousOutput.vout
  unless spendsKnown do return (s, false)
  let txid := tx.txid
  let mut r := r
  for input in tx.inputs do
    let o := input.previousOutput
    r := { r with allUtxos := r.allUtxos.map fun u =>
      if !u.isSpent && u.txid == o.txid && u.vout == o.vout then { u with spent := some { spentBy := txid, height := none } }
      else u }
  if let some change := changeScriptPubKey then
    if let some vout := tx.outputs.findIdx? (·.scriptPubKey == change) then
      let output := tx.outputs[vout]!
      r := { r with
        allUtxos := r.allUtxos.push { txid, vout := vout.toUInt32, amount := output.value, scriptPubKey := change,
                                      chain := .change, index := changeIndex, height := 0 }
        nextChangeIndex := changeIndex + 1 }
  let next := { s with records := s.records.set! index r }
  validate next.records s.network
  next.persist keys writeData
  return (next, true)

/-- `rollBack(to:)`: rewinds vault coins to a fork height, keeping in-flight spends reserved. -/
def rollBack (s : VaultStore) (keys : StoreKeyVault) (writeData : WriteData) (forkHeight : UInt32) : RM VaultStore := do
  let candidate := s.records.map fun r =>
    { r with allUtxos := (r.allUtxos.filter (·.height ≤ forkHeight)).map fun u =>
        match u.spent.bind (·.height) with
        | some h => if h > forkHeight then { u with spent := none } else u
        | none => u }
  if candidate == s.records then return s
  let next := { s with records := candidate }
  next.persist keys writeData
  return next

end VaultStore

/-! ## People -/

/-- `PersonRecord`: a saved recipient or co-owner. Public keys only. -/
structure PersonRecord where
  /-- Opaque; a UUID string. -/
  id : String
  name : String
  payTo : Option PersonPayTo := none
  signerKey : Option String := none
  nextPaymentIndex : UInt32 := 0
  savedRecipient : Option Bool := none
  destinationProvenance : Option Provenance := none
  destinationSource : Option String := none
  deriving Inhabited, BEq

namespace PersonRecord

def hasUnverifiedFundingDestination (p : PersonRecord) : Bool :=
  p.destinationProvenance == some .localFunding || p.destinationProvenance == some .explorerFunding
def canCoOwnSavings (p : PersonRecord) : Bool := p.signerKey.isSome
def derivesFreshAddresses (p : PersonRecord) : Bool := (p.payTo.map (·.derivesFreshAddresses)).getD false
def isSavedRecipient (p : PersonRecord) : Bool := p.payTo.isSome && p.savedRecipient != some false

def provenanceRaw : Provenance → String
  | .supplied => "supplied" | .localFunding => "localFunding" | .explorerFunding => "explorerFunding"

def provenanceOfJV (v : JV) : D Provenance := do
  match ← asString v with
  | "supplied" => pure .supplied
  | "localFunding" => pure .localFunding
  | "explorerFunding" => pure .explorerFunding
  | _ => dataCorrupted

def toJV (p : PersonRecord) : JV :=
  obj [("id", some (.str p.id)), ("name", some (.str p.name)), ("payTo", p.payTo.map PersonPayTo.toJV),
    ("signerKey", p.signerKey.map .str), ("nextPaymentIndex", some (ofInt p.nextPaymentIndex.toNat)),
    ("savedRecipient", p.savedRecipient.map .bool),
    ("destinationProvenance", p.destinationProvenance.map (.str ∘ provenanceRaw)),
    ("destinationSource", p.destinationSource.map .str)]

/-- Synthesized `init(from:)`: `id`, `name` and `nextPaymentIndex` required (property defaults are not
used by the synthesized decoder), the optionals `decodeIfPresent`. -/
def ofJV (v : JV) : D PersonRecord := do
  let kvs ← asObject v
  let id ← key kvs "id" asString
  let name ← key kvs "name" asString
  let payTo ← keyIfPresent kvs "payTo" PersonPayTo.ofJV
  let signerKey ← keyIfPresent kvs "signerKey" asString
  let nextPaymentIndex ← key kvs "nextPaymentIndex" asUInt32
  let savedRecipient ← keyIfPresent kvs "savedRecipient" asBool
  let destinationProvenance ← keyIfPresent kvs "destinationProvenance" provenanceOfJV
  let destinationSource ← keyIfPresent kvs "destinationSource" asString
  return { id, name, payTo, signerKey, nextPaymentIndex, savedRecipient, destinationProvenance, destinationSource }

end PersonRecord

/-- `PeopleStore`. -/
structure PeopleStore where
  records : Array PersonRecord := #[]
  /-- Txid display hex → person id. -/
  senderByTxid : Array (String × String) := #[]
  path : Option System.FilePath := none
  network : BitcoinNetwork := .signet
  isDamaged : Bool := false
  deriving Inhabited

namespace PeopleStore

def maximumPeople : Nat := 1_000
def maximumSenderLabels : Nat := 1_000
def maximumNextIndex : UInt32 := VaultStore.maximumNextIndex
def maximumFileBytes : Nat := 4 * 1_024 * 1_024
def maximumSourceLength : Nat := 256
def storeName : String := "people"

def damagedStorageMessage : String :=
  "Winnow could not read the saved-recipient file. It has been left untouched. You can still send to an address; saved recipients cannot be changed until the file is readable again."

def unverifiedStorageMessage : String :=
  "The saved-recipient file could not be verified: it was not written by Winnow on this device, or its protected key is gone. It has been left untouched. You can still send to an address; saved recipients cannot be changed until the file verifies again."

def messageFor (e : RecordsError) : String := if isSealFailure e then unverifiedStorageMessage else damagedStorageMessage

def invalid {α} (reason : String) : RM α := throw (.people (.invalidState reason))

def lookupLabel (labels : Array (String × String)) (k : String) : Option String := (labels.find? (·.1 == k)).map (·.2)

def setLabel (labels : Array (String × String)) (k : String) (v : Option String) : Array (String × String) :=
  let rest := labels.filter (·.1 != k)
  match v with | some x => rest.push (k, x) | none => rest

def normalizedName (name : String) : RM String := do
  let some n := DisplayName.normalized name | invalid "a person needs a short, single-line name"
  return n

def requireSource (source : Option String) : RM Unit := do
  let some s := source | return
  unless Characters.count s ≤ maximumSourceLength && (DisplayName.normalized s).isSome do
    invalid "a destination source must be short and single-line"

def payIdentity (p : PersonPayTo) (network : BitcoinNetwork) : RM ByteArray := liftNamed network (p.identity network)
def signerIdentity (k : String) (network : BitcoinNetwork) : RM ByteArray := liftNamed network (PersonKeys.signerIdentity k network)

/-- The existing person who already holds one of `candidate`'s keys (compared as derived material). -/
def firstSharingAKey (candidate : PersonRecord) (others : Array PersonRecord) (network : BitcoinNetwork) :
    RM (Option PersonRecord) := do
  let payId ← candidate.payTo.mapM (payIdentity · network)
  let signerId ← candidate.signerKey.mapM (signerIdentity · network)
  for other in others do
    if let some pid := payId then
      if let some op := other.payTo then
        if (← payIdentity op network) == pid then return some other
    if let some sid := signerId then
      if let some k := other.signerKey then
        if (← signerIdentity k network) == sid then return some other
  return none

def validateShape (r : PersonRecord) : RM Unit := do
  unless DisplayName.normalized r.name == some r.name do invalid "a person has no usable name"
  requireSource r.destinationSource
  unless r.nextPaymentIndex ≤ maximumNextIndex do invalid "payment index is out of range"

def validatePayTo (r : PersonRecord) (network : BitcoinNetwork) (seen : Std.HashSet ByteArray) : RM (Std.HashSet ByteArray) := do
  let some payTo := r.payTo | return seen
  let canonical ← match payTo with
    | .descriptor t => RM.lift (fun e => .named e.name e.description) (PersonPayTo.ofDescriptor t network)
    | .address t => liftNamed network (PersonPayTo.ofAddress t network)
  unless canonical == payTo do invalid "pay-to key is not in canonical form"
  let id ← payIdentity payTo network
  if seen.contains id then invalid "two people share a pay-to key"
  return seen.insert id

def validateSigner (r : PersonRecord) (network : BitcoinNetwork) (seen : Std.HashSet ByteArray) : RM (Std.HashSet ByteArray) := do
  let some k := r.signerKey | return seen
  let validated ← RM.lift (fun e => .named e.name e.description) (VaultCosignerKey.make k .scriptPath network)
  unless validated.expression == k do invalid "signer key is not in canonical form"
  let id ← liftNamed network (validated.publicKey 0 0)
  if seen.contains id then invalid "two people share a signer key"
  return seen.insert id

def isHexTxid (s : String) : Bool := s.length == 64 && (Wire.dataOfHex? s).isSome

def validate (records : Array PersonRecord) (senderByTxid : Array (String × String)) (network : BitcoinNetwork) : RM Unit := do
  unless records.size ≤ maximumPeople do invalid "too many people"
  unless senderByTxid.size ≤ maximumSenderLabels do invalid "too many sender labels"
  for (t, _) in senderByTxid do
    unless isHexTxid t do invalid "a sender label has an invalid transaction id"
  let mut ids : Std.HashSet String := {}
  let mut pays : Std.HashSet ByteArray := {}
  let mut signers : Std.HashSet ByteArray := {}
  for r in records do
    if ids.contains r.id then invalid "duplicate person identifier"
    ids := ids.insert r.id
    validateShape r
    pays ← validatePayTo r network pays
    signers ← validateSigner r network signers

def labelsJV (labels : Array (String × String)) : JV := .obj (labels.map fun (k, v) => (k, .str v))

def encode (records : Array PersonRecord) (senderByTxid : Array (String × String)) : ByteArray :=
  (writeUnescaped (.obj #[("people", .arr (records.map PersonRecord.toJV)), ("senderByTxid", labelsJV senderByTxid)])).toUTF8

/-- `[String: String]`: an object of strings (a repeated key keeps the last value). -/
def asStringMap (v : JV) : D (Array (String × String)) := do
  let kvs ← asObject v
  let mut out : Array (String × String) := #[]
  for (k, x) in kvs do
    out := setLabel out k (some (← asString x))
  return out

def decodeEnvelope (v : JV) : D (Array PersonRecord × Array (String × String)) := do
  let kvs ← asObject v
  let people ← key kvs "people" (asArray PersonRecord.ofJV)
  let labels := (← keyIfPresent kvs "senderByTxid" asStringMap).getD #[]
  return (people, labels)

/-- The envelope, or the older bare array of people (without labels). -/
def decodePayload (payload : ByteArray) : RM (Array PersonRecord × Array (String × String)) := do
  let some text := String.fromUTF8? payload | throw (.named "dataCorrupted" "The people file is not valid JSON.")
  match decodeText text decodeEnvelope with
  | .ok r => pure r
  | .error _ =>
    let people ← RM.lift (fun e => .named e "The people file could not be decoded.") (decodeText text (asArray PersonRecord.ofJV))
    return (people, #[])

def persist (s : PeopleStore) (keys : StoreKeyVault) (writeData : WriteData) : RM Unit := do
  let some p := s.path | return
  ({ store := storeName, keys } : StoreSeal).write (encode s.records s.senderByTxid) s.network p writeData

/-- `configure(storageURL:network:)`: damage is reported and refuses mutations; the app carries on. -/
def configure (keys : StoreKeyVault) (path : Option System.FilePath) (network : BitcoinNetwork)
    (writeData : WriteData := writeAtomically) : IO (PeopleStore × OpenResult) := do
  let empty : PeopleStore := { path, network }
  let some p := path | return (empty, .missing)
  unless ← fileExists p do return (empty, .missing)
  let attempt : RM (PeopleStore × Bool) := do
    let data ← boundedRead p maximumFileBytes (.people (.invalidState "people file too large"))
    let (payload, predates) ← ({ store := storeName, keys } : StoreSeal).read data network
    let (people, labels) ← decodePayload payload
    validate people labels network
    return ({ empty with records := people, senderByTxid := labels }, predates)
  match ← attempt.run with
  | .ok (s, predates) =>
    if predates then discard <| (s.persist keys writeData).run
    return (s, .loaded)
  | .error e => return ({ empty with isDamaged := true }, .damaged (messageFor e))

def record? (s : PeopleStore) (id : String) : Option PersonRecord := s.records.find? (·.id == id)

def sender? (s : PeopleStore) (txidHex : String) : Option PersonRecord :=
  (lookupLabel s.senderByTxid txidHex).bind s.record?

/-- `mutate`: validate, persist, adopt; labels naming a removed person are pruned. -/
def mutate (s : PeopleStore) (keys : StoreKeyVault) (writeData : WriteData) (candidate : Array PersonRecord) : RM PeopleStore := do
  let surviving : Std.HashSet String := candidate.foldl (fun a p => a.insert p.id) {}
  let labels := s.senderByTxid.filter fun (_, pid) => surviving.contains pid
  validate candidate labels s.network
  let next := { s with records := candidate, senderByTxid := labels }
  next.persist keys writeData
  return next

def mutateLabels (s : PeopleStore) (keys : StoreKeyVault) (writeData : WriteData) (labels : Array (String × String)) :
    RM PeopleStore := do
  validate s.records labels s.network
  let next := { s with senderByTxid := labels }
  next.persist keys writeData
  return next

def requireReadable (s : PeopleStore) : RM Unit := do
  if s.isDamaged then throw (.people .damaged)

/-- `updateRecipient(id:name:saved:)`: presentation only. -/
def updateRecipient (s : PeopleStore) (keys : StoreKeyVault) (writeData : WriteData) (id : String) (name : Option String)
    (saved : Bool) : RM (PeopleStore × PersonRecord) := do
  s.requireReadable
  let some i := s.records.findIdx? (·.id == id) | throw (.people .unknownPerson)
  let normalized ← name.mapM normalizedName
  let next ← s.mutate keys writeData (s.records.modify i fun r =>
    { r with name := normalized.getD r.name, savedRecipient := some saved })
  return (next, next.records[i]!)

/-- `add(name:payTo:signerKey:provenance:source:)`; `id` is the new record's UUID. -/
def add (s : PeopleStore) (keys : StoreKeyVault) (writeData : WriteData) (id : String) (name : String)
    (payTo : Option PersonPayTo) (signerKey : Option String) (provenance : Option Provenance := none)
    (source : Option String := none) : RM (PeopleStore × PersonRecord) := do
  s.requireReadable
  let trimmed ← normalizedName name
  requireSource source
  let candidate : PersonRecord := { id, name := trimmed, payTo, signerKey, destinationProvenance := provenance,
                                    destinationSource := source }
  if let some existing ← firstSharingAKey candidate s.records s.network then
    if !existing.isSavedRecipient && payTo.isSome && existing.payTo == payTo && existing.signerKey == signerKey then
      return ← s.updateRecipient keys writeData existing.id (some trimmed) true
    throw (.people (.duplicate existing.name))
  unless s.records.size < maximumPeople do throw (.people .tooMany)
  let next ← s.mutate keys writeData (s.records.push candidate)
  return (next, candidate)

/-- `remove(id:)`: the person and every sender label naming them. -/
def remove (s : PeopleStore) (keys : StoreKeyVault) (writeData : WriteData) (id : String) : RM PeopleStore := do
  s.requireReadable
  unless s.records.any (·.id == id) do throw (.people .unknownPerson)
  s.mutate keys writeData (s.records.filter (·.id != id))

/-- `attachDestination(id:payTo:provenance:source:)`: only a name-only contact gains a destination. -/
def attachDestination (s : PeopleStore) (keys : StoreKeyVault) (writeData : WriteData) (id : String) (payTo : PersonPayTo)
    (provenance : Provenance) (source : Option String := none) : RM PeopleStore := do
  s.requireReadable
  let some i := s.records.findIdx? (·.id == id) | invalid "only a name-only contact can attach a destination"
  unless s.records[i]!.payTo.isNone do invalid "only a name-only contact can attach a destination"
  requireSource source
  let candidate := { s.records[i]! with payTo := some payTo }
  if let some dup ← firstSharingAKey candidate (s.records.filter (·.id != id)) s.network then
    throw (.people (.duplicate dup.name))
  s.mutate keys writeData (s.records.modify i fun r =>
    { r with payTo := some payTo, destinationProvenance := some provenance, destinationSource := source,
             savedRecipient := some true })

/-- `advancePaymentIndex(id:past:)`: monotonic. -/
def advancePaymentIndex (s : PeopleStore) (keys : StoreKeyVault) (writeData : WriteData) (id : String) (index : UInt32) :
    RM PeopleStore := do
  s.requireReadable
  let some i := s.records.findIdx? (·.id == id) | throw (.people .unknownPerson)
  let next := index + 1
  unless next > s.records[i]!.nextPaymentIndex do return s
  s.mutate keys writeData (s.records.modify i fun r => { r with nextPaymentIndex := next })

/-- `labelSender(txidHex:personID:)`. -/
def labelSender (s : PeopleStore) (keys : StoreKeyVault) (writeData : WriteData) (txidHex personID : String) : RM PeopleStore := do
  s.requireReadable
  unless s.records.any (·.id == personID) do throw (.people .unknownPerson)
  unless (lookupLabel s.senderByTxid txidHex).isSome || s.senderByTxid.size < maximumSenderLabels do
    throw (.people .tooMany)
  s.mutateLabels keys writeData (setLabel s.senderByTxid txidHex (some personID))

/-- `removeSenderLabel(txidHex:)`: best effort (a failed write keeps the label). -/
def removeSenderLabel (s : PeopleStore) (keys : StoreKeyVault) (writeData : WriteData) (txidHex : String) : IO PeopleStore := do
  if (lookupLabel s.senderByTxid txidHex).isNone then return s
  match ← (s.mutateLabels keys writeData (setLabel s.senderByTxid txidHex none)).run with
  | .ok n => return n
  | .error _ => return s

end PeopleStore

/-! ## Receive address labels -/

/-- `ReceiveAddressLabelStore`: notes about this wallet's own addresses (one wallet, one network). -/
structure LabelStore where
  walletID : String
  network : BitcoinNetwork
  path : Option System.FilePath
  /-- Canonical script → note. -/
  labels : Array (ByteArray × String) := #[]
  notice : Option String := none
  deriving Inhabited

namespace LabelStore

def maximumLabels : Nat := 10_000
def maximumLabelLength : Nat := 120
def maximumFileBytes : Nat := 4 * 1_024 * 1_024

/-- `normalizedLabel(_:)`: trimmed, at most 120 characters (480 UTF-8 bytes), no control characters or
newlines. Empty is allowed (it removes a label). -/
def normalizedLabel (text : String) : Except LabelStorageError String := do
  let label := Wire.trimWhitespace text
  unless Characters.count label ≤ maximumLabelLength && label.utf8ByteSize ≤ maximumLabelLength * 4 &&
      !label.toList.any DisplayName.isControlOrNewline do
    throw .invalidLabel
  return label

def readLabels (path : System.FilePath) (walletID : String) (network : BitcoinNetwork) : RM (Array (ByteArray × String)) := do
  let damaged : RecordsError := .labels .damaged
  let data ← boundedRead path maximumFileBytes damaged
  let some text := String.fromUTF8? data | throw damaged
  let payload : D (Int × String × String × Array (String × String)) := decodeText text fun v => do
    let kvs ← asObject v
    return (← key kvs "version" asInt, ← key kvs "walletID" asString, ← key kvs "network" asString,
            ← key kvs "labels" PeopleStore.asStringMap)
  let .ok (version, wid, net, labels) := payload | throw damaged
  unless version == 1 && wid == walletID && net == networkRaw network && labels.size ≤ maximumLabels do throw damaged
  let mut out : Array (ByteArray × String) := #[]
  for (k, label) in labels do
    let some script := Wire.dataOfHex? k | throw damaged
    unless hex script == k && (AddressDecoder.address script network).isSome &&
        (normalizedLabel label).toOption == some label && !label.isEmpty do throw damaged
    out := (out.filter (·.1 != script)).push (script, label)
  return out

/-- `init(storageURL:walletID:network:)`. -/
def «open» (path : Option System.FilePath) (walletID : String) (network : BitcoinNetwork) : IO LabelStore := do
  let s : LabelStore := { walletID, network, path }
  let some p := path | return { s with notice := some (RecordsError.labels .unavailable).description }
  unless ← fileExists p do return s
  match ← (readLabels p walletID network).run with
  | .ok labels => return { s with labels }
  | .error _ => return { s with notice := some (RecordsError.labels .damaged).description }

def label? (s : LabelStore) (script : ByteArray) : Option String := (s.labels.find? (·.1 == script)).map (·.2)

def encode (s : LabelStore) (labels : Array (ByteArray × String)) : ByteArray :=
  (write (.obj #[("version", ofInt 1), ("walletID", .str s.walletID), ("network", .str (networkRaw s.network)),
    ("labels", .obj (labels.map fun (k, v) => (hex k, .str v)))])).toUTF8

/-- `setLabel(_:address:)`: empty text removes a label; the live view changes only after the write. -/
def setLabel (s : LabelStore) (writeData : WriteData) (text address : String) : RM LabelStore := do
  if s.notice.isSome then throw (.labels .damaged)
  let some p := s.path | throw (.labels .unavailable)
  let script ← RM.lift (fun e => namedError e.name s.network) (AddressDecoder.scriptPubKey address s.network)
  let label ← RM.lift .labels (normalizedLabel text)
  let rest := s.labels.filter (·.1 != script)
  let updated := if label.isEmpty then rest else rest.push (script, label)
  unless updated.size ≤ maximumLabels do throw (.labels .full)
  let data := s.encode updated
  unless data.size ≤ maximumFileBytes do throw (.labels .full)
  RM.io (writeData data p)
  return { s with labels := updated }

end LabelStore

end WinnowApp.RecordsReal
