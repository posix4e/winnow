import Std.Sync.Mutex
import Winnow.IO.Http
import WinnowApp.Model
import WinnowApp.Pure
import WinnowApp.Real.RecordsStores

/-! # The records side of the backend (people, vaults, shared savings, labels)

Ports of AppModel's records state and operations (`Sources/WinnowApp/AppModel.swift`: the vault ops from
`ownKeyExpression` on, people and shared savings, labels, the sender lookup) over the three stores of
`RecordsStores.lean`, plus the derived data AppModel recomputes in its `didSet`s
(`recomputeSharedSavings`, `ownedVaultScripts`, `recipientByScript`, `senderByTxid`) and the app's
`Records` summary.

Every operation takes what it needs explicitly: the `RecordsStore` (which holds the network, the
directory and the store keys), the open `Winnow.Wallet` where the wallet's own keys matter, the chain tip
for reviews, the creation height for new vaults. Failures are `RecordsError`s (`RM`); `RM.toIO` turns
one into the `IO.userError` of its description, which is what the screens show.

The store state sits behind one `Std.Mutex`, so reads from another task never see half a mutation. The
caller still serializes mutations (AppModel's `exclusively(.spending)` gate is the caller's). -/

namespace WinnowApp.RecordsReal
open Winnow SwiftJSON
open Tx (BitcoinNetwork)

/-! ## The store -/

structure RecordsState where
  vaults : VaultStore := {}
  people : PeopleStore := {}
  /-- `peopleStorageNotice`: set when `people.json` could not be read; never blocks boot. -/
  peopleNotice : Option String := none
  /-- The receive-label store of the wallet last asked about (`configureReceiveAddressLabels`). -/
  labels : Option LabelStore := none
  /-- `recipientByScript`, recomputed only after people change (AppModel's `didSet`): each person
  derives `nextPaymentIndex + gapLimit` scripts. -/
  recipientsCache : Option (Array (ByteArray × PersonRecord)) := none
  deriving Inhabited

/-- vaults.json, people.json and receive-labels.json of one network directory. -/
structure RecordsStore where
  network : BitcoinNetwork
  /-- `ApplicationSupport/BTCSwift/<network>/`; none when storage is unreachable. -/
  dir : Option System.FilePath
  keys : StoreKeyVault
  writeData : WriteData := writeAtomically
  state : Std.Mutex RecordsState
  /-- `e2e?.journal(_:fields:)` (test mode's event journal); a no-op otherwise. -/
  journal : String → List (String × String) → IO Unit := fun _ _ => pure ()

namespace RecordsStore

def vaultsPath (s : RecordsStore) : Option System.FilePath := s.dir.map (· / "vaults.json")
def peoplePath (s : RecordsStore) : Option System.FilePath := s.dir.map (· / "people.json")
def labelsPath (s : RecordsStore) : Option System.FilePath := s.dir.map (· / "receive-labels.json")

/-- Runs `f` on the state under the lock; the state changes only when `f` succeeds. -/
def modify {α} (s : RecordsStore) (f : RecordsState → RM (RecordsState × α)) : RM α :=
  s.state.atomically do
    let st ← get
    let (st', a) ← (f st : RM _)
    set { st' with recipientsCache := none }
    return a

def read (s : RecordsStore) : IO RecordsState := s.state.atomically get

/-- One journal line from inside a records operation. -/
def note (s : RecordsStore) (name : String) (fields : List (String × String)) : RM Unit := RM.io (s.journal name fields)

/-- `journalPSBT(stage:psbt:)`: only the public PSBT exchanged with cosigners (`psbt.generated`). -/
def notePSBT (s : RecordsStore) (stage : String) (p : PSBT) : RM Unit :=
  s.note "psbt.generated" [("stage", stage), ("base64", p.base64), ("inputCount", toString p.inputs.size),
                           ("outputCount", toString p.outputs.size)]

/-- Re-reads both sealed files (boot, adopting a wallet, deleting one). The vault result is what the app
turns into `storageDamaged`; damage to people is the notice. -/
def configure (s : RecordsStore) : IO OpenResult := do
  let (vaults, vaultResult) ← VaultStore.configure s.keys s.vaultsPath s.network s.writeData
  let (people, peopleResult) ← PeopleStore.configure s.keys s.peoplePath s.network s.writeData
  let notice := match peopleResult with | .damaged m => some m | _ => none
  s.state.atomically (set ({ vaults, people, peopleNotice := notice, labels := none } : RecordsState))
  return vaultResult

/-- Opens the records of `network` under `dir`, with store keys from `keys`. -/
def «open» (network : BitcoinNetwork) (dir : Option System.FilePath) (keys : StoreKeyVault)
    (writeData : WriteData := writeAtomically) : IO (RecordsStore × OpenResult) := do
  let s : RecordsStore := { network, dir, keys, writeData, state := ← Std.Mutex.new {} }
  let r ← s.configure
  return (s, r)

/-- The receive-label store for `walletID`, reopened when the wallet changed. -/
def labelStore (s : RecordsStore) (st : RecordsState) (walletID : String) : IO LabelStore := do
  match st.labels with
  | some l => if l.walletID == walletID then return l else LabelStore.open s.labelsPath walletID s.network
  | none => LabelStore.open s.labelsPath walletID s.network

end RecordsStore

/-! ## The wallet's own keys -/

def formatPath (path : Array UInt32) : String :=
  "/".intercalate (path.toList.map fun step =>
    if step ≥ Keys.HDKey.hardenedOffset then s!"{(step - Keys.HDKey.hardenedOffset).toNat}'" else s!"{step.toNat}")

/-- `ownKeyExpression(multipathSuffix:)`: `[fp/86'/coin'/0']xpub…`, plus `/<0;1>/*` for multi_a leaves. -/
def ownKeyExpressionOf (d : Descriptor) (multipath : Bool) : RM String := do
  let .tr (.single key) none := d.expression | throw (.app .noWallet)
  let some origin := key.origin | throw (.app .noWallet)
  let .extended accountKey hdNetwork := key.base | throw (.app .noWallet)
  let base := s!"[{Wallet.hex8 origin.fingerprint}/{formatPath origin.path}]{accountKey.serialized hdNetwork}"
  return if multipath then base ++ "/<0;1>/*" else base

def ownKeyExpression (w : Wallet) (multipath : Bool) : RM String := ownKeyExpressionOf w.descriptor multipath

def ownSignerIdentity (w : Wallet) : RM ByteArray := do
  liftNamed w.network (PersonKeys.signerIdentity (← ownKeyExpression w true) w.network)

def ownSignerIdentity? (w : Option Wallet) : IO (Option ByteArray) := do
  let some w := w | return none
  return (← (ownSignerIdentity w).run).toOption

/-- `ownPersonCard(name:)`: this wallet's account key as both pay-to key and signer key. -/
def ownPersonCardOf (d : Descriptor) (network : BitcoinNetwork) (name : String) : RM PersonCard := do
  let signer ← ownKeyExpressionOf d true
  let payTo ← RM.lift (fun e => .named e.name e.description) (PersonPayTo.ofDescriptor s!"tr({signer})" network)
  return PersonCard.make network name (some payTo.text) (some signer)

def ownPersonCard (w : Wallet) (name : String) : RM PersonCard := ownPersonCardOf w.descriptor w.network name

/-! ## Derived data -/

/-- `ownedVaultScripts`: every vault's scripts up to `max(nextReceive, nextChange) + gapLimit`. -/
def ownedVaultScripts (vaults : Array VaultRecord) (network : BitcoinNetwork) : Array ByteArray := Id.run do
  let mut out := #[]
  for r in vaults do
    let some v := (Vault.parse r.descriptor network).toOption | continue
    let count := max r.nextReceiveIndex r.nextChangeIndex + Wallet.gapLimit
    out := out ++ (v.watchScripts count).toOption.getD #[]
  return out

/-- `recipientByScript`: every script a person could have been paid at so far (the first person wins). -/
def recipientByScript (people : Array PersonRecord) (network : BitcoinNetwork) : Array (ByteArray × PersonRecord) := Id.run do
  let mut seen : Std.HashSet ByteArray := {}
  let mut out := #[]
  for p in people do
    let some payTo := p.payTo | continue
    let scripts := (payTo.scripts (p.nextPaymentIndex + Wallet.gapLimit) network).toOption.getD #[]
    for s in scripts do
      if seen.contains s then continue
      seen := seen.insert s
      out := out.push (s, p)
  return out

/-- `personScripts()`: script → name. -/
def personScripts (people : Array PersonRecord) (network : BitcoinNetwork) : Array (ByteArray × String) :=
  (recipientByScript people network).map fun (s, p) => (s, p.name)

/-- `SharedSavings.Signer`. -/
structure SavingsSigner where
  fingerprint : String
  name : Option String
  isYou : Bool
  deriving Inhabited, BEq

/-- `AppModel.SharedSavings`: a script-path vault read as savings shared with people. -/
structure SharedSavings where
  record : VaultRecord
  coOwners : Array PersonRecord
  includesYou : Bool
  threshold : Int
  signerCount : Nat
  signers : Array SavingsSigner
  deriving Inhabited

def signerIdentities (people : Array PersonRecord) (network : BitcoinNetwork) : Array (PersonRecord × ByteArray) :=
  people.filterMap fun p => do
    let k ← p.signerKey
    let id ← (PersonKeys.signerIdentity k network).toOption
    return (p, id)

/-- `recomputeSharedSavings()`: pairs every script-path vault with the people whose signer keys it carries,
judged by derived keys, never by a stored mapping. -/
def recomputeSharedSavings (vaults : Array VaultRecord) (people : Array PersonRecord) (network : BitcoinNetwork)
    (ownKey : Option ByteArray) : Array SharedSavings :=
  let identities := signerIdentities people network
  vaults.filterMap fun record => do
    let vault ← (Vault.parse record.descriptor network).toOption
    unless vault.isScriptPath do none
    let signerKeys ← (vault.signerKeys).toOption
    let coOwners := (identities.filter fun (_, k) => signerKeys.contains k).map (·.1)
    let includesYou := (ownKey.map signerKeys.contains).getD false
    let signers := signerKeys.map fun key =>
      { fingerprint := PersonKeys.fingerprint key, name := (identities.find? (·.2 == key)).map (·.1.name),
        isYou := ownKey == some key : SavingsSigner }
    return { record, coOwners, includesYou, threshold := vault.threshold, signerCount := vault.signerCount, signers }

/-! ## The `Records` summary -/

def personSummary (p : PersonRecord) (network : BitcoinNetwork) : Person :=
  { id := p.id, name := p.name, payTo := p.payTo.map (·.derivesFreshAddresses), signerKey := p.signerKey,
    signerFingerprint := p.signerKey.bind fun k => (PersonKeys.signerFingerprint k network).toOption,
    nextPaymentIndex := p.nextPaymentIndex.toNat, savedRecipient := p.savedRecipient,
    provenance := p.destinationProvenance }

def utxoSummary (u : WalletUTXO) : VaultUtxo :=
  { txid := displayHex u.txid, vout := u.vout.toNat, amount := u.amount.toInt.toNat, height := u.height.toNat,
    isCoinbase := u.isCoinbase }

def vaultSummary (r : VaultRecord) (network : BitcoinNetwork) (savings : Array SharedSavings) : VaultSummary :=
  let vault? := (Vault.parse r.descriptor network).toOption
  let shared := savings.find? (·.record.id == r.id)
  { id := r.id, name := r.name, descriptor := r.descriptor, balance := r.balance.toInt.toNat,
    threshold := (vault?.map (·.threshold.toNat)).getD 0, signerCount := (vault?.map (·.signerCount)).getD 0,
    isScriptPath := (vault?.map (·.isScriptPath)).getD false,
    receiveAddress := vault?.bind fun v => (v.address r.nextReceiveIndex 0).toOption,
    utxos := r.utxos.toList.map utxoSummary,
    coOwners := (shared.map fun s => s.coOwners.toList.map (·.name)).getD [],
    includesYou := (shared.map (·.includesYou)).getD false,
    signers := (shared.map fun s => s.signers.toList.map fun g =>
      ({ fingerprint := g.fingerprint, name := g.name, isYou := g.isYou } : Signer)).getD [] }

/-- The app's `Records` from the stores and the open wallet (if any). -/
def summaryOf (s : RecordsStore) (st : RecordsState) (w : Option Wallet) : IO (Records × RecordsState) := do
  let network := s.network
  let ownKey ← ownSignerIdentity? w
  let savings := recomputeSharedSavings st.vaults.records st.people.records network ownKey
  let (labels, st) ← match w with
    | some w => do
      let l ← s.labelStore st w.id
      pure (some l, { st with labels := some l })
    | none => pure (none, st)
  let recipients := st.recipientsCache.getD (recipientByScript st.people.records network)
  let st := { st with recipientsCache := some recipients }
  let records : Records := {
    people := st.people.records.toList.map (personSummary · network)
    vaults := st.vaults.records.toList.map (vaultSummary · network savings)
    senderByTxid := st.people.senderByTxid.toList
    recipientByScript := recipients.toList.map fun (sc, p) => (hex sc, p.id)
    receiveLabels := match labels with
      | some l => l.labels.toList.filterMap fun (sc, note) => (AddressDecoder.address sc network).map (·, note)
      | none => []
    peopleStorageNotice := st.peopleNotice
    receiveLabelStorageNotice := labels.bind (·.notice)
    ownSignerFingerprint := ownKey.map PersonKeys.fingerprint }
  return (records, st)

/-- `records`: people, vaults (with their shared-savings reading), sender and receive labels. -/
def records (s : RecordsStore) (w : Option Wallet) : IO Records := do
  s.state.atomically do
    let (r, st) ← summaryOf s (← get) w
    set st
    return r

/-- `recipientByScript`, from the cache when people have not changed since. -/
def recipients (s : RecordsStore) : IO (Array (ByteArray × PersonRecord)) :=
  s.state.atomically do
    let st ← get
    match st.recipientsCache with
    | some r => return r
    | none =>
      let r := recipientByScript st.people.records s.network
      set { st with recipientsCache := some r }
      return r

/-- A mutation of the state, answered with the fresh `Records`. -/
def mutate (s : RecordsStore) (w : Option Wallet) (f : RecordsState → RM RecordsState) : RM Records := do
  s.modify fun st => do pure (← f st, ())
  RM.io (records s w)

/-- Scripts of the vaults, for labelling outputs (`ownedVaultScripts`). -/
def vaultScripts (s : RecordsStore) : IO (Array ByteArray) := do
  return ownedVaultScripts (← s.read).vaults.records s.network

/-! ## Receive labels -/

/-- `setReceiveAddressLabel(_:address:)`: only for the wallet's own watched scripts; empty text removes. -/
def setReceiveLabel (s : RecordsStore) (w : Wallet) (address label : String) : RM Records := do
  let script ← RM.lift (fun e => namedError e.name s.network) (AddressDecoder.scriptPubKey address s.network)
  let watched ← liftWallet s.network w.watchScripts
  unless watched.contains script do throw (.app .noWallet)
  mutate s (some w) fun st => do
    let l ← RM.io (s.labelStore st w.id)
    let l ← l.setLabel s.writeData label address
    return { st with labels := some l }

/-! ## People -/

/-- `PersonPaste.parse`, as the Add-person screen previews it. -/
def parsePaste (network : BitcoinNetwork) (text : String) : RM PastePreview := do
  let p ← liftNamed network (PersonPaste.parse text network)
  return { name := p.name, payTo := p.payTo.map (·.derivesFreshAddresses), hasSignerKey := p.signerKey.isSome }

def withPeople (s : RecordsStore) (w : Option Wallet) (f : PeopleStore → RM PeopleStore) : RM Records :=
  mutate s w fun st => do return { st with people := ← f st.people }

/-- `labelReceivedSender(txid:personID:)` (txid in display hex). -/
def labelSender (s : RecordsStore) (w : Option Wallet) (txid personID : String) : RM Records := do
  let r ← withPeople s w fun ps => ps.labelSender s.keys s.writeData txid personID
  s.note "person.senderLabeled" [("txid", txid), ("personID", personID)]
  return r

/-- `person.added`: what kind of destination, and whether the person can co-own savings. -/
def notePersonAdded (s : RecordsStore) (record : PersonRecord) : RM Unit :=
  s.note "person.added" [("name", record.name),
    ("payToKind", (record.payTo.map fun p => if p.derivesFreshAddresses then "descriptor" else "address").getD "none"),
    ("hasSignerKey", toString record.canCoOwnSavings)]

/-- AddPersonView's save: `addPerson` (+ `labelReceivedSender` when labelling a payment, `labelTxid` in
display hex). Labelling saves the pasted destination (if any) without a signer key. -/
def addPerson (s : RecordsStore) (w : Option Wallet) (name : String) (paste : Option String) (forSigning : Bool)
    (provenance : Option Provenance) (source : Option String) (labelTxid : Option String) : RM Records := do
  let network := s.network
  let pasted := paste.bind fun t => if (Wire.trimWhitespace t).isEmpty then none else some t
  let parsed ← pasted.mapM fun t => liftNamed network (PersonPaste.parse t network)
  let id ← RM.io uuidString
  match labelTxid with
  | some txid =>
    -- Two steps, as AppModel takes them: the person is saved even when the label then fails.
    let payTo := parsed.bind (·.payTo)
    let record ← s.modify fun st => do
      let (ps, record) ← st.people.add s.keys s.writeData id name payTo none (if payTo.isSome then provenance else none)
        (if payTo.isSome then source else none)
      return ({ st with people := ps }, record)
    notePersonAdded s record
    labelSender s w txid record.id
  | none =>
    let some p := parsed | throw (namedError "empty" network)
    if forSigning && p.signerKey.isNone then
      throw (.named "noSignerKey" "Ask for their signer key or Winnow card.")
    if !forSigning && p.payTo.isNone then throw (namedError "unrecognised" network)
    let record ← s.modify fun st => do
      let (ps, record) ← st.people.add s.keys s.writeData id name p.payTo p.signerKey provenance source
      return ({ st with people := ps }, record)
    notePersonAdded s record
    RM.io (records s w)

/-- `attachDestination(id:payTo:provenance:source:)` from a pasted address or card. -/
def attachDestination (s : RecordsStore) (w : Option Wallet) (personID paste : String) (provenance : Provenance)
    (source : Option String) : RM Records := do
  let p ← liftNamed s.network (PersonPaste.parse paste s.network)
  let some payTo := p.payTo | throw (.app .personCannotBePaid)
  withPeople s w fun ps => ps.attachDestination s.keys s.writeData personID payTo provenance source

def updateRecipient (s : RecordsStore) (w : Option Wallet) (personID : String) (name : Option String) (saved : Bool) :
    RM Records :=
  withPeople s w fun ps => do return (← ps.updateRecipient s.keys s.writeData personID name saved).1

/-- `PeopleStore.remove(id:)`: forgets the person and every sender label naming them. -/
def removePerson (s : RecordsStore) (w : Option Wallet) (personID : String) : RM Records :=
  withPeople s w fun ps => ps.remove s.keys s.writeData personID

def removeSenderLabel (s : RecordsStore) (w : Option Wallet) (txid : String) : RM Records :=
  withPeople s w fun ps => RM.io (ps.removeSenderLabel s.keys s.writeData txid)

/-- `advancePersonPaymentIndex(id:past:)`: best effort, as AppModel calls it. -/
def advancePersonPaymentIndex (s : RecordsStore) (w : Option Wallet) (personID : String) (index : UInt32) : IO Records := do
  discard <| (withPeople s w fun ps => ps.advancePaymentIndex s.keys s.writeData personID index).run
  records s w

/-- `nextPaymentAddress(for:)`: peeked, never advanced here. -/
def nextPaymentAddress (s : RecordsStore) (personID : String) : RM (String × UInt32) := do
  let st ← RM.io s.read
  let some p := st.people.record? personID | throw (.people .unknownPerson)
  let some payTo := p.payTo | throw (.app .personCannotBePaid)
  return (← liftNamed s.network (payTo.addressAt p.nextPaymentIndex s.network), p.nextPaymentIndex)

/-! ## The sender lookup -/

def maximumLookupBytes : Nat := 2 * 1024 * 1024

def lookupFormatError : RecordsError := .lookup "The explorer answered in a format Winnow does not understand."

/-- `EsploraSenderLookup.parseFundingAddresses`: a top-level object with a `vin` array of objects, each
optionally carrying `prevout.scriptpubkey_address`; the distinct addresses in input order. -/
def parseFundingAddresses (data : ByteArray) (network : BitcoinNetwork) (expectedTxid : Option String) :
    RM (List String) := do
  unless data.size ≤ maximumLookupBytes do throw (.lookup "Explorer response too large.")
  let some text := String.fromUTF8? data | throw lookupFormatError
  let some (.obj root) := parse? text | throw lookupFormatError
  let some (.arr vin) := SwiftJSON.lookup root "vin" | throw lookupFormatError
  let inputs ← vin.mapM fun v => match v with | .obj kvs => pure kvs | _ => throw lookupFormatError
  unless inputs.size ≤ 10_000 do throw lookupFormatError
  if let some expected := expectedTxid then
    unless SwiftJSON.lookup root "txid" == some (.str expected) do
      throw (.lookup "The explorer returned a different transaction.")
  let mut out : Array String := #[]
  for input in inputs do
    let some (.obj prevout) := SwiftJSON.lookup input "prevout" | continue
    let some (.str address) := SwiftJSON.lookup prevout "scriptpubkey_address" | continue
    if address.isEmpty || out.contains address then continue
    discard <| RM.lift (fun e => namedError e.name network) (AddressDecoder.scriptPubKey address network)
    out := out.push address
  return out.toList

/-- One GET of `{baseURL}/tx/{txid}` through `get url maximumBytes` (the routed HTTP client); `txid` in
display hex. The consent check (network generation) is the caller's. -/
def lookupSender (get : String → Nat → IO ByteArray) (network : BitcoinNetwork) (txid baseURL : String) :
    RM (List String) := do
  let some raw := Wire.dataOfHex? txid | throw (.lookup "Invalid transaction ID.")
  unless raw.size == 32 do throw (.lookup "Invalid transaction ID.")
  let url := appendPath baseURL ["tx", txid]
  let data ← RM.io (get url maximumLookupBytes)
  parseFundingAddresses data network (some txid)

/-- The getter over the I/O area's `RoutedHTTPClient`. -/
def routedGetter (c : Winnow.IO.RoutedHTTPClient) : String → Nat → IO ByteArray := fun url max =>
  (c.get url max).toIO

/-! ## Vaults -/

def roleOf : VaultRole → VaultCosignerRole | .scriptPath => .scriptPath | .muSig2 => .muSig2

def cosignerError (e : VaultCosignerKeyError) : RecordsError := .named e.name e.description

/-- `VaultDraft.add`'s validation (shape, network, duplicate) against the cosigners already added. -/
def checkCosigner (network : BitcoinNetwork) (role : VaultRole) (existing : List String) (expression : String) : RM Unit := do
  let mut d : VaultDraft := { role := roleOf role }
  for e in existing do
    d ← RM.lift cosignerError (d.add e network)
  discard <| RM.lift cosignerError (d.add expression network)

/-- VaultCreateView's build: `tr(musig(…)/<0;1>/*)` or `Vault.multiADescriptor`, validated as a vault. -/
def buildVault (network : BitcoinNetwork) (role : VaultRole) (threshold : Nat) (cosigners : List String) : RM VaultBuild := do
  let mut d : VaultDraft := { role := roleOf role }
  for e in cosigners do
    d ← RM.lift cosignerError (d.add e network)
  let validated := d.cosigners.map (·.expression)
  let descriptor ← if role == .muSig2 then
      RM.lift (fun (e : DescriptorError) => namedError e.name network)
        (Descriptor.parse s!"tr(musig({",".intercalate validated.toList})/<0;1>/*)")
    else liftVault network (Vault.multiADescriptor threshold validated)
  let vault ← liftVault network (Vault.ofDescriptor descriptor network)
  return { descriptor := descriptor.serialized, firstAddress := (vault.address 0 0).toOption,
           threshold := vault.threshold.toNat, signerCount := vault.signerCount, isScriptPath := vault.isScriptPath }

def addVaultDescriptor (s : RecordsStore) (w : Option Wallet) (createdAtHeight : UInt32) (name : String)
    (descriptor : Descriptor) : RM (VaultRecord × Records) := do
  let record ← s.modify fun st => do
    let (vs, r) ← st.vaults.add s.keys s.writeData name descriptor createdAtHeight
    return ({ st with vaults := vs }, r)
  s.note "vault.created" [("name", name), ("descriptor", descriptor.serialized), ("height", toString createdAtHeight)]
  return (record, ← RM.io (records s w))

/-- `addVault(name:descriptor:)`; `createdAtHeight` is the filter frontier (or the wallet's next scan height). -/
def addVault (s : RecordsStore) (w : Option Wallet) (createdAtHeight : UInt32) (name descriptor : String) : RM Records := do
  let d ← RM.lift (fun e => namedError e.name s.network) (Descriptor.parse descriptor)
  return (← addVaultDescriptor s w createdAtHeight name d).2

/-- `removeVault(id:)`: best effort. -/
def removeVault (s : RecordsStore) (w : Option Wallet) (vaultID : String) : IO Records := do
  discard <| (s.modify fun st => do return ({ st with vaults := ← st.vaults.remove s.keys s.writeData vaultID }, ())).run
  records s w

/-- `advanceVaultReceiveIndex(id:)`: best effort. -/
def advanceVaultReceive (s : RecordsStore) (w : Option Wallet) (vaultID : String) : IO Records := do
  discard <| (s.modify fun st => do
    return ({ st with vaults := ← st.vaults.advanceReceiveIndex s.keys s.writeData vaultID }, ())).run
  records s w

/-- `createSharedSavings(name:coOwners:threshold:)`: the chosen people's signer keys plus this wallet's own,
filed as a vault. The new vault's id with the records. -/
def createSharedSavings (s : RecordsStore) (w : Wallet) (createdAtHeight : UInt32) (name : String)
    (personIDs : List String) (threshold : Nat) : RM (String × Records) := do
  let st ← RM.io s.read
  let keys ← personIDs.mapM fun pid => do
    let some p := st.people.record? pid | throw (.people .unknownPerson)
    let some k := p.signerKey | throw (.app (.personCannotCoOwn p.name))
    pure k
  let own ← ownKeyExpression w true
  let descriptor ← liftVault s.network (Vault.multiADescriptor threshold (#[own] ++ keys.toArray))
  let (record, r) ← addVaultDescriptor s (some w) createdAtHeight name descriptor
  let coOwners := personIDs.filterMap fun pid => (st.people.record? pid).map (·.name)
  s.note "savings.created" [("name", name), ("descriptor", descriptor.serialized), ("coOwners", ",".intercalate coOwners)]
  return (record.id, r)

/-- `addSharedSavings(card:)`: validated as a vault for this network before it is filed. -/
def addSharedSavings (s : RecordsStore) (w : Option Wallet) (createdAtHeight : UInt32) (card : String) : RM Records := do
  let (c, vault) ← liftNamed s.network (SharedSavingsCard.decode card s.network)
  let (_, r) ← addVaultDescriptor s w createdAtHeight c.name vault.descriptor
  s.note "savings.added" [("name", c.name), ("descriptor", vault.descriptor.serialized)]
  return r

def vaultRecord (s : RecordsStore) (vaultID : String) : RM VaultRecord := do
  let some r := (← RM.io s.read).vaults.record? vaultID | throw (.app .unknownVault)
  return r

/-- `sharedSavingsCard(for:)`. -/
def sharedSavingsCard (s : RecordsStore) (vaultID : String) : RM String := do
  let r ← vaultRecord s vaultID
  return (SharedSavingsCard.make s.network r.name r.descriptor).serialized

/-! ## Vault spends: review, recording -/

/-- `vaultAuthorizationCoordinates(for:)`: every coin's own, plus the next receive and change slots. -/
def authorizationCoordinates (r : VaultRecord) : Array Vault.OutputCoordinate :=
  r.utxos.map (fun u => ({ choice := u.chain.rawValue, index := u.index } : Vault.OutputCoordinate)) ++
    #[{ choice := 0, index := r.nextReceiveIndex }, { choice := 1, index := r.nextChangeIndex }]

def vaultOf (s : RecordsStore) (r : VaultRecord) : RM Vault := liftVault s.network (Vault.parse r.descriptor s.network)

/-- `reviewVaultSpend(_:record:)`: proves a proposal is an exact, safe spend of the vault's known coins. -/
def reviewVaultSpend (s : RecordsStore) (r : VaultRecord) (p : PSBT) (tip : UInt32) : RM Vault.SpendReview := do
  let v ← vaultOf s r
  liftVault s.network (v.reviewSpend p r.utxos (authorizationCoordinates r) tip)

/-- A finalized vault spend, ready for the caller to broadcast; `commitVaultSpend` records it afterwards. -/
structure FinishedSpend where
  vaultID : String
  transaction : Transaction
  /-- The raw transaction (with witnesses), hex. -/
  rawHex : String
  /-- Display hex. -/
  txid : String
  changeScriptPubKey : Option ByteArray
  changeIndex : UInt32
  deriving Inhabited

def finished (r : VaultRecord) (v : Vault) (tx : Transaction) : FinishedSpend :=
  { vaultID := r.id, transaction := tx, rawHex := hex (tx.serialized true), txid := displayHex tx.txid,
    changeScriptPubKey := (v.scriptPubKey r.nextChangeIndex 1).toOption, changeIndex := r.nextChangeIndex }

/-- `recordVaultSpend` after the broadcast: inputs out, change in pending, and whether anything was
recorded (false: already recorded, or no known input). A failure here reads as `vaultSpendNotRecorded`
with the txid (the transaction is out). -/
def recordVaultSpend (s : RecordsStore) (w : Option Wallet) (f : FinishedSpend) : RM (Records × Bool) := do
  let r ← RM.io (s.modify fun st => do
    let (vs, recorded) ← st.vaults.recordSpend s.keys s.writeData f.vaultID f.transaction f.changeScriptPubKey f.changeIndex
    return ({ st with vaults := vs }, recorded)).run
  match r with
  | .ok recorded =>
    if recorded then
      s.note "vault.spendRecorded" [("vaultID", f.vaultID), ("txid", f.txid), ("changeIndex", toString f.changeIndex),
                                    ("hasChange", toString f.changeScriptPubKey.isSome)]
    return (← RM.io (records s w), recorded)
  | .error e => throw (.app (.vaultSpendNotRecorded f.txid e.description))

def commitVaultSpend (s : RecordsStore) (w : Option Wallet) (f : FinishedSpend) : RM Records := do
  return (← recordVaultSpend s w f).1

/-! ## Sync hooks (what `syncOnce` and the rollback do with the vault store) -/

def vaultWatchScripts (s : RecordsStore) : RM (Array ByteArray) := do
  (← RM.io s.read).vaults.watchScripts s.network

def applyVaultMatch (s : RecordsStore) (m : Net.BlockMatch) : RM Unit :=
  s.modify fun st => do return ({ st with vaults := ← st.vaults.apply s.keys s.writeData m s.network }, ())

def rollBackVaults (s : RecordsStore) (forkHeight : UInt32) : RM Unit :=
  s.modify fun st => do return ({ st with vaults := ← st.vaults.rollBack s.keys s.writeData forkHeight }, ())

def backupVaultRecords (s : RecordsStore) : RM (Array VaultRecord) := do (← RM.io s.read).vaults.backupRecords

def restoreVaults (s : RecordsStore) (restored : Array VaultRecord) : RM Unit :=
  s.modify fun st => do return ({ st with vaults := ← st.vaults.restore s.keys s.writeData restored }, ())

/-! ## The vault path of `previewSend` and `prepareVaultApproval` -/

/-- The reviewed vault send (`SendPreview` with source `.vault(record, psbt)`): kept by the caller between
review and `prepareVaultApproval`. -/
structure VaultSendPreview where
  vaultID : String
  descriptor : String
  psbt : PSBT
  destination : String
  payments : Array Payment
  fee : Int64
  changeAmount : Option Int64
  selectedOutpoints : Array Transaction.Outpoint
  change : Option Payment
  locktimeLagsTip : Bool
  recipient : Option PreviewRecipient := none
  /-- The person's payment index the address was derived at (fresh-address recipients only). -/
  paymentIndex : Option UInt32 := none
  deriving Inhabited

def VaultSendPreview.amountSent (p : VaultSendPreview) : Int64 := p.payments.foldl (fun a x => a + x.amount) 0

/-- `SendPreview.authorizes(_:)`: the built transaction is the reviewed one. -/
def VaultSendPreview.authorizes (p : VaultSendPreview) (built : BuiltTransaction) : Bool := Id.run do
  unless built.fee == p.fee && built.changeAmount == p.changeAmount &&
      built.transaction.inputs.map (·.previousOutput) == p.selectedOutpoints do return false
  let expected := match p.change with | some c => p.payments.push c | none => p.payments
  unless built.transaction.outputs.size == expected.size do return false
  let mut unmatched := built.transaction.outputs
  for payment in expected do
    let some i := unmatched.findIdx? (fun o => o.value == payment.amount && o.scriptPubKey == payment.scriptPubKey)
      | return false
    unmatched := unmatched.eraseIdx! i
  unless unmatched.isEmpty do return false
  return p.change.isNone == p.changeAmount.isNone

def VaultSendPreview.toPreview (p : VaultSendPreview) (name : String) (v : Vault) (feeRateMilli : Nat) : Preview :=
  { source := .vault p.vaultID name p.psbt.base64 v.isScriptPath v.threshold.toNat v.signerCount,
    recipient := p.recipient, destination := p.destination, amount := p.amountSent.toInt.toNat,
    fee := p.fee.toInt.toNat, feeRateMilli, inputCount := p.selectedOutpoints.size,
    change := p.changeAmount.map (·.toInt.toNat), locktimeLagsTip := p.locktimeLagsTip }

/-- `previewSend(destination:…accountID:)` for a vault (`previewVaultSend`): the spend PSBT (creator role)
at the resolved fee rate, reviewed. `personID` pays the person's next address (peeked). -/
def previewVaultSend (s : RecordsStore) (vaultID : String) (destination : String) (amount : Int64)
    (feeRateMilli : Nat) (tip : UInt32) (locktimeLagsTip : Bool) (personID : Option String := none)
    (random : Randomness := .system) (exactRate : Option Float := none) : RM (VaultSendPreview × Preview) := do
  let r ← vaultRecord s vaultID
  let st ← RM.io s.read
  let (destination, recipient, paymentIndex) ← match personID with
    | none => pure (Wire.trimWhitespace destination, none, none)
    | some pid => do
      let some p := st.people.record? pid | throw (.people .unknownPerson)
      let (address, index) ← nextPaymentAddress s pid
      pure (address, some ({ personID := p.id, name := p.name, derivesFreshAddresses := p.derivesFreshAddresses,
                             hasUnverifiedFundingDestination := p.hasUnverifiedFundingDestination } : PreviewRecipient),
            if p.derivesFreshAddresses then some index else none)
  let payment ← RM.lift (fun e => namedError e.name s.network) (Payment.ofAddress amount destination s.network)
  let v ← vaultOf s r
  let feeRate := exactRate.getD (feeRateMilli.toFloat / 1000)
  let psbt ← liftVaultIO s.network (v.createSpend r.utxos #[payment] r.nextChangeIndex feeRate tip random)
  s.notePSBT "vault-spend-created" psbt
  let reviewed ← reviewVaultSpend s r psbt tip
  let tx ← RM.lift (fun e => namedError e.name s.network) psbt.unsignedTransaction
  let remaining := reviewed.outputTotal - payment.amount
  let changeScript ← liftVault s.network (v.scriptPubKey r.nextChangeIndex 1)
  let vp : VaultSendPreview := {
    vaultID := r.id, descriptor := r.descriptor, psbt, destination, payments := #[payment], fee := reviewed.fee,
    changeAmount := if remaining > 0 then some remaining else none,
    selectedOutpoints := tx.inputs.map (·.previousOutput),
    change := if remaining > 0 then some { amount := remaining, scriptPubKey := changeScript } else none,
    locktimeLagsTip, recipient, paymentIndex }
  return (vp, vp.toPreview r.name v feeRateMilli)

/-- `prepareVaultApproval(_:)`: the vault spend is still the reviewed one; a fresh-address recipient's
counter moves past the reserved index. -/
def prepareVaultApproval (s : RecordsStore) (w : Option Wallet) (p : VaultSendPreview) (tip : UInt32) : RM Records := do
  let st ← RM.io s.read
  let some r := st.vaults.records.find? (fun r => r.id == p.vaultID && r.descriptor == p.descriptor)
    | throw (.app .sendReviewChanged)
  let reviewed ← reviewVaultSpend s r p.psbt tip
  let remaining := reviewed.outputTotal - p.amountSent
  let tx ← RM.lift (fun e => namedError e.name s.network) p.psbt.unsignedTransaction
  let built : BuiltTransaction := { psbt := p.psbt, transaction := tx, fee := reviewed.fee,
                                    changeAmount := if remaining > 0 then some remaining else none }
  unless p.authorizes built do throw (.app .sendReviewChanged)
  if let (some rec, some index) := (p.recipient, p.paymentIndex) then
    unless ((st.people.record? rec.personID).map (·.nextPaymentIndex)) == some index do throw (.app .sendReviewChanged)
    withPeople s w fun ps => ps.advancePaymentIndex s.keys s.writeData rec.personID index
  else RM.io (records s w)

end WinnowApp.RecordsReal
