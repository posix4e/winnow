import WinnowApp.Backend
import WinnowApp.Real.RecordsSession

/-! # The records fields of `Backend`, ready to plug in

`RecordsCtx` bundles what the records operations need from the core (the current store, the open
wallet, the chain tip, the creation height of new vaults, the HTTP getter, the broadcaster); each
definition below has exactly the type of the `Backend` field of the same name, so the core writes
`records := ctx.records, addPerson := ctx.addPerson, …`. Failures surface as `IO.userError` with the
description the screens show. -/

namespace WinnowApp.RecordsReal
open Winnow

structure RecordsCtx where
  /-- The records of the current network (the core swaps it on a network switch). -/
  store : IO RecordsStore
  wallet : IO (Option Wallet)
  /-- `status.tipHeight`, for spend reviews. -/
  tip : IO UInt32
  /-- `filters.nextScanHeight`, else the wallet's `nextScanHeight`: a new vault's `createdAtHeight`. -/
  creationHeight : IO UInt32
  /-- The explorer GET (`url`, `maximumBytes`), e.g. `routedGetter httpClient`. -/
  http : String → Nat → IO ByteArray
  /-- AppModel's `broadcast(_:)`: hands the transaction to the broadcaster; throws if it could not. -/
  broadcast : Transaction → IO Unit
  sessions : MusigSessions
  /-- `e2e?.journal(_:fields:)` (test mode); a no-op otherwise. -/
  journal : String → List (String × String) → IO Unit := fun _ _ => pure ()
  /-- `journalSnapshotIfChanged()` of the core, after a recorded vault spend. -/
  journalSnapshot : IO Unit := pure ()

namespace RecordsCtx

def needWallet (c : RecordsCtx) : RM Wallet := do
  let some w ← RM.io c.wallet | throw (.app .noWallet)
  return w

def run {α} (c : RecordsCtx) (f : RecordsStore → Option Wallet → RM α) : IO α := RM.toIO do
  f (← RM.io c.store) (← RM.io c.wallet)

def runW {α} (c : RecordsCtx) (f : RecordsStore → Wallet → RM α) : IO α := RM.toIO do
  f (← RM.io c.store) (← c.needWallet)

def records (c : RecordsCtx) : IO Records := do RecordsReal.records (← c.store) (← c.wallet)

def setReceiveLabel (c : RecordsCtx) (address label : String) : IO Records :=
  c.runW fun s w => RecordsReal.setReceiveLabel s w address label

def ownCard (c : RecordsCtx) (name : String) : IO String :=
  c.runW fun _ w => do return (← ownPersonCard w name).serialized

def parsePaste (c : RecordsCtx) (text : String) : IO PastePreview :=
  c.run fun s _ => RecordsReal.parsePaste s.network text

def addPerson (c : RecordsCtx) (name : String) (paste : Option String) (forSigning : Bool) (provenance : Option Provenance)
    (source : Option String) (labelTxid : Option String) : IO Records :=
  c.run fun s w => RecordsReal.addPerson s w name paste forSigning provenance source labelTxid

def attachDestination (c : RecordsCtx) (personID paste : String) (provenance : Provenance) (source : Option String) :
    IO Records :=
  c.run fun s w => RecordsReal.attachDestination s w personID paste provenance source

def updateRecipient (c : RecordsCtx) (personID : String) (name : Option String) (saved : Bool) : IO Records :=
  c.run fun s w => RecordsReal.updateRecipient s w personID name saved

def labelSender (c : RecordsCtx) (txid personID : String) : IO Records :=
  c.run fun s w => RecordsReal.labelSender s w txid personID

def removeSenderLabel (c : RecordsCtx) (txid : String) : IO Records :=
  c.run fun s w => RecordsReal.removeSenderLabel s w txid

/-- `URL.host` of an explorer base URL: no scheme, user, port or path ("" when there is none). -/
def urlHost (url : String) : String :=
  match url.splitOn "://" with
  | _ :: rest@(_ :: _) =>
    let afterScheme := "://".intercalate rest
    let authority := (afterScheme.takeWhile fun ch => ch != '/' && ch != '?' && ch != '#').toString
    let hostPort := (authority.splitOn "@").getLast!
    if hostPort.startsWith "[" then ((hostPort.drop 1).takeWhile (· != ']')).toString
    else (hostPort.takeWhile (· != ':')).toString
  | _ => ""

def lookupSender (c : RecordsCtx) (txid baseURL : String) : IO (List String) := do
  let addresses ← c.run fun s _ => RecordsReal.lookupSender c.http s.network txid baseURL
  c.journal "sender.lookupOnline" [("txid", txid), ("explorer", urlHost baseURL)]
  return addresses

def ownKeyExpression (c : RecordsCtx) (multipath : Bool) : IO String :=
  c.runW fun _ w => RecordsReal.ownKeyExpression w multipath

def checkCosigner (c : RecordsCtx) (role : VaultRole) (existing : List String) (expression : String) : IO Unit :=
  c.run fun s _ => RecordsReal.checkCosigner s.network role existing expression

def buildVault (c : RecordsCtx) (role : VaultRole) (threshold : Nat) (cosigners : List String) : IO VaultBuild :=
  c.run fun s _ => RecordsReal.buildVault s.network role threshold cosigners

def addVault (c : RecordsCtx) (name descriptor : String) : IO Records := do
  let h ← c.creationHeight
  c.run fun s w => RecordsReal.addVault s w h name descriptor

def removeVault (c : RecordsCtx) (vaultID : String) : IO Records := do
  RecordsReal.removeVault (← c.store) (← c.wallet) vaultID

def advanceVaultReceive (c : RecordsCtx) (vaultID : String) : IO Records := do
  RecordsReal.advanceVaultReceive (← c.store) (← c.wallet) vaultID

def createSharedSavings (c : RecordsCtx) (name : String) (personIDs : List String) (threshold : Nat) :
    IO (String × Records) := do
  let h ← c.creationHeight
  c.runW fun s w => RecordsReal.createSharedSavings s w h name personIDs threshold

def addSharedSavings (c : RecordsCtx) (card : String) : IO Records := do
  let h ← c.creationHeight
  c.run fun s w => RecordsReal.addSharedSavings s w h card

def sharedSavingsCard (c : RecordsCtx) (vaultID : String) : IO String :=
  c.run fun s _ => RecordsReal.sharedSavingsCard s vaultID

/-- Broadcast a finished spend, then record it (`broadcastVaultSpend`); the txid. -/
def broadcastFinished (c : RecordsCtx) (s : RecordsStore) (w : Option Wallet) (f : FinishedSpend) : RM String := do
  RM.io (c.broadcast f.transaction)
  let (_, recorded) ← recordVaultSpend s w f
  if recorded then RM.io c.journalSnapshot
  return f.txid

def approvalAdd (c : RecordsCtx) (vaultID : String) (working : Option String) (text : String) : IO ApprovalReview := do
  let tip ← c.tip
  c.run fun s w => RecordsReal.approvalAdd s w vaultID working text tip

def approvalRecheck (c : RecordsCtx) (vaultID working : String) : IO ApprovalReview := do
  let tip ← c.tip
  c.run fun s w => RecordsReal.approvalRecheck s w vaultID working tip

def approvalApprove (c : RecordsCtx) (vaultID working : String) : IO ApprovalReview := do
  let tip ← c.tip
  c.runW fun s w => RecordsReal.approvalApprove s w vaultID working tip

def approvalFinish (c : RecordsCtx) (vaultID working : String) : IO String := do
  let tip ← c.tip
  let txid ← c.run fun s w => do c.broadcastFinished s w (← RecordsReal.approvalFinish s w vaultID working tip)
  c.journal "approval.finished" [("txid", txid), ("vaultID", vaultID)]
  return txid

def musigAdd (c : RecordsCtx) (vaultID : String) (working : Option String) (text : String) : IO MusigReview := do
  let tip ← c.tip
  c.run fun s w => RecordsReal.musigAdd s w vaultID working text tip

def musigNonces (c : RecordsCtx) (vaultID working : String) : IO MusigReview := do
  let tip ← c.tip
  c.runW fun s w => RecordsReal.musigNonces s c.sessions w vaultID working tip

def musigSign (c : RecordsCtx) (vaultID working : String) : IO MusigReview := do
  let tip ← c.tip
  c.runW fun s w => RecordsReal.musigSign s c.sessions w vaultID working tip

def musigBroadcast (c : RecordsCtx) (vaultID working : String) : IO String := do
  let tip ← c.tip
  c.run fun s w => do c.broadcastFinished s w (← RecordsReal.musigBroadcast s vaultID working tip)

def musigRestart (c : RecordsCtx) (vaultID working : String) : IO MusigReview := do
  let tip ← c.tip
  c.run fun s w => RecordsReal.musigRestart s c.sessions w vaultID working tip

def musigRecheck (c : RecordsCtx) (vaultID working : String) : IO MusigReview := do
  let tip ← c.tip
  c.run fun s w => RecordsReal.musigRecheck s w vaultID working tip

def musigClear (c : RecordsCtx) : IO Unit := RecordsReal.musigClear c.sessions

/-- The records fields of `base` replaced by these. -/
def install (c : RecordsCtx) (base : Backend) : Backend :=
  { base with
    records := c.records, setReceiveLabel := c.setReceiveLabel, ownCard := c.ownCard, parsePaste := c.parsePaste,
    addPerson := c.addPerson, attachDestination := c.attachDestination, updateRecipient := c.updateRecipient,
    labelSender := c.labelSender, removeSenderLabel := c.removeSenderLabel, lookupSender := c.lookupSender,
    ownKeyExpression := c.ownKeyExpression, checkCosigner := c.checkCosigner, buildVault := c.buildVault,
    addVault := c.addVault, removeVault := c.removeVault, advanceVaultReceive := c.advanceVaultReceive,
    createSharedSavings := c.createSharedSavings, addSharedSavings := c.addSharedSavings,
    sharedSavingsCard := c.sharedSavingsCard,
    approvalAdd := c.approvalAdd, approvalRecheck := c.approvalRecheck, approvalApprove := c.approvalApprove,
    approvalFinish := c.approvalFinish,
    musigAdd := c.musigAdd, musigNonces := c.musigNonces, musigSign := c.musigSign, musigBroadcast := c.musigBroadcast,
    musigRestart := c.musigRestart, musigRecheck := c.musigRecheck, musigClear := c.musigClear }

end RecordsCtx
end WinnowApp.RecordsReal
