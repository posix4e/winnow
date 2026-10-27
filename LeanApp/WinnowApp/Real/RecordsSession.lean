import WinnowApp.Real.Records

/-! # Shared-savings spends on this phone (ports of `VaultSpendSession.swift` and `MuSig2SignView.swift`)

The script-path approval flow is stateless here: the working PSBT is public and travels in the app's
Model (as Base64), so every operation re-reads it, combines, re-reviews against trusted local state and
answers with an `ApprovalReview`.

The MuSig2 exchange is not: round 1's secret nonces must stay on this phone, between the two rounds, and
nowhere else. They live only in a `MusigSessions` value this module owns (behind a `Std.Mutex`), never in
`MusigReview`, `Records` or any app type. Round 2 consumes them and they are scrubbed (overwritten, then
dropped) after a successful round 2, on restart, on `musigClear`, and whenever a session for another vault
starts. As in Swift this is best effort: a Lean `ByteArray` shared with another reference is copied, not
zeroed, on write.

The SwiftUI screens gate each step by disabling buttons; here each gate is a refusal
(`SessionError.notReady`), so the backend cannot be driven into a second nonce or a second signature.

Broadcasting is the caller's: `approvalFinish` and `musigBroadcast` return the finalized transaction
(`FinishedSpend`); after the broadcast succeeds the caller records it with `commitVaultSpend`. -/

namespace WinnowApp.RecordsReal
open Winnow
open Tx (BitcoinNetwork)

def parsePSBT (network : BitcoinNetwork) (text : String) : RM PSBT :=
  RM.lift (fun (e : PSBTError) => namedError e.name network) (PSBT.ofBase64 (Wire.trimWhitespace text))

def combine (network : BitcoinNetwork) (working : Option PSBT) (incoming : PSBT) : RM PSBT :=
  match working with
  | some w => RM.lift (fun (e : PSBTRoleError) => namedError e.name network) (w.combined #[incoming])
  | none => pure incoming

/-- `VaultSpendSession.address(forScript:network:)`: hex for anything non-standard. -/
def addressForScript (script : ByteArray) (network : BitcoinNetwork) : String :=
  (AddressDecoder.address script network).getD (hex script)

def payLabel : PaymentLabel → PayLabel
  | .savings n => .savings n | .person n => .person n | .you => .you | .unknown => .unknown

def ownWatchScripts (s : RecordsStore) (w : Option Wallet) : IO (Array ByteArray) := do
  let some w := w | return #[]
  return (← (liftWallet s.network w.watchScripts).run).toOption.getD #[]

/-- The reviewed outputs, labelled as the approval screen labels them. -/
def spendLines (s : RecordsStore) (w : Option Wallet) (r : VaultRecord) (review : Vault.SpendReview) : IO (List SpendLine) := do
  let named := (← recipients s).map fun (sc, p) => (sc, p.name)
  let labeler : PaymentLabeler := { savingsName := r.name, personScripts := named,
                                    ownScripts := ← ownWatchScripts s w }
  return review.outputs.toList.map fun o =>
    { label := payLabel (labeler.label o.scriptPubKey o.isVaultOwned), address := addressForScript o.scriptPubKey s.network,
      amount := o.amount.toInt.toNat, isVaultOwned := o.isVaultOwned }

/-! ## Script-path approvals (`VaultSpendSession`) -/

def approvalRequest (s : RecordsStore) (r : VaultRecord) (p : PSBT) : String :=
  (ApprovalRequest.make s.network (some r.id) (some r.name) p).serialized

/-- `resolveSignerNames(vault:)`: "you", a saved person's name, or "an unnamed co-owner". -/
def signerNames (s : RecordsStore) (w : Option Wallet) (v : Vault) : IO (List (Nat × String) × Option Nat) := do
  let some keys := v.signerKeys.toOption | return ([], none)
  let ownKey ← ownSignerIdentity? w
  let identities := signerIdentities (← s.read).people.records s.network
  let mut names := #[]
  let mut own := none
  for h : i in [0:keys.size] do
    let key := keys[i]
    if ownKey == some key then
      names := names.push (i, "you")
      own := some i
    else names := names.push (i, ((identities.find? (·.2 == key)).map (·.1.name)).getD "an unnamed co-owner")
  return (names.toList, own)

/-- `refresh(with:record:)`: review, lines, approvals, signer names. Throws when the spend is not valid. -/
def approvalRefresh (s : RecordsStore) (w : Option Wallet) (r : VaultRecord) (p : PSBT) (tip : UInt32) : RM ApprovalReview := do
  let v ← vaultOf s r
  let reviewed ← reviewVaultSpend s r p tip
  let lines ← RM.io (spendLines s w r reviewed)
  let approvals ← liftVault s.network (v.signers p r.utxos)
  let (names, own) ← RM.io (signerNames s w v)
  return { working := p.base64, output := approvalRequest s r p, rawPSBT := p.base64V0.toOption, lines := some lines,
           fee := some reviewed.fee.toInt.toNat, threshold := if v.isScriptPath then v.threshold.toNat else 0,
           approvals := approvals.toList, signerNames := names, ownPosition := own }

/-- The review of a request that cannot be reviewed against local state (`recheck` failing): no lines,
no approvals, the reason. -/
def approvalUnreviewed (s : RecordsStore) (w : Option Wallet) (r : VaultRecord) (p : PSBT) (reason : Option String) :
    IO ApprovalReview := do
  let v? := (Vault.parse r.descriptor s.network).toOption
  let (names, own) ← match v? with | some v => signerNames s w v | none => pure ([], none)
  return { working := p.base64, output := approvalRequest s r p, rawPSBT := p.base64V0.toOption, lines := none,
           reviewError := reason, threshold := (v?.map fun v => if v.isScriptPath then v.threshold.toNat else 0).getD 0,
           signerNames := names, ownPosition := own }

/-- `add(text:)`: a request (envelope or bare PSBT) combined into the working copy and re-reviewed. A
request for other savings is refused by name. -/
def approvalAdd (s : RecordsStore) (w : Option Wallet) (vaultID : String) (working : Option String) (text : String)
    (tip : UInt32) : RM ApprovalReview := do
  let st ← RM.io s.read
  let some r := st.vaults.record? vaultID | throw (.session (.unknownSavings none))
  let request ← liftNamed s.network (ApprovalRequest.decode text s.network)
  if let some other := request.vault then
    if other != r.id then
      throw (.session (if st.vaults.records.any (·.id == other) then .notTheseSavings else .unknownSavings request.name))
  let incoming ← liftNamed s.network request.decodedPSBT
  let w0 ← working.mapM (parsePSBT s.network)
  let candidate ← combine s.network w0 incoming
  let review ← approvalRefresh s w r candidate tip
  s.notePSBT "vault-psbt-combined" candidate
  return review

/-- `recheck()`: against trusted local state; a spend no longer valid loses its review and approvals. -/
def approvalRecheck (s : RecordsStore) (w : Option Wallet) (vaultID working : String) (tip : UInt32) : RM ApprovalReview := do
  let p ← parsePSBT s.network working
  let some r := (← RM.io s.read).vaults.record? vaultID
    | return { working := p.base64, output := "", lines := none, threshold := 0 }
  match ← RM.io (approvalRefresh s w r p tip).run with
  | .ok review => pure review
  | .error e => RM.io (approvalUnreviewed s w r p (some e.description))

/-- `approve()` (after authentication): this device's script-path signature on every input, after the
review that decides what it authorizes. -/
def approvalApprove (s : RecordsStore) (w : Wallet) (vaultID working : String) (tip : UInt32) : RM ApprovalReview := do
  let p ← parsePSBT s.network working
  let r ← vaultRecord s vaultID
  let v ← vaultOf s r
  let current ← approvalRefresh s (some w) r p tip
  if let some own := current.ownPosition then
    if current.approvals.contains own then throw (.session (.notReady "You already approved this payment."))
  let master ← liftWallet s.network w.masterKey
  let signed ← liftVaultIO s.network (v.partialSign p master r.utxos (authorizationCoordinates r) tip)
  s.notePSBT "multi-a-partial-signed" signed
  let review ← approvalRefresh s (some w) r signed tip
  s.note "approval.given" [("approvals", toString review.approvals.length), ("vaultID", r.id)]
  return review

/-- `finish()`: once enough co-owners approved every input, the finalized transaction (the caller
broadcasts it, then `commitVaultSpend`). -/
def approvalFinish (s : RecordsStore) (w : Option Wallet) (vaultID working : String) (tip : UInt32) : RM FinishedSpend := do
  let p ← parsePSBT s.network working
  let r ← vaultRecord s vaultID
  let v ← vaultOf s r
  unless v.isScriptPath do throw (.session (.notReady "These savings do not use approvals."))
  let review ← approvalRefresh s w r p tip
  unless review.approvals.length ≥ review.threshold do
    throw (.session (.notReady "Not enough co-owners have approved yet."))
  let (_, tx) ← liftVault s.network (v.finalizeSpend p r.utxos (authorizationCoordinates r) tip)
  return finished r v tx

/-! ## MuSig2 (`MuSig2SignView`) -/

/-- One phone's side of one MuSig2 exchange: round-1 secret nonces per input (participant → secnonce). -/
structure MusigSession where
  vaultID : String
  nonces : Array (Nat × Array (ByteArray × ByteArray)) := #[]
  nonceSessionStarted : Bool := false
  signedThisSession : Bool := false
  deriving Inhabited

/-- The session store (at most one exchange at a time, like the one signing sheet). -/
structure MusigSessions where
  state : Std.Mutex (Option MusigSession)

def MusigSessions.new : IO MusigSessions := do return { state := ← Std.Mutex.new none }

/-- Overwrites every secret nonce before dropping them (best effort). -/
def scrubNonces (nonces : Array (Nat × Array (ByteArray × ByteArray))) : Array (Nat × Array (ByteArray × ByteArray)) :=
  nonces.map fun (i, xs) => (i, xs.map fun (k, v) => (k, ByteArray.mk (Array.replicate v.size 0)))

def MusigSession.scrubbed (m : MusigSession) : MusigSession :=
  { m with nonces := (scrubNonces m.nonces).filter fun _ => false }

/-- The session for `vaultID`; a session for any other vault is scrubbed and dropped first. -/
def sessionFor (vaultID : String) : Std.AtomicT (Option MusigSession) RM MusigSession := do
  match ← get with
  | some m =>
    if m.vaultID == vaultID then return m
    set (some m.scrubbed); set (none : Option MusigSession)
    return { vaultID }
  | none => return { vaultID }

def participantCount (v : Vault) : Option Nat :=
  match v.policy with | .muSig2 ps _ => some ps.size | _ => none

def minNonces (p : PSBT) : Nat := (p.inputs.map (·.musig2PubNonces.size)).foldl min (if p.inputs.isEmpty then 0 else p.inputs[0]!.musig2PubNonces.size)
def minPartialSigs (p : PSBT) : Nat := (p.inputs.map (·.musig2PartialSigs.size)).foldl min (if p.inputs.isEmpty then 0 else p.inputs[0]!.musig2PartialSigs.size)

/-- The proposal as the signing screen shows it; `reviewError` set (and no lines) when it is not a valid
spend of the vault's available coins. -/
def musigReviewOf (s : RecordsStore) (w : Option Wallet) (r : VaultRecord) (p : PSBT) (tip : UInt32) : IO MusigReview := do
  let v? := (Vault.parse r.descriptor s.network).toOption
  let base : MusigReview := { working := p.base64, output := (p.base64V0.toOption).getD p.base64, lines := none,
                              participantCount := v?.bind participantCount, minNonces := minNonces p,
                              minPartialSigs := minPartialSigs p }
  match ← (reviewVaultSpend s r p tip).run with
  | .ok review =>
    let lines ← spendLines s w r review
    let sighashes := review.sighashTypes.toList.map (·.toNat)
    let txVersion := review.transactionVersion.toInt.toNat
    let sequences := review.sequences.toList.map (·.toNat)
    return { base with lines := some lines, fee := some review.fee.toInt.toNat, sighashTypes := sighashes,
                       version := txVersion, locktime := some review.fallbackLocktime.toNat, sequences := sequences }
  | .error e => return { base with reviewError := some e.description }

/-- `context(for:vault:record:)`: an input's vault coordinates, found via the vault's coins. -/
def inputContext (s : RecordsStore) (v : Vault) (r : VaultRecord) (input : PSBT.Input) : RM Vault.MuSig2Context := do
  let (some txid, some vout) := (input.previousTxid, input.outputIndex) | throw (.session .unknownInput)
  let some u := r.utxos.find? (fun u => u.txid == txid && u.vout == vout) | throw (.session .unknownInput)
  liftVault s.network (v.muSig2Context u.chain.rawValue u.index)

/-- `addPasted()`: a bare Base64 PSBT, combined and reviewed (a proposal that does not review is refused). -/
def musigAdd (s : RecordsStore) (w : Option Wallet) (vaultID : String) (working : Option String) (text : String)
    (tip : UInt32) : RM MusigReview := do
  let r ← vaultRecord s vaultID
  let incoming ← parsePSBT s.network text
  let w0 ← working.mapM (parsePSBT s.network)
  let candidate ← combine s.network w0 incoming
  discard <| reviewVaultSpend s r candidate tip
  s.notePSBT "vault-psbt-combined" candidate
  RM.io (musigReviewOf s w r candidate tip)

structure MusigInputs where
  record : VaultRecord
  vault : Vault
  psbt : PSBT
  participants : Nat

def musigInputs (s : RecordsStore) (vaultID working : String) (tip : UInt32) : RM MusigInputs := do
  let p ← parsePSBT s.network working
  let r ← vaultRecord s vaultID
  let v ← vaultOf s r
  let some n := participantCount v | throw (.session (.notReady "This vault does not use MuSig2."))
  unless (← RM.io (reviewVaultSpend s r p tip).run).toOption.isSome do
    throw (.session (.notReady "This PSBT is no longer a valid spend of the vault's available coins. It may be stale or altered; create or import a valid PSBT instead."))
  return { record := r, vault := v, psbt := p, participants := n }

/-- Round 1 (after authentication): this phone's public nonces on every input. The secret nonces stay in
the session. -/
def musigNonces (s : RecordsStore) (sessions : MusigSessions) (w : Wallet) (vaultID working : String) (tip : UInt32) :
    RM MusigReview := do
  let i ← musigInputs s vaultID working tip
  let psbt ← sessions.state.atomically do
    let cur ← sessionFor vaultID
    if cur.nonceSessionStarted then throw (.session (.notReady "This phone is already prepared for this exchange."))
    if minNonces i.psbt ≥ i.participants || minPartialSigs i.psbt > 0 then
      throw (.session (.notReady "Every signer is already prepared."))
    let master ← liftWallet s.network w.masterKey
    let coords := authorizationCoordinates i.record
    let mut p := i.psbt
    let mut nonces : Array (Nat × Array (ByteArray × ByteArray)) := #[]
    for k in [0:p.inputs.size] do
      let ctx ← inputContext s i.vault i.record p.inputs[k]!
      let (p', sec) ← liftVaultIO s.network (i.vault.muSig2AttachNonce p k ctx master i.record.utxos coords tip)
      p := p'
      nonces := nonces.push (k, sec)
    set (some ({ vaultID := vaultID, nonces := nonces, nonceSessionStarted := true, signedThisSession := false } : MusigSession))
    return p
  s.notePSBT "musig2-public-nonces" psbt
  RM.io (musigReviewOf s (some w) i.record psbt tip)

/-- Round 2 (after authentication): partial signatures with the session's nonces, which are then
scrubbed. A failure leaves the live session as it was (retryable). -/
def musigSign (s : RecordsStore) (sessions : MusigSessions) (w : Wallet) (vaultID working : String) (tip : UInt32) :
    RM MusigReview := do
  let i ← musigInputs s vaultID working tip
  let psbt ← sessions.state.atomically do
    let cur ← sessionFor vaultID
    unless cur.nonceSessionStarted && !cur.signedThisSession && !cur.nonces.isEmpty do
      throw (.session (.notReady "Prepare this phone first; a finished exchange cannot sign again."))
    unless minNonces i.psbt ≥ i.participants && minPartialSigs i.psbt < i.participants do
      throw (.session (.notReady "Wait for every signer to be prepared."))
    let master ← liftWallet s.network w.masterKey
    let coords := authorizationCoordinates i.record
    let mut p := i.psbt
    for k in [0:p.inputs.size] do
      let ctx ← inputContext s i.vault i.record p.inputs[k]!
      let staged := ((cur.nonces.find? (·.1 == k)).map (·.2)).getD #[]
      let (p', _) ← liftVault s.network (i.vault.muSig2Sign p k ctx master staged i.record.utxos coords tip)
      p := p'
    set (some { cur.scrubbed with signedThisSession := true })
    return p
  s.notePSBT "musig2-partial-signed" psbt
  RM.io (musigReviewOf s (some w) i.record psbt tip)

/-- Aggregate and finalize once every partial signature is present; the caller broadcasts, then
`commitVaultSpend`. -/
def musigBroadcast (s : RecordsStore) (vaultID working : String) (tip : UInt32) : RM FinishedSpend := do
  let i ← musigInputs s vaultID working tip
  unless minPartialSigs i.psbt ≥ i.participants do throw (.session (.notReady "Wait for every approval."))
  let coords := authorizationCoordinates i.record
  let mut p := i.psbt
  for k in [0:p.inputs.size] do
    let ctx ← inputContext s i.vault i.record p.inputs[k]!
    p ← liftVault s.network (i.vault.muSig2Aggregate p k ctx i.record.utxos coords tip)
  s.notePSBT "musig2-aggregated" p
  let (_, tx) ← liftVault s.network (i.vault.finalizeSpend p i.record.utxos coords tip)
  return finished i.record i.vault tx

/-- Scrubs the session's secret nonces (`clearSensitiveSigningState`). -/
def musigClear (sessions : MusigSessions) : IO Unit :=
  sessions.state.atomically do
    match ← get with
    | some m => set (some m.scrubbed); set (none : Option MusigSession)
    | none => pure ()

def strippedTypes : List UInt8 :=
  [PSBT.InType.musig2PubNonce, PSBT.InType.musig2PartialSig, PSBT.InType.tapKeySignature, PSBT.InType.finalScriptWitness]

/-- `restartExchange()`: strips nonces, partial signatures and final fields; scrubs the session. -/
def musigRestart (s : RecordsStore) (sessions : MusigSessions) (w : Option Wallet) (vaultID working : String)
    (tip : UInt32) : RM MusigReview := do
  let p ← parsePSBT s.network working
  let r ← vaultRecord s vaultID
  let stripped := { p with inputs := p.inputs.map fun inp => { inp with pairs := inp.pairs.filter fun kv => !strippedTypes.contains kv.type } }
  RM.io (musigClear sessions)
  RM.io (musigReviewOf s w r stripped tip)

/-- `refreshSpendReview()`: re-review against trusted local state. -/
def musigRecheck (s : RecordsStore) (w : Option Wallet) (vaultID working : String) (tip : UInt32) : RM MusigReview := do
  let p ← parsePSBT s.network working
  let r ← vaultRecord s vaultID
  RM.io (musigReviewOf s w r p tip)

/-- Whether the session holds round-1 nonces for `vaultID` (for the screen's instruction line and tests). -/
def musigHasNonces (sessions : MusigSessions) (vaultID : String) : IO Bool :=
  sessions.state.atomically do
    match ← get with
    | some m => return m.vaultID == vaultID && !m.nonces.isEmpty
    | none => return false

end WinnowApp.RecordsReal
