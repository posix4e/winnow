import WinnowApp.Home
import WinnowApp.Backup

/-! AccountDetailView.swift (with VaultPolicySection and SignerKeyRow), VaultsView.swift
(VaultCreateView), SharedSavingsViews.swift (create, share, add) and BeginnerHomeView's
SavingsChooserView. -/

namespace WinnowApp
open ElmLean

def VaultCreate.isMuSig2 (v : VaultCreate) : Bool := v.role == .muSig2

def SavingsCreate.chosen (s : SavingsCreate) (m : Model) : List Person :=
  m.records.people.filter (s.selected.contains ·.id)

def SavingsCreate.signerCount (s : SavingsCreate) (m : Model) : Nat := (s.chosen m).length + 1

def SavingsCreate.defaultName (s : SavingsCreate) (m : Model) : String :=
  match s.chosen m with
  | [] => "Shared savings"
  | ps => "Savings with " ++ ", ".intercalate (ps.map (·.name))

def SavingsCreate.effectiveName (s : SavingsCreate) (m : Model) : String :=
  let typed := s.name.trimAscii.copy
  if s.nameEdited && !typed.isEmpty then typed else s.defaultName m

/-- Present `s`, or replace the chooser with it (choosing swaps the chooser's content for the flow). -/
def Model.presentFlow (m : Model) (s : Sheet) : Model :=
  if m.topSheet == some .savingsChooser then { m with sheets := m.sheets.dropLast ++ [s] } else m.present s

def stepVault (msg : VaultMsg) (m : Model) : Model × List Cmd :=
  let g := m.generation
  let v := m.vaultCreate
  let sc := m.savingsCreate
  let changed (v : VaultCreate) : Model := { m with vaultCreate := { v with built := none } }
  match msg with
  | .openCreate role => ({ m with vaultCreate := { role } }.present .vaultCreate, [])
  | .setName s => ({ m with vaultCreate := { v with name := s } }, [])
  | .setRole i =>
    -- the policy cannot change underneath signer expressions
    if !v.cosigners.isEmpty then (m, []) else
    (changed { v with role := if i == 1 then .muSig2 else .scriptPath, threshold := 1, error := none }, [])
  | .setThreshold n => (changed { v with threshold := clampThreshold n v.cosigners.length }, [])
  | .setPasted s => ({ m with vaultCreate := { v with pasted := s } }, [])
  | .addPasted =>
    let t := v.pasted.trimAscii.copy
    if t.isEmpty then (m, []) else (m, [.checkCosigner g v.role v.cosigners t])
  | .addOwn => (m, [.ownKeyExpression g (v.role == .scriptPath)])
  | .removeCosigner i =>
    let cs := v.cosigners.eraseIdx i
    (changed { v with cosigners := cs, threshold := reconcileThreshold v.threshold v.cosigners.length cs.length, error := none }, [])
  | .build =>
    if v.cosigners.length < 2 then (m, []) else
    ({ m with vaultCreate := { v with error := none } }, [.buildVault g v.role v.threshold v.cosigners])
  | .save =>
    match v.built with
    | some b =>
      if v.saving || v.name.trimAscii.isEmpty then (m, []) else
      ({ m with vaultCreate := { v with saving := true } }, [.addVault g v.name.trimAscii.copy b.descriptor])
    | none => (m, [])
  | .newAddress id => (m, [.advanceVaultReceive g id])
  | .send id => m.sendTo none (some id)
  | .openSigning id =>
    match m.vault? id with
    | some vs => if vs.isScriptPath then ({ m with approval := { vaultID := id } }.present .approval, [])
                 else ({ m with musig := { vaultID := id } }.present .musig, [])
    | none => (m, [])
  | .openBackup => stepBackup .openExport m
  | .openShare id => ({ m with savingsCardText := none }.present (.savingsShare id), [.savingsCard g id])
  | .askRemove id => ({ m with confirm := some (.removeSavings id) }, [])
  | .remove id => ({ m with confirm := none }, [.removeVault g id])
  | .openChooser => ({ m with savingsCreate := {}, savingsAdd := {} }.present .savingsChooser, [])
  | .openSavingsCreate => ({ m with savingsCreate := {}, savingsCardText := none }.presentFlow .sharedSavingsCreate, [])
  | .openSavingsAdd => ({ m with savingsAdd := {} }.presentFlow .addSharedSavings, [])
  | .toggleCoOwner pid =>
    match m.person? pid with
    | some p =>
      if !p.canCoOwnSavings then (m, []) else
      let before := sc.signerCount m
      let sel := if sc.selected.contains pid then sc.selected.erase pid else sc.selected ++ [pid]
      let sc' := { sc with selected := sel }
      ({ m with savingsCreate := { sc' with threshold := reconcileThreshold sc.threshold before (sc'.signerCount m) } }, [])
    | none => (m, [])
  | .setSavingsThreshold n => ({ m with savingsCreate := { sc with threshold := clampThreshold n (sc.signerCount m) } }, [])
  | .setSavingsName s => ({ m with savingsCreate := { sc with name := s, nameEdited := true } }, [])
  | .addCoOwner => m.openPerson { forSigning := true } ""
  | .createSavings =>
    let chosen := sc.chosen m
    if sc.creating || chosen.isEmpty || m.walletID.isNone then (m, []) else
    ({ m with savingsCreate := { sc with creating := true, error := none } },
     [.createSharedSavings g (sc.effectiveName m) (chosen.map (·.id)) (clampThreshold sc.threshold (sc.signerCount m))])
  | .setSavingsCard s => ({ m with savingsAdd := { m.savingsAdd with pasted := s } }, [])
  | .pasteSavingsCard => (m, [.paste .savingsCard])
  | .addSavings =>
    let a := m.savingsAdd
    if a.adding || a.pasted.trimAscii.isEmpty then (m, []) else
    ({ m with savingsAdd := { a with adding := true, error := none } }, [.addSharedSavings g a.pasted])

/-! ## View -/

/-- `VaultPolicySection`: read from the spending descriptor, never from a label or imported claim. -/
def policySection (m : Model) (key : String) (threshold signerCount : Nat) (isScriptPath : Bool) : H :=
  .section "Signing policy" ""
    [ body s!"{threshold} of {signerCount} signing keys required"
    , body (if isScriptPath then "Shared control" else "Every signing key")
    , body (if threshold == 1 then "One signing key can spend these funds." else "One signing key cannot spend these funds.")
    , .disclosure "What this policy proves" (m.isExpanded key) (Msg.setExpanded key)
        [ caption (if isScriptPath
            then "The spending script enforces the threshold, with no secret key that bypasses it. A spend reveals the script and threshold on chain; the receiving address alone does not."
            else "MuSig2 requires every participating key and produces one Taproot key-path signature. The signature itself does not reveal how many devices participated. There is no recovery path if a required key and its backups are lost.")
        , caption "Names and cards do not enforce protection. The policy cannot prove who has key copies, where they are kept, or safety from physical coercion." ] ]

/-- `SignerKeyRow`. -/
def signerRow (s : Signer) : H :=
  .row [body (if s.isYou then "you" else s.name.getD "Not one of your people"), .spacer, caption s.fingerprint]

def accountScreen (m : Model) (id : String) (overlays : List H) : H :=
  match m.vault? id with
  | none => .screen "Account" (some (.home .pop)) ([.list [.section "" "" [caption "This account is no longer on this phone."]]] ++ overlays)
  | some v =>
    let vm (msg : VaultMsg) : Option Msg := some (.vault msg)
    .screen v.name (some (.home .pop))
      ([.list
        ((match v.receiveAddress with
          | some a => [.section "Receive" "" [.qr a, copyableBlock m "account.address" a, .button "New address" .plain (vm (.newAddress v.id))]]
          | none => [.section "Receive" "" []]) ++
         [ .section "Balance · confirmed" ""
             ([.labeled "Total" (satsText v.balance)] ++
              (if v.utxos.isEmpty then [caption "No money in yet. Payments to this account appear once they confirm in a block."] else []))
         , policySection m "account.policy" v.threshold v.signerCount v.isScriptPath
         , .section "" (if v.isScriptPath
               then "Send prepares a payment for the co-owners to approve. To approve someone else’s payment, open their request."
               else "Create a payment, then exchange approvals with the other signer.")
             [ .button "Send" .plain (if v.utxos.isEmpty then none else vm (.send v.id))
             , .button (if v.isScriptPath then "Approve a request" else "Continue signing") .plain (vm (.openSigning v.id)) ]
         , .section "" "Save the wallet backup file and your recovery phrase. Each other signer needs its own key backup. A backup cannot replace a missing signer’s key."
             [.button "Back up this wallet" .plain (vm .openBackup)] ] ++
         (if v.isScriptPath then
           [.section "Co-owners" "Every key that can approve a payment, with its fingerprint. Compare each with the card its owner shows you; a key that is not one of your people can approve payments all the same."
             ([body (", ".intercalate ((if v.includesYou then ["you"] else []) ++ v.coOwners))] ++
              v.signers.map signerRow ++
              [.button "Share the savings card" .plain (vm (.openShare v.id))])] else []) ++
         (if m.settings.advancedMode then
           [.section "" ""
             [.disclosure "Technical details" (m.isExpanded "account.technical") (Msg.setExpanded "account.technical")
               ([copyableBlock m "account.descriptor" v.descriptor] ++
                v.utxos.map fun u =>
                  .col [body (satsText u.amount),
                        caption s!"{String.ofList (u.txid.toList.take 16)}…:{u.vout} · {if u.height > 0 then s!"block {u.height}" else "awaiting confirmation"}{maturityNote u m.status.tipHeight}"])]] else []) ++
         (if v.isScriptPath then
           [.section "" "Forgets these savings here. The money stays where it is; other co-owners keep their copies, and the card adds it back."
             [.button "Remove from this phone" .destructive (vm (.askRemove v.id))]] else []))] ++ overlays)

def vaultCreateSheet (m : Model) (inner : List H) : H :=
  let v := m.vaultCreate
  let n := v.cosigners.length
  .sheet s!"New {if v.isMuSig2 then "MuSig2" else "k-of-n"} vault" (if v.saving then none else some .closeSheet)
    ([ closeRow "Cancel"
     , .section "" (if v.isMuSig2
           then "Use separate keys for this phone and another signing device. Every key is needed for every payment; losing a required key can lock the funds. External signers must support Winnow’s MuSig2 exchange; hardware-wallet compatibility is not yet verified."
           else "Share control with a threshold such as 2 of 3. Any two keys can authorize a payment; one can be unavailable. Keep the keys separate if you want one device to be insufficient.")
         ([ .input .plain "" "Vault name" v.name (fun s => .vault (.setName s)) none
          , .picker "Who must approve" ["Choose a threshold", "Every signing key"] (if v.isMuSig2 then 1 else 0) (fun i => .vault (.setRole i)) ] ++
          (if v.isMuSig2 then [] else
            if n ≥ 2 then [ .stepper "Required signatures" v.threshold 1 n (fun k => .vault (.setThreshold k)) s!"{v.threshold} of {n}" ]
            else [.labeled "Required signatures" "Add at least two signers"]) ++
          (if v.cosigners.isEmpty then [] else [caption "Remove all signer keys before changing the policy."]))
     , .section "Cosigners" (if v.isMuSig2
           then "MuSig2 participants are bare key expressions: [fingerprint/path]xpub with no derivation suffix (BIP390)."
           else "Each cosigner is a key expression like [fingerprint/86'/1'/0']xpub…/<0;1>/*. The vault's internal key is the BIP341 NUMS point — no one can key-path spend around the multisig.")
         ((v.cosigners.zipIdx.map fun (c, i) =>
             .row [.col [caption s!"Cosigner {i + 1}", caption c], .spacer, .button "Remove" .destructive (some (.vault (.removeCosigner i)))]) ++
          [ .input .plain "" "Paste a cosigner key expression" v.pasted (fun s => .vault (.setPasted s)) none
          , .button "Add pasted key" .plain (if v.pasted.trimAscii.isEmpty then none else some (.vault .addPasted))
          , .button "Add this device's key" .plain (some (.vault .addOwn)) ]) ] ++
     (match v.error with | some e => [.section "" "" (errorRows (some e))] | none => []) ++
     [.section "" "" [.button "Build descriptor" .plain (if n ≥ 2 then some (.vault .build) else none)]] ++
     (match v.built with
      | some b =>
        [ policySection m "create.policy" b.threshold b.signerCount b.isScriptPath
        , .section "Descriptor" "" [copyableBlock m "create.descriptor" b.descriptor] ] ++
        (match b.firstAddress with | some a => [.section "First address" "" [copyableBlock m "create.address" a]] | none => []) ++
        [.section "" "" [.button (if v.saving then "Saving…" else "Save vault") .primary
                          (if v.name.trimAscii.isEmpty || v.saving then none else some (.vault .save))]]
      | none => []) ++
     inner)

/-- `SharedSavingsShareView`: the card, with the reason it must travel before any money does. -/
def savingsShareContent (m : Model) (id : String) (afterCreate : Bool) : List H :=
  let v := m.vault? id
  let names := joinNames ((v.map (·.coOwners)).getD []) "your co-owners"
  let text := match m.savingsCardText with
    | some (i, t) => if i == id then some t else none
    | none => none
  [ .section "" "" [caption s!"Share with {names} now. Each of them must add these savings on their phone before any money goes in — their phone only notices coins from the moment it starts watching, and it cannot approve a payment of coins it has not seen."]
  , .section ((v.map (·.name)).getD "") (if afterCreate then "Nothing here is secret; it describes who can approve, not how to spend."
                                         else "Anyone with this card can watch the savings' addresses. It cannot spend.")
      (match text with
       | some t => [.qr t, copyableBlock m "savings.card" t]
       | none => [.progress ""]) ]

def savingsShareSheet (m : Model) (id : String) (inner : List H) : H :=
  .sheet "Savings card" (some .closeSheet) ([closeRow "Done"] ++ savingsShareContent m id false ++ errorRows m.savingsCreate.error ++ inner)

def savingsCreateSheet (m : Model) (inner : List H) : H :=
  let sc := m.savingsCreate
  match sc.created with
  | some id =>
    .sheet "Share the savings" (some .closeSheet) ([closeRow "Done"] ++ savingsShareContent m id true ++ inner)
  | none =>
    let n := sc.signerCount m
    .sheet "New shared savings" (if sc.creating then none else some .closeSheet)
      ([ closeRow "Cancel"
       , .section "Co-owners, with you" "You are always a co-owner. Pick at least one person. Each key’s fingerprint should match the one on that person’s own card."
           ((if m.records.people.isEmpty then [caption "Add each co-owner’s Winnow card, then choose who will share control."] else []) ++
            [.button "Add a co-owner" .plain (some (.vault .addCoOwner))] ++
            (m.records.people.map fun p =>
              .row ([ .col [ .button p.name .plain (if p.canCoOwnSavings then some (.vault (.toggleCoOwner p.id)) else none)
                           , caption (match p.signerFingerprint with | some f => s!"key {f}" | none => "needs a signer key") ]
                    , .spacer ] ++ (if sc.selected.contains p.id then [.icon "checkmark"] else []))))
       , .section "" s!"Any {sc.threshold} of these {n} keys can approve a payment. {if sc.threshold == 1 then "One key is enough to spend." else "One key alone is not enough to spend."} Names do not prove that the keys are held by different people."
           [ .stepper "How many must approve" sc.threshold 1 (max n 1) (fun k => .vault (.setSavingsThreshold k)) s!"{sc.threshold} of {n}"
           , .input .plain "" (sc.defaultName m) sc.name (fun s => .vault (.setSavingsName s)) none ] ] ++
       (match sc.error with | some e => [.section "" "" (errorRows (some e))] | none => []) ++
       [.section "" "" [.button (if sc.creating then "Creating…" else "Create") .primary
                         (if sc.creating || (sc.chosen m).isEmpty || m.walletID.isNone then none else some (.vault .createSavings))]] ++
       inner)

def addSavingsSheet (m : Model) (inner : List H) : H :=
  let a := m.savingsAdd
  .sheet "Add shared savings" (if a.adding then none else some .closeSheet)
    ([ closeRow "Cancel"
     , .section "" "Winnow starts watching these savings from now. Money sent to them earlier is not seen from this phone."
         [ .input .multiline "" "Paste the savings card" a.pasted (fun s => .vault (.setSavingsCard s)) none
         , .button "Paste from clipboard" .plain (some (.vault .pasteSavingsCard)) ] ] ++
     (match a.error with | some e => [.section "" "" (errorRows (some e))] | none => []) ++
     [.section "" "" [.button (if a.adding then "Adding…" else "Add") .primary
                       (if a.adding || a.pasted.trimAscii.isEmpty then none else some (.vault .addSavings))]] ++
     inner)

def savingsChooserSheet (inner : List H) : H :=
  .sheet "Save with someone" (some .closeSheet)
    ([ closeRow "Cancel"
     , .section "" "Shared savings need more than one of you to approve a payment. Whoever starts them shares a card; everyone else joins from it."
         [ .button "Start savings with people you’ve added" .plain (some (.vault .openSavingsCreate))
         , .button "Join savings someone shared with you" .plain (some (.vault .openSavingsAdd)) ] ] ++ inner)

end WinnowApp
