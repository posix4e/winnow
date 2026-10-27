import WinnowApp.Common

/-! VaultSpendSession.swift (ApprovalView: paste a request, review what it pays, approve, share, finish
when enough co-owners have signed) and MuSig2SignView.swift (prepare → exchange → approve → send). The
MuSig2 round-1 secret nonces never enter the Model: the backend keeps them in its signing session, the
Model only knows that it does (`holdsNonces`), and every exit path scrubs them (`Cmd.musigClear`). -/

namespace WinnowApp
open ElmLean

def busyMessage : String := "Another payment is already being signed and broadcast. Wait for it to finish."

def stepApproval (msg : ApprovalMsg) (m : Model) : Model × List Cmd :=
  let g := m.generation
  let a := m.approval
  match msg with
  | .setPasted s => ({ m with approval := { a with pasted := s } }, [])
  | .paste => (m, [.paste .approval])
  | .review =>
    if a.busy || a.pasted.trimAscii.isEmpty then (m, []) else
    ({ m with approval := { a with error := none } }, [.approvalAdd g a.vaultID (a.review.map (·.working)) a.pasted])
  | .approve =>
    match a.review with
    | some r =>
      if a.busy || r.lines.isNone || r.approvedByYou then (m, []) else
      ({ m with approval := { a with busy := true, error := none } }, [.approvalApprove g a.vaultID r.working])
    | none => ({ m with approval := { a with error := some "Paste a request first." } }, [])
  | .finish =>
    match a.review with
    | some r =>
      if a.busy || !r.canFinish || a.broadcastTxid.isSome then (m, []) else
      if m.spendingInFlight then ({ m with approval := { a with error := some busyMessage } }, []) else
      ({ m with approval := { a with busy := true, error := none }, spendingInFlight := true }, [.approvalFinish g a.vaultID r.working])
    | none => (m, [])

def MusigState.participants (s : MusigState) : Option Nat := s.review.bind (·.participantCount)
def MusigState.reviewable (s : MusigState) : Bool := (s.review.bind (·.lines)).isSome
def MusigState.minNonces (s : MusigState) : Nat := (s.review.map (·.minNonces)).getD 0
def MusigState.minPartialSigs (s : MusigState) : Nat := (s.review.map (·.minPartialSigs)).getD 0

def MusigState.canPrepare (s : MusigState) : Bool :=
  match s.participants with
  | some n => !s.nonceSessionStarted && s.minNonces < n && s.minPartialSigs == 0 && s.reviewable &&
              !s.authorizing && s.broadcastTxid.isNone
  | none => false

def MusigState.canSign (s : MusigState) : Bool :=
  match s.participants with
  | some n => s.nonceSessionStarted && !s.signedThisSession && s.holdsNonces && s.minNonces ≥ n &&
              s.minPartialSigs < n && s.reviewable && !s.authorizing
  | none => false

def MusigState.canBroadcast (s : MusigState) : Bool :=
  match s.participants with
  | some n => s.minPartialSigs ≥ n && s.reviewable && !s.authorizing && !s.broadcasting && s.broadcastTxid.isNone
  | none => false

/-- `clearSensitiveSigningState` minus the proposal itself: the round flags reset with a new epoch. -/
def Model.musigForgetRound (m : Model) : Model :=
  { m with epoch := m.epoch + 1,
           musig := { m.musig with nonceSessionStarted := false, signedThisSession := false, holdsNonces := false,
                                   authorizing := false, broadcasting := false, error := none } }

def stepMusig (msg : MusigMsg) (m : Model) : Model × List Cmd :=
  let g := m.generation
  let s := m.musig
  let working := (s.review.map (·.working)).getD ""
  match msg with
  | .setPasted t => ({ m with musig := { s with pasted := t } }, [])
  | .paste => (m, [.paste .musig])
  | .addReply =>
    if s.authorizing || s.pasted.trimAscii.isEmpty then (m, []) else
    ({ m with musig := { s with error := none } }, [.musigAdd g s.vaultID (s.review.map (·.working)) s.pasted.trimAscii.copy])
  | .prepare =>
    if !s.canPrepare then (m, []) else
    let e := m.epoch + 1
    ({ m with epoch := e, musig := { s with authorizing := true, error := none } }, [.musigNonces g e s.vaultID working])
  | .sign =>
    if !s.canSign then (m, []) else
    let e := m.epoch + 1
    ({ m with epoch := e, musig := { s with authorizing := true, error := none } }, [.musigSign g e s.vaultID working])
  | .broadcast =>
    if !s.canBroadcast then (m, []) else
    if m.spendingInFlight then ({ m with musig := { s with error := some busyMessage } }, []) else
    let e := m.epoch + 1
    ({ m with epoch := e, musig := { s with broadcasting := true, error := none }, spendingInFlight := true },
     [.musigBroadcast g e s.vaultID working])
  | .restart =>
    if s.minNonces == 0 || s.broadcastTxid.isSome || s.authorizing || s.broadcasting then (m, []) else
    (m.musigForgetRound, [.musigClear, .musigRestart g s.vaultID working])

/-- MuSig2SignView's `signingInstruction`. -/
def MusigState.instruction (s : MusigState) (required : Nat) : String :=
  if s.minPartialSigs ≥ required then "Every approval is here. You can send the payment."
  else if s.signedThisSession then "Copy the request below to the other signer, then add its signed reply here."
  else if s.minNonces ≥ required && s.nonceSessionStarted then "The signers are ready. Check the payment, then approve it on this phone."
  else if s.nonceSessionStarted then "Copy the request below to the other signer, then paste its reply above."
  else "Check the payment, then prepare this phone for the signing exchange."

/-! ## Views -/

def approvalSheet (m : Model) (inner : List H) : H :=
  let a := m.approval
  let content : List H :=
    match a.broadcastTxid with
    | some t =>
      [.section "" "" [.row [.icon "checkmark.seal", body "Sent"], caption t, caption "The savings balance updates once a block includes it."]]
    | none =>
      [.section "" "A request is what a co-owner shares when they want money to leave the savings. Paste it here; Winnow shows exactly what it pays before you approve."
        [ .input .multiline "" "Paste the request" a.pasted (fun s => .approval (.setPasted s)) none
        , .button "Paste from clipboard" .plain (some (.approval .paste))
        , .button "Review request" .plain (if a.busy || a.pasted.trimAscii.isEmpty then none else some (.approval .review)) ]] ++
      (match a.review with
       | some r =>
         [ .section "What it pays" "Anyone can propose a payment. Winnow checks the coins are these savings' own and that your approval covers exactly what is shown here."
             (match r.lines with
              | some lines =>
                (lines.map fun l => .col [.row [body l.label.title, .spacer, body (satsText l.amount)], caption l.address]) ++
                (match r.fee with | some f => [.labeled "Fee" (satsText f)] | none => []) ++
                [caption r.progressText]
              | none =>
                [ .row [.icon "exclamationmark.triangle.fill", body "Winnow cannot safely review this request"]
                , caption ((r.reviewError <|> a.error).getD "The savings or the request are unavailable.") ])
         , .section "" (if r.canFinish then "Enough co-owners have approved. Finishing broadcasts the payment."
                        else "When enough co-owners have approved, whoever holds the last approval taps Finish.")
             [ .button (if a.busy then "Working…" else "Approve") .primary
                 (if a.busy || r.lines.isNone || r.approvedByYou then none else some (.approval .approve))
             , .button "Finish — send it" .plain (if !r.canFinish || a.busy then none else some (.approval .finish)) ] ]
       | none => []) ++
      (match a.error, a.review with
       | some e, none => [.section "" "" (errorRows (some e))]
       | some e, some r => if r.lines.isSome then [.section "" "" (errorRows (some e))] else []
       | none, _ => []) ++
      (match a.review with
       | some r =>
         [.section (if r.approvedByYou then "Share your approval" else "Share payment request") "Send this back to a co-owner, or to whoever will finish the payment."
           ([copyableBlock m "approval.output" r.output] ++
            (match r.rawPSBT with
             | some raw => if m.settings.advancedMode then
                 [.disclosure "Raw PSBT" (m.isExpanded "approval.raw") (Msg.setExpanded "approval.raw") [copyableBlock m "approval.raw" raw]]
               else []
             | none => []))]
       | none => [])
  .sheet (if a.broadcastTxid.isNone then "Approve a request" else "Payment") (if a.busy then none else some .closeSheet)
    ([closeRow "Done"] ++ content ++ inner)

def musigSheet (m : Model) (inner : List H) : H :=
  let s := m.musig
  let content : List H :=
    match s.broadcastTxid with
    | some t => [.section "" "You can close this screen." [body "Payment sent", caption t]]
    | none =>
      [.section "" "Paste the payment or the other signer’s reply here."
        [ .input .plain "" "Paste a PSBT (Base64)" s.pasted (fun t => .musig (.setPasted t)) none
        , .button "Paste from clipboard" .plain (some (.musig .paste))
        , .button "Add reply" .plain (if s.authorizing || s.pasted.trimAscii.isEmpty then none else some (.musig .addReply)) ]] ++
      (match s.review with
       | some r =>
         [.section "Check this payment" (if r.lines.isNone then "Fix the problem above before approving this payment."
                                         else "Check the address, amount, and fee on both devices before approving.")
           (match r.lines with
            | some lines =>
              (lines.map fun l => .col [.row [caption (if l.isVaultOwned then "Back to this account" else "Pays"), .spacer, body s!"{l.amount} sat"],
                                         caption l.address]) ++
              (match r.fee with | some f => [.labeled "Fee" s!"{f} sat"] | none => []) ++
              [.disclosure "Transaction details" (m.isExpanded "musig.details") (Msg.setExpanded "musig.details")
                [ .labeled "Sighash" (sighashLabel r.sighashTypes), .labeled "Version" s!"{r.version}"
                , .labeled "Locktime" (locktimeLabel r.locktime), .labeled "Sequence" (sequenceLabel r.sequences) ]]
            | none =>
              [ .row [.icon "exclamationmark.triangle.fill", body "Winnow cannot safely review this proposal"]
              , caption (r.reviewError.getD "The vault or proposal is unavailable.") ])] ++
         (match r.participantCount with
          | some n =>
            [ .section "Next step" ""
                ([body (s.instruction n)] ++
                 (if s.holdsNonces then [caption "Keep this screen open while you use the other signer. If you leave or lock the phone, start a fresh exchange on both devices."] else []))
            , .section "Actions" ""
                ([ .button "Prepare this phone" .plain (if s.canPrepare then some (.musig .prepare) else none)
                 , .button "Approve on this phone" .plain (if s.canSign then some (.musig .sign) else none)
                 , .button (if s.broadcasting then "Sending…" else "Send payment") .primary (if s.canBroadcast then some (.musig .broadcast) else none) ] ++
                 (if s.reviewable then [] else
                   [caption "This PSBT is no longer a valid spend of the vault's available coins. It may be stale or altered; create or import a valid PSBT instead."]) ++
                 (if s.minNonces > 0 && s.broadcastTxid.isNone then
                   [.button "Start again" .plain (if s.authorizing || s.broadcasting then none else some (.musig .restart))] else [])) ]
          | none => [])
       | none => []) ++
      (match s.error with | some e => [.section "" "" (errorRows (some e))] | none => []) ++
      (match s.review with
       | some r => if r.output.isEmpty then [] else [.section "PSBT to share" "" [copyableBlock m "musig.output" r.output]]
       | none => [])
  .sheet (if s.broadcastTxid.isNone then "Approve payment" else "Payment") (if s.authorizing || s.broadcasting then none else some .closeSheet)
    ([closeRow "Done"] ++ content ++ inner)

end WinnowApp
