import WinnowApp.Common

/-! SendView.swift: the form (address or saved person, amount, Advanced fee controls), the review with
Winnow's four warnings, and the status with the relay log. -/

namespace WinnowApp
open ElmLean

/-- `SendView.reviewInputs`: what a preview must have been made for. Priority and override count only
in Advanced mode; a person's payment index is part of it, so a review for an earlier address is void. -/
def Model.sendInputs (m : Model) : SendInputs :=
  let i := m.send.inputs
  let person := i.personID.bind m.person? |>.filter (·.isSavedRecipient)
  { i with destination := if person.isSome then "" else i.destination
           priority := if m.settings.advancedMode then i.priority else 1
           override := if m.settings.advancedMode then i.override else ""
           network := m.settings.network
           personID := person.map (·.id)
           paymentIndex := person.map (·.nextPaymentIndex)
           walletID := m.walletID }

/-- An edit of the form voids the preview, unless a payment is being sent or was sent. -/
def Model.editSend (m : Model) (f : SendInputs → SendInputs) (rerate := false) : Model × List Cmd :=
  if m.send.sending || m.send.sentTxid.isSome then (m, [])
  else
    let m' := { m with send := { m.send with inputs := f m.send.inputs, preview := none, error := none } }
    (m', if rerate then [.resolveRate m.generation m'.sendInputs m.status.feeFloorMilli] else [])

def stepSend (msg : SendMsg) (m : Model) : Model × List Cmd :=
  let g := m.generation
  match msg with
  | .setDestination t => m.editSend fun i => { i with destination := t }
  | .setAmount t => m.editSend fun i => { i with amount := t }
  | .setPriority p => m.editSend (fun i => { i with priority := p }) true
  | .setOverride t => m.editSend (fun i => { i with override := t }) true
  | .pasteDestination => (m, [.paste .destination])
  | .openRecipients => (m.present .savedRecipients, [])
  | .choosePerson id => m.editSend fun i => { i with personID := some id, destination := "" }
  | .clearPerson => m.editSend fun i => { i with personID := none }
  | .review =>
    let inputs := m.sendInputs
    if m.send.reviewing || m.send.sending || !canReview inputs then (m, []) else
    match inputs.amount.trimAscii.copy.toNat? with
    | some a =>
      if a == 0 then ({ m with send := { m.send with error := some "Enter an amount in sats." } }, []) else
      ({ m with send := { m.send with reviewing := true, error := none, preview := none } }, [.previewSend g inputs])
    | none => ({ m with send := { m.send with error := some "Enter an amount in sats." } }, [])
  | .sendPayment =>
    match m.send.preview with
    | none => (m, [])
    | some p =>
      if m.send.sending then (m, []) else
      if m.spendingInFlight then
        (m.fail "send" "Another payment is already being signed and broadcast. Wait for it to finish.", [])
      else ({ m with send := { m.send with sending := true, error := none }, spendingInFlight := true },
            [.sendPayment g m.sendInputs p])
  | .editPayment => if m.send.sending then (m, []) else ({ m with send := { m.send with preview := none, error := none } }, [])
  | .newPayment =>
    ({ m with send := { inputs := { network := m.settings.network } } }, [.resolveRate g { network := m.settings.network } m.status.feeFloorMilli])

/-- A relay event about the sent transaction (SendView's `apply`). -/
def Model.onRelay (m : Model) (txid : String) (e : RelayEvent) : Model :=
  if m.send.sentTxid != some txid then m else
  let s := m.send
  let s := match e with
    | .announced n => { s with relayLog := s.relayLog ++ [s!"Announced to {n} peer(s)"] }
    | .requested peer =>
      if s.relayedPeers.contains peer then s
      else { s with relayedPeers := s.relayedPeers ++ [peer], relayLog := s.relayLog ++ [s!"Relayed to {peer}"] }
    | .echoed peer => if s.relayedPeers.contains peer then s else { s with relayedPeers := s.relayedPeers ++ [peer] }
    | .feeFloorExceeded => { s with feeFloorNotice := true }
    | .confirmed =>
      match m.historyItem? txid with
      | some h => if h.height > 0 then { s with confirmedHeight := some h.height } else s
      | none => s
  { m with send := s }

/-! ## View -/

def sendForm (m : Model) : List H :=
  let i := m.send.inputs
  let inputs := m.sendInputs
  let person := inputs.personID.bind m.person?
  let send (f : String → SendMsg) : String → Msg := fun s => .send (f s)
  let toSection : H :=
    .section "To" ""
      (match person with
       | some p => [.row [body p.name, .spacer, .button "Change" .plain (some (.send .clearPerson))]]
       | none =>
         [ .row [.input .plain "" "Bitcoin address" i.destination (send .setDestination) none,
                 .button "Paste" .plain (some (.send .pasteDestination))]
         , .button "Saved recipients" .plain (some (.send .openRecipients)) ])
  [toSection,
    .section "Amount" "You'll see the network fee before you send."
      [ .row [.input .number "" "0" i.amount (send .setAmount) none, caption "sats"] ] ] ++
  (if m.settings.advancedMode then
    [ .section "Fee" "The rate uses your override, recent confirmed fees, or a preset, never below the peers' relay floor. It is not a live fee-market estimate."
        [ .picker "Priority" ["Low", "Medium", "High"] i.priority (fun n => .send (.setPriority n))
        , .labeled "Resolved rate" ((m.send.resolvedRateMilli.map feeRateText).getD "—")
        , .labeled "Network floor" ((m.status.feeFloorMilli.map feeRateText).getD "unknown")
        -- a decimal rate: the number pad has no decimal point
        , .input .decimal "" "Override (sat/vB, optional)" i.override (send .setOverride) none ] ]
   else []) ++
  [ .section "" ""
      [ .button (if m.send.reviewing then "Preparing review…" else "Review payment") .primary
          (if m.send.reviewing || !canReview inputs then none else some (.send .review)) ] ]

def paymentAmounts (p : Preview) : H :=
  .section "" "" [ .labeled "Amount" (satsText p.amount), .labeled "Network fee" (satsText p.fee),
                   .labeled "Total" (satsText (p.amount + p.fee)) ]

def warning (iconName text : String) : H := .section "" "" [.row [.icon iconName, caption text]]

def sendReview (m : Model) (p : Preview) : List H :=
  let warnings : List H :=
    (match p.recipient with
     | some r =>
       (if r.hasUnverifiedFundingDestination then
         [warning "exclamationmark.triangle" s!"This destination was inferred from transaction funding. Winnow has not verified that it belongs to {r.name}. Confirm it with them before sending."] else []) ++
       (if !r.derivesFreshAddresses then
         [warning "eye" s!"This address has been saved for reuse. Repeated payments can be linked. Ask {r.name} for a fresh address or Winnow contact card."] else [])
     | none => []) ++
    (match feeProportionWarning p.amount p.fee with | some w => [warning "exclamationmark.triangle" w] | none => []) ++
    (if p.locktimeLagsTip then
      [warning "clock.arrow.circlepath" "Your wallet is still syncing. Sending now can reveal that on the Bitcoin network. Wait for sync to finish for better privacy."]
     else [])
  let action := if m.send.sending then "Working…" else "Send payment"
  [ .section "To" "" ((match p.recipient with | some r => [body r.name] | none => []) ++ [caption p.destination])
  , paymentAmounts p ] ++ warnings ++
  [ .section "" ""
      [ .button action .primary (if m.send.sending then none else some (.send .sendPayment))
      , .button "Edit payment" .plain (if m.send.sending then none else some (.send .editPayment)) ] ] ++
  (if m.settings.advancedMode then
    [ .section "Transaction details" ""
        ([ .labeled "Rate" (feeRateText p.feeRateMilli), .labeled "Inputs" s!"{p.inputCount}" ] ++
         (match p.change with | some c => [.labeled "Change back" (satsText c)] | none => [])) ]
   else [])

def sendStatus (m : Model) (txid : String) : List H :=
  let s := m.send
  [ .section ""  ""
      ((if s.confirmedHeight.isSome then [.row [.icon "checkmark.circle.fill", body "Payment confirmed"]]
        else [.row [.icon "clock", body "Waiting for confirmation"],
              caption (if m.settings.advancedMode then "You can leave this screen. Follow this payment in Wallet."
                       else "You can close this screen. The payment stays in Activity until it confirms.")]) ++
       (if s.feeFloorNotice then
         [.row [.icon "exclamationmark.triangle", caption "The network now requires a higher fee. This payment may be delayed. Advanced mode lets you raise its fee in Wallet."]]
        else [])) ] ++
  (match s.preview with | some p => [paymentAmounts p] | none => []) ++
  [ .section "" "" [ .button "New payment" .primary (some (.send .newPayment)) ]
  , .section "" ""
      [ .disclosure "Transaction details" (m.isExpanded "send.details") (Msg.setExpanded "send.details")
          ([ copyableIdentifier m "send.txid" txid ] ++
           (match s.rawTransaction, s.confirmedHeight with
            | some raw, none => [copyableIdentifier m "send.raw" raw (abbreviated := true) (label := "Copy raw transaction")]
            | _, _ => []) ++
           [ explorerButton "View transaction" (m.settings.transactionURL txid) "transaction ID" ] ++
           (if s.relayedPeers.isEmpty then [] else [body s!"Relayed to {s.relayedPeers.length} peer(s)"]) ++
           s.relayLog.map caption ++
           (match s.confirmedHeight with | some h => [.labeled "Block" s!"{h}"] | none => [])) ] ]

def sendContent (m : Model) : List H :=
  (match m.send.sentTxid, m.send.preview with
   | some t, _ => sendStatus m t
   | none, some p => sendReview m p
   | none, none => sendForm m) ++
  (match m.send.error with | some e => [.section "" "" (errorRows (some e))] | none => [])

def sendTitle (m : Model) : String :=
  if m.send.sentTxid.isSome then "Payment" else if m.send.preview.isSome then "Review payment" else "Send"

/-- Beginner mode's Send sheet. -/
def sendSheet (m : Model) (inner : List H) : H :=
  .sheet (sendTitle m) (if m.send.sending then none else some .closeSheet)
    ([closeRow (if m.send.sentTxid.isNone then "Cancel" else "Done")] ++ sendContent m ++ inner)

end WinnowApp
