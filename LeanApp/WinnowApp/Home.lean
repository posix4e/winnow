import WinnowApp.Common

/-! HomeView.swift and BeginnerHomeView.swift: the balance, sync and activity; HistoryRow,
PaymentDetailView (recipients, receive labels, sender, details, transaction) and FeeBumpView. -/

namespace WinnowApp
open ElmLean

/-! ## Update -/

def Model.currentPayment? (m : Model) : Option String :=
  match m.routes.getLast? with
  | some (.payment t) => some t
  | _ => none

/-- PaymentDetailView's `load()`: only a send whose transaction is not stored, once at a time, and not
while syncing (the `.task(id: syncing)` reruns it when a sync ends). -/
def Model.loadPayment (m : Model) : Model × List Cmd :=
  match m.currentPayment? with
  | none => (m, [])
  | some txid =>
    match m.historyItem? txid with
    | some h =>
      if h.spent > 0 && h.outputs.isNone && !m.payment.loading && !m.status.syncing then
        ({ m with payment := { loading := true, error := none } }, [.loadPaymentDetails m.generation txid])
      else (m, [])
    | none => (m, [])

/-- Open AddPersonView in `mode`, with the paste field pre-filled. -/
def Model.openPerson (m : Model) (mode : PersonMode) (address : String) : Model × List Cmd :=
  let name := (mode.personID.bind m.person?).map (·.name) |>.getD ""
  let m' := { m with person := { mode, name, pasted := address } }.present .addPerson
  (m', if address.trimAscii.isEmpty then [] else [.parsePaste m.generation address])

/-- A fresh Send form addressed to a saved person (SendView's `consumeRequestedPerson`). -/
def Model.sendTo (m : Model) (personID : Option String) : Model × List Cmd :=
  let p := personID.bind m.person?
  let inputs : SendInputs := { network := m.settings.network, walletID := m.walletID,
                               personID := p.map (·.id), paymentIndex := p.map (·.nextPaymentIndex) }
  let m := { m with send := { inputs } }
  if m.settings.advancedMode then ({ m with tab := 1, routes := [] }, [.resolveRate m.generation inputs m.status.feeFloorMilli])
  else
    let m := if m.hasSheet .send then m else m.present .send
    (m, [.resolveRate m.generation inputs m.status.feeFloorMilli])

def stepHome (msg : HomeMsg) (m : Model) : Model × List Cmd :=
  let g := m.generation
  match msg with
  | .openPayment txid => { m with routes := m.routes ++ [Route.payment txid], payment := {}, expanded := [] }.loadPayment
  | .openBackup => ({ m with routes := m.routes ++ [Route.backup] }, [])
  | .pop => ({ m with routes := m.routes.dropLast, payment := {}, expanded := [] }, [])
  | .loadPayment => m.loadPayment
  | .editRecipient address pid => m.openPerson { personID := pid } address
  | .removeRecipient pid => (m, [.updateRecipient g pid none false "payment"])
  | .editPaymentLabel address =>
    let draft := (lookup m.records.receiveLabels address).getD ""
    ({ m with labelEditor := { address, draft } }.present .labelEditor, [])
  | .labelSender => match m.currentPayment? with
    | some t => m.openPerson { txid := some t } ""
    | none => (m, [])
  | .attachSenderDestination pid => match m.currentPayment? with
    | some t => m.openPerson { personID := some pid, txid := some t } ""
    | none => (m, [])
  | .removeSenderLabel => match m.currentPayment? with
    | some t => (m, [.removeSenderLabel g t])
    | none => (m, [])
  | .sendToPerson pid => m.sendTo (some pid)
  | .openFeeBump => match m.currentPayment? with
    | some t => ({ m with feeBump := { txid := t } }.present .feeBump, [.pendingFeeRate g t])
    | none => (m, [])
  | .setBumpRate s =>
    if m.feeBump.replacement.isSome then (m, []) else
    ({ m with feeBump := { m.feeBump with targetText := s, reviewed := none, error := none } }, [])
  | .reviewBump =>
    match parseRateMilli m.feeBump.targetText (trimNewlines := true) with
    | some milli =>
      ({ m with feeBump := { m.feeBump with reviewed := none, error := none } },
       [.previewFeeBump g m.feeBump.txid m.feeBump.targetText milli])
    | none => (m, [])
  | .bump =>
    match m.feeBump.reviewed with
    | some (_, p) =>
      if m.feeBump.bumping then (m, [])
      else if m.spendingInFlight then
        (m.fail "feeBump" "Another payment is already being signed and broadcast. Wait for it to finish.", [])
      else ({ m with feeBump := { m.feeBump with bumping := true, error := none }, spendingInFlight := true },
            [.bumpFee g m.feeBump.txid p])
    | none => (m, [])

/-! ## View -/

/-- `HistoryRow`: who, the labels, the net amount, and Confirmed/Pending/Replaced (beginner) or the
block, fee and replacement (Advanced). The title opens the payment. -/
def historyRow (m : Model) (h : HistoryItem) (tappable := true) : H :=
  let labels := historyLabels m.records h
  let title := historyTitle m.records h
  let status : List H :=
    if m.settings.advancedMode then
      [ caption (match h.replacedBy with
          | some r => s!"replaced by {String.ofList (r.toList.take 8)}…"
          | none => if h.height > 0 then s!"block {h.height}" else "awaiting confirmation") ] ++
      (match h.fee with | some f => [caption s!"fee {groupDigits f.natAbs} sats"] | none => [])
    else
      [caption (if h.replacedBy.isSome then "Replaced" else if h.height > 0 then "Confirmed" else "Pending")]
  .row [ .col ([if tappable then .button title .plain (some (.home (.openPayment h.txid))) else body title] ++
               (if labels.isEmpty then [] else [caption labels]))
       , .spacer
       , .col ([body (signedSatsText h.net)] ++ status) ]

def syncLine (m : Model) : H :=
  match m.phase.summary m.status.syncing with
  | .synced => .row [.icon "checkmark.circle", caption "Up to date"]
  | .peersUnavailable => body "Couldn't reach the Bitcoin network — check your connection."
  | .syncing => .progress "Syncing…"

def balanceSection (m : Model) : H :=
  .section "" "" ([ caption "Balance", .text (satsText m.status.balance) .title,
                    .row ([syncLine m] ++ (if m.settings.network == .mainnet then [] else [caption "Signet · test coins"])) ] ++
                  (if m.phase.summary m.status.syncing == .peersUnavailable then [.button "Retry" .plain (some .retryPeers)] else []) ++
                  errorRows m.status.lastSyncError)

def activitySection (m : Model) : H :=
  .section "Activity" ""
    (if m.status.history.isEmpty then [caption "Nothing yet. Payments appear here once they are confirmed."]
     else m.status.history.map (historyRow m))

def beginnerSections (m : Model) : List H :=
  [ balanceSection m
  , .section "" "" [.row [.button "Receive" .plain (some .openReceive), .button "Send" .primary (some .openSend)]]
  , activitySection m
  , .section "" "" [.button "Back up wallet" .plain (some (.home .openBackup)), caption "Backup file and recovery words"] ]

/-- Advanced mode's Sync section. -/
def syncSection (m : Model) : H :=
  let statusText := syncStatusText m.phase
  .section "Sync" ""
    ((match statusText with
      | some t => if m.phase == .peerDiscoveryFailed then [body t, .button "Retry" .plain (some .retryPeers)]
                  else [.progress t]
      | none => []) ++
     (match filterScanText m.phase m.status.nextScanHeight m.status.tipHeight with
      | some t => [.labeled "Filter scan" t] | none => []) ++
     [.labeled "Peers" s!"{m.status.peerCount}"] ++
     (if m.status.syncing && statusText.isNone then [.progress "Scanning filters…"] else []) ++
     errorRows m.status.lastSyncError ++
     (match m.status.relayStoreQuarantined with | some q => [body q] | none => []) ++
     [.button "Sync now" .plain (if m.status.syncing then none else some .syncNow)])

def walletSections (m : Model) : List H :=
  [ .section "" "" [caption "Balance · confirmed", .text (satsText m.status.balance) .title, caption s!"{m.status.utxoCount} UTXO(s)"]
  , syncSection m
  , .section "Transactions" ""
      (if m.status.history.isEmpty then [caption "No transactions yet. Payments appear here once they confirm in a block."]
       else m.status.history.map (historyRow m)) ]

/-! ### PaymentDetailView -/

def senderSection (m : Model) (h : HistoryItem) : H :=
  let locked := m.records.peopleStorageNotice.isSome
  let act (msg : HomeMsg) : Option Msg := if locked then none else some (.home msg)
  .section "Sender" ""
    (match receivedSender m.records h with
     | some p =>
       [.text p.name .title] ++
       (if p.payTo.isSome then [.button s!"Send to {p.name}" .plain (some (.home (.sendToPerson p.id)))]
        else [body "This label has no payment destination.",
              .button s!"Add destination for {p.name}" .plain (act (.attachSenderDestination p.id))]) ++
       [ .button "Change sender" .plain (act .labelSender)
       , .button "Remove sender label" .destructive (some (.home .removeSenderLabel)) ]
     | none => [.button "Save sender as person" .plain (act .labelSender)])

def paymentSections (m : Model) (txid : String) : List H :=
  match m.historyItem? txid with
  | none => [.section "" "" [body "This payment is no longer in the wallet’s history."]]
  | some h =>
    let locked := m.records.peopleStorageNotice.isSome
    let recipients := (paymentRecipients m.records h).map fun r =>
      let saved := (r.person.map (·.isSavedRecipient)).getD false
      .section "" ""
        ((match r.person with | some p => [.text p.name .title] | none => []) ++
         technical m s!"pay.addr.{r.id}" "Address" [copyableBlock m s!"pay.addr.{r.id}" r.address] ++
         [ body (satsText r.amount)
         , .button (if saved then "Rename recipient" else "Save recipient") .plain
             (if locked then none else some (.home (.editRecipient r.address (r.person.map (·.id))))) ] ++
         (match r.person with
          | some p => if saved then [.button "Remove from saved recipients" .destructive (some (.home (.removeRecipient p.id)))] else []
          | none => []))
    let labeled := labeledReceiveOutputs m.records h
    let labelSection : List H :=
      if labeled.isEmpty then [] else
      [.section "Receive address labels" "These are your local notes about the addresses paid. They do not verify who sent the payment."
        (labeled.flatMap fun o =>
          [.text o.label .title] ++ technical m s!"pay.label.{o.id}" "Address" [copyableBlock m s!"pay.label.{o.id}" o.address] ++
          [body (satsText o.amount), .button "Edit address label" .plain (some (.home (.editPaymentLabel o.address)))])]
    let notice : List H := match m.records.receiveLabelStorageNotice with
      | some n => [.section "" "" [body n]] | none => []
    let load : List H :=
      if h.outputs.isNone && h.spent > 0 then
        [.section "" "" [if m.payment.loading || m.status.syncing then .progress "Loading payment details…"
                         else .button "Load payment details" .plain (some (.home .loadPayment))]]
      else []
    let txSection : List H :=
      if m.settings.advancedMode then
        [.section "Transaction" ""
          ([ copyableIdentifier m "pay.txid" txid
           , explorerButton "View transaction" (m.settings.transactionURL txid) "transaction ID" ] ++
           (if m.status.feeBumpable.contains txid then [.button "Bump fee" .plain (some (.home .openFeeBump))] else []))]
      else [.section "" "" (technical m "pay.txid" "Transaction ID" [copyableIdentifier m "pay.txid" txid])]
    [.section "" "" [historyRow m h false]] ++ recipients ++ labelSection ++ notice ++
    (if h.received > 0 then [senderSection m h] else []) ++ load ++
    (match m.payment.error with | some e => [.section "" "" (errorRows (some e))] | none => []) ++ txSection

/-! ### FeeBumpView -/

def feeBumpSheet (m : Model) (inner : List H) : H :=
  let f := m.feeBump
  .sheet "Bump fee" (if f.bumping then none else some .closeSheet)
    ([ closeRow "Close"
     , .section "Transaction" "" [ copyableIdentifier m "bump.txid" f.txid,
                                   .labeled "Current rate" ((f.currentRateMilli.map feeRateText).getD "—") ] ] ++
     (if f.replacement.isNone then
       [.section "Replacement fee" "The recipient and inputs stay the same. The extra fee comes from change; Winnow enforces a higher absolute fee, a higher feerate, and the incremental relay fee."
         [ .input .decimal "" "Higher rate (sat/vB)" f.targetText (fun s => .home (.setBumpRate s)) none
         , .button "Review replacement" .plain (if (parseRateMilli f.targetText (trimNewlines := true)).isSome then some (.home .reviewBump) else none) ]]
      else []) ++
     (match f.reviewed, f.replacement with
      | some (_, p), none =>
        [.section "Review" ""
          [ .labeled "Actual rate" (feeRateText p.feeRateMilli)
          , .labeled "Replacement fee" (satsText p.fee)
          , .labeled "Change back" (match p.change with | some c => satsText c | none => "none (remainder becomes fee)")
          , .button (if f.bumping then "Signing & broadcasting…" else "Sign & replace") .primary
              (if f.bumping then none else some (.home .bump)) ]]
      | _, _ => []) ++
     (match f.replacement with
      | some r => [.section "Replacement broadcast" ""
                    [ .row [.icon "arrow.triangle.2.circlepath", body "Original marked replaced"]
                    , copyableIdentifier m "bump.replacement" r
                    , .button "Done" .primary (some .closeSheet) ]]
      | none => []) ++
     (match f.error with | some e => [.section "" "" (errorRows (some e))] | none => []) ++ inner)

end WinnowApp
