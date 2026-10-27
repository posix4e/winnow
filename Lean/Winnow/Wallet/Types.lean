import Winnow.Wallet.SwiftJSON
import Winnow.Tx.Transaction
import Winnow.Tx.TransactionBuilder
import Winnow.Tx.SighashBIP341
import Winnow.Tx.PSBT

/-! # Wallet data types and the wallet file

Port of the data half of `Sources/WalletCore/Wallet/Wallet.swift`: `WalletError`, `FeeBumpError`,
`AddressChain`, `WalletUTXO` (+ `SpentMarker`), `HistoryEntry`, `MatchEffect`, `PendingSend`,
`WalletState` with their hand-written `Codable` forms, `BuiltTransaction` and `FeeBumpPreview`. The
`Wallet` actor itself is not here.

JSON (see `SwiftJSON`): txids are display-order hex, scripts hex, `Data` fields that use the synthesized
coding (`SpentMarker.spentBy`, `rawTransaction`, `fundingScripts`) base64. Decoders run in the Swift
order, so the first failing field names the same error. -/

namespace Winnow
open SwiftJSON

/-! ## Errors -/

inductive WalletError where
  | invalidDescriptor (s : String)
  | descriptorMismatch
  | invalidBundle (reason : String)
  | noPayments
  | changeOutputMissing
  | transactionTooLarge (vsize limit : Int)
  | mnemonicUnavailable
  | exportWhilePending
  | invalidTransactionAmounts
  | unsupportedWalletData
  | storageTooLarge (maxBytes : Int)
  deriving Inhabited, BEq

namespace WalletError
def name : WalletError → String
  | .invalidDescriptor _ => "invalidDescriptor" | .descriptorMismatch => "descriptorMismatch"
  | .invalidBundle _ => "invalidBundle" | .noPayments => "noPayments"
  | .changeOutputMissing => "changeOutputMissing" | .transactionTooLarge .. => "transactionTooLarge"
  | .mnemonicUnavailable => "mnemonicUnavailable" | .exportWhilePending => "exportWhilePending"
  | .invalidTransactionAmounts => "invalidTransactionAmounts" | .unsupportedWalletData => "unsupportedWalletData"
  | .storageTooLarge _ => "storageTooLarge"

/-- `errorDescription`. -/
def description : WalletError → String
  | .invalidDescriptor _ =>
    "That wallet descriptor could not be parsed. It is not repeated here, " ++
      "because a descriptor can carry key material."
  | .descriptorMismatch => "Bundle descriptor does not match the mnemonic."
  | .invalidBundle reason => s!"Invalid import bundle: {reason}"
  | .noPayments => "Nothing to send."
  | .changeOutputMissing => "The built transaction lost its change output."
  | .transactionTooLarge vsize limit => s!"The signed transaction is {vsize} vbytes, above the {limit}-vbyte relay maximum."
  | .mnemonicUnavailable =>
    "This wallet has no recovery phrase to export — it was imported from an extended key, not a BIP39 mnemonic."
  | .exportWhilePending =>
    "Wait for pending transactions to confirm before exporting. A mid-send backup would drop the coins being spent."
  | .invalidTransactionAmounts => "A matched Bitcoin transaction contains invalid amounts. Wallet state was not changed."
  | .unsupportedWalletData =>
    "This wallet contains unsupported signing data and cannot be opened here. " ++
      "Keep the original wallet file and use compatible wallet software to recover these coins."
  | .storageTooLarge maxBytes => s!"The wallet file is larger than the {maxBytes.tdiv 1_048_576} MB this wallet can hold and was not read."
end WalletError

inductive FeeBumpError where
  | transactionNotPending
  | noChangeOutput
  | changeAlreadySpent
  | invalidFeeRate (rate : Float)
  | feeRateNotHigher (current requested : Float)
  | insufficientChange (requiredFee maximumFee : Int64)
  deriving Inhabited

namespace FeeBumpError
def name : FeeBumpError → String
  | .transactionNotPending => "transactionNotPending" | .noChangeOutput => "noChangeOutput"
  | .changeAlreadySpent => "changeAlreadySpent" | .invalidFeeRate _ => "invalidFeeRate"
  | .feeRateNotHigher .. => "feeRateNotHigher" | .insufficientChange .. => "insufficientChange"

/-- `errorDescription` (the two-decimal rates are en_US `formatted`). -/
def description : FeeBumpError → String
  | .transactionNotPending =>
    "This transaction is no longer pending or was created before fee-bump metadata was available."
  | .noChangeOutput => "This transaction has no change output to reduce for a same-input fee bump."
  | .changeAlreadySpent => "This transaction's change has already been spent by another pending transaction."
  | .invalidFeeRate rate => s!"Invalid replacement fee rate: {SwiftDouble.description rate} sat/vB."
  | .feeRateNotHigher current requested =>
    s!"Choose a fee rate above {SwiftDouble.formatted2 current} sat/vB (requested {SwiftDouble.formatted2 requested} sat/vB)."
  | .insufficientChange requiredFee maximumFee =>
    s!"The available change can pay at most {maximumFee.toInt} sats in fees; this bump needs {requiredFee.toInt} sats."
end FeeBumpError

/-! ## Coins and history -/

/-- Which chain of the multipath descriptor an address is on (raw values 0 / 1). -/
inductive AddressChain where
  | receive | change
  deriving Inhabited, BEq, Repr

def AddressChain.rawValue : AddressChain → Nat | .receive => 0 | .change => 1

structure SpentMarker where
  spentBy : ByteArray
  height : Option UInt32
  deriving Inhabited, BEq

structure WalletUTXO where
  txid : ByteArray -- internal byte order
  vout : UInt32
  amount : Int64
  scriptPubKey : ByteArray
  chain : AddressChain
  index : UInt32
  height : UInt32
  isCoinbase : Bool := false
  spent : Option SpentMarker := none
  deriving Inhabited, BEq

namespace WalletUTXO
def isSpent (u : WalletUTXO) : Bool := u.spent.isSome
def outpoint (u : WalletUTXO) : Transaction.Outpoint := ⟨u.txid, u.vout⟩
def spentOutput (u : WalletUTXO) : SighashBIP341.SpentOutput := { amount := u.amount, scriptPubKey := u.scriptPubKey }
end WalletUTXO

structure HistoryEntry where
  txid : ByteArray
  height : UInt32
  received : Int64
  spent : Int64
  fee : Option Int64 := none
  replacedBy : Option ByteArray := none
  rawTransaction : Option ByteArray := none
  fundingScripts : Array ByteArray := #[]
  deriving Inhabited, BEq

/-- What applying one matched block changed. -/
structure MatchEffect.Spend where
  txid : ByteArray
  vout : UInt32
  spentBy : ByteArray
  height : UInt32
  deriving Inhabited, BEq

structure MatchEffect where
  received : Array WalletUTXO := #[]
  spent : Array MatchEffect.Spend := #[]
  discardedReplacements : Array ByteArray := #[]
  deriving Inhabited, BEq

/-- Exact data of a locally-created, still-replaceable send. -/
structure PendingSend where
  rawTransaction : ByteArray
  selected : Array WalletUTXO
  changeIndex : Option UInt32
  changeOutputIndex : Option UInt32
  fee : Int64
  deriving Inhabited, BEq

structure WalletState where
  descriptor : String
  network : String
  creationHeight : UInt32
  nextReceiveIndex : UInt32 := 0
  nextChangeIndex : UInt32 := 0
  nextScanHeight : UInt32
  allUtxos : Array WalletUTXO := #[]
  history : Array HistoryEntry := #[]
  observedFeeRates : Array Float := #[]
  pendingSends : Array PendingSend := #[]
  deriving Inhabited, BEq

def WalletState.utxos (s : WalletState) : Array WalletUTXO := s.allUtxos.filter (!·.isSpent)

/-- `Wallet.send`'s result. -/
structure BuiltTransaction where
  psbt : PSBT
  transaction : Transaction
  fee : Int64
  changeAmount : Option Int64
  deriving Inhabited

structure FeeBumpPreview where
  originalTxid : ByteArray
  currentFeeRateSatPerVByte : Float
  feeRateSatPerVByte : Float
  fee : Int64
  changeAmount : Option Int64
  replacementTransaction : Transaction
  deriving Inhabited

/-- Binds the signed replacement to the reviewed transaction (witnesses excluded). -/
def FeeBumpPreview.authorizes (p : FeeBumpPreview) (built : BuiltTransaction) : Bool :=
  let actual := built.transaction
  let reviewed := p.replacementTransaction
  let sameInputs := actual.inputs.size == reviewed.inputs.size &&
    (actual.inputs.zip reviewed.inputs).all fun (a, b) =>
      a.previousOutput == b.previousOutput && a.scriptSig == b.scriptSig && a.sequence == b.sequence
  if !(built.fee == p.fee && built.changeAmount == p.changeAmount && actual.version == reviewed.version &&
      actual.locktime == reviewed.locktime && actual.outputs == reviewed.outputs && sameInputs) then false
  else
    let vsize := TransactionBuilder.vsize actual
    vsize > 0 && Float.ofInt built.fee.toInt / vsize.toFloat == p.feeRateSatPerVByte

/-! ## JSON -/

def displayHex (b : ByteArray) : String := hex (ByteArray.reverse b)

def hexField (kvs : Array (String × JV)) (k : String) : D ByteArray := do
  let s ← key kvs k asString
  match Wire.dataOfHex? s with
  | some b => pure b
  | none => dataCorrupted

def obj (kvs : List (String × Option JV)) : JV := .obj (kvs.filterMap fun (k, v) => v.map (k, ·)).toArray

namespace SpentMarker
def toJV (m : SpentMarker) : JV :=
  obj [("spentBy", some (ofData m.spentBy)), ("height", m.height.map (ofInt ·.toNat))]
def ofJV (v : JV) : D SpentMarker := do
  let kvs ← asObject v
  let spentBy ← key kvs "spentBy" asData
  let height ← keyIfPresent kvs "height" asUInt32
  return { spentBy, height }
end SpentMarker

namespace WalletUTXO
def toJV (u : WalletUTXO) : JV :=
  obj [("txid", some (.str (displayHex u.txid))), ("vout", some (ofInt u.vout.toNat)),
    ("amount", some (ofInt u.amount.toInt)), ("scriptPubKey", some (.str (hex u.scriptPubKey))),
    ("chain", some (ofInt u.chain.rawValue)), ("index", some (ofInt u.index.toNat)),
    ("height", some (ofInt u.height.toNat)), ("spent", u.spent.map SpentMarker.toJV),
    ("isCoinbase", if u.isCoinbase then some (.bool true) else none)]

def chainOfJV (v : JV) : D AddressChain := do
  match ← asInt v with
  | 0 => pure .receive
  | 1 => pure .change
  | _ => dataCorrupted

def ofJV (v : JV) : D WalletUTXO := do
  let kvs ← asObject v
  let txid ← hexField kvs "txid"
  let scriptPubKey ← hexField kvs "scriptPubKey"
  if contains kvs "silentPaymentTweak" then throw "unsupportedWalletData"
  let vout ← key kvs "vout" asUInt32
  let amount ← key kvs "amount" asInt64
  let chain ← key kvs "chain" chainOfJV
  let index ← key kvs "index" asUInt32
  let height ← key kvs "height" asUInt32
  let isCoinbase := (← keyIfPresent kvs "isCoinbase" asBool).getD false
  let spent ← keyIfPresent kvs "spent" SpentMarker.ofJV
  return { txid := ByteArray.reverse txid, vout, amount, scriptPubKey, chain, index, height, isCoinbase, spent }
end WalletUTXO

namespace HistoryEntry

/-- `transaction()`: the stored payment, checked against the txid and the monetary range. -/
def transaction (h : HistoryEntry) : Except String (Option Transaction) := do
  let some raw := h.rawTransaction | return none
  let tx ← (Transaction.decode raw).mapError (·.name)
  unless tx.txid == h.txid do throw "invalidBundle"
  let mut total : Int64 := 0
  for o in tx.outputs do
    unless 0 ≤ o.value && o.value ≤ bitcoinAmountMaximum && o.value ≤ bitcoinAmountMaximum - total do
      throw "invalidTransactionAmounts"
    total := total + o.value
  return some tx

def toJV (h : HistoryEntry) : JV :=
  obj [("txid", some (.str (displayHex h.txid))), ("height", some (ofInt h.height.toNat)),
    ("received", some (ofInt h.received.toInt)), ("spent", some (ofInt h.spent.toInt)),
    ("fee", h.fee.map (ofInt ·.toInt)), ("replacedBy", h.replacedBy.map (.str ∘ displayHex)),
    ("rawTransaction", h.rawTransaction.map ofData),
    ("fundingScripts", if h.fundingScripts.isEmpty then none else some (.arr (h.fundingScripts.map ofData)))]

def ofJV (v : JV) : D HistoryEntry := do
  let kvs ← asObject v
  let txid ← hexField kvs "txid"
  let replacedBy ← match ← keyIfPresent kvs "replacedBy" asString with
    | none => pure none
    | some s => match Wire.dataOfHex? s with
      | some b => pure (some (ByteArray.reverse b))
      | none => dataCorrupted
  let height ← key kvs "height" asUInt32
  let received ← key kvs "received" asInt64
  let spent ← key kvs "spent" asInt64
  let fee ← keyIfPresent kvs "fee" asInt64
  let rawTransaction ← keyIfPresent kvs "rawTransaction" asData
  let fundingScripts := (← keyIfPresent kvs "fundingScripts" (asArray asData)).getD #[]
  let h : HistoryEntry := { txid := ByteArray.reverse txid, height, received, spent, fee, replacedBy, rawTransaction, fundingScripts }
  discard h.transaction
  return h
end HistoryEntry

namespace PendingSend
def toJV (p : PendingSend) : JV :=
  obj [("rawTransaction", some (.str (hex p.rawTransaction))), ("selected", some (.arr (p.selected.map WalletUTXO.toJV))),
    ("changeIndex", p.changeIndex.map (ofInt ·.toNat)), ("changeOutputIndex", p.changeOutputIndex.map (ofInt ·.toNat)),
    ("fee", some (ofInt p.fee.toInt))]

def ofJV (v : JV) : D PendingSend := do
  let kvs ← asObject v
  let rawHex ← key kvs "rawTransaction" asString
  let raw ← match Wire.dataOfHex? rawHex with
    | some b => if (Transaction.decode b).toOption.isSome then pure b else dataCorrupted
    | none => dataCorrupted
  let selected ← key kvs "selected" (asArray WalletUTXO.ofJV)
  let changeIndex ← keyIfPresent kvs "changeIndex" asUInt32
  let changeOutputIndex ← keyIfPresent kvs "changeOutputIndex" asUInt32
  let fee ← key kvs "fee" asInt64
  return { rawTransaction := raw, selected, changeIndex, changeOutputIndex, fee }
end PendingSend

namespace WalletState

def toJV (s : WalletState) : JV :=
  obj [("descriptor", some (.str s.descriptor)), ("network", some (.str s.network)),
    ("creationHeight", some (ofInt s.creationHeight.toNat)), ("nextReceiveIndex", some (ofInt s.nextReceiveIndex.toNat)),
    ("nextChangeIndex", some (ofInt s.nextChangeIndex.toNat)), ("nextScanHeight", some (ofInt s.nextScanHeight.toNat)),
    ("utxos", some (.arr (s.allUtxos.map WalletUTXO.toJV))), ("history", some (.arr (s.history.map HistoryEntry.toJV))),
    ("observedFeeRates", some (.arr (s.observedFeeRates.map ofDouble))),
    ("pendingSends", some (.arr (s.pendingSends.map PendingSend.toJV)))]

/-- Every coin well-formed and no outpoint twice; optionally the total within the monetary range. -/
def validateCoins (coins : Array WalletUTXO) (countingTotal : Bool := true) : D Unit := do
  let mut seen : Array Transaction.Outpoint := #[]
  let mut total : Int := 0
  for c in coins do
    unless c.txid.size == 32 && !c.scriptPubKey.isEmpty && c.amount > 0 && c.amount ≤ bitcoinAmountMaximum &&
        (c.spent.map (·.spentBy.size == 32)).getD true && !seen.contains c.outpoint do dataCorrupted
    seen := seen.push c.outpoint
    if !countingTotal then continue
    let next := total + c.amount.toInt
    unless next ≤ bitcoinAmountMaximum.toInt do dataCorrupted
    total := next

def inMoney (v : Int64) : Bool := 0 ≤ v && v ≤ bitcoinAmountMaximum

def ofJV (v : JV) : D WalletState := do
  let kvs ← asObject v
  let descriptor ← key kvs "descriptor" asString
  let network ← key kvs "network" asString
  let creationHeight ← key kvs "creationHeight" asUInt32
  let nextReceiveIndex ← key kvs "nextReceiveIndex" asUInt32
  let nextChangeIndex ← key kvs "nextChangeIndex" asUInt32
  let nextScanHeight ← key kvs "nextScanHeight" asUInt32
  let allUtxos ← key kvs "utxos" (asArray WalletUTXO.ofJV)
  let history ← key kvs "history" (asArray HistoryEntry.ofJV)
  let observedFeeRates := (← keyIfPresent kvs "observedFeeRates" (asArray asDouble)).getD #[]
  let pendingSends := (← keyIfPresent kvs "pendingSends" (asArray PendingSend.ofJV)).getD #[]
  let s : WalletState :=
    { descriptor := descriptor, network := network, creationHeight := creationHeight,
      nextReceiveIndex := nextReceiveIndex, nextChangeIndex := nextChangeIndex, nextScanHeight := nextScanHeight,
      allUtxos := allUtxos, history := history, observedFeeRates := observedFeeRates, pendingSends := pendingSends }
  validateCoins allUtxos (countingTotal := false)
  validateCoins s.utxos
  for p in pendingSends do
    validateCoins p.selected
    unless inMoney p.fee do dataCorrupted
  unless history.all (fun e => e.txid.size == 32 && inMoney e.received && inMoney e.spent &&
      (e.fee.map inMoney).getD true) &&
    observedFeeRates.all (fun r => r.isFinite && r > 0 && r ≤ 10_000) do dataCorrupted
  return s

/-- The wallet file text (`JSONEncoder` output, keys sorted). A non-finite fee sample cannot be
written: `JSONEncoder` throws `EncodingError.invalidValue` (`invalidValue` here). -/
def encode (s : WalletState) : Except String String := do
  unless s.observedFeeRates.all (·.isFinite) do throw "invalidValue"
  return write s.toJV

/-- `JSONDecoder().decode(WalletState.self, from:)`. -/
def decode (text : String) : D WalletState := decodeText text ofJV

end WalletState
end Winnow
