/-! # Fee-rate resolution (Wallet/FeePolicy.swift)

Strongest first: an explicit user override, else the median rate observed in the wallet's own confirmed
transactions, else a static preset per priority; the result is clamped from below by the peers' BIP133
`feefilter` floor. Rates are sat/vB as `Float` (Swift's `Double`). -/

namespace Winnow.FeePolicy

inductive Priority where
  | low
  | medium
  | high
  deriving Repr, BEq, DecidableEq, Inhabited

def Priority.satPerVByte : Priority → Float
  | .low => 2
  | .medium => 5
  | .high => 12

def Priority.ofString? : String → Option Priority
  | "low" => some .low
  | "medium" => some .medium
  | "high" => some .high
  | _ => none

/-- Median of the samples (`none` when empty): the middle one, or the mean of the two middle ones. -/
def median (samples : Array Float) : Option Float :=
  if samples.isEmpty then none
  else
    let sorted := samples.qsort (· < ·)
    let mid := sorted.size / 2
    some (if sorted.size % 2 == 1 then sorted[mid]! else (sorted[mid - 1]! + sorted[mid]!) / 2)

def resolve (priority : Priority := .medium) (override : Option Float := none) (observed : Array Float := #[])
    (floor : Option Float := none) : Float :=
  let base := override.getD ((median observed).getD priority.satPerVByte)
  match floor with
  | none => base
  | some f => if base < f then f else base

end Winnow.FeePolicy
