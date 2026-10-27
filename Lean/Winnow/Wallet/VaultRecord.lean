import Winnow.Wallet.Types

/-! # A persisted vault (port of `Sources/WalletCore/Wallet/VaultRecord.swift`)

The record the app keeps in `vaults.json`. The synthesized `Codable` requires every key (Swift ignores
property defaults when it synthesizes `init(from:)`), and the stored `allUtxos` keeps the on-disk key
`utxos`. -/

namespace Winnow
open SwiftJSON

structure VaultRecord where
  /-- The descriptor checksum. -/
  id : String
  name : String
  descriptor : String
  createdAtHeight : UInt32
  nextReceiveIndex : UInt32 := 0
  nextChangeIndex : UInt32 := 0
  allUtxos : Array WalletUTXO := #[]
  deriving Inhabited, BEq

namespace VaultRecord

def utxos (r : VaultRecord) : Array WalletUTXO := r.allUtxos.filter (!·.isSpent)

def balance (r : VaultRecord) : Int64 := r.utxos.foldl (fun a u => a + u.amount) 0

def toJV (r : VaultRecord) : JV :=
  .obj #[("id", .str r.id), ("name", .str r.name), ("descriptor", .str r.descriptor),
    ("createdAtHeight", ofInt r.createdAtHeight.toNat), ("nextReceiveIndex", ofInt r.nextReceiveIndex.toNat),
    ("nextChangeIndex", ofInt r.nextChangeIndex.toNat), ("utxos", .arr (r.allUtxos.map WalletUTXO.toJV))]

/-- Synthesized `init(from:)`: declaration order, every key required. -/
def ofJV (v : JV) : D VaultRecord := do
  let kvs ← asObject v
  let id ← key kvs "id" asString
  let name ← key kvs "name" asString
  let descriptor ← key kvs "descriptor" asString
  let createdAtHeight ← key kvs "createdAtHeight" asUInt32
  let nextReceiveIndex ← key kvs "nextReceiveIndex" asUInt32
  let nextChangeIndex ← key kvs "nextChangeIndex" asUInt32
  let allUtxos ← key kvs "utxos" (asArray WalletUTXO.ofJV)
  return { id, name, descriptor, createdAtHeight, nextReceiveIndex, nextChangeIndex, allUtxos }

end VaultRecord
end Winnow
