import WinnowApp.Backend

/-! A UI harness (like Winnow's DEBUG-only E2EMode): `Backend.pending` with a wallet that "opens" and
fixed sample records, so every screen can be reached in the simulator before the Lean wallet is wired
in. Selected only by the `WINNOW_LEAN_SAMPLE=1` launch environment; every operation that would touch a
wallet still fails with "still being ported". The data is made up (signet-style addresses). -/

namespace WinnowApp

def sampleAlice : Person :=
  { id := "p-alice", name := "Alice", payTo := some true, signerKey := some "[a1b2c3d4/86'/1'/0']tpubAlice/<0;1>/*",
    signerFingerprint := some "a1b2 c3d4", nextPaymentIndex := 3, savedRecipient := some true }
def sampleBob : Person :=
  { id := "p-bob", name := "Bob", payTo := some false, savedRecipient := some true, provenance := some .localFunding }
def sampleCarol : Person :=
  { id := "p-carol", name := "Carol", signerKey := some "[0badcafe/86'/1'/0']tpubCarol/<0;1>/*", signerFingerprint := some "0bad cafe" }

def sampleVault : VaultSummary :=
  { id := "v-1", name := "Savings with Alice", descriptor := "tr(NUMS,multi_a(2,[a1b2c3d4/86'/1'/0']tpubAlice/<0;1>/*,[f00dbabe/86'/1'/0']tpubYou/<0;1>/*))",
    balance := 250000, threshold := 2, signerCount := 2, isScriptPath := true,
    receiveAddress := some "tb1pq7v5yd3k8u0x9sample0vault0address0000000000000000000qqqq",
    utxos := [{ txid := "7a1f00c0ffee0000000000000000000000000000000000000000000000000001", vout := 0, amount := 250000, height := 214001 }],
    coOwners := ["Alice"], includesYou := true,
    signers := [{ fingerprint := "a1b2 c3d4", name := some "Alice", isYou := false },
                { fingerprint := "f00d babe", name := none, isYou := true }] }

def sampleHistory : List HistoryItem :=
  [ { txid := "c0ffee0000000000000000000000000000000000000000000000000000000003", height := 0,
      received := 0, spent := 12000, fee := some 300 }
  , { txid := "b0b0000000000000000000000000000000000000000000000000000000000002", height := 214010,
      received := 30000, spent := 80000, fee := some 450,
      outputs := some [ { index := 0, address := some "tb1qbobsample000000000000000000000000000", script := "0014b0b", amount := 49550, ownedByWallet := false }
                      , { index := 1, address := some "tb1pchange000000000000000000000000000000000000000000000000", script := "5120c4a", amount := 30000, ownedByWallet := true } ] }
  , { txid := "a11ce00000000000000000000000000000000000000000000000000000000001", height := 213990,
      received := 120000, spent := 0, fee := none,
      outputs := some [ { index := 0, address := some "tb1preceive00000000000000000000000000000000000000000000000", script := "5120ab1", amount := 120000, ownedByWallet := true } ],
      fundingAddresses := ["tb1qalicefunding0000000000000000000000000"] } ]

def Backend.sample : Backend :=
  { Backend.pending with
    openWallet := fun _ _ => pure (.opened "sample-wallet")
    snapshot := pure ({ balance := 138000, utxoCount := 2, history := sampleHistory, feeBumpable := [sampleHistory[0]!.txid],
                        peerCount := 0, tipHeight := 214020, nextScanHeight := 214021, feeFloorMilli := some 1000 }, .peerDiscoveryFailed)
    records := pure { people := [sampleAlice, sampleBob, sampleCarol], vaults := [sampleVault],
                      senderByTxid := [(sampleHistory[2]!.txid, "p-alice")],
                      recipientByScript := [("0014b0b", "p-bob")],
                      receiveLabels := [("tb1preceive00000000000000000000000000000000000000000000000", "Alice · invoice 12")],
                      ownSignerFingerprint := some "f00d babe" }
    catalogStatus := pure "Using bundled candidates. Downloaded catalogs expire after seven days." }

end WinnowApp
