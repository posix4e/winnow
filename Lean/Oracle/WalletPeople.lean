import Oracle.WalletScenario

/-! Vault, vault-setup, people and import-bundle ops (Lean side of `LeanOracle/Wallet/People.swift`).
`vault.flow` runs a whole vault spend — create, review, the signing roles, combine, finalize — reporting
the PSBT after each role with signature and nonce values by length (the Swift vault draws its own BIP340
and MuSig2 randomness). -/

namespace Oracle.WalletPeople
open Lean Winnow Keys

def netJ (j : Json) : Except String Tx.BitcoinNetwork := do
  match Tx.BitcoinNetwork.ofString? ((str j "network").toOption.getD "signet") with
  | some n => pure n
  | none => throw "network"

def roleJ (j : Json) : VaultCosignerRole := if (str j "role").toOption == some "muSig2" then .muSig2 else .scriptPath
def errJ (e : String) : Json := err e
def optS (o : Option String) : Json := optJ Json.str o

/-! ## Vault summaries -/

def vaultJ (v : Vault) : Json :=
  let keys (i : UInt32) (c : Nat) : Json := match v.signerKeys i c with
    | .ok ks => Json.arr (ks.map hexJ) | .error e => Json.str s!"error:{e.name}"
  let at_ (i : UInt32) (c : Nat) : Json := match v.scriptPubKey i c, v.address i c with
    | .ok s, .ok a => Json.arr #[hexJ s, Json.str a] | .error e, _ => Json.str s!"error:{e.name}" | _, .error e => Json.str s!"error:{e.name}"
  Json.mkObj [("descriptor", Json.str v.descriptor.serialized), ("threshold", Json.num v.threshold), ("signers", Json.num v.signerCount),
    ("scriptPath", Json.bool v.isScriptPath), ("nums", Json.bool v.usesUnspendableInternalKey),
    ("expressions", Json.arr (v.cosignerExpressions.map Json.str)), ("keys00", keys 0 0), ("keys31", keys 3 1),
    ("at00", at_ 0 0), ("at71", at_ 7 1),
    ("watch", match v.watchScripts 2 with | .ok xs => Json.arr (xs.map hexJ) | .error e => Json.str s!"error:{e.name}")]

/-! ## Pure ops -/

def payToJ (p : PersonPayTo) (network : Tx.BitcoinNetwork) (count : UInt32) : Json :=
  let r {α} (x : PM α) (f : α → Json) : Json := match x with | .ok a => f a | .error e => Json.str s!"error:{e}"
  Json.mkObj [("json", Json.str (SwiftJSON.write p.toJV)), ("fresh", Json.bool p.derivesFreshAddresses), ("text", Json.str p.text),
    ("a0", r (p.addressAt 0 network) Json.str), ("a5", r (p.addressAt 5 network) Json.str),
    ("scripts", r (p.scripts count network) fun xs => Json.arr (xs.map hexJ)), ("identity", r (p.identity network) hexJ)]

def importJ (i : PersonImport) (network : Tx.BitcoinNetwork) : Json :=
  Json.mkObj [("name", optS i.name), ("payTo", optJ (fun p => payToJ p network 2) i.payTo), ("signerKey", optS i.signerKey),
    ("source", Json.str i.source.name)]

def labelJ : PaymentLabel → Json
  | .savings n => Json.str s!"savings:{n}" | .person n => Json.str s!"person:{n}" | .you => Json.str "you" | .unknown => Json.str "unknown"

def draftJ (d : VaultDraft) : Json :=
  Json.mkObj [("role", Json.str (if d.role == .muSig2 then "muSig2" else "scriptPath")), ("threshold", Json.num d.threshold),
    ("cosigners", Json.arr (d.cosigners.map (Json.str ·.expression))), ("canBuild", Json.bool d.canBuild)]

def reportBundleJ (b : ImportBundle) : Json :=
  Json.mkObj [("serialized", Json.str b.serialized),
    ("claimed", match b.claimedUTXOs with
      | .ok us => Json.arr (us.map fun u => Json.str (SwiftJSON.write u.toJV))
      | .error e => Json.str s!"error:{e.name}")]

def ops : List (String × Handler) := [
  ("people.describe", fun j => do
    let n := (Tx.BitcoinNetwork.ofString? ((str j "network").toOption.getD "signet")).getD .signet
    let sArg := (str j "s").toOption.getD ""
    let iArg : Int := (j.getObjValAs? Int "i").toOption.getD 0
    let text ← match ← str j "type", ← str j "case" with
      | "vault", "invalidDescriptor" => pure (VaultError.invalidDescriptor sArg).description
      | "vault", "scriptMismatch" => pure (VaultError.scriptMismatch iArg.toNat.toUInt32 ((j.getObjValAs? Nat "c").toOption.getD 0)).description
      | "vault", "noCosignerKey" => pure (VaultError.noCosignerKey iArg.toNat).description
      | "vault", "invalidSpend" => pure (VaultError.invalidSpend sArg).description
      | "cosigner", c => match ([VaultCosignerKeyError.malformed, .privateKey, .extendedPublicKeyRequired, .missingOrigin,
            .originPathMismatch, .wrongNetwork sArg, .scriptPathDerivationRequired, .muSig2DerivationForbidden, .duplicateKey].find? (·.name == c)) with
        | some e => pure e.description
        | none => throw "case"
      | "payTo", c => match ([PersonPayToError.malformed, .privateKey, .singleAddressKey, .notSingleKey, .wrongNetwork n,
            .unsupportedDerivation].find? (·.name == c)) with
        | some e => pure e.description
        | none => throw "case"
      | "card", "notACard" => pure PersonCardError.notACard.description
      | "card", "unsupportedVersion" => pure (PersonCardError.unsupportedVersion iArg).description
      | "card", "wrongNetwork" => pure (PersonCardError.wrongNetwork sArg n).description
      | "paste", "empty" => pure PersonPasteError.empty.description
      | "paste", "unrecognised" => pure PersonPasteError.unrecognised.description
      | _, _ => throw "case"
    return ok (Json.str text)),
  ("vault.parse", fun j => do
    let n ← netJ j
    return match Vault.parse (← str j "descriptor") n with
      | .ok v => ok (vaultJ v) | .error e => errJ e.name),
  ("vault.multiA", fun j => do
    let cs ← listJ (fun v => match v with | .str s => pure s | _ => throw "cosigner") (field j "cosigners")
    return match Vault.multiADescriptor (← j.getObjValAs? Int "k") cs with
      | .ok d => ok (Json.str d.serialized) | .error e => errJ e.name),
  ("vault.cosigner", fun j => do
    let role := roleJ j
    let expr ← str j "expression"
    let r : Except VaultCosignerKeyError VaultCosignerKey ← match str j "network" with
      | .ok _ => pure (VaultCosignerKey.make expr role (← netJ j))
      | .error _ => pure (VaultCosignerKey.validateWithoutNetwork expr role)
    return match r with
      | .ok k => ok (Json.mkObj [("expression", Json.str k.expression),
          ("pk00", match k.publicKey 0 0 with | .ok b => hexJ b | .error e => Json.str s!"error:{e}"),
          ("pk51", match k.publicKey 5 1 with | .ok b => hexJ b | .error e => Json.str s!"error:{e}")])
      | .error e => errJ e.name),
  ("vault.draft", fun j => do
    let n ← netJ j
    let steps := match field j "steps" with | .arr xs => xs | _ => #[]
    let mut d : VaultDraft := {}
    let mut out := #[]
    for st in steps do
      match str st "op" with
      | .ok "add" =>
        match d.add (← str st "expression") n with
        | .ok d' => d := d'; out := out.push (draftJ d)
        | .error e => out := out.push (Json.mkObj [("error", Json.str e.name), ("draft", draftJ d)])
      | .ok "remove" =>
        d := d.remove (← listJ (fun v => v.getNat?) (field st "offsets")); out := out.push (draftJ d)
      | .ok "threshold" => d := d.setThreshold (← st.getObjValAs? Int "value"); out := out.push (draftJ d)
      | .ok "role" =>
        let (d', changed) := d.setRole (roleJ st)
        d := d'; out := out.push (Json.mkObj [("changed", Json.bool changed), ("draft", draftJ d)])
      | _ => throw "draft op"
    return ok (Json.arr out)),
  ("vault.threshold", fun j => do
    let t ← j.getObjValAs? Int "t"
    let p ← j.getObjValAs? Int "previous"
    let c ← j.getObjValAs? Int "count"
    return ok (Json.arr #[Json.num (VaultThreshold.clamped t c), Json.num (VaultThreshold.reconciled t p c)])),
  ("people.payTo", fun j => do
    let n ← netJ j
    let text ← str j "text"
    let r := if (str j "kind").toOption == some "address" then PersonPayTo.ofAddress text n
      else (PersonPayTo.ofDescriptor text n).mapError (·.name)
    return match r with
      | .ok p => ok (payToJ p n ((nat j "count").toOption.getD 3).toUInt32) | .error e => errJ e),
  ("people.payToJSON", fun j => do
    return match SwiftJSON.decodeText (← str j "json") PersonPayTo.ofJV with
      | .ok p => ok (Json.str (SwiftJSON.write p.toJV)) | .error e => errJ e),
  ("people.signer", fun j => do
    let n ← netJ j
    let e ← str j "expression"
    return match PersonKeys.signerIdentity e n, PersonKeys.signerFingerprint e n with
      | .ok i, .ok f => ok (Json.mkObj [("identity", hexJ i), ("fingerprint", Json.str f)])
      | .error e, _ => errJ e | _, .error e => errJ e),
  ("people.fingerprint", fun j => do return ok (Json.str (PersonKeys.fingerprint (← bytes j "identity")))),
  ("people.displayName", fun j => do return ok (optS (DisplayName.normalized (← str j "text")))),
  ("people.cardMake", fun j => do
    let n ← netJ j
    let c := PersonCard.make n (← str j "name") (str j "payTo").toOption (str j "signerKey").toOption
    let s := SharedSavingsCard.make n (← str j "name") ((str j "descriptor").toOption.getD "")
    return ok (Json.arr #[Json.str c.serialized, Json.str s.serialized])),
  ("people.cardDecode", fun j => do
    return match PersonCard.decode (← str j "text") with
      | .ok c => ok (Json.str c.serialized) | .error e => errJ e.name),
  ("people.savingsDecode", fun j => do
    let n ← netJ j
    return match SharedSavingsCard.decode (← str j "text") n with
      | .ok (c, v) => ok (Json.arr #[Json.str c.serialized, vaultJ v]) | .error e => errJ e),
  ("people.approvalMake", fun j => do
    let n ← netJ j
    return match PSBT.parse (← bytes j "psbt") with
      | .ok p => ok (Json.str (ApprovalRequest.make n (str j "vault").toOption (str j "name").toOption p).serialized)
      | .error e => errJ e.name),
  ("people.approvalDecode", fun j => do
    let n ← netJ j
    return match ApprovalRequest.decode (← str j "text") n with
      | .ok r => ok (Json.mkObj [("serialized", Json.str r.serialized),
          ("psbt", match r.decodedPSBT with | .ok p => hexJ p.serialized | .error e => Json.str s!"error:{e}")])
      | .error e => errJ e),
  ("people.paste", fun j => do
    let n ← netJ j
    return match PersonPaste.parse (← str j "text") n with
      | .ok i => ok (importJ i n) | .error e => errJ e),
  ("people.inner", fun j => do return ok (optS (PersonPaste.innerKeyExpression (← str j "text")))),
  ("people.label", fun j => do
    let persons ← listJ (fun kv => do
      let .arr #[a, b] := kv | throw "pair"
      let .str name := b | throw "name"
      return (← hxJ a, name)) (field j "persons")
    let l : PaymentLabeler := { savingsName := ← str j "savings", personScripts := persons, ownScripts := ← listJ hxJ (field j "own") }
    let owned := (j.getObjValAs? Bool "owned").toOption.getD false
    return ok (labelJ (l.label (← bytes j "script") owned))),
  ("bundle.decode", fun j => do
    return match ImportBundle.decode (← str j "json") with
      | .ok b => ok (reportBundleJ b) | .error e => errJ e.name),
  ("bundle.excerpt", fun j => do return ok (Json.str (ImportBundle.excerpt (← str j "text")))),
  ("record.decode", fun j => do
    return match SwiftJSON.decodeText (← str j "json") (SwiftJSON.asArray VaultRecord.ofJV) with
      | .ok rs => ok (Json.arr (rs.map fun r => Json.mkObj [("json", Json.str (SwiftJSON.write r.toJV)),
          ("balance", Json.str (toString r.balance.toInt)), ("live", Json.num r.utxos.size)]))
      | .error e => errJ e)
]

/-! ## Vault flows -/

def masterOf (b : Nat) : IO HDKey := do
  let some m := (BIP39.mnemonic (ByteArray.mk (Array.replicate 16 b.toUInt8))).toOption | throw (IO.userError "mnemonic")
  let some k := (HDKey.ofSeed (BIP39.seed m)).toOption | throw (IO.userError "seed")
  return k

/-- `[fp/86'/c'/0']xpub…` (the `TestVaults` form, per network). -/
def bareExpression (master : HDKey) (network : Tx.BitcoinNetwork) : IO String := do
  let coin := if network == .mainnet then 0 else 1
  let some account := (master.derived s!"m/86'/{coin}'/0'").toOption | throw (IO.userError "account")
  return s!"[{Wallet.hex8 master.fingerprint}/86'/{coin}'/0']{account.neutered.serialized (Wallet.hdNetwork network)}"

structure FlowCtx where
  psbt : PSBT
  saved : Array PSBT := #[]
  nonces : Std.HashMap Nat (Array (ByteArray × ByteArray)) := {}

def coordsJ (v : Json) : Except String (Array Vault.OutputCoordinate) :=
  listJ (fun c => do
    let .arr #[a, b] := c | throw "coordinate"
    return { choice := ← a.getInt?, index := (← b.getNat?).toUInt32 }) v

def reviewJ (r : Vault.SpendReview) : Json :=
  Json.mkObj [("outputs", Json.arr (r.outputs.map fun o => Json.arr #[Json.str (toString o.amount.toInt), hexJ o.scriptPubKey, Json.bool o.isVaultOwned])),
    ("in", Json.str (toString r.inputTotal.toInt)), ("out", Json.str (toString r.outputTotal.toInt)), ("fee", Json.str (toString r.fee.toInt)),
    ("sighash", Json.arr (r.sighashTypes.map (Json.num ·.toNat))), ("version", Json.num r.transactionVersion.toInt),
    ("locktime", Json.num r.fallbackLocktime.toNat), ("sequences", Json.arr (r.sequences.map (Json.num ·.toNat)))]

def contextJ (c : Vault.MuSig2Context) : Json :=
  Json.mkObj [("participants", Json.arr (c.participants.map hexJ)), ("aggregate", hexJ c.aggregate), ("internal", hexJ c.internalKey),
    ("tweaks", Json.arr (c.tweaks.map hexJ)), ("xonly", Json.arr (c.isXOnlyTweaks.map Json.bool)), ("signing", hexJ c.signingKey)]

def liftVM {α} (r : VM α) : ExceptT VaultFailure IO α := ExceptT.mk (pure r)

/-- The MuSig2 context of the coin an input spends (coordinates (0, 0) for an unknown coin). -/
def ctxFor (v : Vault) (coins : Array WalletUTXO) (p : PSBT) (input : Nat) : VM Vault.MuSig2Context := do
  let some u := p.inputs[input]? | throw (VaultFailure.named "indexOutOfRange")
  match coins.find? (fun (c : WalletUTXO) => some c.txid == u.previousTxid && some c.vout == u.outputIndex) with
  | some coin => v.muSig2Context coin.chain.rawValue coin.index
  | none => v.muSig2Context 0 0

def vaultFlow (j : Json) : IO Json := do
  let some network := Tx.BitcoinNetwork.ofString? ((str j "network").toOption.getD "signet") | return err "bad-request: network"
  let mbytes : Array Nat := match field j "masters" with | .arr xs => xs.filterMap (fun (x : Json) => x.getNat?.toOption) | _ => #[]
  let masters ← mbytes.mapM masterOf
  let exprs ← masters.mapM (bareExpression · network)
  -- the descriptor: explicit, or built from the masters
  let text ← match str j "descriptor" with
    | .ok t => pure t
    | .error _ =>
      let k := (j.getObjValAs? Int "k").toOption.getD 2
      match (str j "kind").toOption.getD "sortedmulti_a" with
      | "musig" => pure s!"tr(musig({",".intercalate exprs.toList})/<0;1>/*)"
      | "multi_a" => pure s!"tr({hex Taproot.unspendableInternalKey},multi_a({k},{",".intercalate (exprs.map (· ++ "/<0;1>/*")).toList}))"
      | _ => match Vault.multiADescriptor k (exprs.map (· ++ "/<0;1>/*")) with
        | .ok d => pure d.serialized
        | .error e => return ok (Json.arr #[Json.mkObj [("error", Json.str e.name)]])
  let v ← match Vault.parse text network with
    | .ok v => pure v
    | .error e => return ok (Json.arr #[Json.mkObj [("error", Json.str e.name)]])
  -- coins at descriptor coordinates (or with a given script)
  let coinSpecs := match field j "coins" with | .arr xs => xs | _ => #[]
  let mut coins : Array WalletUTXO := #[]
  for (c, i) in coinSpecs.zipIdx do
    let chain := Oracle.WalletScenario.chainOf ((nat c "chain").toOption.getD 0)
    let index := ((nat c "index").toOption.getD 0).toUInt32
    let script ← match field c "script" with
      | .str _ => match hxJ (field c "script") with | .ok b => pure b | .error _ => return err "bad-request: script"
      | _ => match v.scriptPubKey index chain.rawValue with
        | .ok s => pure s
        | .error e => return ok (Json.arr #[Json.mkObj [("error", Json.str e.name)]])
    let amount ← match i64J (field c "amount") with | .ok a => pure a | .error _ => return err "bad-request: amount"
    coins := coins.push {
      txid := ByteArray.mk (Array.replicate 32 (0x50 + i).toUInt8), vout := ((nat c "vout").toOption.getD 0).toUInt32,
      amount := amount, scriptPubKey := script, chain := chain, index := index,
      height := ((nat c "height").toOption.getD 100).toUInt32,
      isCoinbase := (c.getObjValAs? Bool "coinbase").toOption.getD false }
  let payments ← match listJ paymentJ (field j "payments") with | .ok p => pure p | .error e => return err s!"bad-request: {e}"
  let rate ← match dblJ (field j "rate") with | .ok r => pure r | .error _ => return err "bad-request: rate"
  let draws ← IO.mkRef ((listJ dblJ (field j "draws")).toOption.getD #[]).toList
  let aux ← IO.mkRef (1 : Nat)
  let random : Randomness := { Randomness.system with
    draw := do match ← draws.get with | x :: r => draws.set r; pure x | [] => pure 0.5
    changePosition := fun _ => pure ((nat j "changePos").toOption.getD 0)
    auxRand := do let n ← aux.modifyGet fun n => (n, n + 1); pure (ByteArray.mk (Array.replicate 32 n.toUInt8)) }
  let tip := ((nat j "tip").toOption.getD 840000).toUInt32
  let created ← (v.createSpend coins payments ((nat j "changeIndex").toOption.getD 0).toUInt32 rate tip random).run
  let mut out : Array Json := #[Json.mkObj [("vault", vaultJ v)]]
  let p ← match created with
    | .ok p => pure p
    | .error e => return ok (Json.arr (out.push (Json.mkObj [("error", Json.str e.name)])))
  out := out.push (Json.mkObj [("psbt", Oracle.WalletScenario.psbtShape p)])
  let mut s : FlowCtx := { psbt := p }
  let steps := match field j "steps" with | .arr xs => xs | _ => #[]
  for st in steps do
    let known ← match field st "known" with
      | .arr xs => pure (xs.filterMap (fun (x : Json) => x.getNat?.toOption) |>.filterMap (coins[·]?))
      | _ => pure coins
    let coords ← match coordsJ (field st "owned") with | .ok c => pure c | .error e => return err s!"bad-request: {e}"
    let stTip := ((nat st "tip").toOption.getD tip.toNat).toUInt32
    let master := (nat st "master").toOption.bind (masters[·]?)
    let input := (nat st "input").toOption.getD 0
    let reply (r : Except VaultFailure (FlowCtx × List (String × Json))) : Json × FlowCtx :=
      match r with
      | .ok (s', extra) => (Json.mkObj (extra ++ [("psbt", Oracle.WalletScenario.psbtShape s'.psbt)]), s')
      | .error e => (Json.mkObj [("error", Json.str e.name)], s)
    let (o, s') ← match (str st "role").toOption.getD "" with
      | "review" => pure (reply do
          let r ← v.reviewSpend s.psbt known coords stTip
          return (s, [("review", reviewJ r)]))
      | "partialSign" =>
        let some m := master | return err "bad-request: master"
        pure (reply (← (do
          let q ← v.partialSign s.psbt m known coords stTip random.auxRand
          return ({ s with psbt := q }, [])).run))
      | "signers" => pure (reply do
          let xs ← v.signers s.psbt known
          return (s, [("signers", Json.arr ((xs.qsort (· < ·)).map fun (n : Nat) => toJson n))]))
      | "context" => pure (reply do
          let c ← v.muSig2Context ((nat st "choice").toOption.getD 0) ((nat st "index").toOption.getD 0).toUInt32
          return (s, [("context", contextJ c)]))
      | "sighash" => pure (reply do
          let h ← Vault.keyPathSighash s.psbt input
          return (s, [("sighash", hexJ h)]))
      | "nonce" =>
        let some m := master | return err "bad-request: master"
        let mi := (nat st "master").toOption.getD 0
        pure (reply (← (do
          let c ← liftVM (ctxFor v coins s.psbt input)
          let (q, secrets) ← v.muSig2AttachNonce s.psbt input c m known coords stTip random.nonceRand
          return ({ s with psbt := q, nonces := s.nonces.insert (mi * 1000 + input) secrets }, [])).run))
      | "sign" =>
        let some m := master | return err "bad-request: master"
        let mi := (nat st "master").toOption.getD 0
        pure (reply do
          let c ← ctxFor v coins s.psbt input
          let (q, zeroed) ← v.muSig2Sign s.psbt input c m ((s.nonces[mi * 1000 + input]?).getD #[]) known coords stTip
          return ({ s with psbt := q, nonces := s.nonces.insert (mi * 1000 + input) zeroed }, []))
      | "aggregate" => pure (reply do
          let c ← ctxFor v coins s.psbt input
          return ({ s with psbt := ← v.muSig2Aggregate s.psbt input c known coords stTip }, []))
      | "finalize" => pure (reply do
          let (q, tx) ← v.finalizeSpend s.psbt known coords stTip
          return ({ s with psbt := q }, [("tx", Oracle.WalletScenario.unsignedHex tx), ("witness", Oracle.WalletScenario.witnessShape tx)]))
      | "save" => pure (reply (pure ({ s with saved := s.saved.push s.psbt }, [])))
      | "restore" => pure (reply (pure ({ s with psbt := s.saved[(nat st "n").toOption.getD 0]?.getD s.psbt }, [])))
      | "combine" =>
        let ns := (listJ (fun x => x.getNat?) (field st "with")).toOption.getD #[]
        pure (reply do
          let q ← VM.lift (·.name) (s.psbt.combined (ns.filterMap (s.saved[·]?)))
          return ({ s with psbt := q }, []))
      | "editInput" =>
        let k := input
        if k ≥ s.psbt.inputs.size then pure (Json.mkObj [("error", Json.str "indexOutOfRange")], s) else
        match editPairs (s.psbt.inputs[k]?.map (·.pairs) |>.getD #[]) st with
        | .ok ps => pure (reply (pure ({ s with psbt := { s.psbt with inputs := s.psbt.inputs.modify k fun _ => ⟨ps⟩ } }, [])))
        | .error e => return err s!"bad-request: {e}"
      | "editOutput" =>
        let k := (nat st "output").toOption.getD 0
        if k ≥ s.psbt.outputs.size then pure (Json.mkObj [("error", Json.str "indexOutOfRange")], s) else
        match editPairs (s.psbt.outputs[k]?.map (·.pairs) |>.getD #[]) st with
        | .ok ps => pure (reply (pure ({ s with psbt := { s.psbt with outputs := s.psbt.outputs.modify k fun _ => ⟨ps⟩ } }, [])))
        | .error e => return err s!"bad-request: {e}"
      | "approval" => pure (reply do
          let r := ApprovalRequest.make network (some "vault-id") (some "Savings") s.psbt
          let back ← (ApprovalRequest.decode r.serialized network).mapError VaultFailure.named
          let q ← back.decodedPSBT.mapError VaultFailure.named
          return ({ s with psbt := q }, [("roundTrip", Json.bool (q.serialized == s.psbt.serialized))]))
      | r => return err s!"bad-request: role {r}"
    s := s'
    out := out.push o
  return ok (Json.arr out)

def ioOps : List (String × (Json → IO Json)) := [("vault.flow", vaultFlow)]

end Oracle.WalletPeople
