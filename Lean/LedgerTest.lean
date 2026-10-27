import Winnow.Ledger
open Winnow Winnow.Ledger Winnow.Keys Winnow.SwiftJSON

/-! `ledger-test`: the Ledger signer's tests (Phase C).

Ports `Tests/WalletCoreTests/LedgerTests.swift` (upstream 1cf93fb) where it does not need
`MultisigAccount`, and checks the port against Swift itself through recorded sessions:

* `Vectors/ledger-bitcoin-app.json` — Ledger's own vectors (policy ids, Taproot addresses), copied
  unchanged from upstream's `Tests/WalletCoreTests/Vectors` (provenance in its README there).
* `Vectors/ledger-sessions.json` — whole sessions recorded from the Swift at 1cf93fb: Swift's
  `LedgerBitcoinClient`/`LedgerMultisig` against Swift's `LedgerSimulator`, every APDU and reply in
  order, for a 2-of-2 (pair, register, show an address, the Ledger signs a two-input spend, a
  refusal on the device, a mainnet key request) and a 2-of-3 with a recovery leaf. Recorded by
  `Vectors/ledger-sessions-recorder.swift.txt` (a swift-testing file added to a scratch copy of the
  Swift checkout, run with `LEDGER_RECORD_OUT=… swift test --filter LedgerRecordTests`).

  - client replay: the Lean client must send byte-identical APDUs and reach the same results and
    signed PSBT from the recorded replies;
  - simulator replay: the Lean simulator, fed the recorded APDUs, must answer byte-identical replies;
  - live: the Lean client against the Lean simulator.

Usage: `lake exe ledger-test [vectors directory]` (default `Vectors`, run from `Lean/`). -/

initialize failures : IO.Ref (Array String) ← IO.mkRef #[]
initialize passes : IO.Ref Nat ← IO.mkRef 0

def say (s : String) : IO Unit := do IO.println s; (← IO.getStdout).flush

def check (name : String) (cond : Bool) (detail : String := "") : IO Unit := do
  if cond then
    passes.modify (· + 1)
  else
    failures.modify (·.push name)
    say s!"  FAIL {name}{if detail.isEmpty then "" else " — " ++ detail}"

def h (s : String) : ByteArray := ofHex! s
def bytes (xs : List Nat) : ByteArray := ByteArray.mk (xs.map (·.toUInt8)).toArray

def isErr {α ε} : Except ε α → Bool | .error _ => true | .ok _ => false
def errName {α} : Except LedgerError α → String | .error e => e.name | .ok _ => "ok"

/-! ## JSON access -/

def field (v : JV) (k : String) : JV := match v with
  | .obj kvs => (lookup kvs k).getD .null
  | _ => .null
def str (v : JV) : String := match v with | .str s => s | _ => ""
def num (v : JV) : Nat := match v with | .num t => t.toNat?.getD 0 | _ => 0
def arr (v : JV) : Array JV := match v with | .arr xs => xs | _ => #[]
def strs (v : JV) : Array String := (arr v).map str
def steps (v : JV) : Array (ByteArray × ByteArray) :=
  (arr (field v "exchanges")).map fun e => let xs := arr e; (h (str xs[0]!), h (str xs[1]!))

/-! ## Transports -/

/-- Over the Lean simulator, as a state. -/
abbrev SimM := StateT Simulator (Except LedgerError)

def simExchange (apdu : ByteArray) : SimM ByteArray :=
  modifyGet fun s => let (s', reply) := s.exchange apdu; (reply, s')

def runSim {α} (p : Program α) (s : Simulator) : Except LedgerError (α × Simulator) := (p.run simExchange).run s

/-- Over a recording: each APDU must be the recorded one; the recorded reply comes back. -/
abbrev ReplayM := ExceptT LedgerError (StateM (Array (ByteArray × ByteArray) × Nat))

def replayExchange (apdu : ByteArray) : ReplayM ByteArray := do
  let (log, i) ← get
  let some (expected, reply) := log[i]? | throw (.transport s!"replay: APDU {i} past the recording")
  unless apdu == expected do throw (.transport s!"replay: APDU {i} differs: {hex apdu} vs {hex expected}")
  set (log, i + 1)
  return reply

/-- Runs `p` against a recording; the result, and whether every recorded exchange was used. -/
def replay {α} (p : Program α) (log : Array (ByteArray × ByteArray)) : Except LedgerError α × Bool :=
  let (r, (_, used)) := ((p.run replayExchange).run).run (log, 0)
  (r, used == log.size)

/-- Feeds recorded APDUs to the simulator; the index of the first reply that differs, if any. -/
def replaySimulator (s : Simulator) (log : Array (ByteArray × ByteArray)) : Simulator × Option Nat := Id.run do
  let mut s := s
  for h : i in [0:log.size] do
    let (apdu, reply) := log[i]
    let (s', got) := s.exchange apdu
    s := s'
    if got != reply then return (s, some i)
  return (s, none)

/-! ## Fixtures -/

/-- `TestKeys.master(entropyByte:)`: an HD master from a repeated one-byte 16-byte entropy, via BIP39. -/
def master (byte : UInt8) : HDKey :=
  match BIP39.mnemonic (ByteArray.mk (Array.replicate 16 byte)) with
  | .ok words => (HDKey.ofSeed (BIP39.seed words)).toOption.get!
  | .error _ => default

def masters : Array HDKey := #[master 0xA1, master 0xB2, master 0xC3]

def get! {α} [Inhabited α] (e : Except LedgerError α) : α := match e with | .ok a => a | .error _ => default

/-- The template with each `@i/**` replaced by its key and `/<0;1>/*` (LedgerTests.descriptor). -/
def templateDescriptor (template : String) (keys : Array String) : String := Id.run do
  let mut text := template
  for index in (List.range keys.size).reverse do
    text := (text.replace s!"@{index}/**" (keys[index]! ++ "/<0;1>/*")).replace s!"@{index}/<" (keys[index]! ++ "/<")
  return text

/-- A key expression as a descriptor key (via `tr(KEY)`). -/
def singleKey (text : String) : Descriptor.SingleKey :=
  match Descriptor.parse s!"tr({text})" with
  | .ok { expression := .tr k _ } => k
  | _ => default

/-! ## Ledger's published vectors -/

def vectorTests (dir : String) : IO Unit := do
  say "ledger's vectors"
  let some v := parse? (← IO.FS.readFile s!"{dir}/ledger-bitcoin-app.json") | check "vectors parse" false; return
  let registers := arr (field v "register")
  check "at least 10 register vectors" (registers.size ≥ 10) s!"{registers.size}"
  for r in registers do
    let policy := WalletPolicy.make (str (field r "walletName")) (str (field r "template")) (strs (field r "keys"))
    check s!"policy id {str (field r "name")}" ((policy.map (hex ·.id)).toOption == some (str (field r "walletID")))
  let addresses := arr (field v "addresses")
  check "an address vector uses sortedmulti_a" (addresses.any fun a => ((str (field a "template")).splitOn "sortedmulti_a").length > 1)
  for a in addresses do
    let text := templateDescriptor (str (field a "template")) (strs (field a "keys"))
    let derived := (Descriptor.parse text).toOption.bind fun d =>
      ((d.derived (num (field a "index")).toUInt32 .signet).toOption.bind (·[num (field a "change")]?)).map (·.address)
    check s!"address {str (field a "name")}" (derived == some (str (field a "address"))) s!"{derived}"
  say s!"  {registers.size} policy ids, {addresses.size} addresses"

/-! ## Merkle, framing, interpreter -/

def merkleTests : IO Unit := do
  say "merkle"
  let expected := #[
    "0000000000000000000000000000000000000000000000000000000000000000",
    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
    "a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a",
    "3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688",
    "9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb",
    "b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f",
    "bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8",
    "3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3",
    "ef7f49b620f6c7ea9b963a214da34b5021c6ded8ed57734380a311ab726aa907",
    "162a21c2230e0284ea38cb8739ee4bb75947a1acd5d529c638ec068969fb3c4a"]
  for count in [0:expected.size] do
    let leaves := (Array.range count).map fun i => Merkle.elementHash (bytes [i])
    check s!"root of {count} leaves" (hex (Merkle.root leaves) == expected[count]!)
  let seven := (Array.range 7).map fun i => Merkle.elementHash (bytes [i])
  check "proof of leaf 5 of 7" ((Merkle.proof seven 5).map hex == #[
    "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
    "40d88127d4d31a3891f41598eeed41174e5bc89b1eb9bbd66a8cbfc09956a3fd",
    "9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb"])
  -- Every proof of every tree up to 40 leaves recomputes the root (the simulator's checker).
  let mut ok := true
  for n in [1:41] do
    let leaves := (Array.range n).map fun i => Merkle.elementHash (bytes [i])
    for i in [0:n] do
      if Simulator.rootOf leaves[i]! i n (Merkle.proof leaves i).toList.reverse != some (Merkle.root leaves) then ok := false
  check "proofs recompute their roots, 1 to 40 leaves" ok

def framingTests : IO Unit := do
  say "framing"
  for length in [5, 15, 16, 17, 150, 260] do
    let apdu := ByteArray.mk ((Array.range length).map (·.toUInt8))
    for frameSize in [20, 23, 156] do
      match BluetoothFraming.frames apdu frameSize with
      | .error _ => check s!"frames {length}/{frameSize}" false
      | .ok frames =>
        check s!"frame sizes {length}/{frameSize}" (frames.all fun f => f.size ≤ frameSize && f[0]! == 0x05)
        let mut r : BluetoothFraming.Reassembler := {}
        let mut reply : Option ByteArray := none
        for f in frames do
          match r.receive f with
          | .ok (r', out) => r := r'; reply := out
          | .error _ => reply := none
        check s!"round trip {length} bytes in {frameSize}-byte frames" (reply == some apdu)
  let frames := get! (BluetoothFraming.frames (ByteArray.mk (Array.replicate 100 7)) 20)
  let r1 := get! ((({} : BluetoothFraming.Reassembler).receive frames[0]!).map (·.1))
  check "a frame out of sequence is refused" (isErr (r1.receive frames[2]!))
  check "MTU reply 153" (BluetoothFraming.frameSize? (bytes [0x08, 0, 0, 0, 1, 153]) == some 153)
  check "not an MTU reply" (BluetoothFraming.frameSize? (bytes [0x05, 0, 0, 0, 1, 153]) == none)
  -- Beyond the Swift test: exact frames, an empty APDU, refusals.
  check "two frames of a 20-byte APDU at 20" ((get! (BluetoothFraming.frames (ByteArray.mk (Array.replicate 20 1)) 20)).map hex ==
    #["0500000014" ++ String.join (List.replicate 15 "01"), "050001" ++ String.join (List.replicate 5 "01")])
  check "an empty APDU is one frame" ((get! (BluetoothFraming.frames .empty 20)).map hex == #["0500000000"])
  check "frame size 5 is refused" (isErr (BluetoothFraming.frames (bytes [1]) 5))
  check "a frame without the tag" (isErr (({} : BluetoothFraming.Reassembler).receive (bytes [0x06, 0, 0, 0, 1, 9])))
  check "a first frame without a length" (isErr (({} : BluetoothFraming.Reassembler).receive (bytes [0x05, 0, 0, 0])))
  check "write frame size is capped" (Bluetooth.writeFrameSize 153 (some 100) == 100 && Bluetooth.writeFrameSize 153 none == 153)
  check "notify characteristic" (Bluetooth.notifyCharacteristic Bluetooth.serviceIdentifiers[0]! == "13D63400-2C97-0004-0001-4C6564676572")
  check "write characteristic" (Bluetooth.writeCharacteristic Bluetooth.serviceIdentifiers[1]! == "13D63400-2C97-6004-0002-4C6564676572")
  let router : Bluetooth.NotificationRouter := {}
  check "router: MTU reply while asking for the frame size"
    ((router.receive (bytes [0x08, 0, 0, 0, 1, 153]) (some .frameSize)).2.map (·.toOption) == some (some (bytes [0x08, 0, 0, 0, 1, 153])))
  check "router: other notifications are ignored" ((router.receive (bytes [0x05, 0, 0]) (some .written)).2.isNone)
  let replyFrames := get! (BluetoothFraming.frames (bytes [0x90, 0x00]) 20)
  check "router: a reply while awaiting one"
    ((router.receive replyFrames[0]! (some .reply)).2.map (·.toOption) == some (some (bytes [0x90, 0x00])))

def interpreterTests : IO Unit := do
  say "interpreter"
  let long := ByteArray.mk ((Array.range 300).map (·.toUInt8))
  let mut i := ({} : Interpreter).addKnownPreimage long
  let (i1, first) := get! (i.execute (bytes [0x40, 0x00] ++ sha256 long))
  i := i1
  let firstParsed := (do
    let total ← Reader.compact
    let n ← Reader.u8
    return (total, ← Reader.bytes n.toNat) : Reader _).run first
  let (total, chunk) := match firstParsed with | .ok (r, _) => r | .error _ => (0, .empty)
  check "preimage length 300" (total == 300)
  let mut received := chunk
  let mut rounds := 0
  let mut allOneByte := true
  while received.size < 300 && rounds < 10 do
    rounds := rounds + 1
    let (i2, more) := get! (i.execute (bytes [0xA0]))
    i := i2
    if more.size < 2 then break
    if more[1]! != 1 then allOneByte := false
    received := received ++ more.extract 2 (2 + more[0]!.toNat)
  check "long preimage over GET_MORE_ELEMENTS" (received == long && allOneByte)

  let elements := (Array.range 200).map fun k => s!"key {k}".toUTF8
  i := i.addKnownList elements
  let leaves := elements.map Merkle.elementHash
  let root := Merkle.root leaves
  let (i3, proofReply) := get! (i.execute (bytes [0x41] ++ root ++ bytes [0xC8, 0x9B]))
  i := i3
  check "leaf 155 of 200" (proofReply.extract 0 32 == leaves[155]!)
  check "proof length and six sent" (proofReply[32]!.toNat == (Merkle.proof leaves 155).size && proofReply[33]! == 6)
  check "a request before the queue is drained is refused" (isErr (i.execute (bytes [0x40, 0x00] ++ ByteArray.mk (Array.replicate 32 0))))
  for _ in [0:10] do
    let (i4, more) := get! (i.execute (bytes [0xA0]))
    i := i4
    if more[0]!.toNat < 7 then break
  check "leaf index 42" ((i.execute (bytes [0x42] ++ root ++ leaves[42]!)).toOption.map (hex ·.2) == some "012a")
  check "leaf not found" ((i.execute (bytes [0x42] ++ root ++ ByteArray.mk (Array.replicate 32 0))).toOption.map (hex ·.2) == some "0000")
  check "leaf search in an unknown tree" (isErr (i.execute (bytes [0x42] ++ ByteArray.mk (Array.replicate 64 0))))

  let fresh : Interpreter := {}
  check "unknown preimage" (errName (fresh.execute (bytes [0x40, 0x00] ++ ByteArray.mk (Array.replicate 32 0))) == "protocolViolation")
  check "unknown tree" (isErr (fresh.execute (bytes [0x41] ++ root ++ bytes [0xC8, 0x00])))
  check "unknown command" (isErr (fresh.execute (bytes [0x99])))
  match fresh.execute (bytes [0x10, 0x01, 0x02]) with
  | .ok (y, reply) => check "yield" (reply.isEmpty && y.yielded.map hex == #["0102"])
  | .error _ => check "yield" false
  -- Beyond the Swift test: malformed and unsupported requests, by message.
  let msg {α} : Except LedgerError α → String | .error (.protocolViolation m) => m | _ => ""
  check "empty request" (msg (fresh.execute .empty) == "an unknown client command")
  check "short preimage request" (msg (fresh.execute (bytes [0x40])) == "a malformed client command")
  check "unsupported preimage request" (msg (fresh.execute (bytes [0x40, 0x01])) == "an unsupported preimage request")
  check "trailing bytes" (msg (fresh.execute (bytes [0x40, 0x00] ++ ByteArray.mk (Array.replicate 33 0))) == "a malformed client command")
  check "more elements with nothing queued" (msg (fresh.execute (bytes [0xA0])) == "a request for elements that were never queued")
  check "non-canonical size" (msg (fresh.execute (bytes [0x41] ++ root ++ bytes [0xFD, 0xC8, 0x00, 0x00])) == "a malformed client command")

/-! ## Errors, yields, the program, the registration record -/

def unitTests : IO Unit := do
  say "errors, yields, programs"
  check "status words" ([0x6985, 0x5515, 0x6E00, 0x6E01, 0x6D00, 0x6D02, 0x6511, 0x6A82].map (fun w => (LedgerError.ofStatus w).name) ==
    ["rejectedOnDevice", "deviceLocked", "appNotOpen", "appNotOpen", "appNotOpen", "appNotOpen", "appNotOpen", "status"])
  check "status description" ((LedgerError.status 0x6a82).description == "The Ledger refused the request (status 6A82).")
  check "short reply" (errName (Response.parse (bytes [0x90])) == "transport")
  check "overlong APDU" (errName (APDU.bitcoin .signPSBT (ByteArray.mk (Array.replicate 256 0))).serialized == "protocolViolation")
  check "APDU bytes" ((APDU.bitcoin .getMasterFingerprint).serialized.toOption.map hex == some "e105000100")
  let key := ByteArray.mk (Array.replicate 32 2)
  let leaf := ByteArray.mk (Array.replicate 32 3)
  let sig := ByteArray.mk (Array.replicate 64 4)
  check "a script-path yield" ((Client.signatureOfYield (bytes [1, 64] ++ key ++ leaf ++ sig) 2).toOption ==
    some (some { inputIndex := 1, publicKey := key, leafHash := some leaf, signature := sig }))
  check "a key-path yield" ((Client.signatureOfYield (bytes [0, 32] ++ key ++ sig) 1).toOption ==
    some (some { inputIndex := 0, publicKey := key, leafHash := none, signature := sig }))
  check "a MuSig2 yield is skipped" ((Client.signatureOfYield (bytes [0xFE, 0, 0, 0, 0x80, 1, 2]) 1).toOption == some none)
  check "an input that does not exist" (errName (Client.signatureOfYield (bytes [2, 32] ++ key ++ sig) 2) == "protocolViolation")
  check "a signature of the wrong length" (errName (Client.signatureOfYield (bytes [0, 32] ++ key ++ bytes [1, 2, 3]) 1) == "protocolViolation")
  check "a key of the wrong length" (errName (Client.signatureOfYield (bytes [0, 31] ++ key.extract 0 31 ++ sig) 1) == "protocolViolation")
  check "a malformed yield" (errName (Client.signatureOfYield (bytes [0, 40] ++ key) 1) == "protocolViolation")
  check "names" (WalletPolicy.isValidName "Savings" &&
    ["", " leading", "trailing ", String.ofList (List.replicate 65 'x'), "café"].all (!WalletPolicy.isValidName ·))
  check "a policy needs keys" (errName (WalletPolicy.make "A" "tr(@0/**)" #[]) == "mismatch")
  let r : Registration :=
    { policyName := "Winnow 2-of-2"
      policyID := ByteArray.mk (Array.replicate 32 1)
      hmac := ByteArray.mk (Array.replicate 32 2)
      masterFingerprint := 0x08914939
      keyPath := Multisig.keyPath .signet }
  check "registration JSON round trip" ((Registration.ofJV r.toJV).toOption == some r)
  -- The step interface gives what `run` gives.
  let sim := Simulator.new masters[1]!
  let mut p := Client.masterFingerprint
  let mut s := sim
  let mut sent := 0
  while sent < 5 do
    let some apdu := p.pending? | break
    let (s', reply) := s.exchange apdu
    s := s'
    p := p.feed reply
    sent := sent + 1
  check "step interface" (sent == 1 && (match p with | .done fp => fp == masters[1]!.fingerprint | _ => false))

/-! ## Recorded Swift sessions -/

def sessionTests (dir : String) : IO Unit := do
  let some v := parse? (← IO.FS.readFile s!"{dir}/ledger-sessions.json") | check "sessions parse" false; return
  -- 2-of-2
  say "swift sessions: 2-of-2"
  let c := field v "twoOfTwo"
  let name := "Winnow 2-of-2"
  let template := str (field c "template")
  let keys := strs (field c "keys")
  let expression := str (field (field c "signerExpression") "expression")
  let fingerprint := (num (field (field c "signerExpression") "fingerprint")).toUInt32
  -- The policy from the account's descriptor, as LedgerWalletPolicy(name:account:) builds it.
  let descriptor := (Descriptor.parse (str (field c "descriptor"))).toOption
  let fromDescriptor := descriptor.bind fun d => (WalletPolicy.ofDescriptor name d).toOption
  check "policy from the account descriptor" (fromDescriptor.map (fun p => (p.template, p.keys)) == some (template, keys))
  let some policy := fromDescriptor | return
  check "policy id" (hex policy.id == str (field c "policyId"))
  let firstAddress := str (field c "firstAddress")
  check "the descriptor's first address" ((descriptor.bind fun d => (d.derived 0 .signet).toOption.bind (·[0]?)).map (·.address) == some firstAddress)
  let makePolicy := fun n => WalletPolicy.make n template keys

  let (r1, used1) := replay (Multisig.signerExpression .signet) (steps (field c "signerExpression"))
  check "client replay: signer expression" (r1.toOption == some (expression, fingerprint) && used1) s!"{errName r1}"
  let path := Multisig.keyPath .signet
  let signers := match descriptor with
    | some { expression := .tr _ (some (.leaf (.sortedMultiA _ ks))) } => ks
    | _ => #[]
  check "the account has a signer for this Ledger" (Multisig.ledgerSigner signers fingerprint path).isSome
  let (r2, used2) := replay (Multisig.register signers .signet makePolicy name fingerprint firstAddress) (steps (field c "register"))
  let hmac := h (str (field (field c "register") "hmac"))
  check "client replay: register" ((r2.toOption.map fun r => (hex r.policyID, r.hmac, r.policyName, r.keyPath)) ==
    some (str (field c "policyId"), hmac, name, path) && used2) s!"{errName r2}"
  let registration := get! r2
  let d := field c "display"
  let (r3, used3) := replay (Multisig.displayAddress makePolicy registration (num (field d "choice")) (num (field d "index")).toUInt32
    (str (field d "address"))) (steps d)
  check "client replay: display address" (r3.toOption == some (str (field d "address")) && used3) s!"{errName r3}"
  let sf := field c "signFirst"
  let unsigned := (PSBT.parse (h (str (field sf "psbt")))).toOption.get!
  let (r4, used4) := replay (Multisig.sign unsigned makePolicy registration) (steps sf)
  check "client replay: sign" used4 s!"{errName r4}"
  match r4 with
  | .ok (.ok (signed, added)) =>
    check "the Ledger's two signatures are applied as Swift applies them"
      (hex signed.serialized == str (field sf "signed") && added == num (field sf "added"))
  | _ => check "the Ledger's signatures verify" false
  let rj := field c "reject"
  let (r5, used5) := replay (Multisig.sign unsigned makePolicy registration) (steps rj)
  check "client replay: refused on the device" (errName r5 == "rejectedOnDevice" && used5) s!"{match r5 with | .error e => toString e | _ => "ok"} {used5}"
  let (r6, used6) := replay (Multisig.signerExpression .mainnet) (steps (field c "mainnet"))
  check "client replay: a mainnet key request" ((match r6 with | .error (.status 0x6A82) => true | _ => false) && used6) s!"{match r6 with | .error e => toString e | _ => "ok"} {used6}"

  -- The same recordings into the Lean simulator.
  let mut s := Simulator.new masters[1]!
  for (label, log) in [("signer expression", steps (field c "signerExpression")), ("register", steps (field c "register")),
      ("display", steps d), ("sign", steps sf)] do
    let (s', bad) := replaySimulator s log
    s := s'
    check s!"simulator replay: {label} ({log.size} exchanges)" bad.isNone s!"first difference at {bad}"
  s := s.setDecision .reject
  let (s', bad) := replaySimulator s (steps rj)
  check "simulator replay: refused on the device" bad.isNone s!"first difference at {bad}"
  s := s'.setDecision .approve
  let (s', bad) := replaySimulator s (steps (field c "mainnet"))
  check "simulator replay: a mainnet key request" bad.isNone
  check "simulator state" (s'.registeredNames == #[name] && s'.displayedAddresses == #[str (field d "address")])

  -- Live: the Lean client against the Lean simulator.
  say "live: Lean client and Lean simulator"
  let sim := Simulator.new masters[1]!
  match runSim (Multisig.signerExpression .signet) sim with
  | .error e => check "live: signer expression" false e.name
  | .ok ((expr, fp), sim) =>
    check "live: signer expression" (expr == expression && fp == masters[1]!.fingerprint &&
      expr.startsWith s!"[{Descriptor.hex8 masters[1]!.fingerprint}/87'/1'/0']tpub")
    match runSim (Multisig.register signers .signet makePolicy name fp firstAddress) sim with
    | .error e => check "live: register" false e.name
    | .ok (reg, sim) =>
      check "live: register" (reg.policyID == policy.id && sim.registeredNames == #[name])
      let expected4 := (descriptor.bind fun d => (d.derived 4 .signet).toOption.bind (·[0]?)).map (·.address)
      match runSim (Multisig.displayAddress makePolicy reg 0 4 (expected4.getD "")) sim with
      | .error e => check "live: display" false e.name
      | .ok (shown, sim) =>
        check "live: display" (some shown == expected4 && sim.displayedAddresses == #[shown])
        match runSim (Multisig.sign unsigned makePolicy reg) sim with
        | .ok (.ok (signed, added), sim) =>
          check "live: the Ledger signs both inputs" (added == 2 && hex signed.serialized == str (field sf "signed"))
          -- Signing again adds nothing.
          match runSim (Multisig.sign signed makePolicy reg) sim with
          | .ok (.error (.ledger (.mismatch m)), _) => check "live: a second signing adds nothing" (m == "the Ledger added no signature")
          | _ => check "live: a second signing adds nothing" false
        | _ => check "live: the Ledger signs both inputs" false
        -- Refusals leave the PSBT alone (the caller keeps it).
        match runSim (Multisig.sign unsigned makePolicy reg) (sim.setDecision .reject) with
        | .error .rejectedOnDevice => check "live: refused on the device" true
        | _ => check "live: refused on the device" false
        let other := { reg with policyName := "Another account" }
        check "live: another account's registration" (match runSim (Multisig.sign unsigned makePolicy other) sim with
          | .error (.mismatch _) => true | _ => false)
        -- A device that flips one bit in every yielded signature.
        let tamper : ByteArray → SimM ByteArray := fun apdu => do
          let reply ← simExchange apdu
          if reply.size > 70 && reply[0]! == 0x10 && reply[reply.size - 2]! == 0xE0 && reply[reply.size - 1]! == 0x00 then
            return reply.set! (reply.size - 3) (reply[reply.size - 3]! ^^^ 0x01)
          return reply
        match ((Multisig.sign unsigned makePolicy reg).run tamper).run sim with
        | .ok (.error (.ledger (.mismatch m)), _) => check "live: a bad signature is refused" (m == "a Ledger signature does not verify")
        | _ => check "live: a bad signature is refused" false
        match runSim (Multisig.displayAddress makePolicy reg 0 5 (expected4.getD "")) sim with
        | .error (.mismatch m) => check "live: a different address is refused" (m == "the Ledger shows a different address")
        | _ => check "live: a different address is refused" false
  check "live: a mainnet key is refused" (isErr (runSim (Multisig.signerExpression .mainnet) (Simulator.new masters[1]!)))
  check "live: an account without this Ledger" (match runSim (Multisig.register #[] .signet makePolicy name fingerprint firstAddress)
    (Simulator.new masters[1]!) with | .error (.mismatch m) => m == "this account has no signer for this Ledger" | _ => false)
  check "live: a wrong first address" (match runSim (Multisig.register signers .signet makePolicy name fingerprint "tb1q")
    (Simulator.new masters[1]!) with | .error (.mismatch m) => m == "the Ledger derives a different first address" | _ => false)

  -- 2-of-3 with a recovery leaf.
  say "swift sessions: 2-of-3 with recovery"
  let c := field v "twoOfThreeRecovery"
  let name := "Family 2-of-3"
  let template := str (field c "template")
  let keys := strs (field c "keys")
  check "the recovery template" (template ==
    "tr(@0/**,{sortedmulti_a(2,@1/**,@2/**,@3/**),and_v(v:multi_a(1,@1/<2;3>/*,@2/<2;3>/*,@3/<2;3>/*),older(10))})" && keys.size == 4)
  -- The tree as the account holds it: its signers on /<0;1>/* and again on /<2;3>/* in the recovery leaf.
  let signerKeys := (keys.extract 1 4).map fun k => singleKey (k ++ "/<0;1>/*")
  let recoveryKeys := (keys.extract 1 4).map fun k => singleKey (k ++ "/<2;3>/*")
  let tree := AccountTree.branch (.leaf (.sortedMultiA 2 signerKeys)) (.leaf (.timelockedMultiA 1 recoveryKeys 10))
  let fromTree := WalletPolicy.ofTree name (singleKey (keys[0]! ++ "/<0;1>/*")) tree
  check "policy from the account tree" ((fromTree.toOption.map fun p => (p.template, p.keys, hex p.id)) ==
    some (template, keys, str (field c "policyId")))
  check "timelocked pk leaf" ((WalletPolicy.ofTree name (singleKey (keys[0]! ++ "/<0;1>/*"))
    (.branch (.leaf (.multiA 1 (signerKeys.extract 0 2))) (.leaf (.timelockedPk recoveryKeys[2]! 144)))).toOption.map (·.template) ==
    some "tr(@0/**,{multi_a(1,@1/**,@2/**),and_v(v:pk(@3/<2;3>/*),older(144))})")
  check "a three-leaf tree is refused" (errName (WalletPolicy.ofTree name (singleKey (keys[0]! ++ "/<0;1>/*"))
    (.branch (.leaf (.multiA 1 signerKeys)) (.branch (.leaf (.multiA 1 signerKeys)) (.leaf (.multiA 1 signerKeys))))) == "mismatch")
  check "a plain pk leaf is refused" (errName (WalletPolicy.ofTree name (singleKey (keys[0]! ++ "/<0;1>/*")) (.leaf (.pk signerKeys[0]!))) == "mismatch")
  check "a key under another suffix is refused" (errName (WalletPolicy.ofTree name (singleKey (keys[0]! ++ "/0/*"))
    (.leaf (.multiA 1 signerKeys))) == "mismatch")
  let makePolicy := fun n => WalletPolicy.make n template keys
  let expression := str (field (field c "signerExpression") "expression")
  let fingerprint := (num (field (field c "signerExpression") "fingerprint")).toUInt32
  let (r1, used1) := replay (Multisig.signerExpression .signet) (steps (field c "signerExpression"))
  check "client replay: signer expression" (r1.toOption == some (expression, fingerprint) && used1)
  let (r2, used2) := replay (Multisig.register signerKeys .signet makePolicy name fingerprint
    (str (field c "firstAddress"))) (steps (field c "register"))
  check "client replay: register" ((r2.toOption.map (hex ·.hmac)) == some (str (field (field c "register") "hmac")) && used2) s!"{errName r2}"
  let registration := get! r2
  let d := field c "display"
  let (r3, used3) := replay (Multisig.displayAddress makePolicy registration (num (field d "choice")) (num (field d "index")).toUInt32
    (str (field d "address"))) (steps d)
  check "client replay: display a change address" (r3.toOption == some (str (field d "address")) && used3) s!"{errName r3}"
  let sf := field c "signFirst"
  let unsigned := (PSBT.parse (h (str (field sf "psbt")))).toOption.get!
  -- Applying recovery-leaf signatures needs Phase B's leaf policies; the exchange itself is checked.
  let (r4, used4) := replay (do
    let p ← Program.ofExcept (Multisig.policy makePolicy registration)
    Client.signPSBT unsigned p registration.hmac) (steps sf)
  check "client replay: sign on the recovery path (two yielded signatures)" ((r4.toOption.map (·.size)) == some 2 && used4) s!"{errName r4}"
  -- Only up to the registration's reply: `LedgerMultisig.register` then asks for the first address,
  -- which the simulator derives through a descriptor with the recovery leaf (Phase B).
  let registerLog := steps (field c "register")
  let registered := (registerLog.findIdx? fun (_, reply) => reply.size ≥ 2 && reply[reply.size - 2]! == 0x90).getD 0
  let mut s3 := Simulator.new masters[1]!
  for (label, log) in [("signer expression", steps (field c "signerExpression")),
      (s!"registration ({registered + 1} of {registerLog.size} exchanges)", registerLog.extract 0 (registered + 1))] do
    let (s', bad) := replaySimulator s3 log
    s3 := s'
    check s!"simulator replay: {label}" bad.isNone s!"first difference at {bad}"

def ioTests : IO Unit := do
  say "IO transport"
  let ref ← IO.mkRef (Simulator.new masters[1]!)
  let r ← (Multisig.signerExpression .signet |>.runIO (Simulator.transport ref)).run
  check "runIO over the shared simulator" ((r.toOption.map (·.2)) == some masters[1]!.fingerprint)
  let r ← (Multisig.signerExpression .mainnet |>.runIO (Simulator.transport ref)).run
  check "runIO returns the device's refusal" (match r with | .error (.status 0x6A82) => true | _ => false)

def main (args : List String) : IO UInt32 := do
  let dir := args.headD "Vectors"
  ioTests
  vectorTests dir
  merkleTests
  framingTests
  interpreterTests
  unitTests
  sessionTests dir
  let fails ← failures.get
  say s!"ledger-test: {← passes.get} passed, {fails.size} failed"
  return if fails.isEmpty then 0 else 1
