import Winnow.IO
open Winnow Winnow.Net Winnow.IO Lean

/-! `io-test`: integration tests of the I/O area against a disposable regtest bitcoind.

Starts `bitcoind -regtest` (temp datadir, random free ports, `-blockfilterindex -peerblockfilters`),
then checks, through the Lean I/O layer only: the handshake; header sync to the node's tip over
several getheaders batches, and the headers.bin round trip; a reorg (invalidateblock + more work) and a
stale equal-work sibling; compact-filter download with a match for a script the test funded, the pinned
filter headers equal to the node's `getblockfilter`, filters.json round trip and a rollback on the
reorg; the mempool window seeing a new transaction; broadcast of a raw transaction the node then holds
in its mempool; peers.json and broadcast.json round trips. Offline policy checks: HTTP permits and
redirects against a local Python server through the curl fetch, seed filtering and dns-json, the
census catalog (the list each build ships). The node is killed by PID at the end, also on failure.

Usage: `io-test [--swift <oracle-io binary>]` (the binary compares Winnow's Swift side on the same node). -/

def bitcoind := "/opt/homebrew/bin/bitcoind"
def bitcoinCli := "/opt/homebrew/bin/bitcoin-cli"

initialize failures : IO.Ref (Array String) ← IO.mkRef #[]
initialize passes : IO.Ref Nat ← IO.mkRef 0

def say (s : String) : IO Unit := do IO.println s; (← IO.getStdout).flush

def check (name : String) (cond : Bool) (detail : String := "") : IO Unit := do
  if cond then
    passes.modify (· + 1)
    say s!"  ok   {name}{if detail.isEmpty then "" else " — " ++ detail}"
  else
    failures.modify (·.push name)
    say s!"  FAIL {name}{if detail.isEmpty then "" else " — " ++ detail}"

def runNet {α} (what : String) (x : NetM α) : IO α := do
  match ← x.attempt with
  | .ok a => return a
  | .error e => throw (IO.userError s!"{what}: {e}")

/-! ## The node -/

structure Node where
  datadir : String
  p2p : UInt16
  rpc : UInt16
  pid : UInt32

def Node.cli (n : Node) (args : Array String) : IO String := do
  let out ← IO.Process.output { cmd := bitcoinCli, args := #["-regtest", s!"-datadir={n.datadir}", s!"-rpcport={n.rpc}"] ++ args }
  if out.exitCode != 0 then throw (IO.userError s!"bitcoin-cli {args}: {out.stderr.trimAscii}")
  return out.stdout.trimAscii.toString

def Node.wallet (n : Node) (args : Array String) : IO String := n.cli (#["-rpcwallet=w"] ++ args)

def Node.json (n : Node) (args : Array String) : IO Json := do
  match Json.parse (← n.cli args) with
  | .ok j => return j
  | .error e => throw (IO.userError s!"json {args}: {e}")

def Node.height (n : Node) : IO Nat := do return (← n.cli #["getblockcount"]).toNat!
def Node.mine (n : Node) (count : Nat) (addr : String) : IO Unit := do
  let mut left := count
  while left > 0 do
    let k := min left 500
    discard <| n.cli #["generatetoaddress", toString k, addr]
    left := left - k

def Node.endpoint (n : Node) : PeerEndpoint := { host := "127.0.0.1", port := n.p2p }

def killPid (pid : UInt32) (signal : String := "-TERM") : IO Unit := do
  discard <| IO.Process.output { cmd := "kill", args := #[signal, toString pid] }

def startNode (dir : String) : IO Node := do
  for attempt in [0:5] do
    let r ← randomU64
    let p2p := (30000 + r.toNat % 25000).toUInt16
    let rpc := p2p + 1
    let datadir := s!"{dir}/node{attempt}"
    IO.FS.createDirAll datadir
    let child ← IO.Process.spawn {
      cmd := bitcoind
      args := #["-regtest", s!"-datadir={datadir}", s!"-port={p2p}", s!"-rpcport={rpc}", "-bind=127.0.0.1",
        "-listen=1", "-server=1", "-blockfilterindex=1", "-peerblockfilters=1", "-fallbackfee=0.0002",
        "-printtoconsole=0", "-dnsseed=0", "-discover=0", "-listenonion=0", "-whitelist=noban@127.0.0.1"]
      stdout := .null, stderr := .null, stdin := .null }
    let n : Node := { datadir, p2p, rpc, pid := child.pid }
    let mut ready := false
    for _ in [0:100] do
      IO.sleep 200
      if (← child.tryWait).isSome then break
      match ← (n.cli #["getblockchaininfo"]).toBaseIO with
      | .ok _ => ready := true; break
      | .error _ => pure ()
    if ready then return n
    killPid child.pid "-KILL"
  throw (IO.userError "bitcoind did not start")

/-- Waits until the block-filter index has caught up with the tip. -/
def Node.waitFilterIndex (n : Node) : IO Unit := do
  for _ in [0:300] do
    let tip ← n.height
    let info ← n.json #["getindexinfo"]
    match info.getObjVal? "basic block filter index" with
    | .ok idx =>
      let synced := (idx.getObjValAs? Bool "synced").toOption.getD false
      let best := (idx.getObjValAs? Nat "best_block_height").toOption.getD 0
      if synced && best == tip then return
    | .error _ => pure ()
    IO.sleep 100
  throw (IO.userError "filter index did not catch up")

def jsonStr (j : Json) (k : String) : String := (j.getObjValAs? String k).toOption.getD ""

/-- Waits for a condition, polling. -/
def waitUntil (ms : Nat) (cond : IO Bool) : IO Bool := do
  let deadline := (← IO.monoMsNow) + ms
  while (← IO.monoMsNow) < deadline do
    if ← cond then return true
    IO.sleep 200
  cond

/-! ## Offline checks -/

def offlineChecks (dir : String) : IO Unit := do
  say "policy (offline)"
  -- Seed filtering and IP literals (BSD inet_pton)
  check "inet_pton4 refuses leading zeros" ((inetPton4 "01.2.3.4").isNone && (inetPton4 "1.2.3.4").isSome)
  check "inet_pton6 forms" ((inetPton6 "::1").isSome && (inetPton6 "2001:db8::1").isSome &&
    (inetPton6 "::ffff:1.2.3.4").isSome && (inetPton6 "1:2:3:4:5:6:7:8:9").isNone && (inetPton6 ":::").isNone)
  check "seed filter drops private answers" (!SeedAddressFilter.accepts "10.0.0.1" false &&
    SeedAddressFilter.accepts "10.0.0.1" true && SeedAddressFilter.accepts "8.8.8.8" false &&
    !SeedAddressFilter.accepts "::ffff:192.168.1.1" false && !SeedAddressFilter.accepts "fe80::1" false &&
    !SeedAddressFilter.accepts "seed.example" true)
  check "netblock" (netblock "8.8.4.4" == some "v4:8.8" && netblock "127.0.0.1" == none &&
    netblock "2a01:4f8::1" == some "v6:2a01:04f8" && netblock "::ffff:8.8.8.8" == some "v4:8.8")
  let dnsBody := "{\"Status\":0,\"Answer\":[{\"name\":\"x\",\"type\":5,\"data\":\"y.\"},{\"type\":1,\"data\":\" 1.2.3.4 \"},{\"type\":28,\"data\":\"2a01::1\"}]}"
  check "dns-json answers" ((DNSJSON.hosts dnsBody.toUTF8).toOption == some #["1.2.3.4", "2a01::1"])
  check "dns-json non-zero status" ((DNSJSON.hosts "{\"Status\":3}".toUTF8).toOption == some #[])
  let stub : SeedResolver := { lookup := fun h p _ => pure #[{ host := h ++ ".1", port := p }, { host := "dup", port := p }] }
  let seeds ← stub.resolveSeeds #["a", "b"] 8333 false
  check "resolveSeeds dedupes" (seeds.size == 3)
  let sys ← SeedResolver.getaddrinfo "localhost" 8333
  check "getaddrinfo resolves localhost" (sys.any (·.host == "127.0.0.1") || sys.any (·.host == "::1")) s!"{sys.map (·.host)}"
  check "seed endpoints keep loopback only with allowPrivate"
    ((SeedResolver.endpoints #["127.0.0.1", "127.0.0.1", "8.8.8.8"] 1 false).size == 1 &&
     (SeedResolver.endpoints #["127.0.0.1", "127.0.0.1", "8.8.8.8"] 1 true).size == 2)
  -- Diversity
  let pol : DiversityPolicy := { peerCount := 3 }
  let c (h : String) (s : PeerSource) : PeerCandidate := { endpoint := { host := h, port := 8333 }, source := s }
  check "diversity: one netblock once" (!pol.admits (c "8.8.1.1" .census) #[c "8.8.2.2" .dnsSeed])
  check "diversity: a class may not hold every seat"
    (!pol.admits (c "9.9.9.9" .census) #[c "1.1.1.1" .census, c "2.2.2.2" .census] &&
      pol.admits (c "9.9.9.9" .manual) #[c "1.1.1.1" .manual, c "2.2.2.2" .manual])
  check "cooldown doubles to the cap" (PeerPool.cooldown 1 == 30_000 && PeerPool.cooldown 2 == 60_000 &&
    PeerPool.cooldown 5 == 480_000 && PeerPool.cooldown 6 == 600_000 && PeerPool.cooldown 40 == 600_000)
  check "rebroadcast backoff" (TxBroadcaster.backoffInterval 0 60 3600 == 60 && TxBroadcaster.backoffInterval 5 60 3600 == 1920 &&
    TxBroadcaster.backoffInterval 6 60 3600 == 3600)
  -- peers.json formats
  let legacy := "[{\"host\":\"1.2.3.4\",\"port\":8333}]".toUTF8
  check "peers.json legacy array reads as persisted"
    ((PersistedPeers.decode legacy).map (·.map (·.source)) == some #[.persisted])
  let enc := PersistedPeers.encode #[c "1.2.3.4" .dnsSeed, c "::1" .manual]
  check "peers.json v2 encodes as JSONEncoder does"
    (String.fromUTF8! enc == "{\"version\":2,\"peers\":[{\"host\":\"1.2.3.4\",\"port\":8333,\"source\":\"dnsSeed\"},{\"host\":\"::1\",\"port\":8333,\"source\":\"manual\"}]}")
  check "peers.json v2 round trip" (PersistedPeers.decode enc == some #[c "1.2.3.4" .dnsSeed, c "::1" .manual])
  let censusEnc := PersistedPeers.encode #[c "5.6.7.8" .census]
  check "a census peer keeps the legacy source name \"fallback\""
    (((String.fromUTF8! censusEnc).splitOn "\"source\":\"fallback\"").length == 2 &&
      PersistedPeers.decode censusEnc == some #[c "5.6.7.8" .census])
  check "peers.json other versions are refused" ((PersistedPeers.decode "{\"version\":3,\"peers\":[]}".toUTF8).isNone)
  -- HTTP policy
  check "permits" (permits "https://1.1.1.1/dns-query" && permits "http://a:8080/x" && !permits "ftp://a/x" &&
    !permits "https://user@a/x" && !permits "https:///x" && !permits "http://a:0/" && !permits "http://a:70000/")
  let a := (parseURL "https://Census.example/p").get!
  check "redirect rules" (followsRedirect a (parseURL "https://census.example/q").get! &&
    !followsRedirect a (parseURL "http://census.example/q").get! && !followsRedirect a (parseURL "https://other.example/").get!)
  -- A local server for the curl fetch.
  let script := s!"{dir}/http_server.py"
  IO.FS.writeFile script ("import http.server, sys\n" ++
    "class H(http.server.BaseHTTPRequestHandler):\n" ++
    "    def log_message(self, *a): pass\n" ++
    "    def do_GET(self):\n" ++
    "        port = self.server.server_address[1]\n" ++
    "        if self.path == '/ok': self.reply(200, b'hello')\n" ++
    "        elif self.path == '/big': self.reply(200, b'x' * 5000)\n" ++
    "        elif self.path == '/accept': self.reply(200, (self.headers.get('Accept') or '').encode())\n" ++
    "        elif self.path == '/same': self.redirect('/ok')\n" ++
    "        elif self.path == '/other': self.redirect('http://localhost:%d/ok' % port)\n" ++
    "        else: self.reply(404, b'no')\n" ++
    "    def reply(self, code, body):\n" ++
    "        self.send_response(code); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)\n" ++
    "    def redirect(self, loc):\n" ++
    "        self.send_response(302); self.send_header('Location', loc); self.send_header('Content-Length', '0'); self.end_headers()\n" ++
    "s = http.server.HTTPServer(('127.0.0.1', 0), H)\n" ++
    "print(s.server_address[1], flush=True)\n" ++
    "s.serve_forever()\n")
  let server ← IO.Process.spawn { cmd := "python3", args := #["-I", script], stdout := .piped, stderr := .null, stdin := .null }
  try
    let port := (← server.stdout.getLine).trimAscii.toString
    let client ← RoutedHTTPClient.new (curlFetch "/usr/bin/curl")
    let base := s!"http://127.0.0.1:{port}"
    let r1 ← (client.get s!"{base}/ok" 100).attempt
    check "http 200" (match r1 with | .ok b => b == "hello".toUTF8 | .error _ => false)
    let r2 ← (client.get s!"{base}/big" 4999).attempt
    check "http body over the cap is tooLarge" (match r2 with | .error (.http .tooLarge) => true | _ => false)
    let r2b ← (client.get s!"{base}/big" 5000).attempt
    check "http body at the cap is accepted" (match r2b with | .ok b => b.size == 5000 | _ => false)
    let r3 ← (client.get s!"{base}/same" 100).attempt
    check "same-host redirect followed" (match r3 with | .ok b => b == "hello".toUTF8 | .error _ => false)
    let r4 ← (client.get s!"{base}/other" 100).attempt
    check "cross-host redirect refused as HTTP 302" (match r4 with | .error (.http (.status 302)) => true | _ => false)
    let r5 ← (client.get s!"{base}/missing" 100).attempt
    check "http 404" (match r5 with | .error (.http (.status 404)) => true | _ => false)
    let r6 ← (client.get s!"{base}/accept" 100 (accept := some "application/dns-json")).attempt
    check "accept header sent" (match r6 with | .ok b => b == "application/dns-json".toUTF8 | _ => false)
    client.cancel
    let r7 ← (client.get s!"{base}/ok" 100).attempt
    check "cancelled client refuses" (match r7 with | .error (.http .unavailable) => true | _ => false)
  finally
    server.kill
  -- The census catalog (shipped with each build: no signature, no expiry).
  let now ← wallSeconds
  let today := now / 86_400
  let civil (days : Int) : String := Id.run do
    -- civil_from_days
    let z := days + 719468
    let era := (if z ≥ 0 then z else z - 146096) / 146097
    let doe := z - era * 146097
    let yoe := (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
    let y := yoe + era * 400
    let doy := doe - (365 * yoe + yoe / 4 - yoe / 100)
    let mp := (5 * doy + 2) / 153
    let d := doy - (153 * mp + 2) / 5 + 1
    let m := if mp < 10 then mp + 3 else mp - 9
    let y := if m ≤ 2 then y + 1 else y
    let p2 (x : Int) := if x < 10 then s!"0{x}" else toString x
    return s!"{y}-{p2 m}-{p2 d}"
  let entry (h : String) := s!"\{\"host\":\"{h}\",\"port\":8333,\"userAgent\":\"/Satoshi:28.0.0/\",\"startHeight\":900000}"
  let doc (date : String) (hosts : List String) :=
    s!"\{\"schemaVersion\":1,\"date\":\"{date}\",\"tip\":900010,\"networks\":\{\"clearnet\":[{",".intercalate (hosts.map entry)}],\"tor\":[]}}"
  let good := doc (civil today) ["9.9.9.9", "::FFFF:8.8.8.8", "2a01:4f8:0:0::1"]
  match CensusCatalog.decode good.toUTF8 with
  | .ok cat => check "census validates and canonicalizes" ((cat.clearnet.map (·.map (·.host))) == some #["2a01:4f8::1", "8.8.8.8", "9.9.9.9"])
                 s!"{cat.clearnet.map (·.map (·.host))}"
  | .error e => check "census validates and canonicalizes" false e.name
  let nameOf (r : Except CensusError CensusCatalog) := match r with | .ok _ => "ok" | .error e => e.name
  check "census of any age validates (no expiry)" (nameOf (CensusCatalog.decode (doc (civil (today - 400)) ["9.9.9.9"]).toUTF8) == "ok")
  check "census dated ahead validates (no clock)" (nameOf (CensusCatalog.decode (doc (civil (today + 1)) ["9.9.9.9"]).toUTF8) == "ok")
  check "census duplicate" (nameOf (CensusCatalog.decode (doc (civil today) ["9.9.9.9", "::ffff:9.9.9.9"]).toUTF8) == "duplicate")
  check "census diversity" (nameOf (CensusCatalog.decode (doc (civil today) ["9.9.9.9", "9.9.1.1"]).toUTF8) == "diversity")
  check "census private host" (nameOf (CensusCatalog.decode (doc (civil today) ["192.168.1.1"]).toUTF8) == "endpoint")
  check "census thin" (nameOf (CensusCatalog.decode (doc (civil today) ["9.9.9.9"]).toUTF8 (minimumEntries := 50)) == "thin")
  check "census bad date" (CensusCatalog.day "2026-02-30" == none && CensusCatalog.day "2026-10-26" == some 20752)
  check "no bundled census outside an app bundle" (← CensusCatalog.bundled).isNone

/-! ## Against the node -/

def regtest := NetworkParams.regtest
def noSeeds : SeedResolver := { lookup := fun _ _ _ => pure #[] }

/-- Collects a stream's elements on a thread of its own. -/
def collect {α ε} (s : EventStream α ε) : IO (IO.Ref (Array α)) := do
  let r ← IO.mkRef #[]
  spawn do
    repeat
      match ← s.next with
      | .value a => r.modify (·.push a)
      | .finished _ => break
  return r

def scriptOf (n : Node) (addr : String) : IO ByteArray := do
  let info ← Json.parse (← n.wallet #["getaddressinfo", addr]) |> IO.ofExcept
  return ofHex! (jsonStr info "scriptPubKey")

def nodeFilterHeader (n : Node) (height : Nat) : IO String := do
  let hash ← n.cli #["getblockhash", toString height]
  let j ← n.json #["getblockfilter", hash]
  return jsonStr j "header"

/-! ## A scripted fake peer (Lean TCP server) for the failure paths -/

inductive FakeMode where
  /-- Accepts and never speaks. -/
  | silent
  /-- Answers version without NODE_COMPACT_FILTERS. -/
  | noFilters
  /-- Speaks the wrong network magic. -/
  | badMagic
  /-- Handshakes, then answers getheaders with one header that does not connect. -/
  | strayHeader
  /-- Handshakes, then never answers. -/
  | mute

def fakePeer (mode : FakeMode) : IO UInt16 := do
  let server ← Std.Async.TCP.Socket.Server.mk
  server.bind (.v4 ⟨Std.Net.IPv4Addr.ofParts 127 0 0 1, 0⟩)
  server.listen 8
  let port := (← server.getSockName).port
  spawn do
    let keep := server
    let sock ← keep.accept.block
    let magic := regtest.magic
    let send (m : PeerMessage) : IO Unit :=
      (sock.send (MessageFramer.frame m.command m.payload (if mode matches .badMagic then ofHex! "deadbeef" else magic))).block
    let version (services : UInt64) : PeerMessage := .version {
      version := 70016
      services := services
      timestamp := 0
      receiver := .unspecified
      sender := .unspecified
      nonce := 7
      userAgent := "/fake:0/"
      startHeight := 0
      relay := false }
    let mut framer : MessageFramer := { magic }
    let mut alive := true
    while alive do
      let some chunk ← (sock.recv? 65536).block | break
      framer := framer.append chunk
      repeat
        match framer.nextMessage with
        | .ok (some (cmd, payload), f) =>
          framer := f
          match mode, cmd with
          | .silent, _ => pure ()
          | .noFilters, "version" => send (version 0); send .verack
          | .badMagic, "version" => send (version 64)
          | .strayHeader, "version" | .mute, "version" => send (version 64); send .verack
          | .strayHeader, "getheaders" =>
            let h := BlockHeader.mk' 1 (ByteArray.mk (Array.replicate 32 9)) (ByteArray.mk (Array.replicate 32 1)) 1 0x207fffff 0
            send (.headers #[h])
          | _, _ => pure ()
          let _ := payload
        | .ok (none, _) => break
        | .error _ => alive := false; break
    discard <| sock.shutdown.toIO
  return port

def fakeChecks (dir : String) : IO Unit := do
  say "transport and pool failure paths (fake peers)"
  let ep (port : UInt16) : PeerEndpoint := { host := "127.0.0.1", port }
  let silent ← fakePeer .silent
  let c1 ← PeerConnection.new (ep silent) regtest
  check "silent peer: handshake times out" (match ← (c1.connect 800).attempt with
    | .error (.peer .timeout) => true | _ => false)
  let nf ← fakePeer .noFilters
  let c2 ← PeerConnection.new (ep nf) regtest
  check "peer without compact filters is refused" (match ← (c2.connect 3_000).attempt with
    | .error (.peer (.missingCompactFilters 0)) => true | _ => false)
  let bm ← fakePeer .badMagic
  let c3 ← PeerConnection.new (ep bm) regtest
  check "wrong magic tears down as a framing error" (match ← (c3.connect 3_000).attempt with
    | .error (.framing .badMagic) => true | _ => false)
  -- Pool judgement: a data fault burns the peer, a timeout only cools it.
  let stray ← fakePeer .strayHeader
  let pool ← PeerPool.new regtest (peerCount := 1) (manualPeers := #[ep stray]) (seedResolver := some noSeeds)
  pool.start
  discard <| waitUntil 5_000 (do return (← pool.connectedPeers).size == 1)
  let store ← runNet "fake headers" (HeaderStore.open regtest none)
  let r ← (pool.syncHeaders store (timeoutPerPeerMs := 2_000)).attempt
  let reason ← pool.rejectionReason (ep stray)
  check "headers that do not connect: misbehaving, then exhausted"
    ((match r with | .error (.pool (.exhausted 1 _)) => true | _ => false) &&
     reason == some (HeaderChainError.description .doesNotConnect))
    (match r with | .error e => e.description | .ok _ => "ok")
  pool.stop
  let mute ← fakePeer .mute
  let pool2 ← PeerPool.new regtest (peerCount := 1) (manualPeers := #[ep mute]) (seedResolver := some noSeeds)
  pool2.start
  discard <| waitUntil 5_000 (do return (← pool2.connectedPeers).size == 1)
  let r2 ← (pool2.syncHeaders store (timeoutPerPeerMs := 800)).attempt
  check "a peer that stops answering is cooled off, not banned"
    ((match r2 with | .error (.pool (.allPeersCoolingDown 1 _)) => true | _ => false) &&
     (← pool2.isCoolingDown (ep mute)) && (← pool2.knownGood).isEmpty == false)
    (match r2 with | .error e => e.description | .ok _ => "ok")
  pool2.stop
  let _ := dir

def nodeChecks (dir : String) (n : Node) (swift : Option String) : IO Unit := do
  say s!"node: bitcoind regtest pid {n.pid}, p2p {n.p2p}"
  discard <| n.cli #["createwallet", "w"]
  let mineAddr ← n.wallet #["getnewaddress"]
  let otherAddr ← n.wallet #["getnewaddress"]
  n.mine 101 mineAddr
  -- 1. Handshake
  let c ← PeerConnection.new n.endpoint regtest
  runNet "connect" (c.connect 10_000)
  let ua ← c.peerUserAgent
  check "handshake: version/verack completed" ((← c.isConnected) && ua.startsWith "/Satoshi:") ua
  check "handshake: peer signals NODE_COMPACT_FILTERS" ((← c.peerServices) &&& PeerConnection.nodeCompactFilters != 0)
  let info ← n.json #["getpeerinfo"]
  let subvers := match info with | .arr xs => xs.map (jsonStr · "subver") | _ => #[]
  check "node sees our user agent /winnow:0.1/" (subvers.contains "/winnow:0.1/") s!"{subvers}"
  runNet "ping" c.ping
  check "ping answered with pong" true
  let refused ← PeerConnection.new { host := "127.0.0.1", port := 1 } regtest
  check "refused dial is a transport error" (match ← (refused.connect 2_000).attempt with
    | .error e => e.isTransportPeerError | .ok _ => false)
  -- Chain: a funded watch script, then enough blocks for several header and filter batches.
  let watchAddr ← n.wallet #["getnewaddress"]
  let spk ← scriptOf n watchAddr
  let fundTxid ← n.wallet #["sendtoaddress", watchAddr, "1.0"]
  n.mine 1 mineAddr
  let fundHeight ← n.height
  n.mine 2100 mineAddr
  let tip ← n.height
  say s!"  chain: tip {tip}, funding tx {fundTxid} at {fundHeight}"
  -- 2. Header sync through the pool
  let peersPath : System.FilePath := s!"{dir}/peers.json"
  let headersPath : System.FilePath := s!"{dir}/headers.bin"
  let filtersPath : System.FilePath := s!"{dir}/filters.json"
  let pool ← PeerPool.new regtest (manualPeers := #[n.endpoint]) (peersFile := some peersPath) (seedResolver := some noSeeds)
  pool.start
  check "pool seats the manual peer" (← waitUntil 10_000 (do return (← pool.connectedPeers).size == 1))
  let status ← pool.connectionStatus
  check "pool reports exhaustion below target" (status.exhausted && status.connected == 1 && status.target == 3)
  let store ← runNet "open headers" (HeaderStore.open regtest (some headersPath))
  let outcome ← runNet "syncHeaders" (pool.syncHeaders store)
  let best ← n.cli #["getbestblockhash"]
  check "header sync reaches the node's tip" ((← store.height).toNat == tip && displayHex (← store.tipHash) == best)
    s!"{outcome.connected} headers, tip {← store.height}"
  let reopened ← runNet "reopen headers" (HeaderStore.open regtest (some headersPath))
  let fileBytes ← IO.FS.readBinFile headersPath
  check "headers.bin round trip" ((← reopened.height) == (← store.height) && (← reopened.tipHash) == (← store.tipHash) &&
    fileBytes == (← store.snapshot).fileBytes) s!"{fileBytes.size} bytes"
  -- 3. Compact filters
  n.waitFilterIndex
  let fs ← runNet "filters open" (FilterSyncIO.new pool store 0 (some filtersPath))
  let matched ← IO.mkRef (#[] : Array (UInt32 × Bool))
  runNet "filter sync" (fs.sync #[spk] (onMatch := fun m => do
    let has := m.block.transactions.any (fun t => displayHex t.txid == fundTxid)
    matched.modify (·.push (m.height, has))))
  let ms ← matched.get
  check "filter sync matches the funded script's block" (ms.any fun (h, has) => h.toNat == fundHeight && has) s!"{ms.map (·.1)}"
  check "filter sync scans to the tip" ((← fs.nextScanHeight).toNat == tip + 1)
  let pinned ← fs.filterHeader tip.toUInt32
  check "pinned filter header equals the node's" ((pinned.map displayHex) == some (← nodeFilterHeader n tip))
  let receipt ← (fs.transaction (ofDisplayHex! fundTxid) fundHeight.toUInt32).attempt
  check "historical receipt fetched from its block" (match receipt with | .ok t => displayHex t.txid == fundTxid | _ => false)
  let fs2 ← runNet "filters reopen" (FilterSyncIO.new pool store 0 (some filtersPath))
  check "filters.json round trip" (fs2.persistenceState == .loaded && (← fs2.nextScanHeight) == (← fs.nextScanHeight) &&
    (← fs2.pinnedFilterHeaders).size == (← fs.pinnedFilterHeaders).size) s!"{(← fs.pinnedFilterHeaders).size} pinned"
  -- 4. A reorg: invalidate three blocks, mine four elsewhere.
  let tipBefore ← n.height
  let forkAt := tipBefore - 3
  discard <| n.cli #["invalidateblock", ← n.cli #["getblockhash", toString (forkAt + 1)]]
  n.mine 4 otherAddr
  let tipAfter ← n.height
  n.waitFilterIndex
  let reorgs ← IO.mkRef (#[] : Array UInt32)
  runNet "filter sync after reorg" (fs.sync #[spk] (onReorg := some fun h => reorgs.modify (·.push h)) (onMatch := fun _ => pure ()))
  check "reorg reported at the fork before filters resume" ((← reorgs.get) == #[forkAt.toUInt32]) s!"{← reorgs.get}"
  check "reorg: headers follow the heavier branch" ((← store.height).toNat == tipAfter &&
    displayHex (← store.tipHash) == (← n.cli #["getbestblockhash"]))
  check "reorg: filters rescanned on the new branch" ((← fs.nextScanHeight).toNat == tipAfter + 1 &&
    ((← fs.filterHeader tipAfter.toUInt32).map displayHex) == some (← nodeFilterHeader n tipAfter))
  -- 5. A stale sibling of equal work, then a heavier branch.
  let oldTip ← store.tipHash
  discard <| n.cli #["invalidateblock", ← n.cli #["getbestblockhash"]]
  -- A fresh coinbase address, or the sibling would be the invalidated block itself.
  n.mine 1 (← n.wallet #["getnewaddress"])
  let sib ← runNet "sync sibling" (store.sync c)
  check "equal-work sibling is a stale sibling, tip kept" (sib.staleSiblings ≥ 1 && (← store.tipHash) == oldTip)
    s!"staleSiblings {sib.staleSiblings}"
  n.mine 1 (← n.wallet #["getnewaddress"])
  let heavier ← runNet "sync heavier" (store.sync c)
  check "heavier sibling branch replaces the tip" (heavier.minForkHeight == some (tipAfter - 1).toUInt32 &&
    displayHex (← store.tipHash) == (← n.cli #["getbestblockhash"])) s!"fork {heavier.minForkHeight}"
  -- 6. The mempool window, on a relaying connection.
  let relayPool ← PeerPool.new regtest (peerCount := 1) (manualPeers := #[n.endpoint]) (relayPreference := true)
    (seedResolver := some noSeeds)
  relayPool.start
  discard <| waitUntil 10_000 (do return (← relayPool.connectedPeers).size == 1)
  let seenAddr ← n.wallet #["getnewaddress"]
  let seenSpk ← scriptOf n seenAddr
  let window ← MempoolWindowIO.new relayPool #[seenSpk]
  let wevents ← collect (← window.events)
  window.start 600
  let seenTxid ← n.wallet #["sendtoaddress", seenAddr, "0.5"]
  let gotIt ← waitUntil 45_000 (do
    return (← wevents.get).any fun | .paymentSeen t a _ => displayHex t == seenTxid && a == 50_000_000 | _ => false)
  check "mempool window sees the payment" gotIt
  -- 7. Broadcast a raw transaction the node has not seen.
  let dest ← n.wallet #["getnewaddress"]
  let rawUnfunded ← n.wallet #["createrawtransaction", "[]", s!"\{\"{dest}\":0.1}"]
  let funded ← Json.parse (← n.wallet #["fundrawtransaction", rawUnfunded]) |> IO.ofExcept
  let signed ← Json.parse (← n.wallet #["signrawtransactionwithwallet", jsonStr funded "hex"]) |> IO.ofExcept
  let raw := ofHex! (jsonStr signed "hex")
  let broadcastPath : System.FilePath := s!"{dir}/broadcast.json"
  let b ← runNet "broadcaster" (TxBroadcaster.new pool (some broadcastPath))
  let bevents ← collect (← b.events)
  let expectedTxid := ((Transaction.decode raw).toOption.map (·.txid)).getD .empty
  window.watchEcho expectedTxid
  let txid ← runNet "broadcast" (b.broadcast raw (some 20.0))
  let inMempool ← waitUntil 20_000 (do
    let mp ← n.json #["getrawmempool"]
    return match mp with | .arr xs => xs.any (· == Json.str (displayHex txid)) | _ => false)
  check "broadcast: the node accepted the transaction" inMempool (displayHex txid)
  check "broadcast: announced, requested, served" ((← bevents.get).any (fun | .served t _ => t == txid | _ => false) &&
    (← b.wasServed txid))
  let echoed ← waitUntil 45_000 (do
    return (← wevents.get).any fun | .txidEchoed t _ => t == txid | _ => false)
  check "mempool window: the broadcast echoes back from the network" echoed
  window.stop
  check "mempool window closes" !(← window.isRunning)
  relayPool.stop
  b.shutdown
  let b2 ← runNet "broadcaster reload" (TxBroadcaster.new pool (some broadcastPath))
  check "broadcast.json round trip" (b2.persistenceState == .loaded 1 && (← b2.pendingTxids) == #[txid] &&
    (← b2.rawTransaction txid) == some raw && (← b2.wasServed txid))
  n.mine 1 mineAddr
  runNet "markConfirmed" (b2.markConfirmed txid (← n.height).toUInt32)
  b2.shutdown
  let b3 ← runNet "broadcaster reload 2" (TxBroadcaster.new pool (some broadcastPath))
  check "confirmed tombstone persists and is silent" ((← b3.pendingTxids).isEmpty && (← b3.rawTransaction txid).isNone &&
    b3.persistenceState == .loaded 1)
  b3.shutdown
  -- 8. A fresh Lean scan from genesis, and Winnow's Swift side on the same node.
  n.waitFilterIndex
  let freshStore ← runNet "fresh headers" (HeaderStore.open regtest (some s!"{dir}/fresh-headers.bin"))
  let freshFilters ← runNet "fresh filters" (FilterSyncIO.new pool freshStore 0 (some s!"{dir}/fresh-filters.json"))
  let freshMatches ← IO.mkRef (#[] : Array Nat)
  runNet "fresh filter sync" (freshFilters.sync #[spk] (onMatch := fun m => freshMatches.modify (·.push m.height.toNat)))
  let leanMatches := (← freshMatches.get).qsort (· < ·)
  let leanTip ← freshStore.height
  -- The broadcast transaction may spend the watched coin, so its block can match too.
  check "fresh scan from genesis: tip and match" (leanTip.toNat == (← n.height) && leanMatches.contains fundHeight) s!"{leanMatches}"
  if let some bin := swift then
    let out ← IO.Process.output { cmd := bin, args := #["127.0.0.1", toString n.p2p, hex spk, s!"{dir}/swift"] }
    say s!"  swift: {out.stdout.trimAscii}{out.stderr.trimAscii}"
    match Json.parse out.stdout with
    | .ok j =>
      check "swift: same header tip" ((j.getObjValAs? Nat "tipHeight").toOption == some leanTip.toNat &&
        jsonStr j "tipHash" == displayHex (← freshStore.tipHash))
      let swiftMatches := ((j.getObjValAs? (Array Nat) "matchedHeights").toOption.getD #[]).qsort (· < ·)
      check "swift: same matched block heights" (swiftMatches == leanMatches) s!"{swiftMatches} vs {leanMatches}"
      check "swift: same filter header at the tip"
        (jsonStr j "filterHeaderAtTip" == ((← freshFilters.filterHeader leanTip).map hex).getD "")
      let swiftHeaders ← IO.FS.readBinFile s!"{dir}/swift/headers.bin"
      check "swift: headers.bin byte-identical" (swiftHeaders == (← IO.FS.readBinFile s!"{dir}/fresh-headers.bin"))
        s!"{swiftHeaders.size} bytes"
      let swiftPeers := (← PersistedPeers.boundedRead s!"{dir}/swift/peers.json").bind PersistedPeers.decode
      check "swift: peers.json readable by Lean" (swiftPeers == some #[{ endpoint := n.endpoint, source := .manual }])
      let swiftProgress ← IO.FS.readFile s!"{dir}/swift/filters.json"
      let leanProgress ← freshFilters.progress.get
      check "swift: filters.json readable by Lean"
        (match FilterSync.load (some swiftProgress) 0 with
         | .ok (_, pr) => pr.nextScanHeight == leanTip + 1 && pr == leanProgress
         | .error _ => false)
    | .error e => check "swift oracle output" false e
  -- 9. peers.json
  pool.stop
  let stored := (← PersistedPeers.boundedRead peersPath).bind PersistedPeers.decode
  check "peers.json written with the peer's source" (stored == some #[{ endpoint := n.endpoint, source := .manual }])
  let pool3 ← PeerPool.new regtest (peersFile := some peersPath) (seedResolver := some noSeeds)
  check "peers.json read back" ((← pool3.knownGood) == #[n.endpoint] && (← pool3.source n.endpoint) == some .manual)
  c.disconnect
  -- 10. Winnow's Swift side opens the files the Lean side wrote.
  if let some bin := swift then
    let out ← IO.Process.output { cmd := bin, args := #["read", dir] }
    say s!"  swift read: {out.stdout.trimAscii}{out.stderr.trimAscii}"
    match Json.parse out.stdout with
    | .ok j =>
      check "swift reads Lean's headers.bin" ((j.getObjValAs? Nat "headersHeight").toOption == some (← store.height).toNat &&
        jsonStr j "headersTip" == hex (← store.tipHash))
      check "swift reads Lean's filters.json" ((j.getObjValAs? Nat "filtersNext").toOption == some (← fs.nextScanHeight).toNat)
      check "swift reads Lean's broadcast.json (the confirmed tombstone)"
        ((j.getObjValAs? Int "broadcastLoaded").toOption == some 1 &&
         (j.getObjValAs? (Array String) "broadcastPending").toOption == some #[])
      check "swift reads Lean's peers.json" ((j.getObjValAs? (Array String) "peers").toOption ==
        some #[s!"{n.endpoint.description}/persisted"])
    | .error e => check "swift read output" false e
def main (args : List String) : IO UInt32 := do
  let swift := match args with | "--swift" :: b :: _ => some b | _ => none
  let tmp ← IO.FS.createTempDir
  let dir := tmp.toString
  say s!"io-test: work dir {dir}"
  let node ← (startNode dir).toBaseIO
  let n ← match node with
    | .ok n => pure n
    | .error e => say s!"FAIL could not start bitcoind: {e}"; return 1
  -- A watchdog: never leave the node behind.
  spawn do
    IO.sleep 900_000
    say "FAIL watchdog: the test ran for 15 minutes"
    killPid n.pid "-KILL"
    IO.Process.exit 2
  try
    offlineChecks dir
    fakeChecks dir
    nodeChecks dir n swift
  catch e =>
    failures.modify (·.push s!"exception: {e}")
    say s!"  FAIL exception: {e}"
  finally
    discard <| (n.cli #["stop"]).toBaseIO
    discard <| waitUntil 10_000 (do
      let r ← IO.Process.output { cmd := "kill", args := #["-0", toString n.pid] }
      return r.exitCode != 0)
    killPid n.pid "-KILL"
    try IO.FS.removeDirAll tmp catch _ => pure ()
  let fs ← failures.get
  say s!"io-test: {← passes.get} passed, {fs.size} failed{if fs.isEmpty then "" else ": " ++ ", ".intercalate fs.toList}"
  -- Exit explicitly: the watchdog and the peers' timer chains would otherwise keep the process alive.
  IO.Process.exit (if fs.isEmpty then 0 else 1)
