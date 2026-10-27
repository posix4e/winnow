import WinnowApp.Types
import WinnowApp.Format
import Winnow.Wallet.People

/-! AppModel's and the views' pure helpers, ported as they are (APP-SURVEY "port the already-pure
helpers as-is"): sync wording, history order, payment titles, explorer URLs, label validation,
thresholds, and the approval/MuSig2 summaries. -/

namespace WinnowApp

/-! ## Sync -/

/-- `AppModel.syncStatusText` (AppModel.swift:220): one line for the advanced Sync section; none when there is nothing to show. -/
def syncStatusText : SyncPhase → Option String
  | .idle | .synced => none
  | .connecting c t => some s!"Connecting to peers ({c} of {t})…"
  | .headers s e => some s!"Headers {groupDigits s} of ~{groupDigits e}"
  | .filters s t => some s!"Filters {groupDigits (min s t)} of {groupDigits t}"
  | .peerDiscoveryFailed => some "Couldn't find filter-serving peers — check your connection."

/-- `SyncPhase.filterScanText` (AppModel.swift:193): never renders a zero as progress (#99). -/
def filterScanText (p : SyncPhase) (fallbackScanned fallbackTip : Nat) : Option String :=
  let progress : Option (Nat × Nat) := match p with
    | .filters s t => some (s, t)
    | .synced => some (fallbackScanned, fallbackTip)
    | _ => none
  match progress with
  | some (s, t) => if t == 0 then none else some s!"block {groupDigits (min s t)} of {groupDigits t}"
  | none => none

/-! ## History -/

/-- `AppModel.historyForDisplay` (AppModel.swift:1010): newest block first; a replaced transaction sorts with the one that
replaced it, the replacement first. -/
def historyForDisplay (history : List HistoryItem) : List HistoryItem :=
  let arr := history.toArray
  let position (txid : String) : Option Nat :=
    -- the last entry with this txid, like `uniquingKeysWith: { _, last in last }`
    (arr.zipIdx.foldl (fun acc (e, i) => if e.txid == txid then some i else acc) none)
  let rank (i : Nat) : Nat × Nat × Nat :=
    -- follow replacements (bounded by the length: `visited` stops cycles)
    let rec go (fuel current : Nat) (visited : List Nat) : Nat × List Nat :=
      match fuel with
      | 0 => (current, visited)
      | fuel + 1 =>
        match arr[current]?.bind (·.replacedBy) >>= position with
        | some next => if visited.contains current then (current, visited) else go fuel next (current :: visited)
        | none => (current, visited)
    let (final, visited) := go arr.size i []
    let f := arr[final]!
    let block := if f.height == 0 && f.replacedBy.isNone then 4294967295 else f.height
    (block, final, visited.length)
  let ranked := arr.zipIdx.toList.map fun (e, i) => (e, rank i)
  let sorted := ranked.mergeSort fun (_, (b1, g1, d1)) (_, (b2, g2, d2)) =>
    if b1 != b2 then b1 > b2 else if g1 != g2 then g1 > g2 else d1 ≤ d2
  sorted.map (·.1)

/-- `+1,234 sats` / `−1,234 sats` (U+2212), as HistoryRow writes the net amount (HomeView.swift:190). -/
def signedSatsText (net : Int) : String :=
  (if net ≥ 0 then "+" else "−") ++ groupDigits net.natAbs ++ " sats"

def lookup (kvs : List (String × String)) (k : String) : Option String :=
  (kvs.find? (·.1 == k)).map (·.2)

/-- `AppModel.receivedSender` (AppModel.swift:2123): the person a received payment is labelled as coming from. -/
def receivedSender (r : Records) (h : HistoryItem) : Option Person :=
  (lookup r.senderByTxid h.txid).bind fun pid => r.people.find? (·.id == pid)

/-- `AppModel.PaymentRecipient` (AppModel.swift:2168). -/
structure PaymentRecipient where
  id : Nat
  address : String
  amount : Nat
  person : Option Person
  deriving Inhabited

/-- `AppModel.paymentRecipients` (AppModel.swift:2180): the outputs of a send that are not ours, with the person each pays. -/
def paymentRecipients (r : Records) (h : HistoryItem) : List PaymentRecipient :=
  if h.spent ≤ 0 then [] else
  match h.outputs with
  | none => []
  | some outs => outs.filterMap fun o =>
    if o.ownedByWallet || o.ownedByVault then none else
    o.address.map fun a =>
      { id := o.index, address := a, amount := o.amount,
        person := (lookup r.recipientByScript o.script).bind fun pid => r.people.find? (·.id == pid) }

/-- `AppModel.LabeledReceiveOutput` (AppModel.swift:1511). -/
structure LabeledOutput where
  id : Nat
  address : String
  label : String
  amount : Nat
  deriving Inhabited

/-- `AppModel.labeledReceiveOutputs` (AppModel.swift:1523): our outputs of a received payment that carry a receive-address label. -/
def labeledReceiveOutputs (r : Records) (h : HistoryItem) : List LabeledOutput :=
  if h.received ≤ 0 then [] else
  match h.outputs with
  | none => []
  | some outs => outs.filterMap fun o =>
    if o.amount == 0 || !o.ownedByWallet then none else
    match o.address with
    | none => none
    | some a => (lookup r.receiveLabels a).map fun l => { id := o.index, address := a, label := l, amount := o.amount }

/-- `AppModel.senderCandidates` (AppModel.swift:2146): the funding addresses the payment itself reveals.
Not the same ids: Swift numbers the candidates by position among all funding scripts, but
`fundingAddresses` keeps only the scripts that render, so a non-standard script before others shifts the
ids here. -/
def senderCandidates (h : HistoryItem) : List (Nat × String) := h.fundingAddresses.zipIdx.map fun (a, i) => (i, a)

/-- HistoryRow's `title` (HomeView.swift:242): "Received from Alice", "Sent to Bob", or plain. -/
def historyTitle (r : Records) (h : HistoryItem) : String :=
  if h.net ≥ 0 then
    match receivedSender r h with
    | some p => s!"Received from {p.name}"
    | none => "Received"
  else
    match paymentRecipients r h with
    | [one] => match one.person with
      | some p => s!"Sent to {p.name}"
      | none => "Sent"
    | _ => "Sent"

/-- The distinct labels of a row, sorted, joined with " · " (HomeView.swift:180). -/
def historyLabels (r : Records) (h : HistoryItem) : String :=
  let ls := (labeledReceiveOutputs r h).map (·.label)
  let distinct := ls.foldl (fun acc l => if acc.contains l then acc else acc ++ [l]) []
  " · ".intercalate (distinct.mergeSort (fun a b => decide (a ≤ b)))

/-! ## Explorer -/

/-- `AppModel.isLoopback` (AppModel.swift:2699). -/
def isLoopback (host : String) : Bool :=
  let h := host.toLower
  h == "localhost" || h == "::1" || h == "[::1]" || h.startsWith "127."

/-! What the explorer code reads of Foundation's `URL(string:)` (RFC 3986, as measured on macOS): the
components, re-encoded the way `absoluteString` spells them (characters a component does not allow are
percent-encoded, `%` without two hex digits becomes `%25`), and `host` percent-decoded and without the
brackets of an IP literal. A string Foundation refuses (a bad scheme, a host or port with characters
they do not allow) has no URL. Hosts with non-ASCII characters (Foundation applies IDNA) are refused. -/

structure URLParts where
  /-- As written (`URL.scheme`); compare lowercased. -/
  scheme : Option String
  /-- `user[:password]@`, re-encoded, without the `@`. -/
  userinfo : Option String := none
  /-- The host as written (brackets included), none without an authority. -/
  hostText : Option String := none
  /-- `URL.host`: percent-decoded, brackets removed. -/
  host : Option String := none
  /-- The text after the host's `:` (possibly empty). -/
  port : Option String := none
  path : String := ""
  query : Option String := none
  fragment : Option String := none
  /-- Some component had to be percent-encoded: Foundation then rebuilds the string from its components,
  which drops an empty port and the leading zeros of a port. -/
  rebuilt : Bool := false
  deriving Inhabited

namespace URLText

def isAlpha (c : Char) : Bool := ('a' ≤ c && c ≤ 'z') || ('A' ≤ c && c ≤ 'Z')
def isDigit (c : Char) : Bool := '0' ≤ c && c ≤ '9'
def isHex (c : Char) : Bool := isDigit c || ('a' ≤ c && c ≤ 'f') || ('A' ≤ c && c ≤ 'F')
def unreserved (c : Char) : Bool := isAlpha c || isDigit c || c == '-' || c == '.' || c == '_' || c == '~'
def subDelim (c : Char) : Bool := "!$&'()*+,;=".toList.contains c
def pathChar (c : Char) : Bool := unreserved c || subDelim c || c == ':' || c == '@' || c == '/'
def queryChar (c : Char) : Bool := pathChar c || c == '?'
def userChar (c : Char) : Bool := unreserved c || subDelim c

def hexDigit (n : Nat) : Char := "0123456789ABCDEF".toList[n % 16]!
def hexVal (c : Char) : Nat :=
  if isDigit c then c.toNat - '0'.toNat else if 'a' ≤ c && c ≤ 'f' then c.toNat - 'a'.toNat + 10 else c.toNat - 'A'.toNat + 10

def percent (c : Char) : String :=
  String.join ((String.singleton c).toUTF8.toList.map fun b => String.ofList ['%', hexDigit (b.toNat / 16), hexDigit b.toNat])

/-- Whether a component is already well formed: `keep` characters and `%XX` escapes only. -/
def validComponent (keep : Char → Bool) (s : String) : Bool :=
  let rec go : List Char → Bool
    | [] => true
    | '%' :: a :: b :: rest => isHex a && isHex b && go rest
    | c :: rest => c.toNat < 128 && keep c && go rest
  go s.toList

/-- One component as `absoluteString` spells it: as it is when well formed, otherwise every character
outside `keep` percent-encoded (UTF-8, upper-case hex), `%` included. -/
def encode (keep : Char → Bool) (s : String) : String :=
  if validComponent keep s then s
  else String.join (s.toList.map fun c => if c.toNat < 128 && keep c && c != '%' then String.singleton c else percent c)

/-- An IP literal's inside (`[` … `]`): an address of unreserved, sub-delim and `:` characters, then
optionally a zone after `%`. A zone not introduced by `%25` or not well formed is re-encoded as
`%25` + the zone with `%` encoded (`fe80::1%en0` → `fe80::1%25en0`). None when the address part has other
characters. -/
def ipLiteral (inner : String) : Option String :=
  let (addr, zone) := match inner.toList.findIdx? (· == '%') with
    | some i => (String.ofList (inner.toList.take i), some (String.ofList (inner.toList.drop (i + 1))))
    | none => (inner, none)
  if !addr.all (fun c => c.toNat < 128 && (unreserved c || subDelim c || c == ':')) then none else
  match zone with
  | none => some addr
  | some z =>
    if z.startsWith "25" && validComponent unreserved (z.drop 2).copy then some inner
    else some (addr ++ "%25" ++ String.join (z.toList.map fun c => if c.toNat < 128 && unreserved c then String.singleton c else percent c))

/-- `%XX` escapes decoded (none when they do not decode to UTF-8). -/
def decode (s : String) : Option String :=
  let rec go : List Char → Array UInt8 → Array UInt8
    | [], acc => acc
    | '%' :: a :: b :: rest, acc =>
      if isHex a && isHex b then go rest (acc.push (hexVal a * 16 + hexVal b).toUInt8) else go (a :: b :: rest) (acc ++ "%".toUTF8.data)
    | c :: rest, acc => go rest (acc ++ (String.singleton c).toUTF8.data)
  String.fromUTF8? (ByteArray.mk (go s.toList #[]))

/-- A reg-name host: unreserved, sub-delims and well-formed escapes only. -/
def validRegName (s : String) : Bool :=
  let rec go : List Char → Bool
    | [] => true
    | '%' :: a :: b :: rest => isHex a && isHex b && go rest
    | c :: rest => c.toNat < 128 && (unreserved c || subDelim c) && go rest
  go s.toList

def splitFirst (s : String) (p : Char → Bool) : String × Option (Char × String) :=
  match s.toList.findIdx? p with
  | some i => (String.ofList (s.toList.take i), some (s.toList[i]!, String.ofList (s.toList.drop (i + 1))))
  | none => (s, none)

/-- `user[:password]` re-encoded (`@` and a second `:` are encoded). -/
def encodeUserinfo (u : String) : String :=
  match splitFirst u (· == ':') with
  | (user, some (_, pass)) => encode userChar user ++ ":" ++ encode userChar pass
  | (user, none) => encode userChar user

/-- The authority: userinfo (up to the last `@`), host (a reg-name or `[…]`), port (digits). -/
def parseAuthority (a : String) : Option (Option String × String × String × Option String) := do
  let cs := a.toList
  let (userinfo, rest) := match cs.reverse.findIdx? (· == '@') with
    | some j => (some (encodeUserinfo (String.ofList (cs.take (cs.length - 1 - j)))), String.ofList (cs.drop (cs.length - j)))
    | none => (none, a)
  let (hostText, host, portText) ← if rest.startsWith "[" then
      match splitFirst (rest.drop 1).copy (· == ']') with
      | (inner, some (_, after)) =>
        let lit ← ipLiteral inner
        if after.isEmpty then pure (s!"[{lit}]", ← decode lit, none)
        else if after.startsWith ":" then pure (s!"[{lit}]", ← decode lit, some (after.drop 1).copy)
        else none
      | (_, none) => none
    else
      match splitFirst rest (· == ':') with
      | (h, some (_, p)) => if validRegName h then pure (h, ← decode h, some p) else none
      | (h, none) => if validRegName h then pure (h, ← decode h, none) else none
  if let some p := portText then
    unless p.all isDigit do none
  return (userinfo, hostText, host, portText)

def validScheme (s : String) : Bool :=
  match s.toList with
  | c :: rest => isAlpha c && rest.all fun c => isAlpha c || isDigit c || c == '+' || c == '-' || c == '.'
  | [] => false

end URLText

/-- `absoluteString`. -/
def URLParts.render (u : URLParts) : String :=
  (u.scheme.map (· ++ ":")).getD "" ++
  (match u.hostText with
   | some h =>
     let port := match u.port with
       | some p => if !u.rebuilt then ":" ++ p else if p.isEmpty then "" else ":" ++ toString p.toNat!
       | none => ""
     "//" ++ ((u.userinfo.map (· ++ "@")).getD "") ++ h ++ port
   | none => "") ++
  u.path ++ ((u.query.map ("?" ++ ·)).getD "") ++ ((u.fragment.map ("#" ++ ·)).getD "")

open URLText in
/-- One parse of `s` into components (re-encoded), without the rebuild. -/
def parseURLOnce (s : String) : Option URLParts := do
  if s.isEmpty then none
  -- a `:` before any `/`, `?` or `#` ends a scheme, which must then be well formed
  let (head, sep) := splitFirst s fun c => c == ':' || c == '/' || c == '?' || c == '#'
  let (scheme, rest) ← match sep with
    | some (':', after) => if validScheme head then pure (some head, after) else none
    | _ => pure (none, s)
  let (beforeFrag, fragment) := match splitFirst rest (· == '#') with
    | (b, some (_, f)) => (b, some (encode queryChar f))
    | (b, none) => (b, none)
  let (beforeQuery, query) := match splitFirst beforeFrag (· == '?') with
    | (b, some (_, q)) => (b, some (encode queryChar q))
    | (b, none) => (b, none)
  if beforeQuery.startsWith "//" then
    let (authority, path) := match splitFirst (beforeQuery.drop 2).copy (· == '/') with
      | (a, some (_, p)) => (a, "/" ++ p)
      | (a, none) => (a, "")
    if authority.isEmpty then
      let u : URLParts := { scheme, hostText := some "", path := encode pathChar path, query, fragment }
      return { u with rebuilt := u.render != s }
    let (userinfo, hostText, host, port) ← parseAuthority authority
    let u : URLParts := { scheme, userinfo, hostText := some hostText, host := some host, port,
                          path := encode pathChar path, query, fragment }
    return { u with rebuilt := u.render != s }
  else
    let u : URLParts := { scheme, path := encode pathChar beforeQuery, query, fragment }
    return { u with rebuilt := u.render != s }

/-- Foundation's `URL(string:)`, as far as the explorer code reads it; none when Foundation refuses it.
A string that had to be re-encoded is rebuilt from its components and read again (so `https://:/a?%`
loses its empty host). -/
def parseURL (s : String) : Option URLParts := do
  let u ← parseURLOnce s
  if !u.rebuilt then return u
  let again ← parseURLOnce u.render
  return { again with rebuilt := true }

/-- Scheme (lowercased) and host of a URL string (`URL(string:)?.scheme`, `.host`); none when it has neither. -/
def urlParts (s : String) : Option (String × String) :=
  (parseURL s).bind fun u => match u.scheme, u.host with
    | some scheme, some host => some (scheme.toLower, host)
    | _, _ => none

/-- `URL(string:)?.host`. -/
def urlHost (s : String) : Option String := (parseURL s).bind (·.host)

/-- `AppModel.explorerBaseURL` (AppModel.swift:2710): HTTPS for any host off this device; blockstream.info
has no signet. A custom URL is kept as `absoluteString` spells it. -/
def explorerBaseURL (provider : Explorer) (custom : String) (network : Network) : String :=
  let preset (p : Explorer) : String :=
    match p, network with
    | .blockstream, .mainnet => "https://blockstream.info"
    | .mempool, .mainnet => "https://mempool.space"
    | _, _ => "https://mempool.space/signet"
  if provider == .custom then
    match parseURL custom with
    | some u =>
      match u.scheme.map String.toLower, u.host with
      | some scheme, some host =>
        if scheme == "https" || (scheme == "http" && isLoopback host) then u.render else preset .blockstream
      | _, _ => preset .blockstream
    | none => preset .blockstream
  else preset provider

/-- `AppModel.esploraBaseURL` (AppModel.swift:2692). -/
def Settings.esploraBaseURL (s : Settings) : String := explorerBaseURL s.scoped.explorer s.scoped.esploraURL s.network

/-- `URL.appending(path:)` for each part (AppModel.swift:2735): a `/` unless the path already ends in one,
before the query and fragment. The parts are path-safe (`tx`, a txid, an address). -/
def appendPath (base : String) (parts : List String) : String :=
  match parseURL base with
  | some u =>
    let path := parts.foldl (fun p part => (if p.endsWith "/" then p else p ++ "/") ++ URLText.encode URLText.pathChar part) u.path
    { u with path }.render
  | none =>
    let b := if base.endsWith "/" then (base.dropEnd 1).copy else base
    b ++ String.join (parts.map ("/" ++ ·))

/-- `esploraTransactionURL` / `esploraAddressURL` (AppModel.swift:2735, :2741). -/
def Settings.transactionURL (s : Settings) (txid : String) : String := appendPath s.esploraBaseURL ["tx", txid]
def Settings.addressURL (s : Settings) (address : String) : String := appendPath s.esploraBaseURL ["address", address]
/-- RecipientsView's `explorerHost` (RecipientsView.swift:101). -/
def Settings.explorerHost (s : Settings) : String := (urlHost s.esploraBaseURL).getD "the explorer"

/-! ## Settings rules -/

/-- `AppModel.showsNetworkPicker` / `showsManualPeers` / `showsChainVerification` / `showsExplorerSettings`
(AppModel.swift:1901, :1911–1913). -/
def Settings.showsNetworkPicker (s : Settings) : Bool := s.advancedMode || s.network != .mainnet
def Settings.showsManualPeers (s : Settings) : Bool := s.advancedMode || !s.manualPeers.isEmpty
def Settings.showsChainVerification (s : Settings) : Bool := s.advancedMode || s.verifyFromGenesis
def Settings.showsExplorerSettings (s : Settings) : Bool := s.advancedMode || !s.scoped.esploraURL.isEmpty

/-- `CharacterSet.whitespaces` (Zs and tab; Foundation counts U+200B too): the measured
`whitespacesAndNewlines` without the newlines. -/
def isWhitespace (c : Char) : Bool :=
  let n := c.toNat
  Winnow.Keys.Unicode.isWhitespaceOrNewline c && !((0x0A ≤ n && n ≤ 0x0D) || n == 0x85 || n == 0x2028 || n == 0x2029)

/-- `trimmingCharacters(in: .whitespaces)`. -/
def trimWhitespaces (s : String) : String :=
  String.ofList ((s.toList.dropWhile isWhitespace).reverse.dropWhile isWhitespace).reverse

/-- `UInt16(_:)`: an optional sign, then ASCII digits (`-` only with a zero value). -/
def parseUInt16 (s : String) : Option Nat :=
  let (neg, digits) := match s.toList with
    | '+' :: ds => (false, ds)
    | '-' :: ds => (true, ds)
    | ds => (false, ds)
  if digits.isEmpty || !digits.all URLText.isDigit then none else
  let v := digits.foldl (fun a c => a * 10 + (c.toNat - '0'.toNat)) 0
  if neg then (if v == 0 then some 0 else none) else if v > 65535 then none else some v

/-- `AppModel.parsePeer` (AppModel.swift:2555): the text trimmed of spaces (not newlines), split at `:` with
empty pieces dropped, exactly a host and a port in 1…65535; the endpoint as `PeerEndpoint.description`
spells it (`host:port`). -/
def parsePeer (text : String) : Except String String :=
  let bad := Except.error s!"Invalid peer “{text}” — use host:port."
  match (trimWhitespaces text).splitOn ":" |>.filter (!·.isEmpty) with
  | [host, port] =>
    match parseUInt16 port with
    | some p => if p == 0 then bad else .ok s!"{host}:{p}"
    | none => bad
  | _ => bad

/-! ## Labels -/

/-- `ReceiveAddressLabelStore.normalizedLabel` (ReceiveAddressLabelStore.swift:81): trimmed of
`.whitespacesAndNewlines`, at most 120 `Character`s and 480 UTF-8 bytes, no control (Cc, Cf) or newline
characters. -/
def normalizedLabel (text : String) : Except String String :=
  let label := Winnow.Keys.Unicode.trimWhitespace text
  if Winnow.Characters.count label > 120 || label.utf8ByteSize > 480 || label.toList.any Winnow.DisplayName.isControlOrNewline
  then .error "Use a single-line label of at most 120 characters."
  else .ok label

/-! ## Fees -/

/-- `SendPreview.feeProportion` with `FeeProportion.message` (AppModel.swift:1645, :1556): shown when the
fee is at least half the amount; the percentage is `Int((Double(fee) / Double(amount) * 100).rounded())`. -/
def feeProportionWarning (amount fee : Nat) : Option String :=
  if amount == 0 || fee * 2 < amount then none
  else
    let pct := ((fee.toFloat / amount.toFloat) * 100).round.toUInt64.toNat
    some (if fee > amount
      then s!"This costs more to send than it delivers: sending {satsText amount} costs {satsText fee} in fees — {pct}% of the amount."
      else s!"The fee is {pct}% of the amount: sending {satsText amount} costs {satsText fee} in fees.")

/-- Swift's `Double(_:)` on a whole string: an optional sign, then decimal digits with an optional `.` and
exponent, `0x` hex digits with an optional `.` and `p` exponent, `inf` / `infinity`, or `nan` / `snan` with
an optional `(digits)` or `(0x hex)` payload (letters case-insensitive); none otherwise. Correctly rounded. -/
def parseDouble (text : String) : Option Float := do
  let (neg, body) := match text.toList with
    | '+' :: r => (false, r)
    | '-' :: r => (true, r)
    | r => (false, r)
  let sign (f : Float) : Float := if neg then -f else f
  let lower := String.ofList (body.map Char.toLower)
  if lower == "inf" || lower == "infinity" then return sign (1.0 / 0.0)
  -- a payload is decimal digits or `0x` and hex digits
  let payload (t : String) : Bool :=
    t.all URLText.isDigit || (t.startsWith "0x" && (t.drop 2).all URLText.isHex)
  let isNaN := ["nan", "snan"].any fun p => lower == p ||
    (lower.startsWith (p ++ "(") && lower.endsWith ")" && payload ((lower.drop (p.length + 1)).dropEnd 1).copy)
  if isNaN then return (0.0 / 0.0)
  let digitsOf (p : Char → Bool) (cs : List Char) : List Char × List Char := (cs.takeWhile p, cs.dropWhile p)
  let natOf (base : Nat) (cs : List Char) : Nat := cs.foldl (fun a c => a * base + URLText.hexVal c) 0
  -- an exponent: sign and decimal digits, at least one
  let expOf (cs : List Char) : Option Int :=
    let (eneg, ds) := match cs with | '+' :: r => (false, r) | '-' :: r => (true, r) | r => (false, r)
    if ds.isEmpty || !ds.all URLText.isDigit then none
    else let v : Int := min (natOf 10 ds) 100000; some (if eneg then -v else v)
  match body with
  | '0' :: 'x' :: hexBody =>
    let (whole, rest) := digitsOf URLText.isHex hexBody
    let (frac, rest) := match rest with
      | '.' :: r => digitsOf URLText.isHex r
      | r => ([], r)
    if whole.isEmpty && frac.isEmpty then none
    let e2 : Int ← match rest with
      | [] => some 0
      | c :: r => if c == 'p' || c == 'P' then expOf r else none
    let m := natOf 16 (whole ++ frac)
    let e := e2 - 4 * frac.length
    if m == 0 then return sign 0.0
    if e > 2000 then return sign (1.0 / 0.0)
    if e < -2000 then return sign 0.0
    return sign (if e ≥ 0 then (m * 2 ^ e.toNat).toFloat else Float.ofScientific (m * 5 ^ e.natAbs) true e.natAbs)
  | _ =>
    let (whole, rest) := digitsOf URLText.isDigit body
    let (frac, rest) := match rest with
      | '.' :: r => digitsOf URLText.isDigit r
      | r => ([], r)
    if whole.isEmpty && frac.isEmpty then none
    let e10 : Int ← match rest with
      | [] => some 0
      | c :: r => if c == 'e' || c == 'E' then expOf r else none
    let m := natOf 10 (whole ++ frac)
    let e := e10 - frac.length
    if m == 0 then return sign 0.0
    let magnitude := (toString m).length + e
    if magnitude > 400 then return sign (1.0 / 0.0)
    if magnitude < -400 then return sign 0.0
    return sign (if e ≥ 0 then Float.ofScientific m false e.toNat else Float.ofScientific m true e.natAbs)

/-- A typed sat/vB rate in thousandths, as the app carries it on: the text trimmed as the field trims it
(the send override `.whitespaces`, SendView.swift:150; the bump sheet `.whitespacesAndNewlines`,
HomeView.swift:12), read by `Double(_:)` (none when that is nil), then `Real.milliOf`'s rounding (NaN and
non-positive rates are 0, huge ones saturate). -/
def parseRateMilli (text : String) (trimNewlines : Bool := false) : Option Nat :=
  let t := if trimNewlines then Winnow.Keys.Unicode.trimWhitespace text else trimWhitespaces text
  (parseDouble t).map fun rate => if rate.isNaN || rate ≤ 0 then 0 else (rate * 1000).round.toUInt64.toNat

/-- HomeView's suggested replacement rate (HomeView.swift:526: `String(format: "%.0f", ceil(rate + 1))`), from
the exact pending rate (the backend computes it before rounding the rate to thousandths for display). -/
def suggestedBumpText (rate : Float) : String := toString (rate + 1).ceil.toUInt64.toNat

/-! ## Vaults and shared savings -/

/-- `VaultThreshold.clamped` (WalletCore VaultSetup.swift:210). -/
def clampThreshold (t keyCount : Nat) : Nat := min (max t 1) (max keyCount 1)

/-- `VaultThreshold.reconciled` (VaultSetup.swift:216): adding the second signer makes the safest useful default, 2 of 2. -/
def reconcileThreshold (t previous keyCount : Nat) : Nat :=
  if previous < 2 && keyCount ≥ 2 then 2 else clampThreshold t keyCount

/-- BeginnerHomeView's `rule(of:)` (BeginnerHomeView.swift:174): who can spend, in words. -/
def vaultRule (v : VaultSummary) : String :=
  if !v.isScriptPath then s!"All {v.signerCount} signers must approve"
  else if v.threshold == 1 then s!"Any one of {v.signerCount} owners can spend"
  else s!"Any {v.threshold} of {v.signerCount} owners can spend"

/-- SharedSavingsShareView's `coOwnerNames` (SharedSavingsViews.swift:158): "Alice", "Alice and Bob",
"Alice, Bob and Carol". -/
def joinNames (names : List String) (none : String) : String :=
  match names with
  | [] => none
  | [a] => a
  | _ => ", ".intercalate names.dropLast ++ " and " ++ names.getLast!

/-- `Wallet.coinbaseMaturity`. -/
def coinbaseMaturity : Nat := 100

/-- AccountDetailView's `maturityNote` (AccountDetailView.swift:43). -/
def maturityNote (u : VaultUtxo) (tip : Nat) : String :=
  if !u.isCoinbase || u.height == 0 then "" else
  let matureAt := u.height + coinbaseMaturity - 1
  if tip < matureAt then s!" · matures in {matureAt - tip} blocks" else ""

/-- `VaultSpendSession.Line.title` (VaultSpendSession.swift:18). -/
def PayLabel.title : PayLabel → String
  | .savings n => s!"Back into {n}"
  | .person n => s!"Pays {n}"
  | .you => "Pays you (your wallet)"
  | .unknown => "Pays an unsaved address"

/-- `VaultSpendSession.approvedByYou` (VaultSpendSession.swift:74). -/
def ApprovalReview.approvedByYou (r : ApprovalReview) : Bool :=
  match r.ownPosition with
  | some p => r.approvals.contains p
  | none => false

/-- `VaultSpendSession.canFinish` (VaultSpendSession.swift:78); the caller checks `broadcastTxid`. -/
def ApprovalReview.canFinish (r : ApprovalReview) : Bool := r.lines.isSome && r.approvals.length ≥ r.threshold

/-- `VaultSpendSession.progressText` (VaultSpendSession.swift:84): "Approved by you · waiting for Alice or Bob (1 of 2)". -/
def ApprovalReview.progressText (r : ApprovalReview) : String :=
  let name (p : Nat) : String := (r.signerNames.find? (·.1 == p)).map (·.2) |>.getD "a co-owner"
  let sorted (xs : List Nat) := xs.mergeSort (· ≤ ·)
  let approved := (sorted r.approvals).map name
  let waiting := (sorted ((r.signerNames.map (·.1)).filter (!r.approvals.contains ·))).map name
  let first := if approved.isEmpty then "No approvals yet" else "Approved by " ++ ", ".intercalate approved
  let parts := if r.approvals.length < r.threshold && !waiting.isEmpty then [first, "waiting for " ++ " or ".intercalate waiting] else [first]
  " · ".intercalate parts ++ s!" ({r.approvals.length} of {r.threshold})"

/-- MuSig2SignView's `sighashLabel` (MuSig2SignView.swift:182); no review is `[]`. -/
def sighashLabel (types : List Nat) : String :=
  if types.isEmpty then "unavailable"
  else if types.all (· == 0) then "DEFAULT — all inputs commit to every output"
  else if types.all (· == 1) then "ALL — all inputs commit to every output"
  else if types.all (fun t => t == 0 || t == 1) then "DEFAULT / ALL — all inputs commit to every output"
  else "unavailable"

/-- MuSig2SignView's `locktimeLabel` (MuSig2SignView.swift:193). -/
def locktimeLabel : Option Nat → String
  | none => "unavailable"
  | some 0 => "none"
  | some n => toString n

/-- MuSig2SignView's `sequenceLabel` (MuSig2SignView.swift:198). No review is `[]` here (Swift: nil); a
reviewed spend always has inputs, so Swift's "final" for an empty list is not reachable. -/
def sequenceLabel (seqs : List Nat) : String :=
  if seqs.isEmpty then "unavailable" else if seqs.any (· < 0xFFFFFFFE) then "replaceable (RBF)" else "final"

end WinnowApp
