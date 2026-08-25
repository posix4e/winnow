# Winnow: One Wallet, Two Signers, Three Roles

*A canonical design paper for Winnow, August 2026.*

## Abstract

A phone wallet is often a remote control for somebody else's wallet server. It
creates keys locally, then gives an indexer enough information to answer what
has been received, what remains unspent, what confirmed, and what should be
broadcast.

Winnow takes a different position. A phone cannot be a full validating node,
but it can verify Bitcoin's proof-of-work header chain, obtain compact block
filters from ordinary peers, match those filters locally, fetch relevant
blocks, construct and sign transactions, and relay them over the peer-to-peer
network. The same read and write path can support a custody ladder whose levels
have different failure domains:

1. **One · Personal:** one Winnow hot-wallet key for daily liquidity.
2. **Two · Independent:** Winnow and a different Bitcoin wallet, with distinct
   seeds and implementations, both authorize a spend.
3. **Three · Stewarded:** an owner, an exchange or lender, and a trust or
   fiduciary form a 2-of-3 policy for liquidity, recovery, and succession.

The ladder is not a claim that more signers are always safer. Two-of-two cannot
survive one missing key. A professional 2-of-3 can survive one missing key, but
it also allows two institutions to act without the owner. Jurisdiction,
contracts, privacy, fees, operational competence, and counterparty risk remain
part of custody.

This paper explains the design through fictional people and institutions:
Sofía Cruz and Brisa Café; Elena and Mateo Rivera; Harbor Exchange; and Ceiba
Trust. Public transaction evidence comes from Bitcoin signet, where coins have
no monetary value.

Four status words are used deliberately:

| Status | Meaning |
|---|---|
| **Implemented** | Present in current code and covered by deterministic tests. |
| **Verified on signet** | Exercised in the reproducible public-signet story and backed by public transaction evidence. |
| **Experimental** | Available only with an explicit warning and unresolved privacy or reliability constraints. |
| **Planned** | Designed or tracked, but not represented as working product behavior. |

## 1. The 1–2–3 custody ladder

The useful question is not “which single wallet should hold everything?” It is
“which independent failures should this money survive?” The smallest policy
that fits the purpose is often the safest policy a person will operate well.

### 1.1 One · Personal

**Implemented; daily payments and RBF verified on signet.**

Sofía receives customer payments and pays suppliers from one BIP86 hot wallet
on her phone. This level is fast, understandable, and appropriate for modest
balances and everyday liquidity. Its principal failure mode is equally plain:
one compromised or irrecoverably lost key can lose the funds.

The wallet is created locally. Its recovery phrase can be copied during
onboarding or later from Settings after device authentication. Creation and
backup do not wait for header synchronization. Chain history loads in the
background.

### 1.2 Two · Independently verified

**Coming soon · planned:** Taproot threshold and MuSig2 primitives are
implemented. A polished ceremony with a different wallet implementation is not
yet verified and is tracked in [issue 58](https://github.com/posix4e/winnow/issues/58).

Winnow and a different Bitcoin wallet each generate independent seed material,
derive one participant key, review the same proposed transaction, and provide
one required signature. A hardware wallet is one possible second wallet; it is
not a separate custody architecture.

The benefit comes from independence, not from owning two objects. An attacker
who learns one key still lacks a valid spend. A second wallet can independently
show the destination, amount, fee, inputs, and change before the owner approves
its signature. Shared seed material, two devices affected by the same defect,
or a common signing implementation can erase the diversity benefit.

Two-of-two has a severe availability cost: losing either unbacked-up key locks
the funds. Winnow therefore treats it as an advanced compromise-containment
option, not the universal default. A 2-of-3 is usually a better fit when the
owner also needs loss tolerance.

#### Incident case study: one weak key is still a weak key

Public reporting on the 2026 Coldcard incident attributes affected seed
generation to a weak-entropy firmware path. The incident is useful here as a
narrow model, not as a claim that any product is infallible.

In a mixed-wallet threshold whose second seed was independently generated, the
affected Coldcard key would remain compromised. The threshold would contain
that compromise because the attacker could not produce the second signature.
The second wallet would not necessarily display an attempted theft: the
absence of its signature is what stops the transaction from becoming valid.
Two affected devices, a shared seed, or a common entropy failure would defeat
that protection. This is a counterfactual security analysis, not a Winnow test
performed against the incident.

### 1.3 Three · Professionally stewarded

**Coming soon · planned:** Generic 2-of-3 construction and two signing paths are
verified on signet. Provider onboarding and institutional accounts are tracked
in [issue 53](https://github.com/posix4e/winnow/issues/53).

The Rivera cold reserve assigns three distinct roles:

- **Owner — Elena Rivera:** keeps a key in Winnow or a compatible external
  wallet.
- **Exchange/lender — Leo Santos at fictional Harbor Exchange:** supports
  temporary liquidity and operational recovery.
- **Trust/fiduciary — Marina Ortiz at fictional Ceiba Trust:** supports
  succession and legal continuity.

Any two keys satisfy the Bitcoin policy:

| Signing pair | Intended real-world meaning |
|---|---|
| Owner + exchange | Loans, collateral changes, and ordinary liquidity. |
| Owner + trust | Recovery or migration after lender obligations have cleared. |
| Exchange + trust | Inheritance when the owner is unavailable, subject to the governing agreement. |

Bitcoin enforces only two valid signatures. It does not know whether a loan was
repaid, an owner died, a beneficiary qualified, or a court acted. Those facts
come from people, contracts, and jurisdictions. Level three is Winnow's
strongest continuity option in this ladder, not “maximum safety” for everyone:
the exchange and trust can cooperate without the owner.

## 2. Independent failure domains

A signer count is not a security model. Winnow evaluates diversity across:

- seed generation and backup;
- wallet implementation and release process;
- secure hardware and operating system;
- person or institution controlling approval;
- signing transport and transaction review;
- jurisdiction and legal authority; and
- network path used to learn and submit transactions.

Two wallets built from one seed have one cryptographic failure domain. Two
brands that share a vulnerable library may have one implementation failure
domain. Three institutional signers in one jurisdiction can have a common legal
failure domain. The interface should expose these relationships rather than
reduce safety to “number of keys.”

The 1–2–3 ladder also separates purposes. Sofía's café wallet optimizes for
liquidity. A mixed-wallet 2-of-2 optimizes for compromise containment. The
owner–exchange–trust 2-of-3 optimizes for financial and legal continuity.

## 3. The phone is the constraint

A phone is intermittent. The application can be suspended, killed between
protocol rounds, moved between networks, or left offline for days. Storage,
bandwidth, battery, and continuity all matter.

Winnow adopts these boundaries:

1. **No local Bitcoin Core requirement.** The application speaks the Bitcoin
   peer protocol; the owner does not operate an RPC service for the phone.
2. **No wallet-server read path by default.** An Esplora endpoint may be chosen
   for warned human explorer links, but it does not silently supply balances,
   histories, fee estimates, discovery, or broadcast.
3. **Fresh and forward-oriented.** A new wallet scans from its creation height.
   Recovery carries public history instead of silently outsourcing a complete
   historical search.
4. **Taproot-first output policy.** The wallet receives to BIP86 Taproot and
   expresses shared custody through Taproot script and key paths.
5. **Interruption is normal where replay is safe.** Header sync, filter sync,
   PSBT exchange, broadcast, and signet waits are resumable and idempotent. A
   MuSig2 secret-nonce session is the exception: leaving before round two
   abandons it instead of persisting reusable nonce material.

The design does not claim a phone is a full node. It verifies header proof of
work and relevant block inclusion but does not execute every consensus rule for
every block.

## 4. Threat model and trust boundaries

Winnow tries to prevent a wallet service from learning a stable set of wallet
identifiers. It does not promise network anonymity or immunity from a complete
eclipse.

| Component | It may learn | It must not receive by default | Status |
|---|---|---|---|
| Bitcoin peer | IP connection, timing, public header/filter ranges, requested blocks | addresses, descriptors, scan keys, balance query | Implemented default |
| Selected explorer | IP address and the specific public item the user opens | automatic wallet history or background address queries | Implemented, warned |
| PSBT cosigner | transaction proposed for joint authorization | another signer's private key | Implemented |
| External wallet transport | public participant key, descriptor context, PSBT or signing transcript | Winnow seed or unrelated wallet history | Planned |
| Professional provider | identity and account data required by its contract, proposed transactions | another provider's private key | Planned |
| Provider directory/referral layer | choices, and possibly clicks if designed badly | recovery material or hidden behavioral tracking | Decision required |
| Selected miner | raw transaction, connection metadata, credentials, status queries | wallet history unrelated to the submission | Planned |
| Export recipient | exactly the bundle the user chooses to share | unredacted recovery material in logs or previews | Implemented |

Multiple peers reduce dependence on one view. Header synchronization tries
another connected peer when one supplies stale, malformed, invalid, or
nonconnecting headers. Successfully verified headers survive the retry. Local
storage corruption is reported separately and is not treated as a peer fault.

Compact-filter commitments are part of the P2P protocol, not Bitcoin consensus.
Comparing peers detects disagreement, and a downloaded matching block can be
checked against its header. A fully eclipsed client can still be shown one
coordinated view. Manual peer controls exist for people who want to choose a
node they trust.

## 5. Learning from Bitcoin

The standard read path is:

```text
Bitcoin peers
    → proof-of-work block headers
    → compact-filter checkpoints and filter headers
    → BIP158 basic filters
    → local script matching
    → matched full block from a peer
    → header, block-hash, and Merkle-root checks
    → wallet and vault state
```

### 5.1 Headers establish the chain

An 80-byte Bitcoin block header commits to the previous block and current
transaction Merkle root. Winnow validates header linkage, proof of work,
difficulty behavior for the selected network, and accumulated chainwork.

This happens in the background. The current tip is not required to generate a
seed, derive a receive address, or complete backup.

### 5.2 Compact filters invert the query

BIP37 Bloom-filter clients sent a personalized filter to a peer. BIP157/158
invert that relationship: a node constructs one deterministic basic filter for
each block and serves the same filter to every client. Winnow derives candidate
scripts, downloads public filters, and performs the wallet-specific match on
the phone. A full block is fetched only after a match and checked against the
proof-of-work header chain.

### 5.3 The mempool is bounded

Compact filters describe confirmed blocks, not the mempool. While a Receive
screen is open, Winnow can temporarily inspect relayed transactions for the
displayed scripts. This is an observation window, not an always-on mempool
subscription and not confirmation. The interface distinguishes “observed,”
“relayed,” and “seen in a block.”

### 5.4 Explorer access is a user action

Opening a transaction or address tells the selected explorer what was requested
and exposes the connection. Winnow lets the user choose or configure an
explorer, warns first, and permits cancellation. Explorer access is not a
hidden fast path for wallet reads.

## 6. Constructing and submitting a payment

The shipping write path begins with local UTXOs and ends at Bitcoin peers:

1. Coin selection chooses confirmed spendable outputs and creates change.
2. Review shows destination, amount, fee, feerate, inputs, and change.
3. The authenticated key store exposes signing material only while signing.
4. The signed transaction is relayed to connected Bitcoin peers.
5. Peer echoes provide propagation evidence, not confirmation.
6. Compact-filter sync later discovers the confirming block.

Winnow does not pretend to know the whole fee market without an always-on
mempool service. Its spends signal Replace-by-Fee. A fee bump spends the same
inputs at a higher fee, and history retains the original, intermediate
replacements, and final confirmed transaction. The Brisa Café signet story
verified a two-step replacement chain.

### 6.1 Coming soon: planned submission routes

Signing and submission are separate decisions. Winnow's planned modes are:

| Route | Behavior |
|---|---|
| **Bitcoin peers** | Shipping default; ordinary P2P relay. |
| **Selected miner only** | Submit to one chosen miner; never fall back silently to peers. |
| **Miner and peers** | Use both routes and label the broader disclosure. |
| **Export signed transaction** | Do not submit; hand the transaction to another system. |

Each route needs a receipt distinct from ordinary relay state: endpoint,
request identity, acceptance or rejection, response, and polling status. A
selected miner receives the raw transaction and connection metadata and may
log, reject, delay, or disclose it. Direct submission is not anonymity.

The miner API is **coming soon · planned** in
[issue 59](https://github.com/posix4e/winnow/issues/59). The first pilot is
scoped around MARA Slipstream's documented beta API, whose
published interface includes single transactions, transaction packages, status
queries, fee requirements, and support statements for RBF and CPFP. That is
research scope, not a partnership or endorsement.

## 7. Taproot shared custody

### 7.1 Two independent wallets

Winnow currently implements generic Taproot script-path thresholds and a MuSig2
key-path flow. MuSig2 participants aggregate public keys, exchange public
nonces, create partial signatures, and aggregate one Schnorr signature. Secret
nonce reuse can reveal a signing key, so Winnow keeps nonce material only in the
active session, consumes it during round two, and abandons it if interrupted.

Elena and Mateo's verified signet spend used Winnow-controlled story roles. Its
witness contained one 64-byte signature and revealed no script. It proves the
Winnow MuSig2 implementation; it does **not** prove descriptor, PSBT, transport,
or review compatibility with another Bitcoin wallet or hardware device.

The planned two-wallet ceremony must generate two independent seeds, compare
participant keys and policy on both devices, review the same transaction in
both implementations, test backup before funding, and provide a rotation path.
Coldcard NFC and microSD are initial research targets rather than implied
support.

### 7.2 Owner–exchange–trust threshold

The Rivera cold reserve uses a NUMS internal key and Taproot script leaf with a
threshold multisignature policy. Funds cannot be spent through an unknown key
path. A valid spend reveals the selected script, control block, and required
signatures.

PSBTv2 carries the unsigned transaction and metadata cosigners need. Each
participant reviews before contributing a signature. A provider integration
must add a versioned signer package, public-key validation, safe transport,
policy display, status, and an exit procedure without turning the coordinator
into a hidden authorization service.

The public-signet story completed Elena + Leo and Leo + Marina. This proves two
generic signing paths. It does not prove loan servicing, identity checks,
inheritance adjudication, or an account at a real institution.

### 7.3 Market evidence is not an endorsement

Existing firms show that pieces of this model have market demand, although
their policies and control models differ. Onramp describes multi-institution
2-of-3 custody and trust services; Debifi describes multisignature
Bitcoin-collateralized lending; Gannett Trust describes flexible key control,
fiduciary service, and succession planning; BTCBacked describes
Bitcoin-backed lending. These are attributed provider claims, not audited by
Winnow, and none is a Winnow partner or compatibility claim.

A future directory should compare role, jurisdiction, regulation, key
ownership, loan terms, rehypothecation, succession process, fees, insurance
limits, signing method, and exit procedure. Governance, corrections, removals,
referral disclosure, ranking independence, sponsored placement, and click
privacy must be decided before any marketplace ships.

## 8. Backup and replacement phones

A BIP39 phrase recreates deterministic keys. It does not recreate the answers a
forward-only mobile wallet already learned: creation height, known
transactions, replacement relationships, spent outputs, and scan frontier.

Winnow exports a versioned bundle. A watch-only form can transfer public wallet
state without spend authority. A seed-bearing form requires an explicit
authenticated choice and keeps the preview redacted. The phrase remains
copyable after authentication because recovery material must fit the owner's
chosen backup process.

On import, the replacement phone validates the bundle, reconstructs wallet
state, and verifies forward. The public-signet story matched balance, UTXO
count, history, replacement links, scan height, and peer connectivity.
Export is refused while a send is still pending: the parent inputs have
already left the UTXO set, and a forward-only restore cannot recover them
if the send never confirms. The bundle records the next unused receive and
change indices so a spent-out restore does not reissue address zero.

Public automation excludes mnemonics, entropy, private keys, secret nonces, and
unredacted recovery screens. Any export must be protected according to the
authority it carries.

## 9. Silent Payments: on the alpha branch, not in this build

BIP352 Silent Payments give a recipient a reusable code without publishing
that code or an obvious address-reuse pattern on chain. Sending is
self-contained. Receiving is not: finding payments to a silent code requires
per-block tweak data, and no public infrastructure serves it — a compact-filter
peer does not. That dependency, not the cryptography, is why the feature is not
in this build.

The implementation lives on the `alpha` branch. A wallet that has received a
silent payment can only be opened by a build from there, because the coin
carries a per-output tweak that is required to derive its signing key; a build
of this branch refuses such a wallet rather than showing a balance it cannot
spend.

## 10. Reproducible evidence

The `winnow-story` command (its own repository, github.com/posix4e/winnow-story) creates an isolated simulator run,
records scenario and tool versions, launches named roles, preserves protected
state for resume, monitors public signet, and emits a safe event journal. It
does not require Bitcoin Core, RPC credentials, or an owner-machine daemon.

The August 2026 story verified these confirmed transactions:

| Story event | Public signet transaction | Result |
|---|---|---|
| First customer payment | [`44890b72…935c0`](https://explorer.bc-2.jp/tx/44890b72d9910a4ad9390a1f1e1ade446bde809ceb1736128274199e48e935c0) | Hot wallet credited |
| Final supplier RBF | [`543a9cf3…ff65`](https://explorer.bc-2.jp/tx/543a9cf35d1db26dc8b656d78a3b6c5fe88d23b4a4710883f521f6800814ff65) | Replacement confirmed |
| Cold-reserve funding | [`0e860e41…e791`](https://explorer.bc-2.jp/tx/0e860e416d346caca681f2a1b6016f9976787c363b2a4e1178bf2c07d0ebe791) | Hot wallet fed 2-of-3 reserve |
| Elena + Leo | [`46081b3d…698a`](https://explorer.bc-2.jp/tx/46081b3dfb1f841bf5642737082cb88e376cc6f967fba2109ce55991aa0e698a) | Ordinary path confirmed |
| Leo + Marina | [`7df05a81…8cbb`](https://explorer.bc-2.jp/tx/7df05a8190ccfd3ae7f39e48118616cbe210561c74d41d7f23328e86e6028cbb) | Recovery path confirmed |
| Joint-reserve funding | [`995bedd3…761c`](https://explorer.bc-2.jp/tx/995bedd34e108a9d640ebb0c005cb1519e156059086c7349918a4e1198b4761c) | MuSig2 reserve funded |
| Elena + Mateo | [`1b126138…dc03`](https://explorer.bc-2.jp/tx/1b1261381ae44e1d3a0d99bfbc2bb9d428223a45f2a26642b0fcf7a17c51dc03) | Key-path spend confirmed |

The complete safe summary is published on the [evidence page](evidence.html).
Media stays behind human review because automated scanning cannot guarantee
that recovery words never appear in a video frame.

## 11. Limitations and non-goals

- **Not a full node.** Winnow does not validate every transaction and consensus
  rule in every block.
- **Not anonymous networking.** Peers and optional services see a connection
  unless the surrounding network adds privacy.
- **Not instant finality.** A mempool observation is not confirmation.
- **Not completed mixed-wallet onboarding.** External descriptor exchange,
  hardware transports, dual review, ceremony backup, and key rotation are
  planned.
- **Not a provider marketplace.** Winnow has no provider endorsements,
  referrals, rankings, account integrations, or production signer packages.
- **Not a custody company or legal agreement.** Software cannot authenticate
  heirs, resolve disputes, enforce loan repayment, or replace legal advice.
- **Not private-miner submission today.** P2P is the shipping broadcast path;
  selected-miner and export-only routes are planned.
- **No Silent Payment support in this build.** Both send and receive live on
  the `alpha` branch; receiving additionally depends on tweak-data
  infrastructure that does not exist publicly.
- **Not mainnet release evidence.** Signet integration does not prove readiness
  to hold valuable mainnet funds.

## 12. Implementation roadmap

[Epic 60](https://github.com/posix4e/winnow/issues/60) is the canonical program.
Each item is a public contribution surface; the external-wallet, institutional,
and miner-API issues are explicitly labeled `help wanted`:

1. [Build the 1–2–3 custody-template UX and warnings](https://github.com/posix4e/winnow/issues/54).
2. [Test descriptors and PSBTs across independent wallets](https://github.com/posix4e/winnow/issues/58).
3. [Build the two-wallet setup, signing, backup, and rotation ceremony](https://github.com/posix4e/winnow/issues/50).
4. [Research hardware transports, starting with Coldcard NFC and microSD](https://github.com/posix4e/winnow/issues/55).
5. [Build the professional owner–exchange–trust template](https://github.com/posix4e/winnow/issues/53).
6. [Specify a versioned provider signer package](https://github.com/posix4e/winnow/issues/49).
7. [Decide provider-directory governance](https://github.com/posix4e/winnow/issues/52).
8. [Decide referral disclosure, ranking, and click privacy](https://github.com/posix4e/winnow/issues/57).
9. [Add submission modes and durable receipts](https://github.com/posix4e/winnow/issues/51).
10. [Build the MARA Slipstream direct-miner pilot](https://github.com/posix4e/winnow/issues/59).
11. [Extend the reproducible story](https://github.com/posix4e/winnow/issues/56).

No provider marketplace ships until the directory and referral decisions are
recorded. P2P remains the default. New signet evidence must describe only the
flows actually performed.

## Protocol references

- [BIP141 — Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
- [BIP157 — Client Side Block Filtering](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)
- [BIP158 — Compact Block Filters for Light Clients](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
- [BIP174 — Partially Signed Bitcoin Transaction Format](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
- [BIP327 — MuSig2](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
- [BIP341 — Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP342 — Validation of Taproot Scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [BIP352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP370 — PSBT Version 2](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
- [Winnow source and test suite](https://github.com/posix4e/winnow)

## Attributed incident and market references

- [TRM Labs — Coldcard incident analysis](https://www.trmlabs.com/resources/blog/the-largest-hardware-wallet-exploit-of-2026-inside-the-usd-116-million-coldcard-hack)
- [Onramp — multi-institution custody](https://onrampbitcoin.com/products/multi-institution-custody)
- [Onramp — dynasty trust services](https://onrampbitcoin.com/products/dynasty-trusts)
- [Debifi — Bitcoin-collateralized lending](https://debifi.com/lend-bitcoin)
- [Gannett Trust — Bitcoin trust and custody](https://www.gannetttrust.com/index.html)
- [BTCBacked — Bitcoin-backed lending](https://btcbacked.com/)
- [MARA Slipstream — beta API documentation](https://slipstream.mara.com/docs/)

---

Winnow's proposition is not that a phone can eliminate trust. It is that the
wallet can make trust smaller, visible, and appropriate to the money: one key
for today's liquidity, two independent wallets to contain one compromised
implementation, and three professionally distinct roles for continuity.
