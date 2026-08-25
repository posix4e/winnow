# Limited-mainnet gate report

**Decision: NO-GO.** This report does not authorize a mainnet release, and it
is not an approval. It records what is now evidenced, what is not, and what a
person still has to decide.

| | |
|---|---|
| Reported at | `main`, `4fb8ec9` |
| Epic | [#100](https://github.com/posix4e/winnow/issues/100), handoff [#124](https://github.com/posix4e/winnow/issues/124) |
| Landed | #122, #125, #126 merged; the remaining findings closed since, most recently #156 |
| Package tests | 492 in 82 suites |
| App tests | 116, 0 failures |
| Findings | 23 recorded, 23 fixed, **0 open** |
| Invariants | 12 total: 1 evidence complete, 11 partial, **all blocked release** |
| Last revised | 2026-08-23 |

## Why this is NO-GO

One reason now, where there were three.

**The evidence that needs hardware and external systems does not exist yet.**
A Bitcoin Core node for the differential corpus cross-check, independent
wallets for mixed-implementation PSBT fixtures ([#58](https://github.com/posix4e/winnow/issues/58)),
a physical device for Keychain and screenshot behaviour, and sustained signet
runs. None of it can be produced by reading code, and none of it has been
produced.

The other two reasons have since been resolved, and are recorded here rather
than quietly dropped:

- **All findings are closed.** `SEC-016` — the wallet not rolling back after a
  reorg, the one Medium on the money path — was fixed in
  [#156](https://github.com/posix4e/winnow/pull/156) and is the last of the
  twenty-three. `SEC-005` and `SEC-017` were fixed earlier in the epic.
- **Independent review: dispositioned by the owner, 2026-08-23.** The epic
  required a reviewer that is not an agent working inside this project. The
  reviews were performed by a separate model (K3) reading the code directly,
  and it argued against its own earlier conclusions more than once — it
  withdrew a characterisation of the retry-counter clamp when shown the blast
  radius, and it found the defect that the ordering invariant in the rollback
  was violated by the code stating it. The project owner accepts that lane as
  satisfying the independence requirement.

  The limitation is recorded so the reader can weigh it: the reviewer was
  driven by the same agent that wrote the code, which chose what to submit and
  how to frame it. That shapes what a reviewer looks at. It is a materially
  stronger check than self-review and it is not the same thing as an
  uninvolved auditor, which is what [#12](https://github.com/posix4e/winnow/issues/12)
  is for.

**Eleven of twelve invariants remain partial**, and the residue is not
incidental. What is missing needs things this pass could not reach: a Bitcoin
Core node for the differential corpus cross-check, independent wallets for
mixed-implementation PSBT fixtures (#58), a physical device for Keychain and
screenshot behaviour, and sustained signet runs. The cfcheckpt majority rule
is no longer among them: it is exercised on a 1,001-block fixture (`SEC-021`).

## What is now evidenced

Fourteen findings fixed, including four found and fixed during this pass on the
authorization path itself:

| | |
|---|---|
| SEC-007 | `SendPreview.authorizes` — the last gate before broadcast — verified fee, change and inputs but **never the payment outputs**. A build paying a different script, paying one satoshi, or omitting the recipient entirely was authorized. |
| SEC-018 | The same gate never inspected silent payments at all, and did not require the reviewed outputs to exhaust the actual ones. Fixed; the residual is that the app cannot bind a derived script to the reviewed `sp1…` code without the input keys. |
| SEC-019 | Signer independence was proved by sampling one derivation coordinate. Two expressions over one account key could differ there and collide at a later address, making a threshold-2 vault impossible to finalize. Fixed by pinning the accepted descriptor shape. |
| SEC-020 | A vault's Taproot internal key was never checked, so a tampered record could carry a real key and spend a k-of-n alone. Fixed. |
| SEC-008 | `send` and `bumpFee` are `@MainActor` but release the actor at every await, so a second entry could interleave. The only protection was a disabled button. |
| SEC-009 | `Vault.init` accepted a policy repeating a signer. `tr(musig(K,K))` presented as 2-of-2 while being spendable by whoever held K alone. |
| SEC-010 | The recursive-descent descriptor parser had no depth bound; ~1,000 levels of nesting terminated the process by signal, from a path read at startup. |

Plus SEC-013, which fixes open bug #81: peer, explorer and tweak-index settings
crossed a network switch, and manual peers are dialed first — so a signet node
left configured spent a mainnet pool's opening attempts on a peer that rejects
the handshake.

Full detail, with the exact commands and their results, is in
`findings.md` and `invariant-matrix.md`.

## On the strength of the evidence

Every claim here rests on a test that was **observed failing** before it was
accepted — against a deliberately mutated implementation, or against the
pre-fix code. That discipline is the reason to trust the numbers, and twice it
caught tests that would otherwise have been counted as evidence while checking
nothing:

- A fee-rate bound test asserted "some `CoinSelectionError`". Removing the
  bound still threw, as a *different* case, so the mutation killed nothing. The
  bound had no test defending it.
- A peer-disagreement test asserted "some `FilterSyncError`", and the mutation
  again killed nothing — which revealed that the cfcheckpt majority rule
  **never engages below height 1000**, and the defence actually exercised was
  the cfheaders cross-check. That gap is recorded rather than papered over.

A mutation that kills no test means the test is weak, not that the code is
safe. Both assertions were tightened; both now fail against their mutation.

## Two decisions that were yours — both now made

Neither is a defect. Both are judgement calls that were made explicit rather
than left implicit, and either could reasonably have been decided the other
way. Both were accepted by the owner on 2026-08-23, with the reasoning and the
residual exposure recorded here rather than resolved by silence.

**The single-peer eclipse — decided by the owner, 2026-08-23: accept.** With
one peer there is nobody to compare against, so a self-consistent lying
filter-commitment chain is accepted and the user has no indication of it.
Failing closed would strand anyone whose network reaches one peer, and that
was judged the worse outcome: a wallet that refuses to sync is a wallet nobody
can use, and the eclipse it protects against requires an attacker already
positioned to be that one peer.

The mitigation is therefore *peer diversity rather than refusal* — reaching
more independent peers cheaply, so the one-peer case is rare instead of
tolerated. That work is [#3](https://github.com/posix4e/winnow/issues/3) and
[#4](https://github.com/posix4e/winnow/issues/4), and this decision makes them
the response to the risk rather than an alternative to it. Current behaviour
stays pinned by test as *documented*, and is now also *endorsed, with a named
mitigation*.

**Clipboard reach — decided by the owner, 2026-08-23: accept.** Descriptors and
PSBTs may still cross to another device via Universal Clipboard. A descriptor
carries xpubs, so whoever holds it can derive every address the vault will ever
use.

Interchange is kept because pasting a watch-only descriptor into Bitcoin Core is
the workflow those buttons exist for, and the alternative costs the user a file
transfer for the one operation that most wants to be easy. The mitigation
already in place is expiry: interchange material does not sit on the clipboard
indefinitely. Forcing local-only remains a one-line change to
`ClipboardPolicy.interchange` if the workflow cost is ever judged worth paying.

What the reader should weigh: this accepts that a descriptor can reach any
device signed into the same Apple account, which is a real exposure and not a
theoretical one. It is accepted because the material is watch-only — it reveals
every address, and it spends nothing.

## What a GO would require

1. ~~An **independent** reviewer — not an agent in this project — on one exact
   integration commit, with findings remediated or dispositioned.~~
   **Dispositioned by the owner, 2026-08-23**, with the limitation recorded
   above.
2. ~~SEC-016 resolved: a wallet rollback consuming `lastReorg`, or an explicit,
   written acceptance of the risk.~~ **Done** — [#156](https://github.com/posix4e/winnow/pull/156).
3. ~~SEC-005 and SEC-017 closed, or dispositioned with an owner and a date.~~
   **Done** — both fixed.
4. **Substantially reduced, still outstanding.** Most of what this condition
   named now exists, and producing it found five defects that no amount of
   reading would have surfaced — `SEC-024` through `SEC-028`.

   - *Node-backed differential runs:* the fixture had been **unrunnable**, its
     BIP325 challenge key lost with a workstation. It is rebuildable from the
     repository now (`scripts/signet-fixture`), and rebuilding it from genesis
     exposed three defects invisible on an established chain. The corpus is a
     seeded sweep cross-checked field-by-field against Core rather than three
     hand-written transactions.
   - *Mixed-wallet PSBT fixtures:* **done for script-path.** Bitcoin Core holds
     one key of three in a `tr(NUMS, sortedmulti_a(2,…))` vault and co-signs a
     spend that confirms — #58's acceptance bar. The envelope conversion every
     Core exchange forces is proven lossless. **MuSig2/BIP390 reaches round 1 and stops:** Core
     contributes a BIP373 nonce, but keys it by the tweaked output key
     where we key by the root aggregate, so neither side can consume the
     other's. Named, pinned by test, and not inferred from the
     script-path result.
   - *Device Keychain and screenshot checks:* the simulator half is done and
     the claims are observations now rather than readings. **The hardware half
     is not, and cannot be:** that iOS enforces the protection class when the
     device locks, and that its app-switcher snapshot contains the cover, are
     platform behaviours a simulator has no data protection, no Secure Enclave
     and no snapshot to show. Those need the phone.
   - *Sustained signet:* two runs, the second 90 minutes with 88 at chain tip,
     timeseries committed. It found `SEC-024` within the first hour. A third
     run starting at tip holds resident size between 13 MB and 36 MB. That
     is 110 minutes of at-tip observation, which supports a claim about
     hours and not about days — and days will need the `node-e2e` runner,
     because two multi-hour attempts were killed by the environment here.

   What is left is genuinely the hardware: on-device Keychain enforcement,
   screenshot and lifecycle behaviour, and runs long enough to speak about days.
   Crash-during-write is deliberately **not** among them — every store writes
   atomically or through the fsync-ordered append path, and the consequences of
   a damaged file are already evidenced by the storage-corruption, append,
   quarantine and rollback-marker suites. A racy process-kill test would add
   noise, not evidence.
5. ~~The two judgement calls decided, or recorded as open.~~ **Done** — the
   single-peer eclipse and the clipboard reach were both dispositioned by the
   owner on 2026-08-23, and both are written up above with their reasoning.

**Four is now the only thing standing between this report and a different
verdict.** It needs a person and hardware, and it cannot be closed by writing
more code.

## Human decision required

This report recommends **NO-GO** and does not make the decision. The mainnet
release decision belongs to the project owner, on evidence, not to the process
that produced this document.
