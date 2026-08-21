# Limited-mainnet gate report

**Decision: NO-GO.** This report does not authorize a mainnet release, and it
is not an approval. It records what is now evidenced, what is not, and what a
person still has to decide.

| | |
|---|---|
| Reported at | `claude/security-gate-100`, on top of `codex/security-hardening-integration` |
| Epic | [#100](https://github.com/posix4e/winnow/issues/100), handoff [#124](https://github.com/posix4e/winnow/issues/124) |
| Draft PRs | #122 (parser/fuzzer), #125 (CI/provenance), #126 (this work) — none merged |
| Package tests | 420 in 74 suites |
| App tests | 67, 0 failures |
| Findings | 17 recorded, 14 fixed, **3 open** |
| Invariants | 12 total: 1 evidence complete, 11 partial, **all blocked release** |

## Why this is NO-GO

Three reasons, in order of how much they matter.

**No independent review exists.** Every review row in the invariant matrix is
marked *not independent*, because every one was produced by an agent working
inside this project. The epic's own acceptance criteria require an independent
reviewer on one exact commit, and nothing here substitutes for that. An agent
reviewing work it produced is a consistency check, not a second opinion.

**Three findings are open**, one of them Medium and on the money path:

- **SEC-016 (Medium)** — the wallet does not roll back after a chain reorg. It
  scans forward from `nextScanHeight` and never revisits a passed height, so a
  reorg that removes an already-credited block leaves a payment recorded as
  confirmed and a coin recorded as spendable when neither is true on chain.
  Short reorgs are ordinary on mainnet. `HeaderChain.lastReorg` now reports the
  fork so the gap is closeable, but nothing consumes it. **Deliberately left
  open:** the fix drops coins and confirmations and rewinds the scan frontier,
  which is money-path surgery that belongs in front of a person.
- **SEC-005 (Medium)** — `ci.yml`'s `package-tests` runs fork pull-request code
  on the persistent self-hosted runner. `site.yml` already carries the guard it
  needs.
- **SEC-017 (Low)** — the scheduled sustained fuzz run pins a constant seed, so
  every weekly run repeats the same 25,000 iterations.

**Eleven of twelve invariants remain partial**, and the residue is not
incidental. What is missing needs things this pass could not reach: a Bitcoin
Core node for the differential corpus cross-check, independent wallets for
mixed-implementation PSBT fixtures (#58), a physical device for Keychain and
screenshot behaviour, sustained signet runs, and a chain above height 1000 to
exercise the cfcheckpt majority rule at all.

## What is now evidenced

Fourteen findings fixed, including four found and fixed during this pass on the
authorization path itself:

| | |
|---|---|
| SEC-007 | `SendPreview.authorizes` — the last gate before broadcast — verified fee, change and inputs but **never the payment outputs**. A build paying a different script, paying one satoshi, or omitting the recipient entirely was authorized. |
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

## Two decisions that are yours

Neither is a defect. Both are judgement calls that were made explicit rather
than left implicit, and either could reasonably be decided the other way.

**The single-peer eclipse.** With one peer there is nobody to compare against,
so a self-consistent lying filter-commitment chain is accepted and the user has
no indication of it. Failing closed would strand anyone whose network reaches
one peer. Current behaviour is pinned by test as *documented*, not endorsed.

**Clipboard reach.** Descriptors and PSBTs may still cross to another device via
Universal Clipboard, because pasting a watch-only descriptor into Bitcoin Core
is the workflow those buttons exist for. A descriptor carries xpubs, so whoever
holds it can derive every address the vault will ever use. Interchange material
now expires; forcing local-only is a one-line change to
`ClipboardPolicy.interchange` if you would rather take the workflow cost.

## What a GO would require

1. An **independent** reviewer — not an agent in this project — on one exact
   integration commit, with findings remediated or dispositioned.
2. SEC-016 resolved: a wallet rollback consuming `lastReorg`, or an explicit,
   written acceptance of the risk.
3. SEC-005 and SEC-017 closed, or dispositioned with an owner and a date.
4. The evidence that needs hardware and external systems: node-backed
   differential runs, mixed-wallet PSBT fixtures, device Keychain and
   screenshot checks, sustained signet.
5. A decision on the two judgement calls above.

## Human decision required

This report recommends **NO-GO** and does not make the decision. The mainnet
release decision belongs to the project owner, on evidence, not to the process
that produced this document.
