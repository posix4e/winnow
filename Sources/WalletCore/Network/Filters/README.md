[Back to main README](../../../../README.md)

# Private chain scanning

FilterSync asks peers for compact filters and retrieves matching blocks.
It lets the wallet find its confirmed payments without sending its addresses
to a remote indexer. Persisted progress and reorg rollback keep recovery usable.
A batch's filter headers must agree with the adopted cfcheckpt answer before
any matches are delivered. A checkpoint rejection therefore has no payment
callbacks or saved progress from that batch. A later filter, network, or
callback error can follow earlier delivered matches; the scan frontier is
saved only after all chunks finish.

Saved progress keeps sparse checkpoint boundaries plus recent filter headers,
rather than every block’s filter header. Boundary storage still grows with the
chain. Each batch persists the pinned headers a later check can ask for: every checkpoint boundary, which
the cfcheckpt comparison reads on every sync, and the recent run a reorg could
rewind into, which ends at the anchor the next batch checks a peer's answer
against. Keeping that anchor is the condition, not the goal — with no anchor to
keep, nothing is pruned at all.

A batch of up to 1000 blocks stays the span peers are cross-checked over and
the span progress is saved after, but its filters are requested a chunk at a
time and matched as each chunk lands, so a scan holds one chunk rather than a
whole batch. A caller that cannot run to the tip in one go passes `maxBlocks`
to bound a single run; the next one resumes from the saved frontier.

[The app](../../../WinnowApp/AppModel.swift) coordinates scanning with
[wallet state](../../Wallet/README.md),
[headers](../Headers/README.md), and
[peer selection](../Peers/README.md).

[FilterSync tests](../../../../Tests/WalletCoreTests/Network/FilterSyncTests.swift) and
[adversarial peers](../../../../Tests/WalletCoreTests/Network/FilterSyncAdversaryTests.swift)
exercise verification, damaged progress, disagreement, and rollback.
The [UI journey](../../../../UITests/README.md) discovers and confirms the
app's payments through the real signet node's filters.

A checkpoint comparison records a `CrossCheckReceipt`: the answer digest,
compared tip, endpoints and known acquisition source classes that actually
agreed; configuration alone is not evidence. Receipts persist atomically with
progress and clear on rollback. `CrossCheckPolicy.requireDistinctSources`
refuses a run whose agreeing peers span fewer than two known classes, and cools
off rather than bans the peers such a vote outvoted. Every network defaults to
`acceptSingleSource`, the behaviour before the policy existed, because an
overlay-only or all-manual pool can never span two classes; making the strict
policy the mainnet default needs its own change with a way for those pools to
satisfy it. Source classes describe acquisition, not independent operators or
consensus proof, and unknown provenance cannot satisfy the strict policy. The
app does not expose the policy yet.

`scanRange(from:to:watchScripts:limits:storageURL:onMatch:)` is an opt-in recovery
primitive. Its separate `RangeScanProgress` file cannot replace the forward
progress file. It never syncs headers or moves the forward frontier. Callers own
the recovery birthday, derivation expansion and fixed-point loop; one complete
pass is not proof the whole wallet has been recovered. Interrupted batches may
redeliver matches, so callbacks must be idempotent.

Default range limits are 105,120 blocks, 2,000 scripts, 64 MiB of filters plus
matched blocks, 300 seconds per run and 10 passes. Hard ceilings are 262,800
blocks, 20,000 scripts, 1 GiB, one hour and 50 passes. Exhaustion refuses rather
than claiming completion. Byte accounting can overshoot by one bounded filter
chunk plus one block; time can overshoot by one outstanding peer request or
callback. A resumed scan retains committed batches and verifies its anchor.
Ranges lacking a checkpoint boundary or an already verified anchor fail closed
except on chains shorter than the first checkpoint interval. Range scanning is
covered by [RangeScan tests](../../../../Tests/WalletCoreTests/Network/RangeScanTests.swift).
