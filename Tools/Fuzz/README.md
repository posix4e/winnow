[Back to main README](../../README.md)

# Deterministic fuzzing

The harness covers fourteen parsing surfaces: PSBT, descriptors, transactions,
blocks, wire messages (including `addr`), framing, filters, addresses, import
bundles, the census catalog, DNS-over-HTTPS answers, funding
sources, Taproot control blocks, and person cards and pastes. It
uses the local Bitcoin modules as a development target in the root package.
Parsers in the app target (`PeopleStore`, `ReceiveAddressLabelStore`,
`SealedStoreFile`) and WalletCore's internal `PersistedPeers` are out of its
reach; AppTests and the package suite feed those hand-written hostile inputs.
It is excluded from the app target and counted as test code.

From the repository root, run the fixed-seed fuzz smoke campaign:

```sh
swift run --configuration release WinnowFuzz \
  --iterations 1000 --seed 0x57494e4e4f575055 --max-input 16384 \
  --artifact-dir /tmp/fuzz-smoke
```

Every iteration exercises all fourteen targets, so this runs 14,000 deterministic
cases. Use `--target psbt` (or another target name) to focus a run. Keep the
target selection, seed, input limit, and iteration count when replaying.

CI runs the fixed-seed campaign for PRs, main, and Winnow releases. The separate weekly
and manually dispatched lanes run 25,000 iterations per sanitizer with
distinct rotating seeds: 350,000 cases under Address Sanitizer and another
350,000 under Thread Sanitizer (25,000 × 14 targets). A manual `replay_seed` input reproduces a
recorded seed. For example, replay an address-sanitized run locally with:

```sh
swift run --scratch-path /tmp/fuzz-address-build \
  --configuration release --sanitize address WinnowFuzz \
  --iterations 25000 --seed 0x57494e4e4f575055 --max-input 65536 \
  --artifact-dir /tmp/fuzz-address
```

Use `--sanitize thread` and a separate scratch path for Thread Sanitizer.
CI records `seed.txt` before starting and uploads it with `run.log`; detected
invariant failures also save the input bytes.

## Attributing a crash

A trap (a force unwrap, an index out of range) never reaches the reproducer
path, and because the targets interleave within each iteration the log alone
cannot say which case was running. Two things narrow it down:

- The run prints one `fuzzing target=… seed=… iterations=… max-input=…` line
  per target before it starts, written unbuffered so the lines survive a trap
  even through a pipe.
- With `--artifact-dir`, the harness overwrites `in-flight.txt` in that
  directory before every case with one line such as
  `target=psbt seed=0x57494e4e4f575055 iteration=734 targets=all max-input=16384`
  and deletes it on clean completion. After a crash or a timeout, the file
  names the case that was running.

Replay with the same `--target` selection (`targets=`), `--seed`, and
`--max-input`. Every target in a run draws from one generator, so narrowing
`--target` afterwards changes the inputs. `--iterations` can be trimmed to the
recorded iteration plus one, since the run stops at the crashing case anyway:

```sh
swift run --configuration release WinnowFuzz \
  --target all --seed 0x57494e4e4f575055 --max-input 16384 --iterations 735
```

## Keeping a finding

An invariant failure saves its input as `<target>-<seed>-<iteration>.bin` in
the artifact directory and prints where it went. Copy that file to
`Tests/ToolsTests/Cases/<target>/` (any name, `.bin` extension), and
`swift test --filter FuzzRegressionTests` replays it under the same per-target
invariant on every run; a trap there fails the test process, which is the
point. The invariants live in `WinnowFuzzCore`, so the harness and the
regression tests cannot drift apart. The corpus starts with the compactSize
prefix and PSBT map-order findings that also exist as hand-written tests.

The source and embedded corpus were migrated unchanged from revision
`0f051dadc94f99355577632b0cc8c30c9357d8a1` of the former harness repository.
They remain covered by the repository's MIT license.

[Execution and artifacts](Sources/WinnowFuzz/README.md) and
[shared invariants](Sources/WinnowFuzzCore/README.md) explain the two source targets.
