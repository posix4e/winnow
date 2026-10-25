[Back to main README](../../../../README.md)

# PSBT map-order regression

map-order.bin retains a PSBT encoding whose map ordering exposed a parser or
round-trip assumption. Keeping the input protects imported signing
requests against a recurrence of that failure.

[FuzzRegressionTests](../../FuzzRegressionTests.swift) replays this
`.bin` file through the shared
[PSBT fuzz invariant](../../../../Tools/Fuzz/Sources/WinnowFuzzCore/README.md).
Documentation files are not part of the replay corpus.

The [fuzz runbook](../../../../Tools/Fuzz/README.md) records the corpus's origin and the
procedure for retaining investigated failures. Keep exact reproducer bytes and
their target; use `swift test --filter FuzzRegressionTests` to verify a change.
A single saved input is a regression check, not exhaustive PSBT coverage.
