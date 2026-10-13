[Back to main README](../../../../README.md)

# Shared parser fuzz invariants

Exercise.swift defines seeded generation and invariants for PSBTs, descriptors,
transactions, blocks, wire messages, framing, filters, addresses, import bundles,
census documents, DNS answers, funding sources, Taproot control
blocks, and person cards/pastes. The [runbook](../../README.md) lists the
fourteen targets and the app-owned stores outside this harness.
It checks hostile inputs against the same parsers used by the wallet.

The [fuzz executable](../WinnowFuzz/README.md) and
[FuzzRegressionTests](../../../../Tests/ToolsTests/FuzzRegressionTests.swift) both consume
this development-only target. Sharing the invariant avoids a separate replay
implementation that could disagree with the original failure.

Run `swift test --filter FuzzRegressionTests` for saved inputs, or follow the
[fuzz runbook](../../README.md) for a seeded campaign.
Keep invariant changes reviewable: weakening an assertion changes what both
campaigns and saved regressions can detect.
