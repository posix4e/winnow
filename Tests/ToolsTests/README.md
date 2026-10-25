[Back to main README](../../README.md)

# Tests for debugging and fuzz tools

This suite checks the development tools that diagnose the GUI, derive the header
checkpoint, observe long-running scans, and replay parser failures. These tools
need tests because their output informs debugging and release decisions.

It consumes the shared [debugging implementation](../../Tools/Debug/Sources/WinnowDebug/README.md)
and [fuzz invariants](../../Tools/Fuzz/Sources/WinnowFuzzCore/README.md).
[GenerateTests](GenerateTests.swift) exercise offline generation
decisions; [OperatorCLITests](OperatorCLITests.swift) check command behavior.

Run `swift test --filter ToolsTests` from the repository root.
[FuzzRegressionTests](FuzzRegressionTests.swift) discover only
`Cases/<target>/*.bin`; READMEs are not replay inputs.
[FuzzTargetTests](FuzzTargetTests.swift) run every fuzz target on small inputs,
so the harness's own checks run under `swift test`.
[ReferenceSecp256k1Tests](ReferenceSecp256k1Tests.swift) hold the fuzz
target's second secp256k1 to BIP340's own vectors before it judges the
native module. Real-network observations
and checkpoint derivation from a full genesis-validated header file remain
separate from these deterministic tests.
