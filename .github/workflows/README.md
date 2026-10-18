# Workflows

[CI and release operations](../internal/ci-release.md) is the operating runbook.
[Testing](../../docs/testing.md) explains what the suites establish.

| Workflow | Purpose |
| --- | --- |
| [ci.yml](ci.yml) | Select parallel validation or hosted fallback; require the selected result |
| [ci-parallel.yml](ci-parallel.yml) | Verify reusable evidence or execute package, build, units, journey and tailnet lanes on disposable WarpBuild Macs |
| [ci-hosted.yml](ci-hosted.yml) | Combined GitHub-hosted validation for fork PRs or the manual hosted option |
| [release.yml](release.yml) | Manual validation, or signing/TestFlight/GitHub publishing after a stable tag push |
| [testflight-recover.yml](testflight-recover.yml) | Finish processing, notes and the internal group for an exact existing version/build; external review when ticked |
| [appstore-submit.yml](appstore-submit.yml) | Inspect or change a selected App Store version and optionally submit it |
| [testflight-feedback.yml](testflight-feedback.yml) | Fetch tester feedback into an encrypted artifact |
| [fuzz.yml](fuzz.yml) | Fixed-seed fuzz smoke on every pull request and main push; weekly or manual sanitizer runs with rotating seeds |

Parallel validation builds the Debug app and test runners once. Units and
journey consume verified copies on separate runners and simulators. Build also
checks ARM64 Release; package owns the SwiftPM, lint and dependency gates.
Tailnet runs discovery and routing against disposable Headscale clients and
controlled gateway services. The hosted fallback combines its checks in one
`build` job. Fork PRs omit the signet journey and deployment credentials.

The parallel lane artifacts contain logs and result bundles; `lane-debug-…`
contains transferred build products, and `validation-<fingerprint>` contains
complete reusable evidence. Hosted runs retain `app-tests-<run>-<attempt>`.
Fuzz is its own check and never part of that evidence: the smoke retains
`fuzz-smoke-<run>-<attempt>` and the sanitizer runs `fuzz-<sanitizer>-<run>`,
each with the run log, the seed and any saved reproducer.
Manual and nightly runs force fresh tests. Other eligible runs, including tag
releases, can reuse matching evidence up to seven days old. See the runbook for
validation identity, artifact details and limitations.

Wallet CI normalizes journey media with its original source and run provenance.
The public website and deployment are maintained in
[winnowwallet/website](https://github.com/winnowwallet/website).
