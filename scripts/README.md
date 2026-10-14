[Back to main README](../README.md)

# Build, test, and debugging entry points

These scripts connect the repository's code to Xcode, SwiftPM, disposable test
nodes, the website, reporting, and release tooling. They provide shared commands
for contributors and CI without duplicating the wallet implementation.

[The workflows](../.github/workflows/README.md) are their primary automated
consumers. [CI/release operations](../.github/internal/ci-release.md) and
[debugging](../Tools/Debug/README.md) explain how to use them.
`signet-fixture` starts disposable test nodes. Combined CI uses GitHub-hosted
Apple silicon (`macos-26`), with a fresh fixture and per-run build products.
Local development can still use an optional prepared-bank snapshot.

[ci-journey-cache](ci-journey-cache) hashes test and build inputs and finds a
successful same-repository run's reusable journey media. Website-only changes
can skip compilation and wallet tests when that evidence exists; app-bundled
HTML/CSS remains part of the inputs. Missing artifacts or API errors run fresh
checks. Manual, nightly and release runs always run fresh.

[ci-ui-journey](ci-ui-journey) builds and runs the one iPhone integration
journey against the configured signet fixture. Before simulator boot, recording,
or XCTest, it runs `swift run winnow-fixture prepare-bank` and saves the output
to `fixture-prepare.log` in the journey results directory. This native Debug
build reuses earlier SwiftPM build products. The command uses the shared
`SignetFixture`, `BitcoinCLI`, and `SignetMiner` helpers; a fresh CI fixture
still mines 101 blocks without a bank snapshot from another run.

The script records one continuous `journey.mp4` alongside the test's checkpoint
screenshots, logs, and result
bundle. The journey covers ordinary-wallet, MuSig2, and 2-of-3 payments;
Core wallets provide the other signing keys. There is no separate differential
test launcher or CI job.

Host preparation reports `SIGNET_BANK_PREPARATION_SECONDS`; XCTest's
`SIGNET_SETUP_SECONDS` now measures only chain and bank readiness checks.
CI performs mining in the existing fixture initialization step, bounded to five
minutes, and retains its output as `bank-setup.log`. The recording script then
checks readiness without mining again. The recorded journey retains its
15-minute step limit and 600-second XCTest limit.

CI's single `build` job runs package, fuzz, lint and release checks. For a fresh
test run it builds the Debug app and both test runners once, then calls
[ci-app-tests](ci-app-tests) and `ci-ui-journey` with separate fresh results
directories and `--skip-build`. Both require the shared `SIMULATOR_ID` and
`DERIVED_DATA` environment variables in this mode. Without `--skip-build`,
each script still builds what it needs for standalone local use. The recorded
journey requires the signet fixture configuration described in
[the UI test guide](../UITests/README.md).

[prepare-site-artifact](prepare-site-artifact) normalizes a successful journey
with `--normalize-journey <results> --media-output <directory>`. The bundle
contains the normalized movie, 16 checkpoint images, and original recording
provenance. `--validate-media <bundle>` validates retained evidence. Website
sources, builds, and deployment are owned by winnowwallet/website.

[Python regressions](tests/README.md) cover media reuse, evidence normalization,
artifact preparation, App Store status parsing, and release policy.
Signing/submission commands have external effects;
their workflow runbooks identify when they are used.
Run commands from the repository root unless their help specifies otherwise.

## Tool index

Run shell/Python entry points as `scripts/<name>` from the repository root.
The two `.swift` scripts below require `swift scripts/<name>.swift`. Build
outputs, signing material and diagnostic captures stay outside committed source.
The [debug CLI](../Tools/Debug/README.md), [fuzz harness](../Tools/Fuzz/README.md),
and [native fixture](../Tools/Fixture/README.md) are the three Swift executables.

### Build and validation

| Entry point | Inputs and purpose | Effects / caller |
| --- | --- | --- |
| [check-dependencies](check-dependencies) | Optional `--xcode DERIVED_DATA`; compare package and Xcode resolutions with the root lockfile. | Reads manifests/build state; CI and release. |
| [check-live-gateways](check-live-gateways) | No arguments; live discovery and Bitcoin handshakes through the tailnet gateways with peers from the shipped census list. | Manual, from a Mac on that tailnet; CI has no tailnet. Sends no wallet data. See [peer gateways](../docs/peer-gateways.md). |
| [check-live-gateways-ui](check-live-gateways-ui) | `<Xcode destination> <new evidence directory>`; live gateway journey on a device or simulator on the tailnet. | Manual; records `LiveGateways.xcresult` screenshots. Disposable mainnet wallet, nothing sent. |
| [check-test-gates](check-test-gates) | No arguments; check environment gates, deliberate skips, and retired flags. | Source check in CI’s build job; does not execute tests. |
| [check-swift-warnings](check-swift-warnings) | `BUILD_LOG`; reject compiler warnings under `Sources/` and `SoakCommand.swift`. | Reads a log; it does not compile or prove a build succeeded. |
| [ci-production-warnings](ci-production-warnings) | Optional `SCRATCH_PATH [LOG_PATH]`; Release-build `winnow-debug`, check warnings and lockfile drift. | Compiles package code. Use a fresh scratch path for meaningful warning evidence. |
| [ci-tailnet](ci-tailnet) | No arguments; builds a private tailnet (Headscale, a TUN client, two userspace gateway nodes) and runs `TailnetSimulationTests` against it. | Needs Go and sudo; the parallel CI's `tailnet` lane on a disposable macOS runner. Disturbs Tailscale on a developer Mac. |
| [ci-debug](ci-debug) | No arguments; exercise wrapper help and environment checks from outside the checkout. | Builds/runs the debug CLI; lists simulators without launching one. |
| [ci-app-tests](ci-app-tests) | `FRESH_RESULTS_DIR [--skip-build]`; app tests in the iOS host. | Builds/uses a simulator; see shared-build setup above. |
| [ci-ui-journey](ci-ui-journey) | `FRESH_RESULTS_DIR [--skip-build]`; the one recorded payment journey. | Uses the fixture and simulator, mines blocks, and writes test/media artifacts. |
| [install-xcodegen](install-xcodegen) | No arguments; fetch checksum-pinned XcodeGen. | Installs under runner/temp storage; sets CI’s path or prints the local executable path. |
| [ios-simulator](ios-simulator) | Optional `iPhone` or `iPad`; print an available device ID from the newest installed iOS runtime, or from `IOS_SIMULATOR_RUNTIME` when set. | Selection only; does not boot, create, or erase a simulator. |
| [verify-release-e2e-exclusion](verify-release-e2e-exclusion) | `APP_BUNDLE_OR_EXECUTABLE`; reject known test-activation markers. | Inspects an already-built binary; CI and release. |

### Website and local development

| Entry point | Inputs and purpose | Effects / caller |
| --- | --- | --- |
| [ci-journey-cache](ci-journey-cache) | CI environment identifies the event, revision and repository. | Queries GitHub for matching successful media; writes CI outputs. See the reuse policy above. |
| [prepare-site-artifact](prepare-site-artifact) | `--normalize-journey DIR --media-output DIR` or `--validate-media DIR`. | Normalizes or validates wallet recording evidence; no website build. |
| [winnow-debug](winnow-debug) | `inspect`, `doctor`, `diagnostics`, `generate checkpoint`, `soak`; see its [runbook](../Tools/Debug/README.md). | Inspection is offline; diagnostics writes captures; soak contacts peers. |
| [refresh-checkpoint](refresh-checkpoint) | `HEADERS_FILE [HEIGHT]`; derive and validate a boundary checkpoint. | Writes a test vector and prints a source literal for review; does not automatically edit app constants. See the [runbook](../Tools/Generate/README.md). |
| [signet-fixture](signet-fixture) | `up`, `down`, `status`, `snapshot DIR`, `destroy`. | Manages the configured local node; `destroy` deletes its data. No argument defaults to `up`. See the [UI setup](../UITests/README.md#run-locally). |
| [make-icon.swift](make-icon.swift) | `OUTPUT.png` (default `icon.png`); render the icon with macOS graphics APIs. | Writes the requested PNG; inspect it before replacing the app asset. Not a CI generator. |

### Release helpers

Prefer the [hosted workflows](../.github/internal/ci-release.md#release) for
publishing. The helper names below are not additional release pipelines.

| Entry point | Inputs and purpose | Effects / caller |
| --- | --- | --- |
| [import-census](import-census) | Optional census commit (default: the census's `main`); fetch its `census/peers.json` with the commit beside it. | Network fetch; writes `build/census/`, which project.yml bundles. Run before XcodeGen; CI and release do. |
| [check-release-policy](check-release-policy) | `RELEASE_TAG=vMAJOR.MINOR.PATCH`; validate stable tag syntax. An unset value supports manual validation. | No network or source generation; release workflow. |
| [generate-supply-chain-metadata](generate-supply-chain-metadata) | `--output-dir DIR`, optional `--subject PATH`, `--subject-name NAME`, `--builder-id ID`. | Writes SPDX/provenance JSON for a Git tree or built artifact; no upload or signing. CI and release retain it as artifacts. |
| [ci-sign.sh](ci-sign.sh) | `ASC_PRIVATE_KEY`; write the API key file under runner/temp storage. | Writes sensitive signing material; release/recovery workflows provide and clean it up. Certificate import is a separate release step. |
| [asc-jwt.swift](asc-jwt.swift) | `KEY_PATH KEY_ID ISSUER_ID`; create a short-lived App Store Connect token. | Reads a private key and prints a bearer token. Internal helper of `testflight.sh`; do not log its output. |
| [testflight.sh](testflight.sh) | Explicit operation plus ASC credentials and build/version selectors; see below. | Reads or changes App Store Connect according to the operation. |
| [testflight-feedback](testflight-feedback) | `OUT [--limit N]` plus ASC credentials; pull TestFlight screenshot and crash feedback. | Reads tester comments, emails and device details; prints counts only. The TestFlight feedback workflow encrypts its output before upload. |

`testflight.sh` requires `ASC_KEY_ID`, `ASC_ISSUER_ID`, and the key at
`ASC_KEY_PATH` (default `~/.appstoreconnect/private_keys/AuthKey_<id>.p8`).
Select an existing build with `TESTFLIGHT_BUILD_ID`, or both
`TESTFLIGHT_MARKETING_VERSION` and `TESTFLIGHT_BUILD_NUMBER`. With neither,
its legacy fallback selects the latest upload; release/recovery workflows pass
an exact version and build number.

- `status` and `appstore-status` read remote state; the latter also validates
  metadata and may exit nonzero for missing fields.
- `wait-processing` waits for processing; `notes`, `internal`, and `external`
  update TestFlight notes/groups. External distribution can require beta review.
- `upload` sends `build/WinnowApp.ipa`. `register-bundle-id` and `create-app`
  are initial account setup operations. `all` runs those setup steps, upload,
  processing, notes and group assignment. **No argument defaults to `all`.**
- `appstore-attach` and `appstore-notes` change an existing editable App Store
  version, selected by `APPSTORE_VERSION_ID` or `APPSTORE_VERSION_STRING`.
  They do not create a version record or withdraw an approved submission.
  Notes default to `docs/appstore-whats-new.txt`; TestFlight notes default to
  `docs/testflight-what-to-test.txt`.
- `appstore-submit` requires `APPSTORE_CONFIRM_SUBMIT=yes` and submits that
  version for review. Submission is not approval or publication. In the hosted
  submission workflow, `submit=false` still attaches a build and writes notes;
  only `status_only=true` is read-only.

The old story/demo publisher, standalone differential launcher, LOC reporter,
and bundled-peer generator/crawler are retired. Their replacement or historical
status is documented in the [debug runbook](../Tools/Debug/README.md#removed-commands)
and [test-suite map](../docs/security/test-suite-map.md).
