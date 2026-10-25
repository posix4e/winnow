[Back to main README](../README.md)

# Build, test, and debugging entry points

These scripts connect the wallet to Xcode, SwiftPM, disposable test fixtures,
evidence handling and release operations. Run from the repository root unless
an entry point says otherwise. [CI and release operations](../.github/internal/ci-release.md)
describes the automated calls; [testing](../docs/testing.md#run-locally) and
[UI setup](../UITests/README.md#run-locally) give local commands.

[ci-validation](ci-validation) verifies complete reusable CI evidence for
matching inputs and policy, up to seven days old. Unbundled documentation can
leave the fingerprint unchanged; app-bundled HTML/CSS participates in it.
Missing or invalid evidence runs fresh checks. Manual and nightly runs force
fresh validation; tag releases may reuse eligible evidence. The underlying
[ci-journey-cache](ci-journey-cache) provides fingerprint and media helpers.

Parallel CI uses [ci-lane](ci-lane) for package, build, units and journey, plus
[ci-tailnet](ci-tailnet) for controlled gateway routing. These scripts orchestrate
disposable runners. Build publishes Debug products; units and journey verify
and use them on separate runners and simulators. The hosted fallback combines
its build and checks in one job. Each fresh journey uses a new signet fixture;
local development can use an optional prepared-bank snapshot.

[ci-app-tests](ci-app-tests) and [ci-ui-journey](ci-ui-journey) can build their own
products for local use. Their `--skip-build` mode requires `SIMULATOR_ID` and
`DERIVED_DATA` pointing to prepared products. The journey prepares the native
fixture bank before XCTest, records one continuous `journey.mp4`, and retains
checkpoint screenshots, logs and the result bundle. It covers one ordinary
receive, send and confirmation. See the
[UI test guide](../UITests/README.md) for timing fields and fixture setup.

[prepare-site-artifact](prepare-site-artifact) normalizes a successful journey
with `--normalize-journey <results> --media-output <directory>` and validates a
retained bundle with `--validate-media <bundle>`. It preserves the original
recording source and run. Website sources and deployment live in
[winnowwallet/website](https://github.com/winnowwallet/website).

[Python regressions](tests/README.md) cover evidence validation, media handling,
App Store status parsing and release policy. Signing and submission helpers
perform the external operations named in the index below.

## Tool index

Run shell/Python entry points as `scripts/<name>` from the repository root.
The two `.swift` scripts below require `swift scripts/<name>.swift`. Build
outputs, signing material and diagnostic captures stay outside committed source.
The [debug CLI](../Tools/Debug/README.md), [fuzz harness](../Tools/Fuzz/README.md),
and [native fixture](../Tools/Fixture/README.md) are the three Swift executables.

### Build and validation

| Entry point | Inputs and purpose | Effects / caller |
| --- | --- | --- |
| [check-dependencies](check-dependencies) | Optional `--xcode DERIVED_DATA`; require the local package only: no manifest dependencies, no lockfile pins, no Xcode package checkouts. | Reads manifests/build state; CI and release. |
| [check-multisig-core](check-multisig-core) | Optional `--cases N --seed HEX`; hold the Taproot script-path multisig to Bitcoin Core on a disposable regtest node: addresses, signatures, every k-of-n subset, finalizer bytes, mempool and mining, recovery locks at the boundary height. See [the fixture tool](../Tools/Fixture/README.md#the-multisig-differential). | Starts and deletes its own regtest `bitcoind` (RPC 38710 by default); needs bitcoind. Local, not in CI. |
| [check-live-gateways](check-live-gateways) | No arguments; live discovery and Bitcoin handshakes through the tailnet gateways with peers from the shipped census list. | Manual, from a Mac on the live gateway tailnet; CI uses a separate controlled simulation. Sends no wallet data. See [peer gateways](../docs/peer-gateways.md). |
| [check-live-gateways-ui](check-live-gateways-ui) | `<Xcode destination> <new evidence directory>`; live gateway journey on a device or simulator on the tailnet. | Manual; records `LiveGateways.xcresult` screenshots. Disposable mainnet wallet, nothing sent. |
| [check-test-gates](check-test-gates) | No arguments; check environment gates, deliberate skips, and retired flags. | Source check in CI; does not execute tests. |
| [check-swift-warnings](check-swift-warnings) | `BUILD_LOG`; reject compiler warnings under `Sources/` and `SoakCommand.swift`. | Reads a log; it does not compile or prove a build succeeded. |
| [ci-production-warnings](ci-production-warnings) | Optional `SCRATCH_PATH [LOG_PATH]`; Release-build `winnow-debug`, check warnings and that no lockfile appeared. | Compiles package code. Use a fresh scratch path for meaningful warning evidence. |
| [ci-tailnet](ci-tailnet) | No arguments; builds a private tailnet (Headscale, a TUN client, two userspace gateway nodes) and runs `TailnetSimulationTests` against it. | Needs Go and sudo; the parallel CI's `tailnet` lane on a disposable macOS runner. Disturbs Tailscale on a developer Mac. |
| [ci-debug](ci-debug) | No arguments; exercise wrapper help and environment checks from outside the checkout. | Builds/runs the debug CLI; lists simulators without launching one. |
| [ci-app-tests](ci-app-tests) | `FRESH_RESULTS_DIR [--skip-build]`; app tests in the iOS host. | Builds/uses a simulator; see shared-build setup above. |
| [ci-ui-journey](ci-ui-journey) | `FRESH_RESULTS_DIR [--skip-build]`; the one recorded payment journey. | Uses the fixture and simulator, mines blocks, and writes test/media artifacts. |
| [install-xcodegen](install-xcodegen) | No arguments; fetch checksum-pinned XcodeGen. | Installs under runner/temp storage; sets CI’s path or prints the local executable path. |
| [ios-simulator](ios-simulator) | Optional `iPhone` or `iPad`; print an available device ID from the newest installed iOS runtime, or from `IOS_SIMULATOR_RUNTIME` when set. | Selection only; does not boot, create, or erase a simulator. |
| [verify-release-e2e-exclusion](verify-release-e2e-exclusion) | `APP_BUNDLE_OR_EXECUTABLE`; reject known test-activation markers. | Inspects an already-built binary; CI and release. |

### Evidence and local development

| Entry point | Inputs and purpose | Effects / caller |
| --- | --- | --- |
| [ci-validation](ci-validation) | `lookup`, `publish` or `verify` plus an evidence directory. | Verifies complete records and file hashes; lookup queries GitHub and writes CI outputs. |
| [ci-journey-cache](ci-journey-cache) | Fingerprint and media helpers, also usable by hosted CI. | Queries matching successful evidence; see the runbook for caller-specific reuse policy. |
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
