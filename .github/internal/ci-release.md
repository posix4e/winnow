# CI, release and website operations

Winnow is one repository and one release train. The root Swift package organizes
internal modules and development executables. The app, fuzz harness
and debugging tool share one `Package.swift` and one `Package.resolved`; the Swift dependency
is swift-secp256k1. Xcode resolution must match that root lockfile.

## Checks and ownership

| Workflow | When | Responsibility |
| --- | --- | --- |
| CI | PR, main push, nightly, manual, release caller | One validation lane (four WarpBuild jobs or one hosted build job) owns lint/test gates, package and debugging tests, app/Keychain tests and signet UI journey, release warning and E2E exclusion gates, inspection smoke, provenance, fixed fuzz corpus, and journey evidence normalization |
| Fuzz sanitizers | Weekly or manual seed replay | Sustained address/thread sanitizer coverage; does not repeat normal suites |
| Release | New stable version tag or manual validation | Calls CI, then signs/uploads and publishes only for tag pushes |
| TestFlight recovery | Manual, exact version and build number | Finish notes/group assignment for an existing upload |
| App Store submission | Manual | Attach a processed build and optionally submit for review |
| TestFlight feedback | Manual, with an age recipient | Pull tester comments, screenshots and crash logs encrypted to that recipient; the log shows counts only |

CI runs one validation lane; there are no separate selector,
complexity, architecture or size-report jobs. Same-repository runs use four
parallel WarpBuild jobs ([ci-parallel.yml](../workflows/ci-parallel.yml));
the rest of this section describes the hosted `build` job, which fork PRs and
the manual `hosted` input use. The build job checks out the PR
head explicitly. `scripts/ci-journey-cache` hashes the test/build inputs,
including HTML/CSS bundled in the app, and looks for normalized media from a
successful same-repository run with the same inputs. Website-only edits can
reuse that media, skip compilation and wallet tests, and still prepare and
check a fresh website. Reuse preserves the original recording's source and run;
it does not establish a new test result for the website revision. Missing
artifacts, API errors or changed inputs run fresh checks. Manual, nightly and
release calls always run fresh checks.

The hosted build job runs on GitHub-hosted Apple silicon with `macos-26`.
Each job gets its own Mac environment; it does not depend on a developer's
Mac mini. Same-repository pull requests and
trusted push, manual, nightly and release runs include the signet journey.
Fork pull requests use the same hosted runner image for package and app checks,
without the node fixture, UI journey or deployment credentials.
The UI journey uses `Tests/Support/Node` for chain operations and Core-held
cosigner keys. The broad differential target and its separate CI job are retired.

The workflow provisions Python on every run and installs the Bitcoin Core and
video tools when a fresh journey is needed. Debug build products use a per-run
DerivedData directory. The temporary node starts from a fresh fixture through
`scripts/signet-fixture`, without a persistent prepared-bank or simulator cache.
The iPhone journey covers ordinary-wallet,
MuSig2 and 2-of-3 payments, with Core supplying the other signing keys.

The build job owns fixture setup and teardown under its temporary directory.
Test logs, checkpoint screenshots, the continuous video, and result bundles use a fresh `mktemp` evidence
directory per job so cancelled runs cannot poison a later Xcode result path; prior
wallet state and difficulty retargets cannot affect the next run. The single
`app-tests-<run-id>-<attempt>` artifact contains `debug-build.log`, `units/` with
`AppTests.xcresult`, `journey/` with `NodeUI.xcresult`, `journey.mp4`,
`video.log` and `node-screenshots/`, plus `release-build.log`.
The Keychain attribute tests use the app's existing iOS test host.
They verify recorded attributes and round-trip storage; device-lock enforcement
still needs real hardware. The retired story/media workflow has no CI role;
app screenshots and video now come from the asserted UI journey through
`scripts/ci-ui-journey`.

## Release

Create a new, unused stable `vMAJOR.MINOR.PATCH` tag on the intended Winnow
commit. This is an app release, including its internal modules and tools. Existing
tags in Winnow and the archived library remain fixed; the former library's
`v0.1.0` is historical and is not Winnow's next version.

Run Release manually first to validate the checkout without signing, uploading,
assigning TestFlight groups or publishing. Release validates the stable version.
The release fetches the census's current list with `scripts/import-census`
before building, and its log names the census commit the app ships.
Refreshing the header checkpoint uses `scripts/refresh-checkpoint` and needs a
genesis-validated header file. This is manual maintenance, not an automatic
requirement for every release. Its validation and vector update are described in the
[checkpoint runbook](../../Tools/Generate/README.md).
The signed app archive is checked for E2E controls and its provenance is
attached to the GitHub release.

The CI workflow is reused directly, so release definitions cannot drift into a
second copy of package/app/fuzz checks. One unfiltered Debug `build-for-testing`
builds the app and both test runners. App unit tests and the UI journey then
reuse those products with `test-without-building`, using the same simulator
and DerivedData directory. Native inspection smoke and provenance use the same
warning-checked release binary. Fuzz smoke reuses its compiled modules, while
`swift test` runs the library and debugging-tool suites together once per
run. The iOS Release build separately checks shipping compiler settings
and bundled resources.

If App Store Connect processing outlasts a release, use **TestFlight recovery**
with its exact marketing version and build number; do not upload that number
again. App Store submission remains a separate deliberate operation.

To read tester feedback, run **TestFlight feedback** with an `age` public key
whose private key stays on your machine, download the `testflight-feedback-<run>`
artifact (kept three days) and decrypt it with `age -d -i <key>`. The repository is
public, so feedback never appears unencrypted in logs or artifacts.

There is no separate public library product or release process. The local app
and tools change together and need no internal version bumps.

## Website

Public site sources, generation, blog and deployment live in
[winnowwallet/website](https://github.com/winnowwallet/website). Wallet CI
normalizes and validates journey media, preserving its original source SHA,
run URL and result. It uploads wallet evidence without publishing the site.
The app separately bundles five offline technical guides and site.css from
docs/. Copy reviewed guide updates from the website when releasing the app.
