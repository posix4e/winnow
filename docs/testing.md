# Features, journeys, and evidence

This developer policy explains the test suites and evidence requirements.
The [CI runbook](../.github/internal/ci-release.md) describes how to run checks
and inspect their artifacts.

The product is the wallet app for iPhone, iPad, and Apple silicon Mac, plus
explicit debugging tools. Automated UI coverage is limited to iPhone.
Everyday and advanced features are documented in the public website's
[journey inventory](https://github.com/winnowwallet/website/blob/main/docs/journeys.json).
Its generator references captures named by the pinned UI journey. XCTest takes
the checkpoints; scripts/prepare-site-artifact normalizes the host recording
and validates evidence independently of the website.
Recording evidence identifies the steps
exercised by the current focused UI journey. The
public roadmap owns future work; it is not evidence that a feature ships.

## What earns a place

- A user-facing feature needs clear usage instructions and focused tests for
  its decisions and failure cases. One UI integration journey checks ordinary,
  MuSig2, and script-path 2-of-3 receiving, sending, and confirmation through
  the real app. Detailed coverage belongs in app, wallet, and protocol tests
  without repeated screen navigation.
- A debugging command needs a concrete diagnostic purpose, a runbook, and
  meaningful command/protocol checks. Help output alone does not prove a live
  network operation.
- A lower-level component must serve one of those purposes or enforce a named
  security property. Do not add a production API just to make a test convenient.
- Delete obsolete features with their tests. Delete duplicate happy-path tests
  when the actual app journey and relevant independent checks cover the promise.
  Keep vectors, adversarial cases, arithmetic bounds, storage integrity,
  authorization, and recovery regressions when their invariant still exists.

## Architecture follows the app

WalletCore now owns wallet state, transaction construction, peer connections,
headers, filters, and relay in one package target. The app directly orchestrates
those parts; there is no extra wallet/network facade or parallel library-only
send/scan workflow. Cryptography, descriptors, and wallet networking now share
WalletCore too, including their byte encoders. Actors retain their existing
ownership and lifetimes. Offline inspection is part of winnow-debug; there is no
separate CLI or demo signing path. Shared-savings vaults and their contact cards
live in VaultKit, a second library on WalletCore's public interface.

InMemoryKeyStore belongs to TestSupport, not the shipping wallet. The module
version placeholders and duplicate binary serializers are removed. There is one
app release version.

## Which tests say what

The one integration test is `test01CreateReceiveSendConfirm` in
`UITests/WinnowAppUITests.swift`. It starts with a quick ordinary receive and
send, then receives and sends with a 2-of-2 MuSig2 account shared by the phone
and one Core cosigner. Finally it receives and sends through a script-path
2-of-3 account containing the phone’s key and two Core cosigners. Both Core
wallets know that account, but only the phone and one Core key approve its
payment. The test checks the funded destinations, accepted transactions, and
confirmation through the app. The private signet fixture mines blocks
automatically so confirmations follow promptly. The automated journey runs on an iPhone simulator; there is no iPad UI
job currently.

This is one continuous UI/video journey, not a broad interoperability matrix.
There is no separate DifferentialTests target or node comparison job. Other
signing orders, combinations, and physical hardware need their own evidence.
The retained video and screenshots are evidence only for the revision and
coverage recorded in their provenance.

CI has one `build` job for package, app, fuzz, lint/test gates and release checks,
followed by a reusable `website` job. One Debug build serves app unit tests
and this journey with the same simulator and build directory. A fresh run's
`app-tests-…` artifact contains `units/` and `journey/` result bundles and logs,
plus the journey recording and checkpoint screenshots. The build job runs on
GitHub-hosted Apple silicon (`macos-26`) with per-run build products and a fresh
signet fixture, independently of any developer Mac. Fork pull requests use
the same image for package and app checks without the private node, UI journey
or deployment credentials. Manual, nightly and release runs execute fresh tests.

For website-only edits, `scripts/ci-journey-cache` hashes test/build inputs and
finds a successful same-repository run's normalized media artifact. Matching
inputs allow build and wallet test steps to skip while the current website is
generated and checked. App-bundled HTML/CSS stays in the fingerprint; changed
inputs, missing media or API errors require fresh tests. Reused media retains
its original source and result, rather than claiming a new test execution.
There are no separate architecture, complexity, selector or LOC jobs. The
legacy LOC reporter and its tests were removed.

The detailed rules stay in smaller suites. `AppTests/PeoplePaymentTests.swift`
and `AppTests/SenderLabelTests.swift` cover people, payment decisions, and sender
labels. `AppTests/WalletStartupTests.swift` and `AppTests/VaultBackupTests.swift`
cover persisted startup and backup state. `Tests/VaultKitTests/VaultSpendTests.swift`
checks threshold and missing-signature rules. These focused checks supplement
the journey without repeating every behavior through screen navigation.

Policy explanations must come from the actual descriptor, including 1-of-n.
Names, contact mappings, and PSBT metadata must not change signing requirements
or establish output ownership. Keep adversarial checks for altered policies,
forged change metadata, missing signatures, and nonce reuse. Provider, trust,
physical key separation, and coercion claims require evidence outside a
simulator; their unverified integrations belong on the roadmap.

- UITests runs the one focused journey against a disposable signet node and
  checks its screen and node outcomes. The host records one continuous video
  for review and the website; checkpoint screenshots remain secondary artifacts.
- AppTests checks protected actions, review invalidation, persisted state,
  network separation, people, and OS integration.
- WalletCoreTests checks wallet/network invariants and hostile peer behavior.
  The former BitcoinP2PTests are grouped under WalletCoreTests/Network.
- VaultKitTests checks contact cards, vault admission and vault spends.
- BitcoinCoreTests retains independent vectors and parser/cryptographic bounds.
- ToolsTests and the fuzz harness cover debugging commands and hostile inputs.

The larger UI story suite and separate differential matrix are retired. The
three payment flows share one journey; other detailed behavior and interruptions
use focused tests. The [recording page](https://winnowwallet.com/recording)
shows the continuous journey and its source provenance. Older guide
illustrations retain their provenance.

## What generated pages do and do not establish

Generation refuses a missing test selector, an app scenario with no documented
journey, or a missing/unresolved journey video. The recording page embeds the
video once with its tested source and run; the signing guides explain the
policies and setup steps.
This catches documentation drift; it is not runtime coverage analysis. Changes
need checks appropriate to their behavior; the integration journey does not replace
relevant invariant tests.

The xcresult bundle and logs are authoritative for success, failure, and the
tested revision. The host records the simulator while the journey runs; the
recording and checkpoint screenshots do not replace test assertions. Keep the
revision, device, date, and result bundle together in the deployment's
`/recording` provenance. [Repository video notes](https://github.com/winnowwallet/website/blob/main/docs/videos/README.md) preserve
the dated history of checked-in recordings.
`scripts/prepare-site-artifact --normalize-journey` writes a reusable media
bundle preserving source and run provenance. `--validate-media` checks retained
evidence. Website sources and deployment live in winnowwallet/website; wallet
CI no longer prepares or publishes site artifacts. Historical assets and audit
notes retain their historical status.

Simulator tests do not establish locked-device Keychain enforcement, battery
life, real-world peer independence, or independent review. Keep those limitations
explicit. Future work belongs on the separate roadmap.
