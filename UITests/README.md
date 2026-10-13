[Back to main README](../README.md)

# One wallet journey on signet

`WinnowAppUITests.test01CreateReceiveSendConfirm` is the single integration
journey, recorded continuously on iPhone. It covers three payments in order:

1. Create a wallet in Simple mode, receive test coins, review and send an
   ordinary payment, and see its receipt confirm.
2. Turn on Advanced mode, create a 2-of-2 MuSig2 account with the phone and one
   Bitcoin Core cosigner, receive into it, exchange approvals, and send.
3. Create script-path 2-of-3 savings with the phone and two Core cosigners,
   receive into it, then send with the phone and one Core approval. The other
   Core key remains available but unused.

[WinnowAppUITests.swift](WinnowAppUITests.swift) owns the ordinary payment and
fixture readiness checks; [MultisigJourney.swift](MultisigJourney.swift)
continues in the same app session. [JourneyPayment.swift](JourneyPayment.swift) checks the
shared-account transactions accepted by Core. The journey is one test result, not
three independently prepared stories.

Two smaller classes share the bundle.
[PeerGatewaySettingsUITests.swift](PeerGatewaySettingsUITests.swift) checks the
Advanced peer-network controls and their persistence across relaunch with a
disposable wallet; CI runs it with the journey.
[LiveGatewayDeviceTests.swift](LiveGatewayDeviceTests.swift) skips unless
`scripts/check-live-gateways-ui` selects it on a device or simulator whose
network is on the tailnet running both [gateways](../docs/peer-gateways.md).

Before XCTest starts, `scripts/ci-ui-journey` runs
`swift run winnow-fixture prepare-bank` on the host. The command uses the shared
`SignetFixture`, `BitcoinCLI`, and `SignetMiner` helpers to mature the bank's
coins. XCTest only checks the chain and ready balance before launching the app.

The disposable private signet fixture funds the addresses read from the app
and mines blocks automatically for prompt confirmation. The app must discover
the funded balances. Core derives the same account addresses, its cosigner
wallets see the same coins, and accepted transactions must match the reviewed
payments and fees. The app then discovers confirmation and shows the remaining
account balances. This exercises the actual UI payment paths without a broad
matrix of signing orders or cosigner combinations.

The app’s periodic scan runs every three seconds under E2E configuration; the
journey never drags to refresh. Each launch pins a fresh test seed so repeated
runs do not share coins. Paste buttons read the existing test control file.
Detailed cases belong in `AppTests` and `WalletCoreTests`: labels, backup state,
fee rules, signing invariants, privacy, and network recovery. The separate
`DifferentialTests` target and job are removed. This journey does not establish
every feature’s UI behavior or hardware-wallet compatibility. There is no iPad UI job currently.

The scroll helper waits for text to materialize before reading its accessible
label, including long descriptors and approval payloads that need not fit on
screen. Controls and screenshot balances explicitly require their whole frame
clear of navigation, tab bars, and the keyboard before use. Shared payment
buttons then use a fresh, finite frame to tap its center relative to the app.

## Video, screenshots, and timing

The host records the whole test invocation as `journey.mp4` using H.264.
Recording starts after compilation and host bank preparation, and stops after
the test finishes. The scheme turns off automatic video capture; the host video and explicit
checkpoint screenshots remain enabled. The
[recording page](https://winnowwallet.com/recording) presents the complete journey
and its source provenance; checkpoint screenshots
remain secondary artifacts. Assertions, the log, and the result bundle
establish whether the run passed.

The source contains 16 captures, attached to the result bundle and copied to
`WINNOW_SCREENSHOT_DIR`:

- Ordinary payment: `01-onboarding`, `03-receive`, `56-home-beginner`,
  `06-send-review`, `08-send-confirmed`, `09-home-after-send`.
- MuSig2: `35-extra-device-policy`, `36-extra-device-review`,
  `37-extra-device-waiting`, `39-extra-device-sent`, `40-extra-device-confirmed`.
- Script-path 2-of-3: `26-savings-share`, `27-savings-funded`,
  `14-approval-waiting`, `15-approval-sent`, `28-savings-confirmed`.

They are taken at screens the journey already visits. CI normalizes the
continuous video after successful tests and retains all 16 checkpoints in
wallet evidence. The public website is maintained in winnowwallet/website,
where [video provenance](https://github.com/winnowwallet/website/blob/main/docs/videos/README.md)
and [screenshot provenance](https://github.com/winnowwallet/website/blob/main/docs/screenshots/README.md)
retain dated facts about the checked-in assets. Reused media keeps its original
source and run in journey-provenance.json.

`SIGNET_BANK_PREPARATION_SECONDS` measures host bank preparation, logged in
`bank-setup.log` in CI or `fixture-prepare.log` in standalone runs.
`SIGNET_SETUP_SECONDS` measures XCTest's fast chain and
bank readiness checks; `SIGNET_JOURNEY_SECONDS` measures the complete app
journey. Xcode reports overall test execution separately.
The recorded run of source `809c383` passed on 2026-09-17 on an iPhone 17 Pro
simulator running iOS 26.5: 213.202 seconds for the test, including 0.325 seconds
of bank preparation and 212.342 seconds for the app journey. Its ordinary,
MuSig2, and 2-of-3 phases took 35.264, 101.585, and 74.482 seconds respectively.
These are one local run’s measurements, not a CI duration guarantee. Compilation
is outside that test duration. That local run reused a prepared bank.
GitHub-hosted CI starts a fresh fixture and mines the bank's initial 101 blocks;
this preparation happens before recording and XCTest, with no bank snapshot
reused across CI runs. Its preparation and total runtime must be measured from
the hosted run. CI prepares the bank in its five-minute fixture initialization
step. The recording step retains its 15-minute limit and XCTest retains its
600-second execution limit. The recording script checks the prepared bank
again without mining more blocks.

## CI

The main [CI workflow](../.github/workflows/ci.yml) runs this journey inside its
single `build` job alongside package, fuzz, lint/test gates and release checks.
One Debug `build-for-testing` prepares the app and test bundles;
app unit tests and the journey then use `test-without-building` with the same
simulator and build directory. There is no separate node workflow or second
Debug build. A release build follows the tests.

The build job uses GitHub-hosted Apple silicon (`macos-26`) with per-run
DerivedData and a fresh disposable signet fixture. It needs no developer Mac
or persistent local caches. Fork pull requests use the same hosted image for
app checks without the fixture or UI journey.
Manual, nightly and release calls always run fresh tests. The `app-tests-…`
artifact from a fresh run contains unit evidence
under `units/` and journey evidence under `journey/`: `NodeUI.xcresult`,
`bank-setup.log`, `fixture-prepare.log`, `node-ui.log`, `journey.mp4`, `video.log`, and
`node-screenshots/`.
On exit, the recorder script also saves the app's E2E event journal as
`story-events.jsonl` and Core's network debug log as `node.log` when available.
Missing diagnostics do not change the test result.

`scripts/ci-journey-cache` can skip build and wallet test steps for website-only
changes when a successful same-repository run has matching test/build inputs
and a retained normalized media artifact. App-bundled HTML/CSS changes still
force fresh tests; absent evidence or API errors also run fresh. The build job
always prepares and checks a fresh website. Its separate reusable `website`
job deploys only that same-run artifact, with trusted PR previews and main
production. There is no separate architecture lane or LOC job.

## Run locally

Use the same fixture tooling as CI, with dedicated local ports and a new
results directory. Keep local simulator runs serial: they share the simulator
environment file and fixture ports. GitHub-hosted CI runs independently.
The script prepares the bank automatically, using an incremental native Debug
build of `winnow-fixture`. For a direct Xcode test run, run
`swift run winnow-fixture prepare-bank` first with the same exported node
environment variables.

```sh
set -o pipefail
RESULTS_DIR=$(mktemp -d /tmp/winnow-ui-XXXXXX)
export WINNOW_NODE_HOST=127.0.0.1 WINNOW_RPC_PORT=38700 WINNOW_P2P_PORT=38701
export WINNOW_DATADIR="$RESULTS_DIR/fixture"
export WINNOW_SCREENSHOT_DIR="$RESULTS_DIR/screenshots"
export WINNOW_FIXTURE_TEMPLATE="$HOME/Library/Caches/winnow-signet-template"
test ! -e "$HOME/.winnow-node.env" || exit 1
scripts/signet-fixture up
mkdir -p "$WINNOW_SCREENSHOT_DIR"
env | grep '^WINNOW_' > "$HOME/.winnow-node.env"
trap 'rm -f "$HOME/.winnow-node.env"; scripts/signet-fixture down' EXIT
scripts/import-census
xcodegen
SIMULATOR_ID=$(scripts/ios-simulator iPhone) \
  scripts/ci-ui-journey "$RESULTS_DIR"
```

After the first successful run, the stopped fixture can be saved with
`scripts/signet-fixture snapshot "$HOME/Library/Caches/winnow-signet-template"`
while `WINNOW_DATADIR` still identifies it. Future local runs can copy that
prepared bank into their own fixture; hosted CI starts fresh. Keep the original result bundle, screenshots,
and source revision with runtime measurements.
