[Back to main README](../README.md)

# One wallet journey on signet

`WinnowAppUITests.test01CreateReceiveSendConfirm` is the single integration
journey, recorded continuously on iPhone: create a wallet in Simple mode,
receive test coins, review and send a payment, and see its receipt confirm on
a real signet node; then pay a BIP352 silent payment code from the change,
where the test holds the receiver's keys (Core has no BIP352 support), derives
the one address that receiver would scan for from the mined transaction,
requires the app to have paid exactly that, and has a watch-only Core wallet
confirm the coin by that address. [WinnowAppUITests.swift](WinnowAppUITests.swift)
owns both payments and the fixture readiness checks. It then runs
[MultisigJourney.swift](MultisigJourney.swift): a 2-of-3 script-path multisig
account between the phone and two Bitcoin Core wallets, whose first address
must equal Core's `deriveaddresses`. The phone funds it, creates the PSBT and
signs first; each Core wallet adds its own script-path signature through
`walletprocesspsbt`, and the phone combines both copies, so three signatures
verify where two are needed. The phone finalizes the BIP387 witness, which
must carry exactly two, and broadcasts, and Core must accept and mine it.
Three blocks later the phone alone spends the change on the recovery leaf,
with both leaves' counts on screen, and Core must accept the CSV-locked
witness. The journey is one test result.

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

The disposable private signet fixture funds the address read from the app
and mines blocks automatically for prompt confirmation. The app must discover
the funded balance, and the transaction Core accepts must match the reviewed
payment and fee. The app then discovers confirmation and shows the remaining
balance. This exercises the actual UI payment path on a real node.

The app’s periodic scan runs every three seconds under E2E configuration; the
journey never drags to refresh. Each launch pins a fresh test seed so repeated
runs do not share coins. Paste buttons read the existing test control file.
Detailed cases belong in `AppTests` and `WalletCoreTests`: labels, backup state,
fee rules, signing invariants, privacy, and network recovery. The separate
`DifferentialTests` target and job are removed. This journey does not establish
every feature’s UI behavior or hardware-wallet compatibility. There is no iPad UI job currently.

The scroll helper waits for text to materialize before reading its accessible
label. Controls and screenshot balances explicitly require their whole frame
clear of navigation, tab bars, and the keyboard before use.

## Video, screenshots, and timing

The host records the whole test invocation as `journey.mp4` using H.264.
Recording starts after compilation and host bank preparation, and stops after
the test finishes. The scheme turns off automatic video capture; the host video and explicit
checkpoint screenshots remain enabled. The
[recording page](https://winnowwallet.com/recording) presents the complete journey
and its source provenance; checkpoint screenshots
remain secondary artifacts. Assertions, the log, and the result bundle
establish whether the run passed.

The source contains 11 captures, attached to the result bundle and copied to
`WINNOW_SCREENSHOT_DIR`: `01-onboarding`, `03-receive`, `56-home-beginner`,
`06-send-review`, `08-send-confirmed`, `09-home-after-send`, then the multisig
leg's `26-savings-share`, `27-savings-funded`, `14-approval-waiting`,
`15-approval-sent` and `28-savings-confirmed`, the names the shared-account
Winnow used for its threshold leg. They are taken at screens the journey
already visits. CI normalizes the continuous video after successful tests and
retains all 11 checkpoints in wallet evidence. The public
website, which still presents the sixteen-checkpoint journey of the
shared-account Winnow, is maintained in winnowwallet/website,
where [video provenance](https://github.com/winnowwallet/website/blob/main/docs/videos/README.md)
and [screenshot provenance](https://github.com/winnowwallet/website/blob/main/docs/screenshots/README.md)
retain dated facts about the checked-in assets. Reused media keeps its original
source and run in journey-provenance.json.

`SIGNET_BANK_PREPARATION_SECONDS` measures host bank preparation, logged in
`bank-setup.log` in CI or `fixture-prepare.log` in standalone runs.
`SIGNET_SETUP_SECONDS` measures XCTest's fast chain and
bank readiness checks; `SIGNET_MULTISIG_SECONDS` measures the multisig leg and
`SIGNET_RECOVERY_SECONDS` its recovery-path spend after the delay;
`SIGNET_ORDINARY_SECONDS` measures the payment and
`SIGNET_JOURNEY_SECONDS` the complete app journey. Xcode reports overall test
execution separately; compilation is outside that test duration.
Fresh CI starts a new fixture and mines the bank's initial 101 blocks;
this preparation happens before recording and XCTest, with no bank snapshot
reused across CI runs. Its preparation and total runtime must be measured from
the specific run. CI prepares the bank in its five-minute fixture initialization
step. The recording step retains its 15-minute limit and XCTest retains its
600-second execution limit. The recording script checks the prepared bank
again without mining more blocks.

## CI

The [main workflow](../.github/workflows/ci.yml) selects parallel validation for
same-repository runs. The build lane publishes Debug app/test products once;
the journey lane verifies the artifact hash and uses those products on its own
runner and simulator with `test-without-building`. The journey lane prepares a
fresh disposable signet fixture and retains `NodeUI.xcresult`, test and fixture
logs, `journey.mp4`, video logs and checkpoint screenshots in
`lane-journey-<run>-<attempt>`. The unit lane retains its own app-test results.

The hosted fallback combines build and tests on GitHub-hosted Apple silicon;
fork PRs omit the fixture and journey. Its fresh evidence uses the
`app-tests-<run>-<attempt>` artifact. In either implementation, cancelled or failed
runs can retain partial evidence. On exit the recorder also saves
`story-events.jsonl` and Core's `node.log` when available; missing diagnostics
do not change the test result.

Manual and nightly runs force fresh checks. Other eligible runs, including tag
releases, can reuse complete matching validation evidence up to seven days old
through `scripts/ci-validation`. Reused results and media retain their original
revision and run. App-bundled HTML/CSS changes affect the build fingerprint.
See [CI and release operations](../.github/internal/ci-release.md) for the reuse
policy and artifacts. Wallet CI does not build or deploy the public website.

## Run locally

Use the same fixture tooling as CI, with dedicated local ports and a new
results directory. Keep local simulator runs serial: they share the simulator
environment file and fixture ports. CI runs on separate disposable runners.
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
prepared bank into their own fixture; fresh CI starts a new fixture. Keep the original result bundle, screenshots,
and source revision with runtime measurements.
