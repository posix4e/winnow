# Winnow whole-app public-signet story run

This is the canonical manual acceptance and website-capture journey. It uses
ordinary public signet peers and the iOS Simulator. It does **not** install,
start, stop, or contact a local `bitcoind`, and it needs no RPC credential.

The run is intentionally resumable: public signet decides when transactions
confirm. A waiting checkpoint is a healthy paused run, not a failed test.
An experimental scene can be marked `--defer` to continue with independent
stages, but deferred coverage remains incomplete and blocks final publication.

## Cast

| Person | Story role | Visual theme |
|---|---|---|
| Sofía Cruz · Brisa Café | shop owner; single-signature phone wallet | sunrise amber `#E59B3A` |
| Lina Vega | privacy-minded customer | violet night `#6F5BD3` |
| Elena Rivera | Sofía's family steward; personal cold-vault key | heirloom blue `#315A8A` |
| Leo Santos · Harbor Exchange | exchange-held inheritance key | custody cobalt `#356FC4` |
| Marina Ortiz · Ceiba Trust | trust key and next-of-kin authentication | trust sage `#62896B` |
| Mateo Rivera | next generation; joint reserve signer | reserve teal `#2E8B88` |

Harbor Exchange and Ceiba Trust are fictional. The colors belong to captions,
clips, and the site—not Winnow's production UI.

## One connected money story

This is one flow of funds, not a gallery of unrelated features. Sofía keeps a
small Brisa Café hot-wallet balance for customers and suppliers. After the
standard payment scenes, she sweeps café savings into the Rivera
family's 2-of-3 cold reserve, held by Elena, Harbor Exchange, and Ceiba Trust.
Elena plus Leo return ordinary operating liquidity to Brisa Café. Leo plus
Marina demonstrate recovery without Elena and direct legacy funds toward
Elena and Mateo's separate 2-of-2 MuSig2 reserve. Sofía's replacement phone
then recovers the original hot-wallet side of that same history.

## Start or resume

```sh
./scripts/winnow-story doctor
./scripts/winnow-story start --run august-story
```

`start` creates protected identities and a dedicated simulator named for the
run, builds and installs Winnow, launches Sofía's isolated public-signet
wallet, and prints the first instruction. `resume` reuses that device or
recreates it if it was deleted. Private state lives under
`.build/winnow-story/runs/<run>/private.json` with owner-only permissions.
For the recovery-screen proof, enter the simulator passcode when Winnow asks,
or choose **Features → Face ID → Enrolled** and then **Matching Face**. Story
mode requires that real simulator Local Authentication path; ordinary
unattended XCUITests retain their explicit test-only bypass. Never record while
the words are visible.

After any pause or signet confirmation:

```sh
./scripts/winnow-story status --run august-story
./scripts/winnow-story resume --run august-story
```

Within a multi-person stage, switch between isolated app roles without
rebuilding or copying wallet data:

```sh
./scripts/winnow-story launch-role --run august-story --persona elena --tab vaults
./scripts/winnow-story launch-role --run august-story --persona sofia --tab send \
  --clipboard PUBLIC_VAULT_ADDRESS
# Wipe only the isolated replacement-phone role before rehearsing recovery.
./scripts/winnow-story launch-role --run august-story --persona sofia-replacement \
  --tab wallet --reset
```

Never use `start` twice for the same name. `resume` incrementally rebuilds and
reinstalls the current code, then reuses the exact identities, transactions,
nonce session, simulator, and next incomplete checkpoint. This is how a failed
stage is rerun after its fix without starting the story over.

## Recording and checkpointing

Run `capture` once to start a short stage clip and the same command again to
stop it and take the stage screenshot:

```sh
./scripts/winnow-story capture sofia-onboarding --run august-story
./scripts/winnow-story capture sofia-onboarding --run august-story
```

Do not record while recovery words are visible. A human must review every
video frame before publication even after the text redaction check passes.
The runner fingerprints every reviewed file, so a later recording or screenshot
automatically requires a new review.

Mark a completed or waiting stage explicitly:

```sh
./scripts/winnow-story checkpoint customer-funding --waiting --run august-story \
  --txid SIGNET_TXID --note "Seen unconfirmed; waiting for a block"

./scripts/winnow-story checkpoint customer-funding --pass --run august-story \
  --txid SIGNET_TXID --height 123456 --label customer-funding --persona sofia

./scripts/winnow-story verify --run august-story
```

Reapplying the same transaction ID or height is safe; the manifest deduplicates
it. `verify` fetches the claimed block from ordinary public peers, authenticates
it against Winnow's validated header chain and Merkle root, and records the
transaction's parents. This proves the hot-wallet → cold-reserve → joint-reserve
money trail without an explorer or local node. Temporary peer trouble prints
`Waiting` and remains resumable. A passed checkpoint cannot accidentally be
reopened or failed.

## The journey

1. **Sofía opens Brisa Café's wallet.** Create the wallet, stop the app on the
   backup sheet, resume, finish backup, authenticate phrase reveal without
   recording it, and reach the empty wallet.
2. **First customer payment.** Keep Receive open and make the run's one human
   signet funding transfer. Record unconfirmed detection, then pause until the
   balance and Received history row confirm.
3. **Supplier payment and RBF.** Get Lina's fixture address with
   `winnow-story address --persona lina`, pay it, confirm relay, immediately
   bump the fee, and record the original as replaced and the replacement as
   confirmed.
4. **Brisa Café's Rivera cold reserve.** `keys` prints the named Elena, Leo,
   and Marina expressions. Create the 2-of-3 vault, then fund it by sweeping
   savings from Sofía's already-funded hot wallet—do not introduce unrelated
   faucet coins. Copy the creator PSBT into files and use
   `cosign-inheritance --as leo|marina --psbt FILE`. Exercise Elena+Leo to
   return operating liquidity to Sofía's hot wallet. Exercise Leo+Marina for
   next-of-kin recovery, directing the recovered amount toward the joint
   reserve while preserving and verifying cold-vault change.
5. **Rivera joint reserve.** Fund Elena+Mateo's 2-of-2 MuSig2 reserve from the
   preceding cold/recovery flow. Copy the initial
   PSBT to `musig-nonce`; combine Mateo's result with Elena's UI nonce without
   leaving the screen; feed the combined nonce PSBT to `musig-sign`; combine,
   aggregate, broadcast, and confirm. The runner removes Mateo's secret nonce
   immediately after round two so it cannot be reused.
6. **Replacement phone.** Capture the watch-only export and the redacted seed export.
   Resume launches an isolated replacement-phone namespace using Sofía's same
   identity; import, verify forward, and compare balance/history/spendability.
7. **Privacy tour.** Capture connected public peers, configure the selected
   explorer, cancel its address/transaction disclosure warning, capture the
   manual-peer controls, and bundled design papers. Do not switch
   to or fund mainnet.

Each successful broadcast is recorded as `--waiting`; public signet confirmation
has no artificial failure timeout. If an app defect blocks a stage, mark it
`--fail`, retain the generated screenshot/log evidence, fix the defect, and
resume the same run at that checkpoint.

Transaction stages need separate labels when they contain multiple broadcasts:
cold-reserve funding plus its ordinary and recovery
spends; and joint-reserve funding plus its MuSig2 spend. Run `verify` after each
confirmation. `finish` refuses to pass unless every required transaction and
both inter-wallet money links have authenticated evidence.

## Finish

First inventory the media. Watch every listed video from start to finish and
inspect every screenshot; the command deliberately cannot do that judgment for
you. It writes both a Markdown checklist and a local HTML page with every video,
screenshot, and a browser-local progress checkbox. Once the human review is
complete, record the approval:

```sh
./scripts/winnow-story review-media --run august-story
./scripts/winnow-story review-media --run august-story --approve
```

Approval records only relative paths, sizes, SHA-256 hashes, and the review
time. It contains no wallet secrets. `finish` rejects missing stage media,
missing approval, or any file added or changed after approval.

```sh
./scripts/winnow-story finish --run august-story
```

The command stops managed recording/index processes and writes:

- `artifacts/report.md` — human-readable story and pass/fail checklist;
- `artifacts/public-manifest.json` — scenario, environment, personas, timings,
  transaction IDs, heights, and checkpoint results;
- per-persona safe event journals and public peer snapshots;
- one `.mp4` and `.png` pair for every captured stage.

It refuses publication when a text artifact contains a mnemonic/entropy/private
key/secret-nonce label or a protected run identity. The passing state is saved
only after that scan succeeds, so a rejected publication remains resumable and
cannot leave behind a false passing report. Private state, raw PSBTs, and
unapproved media remain under the ignored `.build` directory.
