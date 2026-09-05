# App Store screenshot candidates

Two sets live in `docs/screenshots/`, both 1320 × 2868 pixels (the 6.9-inch
portrait size App Store Connect asks for), both from the real app on the
local signet fixture, iPhone 17 Pro Max simulator.

## The storefront set (`store-*.png`)

Produced by `scripts/storefront-capture` (UITests/StorefrontCaptureTests,
#39): a story with believable amounts in the beginner shell, its own wallet
(entropy pinned per run from the chain height), and a keyed node wallet as
the payer so received payments look like payments, not coinbases. The script
fails unless all ten files exist at the right size.

Use these six, in this order:

1. `store-01-onboarding.png` — product and privacy model, no network row
2. `store-02-receive.png` — a fresh Taproot address (`store-03-receive-unconfirmed.png` tells the mempool-window story instead)
3. `store-05-send-form.png` — fee selection without a fee server, before any address is typed
4. `store-06-send-review.png` — explicit payment review before signing
5. `store-08-people.png` — the address book and shared savings side by side
6. `store-09-shared-savings.png` — savings held with two people, 2 of 3 must approve

`store-04-home.png`, `store-07-home-after-send.png` and
`store-10-approve-request.png` are the alternates. Every capture shows the
four tabs Wallet, Send, People, Settings, and none launches in Advanced
mode. Addresses are `tb1p…` (signet): accepted, not doctored. Nothing in the
set shows a mnemonic, a development endpoint or a node address.

## The functional set (`NN-name.png`)

The UI suite's own evidence (WinnowAppUITests), last captured 2026-09-05.
Not store artwork: `02`, `14`, `20`, `21` and `22` display the deterministic
test mnemonic; `07`, `08`, `12` and `13` expose development-node or service
configuration; `10` and `11` launch in Advanced mode and show the Vaults
section. `15-approve-request.png`, `24-people.png`, `25-pay-person-review.png`
and `26-savings-share.png` are the People-flow shots the storefront set
re-stages with better amounts. Measured scenario timings are in
[`docs/screenshots/timings.json`](../../docs/screenshots/timings.json).

No App Store upload is performed by any test; the six picks are uploaded by
hand in App Store Connect, and `scripts/testflight.sh appstore-status`
reports the screenshot sets it finds there.

Validation command:

```sh
sips -g pixelWidth -g pixelHeight docs/screenshots/store-*.png
```
