# App Store screenshot candidates

The canonical UI suite was last captured on 2026-08-17 using an iPhone 17 Pro Max simulator. Every PNG in `docs/screenshots/` is 1320 × 2868 pixels, the 6.9-inch portrait size.

Use these six files, in this order, as the composition candidates for the final recapture:

1. `01-onboarding.png` — product and privacy model
2. `03-receive.png` — native Taproot receive flow
3. `05-send-form.png` — fee selection without a fee server
4. `06-send-review.png` — explicit payment review before signing
5. `24-people.png` — the address book, with fresh addresses per payment
6. `26-savings-share.png` — shared savings, 2 of 3, shared as a card

`15-approve-request.png` (a co-owner approving a spend in plain words) and
`25-pay-person-review.png` (a review that names the person) are the
alternates. `11-vault-list.png` and `15-vault-cosign.png` were the raw vault
views; the app now shows those only in Advanced mode, and the beginner shots
above replace them in the set. Every capture shows the four tabs Wallet,
Send, People, Settings; the Vaults section appears in `10-vault-create` and
`11-vault-list` because that run launches in Advanced mode.

These are deterministic signet fixtures, not real funds. All six were visually inspected on 2026-08-17; none contains a mnemonic or development endpoint. They are not yet upload-ready: onboarding explicitly names signet and the payment screens use testnet addresses. Recapture and recheck the set after the mainnet-default change in #9.

Do not upload `02`, `14`, `20`, `21`, or `22`: they display the deterministic test mnemonic. Do not upload `07`, `08`, `12`, or `13`: they expose development-node or service configuration. The remaining captures are engineering evidence, not selected store artwork. No App Store upload is performed by the test suite.

Validation command:

```sh
sips -g pixelWidth -g pixelHeight docs/screenshots/*.png
```

The producing run executed 10 tests with zero failures. Its measured scenario timings are in [`docs/screenshots/timings.json`](../../docs/screenshots/timings.json).
