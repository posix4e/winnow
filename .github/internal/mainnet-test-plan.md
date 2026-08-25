# Manual mainnet test + launch recording plan

**Goal:** prove the critical path on mainnet with real (small) money — fresh wallet → receive → unconfirmed detection → confirmation → spend — and capture it as launch material.

**You'll need:** the TestFlight build (public link in README), an iPhone with screen recording enabled (Control Center → Screen Recording), and ~$20–50 of BTC in an external wallet you control. Everything here is mainnet, real money, small stakes.

**Safety rules:** the mnemonic shown during onboarding is a REAL mainnet seed — pause/stop the recording before it appears, or blur it in the edit. Keep the amount trivial. If anything misbehaves, the seed restores elsewhere (BIP86 `m/86'/0'/0'`).

## The beats (record continuously from Beat 1)

1. **Cold open (30s).** Fresh install from TestFlight → create wallet → show the empty home. Narration hook: "no account, no server, it hasn't asked anyone anything."
2. **Receive + unconfirmed detection (the money shot).** Open Receive, copy the address. From your external wallet, send the small amount. Keep the app on the Receive screen — the mempool window should show **"Unconfirmed: +X sats — awaiting confirmation"** within seconds of the send. That delay is the metric to call out (target: < 10s on Wi-Fi).
3. **Confirmation.** Leave the app open (or note the time) — when the next block lands, filters flip it to confirmed and the balance appears. (~10 min is normal; a fast block is a gift, a slow one is honest.)
4. **Spend.** Send ~half back to your external wallet. Capture: fee control (preset + floor), the review screen, **"Relayed to N peers"** propagation, then "Seen in block N" after a block. 
5. **Sync honesty.** Settings → peer list: show N ordinary full-node peers, no company server. That's the whole infrastructure story in one screenshot.

## Pass criteria

- [ ] Mainnet peers connect via DNS discovery with zero config (if not: note it — that's a bug, not a demo fail)
- [ ] Unconfirmed payment appears while Receive is open
- [ ] Balance + history correct after confirmation
- [ ] Spend builds, signs, relays, confirms
- [ ] No crash, no stuck sync

## Abort / fallback

- **No peers on mainnet:** Settings → manual peer won't save you (your node is signet-only) — stop, file it, we fix DNS discovery before launch.
- **Fee estimate looks insane:** the presets are conservative by design; override manually and note the values.
- **Anything touches funds wrongly:** stop immediately; the seed restores in any BIP86 wallet.

## After the recording

- Note wall-clock timings per beat (we'll put them next to timings.json on the site).
- **#89 measurement, same session:** time first-launch-to-tip twice on the
  measurement simulator — once with the shipped checkpoint (the default), once
  with "Verify the chain from genesis" on — fresh wallet each time, the same
  way the 8m28s baseline was taken. Post both numbers to #89; that closes its
  last open phase.
- Keep the raw recording; a 60–90s cut of beats 1–3 is the launch clip.
