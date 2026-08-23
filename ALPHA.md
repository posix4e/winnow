# alpha

This branch is where features live before they are ready for `main`.

It exists because "experimental" and "shipped" were becoming the same branch.
A feature on `alpha` can be incomplete, can depend on infrastructure that does
not exist yet, and can change shape without warning. A feature on `main` cannot.

## What is on it today

**BIP352 silent payments.** Sending works. Receiving works, but only against a
tweak-index server: the wallet cannot find silent payments in the chain by
itself, because doing so privately would mean scanning every block's tweak data
rather than a compact filter. That server is the part that is not solved.
Until it is, receiving is a feature with a dependency most people do not have,
which is why it is here rather than on `main`.

## Nothing here ships by accident

Releases are cut by pushing a `v*.*.*` tag, never by landing code on a branch.
A commit on `alpha` reaches TestFlight only if someone deliberately tags this
branch, and no automation does that.

## If you have received a silent payment

A silent-payment output carries a per-output tweak that is **required to sign
for it**. A build from `main` does not have the code that uses that tweak, and
rather than show you a balance it cannot spend, it refuses to open a wallet
containing one and points here.

So: if you have ever received a silent payment on a wallet, that wallet needs a
build from this branch. This is the reason the removal on `main` fails closed
instead of quietly dropping the field.

## Working on it

`alpha` tracks `main` and is rebased onto it rather than merged, so its history
stays a readable set of feature commits rather than a tangle of merge commits.
Anything on `alpha` that becomes ready moves to `main` as its own reviewed pull
request — this branch is a staging area, not a shortcut around review.
