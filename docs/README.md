[Back to main README](../README.md)

# Website and product explanations

This directory is the static website and the public explanation of Winnow's
features, architecture, testing, and limitations. The app also bundles five
technical guides and site.css so those explanations are available offline.

The home and recording pages were generated from the Swift app's recorded UI journey
([journey inventory](journeys.json)); that generator and journey were removed with the Swift app
(see [PORT.md](../PORT.md)), so the committed pages and screenshots are kept as they are.

[home.css](home.css) styles only the homepage; app-bundled [site.css](site.css)
is unaffected. Native radio controls and the gallery work without JavaScript.
[home.js](home.js) enhances recording links with a dialog containing the full
video. It does not autoplay or preload the recording. Without JavaScript, those
links open the [recording page](https://winnowwallet.com/recording), which retains
playback controls and source provenance. The [signing guide](vaults.html)
explains the policies. Other pages are authored directly. Shared wallets combines the former custody overview with setup and backup instructions. Technical guides begin with summaries and contents links; deeper reference material uses native disclosures. The archive keeps old talk notes and public-signet evidence separate from the current recording. Older illustrations retain their dated provenance.
[The roadmap](roadmap.html) separates planned work from current behavior.
[Architecture](architecture.html) links directly to the focused technical guides.
Those HTML files are the maintained explanations; no separate paper or paper
index is needed. [_redirects](_redirects) sends old paper URLs to the architecture page.

Run `scripts/build-site --check` and, with real LFS images downloaded,
`scripts/check-site` from the root. Both accept `--root` for a staged repository.
[prepare-site-artifact](../scripts/prepare-site-artifact) builds the deployable
directory; [Website CI](../.github/workflows/site.yml) consumes that artifact.
The checks cover generation, local links and section targets, media objects, and the 25 MiB per-file
hosting limit, not rendered-browser layout or the truth of every prose claim.

For a successful CI journey, run `scripts/prepare-site-artifact OUTPUT --journey
JOURNEY --media-output MEDIA`. It copies all 16 current checkpoints, normalizes
the full recording with `+igndts` and no cuts, and records source SHA, run URL,
duration, and checksums in `journey-provenance.json`. The output includes a local
`/recording` page explaining that evidence. Replaying an older artifact requires
its `--source-sha` and `--run-url`; CI defaults to the current checkout and run.

Website-only builds use `--media MEDIA` to reuse the small normalized artifact
without video tools or raw result bundles. Its original recording provenance
stays intact while pages are regenerated from the current source. The optional
`--media-output` contains only the video, 16 PNGs, and provenance JSON for caching.
With neither media option, packaging retains the reviewed repository reference
assets and explicitly makes no new integration-result claim. Output directories
must be new. Packaging never changes repository media.
[Testing policy](testing.md), [the recording](videos/README.md),
[current and historical screenshots](screenshots/README.md), and
[security evidence](security/README.md) explain the supporting records.
