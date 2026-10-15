[Back to main README](../../README.md)

# Regression tests for repository tooling

These Python tests cover journey media reuse, journey evidence normalization, App Store
status parsing, and release policy. They prevent skipped checks being mistaken
for evidence and check the inputs used to prepare and release the app.

[test_ci_journey_cache.py](test_ci_journey_cache.py) checks test/build input
matching and requires successful same-repository evidence with a retained media
artifact. Missing or uncertain evidence must run fresh tests. Website-only reuse
keeps the recording's original provenance rather than claiming a new test run.

[test_prepare_site_artifact.py](test_prepare_site_artifact.py) checks evidence
normalization and validation independently of public website sources.

[test_appstore_status.py](test_appstore_status.py) and
[test_release_policy.py](test_release_policy.py) check release tooling with local
fixtures, without App Store requests or signing.

Use Python 3.11 or later (CI provisions 3.12); the macOS system Python may be
older. Run all suites from the repository root with that interpreter:

```sh
python3.12 -m unittest discover -s scripts/tests
```

CI runs the relevant tooling suites. Site-generation regressions are maintained
in winnowwallet/website. These tests validate tooling behavior, not app behavior.
