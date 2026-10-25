"""Media reuse must preserve the app's inputs and the source run's provenance."""
from datetime import datetime, timezone
import importlib.machinery
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


loader = importlib.machinery.SourceFileLoader(
    "ci_journey_cache", str(Path(__file__).parents[1] / "ci-journey-cache"))
spec = importlib.util.spec_from_loader(loader.name, loader)
cache = importlib.util.module_from_spec(spec)
loader.exec_module(cache)


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "--quiet")
        self.git("config", "core.filemode", "true")
        self.write("Sources/App.swift", "app")
        self.baseline = self.tree()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def write(self, path, text):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text)

    def tree(self):
        self.git("add", "--all")
        return self.git("write-tree")

    def digest(self):
        return cache.fingerprint(self.tree(), cwd=self.root)

    def test_website_only_changes_keep_the_same_fingerprint(self):
        before = cache.fingerprint(self.baseline, cwd=self.root)
        for path in ["docs/index.html", "docs/videos/wallet-journey.mp4", "docs/journeys.json",
                     "README.md", "UITests/README.md", ".github/internal/ci-release.md",
                     ".github/workflows/site.yml", "scripts/build-site", "scripts/check-site",
                     "scripts/prepare-site-artifact", "scripts/tests/test_build_site.py",
                     "scripts/tests/test_check_site.py", "scripts/tests/test_prepare_site_artifact.py"]:
            with self.subTest(path=path):
                self.write(path, "website changed")
                self.assertEqual(self.digest(), before)

    def test_every_bundled_page_and_build_or_test_input_invalidates(self):
        paths = [
            "docs/site.css", "docs/mobile.html", "docs/read-side.html",
            "docs/write-side.html", "docs/import.html",
            "Sources/App.swift", "Tools/Debug/Package.swift", "Tests/WalletCoreTests/WalletTests.swift",
            "AppTests/WalletStartupTests.swift", "UITests/PeerGatewaySettingsUITests.swift",
            "Tests/Support/Node/SignetMiner.swift", "Package.swift", "Package.resolved", "project.yml",
            "scripts/ci-ui-journey", "scripts/signet-fixture", "scripts/ci-journey-cache",
            "scripts/tests/test_ci_journey_cache.py", ".github/workflows/ci.yml", ".swiftlint.yml",
            "Tests/WalletCoreTests/Vectors/input.md", "Tools/Tests/fixture.md", "Sources/App/help.md",
            "AppTests/fixture.md", "UITests/fixture.md", "scripts/tests/fixture.md",
        ]
        for path in paths:
            with self.subTest(path=path):
                before = self.digest()
                self.write(path, "changed build input")
                self.assertNotEqual(self.digest(), before)

    def test_modes_renames_and_deletions_invalidate_even_with_identical_content(self):
        before = self.digest()
        (self.root / "Sources/App.swift").chmod(0o755)
        changed_mode = self.digest()
        self.assertNotEqual(changed_mode, before)
        (self.root / "Sources/App.swift").rename(self.root / "Sources/Renamed.swift")
        renamed = self.digest()
        self.assertNotEqual(renamed, changed_mode)
        (self.root / "Sources/Renamed.swift").unlink()
        self.assertNotEqual(self.digest(), renamed)

    def test_new_bundled_docs_resource_invalidates_on_later_content_changes(self):
        self.write("docs/extra.html", "original page")
        website_only = self.digest()
        self.write("project.yml", "sources:\n  - path: docs/extra.html\n    type: file\n")
        bundled = self.digest()
        self.assertNotEqual(bundled, website_only)
        self.write("docs/extra.html", "updated app resource")
        self.assertNotEqual(self.digest(), bundled)

    def test_bundled_directories_and_quoted_paths_are_included(self):
        self.write("project.yml", "sources:\n  - path: './docs/help files' # bundled directory\n")
        before = self.digest()
        self.write("docs/help files/README.md", "app help")
        self.assertNotEqual(self.digest(), before)
        self.write("project.yml", "sources:\n  - path: docs/*.html\n")
        before = self.digest()
        self.write("docs/new.html", "globbed app help")
        self.assertNotEqual(self.digest(), before)

    def test_fingerprint_uses_selected_git_tree_not_worktree_contents(self):
        before = cache.fingerprint(self.baseline, cwd=self.root)
        self.write("Sources/App.swift", "uncommitted app change")
        self.assertEqual(cache.fingerprint(self.baseline, cwd=self.root), before)
        self.assertRegex(before, r"^[0-9a-f]{64}$")


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.digest = "a" * 64
        self.now = datetime(2026, 9, 17, tzinfo=timezone.utc)
        self.artifact = {
            "name": f"journey-media-{self.digest}", "expired": False, "size_in_bytes": 1024,
            "expires_at": "2026-10-17T00:00:00Z",
            "workflow_run": {"id": 42, "repository_id": 7, "head_repository_id": 7,
                             "head_sha": "b" * 40},
        }
        self.run = {
            "id": 42, "path": ".github/workflows/ci.yml", "status": "completed", "conclusion": "success",
            "repository": {"id": 7}, "head_repository": {"id": 7}, "head_sha": "b" * 40,
            "event": "pull_request", "head_branch": "feature",
        }

    def lookup(self, artifacts=None, run=None):
        def request(path):
            if "/actions/artifacts?" in path:
                self.assertIn(f"name=journey-media-{self.digest}", path)
                return {"artifacts": artifacts if artifacts is not None else [self.artifact]}
            self.assertEqual(path, "repos/owner/repo/actions/runs/42")
            return run if run is not None else self.run
        return cache.find_artifact("owner/repo", 7, self.digest, request, self.now)

    def test_successful_same_repo_ci_artifact_is_reused(self):
        self.assertEqual(self.lookup(), {"run-id": "42", "artifact-name": self.artifact["name"]})
        self.run.update(event="push", head_branch="main", path=".github/workflows/ci.yml@main")
        self.assertIsNotNone(self.lookup())

    def test_fresh_manual_and_main_scheduled_runs_can_supply_later_reuse(self):
        for event, branch in [("workflow_dispatch", "feature"), ("schedule", "main")]:
            with self.subTest(event=event, branch=branch):
                self.assertIsNotNone(self.lookup(run=dict(self.run, event=event, head_branch=branch)))

    def test_wrong_workflow_fork_failure_and_untrusted_events_are_rejected(self):
        for change in [
            {"path": ".github/workflows/site.yml"}, {"conclusion": "failure"},
            {"conclusion": "cancelled"}, {"status": "in_progress"},
            {"repository": {"id": 8}}, {"head_repository": {"id": 8}},
            {"head_repository": None}, {"head_sha": "c" * 40}, {"id": 43},
            {"event": "push", "head_branch": "feature"}, {"event": "schedule", "head_branch": "feature"},
            {"event": "release"}, {"event": "pull_request_target"},
        ]:
            with self.subTest(change=change):
                self.assertIsNone(self.lookup(run=dict(self.run, **change)))

    def test_wrong_name_expired_empty_and_fork_artifacts_are_rejected(self):
        for change in [
            {"name": "journey-media-" + "c" * 64}, {"expired": True},
            {"expires_at": "2026-09-16T00:00:00Z"}, {"expires_at": "invalid"},
            {"size_in_bytes": 0}, {"workflow_run": None},
            {"workflow_run": dict(self.artifact["workflow_run"], repository_id=8)},
            {"workflow_run": dict(self.artifact["workflow_run"], head_repository_id=8)},
        ]:
            with self.subTest(change=change):
                self.assertIsNone(self.lookup(artifacts=[dict(self.artifact, **change)]))

    def test_skips_bad_candidate_and_can_find_a_valid_one(self):
        expired = dict(self.artifact, expired=True)
        self.assertIsNotNone(self.lookup(artifacts=[{}, expired, self.artifact]))
        self.assertIsNone(self.lookup(artifacts=[]))

    def invoke(self, event="pull_request", ref="refs/pull/1/merge", evidence=None, error=None):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary, "outputs")
            summary = Path(temporary, "summary")
            environment = {"GITHUB_EVENT_NAME": event, "GITHUB_REF": ref,
                           "GITHUB_REPOSITORY": "owner/repo", "GITHUB_REPOSITORY_ID": "7",
                           "GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(summary),
                           "GITHUB_SERVER_URL": "https://github.example/"}
            with patch.dict(os.environ, environment), patch.object(cache.sys, "argv", ["ci-journey-cache"]), \
                 patch.object(cache, "fingerprint", return_value=self.digest), \
                 patch.object(cache, "find_artifact", return_value=evidence, side_effect=error) as lookup, \
                 patch("sys.stdout", new_callable=io.StringIO) as stdout, \
                 patch("sys.stderr", new_callable=io.StringIO):
                cache.main()
            self.assertEqual(stdout.getvalue(), output.read_text())
            self.last_summary = summary.read_text()
            return dict(line.split("=", 1) for line in output.read_text().splitlines()), lookup.call_count

    def test_current_manual_scheduled_release_and_non_main_pushes_force_fresh(self):
        for event, ref in [("workflow_dispatch", "refs/heads/main"), ("schedule", "refs/heads/main"),
                           ("release", "refs/tags/v1"), ("push", "refs/tags/v1"),
                           ("push", "refs/heads/feature"), ("pull_request_target", "refs/heads/main")]:
            with self.subTest(event=event, ref=ref):
                outputs, calls = self.invoke(event, ref)
                self.assertEqual(outputs, {"fingerprint": self.digest, "reuse": "false"})
                self.assertEqual(calls, 0)

    def test_pr_and_main_outputs_include_download_coordinates_only_on_a_hit(self):
        for event, ref in [("pull_request", "refs/pull/1/merge"), ("push", "refs/heads/main")]:
            outputs, calls = self.invoke(event, ref, evidence=self.lookup())
            self.assertEqual(outputs, {"fingerprint": self.digest, "reuse": "true",
                                      "run-id": "42", "artifact-name": self.artifact["name"]})
            self.assertEqual(calls, 1)
        outputs, _ = self.invoke()
        self.assertEqual(outputs, {"fingerprint": self.digest, "reuse": "false"})

    def test_api_or_malformed_response_failure_falls_back_to_fresh(self):
        for error in [OSError("gh unavailable"), subprocess.CalledProcessError(1, "gh"),
                      subprocess.TimeoutExpired("gh", 30), ValueError("invalid JSON"), KeyError("artifacts")]:
            with self.subTest(error=error):
                outputs, calls = self.invoke(error=error)
                self.assertEqual(outputs, {"fingerprint": self.digest, "reuse": "false"})
                self.assertEqual(calls, 1)

    def test_summary_links_reused_evidence_and_distinguishes_fresh_checks(self):
        self.invoke(evidence=self.lookup())
        self.assertIn("Wallet and test inputs are unchanged", self.last_summary)
        self.assertIn("https://github.example/owner/repo/actions/runs/42", self.last_summary)
        self.assertIn("original recording provenance", self.last_summary)
        self.invoke()
        self.assertIn("Running fresh wallet tests and the recorded journey", self.last_summary)
        self.assertNotIn("/actions/runs/", self.last_summary)


if __name__ == "__main__":
    unittest.main()
