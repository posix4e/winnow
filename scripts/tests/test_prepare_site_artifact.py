import importlib.machinery
import importlib.util
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader(
    "prepare_site_artifact", str(Path(__file__).parents[1] / "prepare-site-artifact"))
spec = importlib.util.spec_from_loader(loader.name, loader)
site = importlib.util.module_from_spec(spec)
loader.exec_module(site)

# Historical checkpoint fixture, validated against capture names independently.
CHECKPOINTS = ['01-onboarding', '03-receive', '56-home-beginner', '06-send-review', '08-send-confirmed', '09-home-after-send', '26-savings-share', '27-savings-funded', '14-approval-waiting', '15-approval-sent', '28-savings-confirmed']

class SiteArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "repo"
        self.docs = self.root / "docs"
        self.docs.mkdir(parents=True)
        (self.root / "UITests").mkdir()
        self.names = sorted(f"{name}.png" for name in CHECKPOINTS)
        calls = "\n".join(f'        Screenshots.capture(app, "{Path(name).stem}", testCase: self)'
                          for name in self.names)
        (self.root / "UITests/WinnowAppUITests.swift").write_text(
            f"    func {site.TEST}() {{\n{calls}\n    }}\n")
        (self.docs / "journeys.json").write_text(json.dumps([
            {"id": "setup", "section": "everyday", "title": "Start", "description": "Create a wallet.",
             "tests": [site.TEST], "journey": ["Create a wallet."]}]))
        for name in ["privacy", "architecture", "roadmap", "archive"]:
            (self.docs / f"{name}.html").write_text("<html></html>")
        (self.docs / "site.css").write_text("body { color: black }")
        (self.docs / "home.css").write_text("body { color: black }")
        (self.docs / "home.js").write_text("")
        (self.docs / "videos").mkdir()
        (self.docs / site.VIDEO).write_bytes(b"reviewed reference video")
        (self.docs / "screenshots").mkdir()
        for name in self.names:
            (self.docs / "screenshots" / name).write_bytes(b"reviewed reference screenshot")
        (self.docs / "screenshots/historical.png").write_bytes(b"historical illustration")
        self.media = self.base / "media"
        (self.media / "videos").mkdir(parents=True)
        (self.media / "screenshots").mkdir()
        (self.media / site.VIDEO).write_bytes(b"normalized video fixture")
        for name in self.names:
            (self.media / "screenshots" / name).write_bytes(b"\x89PNG\r\n\x1a\n" + name.encode())
        self.evidence = {"version": 1, "source_sha": "a" * 40,
                         "run_url": "https://github.com/winnowwallet/winnow/actions/runs/123",
                         "test": site.TEST, "result": "passed", "test_seconds": 200.5,
                         "video": {"sha256": site.digest(self.media / site.VIDEO),
                                   "bytes": 24, "duration_seconds": 220, "width": 720, "height": 1566},
                         "screenshots": {name: site.digest(self.media / "screenshots" / name)
                                         for name in self.names}}
        (self.media / site.MANIFEST).write_text(json.dumps(self.evidence))

    def validate_cli(self, *extra):
        with ExitStack() as stack:
            stack.enter_context(patch.object(site, "ROOT", self.root))
            for name in ["normalize_video", "probe"]:
                stack.enter_context(patch.object(site, name, side_effect=AssertionError(f"must not call {name}")))
            for name in ["run", "check_output"]:
                stack.enter_context(patch.object(site.subprocess, name, side_effect=AssertionError("no external tools")))
            output = stack.enter_context(redirect_stdout(io.StringIO()))
            stack.enter_context(redirect_stderr(io.StringIO()))
            site.main(["--validate-media", str(self.media), *extra])
            return output.getvalue()

    def test_validate_media_cli_checks_cache_without_building_or_copying(self):
        before = sorted(path.relative_to(self.base) for path in self.base.rglob("*"))
        manifest = (self.media / site.MANIFEST).read_bytes()
        self.assertIn("Validated cached journey media", self.validate_cli())
        self.assertEqual((self.media / site.MANIFEST).read_bytes(), manifest)
        self.assertEqual(sorted(path.relative_to(self.base) for path in self.base.rglob("*")), before)

    def test_validate_media_cli_fails_on_tampering(self):
        (self.media / "screenshots" / self.names[0]).write_bytes(b"changed")
        with self.assertRaisesRegex(SystemExit, "checksum or size mismatch"):
            self.validate_cli()

    def test_validate_media_cli_checks_current_capture_names(self):
        source = self.root / "UITests/WinnowAppUITests.swift"
        source.write_text(source.read_text().replace(CHECKPOINTS[0], "changed-capture"))
        with self.assertRaisesRegex(SystemExit, "does not describe this focused journey"):
            self.validate_cli()

    def test_validate_media_cli_rejects_missing_page_fields(self):
        fields = [("source_sha",), ("run_url",), ("test_seconds",), ("video",), ("screenshots",),
                  *(("video", name) for name in ["width", "height", "bytes", "duration_seconds", "sha256"])]
        for field in fields:
            with self.subTest(field=field):
                evidence = copy.deepcopy(self.evidence)
                target = evidence if len(field) == 1 else evidence[field[0]]
                del target[field[-1]]
                (self.media / site.MANIFEST).write_text(json.dumps(evidence))
                with self.assertRaises(SystemExit):
                    self.validate_cli()

    def test_validate_media_cli_rejects_malformed_page_fields(self):
        invalid = [("source_sha", ""), ("run_url", None), ("test_seconds", "200.5"),
                   ("test_seconds", float("nan")), ("test_seconds", True),
                   ("video", []), ("screenshots", []),
                   ("video.duration_seconds", float("inf")), ("video.duration_seconds", -1),
                   ("video.width", "720"), ("video.height", 0), ("video.bytes", True),
                   ("video.bytes", 25), ("video.sha256", "not a checksum")]
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                evidence = copy.deepcopy(self.evidence)
                path = field.split(".")
                target = evidence if len(path) == 1 else evidence[path[0]]
                target[path[-1]] = value
                (self.media / site.MANIFEST).write_text(json.dumps(evidence))
                with self.assertRaises(SystemExit):
                    self.validate_cli()
        (self.media / site.MANIFEST).write_text("[]")
        with self.assertRaises(SystemExit):
            self.validate_cli()

    def test_validate_media_cli_rejects_packaging_options(self):
        for extra in [[str(self.base / "output")], ["--journey", "journey"], ["--media", "media"],
                      ["--media-output", "output"], ["--source-sha", "a" * 40], ["--run-url", "url"]]:
            with self.subTest(extra=extra), self.assertRaises(SystemExit) as raised:
                self.validate_cli(*extra)
            self.assertEqual(raised.exception.code, 2)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            site.main([])
        self.assertEqual(raised.exception.code, 2)

    def test_tampered_cached_image_is_rejected(self):
        (self.media / "screenshots" / self.names[0]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum or size mismatch"):
            site.validate_media(self.media, self.names)

    def test_cached_media_must_cover_current_capture_names(self):
        with self.assertRaisesRegex(ValueError, "does not describe this focused journey"):
            site.validate_media(self.media, sorted([*self.names[:-1], "different.png"]))

    def test_failed_journey_is_not_published(self):
        journey = self.base / "journey"
        journey.mkdir()
        (journey / "node-ui.log").write_text("** TEST EXECUTE FAILED **")
        with self.assertRaisesRegex(ValueError, "successful focused test"):
            site.fresh_media(journey, self.base / "new-media", self.names, "b" * 40, "run")

    def test_missing_checkpoint_fails_before_encoding(self):
        journey = self.base / "journey"
        journey.mkdir()
        (journey / "node-ui.log").write_text(
            f"Test Case '-[WinnowAppUITests.WinnowAppUITests {site.TEST}]' passed (200.5 seconds).\n"
            "** TEST EXECUTE SUCCEEDED **")
        (journey / "NodeUI.xcresult").mkdir()
        with patch.object(site, "normalize_video", side_effect=AssertionError("must not encode")):
            with self.assertRaisesRegex(ValueError, "missing or invalid checkpoint"):
                site.fresh_media(journey, self.base / "new-media", self.names, "b" * 40, "run")

    def test_full_video_uses_presentation_timestamps_and_bounded_bitrate(self):
        original = {"duration_seconds": 668.848333, "bytes": 180_000_000}
        encoded = {"duration_seconds": 668.875, "bytes": 24_000_000}
        with patch.object(site, "probe", side_effect=[original, encoded]), \
             patch.object(site.subprocess, "run") as run:
            self.assertEqual(site.normalize_video(Path("raw.mp4"), Path("web.mp4")), (original, encoded))
        args = run.call_args.args[0]
        self.assertIn("+igndts", args)
        self.assertIn("+faststart", args)
        self.assertNotIn("-ss", args)
        # Limit only the synthetic tail from inflated final VFR frame duration,
        # preserving the source's complete presentation timeline from zero.
        self.assertGreater(args.index("-t"), args.index("-i"))
        self.assertEqual(float(args[args.index("-t") + 1]), original["duration_seconds"])
        self.assertLess(int(args[args.index("-b:v") + 1]) * original["duration_seconds"] / 8, site.MAX_BYTES)

    def test_oversized_shortened_or_extended_video_is_rejected(self):
        original = {"duration_seconds": 255}
        for encoded, error in [({"duration_seconds": 255, "bytes": site.MAX_BYTES + 1}, "25 MiB"),
                               ({"duration_seconds": 240, "bytes": 24_000_000}, "changed the recording duration"),
                               ({"duration_seconds": 295, "bytes": 24_000_000}, "changed the recording duration")]:
            with self.subTest(encoded=encoded), patch.object(site, "probe", side_effect=[original, encoded]), \
                 patch.object(site.subprocess, "run"):
                with self.assertRaisesRegex(ValueError, error):
                    site.normalize_video(Path("raw.mp4"), Path("web.mp4"))


if __name__ == "__main__":
    unittest.main()


class NormalizeOnlyTests(unittest.TestCase):
    setUp = SiteArtifactTests.setUp
    def test_normalize_only_preserves_complete_media_without_building_site(self):
        import shutil
        journey=self.base/'journey';journey.mkdir()
        (journey/'node-ui.log').write_text(
            "Test Case '-[WinnowAppUITests.WinnowAppUITests " + site.TEST +
            "]' passed (200.5 seconds).\n** TEST EXECUTE SUCCEEDED **")
        (journey/'NodeUI.xcresult').mkdir()
        shutil.copytree(self.media/'screenshots',journey/'node-screenshots')
        output=self.base/'normalized'
        def encode(source,destination):
            destination.write_bytes((self.media/site.VIDEO).read_bytes())
            return self.evidence['video'],self.evidence['video']
        with patch.object(site,'ROOT',self.root), patch.object(site,'normalize_video',side_effect=encode) as encoder:
            site.main(['--normalize-journey',str(journey),'--media-output',str(output),
                       '--source-sha','a'*40,'--run-url',self.evidence['run_url']])
            encoder.assert_called_once()
            self.assertEqual(len(list((output/'screenshots').glob('*.png'))),11)
            self.assertEqual(site.validate_media(output,self.names)['source_sha'],'a'*40)
