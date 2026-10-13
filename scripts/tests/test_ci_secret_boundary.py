"""Repository secrets must never cross into a validation worker workflow."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2] / '.github/workflows'


def jobs(text):
    section = text.split('\njobs:\n', 1)[1]
    starts = list(re.finditer(r'^  ([\w-]+):\s*$', section, re.M))
    return {m[1]: section[m.end():starts[i+1].start() if i+1 < len(starts) else len(section)]
            for i, m in enumerate(starts)}


class SecretBoundaryTests(unittest.TestCase):
    def test_workers_have_no_repository_secret_channel(self):
        for name in ('ci-hosted.yml', 'ci-parallel.yml'):
            with self.subTest(workflow=name):
                text = (ROOT/name).read_text()
                self.assertNotRegex(text, r'\bsecrets\s*[:.]')
                self.assertNotRegex(text, r'(?m)^\s+environment:', 'An environment could inject signing secrets')
        for name in ('ci.yml', 'release.yml'):
            for job, body in jobs((ROOT/name).read_text()).items():
                if re.search(r'uses: \./\.github/workflows/(ci|ci-hosted|ci-parallel)\.yml', body):
                    with self.subTest(workflow=name, job=job):
                        self.assertNotRegex(body, r'\bsecrets\s*[:.]')

    def test_wallet_ci_has_no_deployment_secrets(self):
        caller = (ROOT/'ci.yml').read_text()
        self.assertNotRegex(caller, r'\bsecrets\s*[:.]')
        self.assertNotIn('website', jobs(caller))
        self.assertFalse((ROOT/'site.yml').exists())


class AggregateGateTests(unittest.TestCase):
    def test_wallet_gate_requires_exactly_one_successful_lane(self):
        import itertools
        import os
        import subprocess
        import textwrap
        script = textwrap.dedent(jobs((ROOT/'ci.yml').read_text())['validation'].split('run: |\n', 1)[1])
        statuses = ('success', 'skipped', 'failure', 'cancelled')
        for hosted, parallel in itertools.product(statuses, statuses):
            expected = (hosted, parallel) in [('success', 'skipped'), ('skipped', 'success')]
            with self.subTest(hosted=hosted, parallel=parallel):
                result = subprocess.run(['bash', '-e', '-c', script],
                                        env={**os.environ, 'HOSTED': hosted, 'PARALLEL': parallel}, capture_output=True)
                self.assertEqual(result.returncode == 0, expected)
