import copy
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import runpy
import tempfile
import unittest

M = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'ci-validation'))

class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime.now(timezone.utc)
        self.identity={'fingerprint':'a'*64,'policy':M['POLICY'],'workflow_revision':'b'*40}
        self.record={'identity':copy.deepcopy(self.identity),'repository':'winnowwallet/winnow',
                     'result':'success','fresh':True,'source_sha':'c'*40,
                     'created_at':self.now.isoformat(),
                     'lanes':{x:{'result':'success','tests':M['POLICY']['minimum_tests'].get(x,0),'architecture':'arm64','image':'macos26-20261012.1','runtime':'iOS 26.5 (23F77)','release_inspected':True,'source_sha':'c'*40,'debug_sha256':'f'*64} for x in M['LANES']},
                     'files':{**{'lanes/'+x+'.json':'d'*64 for x in M['LANES']},'media/journey-provenance.json':'d'*64}}
    def valid(self):
        return M['validate'](self.record,self.identity,'winnowwallet/winnow',self.now)
    def test_identical_inputs_allow_different_merge_commit(self):
        self.assertTrue(self.valid())
        self.record['source_sha']='e'*40
        for lane in self.record['lanes'].values():lane['source_sha']='e'*40
        self.assertTrue(self.valid())
    def test_changed_source_resource_test_workflow_toolchain_is_rejected(self):
        for field in self.identity:
            with self.subTest(field=field):
                old=self.record['identity'][field]
                self.record['identity'][field]='changed'
                self.assertFalse(self.valid())
                self.record['identity'][field]=old
    def test_wrong_repository_and_reused_partial_records_rejected(self):
        for field,value in [('repository','fork/winnow'),('result','failure'),('fresh',False)]:
            old=self.record[field]; self.record[field]=value
            self.assertFalse(self.valid());self.record[field]=old
    def test_every_lane_must_pass_and_tests_must_execute(self):
        for lane in M['LANES']:
            for result in ['failure','cancelled','skipped']:
                self.record['lanes'][lane]['result']=result
                self.assertFalse(self.valid())
            self.record['lanes'][lane]['result']='success'
        del self.record['lanes']['units']
        self.assertFalse(self.valid())
    def test_different_or_unverified_shared_build_rejected(self):
        for value in [None, 'e'*64]:
            self.record['lanes']['units']['debug_sha256']=value
            self.assertFalse(self.valid())

    def test_stale_and_future_records_rejected(self):
        for age in [timedelta(days=7,seconds=1),timedelta(seconds=-1)]:
            self.record['created_at']=(self.now-age).isoformat()
            self.assertFalse(self.valid())
    def test_corrupt_missing_and_outside_artifacts_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); p=root/'a';p.write_text('good')
            self.record['files']={'a':M['sha'](p)}
            M['verify_files'](root,self.record)
            p.write_text('bad')
            with self.assertRaises(ValueError):M['verify_files'](root,self.record)
            p.unlink()
            with self.assertRaises(ValueError):M['verify_files'](root,self.record)
            self.record['files']={'../outside':'a'}
            with self.assertRaises(ValueError):M['verify_files'](root,self.record)

    def test_symlink_artifacts_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'real').write_text('good'); (root/'link').symlink_to('real')
            self.record['files']={'link':M['sha'](root/'real')}
            with self.assertRaises(ValueError):M['verify_files'](root,self.record)

    def test_wrong_lane_toolchain_and_missing_release_inspection_rejected(self):
        for lane in M['LANES']:
            for field,value in [('architecture','x86_64'),('runtime','iOS 26.4 (23E244)'),('runtime','iOS 26.5'),('image','')]:
                old=self.record['lanes'][lane][field]; self.record['lanes'][lane][field]=value
                self.assertFalse(self.valid()); self.record['lanes'][lane][field]=old
            # A newer runner image is recorded, not refused.
            self.record['lanes'][lane]['image']='macos26-20261101.1'
            self.assertTrue(self.valid())
        self.record['lanes']['build']['release_inspected']=False
        self.assertFalse(self.valid())

class CompleteFingerprintTests(unittest.TestCase):
    def test_each_validation_input_changes_the_key(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            def git(*args):
                return subprocess.check_output(['git','-C',d,*args],stderr=subprocess.DEVNULL)
            git('init');git('config','user.name','Test');git('config','user.email','test@example.invalid')
            paths=['Sources/a.swift','Tests/a.swift','AppTests/a.swift','UITests/a.swift',
                   'docs/site.css','.github/workflows/ci-parallel.yml','.github/workflows/site.yml',
                   'scripts/prepare-site-artifact','scripts/tests/test_prepare_site_artifact.py','Package.resolved','project.yml']
            for path in paths:
                p=root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('original')
            git('add','.');git('commit','-m','baseline')
            baseline=M['fingerprint'](cwd=d)
            for path in paths:
                with self.subTest(path=path):
                    p=root/path;p.write_text('changed');git('add',path);git('commit','-m','changed')
                    self.assertNotEqual(M['fingerprint'](cwd=d),baseline)
                    git('reset','--hard','HEAD~1')
