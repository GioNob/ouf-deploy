import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('governance_delivery',ROOT/'scripts/prepare-policy-token-governance-intake.py')
delivery=importlib.util.module_from_spec(spec);spec.loader.exec_module(delivery)

class GovernanceDeliveryTest(unittest.TestCase):
    def test_existing_portable_gh_without_path_preserves_pins_and_invokes_root_only_after_all_sources(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as temporary:
            home=Path(temporary);gh=home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh';gh.parent.mkdir(parents=True)
            gh.write_text('fixture');gh.chmod(0o700);calls=[]
            def run(args,**kwargs):
                calls.append(args)
                if args[0]=='sudo':
                    self.assertEqual(len(calls),4)
                    payload=json.loads(kwargs['input']);self.assertEqual(payload['sourceCommit'],delivery.COMMIT)
                    self.assertEqual(set(payload['sources']),set(delivery.HASHES))
                    self.assertEqual({n:hashlib.sha256(base64.b64decode(raw)).hexdigest()
                        for n,raw in payload['sources'].items()},delivery.HASHES)
                    return subprocess.CompletedProcess(args,0)
                self.assertEqual(args[0],str(gh));self.assertIn('?ref='+delivery.COMMIT,args[2])
                name=next(n for n in delivery.HASHES if '/'+n+'.py?' in args[2])
                # The historical three-source command pins the original
                # binding compiler; current behavior has separate tests.
                path=(ROOT/'tests/fixtures/policy_token_iam_binding_bcd20f30085.source' if name=='iam_binding_candidate'
                    else ROOT/'tools/semantic_policy_token_owner'/(name+'.py'))
                raw=path.read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),delivery.HASHES[name])
                return subprocess.CompletedProcess(args,0,stdout=base64.b64encode(raw))
            with patch.object(delivery.Path,'home',return_value=home),patch.object(delivery.shutil,'which',return_value=None),patch.object(delivery.subprocess,'run',side_effect=run):
                self.assertEqual(delivery.main(),0)
    def test_missing_or_changed_source_fails_before_sudo(self):
        with patch.object(delivery,'existing_gh',return_value=None),patch.object(delivery.subprocess,'run')as run:
            with self.assertRaisesRegex(SystemExit,'EXISTING_GH'):delivery.main()
            self.assertFalse(run.called)
        calls=[]
        def changed(args,**kwargs):
            calls.append(args);return subprocess.CompletedProcess(args,0,stdout=base64.b64encode(b'TAMPERED'))
        with patch.object(delivery,'existing_gh',return_value='/fixture/gh'),patch.object(delivery.subprocess,'run',side_effect=changed):
            with self.assertRaisesRegex(SystemExit,'SOURCE_HASH'):delivery.main()
        self.assertFalse(any(args[0]=='sudo' for args in calls))
    def test_actual_isolated_root_rechecks_source_hash_before_import_or_target_read(self):
        if os.geteuid()!=0:self.fail('native root qualification required')
        payload={'sourceCommit':delivery.COMMIT,'sources':{n:base64.b64encode(b'TAMPERED').decode() for n in delivery.HASHES}}
        result=subprocess.run([sys.executable,'-I','-B','-c',delivery.ROOT_CODE],input=json.dumps(payload).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertIn(b'SOURCE_HASH_MISMATCH',result.stderr)
        self.assertNotIn(b'privateEvidencePath',result.stdout)

if __name__=='__main__':unittest.main()
