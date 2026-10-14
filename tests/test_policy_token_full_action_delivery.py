import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('full_action_delivery',ROOT/'scripts/prepare-policy-token-full-action-review.py')
delivery=importlib.util.module_from_spec(spec);spec.loader.exec_module(delivery)
CAPSULE=ROOT/'releases/policy-token-iam-action-source-capsule-20261013.json'

class FullActionDeliveryTest(unittest.TestCase):
    def test_existing_portable_gh_one_pinned_capsule_then_prepare_only_no_site_root(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as t:
            home=Path(t);gh=home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh';gh.parent.mkdir(parents=True)
            gh.write_text('SYNTHETIC');gh.chmod(0o700);calls=[];raw=CAPSULE.read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),delivery.CAPSULE_SHA)
            def run(args,**kw):
                calls.append(args)
                if args[0]=='sudo':
                    self.assertEqual(len(calls),2);self.assertEqual(args[:6],['sudo','--','/usr/bin/python3','-I','-B','-S'])
                    self.assertEqual(kw['input'],raw);self.assertIn('entry.main(manifest)',args[-1])
                    self.assertNotIn("mode='apply'",args[-1]);return subprocess.CompletedProcess(args,0)
                self.assertEqual(args[0],str(gh));self.assertTrue(args[2].endswith('?ref='+delivery.CAPSULE_COMMIT))
                return subprocess.CompletedProcess(args,0,stdout=base64.b64encode(raw))
            with patch.object(delivery.Path,'home',return_value=home),patch.object(delivery.shutil,'which',return_value=None),patch.object(delivery.subprocess,'run',side_effect=run):
                self.assertEqual(delivery.main(),0)
    def test_changed_capsule_and_unqualified_pin_deny_before_sudo(self):
        with patch.object(delivery,'CAPSULE_SHA','PENDING'),patch.object(delivery.subprocess,'run')as run:
            with self.assertRaisesRegex(SystemExit,'NOT_QUALIFIED'):delivery.main()
            self.assertFalse(run.called)
        calls=[]
        def changed(args,**kw):calls.append(args);return subprocess.CompletedProcess(args,0,stdout=base64.b64encode(b'CHANGED'))
        with patch.object(delivery.shutil,'which',return_value='/fixture/gh'),patch.object(delivery.subprocess,'run',side_effect=changed):
            with self.assertRaisesRegex(SystemExit,'HASH_MISMATCH'):delivery.main()
        self.assertFalse(any(c[0]=='sudo' for c in calls))
    def test_actual_isolated_no_site_root_denies_checksum_and_apply_field_before_import(self):
        for case in ('checksum','apply'):
            raw=b'CHANGED' if case=='checksum' else json.dumps({'mode':'apply'}).encode()
            expected=delivery.CAPSULE_SHA if case=='checksum' else hashlib.sha256(raw).hexdigest()
            code='CAPSULE_SHA='+repr(expected)+'\n'+delivery.ROOT_BODY
            result=subprocess.run([sys.executable,'-I','-B','-S','-c',code],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
            self.assertIn(b'HASH_MISMATCH' if case=='checksum' else b'EXACT_FULL_CAPSULE_REQUIRED',result.stderr)

if __name__=='__main__':unittest.main()
