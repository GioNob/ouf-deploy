import ast
import base64
import hashlib
import importlib.util
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/semantic_policy_token_owner'))
import iam_binding_candidate as binding
spec=importlib.util.spec_from_file_location('migration_host_delivery',ROOT/'scripts/prepare-policy-token-migration-host-inputs.py')
delivery=importlib.util.module_from_spec(spec);spec.loader.exec_module(delivery)

class MigrationHostReviewTest(unittest.TestCase):
    def test_absent_existing_and_symlink_roots_are_observed_without_custody_acceptance(self):
        tree=ast.parse(delivery.ROOT_BODY);function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='root_metadata')
        namespace={'binding':binding,'stat':stat};exec(compile(ast.Module(body=[function],type_ignores=[]),'metadata-fixture','exec'),namespace)
        with tempfile.TemporaryDirectory(dir=ROOT)as temp:
            root=Path(temp);missing=root/'absent';value=namespace['root_metadata'](missing)
            self.assertEqual(value['state'],'ABSENT');self.assertFalse(value['custodyAccepted']);self.assertFalse(missing.exists())
            value=namespace['root_metadata'](root);self.assertEqual(value['state'],'EXISTING_NOT_ACCEPTED')
            self.assertFalse(value['custodyAccepted']);self.assertIn('inode',value['ancestors'][-1])
            link=root/'symlink';link.symlink_to(root)
            with self.assertRaisesRegex(binding.CandidateDenied,'ANCESTRY_UNPROVEN'):namespace['root_metadata'](link)
    def test_portable_gh_bound_gap_component_and_prepare_only_root(self):
        component=base64.b64decode(delivery.GAP_COMPONENT,validate=True)
        self.assertEqual(component,(ROOT/'tools/semantic_policy_token_owner/accounting_gap_session.py').read_bytes())
        self.assertEqual(hashlib.sha256(component).hexdigest(),delivery.GAP_COMPONENT_HASH)
        self.assertNotIn('FirstGapSession(',delivery.ROOT_BODY);self.assertNotIn('entry.main(',delivery.ROOT_BODY)
        with tempfile.TemporaryDirectory(dir=ROOT)as temp:
            home=Path(temp);gh=home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh';gh.parent.mkdir(parents=True)
            gh.write_text('SYNTHETIC');gh.chmod(0o700);capsule=(ROOT/'releases/policy-token-iam-action-source-capsule-20261013.json').read_bytes();calls=[]
            def run(argv,**kw):
                calls.append(argv)
                if argv[0]=='sudo':
                    self.assertEqual(argv[:6],['sudo','--','/usr/bin/python3','-I','-B','-S']);self.assertEqual(kw['input'],capsule)
                    self.assertIn(delivery.GAP_COMPONENT_HASH,argv[-1]);self.assertEqual(kw['timeout'],140)
                    return subprocess.CompletedProcess(argv,0)
                self.assertEqual(argv[0],str(gh));return subprocess.CompletedProcess(argv,0,stdout=base64.b64encode(capsule))
            with patch.object(delivery.Path,'home',return_value=home),patch.object(delivery.shutil,'which',return_value=None),patch.object(delivery.subprocess,'run',side_effect=run):self.assertEqual(delivery.main(),0)
            self.assertEqual(len(calls),2)
    def test_invalid_capsule_is_denied_in_actual_isolated_root_before_review_or_budget(self):
        code='CAPSULE_SHA='+repr(delivery.CAPSULE_SHA)+'\nGAP_COMPONENT_HASH='+repr(delivery.GAP_COMPONENT_HASH)+'\nGAP_COMPONENT='+repr(delivery.GAP_COMPONENT)+'\n'+delivery.ROOT_BODY
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',code],input=b'CHANGED',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'');self.assertIn(b'FULL_CAPSULE_HASH_MISMATCH',result.stderr)

if __name__=='__main__':unittest.main()
