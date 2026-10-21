import ast
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.ingestion_rollout_preparation import stage18_delivery as d


class Delivery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case=json.loads((ROOT/'releases/ingestion-rollout-stage18-successor-case-20261021.json').read_bytes())
        cls.artifacts={kind:fn(ROOT,cls.case) for kind,fn in [('human',d.generate_auth),('runtime',d.generate_runtime)]}

    def test_both_artifacts_reproduce_and_preserve_all_frozen_native_sources(self):
        _,native=d.native_payload(ROOT)
        for kind,(raw,declaration)in self.artifacts.items():
            self.assertEqual(raw,(ROOT/('scripts/ingestion-rollout-stage18-'+kind+'-20261021.py')).read_bytes())
            self.assertLess(len(raw),1048576)
            if kind=='human':
                self.assertTrue(all(declaration['sourceHashes'].get(k)==v for k,v in native['sourceHashes'].items()))
            else:self.assertEqual(declaration['nativeDeclaration'],native)

    def test_launchers_reproduce_and_shell_syntax_is_valid(self):
        for kind,(raw,_)in self.artifacts.items():
            expected=d.launcher(kind,raw);path=ROOT/('scripts/launch-ingestion-rollout-stage18-'+kind+'-20261021.sh')
            self.assertEqual(expected,path.read_bytes())
            subprocess.run(['bash','-n',str(path)],check=True,capture_output=True)

    def run_source(self,raw,*args):
        with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))as folder:
            p=Path(folder)/'operator.py';p.write_bytes(raw)
            result=subprocess.run([sys.executable,'-I','-B','-S',str(p),*args],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,2);self.assertEqual(result.stderr,'')
        value=json.loads(result.stdout);self.assertEqual(value['status'],'STOP_RECONCILE')
        self.assertFalse(value['runtimeAuthorityIssued']);return value

    def test_unbound_modes_rejected_in_both_isolated_processes(self):
        for kind,(raw,_)in self.artifacts.items():self.run_source(raw,'initialize')

    @unittest.skipUnless(os.geteuid()==0,'actual isolated root process required in CI')
    def test_missing_target_fails_closed_after_qualified_closures_load(self):
        for kind,(raw,_)in self.artifacts.items():
            value=self.run_source(raw,'prepare'if kind=='human'else'preflight')
            if kind=='human':self.assertEqual(value['checkpoint']['phase'],'RETAINED_STAGE18_GRANT')
            else:self.assertEqual(value['phase'],'EXPLICIT_STAGE18_PREFLIGHT')
            self.assertNotIn('Traceback',json.dumps(value))

    @unittest.skipUnless(os.geteuid()==0,'actual isolated root process required in CI')
    def test_changed_runtime_case_is_denied_before_loading_native_code(self):
        raw,_=self.artifacts['runtime'];case=copy.deepcopy(self.case);case['runtimeControllerHash']='f'*64
        changed=raw.decode().replace('CASE='+repr(self.case),'CASE='+repr(case),1).encode()
        value=self.run_source(changed,'preflight')
        self.assertEqual(value['reasonCode'],'STAGE18_RUNTIME_CASE_CHANGED')
        self.assertEqual(value['phase'],'VERIFY_STAGE18_RUNTIME_DELIVERY')

    @unittest.skipUnless(os.geteuid()==0,'actual shell/root wrapper qualification required in CI')
    def test_actual_launcher_download_hash_wrapper_and_safe_log_without_target(self):
        for kind,(raw,_)in self.artifacts.items():
            with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))as folder:
                root=Path(folder);portable=root/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin';portable.mkdir(parents=True)
                import base64
                gh=portable/'gh';gh.write_text('#!/bin/sh\nprintf %s '+base64.b64encode(raw).decode()+'\n');gh.chmod(0o700)
                binary=root/'bin';binary.mkdir();sudo=binary/'sudo';sudo.write_text('#!/bin/sh\nexec "$@"\n');sudo.chmod(0o700)
                launcher=root/'launcher.sh';launcher.write_bytes(d.launcher(kind,raw));launcher.chmod(0o700)
                env={**os.environ,'HOME':str(root),'PATH':str(binary)+os.pathsep+os.environ['PATH']}
                result=subprocess.run(['bash',str(launcher),'prepare'if kind=='human'else'preflight'],env=env,capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,2);self.assertEqual(result.stderr,'')
                logs=list(root.glob('ouf-stage18-*/operator.log'));self.assertEqual(len(logs),1)
                value=json.loads(logs[0].read_bytes());self.assertEqual(value['status'],'STOP_RECONCILE')
                self.assertIn('Log conservato:',result.stdout)
                if kind=='human':self.assertEqual(value['checkpoint']['phase'],'RETAINED_STAGE18_GRANT')
                else:self.assertEqual(value['phase'],'EXPLICIT_STAGE18_PREFLIGHT')
                # Repeated modes must reverify immutable cached bytes and avoid
                # new GitHub download latency during the finite runtime window.
                gh.write_text('#!/bin/sh\nexit 9\n')
                again=subprocess.run(['bash',str(launcher),'prepare'if kind=='human'else'preflight'],env=env,capture_output=True,text=True,timeout=30)
                self.assertEqual(again.returncode,2)
                self.assertEqual(len(list(root.glob('ouf-stage18-*/operator.log'))),2)


if __name__=='__main__':unittest.main()
