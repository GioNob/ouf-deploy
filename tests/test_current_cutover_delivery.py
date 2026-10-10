"""Exercise launcher delivery boundaries without target or privileged operations."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT/'releases/semantic-current-cutover-inputs-20261010.sh'
TEXT = LAUNCHER.read_text()
ROWS = [('scripts/prepare-current-semantic-cutover-inputs.py','read.py','49d47881e3d40277cfa2c57b7bb5d894aed9a971a2a6a77fb75880e2ff494d9d'),('tools/semantic_target_review/prepare_application_runtime_inputs.py','custody.py','cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf')]
PIN = '5a9ab106966a8ecc3a2c61012266d1fd9045cd4d'


class Delivery(unittest.TestCase):
    def run_launcher(self, kind=None, name=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root/'home'; home.mkdir()
            mock = root/'bin'; mock.mkdir()
            gh = mock/'gh'
            gh.write_text('#!'+sys.executable+'\n'+
                'import os,pathlib,sys\n'
                'url=sys.argv[-1]\n'
                'assert url.endswith("?ref='+PIN+'")\n'
                'path=url.split("/contents/",1)[1].split("?ref=",1)[0]\n'
                'if os.environ.get("FAIL_NAME")==path:\n'
                ' if os.environ.get("FAIL_KIND")=="download": sys.exit(9)\n'
                ' sys.stdout.write("changed bytes");sys.exit(0)\n'
                'sys.stdout.buffer.write((pathlib.Path(os.environ["SOURCE_ROOT"])/path).read_bytes())\n')
            gh.chmod(0o700)
            sudo = mock/'sudo'
            sudo.write_text('#!'+sys.executable+'\n'+
                'import json,os,pathlib,sys\n'
                'pathlib.Path(os.environ["SUDO_MARKER"]).write_text(json.dumps(sys.argv[1:]))\n'
                'print("FIXTURE_NO_TARGET_ACTION")\n')
            sudo.chmod(0o700)
            marker = root/'sudo.json'
            env = {**os.environ,'HOME':str(home),'PATH':str(mock)+':/usr/bin:/bin',
                   'SOURCE_ROOT':str(ROOT),'SUDO_MARKER':str(marker),
                   'FAIL_KIND':kind or '', 'FAIL_NAME':name or ''}
            result = subprocess.run(['/usr/bin/bash',str(LAUNCHER)],env=env,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
            arguments = marker.read_text() if marker.exists() else None
            return result, arguments

    def test_exact_two_source_hashes_and_shell_syntax(self):
        self.assertEqual(len(ROWS),2)
        self.assertEqual(len({row[1] for row in ROWS}),2)
        for path,_,digest in ROWS:
            self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),digest,path)
        subprocess.run(['/usr/bin/bash','-n',str(LAUNCHER)],check=True)

    def test_each_download_failure_stops_before_sudo(self):
        for path,_,_ in ROWS:
            with self.subTest(path=path):
                result, args = self.run_launcher('download',path)
                self.assertNotEqual(result.returncode,0)
                self.assertIsNone(args)
                self.assertIn('PHASE=DOWNLOAD_PINNED_CURRENT_CUTOVER_INPUTS_COMPILER',result.stdout)

    def test_each_bad_hash_stops_before_sudo(self):
        for path,_,_ in ROWS:
            with self.subTest(path=path):
                result, args = self.run_launcher('hash',path)
                self.assertNotEqual(result.returncode,0)
                self.assertIsNone(args)

    def test_exact_delivery_reaches_only_isolated_hash_verified_bootstrap(self):
        result, args = self.run_launcher()
        self.assertEqual(result.returncode,0,result.stderr)
        import json
        argv=json.loads(args)
        self.assertEqual(argv[:4],['/usr/bin/python3','-I','-B','-c'])
        self.assertIn('__custody_source__',argv[4])
        self.assertNotIn('R10_DELEGATED_RECOVERY',argv[4])
        with tempfile.TemporaryDirectory() as tmp:
            for selected in range(2):
                paths=[]
                for i,(path,_,_) in enumerate(ROWS):
                    copied=Path(tmp)/('source'+str(i)+'.py')
                    copied.write_bytes(b'raise AssertionError("MUST_NOT_EXECUTE")' if i==selected else (ROOT/path).read_bytes())
                    paths.append(str(copied))
                denial=subprocess.run([sys.executable,'-I','-B','-c',argv[4],*paths],
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=5)
                self.assertNotEqual(denial.returncode,0)
                self.assertIn('OUF_CURRENT_CUTOVER_INPUTS_SOURCE_HASH_MISMATCH',denial.stderr)
                self.assertNotIn('MUST_NOT_EXECUTE',denial.stderr)



if __name__=='__main__': unittest.main()
