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
LAUNCHER = ROOT/'releases/semantic-current-creation-plan-20261011.sh'
TEXT = LAUNCHER.read_text()
ROWS = [["scripts/compile-semantic-creation-plan-after-r12.py","plan.py","38bb934fedfcdd38d11fc29ff4d60e75170854686273b7592edcae92fa0d1d28"],["scripts/prepare-semantic-inputs-after-r12.py","prepare.py","693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b"],["tools/semantic_target_review/prepare_application_runtime_inputs.py","custody.py","cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf"],["tools/semantic_application_cutover/creation_plan.py","creation.py","e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665"]]
PIN = '9fdf4bed6ded1a01640bcaed2ffadb58204e42d5'


class Delivery(unittest.TestCase):
    def run_launcher(self, kind=None, name=None, portable=False, sudo_exit=0):
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
            if portable:
                selected=home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh'
                selected.parent.mkdir(parents=True);gh.rename(selected)
            sudo = mock/'sudo'
            sudo.write_text('#!'+sys.executable+'\n'+
                'import json,os,pathlib,sys\n'
                'pathlib.Path(os.environ["SUDO_MARKER"]).write_text(json.dumps(sys.argv[1:]))\n'
                'print("FIXTURE_NO_TARGET_ACTION")\n'
                'sys.exit(int(os.environ["SUDO_EXIT"]))\n')
            sudo.chmod(0o700)
            marker = root/'sudo.json'
            env = {**os.environ,'HOME':str(home),'PATH':str(mock)+':/usr/bin:/bin',
                   'SOURCE_ROOT':str(ROOT),'SUDO_MARKER':str(marker),
                   'FAIL_KIND':kind or '', 'FAIL_NAME':name or '', 'SUDO_EXIT':str(sudo_exit)}
            result = subprocess.run(['/usr/bin/bash',str(LAUNCHER)],env=env,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
            arguments = marker.read_text() if marker.exists() else None
            return result, arguments

    def test_exact_four_source_hashes_and_shell_syntax(self):
        self.assertEqual(len(ROWS),4)
        self.assertEqual(len({row[1] for row in ROWS}),4)
        for path,_,digest in ROWS:
            self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),digest,path)
        subprocess.run(['/usr/bin/bash','-n',str(LAUNCHER)],check=True)

    def test_each_download_failure_stops_before_sudo(self):
        for path,_,_ in ROWS:
            with self.subTest(path=path):
                result, args = self.run_launcher('download',path)
                self.assertNotEqual(result.returncode,0)
                self.assertIsNone(args)
                self.assertIn('PHASE=DOWNLOAD_PINNED_CURRENT_CREATION_PLANNER',result.stdout)

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
        self.assertIn('__planner_sources__',argv[4])
        self.assertNotIn('R10_DELEGATED_RECOVERY',argv[4])
        with tempfile.TemporaryDirectory() as tmp:
            for selected in range(4):
                paths=[]
                for i,(path,_,_) in enumerate(ROWS):
                    copied=Path(tmp)/('source'+str(i)+'.py')
                    copied.write_bytes(b'raise AssertionError("MUST_NOT_EXECUTE")' if i==selected else (ROOT/path).read_bytes())
                    paths.append(str(copied))
                denial=subprocess.run([sys.executable,'-I','-B','-c',argv[4],*paths],
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=5)
                self.assertNotEqual(denial.returncode,0)
                self.assertIn('OUF_CURRENT_CREATION_SOURCE_HASH_MISMATCH',denial.stderr)
                self.assertNotIn('MUST_NOT_EXECUTE',denial.stderr)



    def test_existing_portable_client_without_gh_in_path(self):
        result,args=self.run_launcher(portable=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIsNotNone(args)
    def test_privileged_failure_propagated_through_tee(self):
        result,args=self.run_launcher(portable=True,sudo_exit=7)
        self.assertEqual(result.returncode,7)
        self.assertIn('OUF_CURRENT_CREATION_PLAN_EXIT=7',result.stdout)

if __name__=='__main__': unittest.main()


