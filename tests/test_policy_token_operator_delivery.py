"""The exact documented command with the retained gh installed outside PATH."""
import ast
import base64
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]

class DeliveryTest(unittest.TestCase):
    def command(self):
        text=(ROOT/'releases/POLICY_TOKEN_REAL_IAM_OWNER_20261013.md').read_text()
        return text.split("python3 - <<'PY' | tee ouf-policy-token-protected-scope-observation.json\n",1)[1].split('\nPY\n',1)[0]
    def fixture(self):
        temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(temp.cleanup);home=Path(temp.name)
        gh=home/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh';gh.parent.mkdir(parents=True);gh.write_text('# disposable unexecuted CLI fixture');gh.chmod(0o700)
        return home,gh
    def test_exact_command_selects_existing_non_path_gh_and_same_hash_checked_root_payload(self):
        home,gh=self.fixture();raw=(ROOT/'tools/semantic_policy_token_owner/protected_scope_probe.py').read_bytes();calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            if len(calls)==1:
                self.assertEqual(argv[0],str(gh));self.assertIn('5cffef27d03374ccfc20e34f7cf3812187428054',argv[2])
                return subprocess.CompletedProcess(argv,0,base64.b64encode(raw))
            self.assertEqual(argv,['sudo','/usr/bin/python3','-I','-B','-'])
            code=kwargs['input'].decode();module=ast.parse(code)
            payload=module.body[1].value.args[0].value;self.assertEqual(base64.b64decode(payload),raw)
            self.assertIn('0974406a9400e4ff42acf766f2734ee8a29e45319fa23677b3fe887a0443511e',code)
            self.assertEqual(kwargs['timeout'],60)
            return subprocess.CompletedProcess(argv,0)
        with patch('pathlib.Path.home',return_value=home),patch('shutil.which',return_value=None),patch('subprocess.run',side_effect=run):
            with self.assertRaises(SystemExit) as result:exec(compile(self.command(),'documented-command','exec'),{})
        self.assertEqual(result.exception.code,0);self.assertEqual(len(calls),2)
    def test_corrupt_source_denies_before_sudo(self):
        home,gh=self.fixture()
        with patch('pathlib.Path.home',return_value=home),patch('shutil.which',return_value=None),patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,base64.b64encode(b'print("UNAPPROVED")'))) as run:
            with self.assertRaisesRegex(SystemExit,'SOURCE_HASH_MISMATCH'):exec(compile(self.command(),'documented-command','exec'),{})
        self.assertEqual(run.call_count,1)
    def test_missing_cli_denies_before_download_or_sudo(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as value:
            with patch('pathlib.Path.home',return_value=Path(value)),patch('shutil.which',return_value=None),patch('subprocess.run') as run:
                with self.assertRaisesRegex(SystemExit,'EXISTING_GH_UNAVAILABLE'):exec(compile(self.command(),'documented-command','exec'),{})
            run.assert_not_called()

if __name__=='__main__':unittest.main()
