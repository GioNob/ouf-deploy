import hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PATHS={'planner':'scripts/compile-semantic-creation-plan-after-r12.py','prepare':'scripts/prepare-semantic-inputs-after-r12.py','custody':'tools/semantic_target_review/prepare_application_runtime_inputs.py','creation':'tools/semantic_application_cutover/creation_plan.py'}
class Delivery(unittest.TestCase):
 def fixture(self,root):
  files={'read':ROOT/'scripts/read-current-r12-cutover-custody.py'}
  for name,path in PATHS.items():files[name]=ROOT/path if (ROOT/path).exists() else ROOT/'tests/fixtures'/f'{name}.py'
  binaries=root/'bin';binaries.mkdir();marker=root/'sudo-called'
  gh='''#!/usr/bin/env python3
import os,pathlib,sys
names=[('read-current-r12-cutover-custody.py','read'),('compile-semantic-creation-plan-after-r12.py','planner'),('prepare-semantic-inputs-after-r12.py','prepare'),('prepare_application_runtime_inputs.py','custody'),('creation_plan.py','creation')]
key=next(v for p,v in names if p in sys.argv[-1])
if os.environ.get('OUF_TEST_FAIL')==key:raise SystemExit(71)
raw=pathlib.Path(os.environ['OUF_TEST_SOURCE_'+key.upper()]).read_bytes()
if os.environ.get('OUF_TEST_TAMPER')==key:raw+=b'\\n#tampered\\n'
sys.stdout.buffer.write(raw)
'''
  (binaries/'gh').write_text(gh);(binaries/'gh').chmod(0o700)
  (binaries/'sudo').write_text('#!/bin/sh\nprintf invoked > "'+str(marker)+'"\nexit 97\n');(binaries/'sudo').chmod(0o700)
  launcher=ROOT/'releases/current-r12-custody-read-20261011.sh'
  executable=root/'launch.sh';executable.write_text(launcher.read_text().replace('$HOME',str(root)))
  env=dict(os.environ,PATH=str(binaries)+':'+os.environ['PATH'])
  for name,path in files.items():env['OUF_TEST_SOURCE_'+name.upper()]=str(path)
  return executable,env,marker
 def test_each_download_and_digest_failure_never_reaches_sudo(self):
  for variable in ('OUF_TEST_FAIL','OUF_TEST_TAMPER'):
   for name in ('read','planner','prepare','custody','creation'):
    with self.subTest(variable=variable,name=name),tempfile.TemporaryDirectory(dir=ROOT) as folder:
     root=Path(folder);launcher,env,marker=self.fixture(root);env[variable]=name
     p=subprocess.run(['bash',str(launcher)],env=env,capture_output=True,timeout=10)
     self.assertNotEqual(p.returncode,0);self.assertFalse(marker.exists())
 def test_exact_closure_reaches_only_sudo_and_propagates_exit(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as folder:
   root=Path(folder);launcher,env,marker=self.fixture(root)
   p=subprocess.run(['bash',str(launcher)],env=env,capture_output=True,timeout=10)
   self.assertEqual(p.returncode,97);self.assertTrue(marker.exists())
   self.assertIn(b'OUF_CURRENT_R12_CUSTODY_LAUNCHER_EXIT=97',p.stdout)
 def test_bootstrap_rechecks_every_source_before_execution(self):
  shell=(ROOT/'releases/current-r12-custody-read-20261011.sh').read_text()
  code=shell.split("sudo /usr/bin/python3 -I -B -c '\n",1)[1].split("\n' \"$OUF_DIR/read.py\"",1)[0]
  compile(code,'sealed-bootstrap','exec')
  for name in ('read','planner','prepare','custody','creation'):
   with self.subTest(name=name),tempfile.TemporaryDirectory(dir=ROOT) as folder:
    root=Path(folder);launcher,env,marker=self.fixture(root)
    files=[]
    for key in ('read','planner','prepare','custody','creation'):
     path=root/(key+'.py');path.write_bytes(Path(env['OUF_TEST_SOURCE_'+key.upper()]).read_bytes()+(b'#drift' if key==name else b''));files.append(str(path))
    p=subprocess.run(['python3','-I','-B','-c',code,*files],capture_output=True,timeout=10)
    self.assertNotEqual(p.returncode,0);self.assertIn(b'OUF_CURRENT_READ_SOURCE_HASH_MISMATCH',p.stderr)
 def test_portable_client_is_checked_before_fallback(self):
  shell=(ROOT/'releases/current-r12-custody-read-20261011.sh').read_text()
  self.assertLess(shell.index('ouf-gh-2.102.0.PNoFbF'),shell.index('command -v gh'))
if __name__=='__main__':unittest.main()
