import json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PATHS={'program':'scripts/prepare-gated-v11-private-plan.py','atomic':'tools/semantic_application_cutover/atomic_review_intake.py','publisher':'scripts/publish-native-v11-review-intake.py','journal':'tools/semantic_application_cutover/transition_journal.py','gate':'tools/semantic_application_cutover/gated_creation_plan.py'}
NAMES=tuple(PATHS)
class Delivery(unittest.TestCase):
 def fixture(self,root):
  files={}
  for name,path in PATHS.items():
   file=ROOT/path
   if not file.exists():file=ROOT/'tests/fixtures'/('recovery_journal.py' if name=='journal' else name+'.py')
   files[name]=str(file)
  binary=root/"bin";binary.mkdir();marker=root/"sudo-called"
  gh='''#!/usr/bin/env python3
import json,os,pathlib,sys
if sys.argv[1]=="attestation":
 if pathlib.Path(sys.argv[3]).name==os.environ.get("OUF_TEST_SIGNATURE_FAIL"):raise SystemExit(71)
 print("{}");raise SystemExit(0)
files=json.loads(os.environ["OUF_TEST_FILES"])
routes=json.loads(os.environ["OUF_TEST_ROUTES"])
key=next(k for k,v in routes.items() if v in sys.argv[-1])
if os.environ.get("OUF_TEST_DOWNLOAD_FAIL")==key:raise SystemExit(71)
raw=pathlib.Path(files[key]).read_bytes()
if os.environ.get("OUF_TEST_TAMPER")==key:raw+=b"#drift"
sys.stdout.buffer.write(raw)
'''
  (binary/"gh").write_text(gh);(binary/"gh").chmod(0o700)
  (binary/"sudo").write_text('#!/bin/sh\nprintf called > "'+str(marker)+'"\nexit 97\n');(binary/"sudo").chmod(0o700)
  launcher=root/"launcher.sh";launcher.write_text((ROOT/"releases/gated-v11-private-plan-20261012.sh").read_text().replace("$HOME",str(root)))
  env=dict(os.environ,PATH=str(binary)+":"+os.environ["PATH"],OUF_TEST_FILES=json.dumps(files),OUF_TEST_ROUTES=json.dumps({k:Path(v).name for k,v in PATHS.items()}))
  return launcher,env,marker,files
 def test_all_download_and_digest_failures_never_reach_sudo(self):
  for var in ("OUF_TEST_DOWNLOAD_FAIL","OUF_TEST_TAMPER"):
   for name in NAMES:
    with self.subTest(var=var,name=name),tempfile.TemporaryDirectory(dir=ROOT) as f:
     launcher,env,marker,_=self.fixture(Path(f));env[var]=name
     p=subprocess.run(["bash",str(launcher)],env=env,capture_output=True,timeout=10)
     self.assertNotEqual(p.returncode,0);self.assertFalse(marker.exists())
 def test_valid_download_closure_propagates_sudo_exit(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as f:
   launcher,env,marker,_=self.fixture(Path(f))
   p=subprocess.run(["bash",str(launcher)],env=env,capture_output=True,timeout=10)
   self.assertEqual(p.returncode,97);self.assertTrue(marker.exists())
   self.assertIn(b"OUF_GATED_V11_PLAN_LAUNCHER_EXIT=97",p.stdout)
 def test_root_bootstrap_checks_all_five_files_before_execution(self):
  shell=(ROOT/"releases/gated-v11-private-plan-20261012.sh").read_text()
  code=shell.split("sudo /usr/bin/python3 -I -B -c '\n",1)[1].split("\n' \"$OUF_DIR/program.py\"",1)[0]
  compile(code,"root-bootstrap","exec")
  for target in NAMES:
   with self.subTest(target=target),tempfile.TemporaryDirectory(dir=ROOT) as f:
    root=Path(f);_,_,_,original=self.fixture(root);paths=[]
    for name in NAMES:
     file=root/(name+".py");file.write_bytes(Path(original[name]).read_bytes()+(b"#tamper" if name==target else b""));paths.append(str(file))
    p=subprocess.run(["python3","-I","-B","-c",code,*paths],capture_output=True,timeout=10)
    self.assertNotEqual(p.returncode,0);self.assertIn(b"OUF_GATED_PLAN_SOURCE_HASH_MISMATCH",p.stderr)
 def test_portable_client_precedes_fallback(self):
  shell=(ROOT/"releases/gated-v11-private-plan-20261012.sh").read_text()
  self.assertLess(shell.index("ouf-gh-2.102.0.PNoFbF"),shell.index("command -v gh"))
if __name__=="__main__":unittest.main()
