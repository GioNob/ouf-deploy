import json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
NAMES=("program","original_program","custody","audit","importer","journal","engine","manifest")
PATHS={"program":"scripts/reconcile-v11-manifest-image.py","original_program":"scripts/import-verified-v11-image.py","custody":"tools/semantic_target_review/prepare_application_runtime_inputs.py",
 "audit":"tools/semantic_application_cutover/image_custody.py","importer":"tools/semantic_application_cutover/image_import.py",
 "journal":"tools/semantic_lease_recovery/recovery_journal.py","engine":"tools/semantic_application_cutover/engine_creation.py","manifest":"tools/semantic_application_cutover/image_manifest_identity.py"}
class Delivery(unittest.TestCase):
 def fixture(self,root):
  files={}
  for name,path in PATHS.items():
   file=ROOT/path
   if not file.exists():file=ROOT/("tests/fixtures/custody.py" if name=="custody" else "tests/fixtures/recovery_journal.py")
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
  launcher=root/"launcher.sh";launcher.write_text((ROOT/"releases/reconcile-v11-manifest-image-20261011.sh").read_text().replace("$HOME",str(root)))
  env=dict(os.environ,PATH=str(binary)+":"+os.environ["PATH"],OUF_TEST_FILES=json.dumps(files),OUF_TEST_ROUTES=json.dumps({k:Path(v).name for k,v in PATHS.items()}))
  return launcher,env,marker,files
 def test_all_download_and_digest_failures_never_reach_sudo(self):
  for var in ("OUF_TEST_DOWNLOAD_FAIL","OUF_TEST_TAMPER"):
   for name in NAMES:
    with self.subTest(var=var,name=name),tempfile.TemporaryDirectory(dir=ROOT) as f:
     launcher,env,marker,_=self.fixture(Path(f));env[var]=name
     p=subprocess.run(["bash",str(launcher)],env=env,capture_output=True,timeout=10)
     self.assertNotEqual(p.returncode,0);self.assertFalse(marker.exists())
 def test_all_eight_publisher_verification_failures_never_reach_sudo(self):
  for name in ("image.docker.tar","source.tar","source-inventory.json","application.jar","package-record.json","migration-continuity.json","trivy-image.json","Dockerfile.resolved"):
   with self.subTest(name=name),tempfile.TemporaryDirectory(dir=ROOT) as f:
    launcher,env,marker,_=self.fixture(Path(f));env["OUF_TEST_SIGNATURE_FAIL"]=name
    p=subprocess.run(["bash",str(launcher)],env=env,capture_output=True,timeout=10)
    self.assertNotEqual(p.returncode,0);self.assertFalse(marker.exists())
    self.assertIn(b"OUF_ORIGINAL_PUBLISHER_VERIFICATION_FAILED",p.stderr)
 def test_valid_download_and_signature_closure_propagates_sudo_exit(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as f:
   launcher,env,marker,_=self.fixture(Path(f))
   p=subprocess.run(["bash",str(launcher)],env=env,capture_output=True,timeout=10)
   self.assertEqual(p.returncode,97);self.assertTrue(marker.exists())
   self.assertIn(b"OUF_V11_MANIFEST_RECONCILIATION_LAUNCHER_EXIT=97",p.stdout)
   self.assertIn(b"OUF_ORIGINAL_PUBLISHER_SUBJECTS_VERIFIED=8",p.stdout)
 def test_root_bootstrap_checks_all_eight_files_before_execution(self):
  shell=(ROOT/"releases/reconcile-v11-manifest-image-20261011.sh").read_text()
  code=shell.split("sudo /usr/bin/python3 -I -B -c '\n",1)[1].split("\n' \"$OUF_DIR/program.py\"",1)[0]
  compile(code,"root-bootstrap","exec")
  for target in NAMES:
   with self.subTest(target=target),tempfile.TemporaryDirectory(dir=ROOT) as f:
    root=Path(f);_,_,_,original=self.fixture(root);paths=[]
    for name in NAMES:
     file=root/(name+".py");file.write_bytes(Path(original[name]).read_bytes()+(b"#tamper" if name==target else b""));paths.append(str(file))
    p=subprocess.run(["python3","-I","-B","-c",code,*paths],capture_output=True,timeout=10)
    self.assertNotEqual(p.returncode,0);self.assertIn(b"OUF_MANIFEST_RECONCILIATION_SOURCE_HASH_MISMATCH",p.stderr)
 def test_portable_client_precedes_fallback(self):
  shell=(ROOT/"releases/reconcile-v11-manifest-image-20261011.sh").read_text()
  self.assertLess(shell.index("ouf-gh-2.102.0.PNoFbF"),shell.index("command -v gh"))
if __name__=="__main__":unittest.main()
