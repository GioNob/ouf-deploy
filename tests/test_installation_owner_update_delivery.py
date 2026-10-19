"""Authenticate pinned seven-file delivery; tampering stops before sudo/exec."""
import ast,base64,hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
LAUNCH=ROOT/'scripts/launch-installation-owner-update-20261019.sh'
PINS=ROOT/'evidence/installation-owner-update-delivery-pins-20261019.json'
COMMIT='b46a99b23f12ef33ef04393ecefb07a6569e8b74'
PATHS={**{n:'tools/installation_owner_update/'+n+'.py'for n in('entry','authority','owner','native','runtime')},'prepare':'scripts/prepare-installation-owner-update.py','bootstrap':'scripts/execute-installation-owner-update.py'}
class Delivery(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.bin=self.root/'bin';self.bin.mkdir();self.mark=self.root/'sudo'
  self.portable=self.root/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh';self.portable.parent.mkdir(parents=True)
  self.env={**os.environ,'HOME':str(self.root),'PATH':str(self.bin)+':/usr/bin:/bin'}
  self.write(self.bin/'sudo','#!/bin/sh\ntouch '+str(self.mark)+'\ncat >/dev/null\n');self.write(self.bin/'gh','#!/bin/sh\nexit 71\n')
 def write(self,path,text):path.write_text(text);path.chmod(0o700)
 def gh(self,tamper=False):
  contents={'repos/GioNob/ouf-deploy/contents/'+path+'?ref='+COMMIT:base64.b64encode(b'changed'if tamper else(ROOT/path).read_bytes()).decode()for path in PATHS.values()}
  self.write(self.portable,'#!/usr/bin/python3\nimport sys\nassert sys.argv[1]=="api" and sys.argv[3:]==["--jq",".content"]\nprint('+repr(contents)+'[sys.argv[2]])\n')
 def launch(self):return subprocess.run(['/bin/bash',str(LAUNCH)],env=self.env,capture_output=True,timeout=15)
 def test_exact_seven_pins_portable_authenticated_client_and_one_sudo(self):
  self.gh();result=self.launch();self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(self.mark.exists());self.assertEqual(result.stdout.count(b': OK'),7)
 def test_tamper_or_missing_client_stops_before_sudo(self):
  self.gh(True);result=self.launch();self.assertNotEqual(result.returncode,0);self.assertFalse(self.mark.exists())
  self.portable.unlink();(self.bin/'gh').unlink();self.env['PATH']=str(self.bin);result=self.launch();self.assertNotEqual(result.returncode,0);self.assertFalse(self.mark.exists());self.assertIn(b'nessun sudo',result.stderr)
 def test_root_shim_rechecks_all_hashes_and_rejects_substitution_before_exec(self):
  body=LAUNCH.read_text().split("<<'OUF_INSTALLATION_OWNER_UPDATE' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_INSTALLATION_OWNER_UPDATE',1)[0]
  tree=ast.parse(body);expected=next(ast.literal_eval(n.value)for n in ast.walk(tree)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='expected'for t in n.targets))
  self.assertEqual(expected,{n:hashlib.sha256((ROOT/path).read_bytes()).hexdigest()for n,path in PATHS.items()})
  self.assertEqual(json.loads(PINS.read_bytes()),expected)
  for name,path in PATHS.items():(self.root/(name+'.py')).write_bytes((ROOT/path).read_bytes())
  (self.root/'entry.py').write_text('raise RuntimeError("MUST_NOT_EXECUTE")')
  result=subprocess.run(['/usr/bin/python3','-I','-B','-S','-',str(self.root),COMMIT],input=body.encode(),capture_output=True,timeout=10)
  self.assertEqual(result.returncode,2);self.assertNotIn(b'MUST_NOT_EXECUTE',result.stdout+result.stderr);self.assertIn(b'STOP_RECONCILE',result.stdout)
if __name__=='__main__':unittest.main()
