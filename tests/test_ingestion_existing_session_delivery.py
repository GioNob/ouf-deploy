"""Pinned host delivery: authenticated portable gh, hashes before sudo, no replay."""
import ast,base64,hashlib,json,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
LAUNCH=ROOT/'scripts/launch-ingestion-existing-session-action-20261019.sh'
if not LAUNCH.exists():LAUNCH=Path(__file__).with_name('launch-ingestion-existing-session-action-20261019.sh')
class Delivery(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.bin=self.root/'bin';self.bin.mkdir();self.mark=self.root/'sudo-called'
  self.portable=self.root/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh';self.portable.parent.mkdir(parents=True)
  self.env={**os.environ,'HOME':str(self.root),'PATH':str(self.bin)+':/usr/bin:/bin','OUF_TEST_MARK':str(self.mark),'OUF_TEST_SOURCE':str(ROOT)}
  self.write(self.bin/'sudo','#!/bin/sh\nprintf invoked > "$OUF_TEST_MARK"\ncat >/dev/null\n')
  self.write(self.bin/'gh','#!/bin/sh\nexit 71\n')
 def write(self,path,content):path.write_text(content);path.chmod(0o700)
 def gh(self,tamper=False):
  self.write(self.portable,'''#!/usr/bin/python3
import base64,os,sys
from pathlib import Path
assert sys.argv[1]=='api' and sys.argv[3:]==['--jq','.content']
value=sys.argv[2]
assert value.startswith('repos/GioNob/ouf-deploy/contents/scripts/')
assert value.endswith(('?ref=37184220c2a565367a194d41e862a704f87dbdb8','?ref=0c654ff46d6a44de32557247ae0790873d67d079'))
name=value.split('/scripts/')[1].split('?')[0];root=Path(os.environ['OUF_TEST_SOURCE'])
path=root/'scripts'/name
if not path.exists():
 path=root/'continuation'/name
 if not path.exists():path=root/'preflight'/name
raw=path.read_bytes()
'''+("if name=='ingestion-existing-session-entry.py':raw=b'changed'\n"if tamper else'')+"print(base64.b64encode(raw).decode())\n")
 def run_launcher(self):return subprocess.run(['/bin/bash',str(LAUNCH)],env=self.env,capture_output=True,timeout=15)
 def test_portable_gh_downloads_exact_pins_and_all_hashes_precede_single_sudo(self):
  self.gh();result=self.run_launcher()
  self.assertEqual(result.returncode,0,result.stderr.decode());self.assertTrue(self.mark.exists())
  self.assertEqual(result.stdout.count(b': OK'),3)
  self.assertEqual(LAUNCH.read_text().count('\nsudo '),1)
 def test_changed_delivery_stops_before_sudo(self):
  self.gh(tamper=True);result=self.run_launcher()
  self.assertNotEqual(result.returncode,0);self.assertFalse(self.mark.exists())
 def test_missing_gh_fails_before_sudo_or_download(self):
  self.env['PATH']=str(self.bin);(self.bin/'gh').unlink()
  result=self.run_launcher();self.assertNotEqual(result.returncode,0);self.assertFalse(self.mark.exists())
  self.assertIn(b'nessun sudo',result.stderr)
 def test_root_rechecks_all_three_hashes_against_actual_qualified_sources(self):
  text=LAUNCH.read_text();body=text.split("<<'OUF_EXISTING_HUMAN' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_EXISTING_HUMAN',1)[0]
  tree=ast.parse(body);expected=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='expected'for t in n.targets))
  paths={'prepare':'prepare-ingestion-existing-session-action.py','entry':'ingestion-existing-session-entry.py',
   'diagnostic':'diagnose-ingestion-administrative-preflight.py'}
  for name,file in paths.items():
   path=ROOT/'scripts'/file
   if not path.exists():
    path=ROOT/('preflight'if name=='diagnostic'else'continuation')/file
   self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),expected[name])
if __name__=='__main__':unittest.main()
