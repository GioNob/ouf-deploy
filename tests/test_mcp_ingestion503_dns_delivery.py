import ast,base64,hashlib,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];LOCAL=Path(__file__).parent
LAUNCH=ROOT/'scripts/launch-mcp-ingestion503-dns-read-20261019.sh'
if not LAUNCH.exists():LAUNCH=LOCAL/LAUNCH.name
READ=ROOT/'scripts/read-mcp-ingestion503-dns.py'
if not READ.exists():READ=LOCAL/'read.py'
class Delivery(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.bin=self.root/'bin';self.bin.mkdir();self.mark=self.root/'sudo'
  self.portable=self.root/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh';self.portable.parent.mkdir(parents=True)
  self.env={**os.environ,'HOME':str(self.root),'PATH':str(self.bin)+':/usr/bin:/bin'}
  self.write(self.bin/'sudo','#!/bin/sh\ntouch '+str(self.mark)+'\ncat >/dev/null\n');self.write(self.bin/'gh','#!/bin/sh\nexit 71\n')
 def write(self,path,text):path.write_text(text);path.chmod(0o700)
 def gh(self,tamper=False):
  raw=b'changed'if tamper else READ.read_bytes()
  self.write(self.portable,'#!/usr/bin/python3\nimport sys\nassert sys.argv[1:]=='+repr(['api','repos/GioNob/ouf-deploy/contents/scripts/read-mcp-ingestion503-dns.py?ref=51c0db6a41fb7c14031b3dc7eae6eebdf47a37fe','--jq','.content'])+'\nprint('+repr(base64.b64encode(raw).decode())+')\n')
 def run_launch(self):return subprocess.run(['/bin/bash',str(LAUNCH)],env=self.env,capture_output=True,timeout=15)
 def test_portable_authenticated_client_exact_pin_before_single_sudo(self):
  self.gh();r=self.run_launch();self.assertEqual(r.returncode,0,r.stderr);self.assertTrue(self.mark.exists());self.assertEqual(r.stdout.count(b': OK'),1)
 def test_tamper_or_no_client_never_reaches_sudo(self):
  self.gh(True);r=self.run_launch();self.assertNotEqual(r.returncode,0);self.assertFalse(self.mark.exists())
  self.portable.unlink();(self.bin/'gh').unlink();self.env['PATH']=str(self.bin);r=self.run_launch();self.assertNotEqual(r.returncode,0);self.assertFalse(self.mark.exists());self.assertIn(b'nessun sudo',r.stderr)
 def test_root_shim_pin_matches_qualified_reader_and_rejects_substitution(self):
  body=LAUNCH.read_text().split("<<'OUF_READ503' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_READ503',1)[0]
  tree=ast.parse(body);expected=next(ast.literal_eval(n.value)for n in ast.walk(tree)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='expected'for t in n.targets))
  self.assertEqual(expected,hashlib.sha256(READ.read_bytes()).hexdigest())
  payload=self.root/'bad.py';payload.write_text('raise RuntimeError("MUST_NOT_EXECUTE")')
  r=subprocess.run(['/usr/bin/python3','-I','-B','-S','-',str(payload)],input=body.encode(),capture_output=True,timeout=10)
  self.assertEqual(r.returncode,2);self.assertNotIn(b'MUST_NOT_EXECUTE',r.stdout+r.stderr);self.assertIn(b'nessuna diagnosi',r.stdout)
if __name__=='__main__':unittest.main()
