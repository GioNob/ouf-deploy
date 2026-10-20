"""Six authenticated immutable pins; all byte checks before single sudo."""
import ast,hashlib,os,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];LOCAL=Path(__file__).parent
LAUNCH=ROOT/'scripts/launch-mcp82-human-continuation-20261019.sh'
if not LAUNCH.exists():LAUNCH=LOCAL/LAUNCH.name
class Delivery(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.bin=self.root/'bin';self.bin.mkdir();self.mark=self.root/'sudo-called'
  self.portable=self.root/'ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh';self.portable.parent.mkdir(parents=True)
  self.env={**os.environ,'HOME':str(self.root),'PATH':str(self.bin)+':/usr/bin:/bin','OUF_TEST_MARK':str(self.mark),'OUF_TEST_SOURCE':str(ROOT),'OUF_TEST_LOCAL':str(LOCAL)}
  self.write(self.bin/'sudo','#!/bin/sh\nprintf invoked > "$OUF_TEST_MARK"\ncat >/dev/null\n')
  self.write(self.bin/'gh','#!/bin/sh\nexit 71\n')
 def write(self,path,content):path.write_text(content);path.chmod(0o700)
 def gh(self,tamper=False):
  self.write(self.portable,'''#!/usr/bin/python3
import base64,os,sys
from pathlib import Path
assert sys.argv[1]=='api'and sys.argv[3:]==['--jq','.content']
value=sys.argv[2];prefix='repos/GioNob/ouf-deploy/contents/'
assert value.startswith(prefix)
relative,ref=value[len(prefix):].split('?ref=')
assert ref=='0be8fb13db3ff1ea014920bbbbb3738a8a434240'
path=Path(os.environ['OUF_TEST_SOURCE'])/relative
if not path.exists():
 name=Path(relative).name;folder=Path(os.environ['OUF_TEST_LOCAL'])
 mapping={'tools/mcp_read_transport_gateway82/entry.py': 'entry.py', 'tools/mcp_read_transport_gateway82/authority.py': 'authority.py', 'tools/mcp_read_transport_gateway82/owner.py': 'owner.py', 'tools/mcp_read_transport_gateway82/native.py': 'native.py', 'tools/mcp_read_transport_gateway82_continuation/runtime.py': 'runtime.py', 'tools/mcp_read_transport_gateway82_continuation/entry.py': 'continuation-entry.py', 'tools/mcp_read_transport_gateway82_continuation/authority.py': 'continuation-authority.py', 'tools/mcp_read_transport_gateway82_continuation/login.py': 'login.py', 'scripts/prepare-mcp82-human-continuation.py': 'prepare.py', 'scripts/execute-mcp82-human-continuation.py': 'bootstrap.py'}
 path=folder/mapping[relative]
raw=path.read_bytes()
'''+("if relative.endswith('/entry.py'):raw=b'changed'\n"if tamper else'')+"print(base64.b64encode(raw).decode())\n")
 def run_launcher(self):return subprocess.run(['/bin/bash',str(LAUNCH)],env=self.env,capture_output=True,timeout=15)
 def test_exact_portable_client_six_pins_and_one_sudo(self):
  self.gh();result=self.run_launcher();self.assertEqual(result.returncode,0,result.stderr.decode())
  self.assertTrue(self.mark.exists());self.assertEqual(result.stdout.count(b': OK'),10)
  self.assertEqual(LAUNCH.read_text().count('\nsudo '),1)
 def test_tampered_entry_prevents_sudo(self):
  self.gh(True);result=self.run_launcher();self.assertNotEqual(result.returncode,0);self.assertFalse(self.mark.exists())
 def test_missing_client_prevents_download_and_sudo(self):
  self.env['PATH']=str(self.bin);(self.bin/'gh').unlink();result=self.run_launcher()
  self.assertNotEqual(result.returncode,0);self.assertFalse(self.mark.exists());self.assertIn(b'nessun sudo',result.stderr)
 def test_root_shim_rechecks_all_six_hashes_against_actual_sources(self):
  body=LAUNCH.read_text().split("<<'OUF_MCP82_HUMAN_CONTINUATION' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_MCP82_HUMAN_CONTINUATION',1)[0]
  tree=ast.parse(body);expected=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='expected'for t in n.targets))
  self.assertEqual(set(expected),{'prepare','bootstrap','entry','authority','owner','native','runtime','continuation-entry','continuation-authority','login'})
  for name,wanted in expected.items():
   mapping={'entry': 'tools/mcp_read_transport_gateway82/entry.py', 'authority': 'tools/mcp_read_transport_gateway82/authority.py', 'owner': 'tools/mcp_read_transport_gateway82/owner.py', 'native': 'tools/mcp_read_transport_gateway82/native.py', 'runtime': 'tools/mcp_read_transport_gateway82_continuation/runtime.py', 'continuation-entry': 'tools/mcp_read_transport_gateway82_continuation/entry.py', 'continuation-authority': 'tools/mcp_read_transport_gateway82_continuation/authority.py', 'login': 'tools/mcp_read_transport_gateway82_continuation/login.py', 'prepare': 'scripts/prepare-mcp82-human-continuation.py', 'bootstrap': 'scripts/execute-mcp82-human-continuation.py'}
   path=ROOT/mapping.get(name,'tools/mcp_read_transport_gateway82/'+name+'.py')
   if not path.exists():path=LOCAL/(name+'.py')
   self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),wanted)
if __name__=='__main__':unittest.main()
