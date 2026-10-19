import ast,base64,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
READER=HERE/'read.py'
if not READER.exists():READER=HERE.parent/'scripts/read-installation-route-preparation-guard-stop.py'
spec=importlib.util.spec_from_file_location('guard_reader',READER);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Read(unittest.TestCase):
 def test_public_method_extraction_never_executes_source(self):
  raw=b'raise RuntimeError("MUST_NOT_EXECUTE")\nclass HumanSession:\n def _check_identity_and_budget(self,row):\n  require(False,"DRIFT")\n'
  view=m.inspect_source(raw);self.assertEqual(view['methodCount'],1);self.assertFalse(view['methods'][0]['matchesExpectedFrozenGuard']);self.assertIn('DRIFT',view['methods'][0]['methodSource'])
 def test_ast_normalizes_format_and_reports_multiple_methods(self):
  a=m.inspect_source(b'def _check_identity_and_budget(self,row):\n return row\n')
  b=m.inspect_source(b'def _check_identity_and_budget( self, row ):\n    return (row)\n')
  self.assertEqual(a['methods'][0]['bodyAstSha256'],b['methods'][0]['bodyAstSha256'])
  self.assertEqual(m.inspect_source(b'def _check_identity_and_budget(): pass\ndef _check_identity_and_budget(): pass')['methodCount'],2)
 def fixture(self,root):
  m.CONTEXT=root/'capsule';m.CONTEXT.mkdir(mode=0o700)
  sources={'tools.chatbot_file_cohort.human_session':b'raise RuntimeError("NEVER")\nclass HumanSession:\n def _check_identity_and_budget(self,row): return row\n'}
  sources.update({'fixture.'+str(i):b'raise RuntimeError("NEVER")'for i in range(218)})
  raw=m.encoded({k:base64.b64encode(v).decode()for k,v in sources.items()})
  decl={'moduleCount':219,'entryModule':'tools.installation_binding_apply.entry','sourceHashes':{k:m.sha(v)for k,v in sources.items()}}
  closure={'declaration':decl};m.CLOSURE=m.digest(closure)
  p={'sourceCommit':m.SOURCE,'closure':closure,'declarationHash':m.digest(decl),'fileHashes':{'sources.json':m.sha(raw)}};m.PACKAGE=m.digest(p)
  for name,data in [('sources.json',raw),('package.json',m.encoded(p))]:
   path=m.CONTEXT/name;path.write_bytes(data);path.chmod(0o600)
 def test_authenticated_full_read_is_read_only(self):
  with tempfile.TemporaryDirectory()as d:
   self.fixture(Path(d));before={p:p.read_bytes()for p in m.CONTEXT.iterdir()}
   with patch.object(m.sys,'flags',SimpleNamespace(isolated=True,no_site=True)):
    result=m.main()
   self.assertTrue(result['complete']);self.assertFalse(result['sourceExecuted']);self.assertEqual(result['credentialJournalsOpened'],0);self.assertFalse(result['newPreparationClaimPresent'])
   self.assertEqual(before,{p:p.read_bytes()for p in m.CONTEXT.iterdir()})
 def test_tampered_sources_denied(self):
  with tempfile.TemporaryDirectory()as d:
   self.fixture(Path(d));(m.CONTEXT/'sources.json').write_bytes(b'{}')
   with patch.object(m.sys,'flags',SimpleNamespace(isolated=True,no_site=True)):
    with self.assertRaisesRegex(ValueError,'PRIVATE_BYTES_CHANGED'):m.main()
  m.signal.alarm(0)
if __name__=='__main__':unittest.main()
