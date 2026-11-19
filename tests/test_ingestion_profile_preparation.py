import ast,base64,hashlib,importlib.util,json,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;PKG=HERE
if not(PKG/'runtime.py').exists():PKG=ROOT/'tools/ingestion_profile_publication'
PREP=HERE/'prepare.py'
if not PREP.exists():PREP=ROOT/'scripts/prepare-ingestion-profile-publication.py'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('projection_preparer',PREP);loader=load('projection_closed_runtime',PKG/'runtime.py');history=load('completed_owner7_history',PKG/'history.py')
class Preparation(unittest.TestCase):
 def fixture(self,root):
  owner=root/'completed-owner';owner.mkdir(mode=0o700);names=loader.MODULES-{n for n in loader.MODULES if n.startswith('tools.ingestion_profile_publication.')}
  sources={n:b'pass\n'for n in names};members={'reader.py':b'raise RuntimeError("OLD_READER_MUST_NOT_RUN")'}
  package={'sourcePins':{'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40,'ouf-mcp-server':'c'*40},'closure':{'executables':{},'stdlibHash':'0'*64,'stdlibFileCount':0}}
  completed={'sources':sources,'package':package,'raw':members,'case':{'originalBinding':{'path':str(root/'original'),'sha256':'0'*64}},
   'plan':{'humanBinding':{'PUBLIC_BINDING_ONLY':True},'projectionBinding':{'sha256':'b'*64}}}
  delivery={n:(PKG/(n+'.py')).read_bytes()for n in m.NAMES if n not in('prepare','bootstrap')}
  bootstrap=HERE/'bootstrap.py'
  if not bootstrap.exists():bootstrap=ROOT/'scripts/execute-ingestion-profile-publication.py'
  delivery.update(prepare=PREP.read_bytes(),bootstrap=bootstrap.read_bytes())
  delivery['history']=('from pathlib import Path\nCONTEXT=Path('+repr(str(owner))+')\nRESULT='+repr(history.RESULT)+'\nEXPORT='+repr(history.EXPORT)+'\ndef verified():return '+repr(completed)+'\n').encode()
  return delivery,sources
 def test_actual244_preparation_has_no_credential_read_or_old_execution_and_is_once_only(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   root=Path(d);delivery,sources=self.fixture(root);dispatch=[]
   with patch.object(m.sys,'flags',types.SimpleNamespace(isolated=True,no_site=True)),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'execv',side_effect=lambda *a:dispatch.append(a)):
    m.main(delivery,'a'*40);self.assertEqual(len(dispatch),1);context=Path(dispatch[0][1][-2]);report=m.parsed(context/'preparation-result.json')
    self.assertEqual(report['sourceModuleCount'],244);self.assertFalse(report['humanSourceChanged']);self.assertEqual(report['humanCredentialJournalsRead'],0)
    sealed=m.parsed(context/'sources.json');self.assertTrue(all(base64.b64decode(sealed[n])==v for n,v in sources.items()))
    self.assertFalse((context/'authority.json').exists());self.assertFalse((context/'runtime.claim.json').exists())
    with self.assertRaisesRegex(ValueError,'PROJECTION_ALREADY_PREPARED_NO_REPLAY'):m.main(delivery,'a'*40)
    self.assertEqual(len(dispatch),1)
   m.signal.alarm(0)
 def test_loader_is_closed_to244_and_new_mode(self):
  self.assertEqual(len(loader.MODULES),244);self.assertEqual(loader.ENTRY,'tools.ingestion_profile_publication.entry')
  sources={n:b'pass\n'for n in loader.MODULES};loader.compile_sources(sources)
  for mode in('INGESTION_OWNER_REFERENCE_APPLY','INGESTION_OWNER_REFERENCE_RECOVERY_APPLY','INSTALLATION_BINDING_APPLY'):
   with self.assertRaises(Exception):loader.declaration('a'*40,sources,b'loader',{'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40,'ouf-mcp-server':'c'*40},{'executorSha256':'d'*64,'caseSha256':'e'*64,'mode':mode})
 def test_history_never_imports_executes_retained_sources_or_opens_token_files(self):
  tree=ast.parse((PKG/'history.py').read_bytes());calls={ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)}
  for forbidden in('exec','eval','compile','__import__','subprocess.Popen','write_new'):self.assertNotIn(forbidden,calls)
  text=(PKG/'history.py').read_text();self.assertNotIn("/'human-access.jwt'",text);self.assertNotIn("'accessToken'",text)
 def test_session_and_owner_reads_precede_native_publication_approval(self):
  tree=ast.parse((PKG/'entry.py').read_bytes());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');calls=[n for n in ast.walk(main)if isinstance(n,ast.Call)]
  line=lambda name:min(n.lineno for n in calls if ast.unparse(n.func)==name)
  self.assertLess(line('session.authenticate'),line('http.active'));self.assertLess(line('http.active'),line('authority.terminal_consent'))
  self.assertLess(line('authority.terminal_consent'),line('authority.issue_action'));self.assertLess(line('authority.issue_action'),line('update.run'))
if __name__=='__main__':unittest.main()
