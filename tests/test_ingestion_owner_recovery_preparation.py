import ast,base64,copy,importlib.util,json,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;PKG=HERE
if not(PKG/'runtime.py').exists():PKG=ROOT/'tools/ingestion_owner_recovery'
PREP=HERE/'prepare.py'
if not PREP.exists():PREP=ROOT/'scripts/prepare-ingestion-owner-recovery.py'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('new_recovery_preparer',PREP);loader=load('new_recovery_loader',PKG/'runtime.py')
class Preparation(unittest.TestCase):
 def test_whole_approved_source_prefix_stays_byte_exact_without_ast_guard_guesses(self):
  raw=b'class HumanSession: pass\n_explicit_272_identity=True\n';patchraw=(PKG/'confirmation_patch.py').read_bytes();extension=(PKG/'human_extension.py').read_bytes()
  result=m.extend_human(raw,m.sha(raw),patchraw,extension);self.assertEqual(result[:len(raw)],raw)
  with self.assertRaises(Exception):m.extend_human(raw+b' ',m.sha(raw),patchraw,extension)
  with self.assertRaises(Exception):m.extend_human(result,m.sha(result),patchraw,extension)
 def fixture(self,root):
  first=root/'stopped';first.mkdir(mode=0o700)
  names=loader.MODULES-{n for n in loader.MODULES if n.startswith('tools.ingestion_owner_recovery.')}
  sources={n:b'pass\n'for n in names};sources['tools.chatbot_file_cohort.human_session']=b'class HumanSession: pass\n_explicit_272_identity=True\n'
  members={'case.json':m.encoded({'originalBinding':{'path':str(root/'original'),'sha256':'0'*64}}),'bootstrap.py':b'raise Exception("OLD_MAIN_MUST_NOT_RUN")',
   'runtime.py':b'raise Exception("OLD_LOADER_MUST_NOT_RUN")','reader.py':b'raise Exception("OLD_READER_MUST_NOT_RUN")',
   'sources.json':m.encoded({n:base64.b64encode(v).decode()for n,v in sources.items()})}
  closure={'declaration':{'moduleCount':232,'sourceHashes':{n:m.sha(v)for n,v in sources.items()}}}
  package={'closure':closure,'sourcePins':{'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40,'ouf-mcp-server':'c'*40},'fileHashes':{n:m.sha(v)for n,v in members.items()}}
  for n,v in members.items():m.write_new(first/n,v)
  m.write_new(first/'package.json',m.encoded(package));m.write_new(first/'runtime.claim.json',m.encoded({'packageHash':m.digest(package),'automaticReplayAllowed':False}))
  delivery={n:(PKG/(n+'.py')).read_bytes()for n in m.NAMES if n not in ('prepare','bootstrap')}
  bootstrap=HERE/'bootstrap.py'
  if not bootstrap.exists():bootstrap=ROOT/'scripts/execute-ingestion-owner-recovery.py'
  delivery.update(prepare=PREP.read_bytes(),bootstrap=bootstrap.read_bytes())
  # A pure public-binding reader fixture: no old bootstrap/imports or network.
  delivery['reconcile']=b"def predecessor_binding():return {'retryProfile':{'maximumAttempts':272},'expiresAt':1792446208}\n"
  return first,package,closure,delivery
 def test_actual238_sealing_preserves_stopped_files_and_cannot_prepare_twice(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   root=Path(d);first,package,closure,delivery=self.fixture(root);before={p:p.read_bytes()for p in first.iterdir()};dispatched=[]
   with patch.object(m,'FIRST',first),patch.object(m,'PACKAGE',m.digest(package)),patch.object(m,'CLOSURE',m.digest(closure)),patch.object(m.sys,'flags',types.SimpleNamespace(isolated=True,no_site=True)),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.os,'execv',side_effect=lambda *args:dispatched.append(args)):
    m.main(delivery,'a'*40);self.assertEqual(len(dispatched),1)
    context=Path(dispatched[0][1][-2]);report=m.parsed(context/'preparation-result.json');self.assertEqual(report['sourceModuleCount'],238)
    self.assertEqual(report['priorOAuthAttempts'],272);self.assertFalse(report['budgetChangeAuthorized']);self.assertEqual(report['oauthRequests'],0)
    self.assertTrue(all(p.read_bytes()==raw for p,raw in before.items()));self.assertFalse((context/'authority.json').exists());self.assertFalse((context/'runtime.claim.json').exists())
    with self.assertRaisesRegex(ValueError,'OWNER_RECOVERY_ALREADY_PREPARED_NO_REPLAY'):m.main(delivery,'a'*40)
    self.assertEqual(len(dispatched),1)
   m.signal.alarm(0)
 def test_compiler_uses_only_stopped_binding_after_reconciliation_before_any_owner_call(self):
  tree=ast.parse((PKG/'entry.py').read_bytes());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main')
  calls=[n for n in ast.walk(main)if isinstance(n,ast.Call)]
  auth=next(n for n in calls if ast.unparse(n.func)=='login.authenticate')
  self.assertEqual(ast.unparse(auth.args[1]),"case['humanBinding']")
  self.assertLess(auth.lineno,min(n.lineno for n in calls if ast.unparse(n.func)in('http.active','http.call')))
 def test_preparer_has_no_token_or_mutation_primitives_or_retained_entrypoint(self):
  calls={ast.unparse(n.func)for n in ast.walk(ast.parse(PREP.read_bytes()))if isinstance(n,ast.Call)}
  for suffix in('.login','.refresh_if_due','.token','.request','.issue_action','.Popen'):
   self.assertFalse(any(n.endswith(suffix)for n in calls))
  self.assertEqual(loader.ENTRY,'tools.ingestion_owner_recovery.entry');self.assertEqual(len(loader.MODULES),238)
if __name__=='__main__':unittest.main()
