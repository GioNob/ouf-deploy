"""Actual isolated preparer; retained history fixtures, no issuer or runtime invocation."""
import ast,base64,copy,hashlib,importlib.util,json,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from tools.mcp_read_transport_compatibility import runtime as old_loader
from tools.ingestion_read_gateway_update import runtime as loader
SCRIPT=ROOT/'scripts/prepare-ingestion-read-gateway-update.py'
spec=importlib.util.spec_from_file_location('gateway_preparer',SCRIPT);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class ExecReached(Exception):pass
class Preparation(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.root.chmod(0o700);self.stopped=self.root/'mcp-ingestion-read-transport-execution-zzp9gqcs';self.stopped.mkdir(mode=0o700)
  self.human=self.root/'human';self.human.mkdir(mode=0o700)
  self.binding={'sessionDirectory':str(self.human),'expiresAt':1792415703}
  self.row={'binding':self.binding,'state':'READY','attempts':225,'budgetReset':False,'monotonicDeadline':10000}
  self.write(self.human/'recovery.json',self.row)
  self.receipt={'compatibilityReviewHash':'71ed7ce4faa930e84d7582ced9aaec56f07abf7fc1d9886e447f6fca39353c3e','reviewHash':'43b0caf6165b43df25e6fba7a37ccce39a1dc56597d47cffe7b6b8a8fed0b301','oauthAttemptsAfter':225,'expiresAt':1792415703,'newLoginWindowOpened':False,'budgetReset':False,'runtimeAuthorityIssued':False}
  self.write(self.stopped/'login-window-receipt.json',self.receipt)
  self.case={'humanBinding':self.binding,'priorOAuthAttempts':217,'originalBinding':{'path':'/never/execute-original','sha256':'a'*64}}
  source={name:b'pass\n'for name in old_loader.MODULES}
  self.sources={name:base64.b64encode(raw).decode()for name,raw in source.items()};self.write(self.stopped/'sources.json',self.sources)
  self.write(self.stopped/'case.json',self.case);(self.stopped/'reader.py').write_bytes(b'raise RuntimeError("HISTORICAL_MAIN_MUST_NEVER_EXECUTE")\n');(self.stopped/'reader.py').chmod(0o600)
  closure={'declaration':{'moduleCount':191,'sourceHashes':{name:p.sha(raw)for name,raw in source.items()}},'executables':{},'stdlibHash':'b'*64,'stdlibFileCount':0}
  self.package={'sourceCommit':p.SOURCE,'closure':closure,'sourcePins':{'ouf-deploy':p.SOURCE,'ouf-onboarding':'c'*40,'ouf-mcp-server':'d'*40},'fileHashes':{name:p.sha((self.stopped/name).read_bytes())for name in('sources.json','case.json','reader.py')}}
  self.write(self.stopped/'package.json',self.package);self.write(self.stopped/'runtime.claim.json',{'packageHash':p.digest(self.package),'automaticReplayAllowed':False})
  self.delivery={name:(ROOT/'tools/ingestion_read_gateway_update'/(name+'.py')).read_bytes()for name in('entry','authority','owner','compiler','runtime')}
  self.delivery.update(prepare=SCRIPT.read_bytes(),bootstrap=(ROOT/'scripts/execute-ingestion-read-gateway-update.py').read_bytes(),**{'gateway-data':(ROOT/'releases/ingestion-read-gateway-compiler-20261019.json').read_bytes()})
  for target,key,value in((p,'CONTEXT',self.stopped),(p,'PACKAGE',p.digest(self.package)),(p,'CLOSURE',p.digest(closure)),(p.time,'time',lambda:1792410000),(p.time,'monotonic',lambda:1000)):
   pa=patch.object(target,key,value);pa.start();self.addCleanup(pa.stop)
  self.exec=patch.object(p.os,'execv',side_effect=ExecReached);self.dispatch=self.exec.start();self.addCleanup(self.exec.stop)
 def write(self,path,value):path.write_bytes(p.encoded(value));path.chmod(0o600)
 def prepare(self):return p.main(self.delivery,'e'*40)
 def test_actual_preparer_preserves_ready225_and_sources_then_seals195_without_any_historical_main(self):
  original=(self.human/'recovery.json').read_bytes()
  with self.assertRaises(ExecReached):self.prepare()
  self.assertEqual((self.human/'recovery.json').read_bytes(),original)
  claims=list(self.root.glob('ingestion-read-gateway-preparation-*.claim.json'));self.assertEqual(len(claims),1)
  destination=Path(json.loads(claims[0].read_bytes())['context']);report=json.loads((destination/'preparation-result.json').read_bytes())
  self.assertEqual(report['sourceModuleCount'],195);self.assertEqual(report['priorOAuthAttempts'],225);self.assertFalse(report['newLoginWindowOpened'])
  case=json.loads((destination/'case.json').read_bytes());self.assertEqual(case['humanBinding'],self.binding)
  self.assertFalse((destination/'authority.json').exists());self.assertFalse((destination/'login-window-receipt.json').exists())
  self.dispatch.assert_called_once()
 def test_repeat_preparation_never_dispatches_second_capsule(self):
  with self.assertRaises(ExecReached):self.prepare()
  self.dispatch.reset_mock()
  with self.assertRaises(FileExistsError):self.prepare()
  self.dispatch.assert_not_called()
 def test_advanced_original_authority_or_changed_login_receipt_denies(self):
  self.write(self.stopped/'authority.json',{})
  with self.assertRaises(ValueError):self.prepare()
  self.dispatch.assert_not_called();(self.stopped/'authority.json').unlink()
  self.write(self.stopped/'login-window-receipt.json',{**self.receipt,'newLoginWindowOpened':True})
  with self.assertRaises(ValueError):self.prepare()
  self.dispatch.assert_not_called()
 def test_expired_window_blocked_session_or_reset_denies_without_new_login(self):
  for changes in({'state':'BLOCKED'},{'attempts':256},{'budgetReset':True},{'monotonicDeadline':1001}):
   self.write(self.human/'recovery.json',{**self.row,**changes})
   with self.subTest(changes=changes),self.assertRaises(ValueError):self.prepare()
  self.dispatch.assert_not_called()
 def test_preparer_has_no_oauth_network_or_old_entry_execution_surface(self):
  tree=ast.parse(SCRIPT.read_bytes());calls=[ast.unparse(n.func)for n in ast.walk(tree)if isinstance(n,ast.Call)]
  self.assertFalse(any(x.endswith(('.login','.refresh_if_due','.authenticate','.current','.request','.ensure'))for x in calls))
  self.assertFalse(any(x in calls for x in('entry.main','reader.main','runtime.main')))
if __name__=='__main__':unittest.main()
