import ast,base64,hashlib,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from tools.ingestion_read_gateway_update import runtime as old_loader
SCRIPT=ROOT/'scripts/prepare-ingestion-read-gateway-custody.py'
spec=importlib.util.spec_from_file_location('custody_preparer',SCRIPT);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class ExecReached(Exception):pass
class Preparation(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.root.chmod(0o700);self.stopped=self.root/'stopped195';self.stopped.mkdir(mode=0o700)
  self.human=self.root/'human';self.human.mkdir(mode=0o700);self.binding={'sessionDirectory':str(self.human),'expiresAt':1792415703}
  self.row={'binding':self.binding,'state':'READY','attempts':227,'budgetReset':False,'monotonicDeadline':10000};self.write(self.human/'recovery.json',self.row)
  self.case={'humanBinding':self.binding,'priorOAuthAttempts':225,'originalBinding':{'path':'/never/execute-original','sha256':'a'*64}}
  sources={name:b'pass\n'for name in old_loader.MODULES};sources['tools.semantic_mcp_update.native']=(ROOT/'tools/semantic_mcp_update/native.py').read_bytes()
  self.source_map={n:base64.b64encode(v).decode()for n,v in sources.items()};self.write(self.stopped/'sources.json',self.source_map);self.write(self.stopped/'case.json',self.case)
  (self.stopped/'reader.py').write_bytes(b'raise RuntimeError("HISTORICAL_MAIN_MUST_NEVER_EXECUTE")\n');(self.stopped/'reader.py').chmod(0o600)
  self.closure={'declaration':{'moduleCount':195,'sourceHashes':{n:p.sha(v)for n,v in sources.items()}},'executables':{},'stdlibHash':'b'*64,'stdlibFileCount':0}
  self.package={'sourceCommit':p.SOURCE,'closure':self.closure,'sourcePins':{'ouf-deploy':p.SOURCE,'ouf-onboarding':'c'*40,'ouf-mcp-server':'d'*40},'fileHashes':{n:p.sha((self.stopped/n).read_bytes())for n in('sources.json','case.json','reader.py')}}
  self.write(self.stopped/'package.json',self.package);self.write(self.stopped/'runtime.claim.json',{'packageHash':p.digest(self.package),'automaticReplayAllowed':False})
  self.before={str(n):{'id':str(n)}for n in range(80)};self.before_hash=p.digest(self.before)
  self.logical=p.digest({'profile':'ouf.ingestion-read-gateway-publication.v1','beforeRouteMapHash':self.before_hash,'capabilities':['ouf.ingestion.status','ouf.ingestion.history']})
  self.plan={'logicalUpdateRef':self.logical,'gateway':{'beforeRoutes':self.before}}
  self.review={'sourceClosureHash':p.digest(self.closure),'scopes':{'ingestionReadGatewayUpdate':{'planHash':p.digest(self.plan),'maximumGatewayWrites':2}}}
  self.journal={'schema':'ouf.ingestion-read-gateway-journal.v1','version':0,'nextStage':0,'effects':[],'budgetReset':False,'scopeHash':p.digest(self.review['scopes']['ingestionReadGatewayUpdate']),'authorityHash':'f'*64,'expiresAt':p.EXPIRES}
  self.decision={'expiresAt':p.EXPIRES,'reviewHash':p.digest(self.review),'sourceClosureHash':p.digest(self.closure)}
  self.write(self.stopped/'execution-plan.json',self.plan);self.write(self.stopped/'review.json',self.review);self.write(self.stopped/'decision.json',self.decision);self.write(self.stopped/'recovery.json',self.journal)
  self.old_fence=self.root/('ingestion-read-gateway-'+self.logical+'.claim.json');self.write(self.old_fence,{'context':str(self.stopped),'planHash':p.digest(self.plan),'authorityHash':'f'*64,'automaticReplayAllowed':False})
  self.delivery={n:(ROOT/'tools/ingestion_read_gateway_custody'/(n+'.py')).read_bytes()for n in('entry','authority','owner','runtime')}
  self.delivery.update(prepare=SCRIPT.read_bytes(),bootstrap=(ROOT/'scripts/execute-ingestion-read-gateway-custody.py').read_bytes())
  for target,key,value in((p,'CONTEXT',self.stopped),(p,'PACKAGE',p.digest(self.package)),(p,'CLOSURE',p.digest(self.closure)),(p,'PLAN',p.digest(self.plan)),(p,'REVIEW',p.digest(self.review)),(p,'BEFORE',self.before_hash),(p.time,'time',lambda:1792413500),(p.time,'monotonic',lambda:1000)):
   pa=patch.object(target,key,value);pa.start();self.addCleanup(pa.stop)
  pa=patch.object(p.os,'execv',side_effect=ExecReached);self.dispatch=pa.start();self.addCleanup(pa.stop)
 def write(self,path,value):path.write_bytes(p.encoded(value));path.chmod(0o600)
 def prepare(self):return p.main(self.delivery,'e'*40)
 def test_actual_preparer_preserves_old_claims_journal_human_budget_and_seals198(self):
  before={path:path.read_bytes()for path in(self.stopped/'recovery.json',self.stopped/'runtime.claim.json',self.old_fence,self.human/'recovery.json')}
  with self.assertRaises(ExecReached):self.prepare()
  self.assertTrue(all(path.read_bytes()==raw for path,raw in before.items()))
  claims=list(self.root.glob('ingestion-read-gateway-custody-preparation-*.claim.json'));self.assertEqual(len(claims),1)
  dest=Path(json.loads(claims[0].read_bytes())['context']);report=json.loads((dest/'preparation-result.json').read_bytes())
  self.assertEqual(report['sourceModuleCount'],198);self.assertEqual(report['priorOAuthAttempts'],227);self.assertTrue(report['predecessorZeroEffectsProven']);self.assertFalse(report['runtimeAuthorityIssued'])
  case=json.loads((dest/'case.json').read_bytes());self.assertEqual(case['custodyPredecessor']['bindings']['journal']['sha256'],p.sha(before[self.stopped/'recovery.json']))
  self.assertFalse((dest/'authority.json').exists());self.dispatch.assert_called_once()
 def test_still_live_old_authority_denies_before_any_new_fence_or_dispatch(self):
  with patch.object(p.time,'time',return_value=p.EXPIRES-1),self.assertRaisesRegex(Exception,'PREDECESSOR_AUTHORITY_STILL_LIVE'):self.prepare()
  self.assertEqual(list(self.root.glob('ingestion-read-gateway-custody-preparation-*')),[]);self.dispatch.assert_not_called()
 def test_old_effect_or_logical_fence_drift_denies(self):
  self.write(self.stopped/'recovery.json',{**self.journal,'nextStage':1})
  with self.assertRaises(Exception):self.prepare()
  self.write(self.stopped/'recovery.json',self.journal);self.write(self.old_fence,{'different':True})
  with self.assertRaises(Exception):self.prepare()
  self.dispatch.assert_not_called()
 def test_no_new_human_window_reset_or_exhausted_budget_is_allowed(self):
  for changes in({'state':'BLOCKED'},{'attempts':256},{'budgetReset':True},{'monotonicDeadline':1001}):
   self.write(self.human/'recovery.json',{**self.row,**changes})
   with self.subTest(changes=changes),self.assertRaises(Exception):self.prepare()
  self.dispatch.assert_not_called()
 def test_second_preparation_never_dispatches_again(self):
  with self.assertRaises(ExecReached):self.prepare()
  self.dispatch.reset_mock()
  with self.assertRaises(FileExistsError):self.prepare()
  self.dispatch.assert_not_called()
 def test_preparer_never_executes_historical_main_or_issuer_flow(self):
  calls=[ast.unparse(n.func)for n in ast.walk(ast.parse(SCRIPT.read_bytes()))if isinstance(n,ast.Call)]
  self.assertFalse(any(x.endswith(('.login','.refresh_if_due','.current','.authenticate','.request','.ensure'))for x in calls))
if __name__=='__main__':unittest.main()
