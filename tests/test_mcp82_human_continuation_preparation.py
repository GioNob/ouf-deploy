import ast,base64,hashlib,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from tools.ingestion_read_gateway_custody import runtime as prior_loader
SCRIPT=ROOT/'scripts/prepare-mcp82-human-continuation.py'
spec=importlib.util.spec_from_file_location('mcp82_preparer',SCRIPT);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class ExecReached(Exception):pass
class Preparation(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.context=self.root/'completed198';self.context.mkdir(mode=0o700);self.human=self.root/'human';self.human.mkdir(mode=0o700)
  self.binding={'sessionDirectory':str(self.human),'expiresAt':1792415703};self.row={'binding':self.binding,'state':'READY','attempts':229,'budgetReset':False,'monotonicDeadline':10000,'lastObservedAt':1792413400}
  self.write(self.human/'recovery.json',self.row)
  self.image=self.root/'image.json';self.write(self.image,{'imageAudit':{'sourceCommit':'1f2c28d7abadae78680b040ba7b58be62ef85ee9'}})
  self.case={'humanBinding':self.binding,'priorOAuthAttempts':227,'imageBinding':{'path':str(self.image),'sha256':p.sha(self.image.read_bytes())}}
  sources={n:b'pass\n'for n in prior_loader.MODULES}
  for name in p.PINS:sources[name]=(ROOT/Path(*name.split('.'))).with_suffix('.py').read_bytes()
  self.write(self.context/'sources.json',{n:base64.b64encode(raw).decode()for n,raw in sources.items()});self.write(self.context/'case.json',self.case)
  (self.context/'reader.py').write_bytes(b'raise RuntimeError("NO_OLD_MAIN")\n');(self.context/'reader.py').chmod(0o600)
  self.closure={'declaration':{'moduleCount':198,'sourceHashes':{n:p.sha(v)for n,v in sources.items()},'entryModule':'tools.ingestion_read_gateway_custody.entry'},'executables':{},'stdlibHash':'b'*64,'stdlibFileCount':0}
  self.package={'sourceCommit':p.SOURCE,'closure':self.closure,'sourcePins':{'ouf-deploy':p.SOURCE,'ouf-onboarding':'c'*40,'ouf-mcp-server':'d'*40},'fileHashes':{n:p.sha((self.context/n).read_bytes())for n in('sources.json','case.json','reader.py')}}
  self.write(self.context/'package.json',self.package);self.write(self.context/'runtime.claim.json',{'packageHash':p.digest(self.package),'automaticReplayAllowed':False})
  self.write(self.context/'preparation-result.json',{'packageHash':p.digest(self.package),'sourceClosureHash':p.digest(self.closure),'contextPath':str(self.context)})
  self.routes={str(i):{'id':str(i)}for i in range(82)};self.plan={'gateway':{'afterRoutes':self.routes}}
  scope={'planHash':p.digest(self.plan)};self.review={'sourceClosureHash':p.digest(self.closure),'scopes':{'ingestionReadGatewayCustodyUpdate':scope}}
  self.write(self.context/'execution-plan.json',self.plan);self.write(self.context/'review.json',self.review);self.write(self.context/'decision.json',{'reviewHash':p.digest(self.review)})
  self.journal={'scopeHash':p.digest(scope),'nextStage':4,'effects':[{'state':'APPLIED'}for i in range(4)],'incidentState':'RECOVERED','budgetReset':False}
  self.write(self.context/'recovery.json',self.journal)
  self.write(self.context/'update-result.json',{'schema':'ouf.ingestion-read-gateway-result.v1','complete':True,'gatewayWrites':2,'humanAttemptsAfter':229,'approvedPublicMetadata0440Preserved':True,'routeCount':82,'routeMapHash':p.digest(self.routes),'sourceActivated':False,'containerLifecycleOperations':0})
  logical=p.digest({'profile':'ouf.ingestion-read-gateway-publication.v1','beforeRouteMapHash':p.BEFORE,'capabilities':['ouf.ingestion.status','ouf.ingestion.history']})
  self.fence=self.root/('ingestion-read-gateway-custody-preparation-'+logical+'.claim.json');self.write(self.fence,{'context':str(self.context),'priorOAuthAttempts':227,'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False})
  self.delivery={n:(ROOT/'tools/mcp_read_transport_gateway82'/(n+'.py')).read_bytes()for n in('entry','authority','owner','native','runtime')};self.delivery['runtime']=(ROOT/'tools/mcp_read_transport_gateway82_continuation/runtime.py').read_bytes();self.delivery.update({'continuation-entry':(ROOT/'tools/mcp_read_transport_gateway82_continuation/entry.py').read_bytes(),'continuation-authority':(ROOT/'tools/mcp_read_transport_gateway82_continuation/authority.py').read_bytes(),'login':(ROOT/'tools/mcp_read_transport_gateway82_continuation/login.py').read_bytes()});self.delivery.update(prepare=SCRIPT.read_bytes(),bootstrap=(ROOT/'scripts/execute-mcp82-human-continuation.py').read_bytes())
  for target,key,value in ((p,'CONTEXT',self.context),(p,'AFTER',p.digest(self.routes)),(p.time,'time',lambda:1792413500),(p.time,'monotonic',lambda:1000)):
   pa=patch.object(target,key,value);pa.start();self.addCleanup(pa.stop)
  pa=patch.object(p.os,'execv',side_effect=ExecReached);self.execv=pa.start();self.addCleanup(pa.stop)
 def write(self,path,value):path.write_bytes(p.encoded(value));path.chmod(0o600)
 def test_completed_history_preserved_new202_capsule_and_no_authority(self):
  paths=[self.context/'recovery.json',self.context/'runtime.claim.json',self.fence,self.human/'recovery.json'];before={x:x.read_bytes()for x in paths}
  with self.assertRaises(ExecReached):p.main(self.delivery,'e'*40)
  self.assertTrue(all(x.read_bytes()==raw for x,raw in before.items()));self.execv.assert_called_once()
  fence=list(self.root.glob('mcp82-explicit-human-continuation-preparation-*.claim.json'));self.assertEqual(len(fence),1)
  context=Path(json.loads(fence[0].read_bytes())['context']);report=json.loads((context/'preparation-result.json').read_bytes())
  self.assertEqual(report['sourceModuleCount'],205);self.assertEqual(report['priorOAuthAttempts'],229);self.assertFalse((context/'authority.json').exists())
  self.execv.reset_mock()
  with self.assertRaises(FileExistsError):p.main(self.delivery,'e'*40)
  self.execv.assert_not_called()
 def test_unknown_or_incomplete_gateway_result_denies(self):
  self.write(self.context/'recovery.json',{**self.journal,'nextStage':3})
  with self.assertRaises(Exception):p.main(self.delivery,'e'*40)
  self.execv.assert_not_called()
 def test_human_budget_blocked_or_insufficient_window_denies_without_claim(self):
  for changes in ({'attempts':256},{'state':'BLOCKED'},{'budgetReset':True},{'attempts':228}):
   self.write(self.human/'recovery.json',{**self.row,**changes})
   with self.assertRaises(Exception):p.main(self.delivery,'e'*40)
  self.execv.assert_not_called();self.assertEqual(list(self.root.glob('mcp82-explicit-human-continuation-preparation-*')),[])
 def test_no_historical_main_network_login_or_rebuild(self):
  calls=[ast.unparse(n.func)for n in ast.walk(ast.parse(SCRIPT.read_bytes()))if isinstance(n,ast.Call)]
  self.assertFalse(any(v.endswith(('.request','.authenticate','.refresh_if_due','.login','.ensure','.archive'))for v in calls))
if __name__=='__main__':unittest.main()
