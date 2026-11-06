import copy,json,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from tools.storage_planning import g0_host as h,g0_package as p
from tools.storage_planning.inventory_manifest import canonical,sha
import test_storage_g0_network as base
put=base.put

class FakeEngine:
 def __init__(self,scope,count):self.scope=scope;self.count=count;self.requests=0;self.bytes=0
 def get(self,path):
  self.requests+=1
  if path=='/containers/json?all=1':return [{'Id':format(i,'064x')} for i in range(1,self.count+1)]
  return {'Id':path.split('/')[2],'Image':'sha256:'+'a'*64,'State':{'Running':False},'Config':{'Env':['SECRET=not-exported']}}

class HostBoundTests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def test_full_145_including_132_unmapped(self):
  e=FakeEngine(self.root,145);roles={str(i):{'containerId':format(i,'064x'),'nativeImage':'sha256:'+'a'*64} for i in range(1,14)}
  r=h.snapshot(e,roles,192);self.assertEqual(len(r['containers']),145);self.assertEqual(r['unmappedContainerCount'],132);self.assertEqual(e.requests,146);self.assertNotIn(b'not-exported',canonical(r))
 def test_exact_192_boundary_two_passes_386_gets(self):
  e=FakeEngine(self.root,192);a=h.snapshot(e,{},192);b=h.snapshot(e,{},192);self.assertEqual(a,b);self.assertEqual(e.requests,386)
 def test_193_denied_after_one_get_with_count_preserved(self):
  e=FakeEngine(self.root,193)
  with self.assertRaisesRegex(ValueError,'G0_HOST_CONTAINER_LIMIT'):h.snapshot(e,{},192)
  self.assertEqual(e.requests,1);self.assertEqual(e.last_list_observation['containerCount'],193);self.assertEqual(json.loads((self.root/'host-list-1.json').read_bytes())['containerCount'],193)
 def test_legacy_145_still_denied_at64(self):
  e=FakeEngine(self.root,145)
  with self.assertRaisesRegex(ValueError,'G0_HOST_CONTAINER_LIMIT'):h.snapshot(e,{})
  self.assertEqual(json.loads((self.root/'host-list-1.json').read_bytes())['maximumContainers'],64)
 def test_budget_denies_387th_request_before_socket(self):
  e=object.__new__(h.Engine);e.max_requests=386;e.requests=386;e.bytes=0;e.until=time.monotonic()+10
  with self.assertRaisesRegex(ValueError,'G0_HOST_BUDGET'):e.get('/containers/json?all=1')
 def test_arbitrary_profile_limit_denied(self):
  e=FakeEngine(self.root,145)
  with self.assertRaisesRegex(ValueError,'G0_HOST_FIXED_CONTAINER_PROFILE'):h.snapshot(e,{},999)
  self.assertEqual(e.requests,0)

class ReconciledProfileTests(unittest.TestCase):
 def setUp(self):
  self.f=base.NetworkTest();self.f.setUp();self.addCleanup(self.f.doCleanups);self.f.install()
  self.old=copy.deepcopy(self.f.config);self.old_path=self.f.path;self.old_pre=self.f.check()[-1]
  scope=self.f.output/self.old['operationId'];scope.mkdir()
  self.prior_result={'schema':'ouf.storage-g0-package-result.v1','status':'HELD','reason':'G0_HOST_CONTAINER_LIMIT','phase':'HOST_BEFORE','scopeConsumed':True,'technicalCaptureComplete':False,'engineGets':1,'cumulativeEngineGets':53,'priorEngineGets':52,'priorControls':17,'targetWrites':0,'databaseExportsAttempted':0,'s3Requests':None,'childScopes':{},'automaticReplayAllowed':False,'runtimeAuthorityIssued':False}
  put(scope/'result.json',self.prior_result)
  claim=self.old_pre|{'collectionDecisionRef':self.old['collectionDecisionRef'],'operationId':self.old['operationId'],'installationRef':self.old['installationRef']};put(scope/'claim.private.json',claim)
  decision={'executionInputSha256':sha(self.old_path.read_bytes()),'decisionRef':self.old['collectionDecisionRef'],'scope':str(scope),'limits':p.LIMITS,'boundInputSha256':claim['boundInputSha256'],'runtimeAuthorityIssued':False};put(self.f.inputs/'decision.json',decision)
  self.c=copy.deepcopy(self.old);self.c.update(schema='ouf.storage-g0-package-input.v3',operationId='fixture-next',collectionDecisionRef=None)
  refs={'result':scope/'result.json','claim':scope/'claim.private.json','decision':self.f.inputs/'decision.json','input':self.old_path}
  self.c['priorAttemptFiles']={k:{'path':str(v),'sha256':sha(v.read_bytes())} for k,v in refs.items()}
  for k,path in self.old['connectionFiles'].items():
   v=json.loads(Path(path).read_bytes());v['operationId']='fixture-next-'+k
   self.c['connectionFiles'][k]=put(self.f.inputs/('next-'+k+'.json'),v)
  v=json.loads(Path(self.old['networkBindingFile']).read_bytes());v['operationId']='fixture-next'
  self.c['networkBindingFile']=put(self.f.inputs/'next-network.json',v)
  self.path=self.f.inputs/'next.json';self.save()
 def save(self):put(self.path,self.c)
 def check(self):return p.preflight(self.path,self.f.bundle,self.f.digest)[-1]
 def test_new_profile_carries53_and_requires_new_decision(self):
  r=self.check();self.assertEqual(r['limits']['engineGets'],386);self.assertEqual(r['limits']['priorEngineGets'],53);self.assertEqual(r['limits']['hostContainers'],192);self.assertIn('COLLECTION_DECISION_REFERENCE',r['operatorInputsMissing']);self.assertFalse(r['targetCommandAuthorized'])
 def test_prior_decision_cannot_be_reused(self):
  self.c['collectionDecisionRef']=self.old['collectionDecisionRef'];self.save()
  with self.assertRaisesRegex(ValueError,'G0_PRIOR_DECISION_NOT_REUSABLE'):self.check()
 def test_rehashed_wrong_disposition_cannot_reset_budget(self):
  ref=self.c['priorAttemptFiles']['result'];v=self.prior_result|{'engineGets':2};put(Path(ref['path']),v);ref['sha256']=sha(Path(ref['path']).read_bytes());self.save()
  with self.assertRaisesRegex(ValueError,'G0_PRIOR_EXACT_HELD_DISPOSITION'):self.check()
 def test_connection_cannot_change_except_operation_id(self):
  path=Path(self.c['connectionFiles']['s3']);v=json.loads(path.read_bytes());v['connection']['region']='changed';put(path,v)
  with self.assertRaisesRegex(ValueError,'G0_PRIOR_CONNECTION_PROJECTION'):self.check()
 def test_changed_prior_bytes_denied(self):
  path=Path(self.c['priorAttemptFiles']['decision']['path']);put(path,{'changed':True})
  with self.assertRaisesRegex(ValueError,'G0_PRIOR_RECEIPT_CHANGED'):self.check()
 def test_old_scope_not_reused(self):
  self.c['operationId']=self.old['operationId'];self.save();self.assertRaises(ValueError,self.check)

if __name__=='__main__':unittest.main()
