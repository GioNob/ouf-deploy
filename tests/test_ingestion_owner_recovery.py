"""Actual dual signatures and journals; native HTTPS lifecycle with an in-memory owner peer."""
import copy,json,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_installation_binding_apply as old
from tools.ingestion_owner_recovery import owner as o,authority as a,native as n,entry as e,runtime as loader
from tools.semantic_lease_recovery.recovery_journal import Journal
ROOT=Path(__file__).resolve().parents[1]
class Signed(old.CryptoAndJournal):
 def setUp(self):
  super().setUp();self.old.hb['retryProfile']={'id':'ouf.human.ingestion-owner-recovery288.v7','maximumAttempts':288};self.context=self.old.c.root/'ingestion-owner-recovery-execution-abcdefgh';self.context.mkdir(mode=0o700)
  source=copy.deepcopy(self.plan['bindingPlan']['candidatePayload']);source['secrets']['provider']='FILES'
  candidate=copy.deepcopy(source);candidate['secrets']['references']['ingestionReadOwnerKey']=str(self.old.c.root/'draft'/'ingestion-read-owner.key')
  checksum=old.prior.p.canonical_owner(candidate);source_checksum=old.prior.p.canonical_owner(source)
  b={'sourcePayload':source,'candidatePayload':candidate,'candidatePayloadChecksum':checksum,'onlyChange':'/secrets/references/ingestionReadOwnerKey','addedBindings':{},
   'expectedActive':{'installationId':'fixture','revision':6,'generation':6,'checksum':source_checksum},'expectedActiveETag':'"6:'+source_checksum+':6"'}
  self.plan.update(schema='ouf.ingestion-owner-reference-plan.v1',kind=o.KIND,authorityDirectory=str(self.context),bindingPlan=b,
   draftBinding={'path':str(self.old.c.root/'draft'/'draft-plan.json'),'sha256':o.DRAFT_HASH},sourceProjection={'installationId':'fixture','revision':6,'checksum':source_checksum,'services':{'bindings':source['networking']['serviceBindings']}},
   **{k:False for k in o.FORBIDDEN})
  self.plan['gateway']['afterRoutes']=copy.deepcopy(self.plan['gateway']['beforeRoutes'])
  self.closure['declaration'].update(entryModule='tools.ingestion_owner_recovery.entry',moduleCount=238)
  for name,value in(('CANDIDATE_HASH',checksum),('ROUTES',o.digest(self.plan['gateway']['beforeRoutes']))):
   p=patch.object(o,name,value);p.start();self.addCleanup(p.stop)
 def issue(self,kind=None):
  selected=o.scope(self.plan);self.review=a.compile_action_review(o.KIND,self.closure,{o.KEY:selected},self.old.hb,self.context,
   {'predecessorHistoryHash':o.DRAFT_HASH,'predecessorIncidentRef':self.plan['logicalRef']},210)
  self.old.c.write(self.context/'review.json',a.encoded(self.review));now=int(time.time())
  decision={'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':a.digest(self.review),'approvalRef':'ingestion-owner-recovery-scoped-'+a.digest(self.review)[:24]+'-'+str(now),
   'sourceClosureHash':self.review['sourceClosureHash'],'humanSessionHash':a.digest(self.old.hb),'approvedAt':now,'expiresAt':now+210,'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
  return a.issue_action(self.review,decision,self.old.human)
 def test_real_two_role_signatures_cannot_authorize_gateway_runtime_or_secret_material(self):
  action=self.issue();self.assertTrue(action.guard(o.KEY,o.scope(self.plan)))
  self.assertEqual(len(list(self.context.glob('*.DEPLOYMENT_INTENT.json'))),1);self.assertEqual(len(list(self.context.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)
  for key in('installationBindingApply','installationProjectionRouteApply','installationRouteReconciliation','installationOwnerUpdate','chatbotFileAuthorization'):
   with self.subTest(key=key),self.assertRaises(Exception):action.guard(key,o.scope(self.plan))
  self.assertEqual([o.scope(self.plan)[k]for k in('maximumOwnerPosts','maximumProjectionExports','maximumGatewayPuts','maximumActiveProjectionWrites')],[3,1,0,0])
 def test_hidden_payload_reference_security_or_budget_flag_drift_denied(self):
  for key in o.FORBIDDEN:
   p=copy.deepcopy(self.plan);p[key]=True
   with self.subTest(flag=key),self.assertRaises(Exception):o.scope(p)
  for kind in('payload','path','source','route','etag'):
   p=copy.deepcopy(self.plan)
   if kind=='payload':p['bindingPlan']['candidatePayload']['hidden']='change'
   if kind=='path':p['draftBinding']['path']='/another/draft-plan.json'
   if kind=='source':p['bindingPlan']['sourcePayload']['hidden']='change'
   if kind=='route':p['gateway']['afterRoutes']['1']={'id':'changed'}
   if kind=='etag':p['bindingPlan']['expectedActiveETag']='"old"'
   with self.subTest(kind=kind),self.assertRaises(Exception):o.scope(p)
 def lifecycle(self,action):
  outer=self
  class Peer:
   def __init__(self):self.posts=0;self.exports=0;self.calls=[];self.active_value={**outer.plan['bindingPlan']['expectedActive'],'etag':outer.plan['bindingPlan']['expectedActiveETag']}
   def active(self):return copy.deepcopy(self.active_value)
   def call(self,method,path,body=None,etag=None):
    self.calls.append((method,path));b=outer.plan['bindingPlan'];new={'installationId':'fixture','revision':7,'checksum':b['candidatePayloadChecksum'],'payload':b['candidatePayload'],'validationState':'VALIDATED','validationFindings':[]}
    if method=='POST':self.posts+=1
    if path=='/revisions':outer.assertEqual(body,b['candidatePayload']);return new,{}
    if path=='/revisions/7:validate-environment':return {'installationId':'fixture','revision':7,'overallStatus':'PASS','validationId':'validated'},{}
    if path=='/revisions/7:activate':
     outer.assertEqual(etag,b['expectedActiveETag']);active={k:new[k]for k in('installationId','revision','checksum')};active['generation']=7
     self.active_value={**active,'etag':'"7:'+active['checksum']+':7"'};return active,{}
    if path=='/projection?revision=7':
     self.exports+=1;projection=copy.deepcopy(outer.plan['sourceProjection']);projection.update(revision=7,checksum=new['checksum'])
     return projection,{'revision':'7','checksum':new['checksum']}
    if path=='/revisions/7':return new,{}
    raise AssertionError('UNAUTHORIZED_OWNER_PATH')
  peer=Peer()
  class P(n.Ports):
   def __init__(self):self.plan=outer.plan;self.context=outer.context;self.action=action;self.http=peer
   def boot(self):return 'fixture-boot'
   def evidence(self,row,stage):return n.Ports.evidence(self,row,stage)
   def guard_current(self,stage,row):
    action.guard(o.KEY,o.scope(self.plan));activated=self.evidence(row,'ACTIVATE_EXPECTED')
    expected=activated['active']if activated else{**self.plan['bindingPlan']['expectedActive'],'etag':self.plan['bindingPlan']['expectedActiveETag']}
    outer.assertEqual(peer.active(),expected)
   def apply(self,stage,row):return n.Ports.apply(self,stage,row)
   def verify(self,stage,row,evidence):
    effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',evidence=evidence);self.guard_current(stage,{**row,'effects':effects})
  return P(),peer
 def test_signed_lifecycle_real_native_methods_three_posts_one_export_and_payload_readback(self):
  action=self.issue();ports,peer=self.lifecycle(action);update=o.FiniteUpdate(action,self.plan,ports,Journal(self.context));update.initialize();row=update.run()
  self.assertEqual(row['incidentState'],'RECOVERED');self.assertEqual(peer.posts,3);self.assertEqual(peer.exports,1)
  self.assertEqual(row['effects'][-1]['evidence']['ownerPayloadReadbackProven'],True)
  projection=json.loads((self.context/'owner-active-projection.json').read_bytes());self.assertEqual(projection['revision'],7)
  self.assertEqual(projection['services'],self.plan['sourceProjection']['services']);self.assertNotIn('ingestionReadOwnerKey',str(projection))
  count=len(peer.calls);update.run();self.assertEqual(len(peer.calls),count)
  with self.assertRaises(Exception):update.initialize()
 def test_ambiguous_owner_mutation_remains_claimed_without_redispatch(self):
  action=self.issue();ports=self.ports();calls=[]
  def lost(stage,row):calls.append(stage);raise ValueError('UNKNOWN')
  ports.apply=lost;update=o.FiniteUpdate(action,self.plan,ports,Journal(self.context));update.initialize()
  with self.assertRaises(Exception):update.run()
  with self.assertRaises(Exception):update.run()
  self.assertEqual(calls,['VERIFY_INPUTS']);self.assertEqual(update.record()['effects'][0]['state'],'CLAIMED')
 def test_native_ports_reject_non_owner_effect_before_any_transport(self):
  ports=object.__new__(n.Ports)
  for stage in('PUBLISH_ACTIVE_PROJECTION','GATEWAY_STATUS_ROUTE','GATEWAY_HISTORY_ROUTE','IMPORT_IMAGE','GENERATE_SECRET','START_REPLACEMENT'):
   with self.subTest(stage=stage),self.assertRaises(Exception):ports.apply(stage,{'effects':[]})
 def test_current_owner_cas_compiler_rejects_stale_generation_or_full_payload(self):
  b=self.plan['bindingPlan'];draft={'owner':{'expectedActiveSnapshot':b['expectedActive'],'candidatePayload':b['candidatePayload'],'candidatePayloadChecksum':b['candidatePayloadChecksum']}}
  inputs={'retainedOwnerPayload':b['sourcePayload']};first={**b['expectedActive'],'etag':b['expectedActiveETag']};revision={**b['expectedActive'],'payload':b['sourcePayload'],'validationState':'VALIDATED','validationFindings':[]}
  for kind in('etag','generation','payload'):
   last=copy.deepcopy(first);r=copy.deepcopy(revision)
   if kind=='etag':last['etag']='"stale"'
   if kind=='generation':last['generation']=8
   if kind=='payload':r['payload']['hidden']='change'
   with self.subTest(kind=kind),self.assertRaises(Exception):e.compile_plan(draft,inputs,{},first,r,last,self.old.human,self.context)
 def test_closed238_loader_rejects_legacy_entry_mode_and_new_external_dependency(self):
  sources={name:b'pass\n'for name in loader.MODULES}
  for name in('entry','authority','owner','native','login','reconcile'):sources['tools.ingestion_owner_recovery.'+name]=(ROOT/'tools/ingestion_owner_recovery'/(name+'.py')).read_bytes()
  self.assertEqual(len(loader.compile_sources(sources)),238)
  sources['tools.ingestion_owner_recovery.entry']=b'import unapproved\n'
  with self.assertRaises(Exception):loader.compile_sources(sources)
  with self.assertRaises(Exception):loader.declaration('a'*40,{name:b'pass\n'for name in loader.MODULES},b'loader',{'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40,'ouf-mcp-server':'c'*40},{'executorSha256':'d'*64,'caseSha256':'e'*64,'mode':'INSTALLATION_BINDING_APPLY'})
def load_tests(loader,tests,pattern):
 return unittest.TestSuite(Signed(name)for name in('test_real_two_role_signatures_cannot_authorize_gateway_runtime_or_secret_material','test_hidden_payload_reference_security_or_budget_flag_drift_denied','test_signed_lifecycle_real_native_methods_three_posts_one_export_and_payload_readback','test_ambiguous_owner_mutation_remains_claimed_without_redispatch','test_native_ports_reject_non_owner_effect_before_any_transport','test_current_owner_cas_compiler_rejects_stale_generation_or_full_payload','test_closed238_loader_rejects_legacy_entry_mode_and_new_external_dependency'))
if __name__=='__main__':unittest.main()
