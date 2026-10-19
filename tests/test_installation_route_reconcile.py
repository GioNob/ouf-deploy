import ast,copy,hashlib,json,time,types,unittest
from pathlib import Path
from unittest.mock import patch
import test_installation_binding_apply as old
from tools.installation_route_reconcile import owner as o,authority as a,native as n,runtime as loader
from tools.semantic_lease_recovery.recovery_journal import Journal
ROOT=Path(__file__).resolve().parents[1]
class Signed(old.CryptoAndJournal):
 def setUp(self):
  super().setUp();self.plan['kind']='INSTALLATION_ROUTE_RECONCILIATION'
  self.closure['declaration']['entryModule']='tools.installation_route_reconcile.entry';self.closure['declaration']['moduleCount']=226
  p=patch.object(o,'CANDIDATE_HASH',old.prior.p.canonical_owner(self.plan['bindingPlan']['candidatePayload']));p.start();self.addCleanup(p.stop)
 def issue(self):
  scope=o.scope(self.plan);self.review=a.compile_action_review(self.plan['kind'],self.closure,{'installationRouteReconciliation':scope},self.old.hb,self.context,
   {'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':self.plan['logicalRef']},210)
  self.old.c.write(self.context/'review.json',a.encoded(self.review));now=int(time.time())
  decision={'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':a.digest(self.review),'approvalRef':'installation-binding-scoped-'+a.digest(self.review)[:24]+'-'+str(now),
   'sourceClosureHash':self.review['sourceClosureHash'],'humanSessionHash':a.digest(self.old.hb),'approvedAt':now,'expiresAt':now+210,'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
  return a.issue_action(self.review,decision,self.old.human)
 def test_new_scope_has_only_two_gateway_puts_and_two_journal_transitions(self):
  scope=o.scope(self.plan);self.assertEqual([scope[k]for k in('maximumOwnerPosts','maximumProjectionExports','maximumActiveProjectionWrites','maximumGatewayPuts','maximumPredecessorJournalTransitions')],[0,0,0,2,2])
  action=self.issue();self.assertTrue(action.guard('installationRouteReconciliation',scope))
  with self.assertRaises(Exception):action.guard('installationProjectionRouteApply',scope)
  for kind in('INSTALLATION_BINDING_APPLY','INSTALLATION_PROJECTION_ROUTE_APPLY'):
   changed=copy.deepcopy(self.plan);changed['kind']=kind
   with self.assertRaises(Exception):o.scope(changed)
 def fixture_prior(self):
  self.prior_context=self.old.c.root/'installation-binding-apply-execution-predecessor';self.prior_context.mkdir(mode=0o700)
  raw=b'{"authoritative":true}';profile=self.old.c.root/'active-projection.json';profile.write_bytes(raw);profile.chmod(0o600)
  _,binding=n.private_config(profile);self.plan['projectionBinding']=binding;self.plan['projectionHash']=o.digest({'authoritative':True})
  self.plan['predecessorPlanHash']='d'*64;self.plan['reconciliationSourceClosureHash']=a.digest(self.closure)
  effects=[{'stage':stage,'state':state,'intentHash':o.digest({'planHash':self.plan['predecessorPlanHash'],'stage':stage})}for stage,state in[('VERIFY_INPUTS','APPLIED'),('PUBLISH_ACTIVE_PROJECTION','CLAIMED')]]
  now=time.time();self.prior_row={'schema':'ouf.installation-binding-native-journal.v1','version':3,'nextStage':1,'effects':effects,'incidentState':'OPEN','expiresAt':now-100,
   'lastWall':now-120,'lastMonotonic':time.monotonic()-120,'scopeHash':'f'*64,'authorityHash':'e'*64,'budgetReset':False}
  self.prior=Journal(self.prior_context);self.prior.initialize(self.prior_row)
  self.plan['predecessorJournalBinding']={'path':str(self.prior_context/'recovery.json'),'sha256':o.digest(self.prior_row)}
 def ports(self,action):
  outer=self
  class Gateway:
   def request(self,method,path,body):
    outer.assertEqual(method,'PUT');outer.puts.append(body['id']);return 200,{}
  class Ports:
   def __init__(self):self.action=action;self.plan=outer.plan;self.context=outer.context;self.gateway=Gateway()
   def boot(self):return 'fixture-boot'
   def guard_current(self,stage,row):
    self.action.guard('installationRouteReconciliation',o.scope(self.plan));n.verify_predecessor(self.plan,row)
    n.approved_projection_bytes(self.plan['projectionBinding']['path'],self.plan['projectionHash'])
   def apply(self,stage,row):return n.Ports.apply(self,stage,row)
   def evidence(self,row,stage):return n.Ports.evidence(self,row,stage)
   def verify(self,stage,row,evidence):
    effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',evidence=evidence);self.guard_current(stage,{**row,'effects':effects})
  self.puts=[];return Ports()
 def test_real_signed_pipeline_reconciles_no_rename_two_puts_and_preserves_expired_authority(self):
  self.fixture_prior();action=self.issue();ports=self.ports(action);update=o.FiniteUpdate(action,self.plan,ports,Journal(self.context));update.initialize();row=update.run()
  self.assertEqual(self.puts,['mcp-ingestion-status','mcp-ingestion-history']);self.assertEqual(row['incidentState'],'RECOVERED')
  prior=self.prior.read();self.assertEqual(prior['version'],5);self.assertEqual(prior['nextStage'],5);self.assertEqual(prior['incidentState'],'RECOVERED')
  self.assertEqual(prior['expiresAt'],self.prior_row['expiresAt']);self.assertEqual(len(prior['effects']),5);self.assertTrue(all(e['state']=='APPLIED'for e in prior['effects']))
  self.assertEqual(prior['effects'][-1]['evidence']['reconciliation']['authorityHash'],action.authority_hash)
  update.run();self.assertEqual(len(self.puts),2)
  with self.assertRaises(Exception):update.initialize()
 def test_changed_predecessor_is_denied_before_any_put(self):
  self.fixture_prior();action=self.issue();ports=self.ports(action);update=o.FiniteUpdate(action,self.plan,ports,Journal(self.context));update.initialize()
  current=self.prior.read();following={**current,'version':99};self.prior.compare_and_save(current,following)
  with self.assertRaises(Exception):update.run()
  self.assertEqual(self.puts,[])
 def test_ambiguous_successor_effect_stays_claimed_without_redispatch(self):
  self.fixture_prior();action=self.issue();ports=self.ports(action);update=o.FiniteUpdate(action,self.plan,ports,Journal(self.context));update.initialize()
  count=[]
  def lost(stage,row):count.append(stage);raise ValueError('UNPROVEN')
  ports.apply=lost
  with self.assertRaises(Exception):update.run()
  with self.assertRaises(Exception):update.run()
  self.assertEqual(count,['VERIFY_INPUTS']);self.assertEqual(update.record()['effects'][0]['state'],'CLAIMED')
 def test_readonly_owner_http_rejects_post_and_export_before_credentials(self):
  client=object.__new__(n.OwnerHttp);client.calls=client.posts=client.exports=0;client.read_only=True;client.deadline=time.monotonic()+30
  for method,path in[('POST','/revisions'),('GET','/projection?revision=6')]:
   with self.assertRaises(Exception):client.call(method,path)
  self.assertEqual((client.calls,client.posts,client.exports),(0,0,0))
 def test_closed226_loader_has_new_entry_and_no_legacy_runtime_mode(self):
  sources={name:b'pass\n'for name in loader.MODULES}
  for name in('entry','authority','owner','native','baseline','login','reconcile'):sources['tools.installation_route_reconcile.'+name]=(ROOT/'tools/installation_route_reconcile'/(name+'.py')).read_bytes()
  self.assertEqual(len(loader.compile_sources(sources)),226)
  with self.assertRaises(Exception):loader.declaration('a'*40,sources,b'loader',{'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40,'ouf-mcp-server':'c'*40},{'executorSha256':'d'*64,'caseSha256':'e'*64,'mode':'INSTALLATION_BINDING_APPLY'})
 def test_original_privileged_surfaces_are_not_stages_in_new_scope(self):
  self.assertFalse(any(x in o.STAGES['INSTALLATION_ROUTE_RECONCILIATION']for x in('CREATE_REVISION','ACTIVATE_EXPECTED','EXPORT_ACTIVE','PUBLISH_ACTIVE_PROJECTION')))
def load_tests(loader,tests,pattern):
 return unittest.TestSuite(Signed(name)for name in('test_new_scope_has_only_two_gateway_puts_and_two_journal_transitions','test_real_signed_pipeline_reconciles_no_rename_two_puts_and_preserves_expired_authority','test_changed_predecessor_is_denied_before_any_put','test_ambiguous_successor_effect_stays_claimed_without_redispatch','test_readonly_owner_http_rejects_post_and_export_before_credentials','test_closed226_loader_has_new_entry_and_no_legacy_runtime_mode','test_original_privileged_surfaces_are_not_stages_in_new_scope'))
if __name__=='__main__':unittest.main()
