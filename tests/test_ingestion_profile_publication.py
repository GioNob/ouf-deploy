"""Real dual Ed25519 authority, durable journal and local atomic publisher."""
import copy,hashlib,json,time,unittest
from pathlib import Path
from unittest.mock import patch
import test_installation_binding_apply as old
from tools.ingestion_profile_publication import owner as o,authority as a,native as n,runtime as loader
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.gateway import private_config
class Signed(old.CryptoAndJournal):
 def setUp(self):
  super().setUp();self.old.hb['retryProfile']={'id':'ouf.human.ingestion-owner-recovery288.v7','maximumAttempts':288}
  self.context=self.old.c.root/'ingestion-profile-publication-execution-abcdefgh';self.context.mkdir(mode=0o700)
  target=self.context/'active-projection.json';self.oldbytes=b'{"revision":6}';self.newbytes=b'{"revision":7}'
  self.old.c.write(target,self.oldbytes);self.oldbinding=private_config(str(target))[1]
  exported=self.context/'owner-active-projection.json';self.old.c.write(exported,self.newbytes)
  for name,value in(('OLD_PROJECTION',hashlib.sha256(self.oldbytes).hexdigest()),('EXPORT',hashlib.sha256(self.newbytes).hexdigest())):
   p=patch.object(o,name,value);p.start();self.addCleanup(p.stop)
  self.plan.update(schema='ouf.ingestion-active-projection-plan.v1',kind=o.KIND,authorityDirectory=str(self.context),
   ownerResultBinding={'path':str(self.context/'owner-result.json'),'sha256':o.OWNER_RESULT},projectionHash=o.EXPORT,
   projectionBinding=self.oldbinding,exportedProjectionBinding={'path':str(exported),'sha256':o.EXPORT},
   expectedActive={'installationId':'fixture','revision':7,'generation':7,'checksum':o.OWNER_CHECKSUM},
   maximumExecutionSeconds=120,maximumEffectAttemptsPerStage=1,**{k:False for k in o.FORBIDDEN})
  self.plan['logicalRef']=o.digest({'ownerResultHash':o.OWNER_RESULT,'oldProjectionHash':o.OLD_PROJECTION,'newProjectionHash':o.EXPORT})
  p=patch.object(o,'ROUTES',o.digest(self.plan['gateway']['beforeRoutes']));p.start();self.addCleanup(p.stop)
  self.closure['declaration'].update(entryModule='tools.ingestion_profile_publication.entry',moduleCount=244)
 def issue(self):
  selected=o.scope(self.plan);self.review=a.compile_action_review(o.KIND,self.closure,{o.KEY:selected},self.old.hb,self.context,
   {'predecessorHistoryHash':o.OWNER_RESULT,'predecessorIncidentRef':self.plan['logicalRef']},120)
  self.old.c.write(self.context/'review.json',a.encoded(self.review));now=int(time.time())
  decision={'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':a.digest(self.review),'approvalRef':'ingestion-profile-publication-scoped-'+a.digest(self.review)[:24]+'-'+str(now),
   'sourceClosureHash':self.review['sourceClosureHash'],'humanSessionHash':a.digest(self.old.hb),'approvedAt':now,'expiresAt':now+120,
   'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
  return a.issue_action(self.review,decision,self.old.human)
 def ports(self,action,lost=False):
  outer=self
  class P(n.Ports):
   def __init__(self):self.action,self.plan,self.context=action,outer.plan,outer.context;self.calls=[]
   def boot(self):return 'fixture-boot'
   def guard_current(self,stage,row):
    action.guard(o.KEY,o.scope(self.plan));applied=self.evidence(row,'PUBLISH_ACTIVE_PROJECTION')
    expected=applied['publishedBinding']if applied else self.plan['projectionBinding']
    actual,_=private_config(expected['path'],expected);outer.assertEqual(actual,outer.newbytes if applied else outer.oldbytes)
   def apply(self,stage,row):
    self.calls.append(stage);proof=n.Ports.apply(self,stage,row)
    if lost and stage=='PUBLISH_ACTIVE_PROJECTION':raise ValueError('LOST_AFTER_RENAME')
    return proof
  return P()
 def test_real_dual_roles_allow_only_one_projection_and_no_owner_or_gateway_effect(self):
  action=self.issue();selected=o.scope(self.plan);self.assertTrue(action.guard(o.KEY,selected))
  self.assertEqual([selected[k]for k in('maximumActiveProjectionWrites','maximumOwnerPosts','maximumProjectionExports','maximumGatewayPuts')],[1,0,0,0])
  for key in('ingestionOwnerReference','installationProjectionRouteApply','installationRouteReconciliation','chatbotFileAuthorization'):
   with self.assertRaises(Exception):action.guard(key,selected)
 def test_real_signed_journal_runs_publisher_once_and_retains_old_source(self):
  action=self.issue();ports=self.ports(action);update=o.FiniteUpdate(action,self.plan,ports,Journal(self.context));update.initialize();row=update.run()
  self.assertEqual(row['incidentState'],'RECOVERED');self.assertEqual(row['nextStage'],3)
  self.assertEqual(ports.calls,['VERIFY_INPUTS','PUBLISH_ACTIVE_PROJECTION','VERIFY_FINAL']);self.assertEqual(Path(self.oldbinding['path']).read_bytes(),self.newbytes)
  count=len(ports.calls);update.run();self.assertEqual(len(ports.calls),count)
  with self.assertRaises(Exception):update.initialize()
 def test_lost_result_after_rename_stays_claimed_without_republication(self):
  action=self.issue();ports=self.ports(action,lost=True);update=o.FiniteUpdate(action,self.plan,ports,Journal(self.context));update.initialize()
  with self.assertRaisesRegex(ValueError,'LOST_AFTER_RENAME'):update.run()
  self.assertEqual(update.record()['effects'][-1]['state'],'CLAIMED');self.assertEqual(Path(self.oldbinding['path']).read_bytes(),self.newbytes)
  calls=len(ports.calls)
  with self.assertRaises(Exception):update.run()
  self.assertEqual(len(ports.calls),calls)
 def test_hidden_mutation_budget_or_scope_drift_is_denied(self):
  for name in o.FORBIDDEN:
   changed=copy.deepcopy(self.plan);changed[name]=True
   with self.subTest(flag=name),self.assertRaises(Exception):o.scope(changed)
  selected=o.scope(self.plan);selected['maximumOwnerPosts']=1
  with self.assertRaises(Exception):o.validate_scope(selected)
 def test_scope_window_is_exact120_not_owner210_or_arbitrary_extension(self):
  for seconds in (119,121,210,900):
   with self.assertRaises(Exception):a.compile_action_review(o.KIND,self.closure,{o.KEY:o.scope(self.plan)},self.old.hb,self.context,
    {'predecessorHistoryHash':o.OWNER_RESULT,'predecessorIncidentRef':self.plan['logicalRef']},seconds)
 def test_native_closed_stage_list_rejects_every_non_publication_effect(self):
  ports=object.__new__(n.Ports)
  for stage in('CREATE_REVISION','EXPORT_ACTIVE','GATEWAY_STATUS_ROUTE','IMPORT_IMAGE','GENERATE_SECRET','START_REPLACEMENT'):
   with self.assertRaises(Exception):ports.apply(stage,{'effects':[]})
 def test_closed244_compile_rejects_external_import_and_old_entry_mode(self):
  sources={name:b'pass\n'for name in loader.MODULES};self.assertEqual(len(loader.compile_sources(sources)),244)
  sources['tools.ingestion_profile_publication.entry']=b'import unapproved\n'
  with self.assertRaises(Exception):loader.compile_sources(sources)
def load_tests(loader,tests,pattern):
 names=('test_real_dual_roles_allow_only_one_projection_and_no_owner_or_gateway_effect','test_real_signed_journal_runs_publisher_once_and_retains_old_source',
 'test_lost_result_after_rename_stays_claimed_without_republication','test_hidden_mutation_budget_or_scope_drift_is_denied',
 'test_scope_window_is_exact120_not_owner210_or_arbitrary_extension','test_native_closed_stage_list_rejects_every_non_publication_effect','test_closed244_compile_rejects_external_import_and_old_entry_mode')
 return unittest.TestSuite(Signed(name)for name in names)
if __name__=='__main__':unittest.main()
