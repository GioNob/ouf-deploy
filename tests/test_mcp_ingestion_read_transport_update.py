"""Real signing/private journals; narrow scope and existing native adapter boundary."""
import ast,copy,hashlib,importlib.util,json,os,stat,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
 str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_read_transport_update import owner as o,authority as a,entry as e,native as n
from tools.ingestion_read_transport_update import runtime as loader
from tools.semantic_lease_recovery.recovery_journal import Journal
import test_ingestion_read_administrative_authority as existing_crypto

def fixture(context=Path('/fixture/mcp-ingestion-read-transport-execution-abcdefgh'),human=None):
 routes={str(i):{'id':str(i)}for i in range(80)}
 image='sha256:'+'a'*64
 p={'schema':'ouf.mcp-ingestion-read-transport-update-plan.v1','authorityDirectory':str(context),
  'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':'b'*64},
  'replacements':{'mcp':{'oldRuntimeBinding':{'containerId':o.OLD_MCP},
   'imageAudit':{'imageId':image,'sourceCommit':o.NEW_SOURCE}}},
  'unchangedApplications':{'onboarding':{},'udp':{},'ingestion':{}},
  'gateway':{'beforeRoutes':routes,'afterRoutes':copy.deepcopy(routes),'additions':{}},
  'mcpMigrationsUnchanged':True,'publicMetadataUnchanged':True,'maximumExecutionSeconds':900,
  'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,'databaseMigration':None,
  'humanBinding':human or {'sessionId':'fixture','issuer':'https://fixture.invalid','tenant':'fixture','subject':'human'},
  **{k:False for k in o.FORBIDDEN}}
 p['logicalUpdateRef']=o.digest({'oldContainerId':o.OLD_MCP,'candidateSourceCommit':o.NEW_SOURCE,
  'candidateImageId':image,'profile':o.PROFILE})
 return p

class Scope(unittest.TestCase):
 def test_exact_mcp_only_scope_has_no_database_gateway_policy_metadata_or_job_authority(self):
  scope=o.scope(fixture());self.assertEqual(scope['maximumGatewayWrites'],0)
  self.assertEqual(scope['oldContainerId'],o.OLD_MCP);self.assertEqual(scope['candidateSourceCommit'],o.NEW_SOURCE)
  self.assertTrue(scope['mcpMigrationsUnchanged']);self.assertTrue(all(scope[k]is False for k in o.FORBIDDEN))
 def test_other_service_migration_route_or_budget_changes_are_denied(self):
  for change in ('replacement','route','migration','budget','metadata','image','old'):
   p=fixture()
   if change=='replacement':p['replacements']['onboarding']={}
   if change=='route':p['gateway']['afterRoutes']['extra']={}
   if change=='migration':p['databaseMigration']={'to':35}
   if change=='budget':p['budgetReset']=True
   if change=='metadata':p['publicMetadataChangesAllowed']=True
   if change=='image':p['replacements']['mcp']['imageAudit']['sourceCommit']='f'*40
   if change=='old':p['replacements']['mcp']['oldRuntimeBinding']['containerId']='0'*64
   with self.subTest(change=change),self.assertRaises(Exception):o.scope(p)
 def test_every_forbidden_flag_and_extra_scope_key_fails_closed(self):
  for flag in o.FORBIDDEN:
   p=fixture();p[flag]=True
   with self.subTest(flag=flag),self.assertRaises(Exception):o.scope(p)
  value=o.scope(fixture());value['databaseRestore']={}
  with self.assertRaises(Exception):o.validate_scope(value)
 def test_effect_surface_has_only_the_existing_mcp_operations(self):
  port=n.NativePorts.__new__(n.NativePorts);port.plan=fixture();port.request=Mock(return_value=(204,None))
  for stage in ('BACKUP_ONBOARDING','VERIFY_MIGRATION','GATEWAY_READ_ROUTE','onboarding.STOP_OLD','mcp.DELETE'):
   with self.assertRaises(Exception):port.apply(stage)
  port.request.assert_not_called();port.apply('mcp.STOP_OLD')
  port.request.assert_called_once_with('POST','/v1.44/containers/'+o.OLD_MCP+'/stop?t=10')
 def test_closed_loader_has185_modules_and_requires_new_scope_mode_and_three_source_pins(self):
  sources={name:b'pass\n'for name in loader.MODULES}
  for name in ('entry','owner','native','authority'):
   sources['tools.ingestion_read_transport_update.'+name]=(ROOT/'tools/ingestion_read_transport_update'/(name+'.py')).read_bytes()
  raw=(ROOT/'tools/ingestion_read_transport_update/runtime.py').read_bytes()
  pins={'ouf-deploy':'a'*40,'ouf-onboarding':'b'*40,'ouf-mcp-server':o.NEW_SOURCE}
  execution={'executorSha256':'c'*64,'caseSha256':'d'*64,'mode':'MCP_READ_TRANSPORT_UPDATE'}
  d=loader.declaration('a'*40,sources,raw,pins,execution)
  self.assertEqual(d['moduleCount'],185);self.assertEqual(d['entryModule'],'tools.ingestion_read_transport_update.entry')
  with self.assertRaises(Exception):loader.declaration('a'*40,sources,raw,pins,{**execution,'mode':'INGESTION_READ_AUTHORIZATION'})
 def test_entry_and_preparer_do_not_reach_old_main_login_iam_or_database(self):
  for path in (ROOT/'tools/ingestion_read_transport_update/entry.py',ROOT/'scripts/prepare-mcp-ingestion-read-transport.py'):
   calls=[ast.unparse(node.func)for node in ast.walk(ast.parse(path.read_bytes()))if isinstance(node,ast.Call)]
   self.assertFalse(any(v.endswith(('.authenticate','.login','.ensure','.backup','.migrate'))for v in calls))
   self.assertNotIn('reader.main',calls);self.assertNotIn('entry.main',calls)

class CryptoAndJournal(unittest.TestCase):
 @classmethod
 def setUpClass(cls):existing_crypto.Issuance.setUpClass()
 def setUp(self):
  self.previous=existing_crypto.Issuance();self.previous.setUp();self.addCleanup(self.previous.doCleanups)
  prior=self.previous;self.c=prior.c;self.human=prior.human;self.hb=prior.hb
  self.context=self.c.root/'mcp-ingestion-read-transport-execution-abcdefgh';self.context.mkdir(mode=0o700)
  self.plan=fixture(self.context,self.hb)
  self.closure=copy.deepcopy(prior.closure);self.closure['declaration']['entryModule']='tools.ingestion_read_transport_update.entry'
  self.scopes={'mcpReadTransportUpdate':o.scope(self.plan)}
  self.review=a.compile_action_review('MCP_READ_TRANSPORT_UPDATE',self.closure,self.scopes,self.hb,self.context,
   {'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':self.plan['logicalUpdateRef']},480)
  self.c.write(self.context/'review.json',a.encoded(self.review))
 def decision(self):
  now=int(time.time());return {'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':a.digest(self.review),
   'approvalRef':'mcp-scoped-'+a.digest(self.review)[:24]+'-'+str(now),'sourceClosureHash':self.review['sourceClosureHash'],
   'humanSessionHash':a.digest(self.hb),'approvedAt':now,'expiresAt':now+480,
   'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
 def test_actual_two_installer_role_signatures_and_one_use_issuance(self):
  action=a.issue_action(self.review,self.decision(),self.human)
  self.assertTrue(action.guard('mcpReadTransportUpdate',self.scopes['mcpReadTransportUpdate']))
  self.assertEqual(len(list(self.context.glob('*.DEPLOYMENT_INTENT.json'))),1)
  self.assertEqual(len(list(self.context.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)
  self.assertFalse((self.c.root/'UNREAD-ATTESTOR.pem').exists())
  with self.assertRaises(Exception):a.issue_action(self.review,self.decision(),self.human)
 def test_wrong_actor_review_scope_or_login_gate_cannot_issue(self):
  with patch.object(a.ExistingEd25519Signer,'sign')as signing:
   bad=self.decision();bad['reviewHash']='0'*64
   with self.assertRaises(Exception):a.issue_action(self.review,bad,self.human)
   with patch.object(self.human,'current',return_value={**self.hb,'subject':'other'}):
    with self.assertRaises(Exception):a.issue_action(self.review,self.decision(),self.human)
   with self.assertRaises(Exception):a.terminal_consent(self.review,'No login allowed',login=True)
  signing.assert_not_called()
  with self.assertRaises(Exception):a.compile_action_review('MCP_READ_TRANSPORT_UPDATE',self.closure,
   {**self.scopes,'chatbotFileAuthorization':{}},self.hb,self.context,
   {'predecessorHistoryHash':'b'*64,'predecessorIncidentRef':'c'*64},480)
 def test_real_durable_journal_complete_sequence_has_no_migration_or_replay(self):
  action=a.issue_action(self.review,self.decision(),self.human);plan=self.plan
  class FixturePorts(n.NativePorts):
   def __init__(self):self.action=action;self.plan=copy.deepcopy(plan);self.dispatched=[]
   def guard_current(self,stage):self.action.guard('mcpReadTransportUpdate',o.scope(self.plan))
   def apply(self,stage):self.dispatched.append(stage)
   def observe(self,stage):return 'APPLIED',{'fixtureStage':stage}
  ports=FixturePorts();update=o.ReadinessUpdate(action,Journal(self.context),plan,ports)
  update.initialize();result=update.run();self.assertTrue(result['complete'])
  self.assertEqual(result['databaseMigrationsPerformed'],0);self.assertEqual(result['gatewayWrites'],0)
  self.assertEqual([v['stage']for v in update.record()['effects']],list(o.STAGES))
  count=len(ports.dispatched);update.run();self.assertEqual(len(ports.dispatched),count)
  self.assertTrue(list(self.context.parent.glob('mcp-ingestion-read-transport-*.claim.json')))
 def test_ambiguous_effect_stays_claimed_and_second_run_does_not_dispatch(self):
  action=a.issue_action(self.review,self.decision(),self.human);plan=self.plan
  class FixturePorts(n.NativePorts):
   def __init__(self):self.action=action;self.plan=copy.deepcopy(plan);self.dispatched=0
   def guard_current(self,stage):self.action.guard('mcpReadTransportUpdate',o.scope(self.plan))
   def apply(self,stage):self.dispatched+=1;raise RuntimeError('UNKNOWN_EFFECT')
   def observe(self,stage):return 'UNKNOWN',{}
  ports=FixturePorts();update=o.ReadinessUpdate(action,Journal(self.context),plan,ports);update.initialize()
  with self.assertRaises(Exception):update.run()
  with self.assertRaises(o.UpdatePaused):update.run()
  self.assertEqual(ports.dispatched,1);self.assertEqual(update.record()['effects'][0]['state'],'CLAIMED')
 def test_actual_private_document_writer_accepts_all_new_owner_document_schemas(self):
  (self.context/'review.json').unlink()
  for name,schema in (('candidate-review.json','ouf.mcp-read-transport-private-selection.v1'),
   ('execution-plan.json','ouf.mcp-ingestion-read-transport-update-plan.v1'),
   ('review.json','ouf.semantic-scoped-infrastructure-review.v1'),
   ('update-result.json','ouf.mcp-ingestion-read-transport-update-result.v1')):
   value={'schema':schema};e.publish_json(self.context,name,value)
   self.assertEqual((self.context/name).read_bytes(),e.encoded(value))
   self.assertEqual(stat.S_IMODE((self.context/name).stat().st_mode),0o600)
   with self.assertRaises(Exception):e.publish_json(self.context,name,value)

if __name__=='__main__':unittest.main()
