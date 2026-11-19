"""Real existing dual-role cryptography; fixture native ports, no target effects."""
import copy,hashlib,importlib.util,json,os,sys,threading,time,unittest,tempfile
from unittest.mock import patch
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as crypto
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.source_revision_update.owner import ReadinessUpdate,UpdateDenied,UpdatePaused,STAGES,digest,scope,MIGRATION
from tools.source_revision_update.native import NativePorts

class FixturePorts(NativePorts):
 def __init__(self,action,plan):
  self.action,self.plan=action,copy.deepcopy(plan);self.calls=[];self.native=set();self.fail_after=None
  self.transient=0;self.reads=0;self.block=None;self.release=None;self.fence=False
 def boot(self):return 'fixture-boot'
 def claim_logical_scope(self):
  if self.fence:raise FileExistsError('fixture-global-fence-consumed')
  self.fence=True
 def guard_current(self,stage):pass
 def apply(self,stage):
  self.calls.append(stage);self.native.add(stage)
  if self.block==stage:self.release.wait(timeout=3)
  if self.fail_after==stage:raise OSError('fixture-response-lost')
 def observe(self,stage):
  if stage.endswith('.READINESS')or stage=='VERIFY_FINAL':
   self.reads+=1
   if self.transient>0:self.transient-=1;return 'TRANSIENT',{'retryAfterSeconds':0}
  return 'APPLIED',{'fixtureStage':stage,'proof':digest({'stage':stage})}

def gateway_fixture():
 additions={}
 for mode in ('prepare','read'):
  additions[mode]={'id':'mcp-source-revision-'+mode,'uri':'/internal/capabilities/v1/execute/source.revision/'+mode,
   'methods':['POST'],'plugins':{'proxy-rewrite':{'uri':'/api/internal/v1/onboarding/source-revision-mcp/'+mode}},
   'upstream':{'retries':0}}
 return {'beforeRoutes':{},'afterRoutes':{r['id']:r for r in additions.values()},'additions':additions}

class Owner(unittest.TestCase):
 def setUp(self):
  self.crypto=crypto.SignedCutover()
  base=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(base.cleanup)
  with patch.object(crypto,'ROOT',Path(base.name)):self.crypto.setUp()
  self.addCleanup(self.crypto.doCleanups)
  c=self.crypto;directory=c.root/'update';directory.mkdir(mode=0o700)
  self.plan={'schema':'ouf.source-revision-native-update-plan.v1','authorityDirectory':str(directory),
   'privateReviewBinding':{'path':str(directory/'private.json'),'sha256':'a'*64},
   'replacements':{'onboarding':{'oldRuntimeBinding':{'containerId':'1'*64}},'mcp':{'oldRuntimeBinding':{'containerId':'2'*64}}},
   'unchangedApplications':{'udp':{'containerId':'3'*64},'ingestion':{'containerId':'4'*64}},'mcpMigrationsUnchanged':True,
   'gateway':gateway_fixture(),'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':2,
   'databaseMigration':MIGRATION,'backupRequiredBeforeMigration':True,
   **{k:False for k in('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed')}}
  self.plan['logicalUpdateRef']=digest({'retiredContainerIds':['1'*64,'2'*64],'migration':MIGRATION})
  c.authority=crypto.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in c.expected.items()if k!='intakeHash'},
   'issuedAt':c.now,'expiresAt':c.now+480,'sourceRevisionUpdate':scope(self.plan)})
  c.approval['expiresAt']=c.now+500;c.approval['executionAuthorityHash']=crypto.sha(c.authority);c.write(c.mandate,crypto.encoded(c.approval));c.approved=crypto.sha(c.mandate.read_bytes())
  for role in c.grant['roles']:c.sign(role)
  self.action=AggregateAction(c.gate(),c.authority,c.expected['sourceClosureHash'])
  self.journal=Journal(directory);self.ports=FixturePorts(self.action,self.plan);self.mono=500
  self.owner=ReadinessUpdate(self.action,self.journal,self.plan,self.ports,lambda:(c.now,self.mono));self.owner.initialize()
 def advance(self,seconds):self.crypto.now+=seconds;self.mono+=seconds
 def test_all_ordered_stages_and_completed_run_never_repeat_effects(self):
  result=self.owner.run();self.assertTrue(result['applicationReady']);self.assertFalse(result['acceptanceGranted'])
  self.assertEqual(self.ports.calls,[s for s in STAGES if not s.endswith('.READINESS')and s!='VERIFY_FINAL']);before=list(self.ports.calls)
  self.owner.run();self.assertEqual(before,self.ports.calls)
  self.assertEqual(self.owner.record()['incidentState'],'RECOVERED')
 def test_lost_mutation_response_consumes_claim_and_requires_readback(self):
  self.ports.fail_after='onboarding.STOP_OLD'
  with self.assertRaises(OSError):self.owner.run()
  before=list(self.ports.calls)
  with self.assertRaises(UpdatePaused):self.owner.run()
  self.assertEqual(before,self.ports.calls)
  self.ports.fail_after=None;self.owner.reconcile_claim();self.owner.run()
  self.assertEqual(self.ports.calls.count('onboarding.STOP_OLD'),1)
 def test_lost_second_application_stop_does_not_repeat_completed_first_application(self):
  self.ports.fail_after='mcp.STOP_OLD'
  with self.assertRaises(OSError):self.owner.run()
  before=list(self.ports.calls)
  self.assertNotIn('onboarding.START_REPLACEMENT',before)
  with self.assertRaises(UpdatePaused):self.owner.run()
  self.assertEqual(before,self.ports.calls)
  self.ports.fail_after=None;self.owner.reconcile_claim();self.owner.run()
  self.assertEqual(self.ports.calls.count('onboarding.STOP_OLD'),1)
  self.assertEqual(self.ports.calls.count('mcp.STOP_OLD'),1)
 def test_lost_backup_response_blocks_start_without_a_second_backup(self):
  self.ports.fail_after='BACKUP_ONBOARDING'
  with self.assertRaises(OSError):self.owner.run()
  before=list(self.ports.calls)
  with self.assertRaises(UpdatePaused):self.owner.run()
  self.assertEqual(before,self.ports.calls)
  self.ports.fail_after=None;self.owner.reconcile_claim();self.owner.run()
  self.assertEqual(self.ports.calls.count('BACKUP_ONBOARDING'),1)
  self.assertEqual(self.ports.calls.count('onboarding.STOP_OLD'),1)
 def test_transient_readiness_preserves_budget_and_backoff(self):
  self.ports.transient=1
  with self.assertRaises(UpdatePaused):self.owner.run()
  row=self.owner.record();self.assertEqual(row['readinessAttempts'],1);calls=list(self.ports.calls)
  with self.assertRaises(UpdatePaused):self.owner.run()
  self.assertEqual(self.owner.record()['readinessAttempts'],1);self.assertEqual(calls,self.ports.calls)
  self.advance(7);self.owner.run();self.assertEqual(self.ports.reads,4)
 def test_hours_outage_or_revocation_never_reopens_authority(self):
  self.ports.transient=3
  with self.assertRaises(UpdatePaused):self.owner.run()
  before=list(self.ports.calls);self.advance(10800)
  with self.assertRaises(Exception):self.owner.run()
  self.assertEqual(before,self.ports.calls);self.assertEqual(self.owner.record()['readinessAttempts'],1)
 def test_current_human_revocation_blocks_before_next_effect(self):
  c=self.crypto;c.approval['state']='REVOKED';c.write(c.mandate,crypto.encoded(c.approval))
  with self.assertRaises(Exception):self.owner.run()
  self.assertEqual(self.ports.calls,[])
 def test_double_invocation_cannot_dispatch_concurrently(self):
  released=threading.Event();self.ports.block='VERIFY_INPUTS';self.ports.release=released;errors=[]
  def run():
   try:self.owner.run()
   except Exception as e:errors.append(e)
  worker=threading.Thread(target=run);worker.start()
  limit=time.monotonic()+2
  while not self.ports.calls and time.monotonic()<limit:time.sleep(.005)
  with self.assertRaises(BlockingIOError):self.owner.run()
  released.set();worker.join(timeout=5);self.assertFalse(worker.is_alive());self.assertEqual(errors,[])
  self.assertEqual(self.ports.calls.count('VERIFY_INPUTS'),1)
 def test_plan_drift_and_new_directory_do_not_reset_consumed_scope(self):
  self.owner.plan['maximumExecutionSeconds']=901
  with self.assertRaises(UpdateDenied):self.owner.run()
  self.assertEqual(self.ports.calls,[])
  with self.assertRaises(FileExistsError):self.ports.claim_logical_scope()
 def test_short_remaining_authority_cannot_start_long_import(self):
  self.ports.fail_after='VERIFY_INPUTS'
  with self.assertRaises(OSError):self.owner.run()
  self.ports.fail_after=None;self.owner.reconcile_claim();self.advance(300)
  with self.assertRaisesRegex(UpdatePaused,'INSUFFICIENT_AUTHORITY_WINDOW'):self.owner.run()
  self.assertNotIn('onboarding.IMPORT_IMAGE',self.ports.calls)
 def test_corrupt_role_signature_cannot_authorize_any_native_effect(self):
  path=self.crypto.signatures/(crypto.sha(self.crypto.authority)+'.FINAL_DEPLOYMENT_APPROVAL.json')
  path.unlink()
  with self.assertRaises(Exception):self.owner.run()
  self.assertEqual(self.ports.calls,[])
 def test_backup_and_migration_are_ordered_before_dependent_start(self):
  self.owner.run();calls=self.ports.calls
  self.assertLess(calls.index('mcp.STOP_OLD'),calls.index('BACKUP_ONBOARDING'))
  self.assertLess(calls.index('BACKUP_ONBOARDING'),calls.index('onboarding.START_REPLACEMENT'))
  self.assertLess(calls.index('VERIFY_MIGRATION'),calls.index('mcp.START_REPLACEMENT'))
 def test_different_migration_or_domain_authority_is_rejected(self):
  for field,value in [('databaseMigration',{**MIGRATION,'to':37}),('jobRetriesAllowed',True),('profilePublicationAllowed',True),('maximumGatewayWrites',1),('backupRequiredBeforeMigration',False),('mcpMigrationsUnchanged',False),('unchangedApplications',{})]:
   with self.subTest(field=field):
    changed=copy.deepcopy(self.plan);changed[field]=value
    with self.assertRaises(UpdateDenied):scope(changed)
 def test_readiness_cumulative_budget_is_not_reset_after_success(self):
  self.owner.run()
  row=self.owner.record()
  self.assertEqual(row['cumulativeReadinessAttempts'],3)
  self.assertEqual(row['readinessAttempts'],0)
 def test_stages_never_include_mcp_migration_or_onboarding_mutation(self):
  self.assertEqual(MIGRATION['from'],33)
  self.assertEqual(MIGRATION['to'],34)
  self.assertFalse(any('udp.' in stage or 'MIGRATOR' in stage for stage in STAGES))
 def test_lost_gateway_write_is_read_back_without_a_second_put(self):
  for stage in ('GATEWAY_PREPARE_ROUTE','GATEWAY_READ_ROUTE'):
   self.ports.fail_after=stage
   with self.assertRaises(OSError):self.owner.run()
   before=list(self.ports.calls)
   with self.assertRaises(UpdatePaused):self.owner.run()
   self.assertEqual(before,self.ports.calls)
   self.ports.fail_after=None;self.owner.reconcile_claim()
  self.owner.run()
  self.assertEqual(self.ports.calls.count('GATEWAY_PREPARE_ROUTE'),1)
  self.assertEqual(self.ports.calls.count('GATEWAY_READ_ROUTE'),1)
 def test_existing_route_overwrite_and_unrelated_addition_are_rejected(self):
  for change in ('before','foreign','owner'):
   value=copy.deepcopy(self.plan);gateway=value['gateway']
   if change=='before':gateway['beforeRoutes']['mcp-source-revision-read']={'uri':'/retained'}
   if change=='foreign':gateway['afterRoutes']['foreign']={'uri':'/foreign'}
   if change=='owner':gateway['additions']['prepare']['plugins']['proxy-rewrite']['uri']='/wrong'
   with self.subTest(change=change),self.assertRaises(UpdateDenied):scope(value)
if __name__=='__main__':unittest.main()
