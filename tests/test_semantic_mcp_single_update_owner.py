"""Real existing dual-role cryptography; fixture native ports, no target effects."""
import copy,hashlib,importlib.util,json,os,sys,threading,time,unittest,tempfile
from unittest.mock import patch
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as crypto
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_mcp_update.owner import SingleMcpUpdate,UpdateDenied,UpdatePaused,STAGES,digest,scope
from tools.semantic_mcp_update.native import NativePorts

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
  if stage=='READINESS':
   self.reads+=1
   if self.transient>0:self.transient-=1;return 'TRANSIENT',{'retryAfterSeconds':0}
  return 'APPLIED',{'fixtureStage':stage,'proof':digest({'stage':stage})}

class Owner(unittest.TestCase):
 def setUp(self):
  self.crypto=crypto.SignedCutover()
  base=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(base.cleanup)
  with patch.object(crypto,'ROOT',Path(base.name)):self.crypto.setUp()
  self.addCleanup(self.crypto.doCleanups)
  c=self.crypto;directory=c.root/'update';directory.mkdir(mode=0o700)
  self.plan={'schema':'ouf.mcp-single-update-execution-plan.v1','authorityDirectory':str(directory),
   'predecessorReviewHash':'a'*64,'migration':{'command':'migrate-semantic-reprocessing','committedMembershipAllowed':False},
   'oldRuntimeBinding':{'containerId':'1'*64},'database':{'oid':42},'retainedClaim':{'attemptId':'fixture-previous'},
   'maximumExecutionSeconds':900,'automaticRollbackAllowed':False,'databaseRestoreAllowed':False,'semanticDispatchAllowed':False}
  self.plan['logicalUpdateRef']=digest({'oldContainerId':'1'*64,'databaseOid':42,'predecessorAttemptId':'fixture-previous'})
  c.authority=crypto.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in c.expected.items()if k!='intakeHash'},
   'issuedAt':c.now,'expiresAt':c.now+120,'mcpSingleUpdate':scope(self.plan)})
  c.approval['executionAuthorityHash']=crypto.sha(c.authority);c.write(c.mandate,crypto.encoded(c.approval));c.approved=crypto.sha(c.mandate.read_bytes())
  for role in c.grant['roles']:c.sign(role)
  self.action=AggregateAction(c.gate(),c.authority,c.expected['sourceClosureHash'])
  self.journal=Journal(directory);self.ports=FixturePorts(self.action,self.plan);self.mono=500
  self.owner=SingleMcpUpdate(self.action,self.journal,self.plan,self.ports,lambda:(c.now,self.mono));self.owner.initialize()
 def advance(self,seconds):self.crypto.now+=seconds;self.mono+=seconds
 def test_all_ordered_stages_and_completed_run_never_repeat_effects(self):
  result=self.owner.run();self.assertTrue(result['applicationReady']);self.assertFalse(result['acceptanceGranted'])
  self.assertEqual(self.ports.calls,[s for s in STAGES if s!='READINESS']);before=list(self.ports.calls)
  self.owner.run();self.assertEqual(before,self.ports.calls)
  self.assertEqual(self.owner.record()['incidentState'],'RECOVERED')
 def test_lost_mutation_response_consumes_claim_and_requires_readback(self):
  self.ports.fail_after='STOP_OLD'
  with self.assertRaises(OSError):self.owner.run()
  before=list(self.ports.calls)
  with self.assertRaises(UpdatePaused):self.owner.run()
  self.assertEqual(before,self.ports.calls)
  self.ports.fail_after=None;self.owner.reconcile_claim();self.owner.run()
  self.assertEqual(self.ports.calls.count('STOP_OLD'),1)
 def test_transient_readiness_preserves_budget_and_backoff(self):
  self.ports.transient=1
  with self.assertRaises(UpdatePaused):self.owner.run()
  row=self.owner.record();self.assertEqual(row['readinessAttempts'],1);calls=list(self.ports.calls)
  with self.assertRaises(UpdatePaused):self.owner.run()
  self.assertEqual(self.owner.record()['readinessAttempts'],1);self.assertEqual(calls,self.ports.calls)
  self.advance(7);self.owner.run();self.assertEqual(self.ports.reads,2)
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
 def test_corrupt_role_signature_cannot_authorize_any_native_effect(self):
  path=self.crypto.signatures/(crypto.sha(self.crypto.authority)+'.FINAL_DEPLOYMENT_APPROVAL.json')
  path.unlink()
  with self.assertRaises(Exception):self.owner.run()
  self.assertEqual(self.ports.calls,[])
class NativeBackupReadback(unittest.TestCase):
 def test_partial_custom_archive_without_success_marker_cannot_be_accepted(self):
  base=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(base.cleanup)
  path=Path(base.name)/'partial.dump';path.write_bytes(b'PGDMPpartial-custom-archive');path.chmod(0o600)
  ports=NativePorts.__new__(NativePorts)
  ports.plan={'oldRuntimeBinding':{'containerId':'1'*64},'database':{'backupPath':str(path),'maximumBackupBytes':1048576}}
  ports.inspect=lambda kind,reference:{'Id':reference}
  with self.assertRaises(FileNotFoundError):ports.observe('BACKUP_DATABASE')
 def test_backup_marker_cannot_accept_different_archive_bytes(self):
  base=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(base.cleanup)
  path=Path(base.name)/'partial.dump';path.write_bytes(b'PGDMPpartial-custom-archive');path.chmod(0o600)
  marker=path.with_name(path.name+'.complete.json');marker.write_text(json.dumps({'customFormatHeader':True,'bytes':path.stat().st_size,'sha256':'0'*64}));marker.chmod(0o600)
  ports=NativePorts.__new__(NativePorts)
  ports.plan={'oldRuntimeBinding':{'containerId':'1'*64},'database':{'backupPath':str(path),'maximumBackupBytes':1048576}}
  ports.inspect=lambda kind,reference:{'Id':reference}
  with self.assertRaises(UpdateDenied):ports.observe('BACKUP_DATABASE')
if __name__=='__main__':unittest.main()
