"""Real signed owner, persistent read-only retries, cancellation and crash bounds."""
import copy,json,unittest
from pathlib import Path
from unittest.mock import patch
import test_chatbot_cohort_authorization as f
from tools.chatbot_file_cohort.authorization import AuthorizationDelta,AuthorizationPaused,OBSERVATION_POLICY,authorization_scope,OwnerTransport

class FiniteObservation(unittest.TestCase):
    def fixture(self,retained=False):
        h=f.ComposedAuthorizationTest();h.setUp();self.addCleanup(h.doCleanups)
        # Existing suite separately qualifies the Java JSON roundtrip. Here the
        # owner fixture starts published so only observational retry is tested.
        with patch.object(f,'owner_constraint_roundtrip',side_effect=copy.deepcopy):
            h.prepare();h.owner.human_confirms();h.delta.apply()
        plan=copy.deepcopy(h.plan);plan['observationPolicy']=copy.deepcopy(OBSERVATION_POLICY)
        receipt=h.delta.verify()
        if retained:
            plan['retainedRoleObservation']={'profile':'ouf.authorization-retained-role-observation.v1',
                'ownerReceiptHash':f.digest(receipt),'policyRef':receipt['policyRef'],'policyHash':receipt['policyHash'],
                'roleCatalogueHash':receipt['roleCatalogueHash'],'allowedStage':'AFTER_GATEWAY',
                'forceFreshMcpBeforeRelease':True,'ownerPublicationContract':'LOCKED_ATOMIC_ROLE_AND_POLICY_PUBLICATION'}
        c=h.crypto;raw=json.loads(c.authority);raw['chatbotFileAuthorization']=authorization_scope(plan)
        if retained:
            raw['applicationRegistryCutover']={'postGrantRecovery':{'profile':'ouf.chatbot-gateway-schema-continuation.v1',
                'retainedNumericGateway':{'authorizationReceiptHash':f.digest(receipt)}}}
        c.authority=f.encoded(raw);c.approval['executionAuthorityHash']=f.signed.sha(c.authority)
        c.write(c.mandate,f.encoded(c.approval));c.approved=f.signed.sha(c.mandate.read_bytes())
        for role in c.grant['roles']:c.sign(role)
        action=f.AggregateAction(c.gate(),c.authority,c.expected['sourceClosureHash'])
        directory=c.root/'read-observations';directory.mkdir(mode=0o700)
        owner=AuthorizationDelta(action,plan,f.Journal(directory),h.delta.transport,h.primitives);owner.initialize()
        self.wall=json.loads(action.raw)['expiresAt']-3500;self.mono=10000.;self.boot='synthetic-boot'
        return owner,h
    def attempt(self,owner):
        return owner.verify_resilient('AFTER_GATEWAY',clock=lambda:self.wall,monotonic=lambda:self.mono,boot=self.boot)
    def advance(self,owner):
        b=owner.record()['observations']['AFTER_GATEWAY']
        delta=max(0,b['nextAttemptAt']-self.wall,b['nextAttemptMonotonic']-self.mono)
        self.wall+=delta;self.mono+=delta
    def test_503_retry_after_survives_new_object_and_verifies_without_any_write(self):
        owner,h=self.fixture();calls=copy.deepcopy(h.owner.calls)
        with patch.object(owner,'verify',side_effect=AuthorizationPaused('AUTHORIZATION_HTTP_503',retryAfterSeconds=120))as read:
            with self.assertRaises(AuthorizationPaused)as failure:self.attempt(owner)
            budget=owner.record()['observations']['AFTER_GATEWAY'];self.assertEqual(budget['attempts'],1)
            self.assertEqual(budget['nextAttemptAt']-self.wall,120)
            self.assertIsNotNone(owner.observation_retry_status(failure.exception))
            with self.assertRaisesRegex(AuthorizationPaused,'NOT_DUE'):self.attempt(owner)
            self.assertEqual(read.call_count,1);self.assertEqual(h.owner.calls,calls)
        self.advance(owner)
        resumed=AuthorizationDelta(owner.action,owner.plan,owner.journal,owner.transport,owner.primitives)
        self.attempt(resumed);self.assertEqual(owner.record()['observations']['AFTER_GATEWAY']['attempts'],2)
        self.assertEqual(owner.record()['observations']['AFTER_GATEWAY']['state'],'COMPLETE')
        self.assertEqual(owner.record()['effects'],{})
    def test_hour_outage_jitter_and_exhaustion_never_reset_or_extend(self):
        owner,_=self.fixture()
        with patch.object(owner,'verify',side_effect=AuthorizationPaused('AUTHORIZATION_HTTP_503'))as read:
            for _ in range(20):
                try:self.attempt(owner)
                except AuthorizationPaused as error:
                    budget=owner.record()['observations']['AFTER_GATEWAY']
                    if budget['state']=='PAUSED_EXHAUSTED':break
                    base=OBSERVATION_POLICY['backoffSeconds'][min(budget['attempts']-1,4)]
                    self.assertGreaterEqual(budget['nextAttemptAt']-self.wall,base)
                    self.assertLessEqual(budget['nextAttemptAt']-self.wall,base*1.2)
                    self.advance(owner)
            else:self.fail('outage was not bounded')
            attempts=read.call_count
            with self.assertRaisesRegex(Exception,'TERMINAL_NO_REPLAY'):self.attempt(owner)
            self.assertEqual(read.call_count,attempts);self.assertLess(attempts,128)
    def test_permanent_crash_revocation_and_invalid_retry_after_stop(self):
        for reason,detail in [('AUTHORIZATION_HTTP_403',{}),('AUTHORIZATION_HTTP_503',{'retryAfterInvalid':True}),
            ('AUTHORIZATION_HTTP_503',{'retryAfterSeconds':7200})]:
            owner,_=self.fixture()
            with patch.object(owner,'verify',side_effect=AuthorizationPaused(reason,**detail))as read:
                with self.assertRaises(AuthorizationPaused):self.attempt(owner)
                with self.assertRaisesRegex(Exception,'TERMINAL_NO_REPLAY'):self.attempt(owner)
                self.assertEqual(read.call_count,1)
        owner,_=self.fixture()
        with patch.object(owner,'verify',side_effect=OSError('simulated interruption'))as read:
            with self.assertRaises(OSError):self.attempt(owner)
            with self.assertRaisesRegex(Exception,'IN_FLIGHT'):self.attempt(owner)
            self.assertEqual(read.call_count,1)
        owner,h=self.fixture()
        with patch.object(owner,'verify',side_effect=AuthorizationPaused('AUTHORIZATION_HTTP_503')):
            with self.assertRaises(AuthorizationPaused):self.attempt(owner)
        before=owner.journal.record.read_bytes();h.crypto.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):self.attempt(owner)
        self.assertEqual(owner.journal.record.read_bytes(),before)
    def test_boot_or_clock_drift_never_reserves_another_attempt(self):
        for change in ('boot','clock'):
            owner,_=self.fixture()
            with patch.object(owner,'verify',side_effect=AuthorizationPaused('AUTHORIZATION_HTTP_503'))as read:
                with self.assertRaises(AuthorizationPaused):self.attempt(owner)
                before=owner.journal.record.read_bytes();self.advance(owner)
                if change=='boot':self.boot='other'
                else:self.mono=0
                with self.assertRaisesRegex(Exception,'HISTORY_OR_CLOCK_DRIFT'):self.attempt(owner)
                self.assertEqual(owner.journal.record.read_bytes(),before);self.assertEqual(read.call_count,1)

    def test_retained_roles_use_fresh_owner_policy_while_mcp_stopped_then_require_real_mcp(self):
        owner,h=self.fixture(retained=True);transport=owner.transport
        with (patch.object(transport,'observe',side_effect=lambda:OwnerTransport.observe(transport)),
            patch.object(transport,'roles',side_effect=lambda active=None:OwnerTransport.roles(transport,active)),
            patch.object(transport,'tool',side_effect=AuthorizationPaused('AUTHORIZATION_HTTP_503'))as mcp):
            self.attempt(owner);self.assertEqual(mcp.call_count,0)
            self.assertEqual(owner.record()['observations']['AFTER_GATEWAY']['state'],'COMPLETE')
            with self.assertRaisesRegex(AuthorizationPaused,'503'):
                owner.verify_resilient('FINAL_COHORT',clock=lambda:self.wall,monotonic=lambda:self.mono,boot=self.boot)
            self.assertEqual(mcp.call_count,1)
            self.assertEqual(owner.record()['observations']['FINAL_COHORT']['state'],'RETRY_WAIT')
            final=owner.record()['observations']['FINAL_COHORT'];delta=max(final['nextAttemptAt']-self.wall,final['nextAttemptMonotonic']-self.mono)
            self.wall+=delta;self.mono+=delta
            mcp.side_effect=None;mcp.return_value=copy.deepcopy(h.owner.current['roles'])
            owner.verify_resilient('FINAL_COHORT',clock=lambda:self.wall,monotonic=lambda:self.mono,boot=self.boot)
            self.assertEqual(mcp.call_count,2)
            self.assertEqual(owner.record()['observations']['FINAL_COHORT']['state'],'COMPLETE')

    def test_changed_owner_policy_or_race_never_uses_retained_roles_or_calls_stopped_mcp(self):
        owner,h=self.fixture(retained=True);transport=owner.transport
        original=copy.deepcopy(h.owner.current['active']);changed=copy.deepcopy(original);changed['contentHash']='f'*64
        with (patch.object(transport,'observe',side_effect=lambda:OwnerTransport.observe(transport)),
            patch.object(transport,'roles',side_effect=lambda active=None:OwnerTransport.roles(transport,active)),
            patch.object(transport,'tool',side_effect=AssertionError('stopped MCP must not be queried'))as mcp,
            patch.object(transport,'active',side_effect=[original,changed])):
            with self.assertRaisesRegex(Exception,'RETAINED_ROLE_POLICY_CHANGED'):self.attempt(owner)
            self.assertEqual(mcp.call_count,0)
            self.assertEqual(owner.record()['observations']['AFTER_GATEWAY']['state'],'ATTEMPTING')

if __name__=='__main__':unittest.main()
