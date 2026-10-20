"""Review contract plus actual role signatures/private CAS journal in disposable CI.

Fixture ports model effects only; no production native executor is qualified.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_rollout_execution import contract as c
from tools.ingestion_rollout_preparation import frames
from test_ingestion_rollout_packet import fixture

def review_fixture(context='/fixture/execution'):
    actual,draft,image=fixture();key=draft['ingestion']['readOnlyBindAddition']['Source']
    gateway=copy.deepcopy(actual);gateway['Id']='d'*64;gateway['Name']='/gateway'
    gateway['Mounts']=[{'Type':'bind','Source':'/fixture/old.yaml','Destination':frames.CONFIG_DESTINATION,'RW':False}]
    gateway['HostConfig']['Binds']=['/fixture/old.yaml:'+frames.CONFIG_DESTINATION+':ro']
    actual['Config']['MacAddress']=actual['NetworkSettings']['Networks']['fixture_net']['MacAddress']
    prepared={'ingestion':frames.frame('ingestion',actual,'sha256:'+'e'*64,image,draft),
              'gateway':frames.frame('gateway',gateway,gateway['Image'],image,draft,'/fixture/new.yaml')}
    routes={k:{'id':k}for k in ['mcp-ingestion-status','mcp-ingestion-history',*[str(i)for i in range(80)]]}
    after=copy.deepcopy(routes)
    for name in ('mcp-ingestion-status','mcp-ingestion-history'):after[name]['fixtureReceipt']=True
    inputs={'candidate':{'configurationImageId':'sha256:'+'f'*64,'nativeImageId':'sha256:'+'e'*64,
                'imageConfig':image,'rootfs':{'type':'layers','diff_ids':['sha256:'+'a'*64]},
                'nativeArchiveBinding':{'path':'/fixture/image.tar','sha256':'c'*64}},
            'expectedRuntimeBindings':{'ingestion':{'containerId':actual['Id'],'imageId':actual['Image']},
                                       'gateway':{'containerId':gateway['Id'],'imageId':gateway['Image']}},
            'gatewayConfigBefore':{'path':'/fixture/old.yaml','sha256':'d'*64},
            'retainedGatewayConfig':{'path':'/fixture/new.yaml','sha256':'b'*64},
            'dedicatedOwnerKey':{'path':key,'state':'MISSING_AT_EXISTING_CUSTODIED_PARENT'},'retainedClaims':{'fixture':True}}
    packet={'schema':'ouf.ingestion-rollout-private-packet.v3','kind':'PRIVATE_TEMPLATES_NOT_EXECUTABLE_AUTHORITY',
            **inputs,'verifiedInputsHash':c.digest(inputs),'frames':prepared,
            'routeDraft':{'beforeRoutes':routes,'afterRoutes':after,'retainedOtherRoutes':80,'maximumPutRequests':2},
            'runtimeAuthorityIssued':False,'runtimeExecutorQualified':False,'databaseAdmissionProven':False,
            'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'newLoginAllowed':False}
    binding={'path':'/fixture/packet-plan.json','sha256':c.digest(packet)}
    human={'sessionId':'fixture-session','issuer':'https://fixture.invalid','tenant':'fixture','subject':'human'}
    return c.compile_review(packet,binding,inputs,human,context),packet,inputs

class ReviewContract(unittest.TestCase):
    def test_exact_packet_to_finite_key_two_runtime_two_put_intents(self):
        review,packet,inputs=review_fixture();scope=c.scope(review)
        self.assertTrue(all(review[k]is False for k in c.FORBIDDEN));self.assertEqual(review['maximumGatewayPuts'],2)
        self.assertEqual(review['maximumEffectAttemptsPerStage'],1);self.assertEqual(scope['maximumReadAttempts'],128)
        stages=review['stages'];self.assertEqual(stages[0]['name'],'VERIFY_CURRENT_GATES')
        self.assertEqual(stages[1]['name'],'CREATE_DEDICATED_KEY');self.assertEqual(stages[1]['intent']['uid'],10002)
        self.assertEqual(len([s for s in stages if s['name'].startswith('PUT_ROUTE.')]),2)
        self.assertEqual([s['name']for s in stages if s['name'].endswith('.CREATE_REPLACEMENT')],
                         ['ingestion.CREATE_REPLACEMENT','gateway.CREATE_REPLACEMENT'])
        self.assertEqual(stages[-1]['name'],'VERIFY_RESTORED_FINAL');self.assertFalse(review['nativeProfilePublished'])
        self.assertEqual(review['packetBinding']['sha256'],c.digest(packet));self.assertEqual(review['verifiedInputsHash'],c.digest(inputs))

    def test_frame_or_route_drift_and_foreign_secret_scope_block(self):
        for mutation in ('third_route','gateway_image','key_reference','existing_key','runtime_authority','input_drift'):
            _,packet,inputs=review_fixture()
            if mutation=='third_route':packet['routeDraft']['afterRoutes']['1']['foreign']=True
            if mutation=='gateway_image':packet['frames']['gateway']['requestTemplate']['Image']='sha256:'+'0'*64
            if mutation=='key_reference':packet['frames']['ingestion']['requestTemplate']['HostConfig']['Binds']=['/wrong:/run/secrets/key:ro']
            if mutation=='existing_key':packet['dedicatedOwnerKey']['state']='EXISTING_CONTENT_UNREAD'
            if mutation=='runtime_authority':packet['runtimeAuthorityIssued']=True
            if mutation=='input_drift':inputs['candidate']['nativeImageId']='sha256:'+'1'*64
            with self.subTest(mutation=mutation),self.assertRaises(c.Denied):
                c.compile_review(packet,{'path':'/fixture/packet','sha256':c.digest(packet)},inputs,
                                 {'sessionId':'f','issuer':'i','tenant':'t','subject':'s'},'/fixture/execution')

    def test_extra_effects_or_reset_do_not_match_approved_scope(self):
        review,_,_=review_fixture();original=c.scope(review)
        changed=copy.deepcopy(review);changed['stages'][1]['intent']['overwriteAllowed']=True
        with self.assertRaises(c.Denied):c.scope(changed)
        for flag in c.FORBIDDEN:
            changed=copy.deepcopy(review);changed[flag]=True
            with self.subTest(flag=flag),self.assertRaises(c.Denied):c.scope(changed)
        changed=copy.deepcopy(review);changed['stages'].reverse()
        self.assertNotEqual(c.scope(changed),original)

if os.environ.get('OUF_NATIVE_UIDS')=='1':
    from tools.ingestion_rollout_execution.runner import Runner,Ports
    from tools.semantic_policy_token_owner.owner_installation import AggregateAction
    from tools.semantic_lease_recovery.recovery_journal import Journal
    import test_cutover_authority_native as crypto

    class SignedFiniteRunner(unittest.TestCase):
        def setUp(self):
            self.temp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(self.temp.cleanup)
            root=Path(self.temp.name);root.chmod(0o700);self.crypto=crypto.SignedCutover()
            with patch.object(crypto,'ROOT',root):self.crypto.setUp()
            self.addCleanup(self.crypto.doCleanups);q=self.crypto
            self.context=q.root/'rollout-execution';self.context.mkdir(mode=0o700)
            self.review,_,_=review_fixture(str(self.context));self.scope=c.scope(self.review);self.mono=100.
            self.clock=lambda:(float(q.now),self.mono)
            authority=json.loads(q.authority);authority[c.AUTHORITY_KEY]=self.scope;authority['expiresAt']=q.now+480
            q.authority=c.encoded(authority);q.approval['expiresAt']=q.now+540;q.approval['executionAuthorityHash']=c.digest(authority)
            q.write(q.mandate,c.encoded(q.approval));q.approved=q.sha(q.mandate.read_bytes())if hasattr(q,'sha')else crypto.sha(q.mandate.read_bytes())
            for role in q.grant['roles']:q.sign(role)
            self.action=AggregateAction(q.gate(),q.authority,q.expected['sourceClosureHash'])
            case=self
            class FixturePorts(Ports):
                def __init__(self):self.effects=[];self.observations=[];self.unknown=False;self.transient=False;self.retry_after=7;self.crash=False;self.blocked=False;self.boot_id='fixture-boot'
                def boot(self):return self.boot_id
                def guard_current(self,stage):
                    case.action.guard(c.AUTHORITY_KEY,case.scope)
                    if self.blocked:raise c.Denied('FIXTURE_CURRENT_NATIVE_GATE_REVOKED')
                def apply(self,stage):
                    self.effects.append(stage['name'])
                    if self.crash:raise RuntimeError('FIXTURE_AMBIGUOUS_EFFECT')
                def observe(self,stage):
                    self.observations.append(stage['name'])
                    if self.unknown:return 'UNKNOWN',{}
                    if self.transient:return 'TRANSIENT',{'retryAfterSeconds':self.retry_after}
                    return 'APPLIED',{'fixtureObservedStage':stage['name']}
            self.ports=FixturePorts();self.runner=Runner(self.action,Journal(self.context),self.review,self.ports,self.clock)
            self.runner.initialize()

        def advance(self,seconds):self.crypto.now+=seconds;self.mono+=seconds
        def test_actual_dual_signature_gate_and_complete_finite_sequence_no_replay(self):
            for _ in self.review['stages']:self.runner.step()
            result=self.runner.step();self.assertTrue(result['complete']);self.assertFalse(result['releaseAcceptance'])
            self.assertFalse(result['nativeProfilePublished']);count=len(self.ports.effects)
            self.runner.step();self.assertEqual(count,len(self.ports.effects))
            self.assertEqual(len(self.ports.effects),len([s for s in self.review['stages']if s['kind']=='EFFECT']))
            self.assertEqual(self.runner.record()['readAttempts'],len(self.review['stages']))

        def test_ambiguous_effect_requires_readback_and_never_dispatches_twice(self):
            self.runner.step();self.ports.crash=True
            with self.assertRaises(RuntimeError):self.runner.step()
            self.assertEqual(self.ports.effects,['CREATE_DEDICATED_KEY'])
            with self.assertRaises(c.Paused):self.runner.step()
            self.ports.unknown=True
            with self.assertRaises(c.Paused):self.runner.reconcile()
            self.ports.unknown=False;self.ports.crash=False;result=self.runner.reconcile()
            self.assertFalse(result['effectReplayed']);self.assertEqual(self.ports.effects,['CREATE_DEDICATED_KEY'])

        def test_transient_read_persists_backoff_and_does_not_hold_journal_transaction(self):
            self.ports.transient=True
            with self.assertRaises(c.Paused):self.runner.step()
            row=self.runner.record();self.assertEqual(row['readState'],'RETRY_WAIT');self.assertEqual(row['readAttempts'],1)
            self.assertGreaterEqual(row['nextReadAt']-self.crypto.now,7)
            with self.assertRaises(c.Paused):self.runner.step()
            self.assertEqual(self.runner.record()['readAttempts'],1)
            self.advance(8);self.ports.transient=False;self.runner.step()
            self.assertEqual(self.runner.record()['readAttempts'],2);self.assertEqual(self.ports.effects,[])

        def test_revoked_role_key_wrong_scope_and_native_gate_block_before_effect(self):
            self.ports.blocked=True
            with self.assertRaises(c.Denied):self.runner.step()
            self.assertEqual(self.ports.effects,[]);self.ports.blocked=False
            policy=json.loads(self.crypto.policy.read_bytes());policy['keys'][0]['state']='REVOKED';self.crypto.write(self.crypto.policy,c.encoded(policy))
            with self.assertRaises(Exception):self.runner.step()
            self.assertEqual(self.ports.effects,[])

        def test_expiry_boot_and_clock_regression_block_without_budget_reset(self):
            original=self.runner.record();self.ports.boot_id='another-boot'
            with self.assertRaises(c.Denied):self.runner.step()
            self.ports.boot_id='fixture-boot';self.mono=99.
            with self.assertRaises(c.Denied):self.runner.step()
            self.mono=100.;self.advance(481)
            with self.assertRaises(Exception):self.runner.step()
            self.assertEqual(original,self.runner.record())

        def test_duplicate_context_cannot_reset_global_logical_claim_and_cas_rejects_stale_writer(self):
            with self.assertRaises(c.Denied):self.runner.initialize()
            before=self.runner.record();self.runner.step()
            with self.assertRaises(Exception):self.runner.journal.compare_and_save(before,{**before,'version':99})
            with self.runner.journal.invocation():
                with self.assertRaises(BlockingIOError):
                    with Journal(self.context).invocation():pass

        def test_cumulative_read_budget_exhaustion_remains_paused(self):
            row=self.runner.record();self.runner.save(row,readAttempts=128)
            with self.assertRaises(c.Paused):self.runner.step()
            self.assertEqual(self.runner.record()['readAttempts'],128)
            self.assertEqual(self.ports.effects,[])

        def test_retry_after_beyond_current_authority_is_retained_without_truncation(self):
            self.ports.transient=True;self.ports.retry_after=1000
            with self.assertRaises(c.Paused):self.runner.step()
            row=self.runner.record();self.assertEqual(row['readState'],'EXHAUSTED')
            self.assertEqual(row['nextReadAt'],self.crypto.now+1000);self.assertEqual(row['readAttempts'],1)
            with self.assertRaises(c.Paused):self.runner.step()
            self.assertEqual(self.runner.record()['readAttempts'],1);self.assertEqual(self.ports.effects,[])

if __name__=='__main__':unittest.main()
