"""Real scoped role signatures/CAS; synthetic peers are explicitly fixture-only."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.ingestion_readiness_patch_execution import contract as c,native_review as nr,native,engine_channel,archive_projection
from tools.ingestion_readiness_patch_execution.runner import Runner,Ports
from tools.ingestion_readiness_patch_execution.lifecycle import NativeLifecycle
from tools.ingestion_readiness_patch_execution.key import NativeKey
from tools.ingestion_readiness_patch_execution import runtime_bindings as rb,gateway_transport,authority
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession
import test_cutover_authority_native as crypto
import test_ingestion_rollout_native_review as pf
import image_custody

def fixture(folder):
    p=pf.NativeReview();p.setUp()
    tool=ROOT/'tools/readiness_patch_review'
    if not tool.exists():tool=ROOT.parent/'readiness-patch-review'
    spec=importlib.util.spec_from_file_location('patch_template_fixture',tool/'tests/test_compiler.py')
    f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
    values=f.fixture();values[0]['candidateSourceCommit']=values[1]['candidateMetadata']['sourceCommit']='2'*40
    values[-1]['Config']['Labels']['org.opencontainers.image.revision']='2'*40
    template=f.c.build(f.io,f.frames,f.replacement,*values)
    before=values[1]['runtimeBefore']['ingestion']
    image=values[-1];image['RootFS']={'Type':'layers','Layers':['sha256:'+'a'*64]}
    unchanged={}
    for i,name in enumerate(('gateway','onboarding','mcp','udp'),5):
        actual=copy.deepcopy(before);actual['Id']=str(i)*64;actual['Name']='/'+name
        unchanged[name]={'binding':rb.observed(actual,rb.NATIVE),'restartCount':actual['RestartCount'],'bindingProfile':rb.NATIVE}
    owner=copy.deepcopy(p.profiles['ownerControlProfile'])
    owner.update(runtimeBinding=copy.deepcopy(unchanged['onboarding']['binding']),
                 restartCount=before['RestartCount'],runtimeBindingProfile=rb.SORTED)
    db=copy.deepcopy(p.profiles['databaseControlProfile']);db['postgresRuntimeBinding']['containerId']='f'*64
    archive=copy.deepcopy(p.profiles['imageImportProfile']['archive'])
    bundle={'schema':'ouf.ingestion-readiness-patch-native-inputs.v1','kind':'PRIVATE_NATIVE_INPUTS_NOT_EXECUTABLE_AUTHORITY',
        'finiteIntentContract':{'logicalOperationRef':template['logicalOperationRef'],'stages':template['stages'],
                              'maximumGatewayWrites':0,'maximumSecretCreations':0},
        'ingestionFrame':template['frame'],'candidate':image,'beforeIngestion':before,
        'unchangedApplications':unchanged,'engineBinding':copy.deepcopy(db['engineBinding']),
        'ownerControlProfile':owner,'databaseControlProfile':db,
        'imageImportProfile':{**copy.deepcopy(p.profiles['imageImportProfile']), 'engineBinding':db['engineBinding'], 'archive':archive},
        'ingestionReadinessProfile':copy.deepcopy(p.profiles['ingestionReadinessProfile']),
        'unchangedGatewayTransportProfile':copy.deepcopy(p.profiles['gatewayTransportProfile']),
        'unchangedGatewayRoutes':copy.deepcopy(p.packet['routeDraft']['afterRoutes']),
        'candidateFileBindings':{'image.tar.gz':archive},'parentReviewHash':'d'*64,
        **{k:False for k in ('nativeRuntimeExecutorQualified','targetApplyAuthorized','runtimeAuthorityIssued',
                            'automaticReplayAllowed','budgetReset','sourceActivationAllowed','releaseAcceptance')}}
    audit={'archiveSha256':archive['sha256'],'imageId':image['Id'],'configSha256':image['Id'][7:],'configBytes':100,
           'sourceCommit':'2'*40,'imageConfig':copy.deepcopy(image['Config']),
           'layers':[{'blobSha256':'a'*64,'diffId':'sha256:'+'a'*64,'archiveBytes':100}]}
    audit['nativeIdentity']=image_custody.native_identity(audit);bundle['nativeArchiveAudit']=audit
    native_id=image_custody.runtime_image_id(audit)
    bundle['ingestionFrame']['requestTemplate']['Image']=native_id
    for stage in bundle['finiteIntentContract']['stages']:
        if stage['name']=='IMPORT_INGESTION_IMAGE':stage['intent']={'nativeImageId':native_id,
            'archiveSha256':archive['sha256'],'maximumArchiveBytes':archive['metadata'][6]}
        if stage['name']=='ingestion.CREATE_REPLACEMENT':stage['intent']['requestTemplate']['Image']=native_id
        stage['intentHash']=c.digest(stage['intent'])
    human={'sessionId':'fixture-session','issuer':'https://fixture.invalid','tenant':'fixture','subject':'fixture-human'}
    review,packet=nr.compile_review(bundle,{'path':str(folder/'inputs.json'),'sha256':c.digest(bundle)},human,str(folder))
    return p,review,packet

class Contract(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.p,self.review,self.packet=fixture(self.root);self.addCleanup(self.p.doCleanups)
    def test_twelve_stages_single_container_no_key_gateway_or_domain_mutations(self):
        nr.validate_review(self.review,self.packet);scope=c.scope(self.review)
        self.assertEqual(len(self.review['stages']),12)
        self.assertEqual(scope['maximumGatewayPuts'],0);self.assertEqual(self.review['maximumDirectEnginePosts'],7)
        self.assertEqual([s['name']for s in self.review['stages']if s['name'].endswith('.CREATE_REPLACEMENT')],['ingestion.CREATE_REPLACEMENT'])
        self.assertFalse(any(s['name'].startswith(('gateway.','PUT_ROUTE.','CREATE_DEDICATED'))for s in self.review['stages']))
        self.assertNotEqual(c.AUTHORITY_KEY,'ingestionGatewayRollout')
        self.assertFalse(NativeLifecycle.handles({'name':'gateway.STOP_OLD'}))
        self.assertFalse(hasattr(gateway_transport.NativeGatewayTransport,'put'))
        for method in ('create','read_for_gateway'):
            with self.assertRaises(c.Denied):getattr(NativeKey(None,None,self.review,None),method)()
    def test_rehashed_foreign_lifecycle_intent_and_gateway_budget_are_rejected(self):
        for mutate in (lambda r:r['stages'].reverse(), lambda r:r.update(maximumGatewayPuts=1),
                       lambda r:r['preparedInputs']['beforeIngestion'].update(Id='9'*64),
                       lambda r:r['stages'][2]['intent'].update(oldContainerId='9'*64)):
            value=copy.deepcopy(self.review);mutate(value)
            for s in value['stages']:s['intentHash']=c.digest(s['intent'])
            value['preparedInputsHash']=c.digest(value['preparedInputs'])
            with self.assertRaises(c.Denied):nr.validate_review(value,self.packet)
    def test_configuration_native_manifest_and_archive_cannot_be_substituted(self):
        for mutate in (
            lambda b:b['nativeArchiveAudit']['nativeIdentity'].update(nativeImageId='sha256:'+'9'*64),
            lambda b:b['nativeArchiveAudit'].update(archiveSha256='9'*64),
            lambda b:b['nativeArchiveAudit'].update(sourceCommit='9'*40),
            lambda b:b['ingestionFrame'].update(preserveObservedAddressesAndMacs=False),
            lambda b:b['ingestionFrame']['requestTemplate'].update(Image=b['candidate']['Id'])):
            bundle=copy.deepcopy(self.review['preparedInputs']);mutate(bundle)
            with self.assertRaises((c.Denied,image_custody.ImageCustodyDenied)):
                nr.compile_review(bundle,{'path':str(self.root/'inputs.json'),'sha256':c.digest(bundle)},
                    self.review['humanBinding'],str(self.root))
    def test_native_archive_successor_preserves_parent_and_logical_operation(self):
        parent=copy.deepcopy(self.review['preparedInputs']);audit=parent.pop('nativeArchiveAudit')
        audit.update(archiveByteCustodyProven=True,targetApplyAuthorized=False,repositoryTags=[])
        config=parent['candidate']['Id'];parent['ingestionFrame']['requestTemplate']['Image']=config
        for stage in parent['finiteIntentContract']['stages']:
            if stage['name']=='IMPORT_INGESTION_IMAGE':stage['intent']['nativeImageId']=config
            if stage['name']=='ingestion.CREATE_REPLACEMENT':stage['intent']['requestTemplate']['Image']=config
            stage['intentHash']=c.digest(stage['intent'])
        frozen=c.encoded(parent);archive=copy.deepcopy(parent['candidateFileBindings']['image.tar.gz'])
        projected=archive_projection.project(parent,c.digest(parent),audit,archive)
        self.assertEqual(c.encoded(parent),frozen)
        self.assertEqual(projected['finiteIntentContract']['logicalOperationRef'],parent['finiteIntentContract']['logicalOperationRef'])
        self.assertEqual(projected['nativeArchivePreparation']['parentNativeInputsHash'],c.digest(parent))
        c.stages(projected)
        with self.assertRaises(c.Denied):archive_projection.project(projected,c.digest(projected),audit,archive)
        for key,val in (('repositoryTags',['foreign:tag']),('archiveSha256','f'*64),('sourceCommit','f'*40)):
            changed=copy.deepcopy(audit);changed[key]=val
            with self.assertRaises(c.Denied):archive_projection.project(parent,c.digest(parent),changed,archive)
    def test_current_custody_channel_or_budget_drift_is_denied(self):
        for key in ('maximumDirectEnginePosts','maximumDirectEngineGets','maximumOwnerGetAttempts'):
            value=copy.deepcopy(self.review);value[key]+=1
            with self.assertRaises(c.Denied):nr.validate_review(value,self.packet)
        packet=copy.deepcopy(self.packet);packet['frames']['gateway']={}
        with self.assertRaises(c.Denied):nr.validate_review(self.review,packet)
    def test_image_stdio_defaults_cannot_override_retained_stdio(self):
        request=self.packet['frames']['ingestion']['requestTemplate']
        self.assertEqual(request['Env'],self.review['preparedInputs']['beforeIngestion']['Config']['Env'])
        self.assertNotIn('MacAddress',request)
        self.assertEqual(request['HostConfig']['Binds'],self.review['preparedInputs']['beforeIngestion']['HostConfig']['Binds'])

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','real root signature/CAS fixture required')
class Signed(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);root.chmod(0o700);self.context=root/'execution';self.context.mkdir(mode=0o700)
        self.p,self.review,self.packet=fixture(self.context);self.addCleanup(self.p.doCleanups)
        self.scope=c.scope(self.review);self.q=crypto.SignedCutover()
        with patch.object(crypto,'ROOT',root):self.q.setUp()
        self.addCleanup(self.q.doCleanups);q=self.q
        raw=json.loads(q.authority);raw[c.AUTHORITY_KEY]=self.scope;raw['expiresAt']=q.now+480
        q.authority=c.encoded(raw);q.approval['expiresAt']=q.now+540;q.approval['executionAuthorityHash']=c.digest(raw)
        q.write(q.mandate,c.encoded(q.approval));q.approved=crypto.sha(q.mandate.read_bytes())
        for role in q.grant['roles']:q.sign(role)
        self.action=AggregateAction(q.gate(),q.authority,q.expected['sourceClosureHash']);self.mono=time.monotonic()
        case=self
        class PeerPorts(Ports):
            def __init__(self):self.effects=[];self.crash=False;self.unknown=False;self.transient=False;self.boot_id='fixture-boot'
            def boot(self):return self.boot_id
            def guard_current(self,s):case.action.guard(c.AUTHORITY_KEY,case.scope)
            def apply(self,s):
                self.effects.append(s['name'])
                if self.crash:raise OSError('fixture ambiguous response')
            def observe(self,s):
                if self.unknown:return 'UNKNOWN',{}
                if self.transient:return 'TRANSIENT',{'retryAfterSeconds':8}
                return 'APPLIED',{'fixtureObservedStage':s['name']}
        self.peers=PeerPorts();self.journal=Journal(self.context)
        self.runner=Runner(self.action,self.journal,self.review,self.peers,lambda:(float(q.now),self.mono));self.runner.initialize()
        self.human=HumanSession.__new__(HumanSession);self.human.current=lambda:self.review['humanBinding']
        self.ports=native.NativePorts(self.action,self.journal,self.review,self.packet,self.human);self.addCleanup(self.ports.close)
    def test_actual_signatures_and_complete_twelve_step_journal_no_replay(self):
        for _ in self.review['stages']:self.runner.step()
        self.assertTrue(self.runner.step()['complete']);effects=list(self.peers.effects);self.runner.step()
        self.assertEqual(self.peers.effects,effects);self.assertEqual(len(effects),8)
        with self.assertRaises(c.Denied):self.runner.initialize()
    def test_ambiguous_effect_requires_observation_and_never_repeats_apply(self):
        self.runner.step();self.peers.crash=True
        with self.assertRaises(OSError):self.runner.step()
        with self.assertRaises(c.Paused):self.runner.step()
        self.peers.unknown=True
        with self.assertRaises(c.Paused):self.runner.reconcile()
        self.peers.unknown=False;self.peers.crash=False;self.runner.reconcile()
        self.assertEqual(self.peers.effects,['IMPORT_INGESTION_IMAGE'])
    def test_expiry_revocation_clock_and_reboot_preserve_progress(self):
        before=self.runner.record();self.peers.boot_id='other'
        with self.assertRaises(c.Denied):self.runner.step()
        self.peers.boot_id='fixture-boot';saved_mono=self.mono;self.mono-=1
        with self.assertRaises(c.Denied):self.runner.step()
        self.mono=saved_mono;policy=json.loads(self.q.policy.read_bytes());policy['keys'][0]['state']='REVOKED'
        self.q.write(self.q.policy,c.encoded(policy))
        with self.assertRaises(Exception):self.runner.step()
        self.assertEqual(self.runner.record(),before)
    def test_transient_read_backoff_and_exhaustion_are_durable(self):
        self.peers.transient=True
        with self.assertRaises(c.Paused):self.runner.step()
        before=self.runner.record();self.assertEqual(before['readAttempts'],1)
        with self.assertRaises(c.Paused):self.runner.step()
        self.assertEqual(self.runner.record(),before)
        self.runner.save(before,readAttempts=128)
        with self.assertRaises(c.Paused):self.runner.step()
        self.assertEqual(self.runner.record()['readAttempts'],128)
    def services(self):
        self.ports.prepare=Mock();self.ports.generations=Mock()
        self.ports.owner=Mock();self.ports.owner.verify.return_value={'ownerActiveAndStrongEtagMatched':True}
        self.ports.routes=Mock(return_value=self.packet['routeDraft']['beforeRoutes'])
        self.ports.database=Mock();self.ports.database.snapshot.side_effect=lambda:{'observedAtUnix':time.time(),'databaseReadPrerequisitesProven':True}
    def test_owner_route_and_database_last_guards_invalidate_stale_proofs(self):
        self.services();events=[];stage=self.review['stages'][0]
        self.ports.generations.side_effect=lambda:events.append('generations')
        self.ports.owner.verify.side_effect=lambda:events.append('owner')or{'ownerActiveAndStrongEtagMatched':True}
        self.ports.routes.side_effect=lambda:events.append('routes')or self.packet['routeDraft']['beforeRoutes']
        self.ports.database.snapshot.side_effect=lambda:events.append('database')or{'observedAtUnix':time.time(),'databaseReadPrerequisitesProven':True}
        self.ports.guard_current(stage);self.assertEqual(events,['generations','owner','routes','database'])
        self.ports.owner.verify.side_effect=c.Denied('FIXTURE_OWNER_CHANGED')
        with self.assertRaises(c.Denied):self.ports.guard_current(stage)
        self.assertIsNone(self.ports.last_gates)
    def test_route_drift_or_human_drift_blocks_before_mutation(self):
        self.services();self.ports.routes.return_value={};self.ports.image=Mock()
        with self.assertRaises(c.Denied):self.ports.guard_current(self.review['stages'][1])
        self.ports.image.apply.assert_not_called()
        self.human.current=lambda:{**self.review['humanBinding'],'sessionId':'foreign'}
        with self.assertRaises(c.Denied):self.ports.guard_current(self.review['stages'][1])
    def test_one_effect_consumes_fresh_gate_even_on_failure(self):
        self.services();stage=self.review['stages'][1];self.ports.image=Mock()
        self.ports.guard_current(stage);self.ports.image.apply.side_effect=OSError('fixture lost response')
        with self.assertRaises(OSError):self.ports.apply(stage)
        with self.assertRaises(c.Denied):self.ports.apply(stage)
        self.assertEqual(self.ports.image.apply.call_count,1)
    def test_cas_and_competing_invocation_never_reset_claim(self):
        old=self.runner.record();self.runner.step()
        with self.assertRaises(Exception):self.journal.compare_and_save(old,{**old,'version':999})
        with self.journal.invocation():
            with self.assertRaises(BlockingIOError):
                with Journal(self.context).invocation():pass

if __name__=='__main__':unittest.main()
