"""Real private CAS, current read-only HUMAN and two-role signatures.

Archive/qualification peers are synthetic; executable/stdlib observation is
mocked only in these controller units, never target admission evidence.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_authority as fixture
from tools.ingestion_readiness_patch_execution import operator_control as op,custody,entry as e
from tools.ingestion_readiness_patch_execution import runtime as loader
from tools.ingestion_readiness_patch_execution.runner import Ports
from test_ingestion_rollout_gateway_transport import binding

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','real root private journal/signature fixtures required')
class OperatorControl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sources={n:(ROOT/loader.SOURCE_PATHS[n]).read_bytes()for n in loader.MODULES}
        pins={n:'1'*40 for n in ('ouf-deploy','ouf-onboarding','ouf-ingestion-runtime','ouf-api-gateway')}
        cls.manifest=loader.declaration('1'*40,sources,(ROOT/'tools/ingestion_readiness_patch_execution/runtime.py').read_bytes(),pins)
        cls.control_hash=hashlib.sha256((ROOT/'tools/ingestion_readiness_patch_execution/operator_control.py').read_bytes()).hexdigest()
    def setUp(self):
        self.fixture=fixture.NativeIssuer();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        q=self.fixture.crypto;self.root=q.root
        policy=json.loads(q.policy.read_bytes())
        for k in policy['keys']:k['expiresAt']=int(fixture.time.time())+1800
        q.write(q.policy,e.c.encoded(policy));self.fixture.issuer['policy']=binding(q.policy)
        installation=Path(self.fixture.issuer['installationAuthority']['path'])
        config=json.loads(installation.read_bytes());config['policyBinding']=q.binding(q.policy)
        q.write(installation,e.c.encoded(config));self.fixture.issuer['installationAuthority']=binding(installation)
        for name,value in ((e,self.manifest['sourceHashes'][e.__name__]),(custody,self.manifest['sourceHashes'][op.CUSTODY])):
            p=patch.object(name,'__qualified_source_sha256__',value,create=True);p.start();self.addCleanup(p.stop)
        for name,value in (('verify_closure',None),('stdlib_binding',{'fileHashes':{'synthetic-only':'a'*64}})):
            p=patch.object(e.authority,name,return_value=value);p.start();self.addCleanup(p.stop)
        p=patch.object(e.NativePorts,'boot',return_value='synthetic-fixture-boot');p.start();self.addCleanup(p.stop)
        folder=self.root/'archive-successor';folder.mkdir(mode=0o700)
        bundle=copy.deepcopy(self.fixture.native_review['preparedInputs'])
        bundle['nativeArchivePreparation']={'parentNativeInputsHash':'a'*64}
        bundle['retainedIssuerProfile']=copy.deepcopy(self.fixture.issuer)
        bundle['historicalSourceClosure']=copy.deepcopy(self.fixture.closure)
        self.bundle=bundle
        path=folder/'native-inputs.json';path.write_bytes(e.c.encoded(bundle));path.chmod(0o400)
        self.receipt={'schema':'ouf.ingestion-readiness-native-archive-result.v1','status':'NATIVE_ARCHIVE_INPUTS_PREPARED_NO_AUTHORITY',
            'complete':True,'bundleHash':e.c.digest(bundle),'parentInputsHash':'a'*64,
            'logicalOperationRef':bundle['finiteIntentContract']['logicalOperationRef'],
            'configurationImageId':bundle['candidate']['Id'],'nativeImageId':bundle['nativeArchiveAudit']['nativeIdentity']['nativeImageId'],
            'nativeArchiveSha256':bundle['nativeArchiveAudit']['archiveSha256'],'plannedStages':12,'contextPath':str(folder),
            **dict.fromkeys(('automaticReplayAllowed','budgetReset','runtimeAuthorityIssued','nativeRuntimeExecutorQualified',
                'targetApplyAuthorized','releaseAcceptance','imageRebuilt','liveRuntimeReverified'),False),
            **dict.fromkeys(('imagesImported','engineRequests','oauthRequests','credentialFilesOpened','runtimeEffectsDispatched'),0)}
        p=folder/'complete.json';p.write_bytes(e.c.encoded(self.receipt));p.chmod(0o400)
        qualification=copy.deepcopy(self.fixture.qualification);qualification['sourceHashes']=self.manifest['sourceHashes']
        self.case={'schema':op.SCHEMA,'snapshotRoot':str(self.root),'nativeInputsPath':str(path),
            'nativeInputsHash':e.c.digest(bundle),'nativeReceiptHash':e.c.digest(self.receipt),'parentInputsHash':'a'*64,
            'logicalOperationRef':self.receipt['logicalOperationRef'],'configurationImageId':self.receipt['configurationImageId'],
            'nativeImageId':self.receipt['nativeImageId'],'nativeArchiveSha256':self.receipt['nativeArchiveSha256'],
            'candidateSourceCommit':'2'*40,'plannedStages':12,'nativeDeclarationHash':e.c.digest(self.manifest),
            'qualification':qualification,'requiredCumulativeOAuthAttempts':296,'maximumRuntimeSeconds':900,
            'controlSourceHash':self.control_hash}
        human=self.fixture.human;row=human.journal.read();receipt=copy.deepcopy(row['governedWindowRenewal'])
        receipt['review']['operationBinding']={'runtimeCaseHash':e.c.digest(self.case),'nativeInputsHash':self.case['nativeInputsHash'],
            'logicalOperationRef':self.case['logicalOperationRef'],'controlSourceHash':self.case['controlSourceHash']}
        receipt['decision']['reviewHash']=e.c.digest(receipt['review'])
        human.journal.compare_and_save(row,{**row,'governedWindowRenewal':receipt,'version':row['version']+1})
        self.fixture.profile['journal']=binding(human.journal.record)
        self.fixture.profile['governedWindowReceiptHash']=e.c.digest(receipt)
        self.profile_path=self.root/'human-read-profile.json';self.profile_path.write_bytes(e.c.encoded(self.fixture.profile));self.profile_path.chmod(0o400)
        self.target=op.context(e,self.case)
    def call(self,*args):return op.execute(e,self.manifest,self.case,self.control_hash,custody,list(args))
    def review(self):return self.call('review',str(self.profile_path))
    def approve(self):
        def consent(review,summary):
            self.assertIn('soltanto Ingestion',summary);self.assertIn('normale lavoro configurato',summary)
            now=int(fixture.time.time())
            return {'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':e.c.digest(review),
                'approvalRef':'mcp-scoped-'+e.c.digest(review)[:24]+'-'+str(now),'sourceClosureHash':review['sourceClosureHash'],
                'humanSessionHash':e.c.digest(review['authenticatedHuman']),'approvedAt':now,
                'expiresAt':min(now+900,review['absoluteExpiresAt']),'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
        with patch.object(e.authority,'terminal_consent',side_effect=consent):return self.call('approve')
    def test_preflight_is_read_only_and_never_opens_human_or_signs(self):
        before=set(self.root.iterdir())
        with patch.object(e.human_reader,'open_existing')as human,patch.object(e.authority,'issue_action')as issue:
            result=self.call('preflight');human.assert_not_called();issue.assert_not_called()
        self.assertEqual(result['status'],'PATCH_RUNTIME_PREFLIGHT_NO_AUTHORITY');self.assertEqual(before,set(self.root.iterdir()))
    def test_real_two_role_issuance_initialization_and_non_authenticating_status(self):
        self.review();approved=self.approve();self.assertTrue(approved['runtimeAuthorityIssued'])
        with self.assertRaises(e.c.Denied):self.approve()
        result=self.call('initialize');self.assertTrue(result['initialized']);self.assertEqual(result['effectsDispatched'],0)
        with self.assertRaises(e.c.Denied):self.call('initialize')
        with patch.object(e.human_reader,'open_existing')as human,patch.object(e.authority,'issue_action')as issue:
            result=self.call('status');human.assert_not_called();issue.assert_not_called()
        self.assertEqual(result['nextStage'],0);self.assertEqual(result['runtimeEffectsRecorded'],0)
        self.assertEqual(len(list(self.target.glob('*.DEPLOYMENT_INTENT.json'))),1)
        self.assertEqual(len(list(self.target.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'))),1)
    def test_completed_review_and_old_human_history_cannot_be_reused(self):
        self.review()
        with patch.object(e.human_reader,'open_existing')as human,self.assertRaises(e.c.Denied):self.review()
        human.assert_not_called()
        p=copy.deepcopy(self.fixture.profile);p['minimumCumulativeAttempts']=292;p['maximumCumulativeAttempts']=292
        with self.assertRaises(e.c.Denied):op.human(e,self.case,p)
    def test_partial_review_publication_retains_claim_and_blocks_replay(self):
        original=op.publish
        def fail(entry,target,name,value):
            if name=='packet.json':raise OSError('synthetic interrupted publication')
            return original(entry,target,name,value)
        with patch.object(op,'publish',side_effect=fail),self.assertRaises(OSError):self.review()
        self.assertTrue(list(self.root.glob('ingestion-readiness-review-*.claim.json')))
        with self.assertRaises(e.c.Denied):self.review()
        result=self.call('status');self.assertEqual(result['state'],'REVIEW_COMPILING')
    def test_partial_signature_failure_cannot_repeat_issuance(self):
        self.review();original=e.authority.ExistingEd25519Signer.sign;calls=[]
        def fail(signer,raw):
            calls.append(signer.scope['role'])
            if len(calls)==2:raise OSError('synthetic lost second signature')
            return original(signer,raw)
        with patch.object(e.authority.ExistingEd25519Signer,'sign',fail),self.assertRaises(OSError):self.approve()
        self.assertEqual(self.call('status')['state'],'ISSUING')
        with patch.object(e.authority.ExistingEd25519Signer,'sign')as sign,self.assertRaises(e.c.Denied):self.approve()
        sign.assert_not_called()
    def test_wrong_scope_case_packet_or_program_material_never_dispatches(self):
        changed=copy.deepcopy(self.case);changed['requiredCumulativeOAuthAttempts']=292
        with self.assertRaises(e.c.Denied):op.execute(e,self.manifest,changed,self.control_hash,custody,['preflight'])
        self.review();path=self.target/'packet.json';packet=json.loads(path.read_bytes());packet['foreign']=True;path.write_bytes(e.c.encoded(packet))
        with patch.object(e,'NativePorts')as ports,self.assertRaises(e.c.Denied):self.approve()
        ports.assert_not_called()
        self.assertFalse((self.target/'authority.json').exists())
    def test_control_cas_ambiguity_and_cancellation_preserve_progress(self):
        self.review();self.approve();self.call('initialize')
        with patch.object(e,'execute',side_effect=OSError('synthetic lost invocation response')),self.assertRaises(OSError):self.call('step')
        self.assertEqual(self.call('status')['state'],'RECONCILE_REQUIRED')
        with patch.object(e,'execute')as execute,self.assertRaises(e.c.Denied):self.call('step')
        execute.assert_not_called()
        _,journal,row=op.opened(e,self.case,custody)
        with journal.invocation():
            with self.assertRaises(BlockingIOError):self.call('reconcile')
        journal.compare_and_save(row,{**row,'state':'RUNNING'})
        with self.assertRaises(Exception):journal.compare_and_save(row,row)
    def test_wrong_mode_and_retained_bundle_drift_are_fail_closed(self):
        for args in ([],['auto'],['step','extra'],['review']):
            with self.assertRaises(e.c.Denied):op.execute(e,self.manifest,self.case,self.control_hash,custody,args)
        path=Path(self.case['nativeInputsPath']);path.chmod(0o600);path.write_bytes(e.c.encoded({'foreign':'bundle'}));path.chmod(0o400)
        with self.assertRaises(e.c.Denied):self.call('preflight')
        self.assertFalse(self.target.exists())

    def peers(self):
        case=self
        class PeerPorts(Ports):
            effects=[];fail_read=False
            def __init__(self,action,journal,review,packet,human):self.action=action;self.scope=e.c.scope(review)
            def guard_current(self,stage):
                self.action.guard(e.c.AUTHORITY_KEY,self.scope)
                if self.fail_read:raise e.c.ReadTransient(0)
            def apply(self,stage):self.effects.append(stage['name'])
            def observe(self,stage):return 'APPLIED',{'syntheticObservation':True}
            def close(self):pass
            def boot(self):return 'synthetic-fixture-boot'
        return PeerPorts
    def test_lost_initialization_reply_reconciles_the_existing_empty_journal(self):
        self.review();self.approve();original=e.execute
        def lose(*args):original(*args);raise OSError('synthetic lost initialization response')
        with patch.object(e,'execute',side_effect=lose),self.assertRaises(OSError):self.call('initialize')
        with patch.object(e,'execute')as dispatch:
            result=self.call('reconcile');dispatch.assert_not_called()
        self.assertTrue(result['reconciledControlOnly']);self.assertEqual(self.call('status')['state'],'INITIALIZED')
        with self.assertRaises(e.c.Denied):self.call('initialize')
        self.assertEqual(len(list(self.root.glob('ingestion-readiness-patch-*.claim.json'))),1)
    def test_lost_applied_stage_reply_never_repeats_effect_and_sequence_completes(self):
        self.review();self.approve();self.call('initialize');peers=self.peers();original=e.execute
        with patch.object(e,'NativePorts',peers):
            self.call('step')
            def lose(*args):original(*args);raise OSError('synthetic lost applied response')
            with patch.object(e,'execute',side_effect=lose),self.assertRaises(OSError):self.call('step')
            self.assertEqual(peers.effects,['IMPORT_INGESTION_IMAGE'])
            with patch.object(e,'execute')as dispatch:
                recovered=self.call('reconcile');dispatch.assert_not_called()
            self.assertEqual(recovered['nextStage'],2);self.assertEqual(peers.effects,['IMPORT_INGESTION_IMAGE'])
            for _ in range(11):result=self.call('step')
            self.assertTrue(result['complete']);self.assertEqual(self.call('status')['state'],'COMPLETE')
            self.assertEqual(len(peers.effects),8)
            with self.assertRaises(e.c.Denied):self.call('step')
            self.assertEqual(len(peers.effects),8)
    def test_unclaimed_interrupted_read_reconciles_to_durable_backoff_without_reset(self):
        self.review();self.approve();self.call('initialize');peers=self.peers();peers.fail_read=True
        with patch.object(e,'NativePorts',peers):
            with patch.object(e.Runner,'retry_read',side_effect=OSError('synthetic interruption before backoff publication')),self.assertRaises(OSError):self.call('step')
            self.assertEqual(self.call('status')['readAttempts'],1)
            peers.fail_read=False;result=self.call('reconcile')
        self.assertTrue(result['reconciledControlOnly']);row=e.Journal(self.target).read()
        self.assertEqual(row['readAttempts'],1);self.assertEqual(row['readState'],'RETRY_WAIT')
        self.assertEqual(row['effects'],[]);self.assertEqual(peers.effects,[])
        self.assertGreater(row['nextReadAt'],fixture.time.time())
    def test_status_does_not_authenticate_or_open_an_expired_human_profile(self):
        self.review();self.approve();self.call('initialize')
        human=self.fixture.human;row=human.journal.read()
        human.journal.compare_and_save(row,{**row,'accessExpiresAt':0,'version':row['version']+1})
        with patch.object(e.human_reader,'open_existing')as opened:
            self.assertEqual(self.call('status')['state'],'INITIALIZED');opened.assert_not_called()
        with patch.object(e,'execute')as dispatch,self.assertRaises(e.c.Denied):self.call('step')
        dispatch.assert_not_called()

if __name__=='__main__':unittest.main()
