"""Real root CAS/two-role authority; synthetic HUMAN and runtime peers.

The separate platform suite must prove actual Docker/readiness/PG transports.
These units never claim current target admission or production authority.
"""
import copy,hashlib,json,os,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_readiness_patch_stage8_live_inputs as fixture
from tools.ingestion_readiness_patch_execution import stage8_continuation as control,runtime_stage8 as loader
from tools.ingestion_readiness_patch_execution import entry_v2 as e
from test_ingestion_rollout_gateway_transport import binding


@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','root private fixtures required')
class Continuation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.LiveInputs.setUpClass()
        sources={n:(ROOT/loader.SOURCE_PATHS[n]).read_bytes()for n in loader.MODULES}
        pins={n:'1'*40 for n in ('ouf-deploy','ouf-onboarding','ouf-ingestion-runtime','ouf-api-gateway')}
        cls.manifest=loader.declaration('1'*40,sources,(ROOT/'tools/ingestion_readiness_patch_execution/runtime_stage8.py').read_bytes(),pins)
    def setUp(self):
        self.l=fixture.LiveInputs();self.l.setUp();self.addCleanup(self.l.doCleanups)
        self.f=self.l.f;self.root=self.f.root;self.boot='synthetic-fixture-boot'
        p=patch.object(control,'boot_id',return_value=self.boot);p.start();self.addCleanup(p.stop)
        j=e.Journal(self.f.target);old=j.read();j.compare_and_save(old,{**old,'bootId':self.boot,
            'nativeDirectEngineGets':127,'nativeDirectEnginePosts':5,'nativeOwnerGets':37})
        self.l.case['expectedSnapshot']=fixture.live.stopped_patch_snapshot.inspect(self.l.case['snapshotCase'])
        receipt=self.l.call()
        self.old=e.Journal(self.f.target).read()
        q=copy.deepcopy(self.f.case['qualification']);q['sourceHashes']=self.manifest['sourceHashes']
        self.case={'schema':control.SCHEMA,'capturePath':receipt['contextPath'],'captureHash':receipt['privateCaptureHash'],
            'expectedCaptureReceipt':receipt,'nativeDeclarationHash':e.c.digest(self.manifest),
            'controlSourceHash':self.manifest['sourceHashes'][control.__name__], 'qualification':q,
            'requiredCumulativeOAuthAttempts':304,'maximumRuntimeSeconds':900}
        p=patch.object(control,'__qualified_source_sha256__',self.case['controlSourceHash'],create=True);p.start();self.addCleanup(p.stop)
        h=self.f.fixture.human;row=h.journal.read();r=copy.deepcopy(row['governedWindowRenewal'])
        b=copy.deepcopy(row['binding']);b['retryProfile']['maximumAttempts']=304
        r['review'].update(priorOAuthAttempts=300,maximumCumulativeOAuthAttempts=304,operationBinding=control.human_operation(self.case))
        r['decision']['reviewHash']=e.c.digest(r['review'])
        h.journal.compare_and_save(row,{**row,'binding':b,'attempts':304,'governedWindowRenewal':r,'version':row['version']+1})
        profile=copy.deepcopy(self.f.fixture.profile)
        profile.update(minimumCumulativeAttempts=304,maximumCumulativeAttempts=304,expectedBinding=b,
            journal=binding(h.journal.record),governedWindowReceiptHash=e.c.digest(r))
        self.profile=self.root/'stage8-human.json';self.profile.write_bytes(e.c.encoded(profile));self.profile.chmod(0o600)
        # These GET replies and generation predicates are explicit unit peers.
        p=patch.object(control,'live_probe',return_value=14);p.start();self.addCleanup(p.stop)
        self.target=control.context(self.case)
    def call(self,*args):return control.execute(self.manifest,self.case,list(args))
    def review(self):return self.call('review',str(self.profile))
    def approve(self):
        def consent(review,summary):
            self.assertIn('quattro stadi residui',summary);self.assertIn('Nessun initialize',summary)
            now=int(time.time())
            return {'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':e.c.digest(review),
                'approvalRef':'mcp-scoped-'+e.c.digest(review)[:24]+'-'+str(now),'sourceClosureHash':review['sourceClosureHash'],
                'humanSessionHash':e.c.digest(review['authenticatedHuman']),'approvedAt':now,
                'expiresAt':min(now+900,review['absoluteExpiresAt']),'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
        with patch.object(e.authority,'terminal_consent',side_effect=consent):return self.call('approve')
    def ready(self):self.review();self.approve();return self.call('import-prefix')
    def peers(self):
        peer=self.f.peers();boot=self.boot
        peer.boot=lambda self:boot
        return peer
    def test_preflight_no_human_keys_effects_or_target_changes(self):
        with patch.object(e.human_reader,'open_existing',side_effect=AssertionError('HUMAN forbidden')):
            result=self.call('preflight')
        self.assertTrue(result['complete']);self.assertEqual(result['remainingStages'],4)
        self.assertEqual(result['engineRequests'],0);self.assertFalse(self.target.exists())
    def test_real_two_roles_import_then_only_four_remaining_stages(self):
        before={str(p):p.read_bytes()for p in self.f.target.rglob('*')if p.is_file()}
        result=self.ready();imported=e.Journal(self.target).read()
        self.assertEqual(result['nextStage'],8);self.assertEqual(imported['readAttempts'],8)
        self.assertEqual(imported['nativeDirectEngineGets'],127);self.assertEqual(imported['nativeOwnerGets'],37)
        self.assertEqual(imported['effects'],self.old['effects']);self.assertEqual(imported['createdAt'],self.old['createdAt'])
        peer=self.peers()
        with patch.object(e,'NativePorts',peer):
            for _ in range(5):result=self.call('step')
        self.assertTrue(result['complete']);self.assertEqual(peer.effects,['ingestion.RESTORE_RESTART'])
        self.assertEqual(e.Journal(self.target).read()['nextStage'],12)
        self.assertEqual(e.Journal(self.target).read()['readAttempts'],12)
        self.assertEqual(before,{str(p):p.read_bytes()for p in self.f.target.rglob('*')if p.is_file()})
        self.assertEqual(len(list(self.target.glob('*.DEPLOYMENT_INTENT.json'))),1)
        with self.assertRaises(Exception):self.call('step')
    def test_initialize_old_human_and_zero_prefix_are_denied(self):
        with self.assertRaises(Exception):self.call('initialize')
        with self.assertRaises(Exception):control.human(self.case,self.f.fixture.profile)
        self.review()
        with self.assertRaises(Exception):self.call('step')
        self.assertFalse((self.target/'recovery.json').exists())
    def test_review_and_issuance_one_use_fences_preserve_partial_failure(self):
        self.review()
        with self.assertRaises(Exception):self.review()
        with patch.object(e.authority,'issue_action',side_effect=OSError('synthetic issuance loss')):
            with self.assertRaises(OSError):self.approve()
        self.assertEqual(self.call('status')['state'],'ISSUING')
        with self.assertRaises(Exception):self.approve()
        self.assertFalse((self.target/'recovery.json').exists())
    def test_lost_import_response_reconciles_without_initializing_again(self):
        self.review();self.approve();original=control.update
        def lose(journal,**changes):
            if changes.get('state')=='IMPORTED':raise OSError('synthetic import response loss')
            return original(journal,**changes)
        with patch.object(control,'update',side_effect=lose):
            with self.assertRaises(OSError):self.call('import-prefix')
        self.assertEqual(self.call('status')['state'],'IMPORTING')
        with patch.object(e.Journal,'initialize',side_effect=AssertionError('reinitialize forbidden')):
            result=self.call('reconcile-import')
        self.assertEqual(result['nextStage'],8)
        with self.assertRaises(Exception):self.call('import-prefix')
    def test_partial_import_keeps_proof_and_blocks_replay(self):
        self.review();self.approve()
        with patch.object(e.Journal,'initialize',side_effect=OSError('synthetic partial journal')):
            with self.assertRaises(OSError):self.call('import-prefix')
        self.assertTrue((self.target/'prefix-import.json').exists())
        with self.assertRaises(Exception):self.call('import-prefix')
        with self.assertRaises(Exception):self.call('reconcile-import')
        self.assertEqual(self.call('status')['state'],'IMPORTING')
    def test_lost_completed_read_response_reconciles_without_duplicate_dispatch(self):
        self.ready();peer=self.peers();original=e.execute
        def lose(*args):original(*args);raise OSError('synthetic lost stage response')
        with patch.object(e,'NativePorts',peer):
            with patch.object(e,'execute',side_effect=lose):
                with self.assertRaises(OSError):self.call('step')
            self.assertEqual(self.call('status')['state'],'RECONCILE_REQUIRED')
            with patch.object(e,'execute',side_effect=AssertionError('dispatch forbidden')):
                result=self.call('reconcile')
        self.assertTrue(result['reconciledControlOnly']);self.assertEqual(result['nextStage'],9)
        self.assertEqual(peer.effects,[])
    def test_foreign_capture_and_prefix_counter_reset_denied(self):
        self.case['captureHash']='f'*64
        with self.assertRaises(Exception):self.call('preflight')
        self.case['captureHash']=self.case['expectedCaptureReceipt']['privateCaptureHash']
        self.ready();j=e.Journal(self.target);row=j.read();j.compare_and_save(row,{**row,'nativeOwnerGets':0})
        with patch.object(e,'execute',side_effect=AssertionError('dispatch forbidden')):
            with self.assertRaises(Exception):self.call('step')
    def test_expired_new_authority_never_becomes_restart_permission(self):
        self.ready();peer=self.peers()
        with patch.object(e,'NativePorts',peer),patch.object(e,'load_action',side_effect=ValueError('expired')):
            with self.assertRaises(Exception):self.call('step')
        self.assertEqual(peer.effects,[]);self.assertEqual(e.Journal(self.target).read()['nextStage'],8)


if __name__=='__main__':unittest.main()
