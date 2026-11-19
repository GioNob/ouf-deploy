"""Real Docker pause + runc paused state, with journal-bound prior Stage proof.
No complete OCI/rootfs/peer/attestation proof, Semantic JVM, or target operation.
"""
import copy,json,shutil,subprocess,sys,unittest
from types import SimpleNamespace
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
import native_runtime_executor as runtime_fixture
from paused_workload_binding import PausedWorkloadBinding
from transition_journal import digest

class NativeBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):runtime_fixture.NativeRuntime.setUpClass();cls.image=runtime_fixture.NativeRuntime.image
    def fixture(self):
        e,engine,store=runtime_fixture.NativeRuntime.fixture(self);e.run(6)
        row=e.t.read()
        with e.t.invocation():e.t.begin('ATTEST_NEW_OCI_PEER',e.intent_hashes['ATTEST_NEW_OCI_PEER'],e.authority_hash,row['version'])
        return e,engine,store,PausedWorkloadBinding(engine,e.t,e.intents['CREATE_REPLACEMENT'],store)
    def test_real_runc_status_is_paused_while_engine_is_paused_and_unpause_denies(self):
        e,engine,store,b=self.fixture();observed=b.observe();cid=observed['runtimeBinding']['containerId'];state=None
        binary=str(Path(shutil.which('runc')).resolve())
        # Disposable fixture inventory only, not target runtime path discovery.
        for root in ('/run/docker/runtime-runc/moby','/run/containerd/runc/moby'):
            p=subprocess.run(['sudo',binary,'--root',root,'state',cid],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            if p.returncode==0:
                state=json.loads(p.stdout);break
        self.assertIsNotNone(state,'NATIVE_FIXTURE_RUNC_STATE_UNPROVEN')
        self.assertEqual(state['status'],'paused');proof=b.verify_runc_state(state,observed)
        self.assertFalse(proof['completeCreationAccepted']);self.assertEqual(e.t.read()['nextPhase'],6)
        status,_=engine.request('POST','/v1.44/containers/'+cid+'/unpause');self.assertEqual(status,204)
        with self.assertRaises(ValueError):b.observe()
    def test_corrupted_native_stage_payload_blocks_current_paused_process(self):
        e,engine,store,b=self.fixture();cid=engine.inspect(e.t)['Id']
        store.path('STAGE_PAUSED_REPLACEMENT').write_bytes(b'{}')
        with self.assertRaises(ValueError):b.observe()
        actual=engine.inspect(e.t);self.assertEqual(actual['Id'],cid);self.assertTrue(actual['State']['Paused'])
        self.assertEqual(e.t.read()['nextPhase'],6)
    def test_real_pause_survives_both_retained_checkpoints_synthetic_acceptance_metadata(self):
        # This component test does NOT issue/verify node acceptance or migrate
        # a database: only its phase metadata is synthetic, explicitly below.
        e,engine,store,original=self.fixture();intent=e.intent_hashes['ATTEST_NEW_OCI_PEER']
        receipt={'schema':'ouf.semantic-owner-signed-paused-node-phase.v1','transitionContextHash':e.t.context,
            'creationRequestHash':e.t.read()['creationRequestHash'],'intentHash':intent,
            'completeNativeObservationPerformed':True,'currentScopedAcceptanceSignatureVerified':True}
        store.publish('ATTEST_NEW_OCI_PEER',receipt)
        # NativeRuntime has the legacy thirteen-phase transport profile. This
        # component supplies synthetic eleven-phase FILE_ONLY cursor metadata;
        # the six real Docker evidence records/container remain unchanged.
        prefix=copy.deepcopy(e.t.read()['effects'][:6])
        accepted={'phase':'ATTEST_NEW_OCI_PEER','state':'APPLIED','intentHash':intent,
            'authorityEvidenceHash':e.authority_hash,'nativeEvidenceHash':digest(receipt)}
        for cursor,phase in((7,'ADMIT_MIGRATION'),(8,'START_REPLACEMENT')):
            effects=copy.deepcopy(prefix)+[copy.deepcopy(accepted)]
            if cursor==8:effects.append({'phase':'ADMIT_MIGRATION','state':'APPLIED','intentHash':e.intent_hashes['ADMIT_MIGRATION'],
                'authorityEvidenceHash':e.authority_hash,'nativeEvidenceHash':digest({'syntheticMigrationMetadata':True})})
            effects.append({'phase':phase,'state':'IN_FLIGHT','intentHash':e.intent_hashes[phase],'authorityEvidenceHash':e.authority_hash})
            row={**e.t.read(),'state':'IN_FLIGHT','nextPhase':cursor,'version':2*cursor+1,'effects':effects}
            checkpoint=SimpleNamespace(context=e.t.context,read=lambda:copy.deepcopy(row))
            original=PausedWorkloadBinding(engine,checkpoint,e.intents['CREATE_REPLACEMENT'],store)
            with self.assertRaises(ValueError):original.observe()
            retained=PausedWorkloadBinding.retained_at_checkpoint(engine,checkpoint,e.intents['CREATE_REPLACEMENT'],store,
                attestation_intent_hash=intent,checkpoint_row=row)
            observed=retained.observe();cid=observed['runtimeBinding']['containerId']
            state=None;binary=str(Path(shutil.which('runc')).resolve())
            for root in('/run/docker/runtime-runc/moby','/run/containerd/runc/moby'):
                p=subprocess.run(['sudo',binary,'--root',root,'state',cid],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                if p.returncode==0:state=json.loads(p.stdout);break
            self.assertIsNotNone(state);self.assertFalse(retained.verify_runc_state(state,observed)['completeCreationAccepted'])
            self.assertTrue(engine.inspect(e.t)['State']['Paused'])
        status,_=engine.request('POST','/v1.44/containers/'+cid+'/unpause');self.assertEqual(status,204)
        with self.assertRaises(ValueError):retained.observe()

if __name__=='__main__':unittest.main()
