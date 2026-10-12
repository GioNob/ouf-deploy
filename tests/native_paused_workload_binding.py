"""Real Docker pause + runc paused state, with journal-bound prior Stage proof.
No complete OCI/rootfs/peer/attestation proof, Semantic JVM, or target operation.
"""
import json,shutil,subprocess,sys,unittest
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

if __name__=='__main__':unittest.main()
