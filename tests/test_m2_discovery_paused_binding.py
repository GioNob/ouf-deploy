"""Actual private evidence store and profile; phase/native records are synthetic."""
import copy,sys,tempfile,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover')]
from test_m2_discovery_native_profile import fixture
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile
from tools.m2_discovery_installation_profile.paused_binding import DiscoveryPausedWorkloadBinding as Binding
from native_evidence_store import NativeEvidenceStore
from engine_creation import Engine
from transition_journal import PHASES,digest


class PausedBinding(unittest.TestCase):
    def fixture(self,cursor,**receipt_changes):
        request,selection,*_=fixture();profile=DiscoveryProfile(request,**selection)
        temp=tempfile.TemporaryDirectory(dir=ROOT,prefix='discovery-retained-binding-');self.addCleanup(temp.cleanup)
        root=Path(temp.name);root.chmod(0o700);store=NativeEvidenceStore(root)
        context='c'*64;intent='e'*64
        receipt={'schema':'ouf.semantic-owner-signed-paused-node-phase.v1','transitionContextHash':context,
            'creationRequestHash':digest(request),'intentHash':intent,'completeNativeObservationPerformed':True,
            'currentScopedAcceptanceSignatureVerified':True,**receipt_changes}
        store.publish('ATTEST_NEW_OCI_PEER',receipt)
        effects=[{'phase':p,'state':'APPLIED' if i<cursor else 'IN_FLIGHT',
            'intentHash':intent if i==6 else 'b'*64,'authorityEvidenceHash':'a'*64,
            'nativeEvidenceHash':digest(receipt) if i==6 else 'f'*64} for i,p in enumerate(PHASES[:cursor+1])]
        row={'state':'IN_FLIGHT','nextPhase':cursor,'creationRequestHash':digest(request),'effects':effects}
        transition=types.SimpleNamespace(execution_profile=None,phases=PHASES,context=context,read=lambda:copy.deepcopy(row))
        options={'attestation_intent_hash':intent,'checkpoint_row':copy.deepcopy(row),'execution_profile':profile}
        args=(object.__new__(Engine),transition,request,store)
        return args,options,row

    def test_retained_attestation_is_available_to_transport_worker_migration_and_unpause(self):
        for cursor in (7,8,9,10):
            args,options,row=self.fixture(cursor)
            binding=Binding.retained_discovery_at_checkpoint(*args,**options)
            self.assertEqual(binding.current_row(),row)
            self.assertEqual(row['effects'][-1]['phase'],PHASES[cursor])

    def test_unaccepted_or_post_release_checkpoints_cannot_use_retained_paused_mode(self):
        for cursor in (5,6,11,12):
            args,options,row=self.fixture(cursor)
            with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_PAUSED'):
                Binding.retained_discovery_at_checkpoint(*args,**options)

    def test_missing_native_or_signature_evidence_is_not_replaced_by_a_cursor(self):
        for changes in ({'completeNativeObservationPerformed':False},{'currentScopedAcceptanceSignatureVerified':False}):
            args,options,row=self.fixture(7,**changes)
            with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_PAUSED_ATTESTATION_RECEIPT'):
                Binding.retained_discovery_at_checkpoint(*args,**options)

    def test_scope_authority_or_checkpoint_change_after_binding_is_denied(self):
        for change in ('authority','checkpoint'):
            args,options,row=self.fixture(8);binding=Binding.retained_discovery_at_checkpoint(*args,**options)
            if change=='authority':row['effects'][-1]['authorityEvidenceHash']='d'*64
            else:row['effects'][0]['state']='IN_FLIGHT'
            with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_PAUSED'):binding.current_row()

if __name__=='__main__':unittest.main()
