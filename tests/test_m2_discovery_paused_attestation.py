"""Discovery adapter dispatch and real scoped acceptance signatures; native reports synthetic."""
import copy,sys,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_paused_node_acceptance_native as accepted
import test_cutover_authority_native as signed
from tools.m2_discovery_installation_profile import paused_attestation as m
from tools.m2_discovery_installation_profile import node_owner
from paused_attestation_adapter import PausedAttestationAdapter as LegacyAdapter
from paused_node_observation import PausedNodeObservation as LegacyObservation

class Adapter(unittest.TestCase):
    setUp=accepted.Acceptance.setUp
    native=accepted.Acceptance.native
    write=accepted.Acceptance.write
    binding=accepted.Acceptance.binding
    sign=accepted.Acceptance.sign
    sign_node=accepted.Acceptance.sign_node
    gate=accepted.Acceptance.gate

    def args(self):
        intent={k:self.expected_node[k] for k in ('creationRequestHash','sourceClosureHash','qualifiedPackageHash','imageConfigurationHash')}
        intent['nodeRecipeHash']='b'*64
        self.expected_node.update(phaseIntentHash=m.digest(intent),transitionContextHash='e'*64)
        self.payload.update(self.expected_node);self.sign_node()
        auth=self.root/'acceptance.json';self.write(auth,self.raw)
        root=self.root/'evidence';root.mkdir(mode=0o700);store=m.NativeEvidenceStore(root)
        row={'state':'IN_FLIGHT','creationRequestHash':intent['creationRequestHash'],
            'effects':[{'phase':m.PHASE,'intentHash':m.digest(intent)}]}
        transition=types.SimpleNamespace(context='e'*64,read=lambda:copy.deepcopy(row))
        observer=object.__new__(m.DiscoveryNodeObservation)
        observer.frame=object.__new__(m.DiscoveryFrameObservation);observer.frame.bundle=lambda _:b''
        observer.observe=lambda *args:copy.deepcopy(self.report)
        request={'containerId':self.cid,**{k:self.expected_node[k] for k in ('applicationHash','artifactHash','transportHash')}}
        context={'transitionContextHash':'e'*64,'creationRequestHash':intent['creationRequestHash']}
        return (transition,intent,store,observer,self.gate(),request,context,
            {'path':str(auth),'sha256':signed.sha(self.raw)}),row

    def test_discovery_owner_uses_distinct_adapter_and_legacy_guard_still_rejects_discovery(self):
        args,_=self.args()
        self.assertIs(node_owner.PausedAttestationAdapter,m.DiscoveryPausedAttestationAdapter)
        with self.assertRaisesRegex(ValueError,'TYPED_PAUSED_NODE_OWNER_PHASE_REQUIRED'):LegacyAdapter(*args)
        adapter=m.DiscoveryPausedAttestationAdapter(*args)
        adapter.apply(args[1]);outcome,evidence=adapter.observe(args[1])
        self.assertEqual(outcome,'APPLIED');self.assertTrue(evidence['currentScopedAcceptanceSignatureVerified'])
        self.assertFalse(evidence['applicationStartAuthorized']);self.assertFalse(evidence['signaturesIssued'])

    def test_discovery_adapter_rejects_legacy_observer_before_effects(self):
        args,_=self.args();bad=list(args);bad[3]=object.__new__(LegacyObservation)
        with self.assertRaisesRegex(ValueError,'TYPED_DISCOVERY'):m.DiscoveryPausedAttestationAdapter(*bad)

    def test_missing_signature_cannot_be_replaced_by_typed_observation(self):
        args,_=self.args();adapter=m.DiscoveryPausedAttestationAdapter(*args)
        (self.signatures/(signed.sha(self.raw)+'.CREATION_ATTESTATION.json')).unlink()
        with self.assertRaises((signed.PreexecDenied,FileNotFoundError)):adapter.observe(args[1])

    def test_changed_generation_or_inflight_intent_is_not_accepted(self):
        args,row=self.args();adapter=m.DiscoveryPausedAttestationAdapter(*args)
        self.report['generation']['pid']+=1
        with self.assertRaises(ValueError):adapter.observe(args[1])
        row['effects'][-1]['intentHash']='0'*64
        with self.assertRaisesRegex(ValueError,'CURRENT_EXECUTOR'):adapter.apply(args[1])

if __name__=='__main__':unittest.main()
