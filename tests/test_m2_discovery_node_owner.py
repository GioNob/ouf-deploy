"""Actual finite HUMAN fixture/dual Ed25519 gate; native Engine is not executed."""
import copy,json,sys,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from test_m2_discovery_native_profile import fixture
from test_m2_discovery_frame_observation import DenyOwnerFixture
import test_cutover_authority_native as signed
from test_cutover_authority_native import encoded,sha
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile
from tools.m2_discovery_installation_profile import node_owner as n

class NodeOwner(unittest.TestCase):
    setUp=signed.SignedCutover.setUp
    native=signed.SignedCutover.native
    write=signed.SignedCutover.write
    binding=signed.SignedCutover.binding
    sign=signed.SignedCutover.sign
    gate=signed.SignedCutover.gate
    # Reuse genuine protected keys, verifier, policy and HUMAN fixture setup.
    # No production authority or secret is read, issued or used.
    def prepared(self, wrong_intent=False):
        r,s,t,l,c=fixture();p=DiscoveryProfile(r,**s);self.expected['creationRequestHash']=n.digest(r)
        recipe={'schema':'ouf.semantic-discovery-node-recipe.v1','executionProfileHash':p.sha256,
            'sourceClosureHash':self.expected['sourceClosureHash'],'qualifiedPackageHash':'3'*64,
            'imageConfigurationHash':'4'*64,'expectedRootfsSeal':{'schema':'ouf.semantic-rootfs-seal.v1','sha256':'5'*64,'entries':3,'bytes':64},
            'template':t,'launch':l,'dockerContext':c,'runtimeRoot':'/fixture/runtime','observationConfiguration':{},
            'frameSourceBinding':{},'transactionId':'7'*64,'observationSeconds':10}
        intent={'creationRequestHash':n.digest(r),'sourceClosureHash':recipe['sourceClosureHash'],
            'qualifiedPackageHash':recipe['qualifiedPackageHash'],'imageConfigurationHash':recipe['imageConfigurationHash'],
            'nodeRecipeHash':n.digest(recipe)}
        raw={'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in self.expected.items() if k!='intakeHash'},
            'issuedAt':self.now,'expiresAt':self.now+120,'phaseIntentHashes':{phase:'a'*64 for phase in n.DISCOVERY_PHASES},
            'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False,'newDistinctLeaseWorkerRequired':True}
        raw['phaseIntentHashes'][n.PHASE]='f'*64 if wrong_intent else n.digest(intent)
        self.authority=encoded(raw);self.approval.update(**self.expected,executionAuthorityHash=sha(self.authority))
        self.write(self.mandate,encoded(self.approval));self.approved=sha(self.mandate.read_bytes())
        for role in self.grant['roles']:self.sign(role)
        authority=self.gate()
        signer=n.ExistingEd25519Signer(self.binding(self.key),'synthetic-fixture-attestor-key',self.verifier,
            {'role':'CREATION_ATTESTATION','issuerRef':self.context['attestorRef'],'installationRef':self.context['installationRef'],'entityRef':self.context['entityRef']})
        directory=self.root/'node';directory.mkdir(mode=0o700)
        evidence=self.root/'evidence';evidence.mkdir(mode=0o700);store=n.NativeEvidenceStore(evidence)
        row={'state':'IN_FLIGHT','creationRequestHash':n.digest(r),'effects':[{'phase':n.PHASE,'intentHash':n.digest(intent),'state':'IN_FLIGHT'}]}
        transition=types.SimpleNamespace(execution_profile=None,phases=n.DISCOVERY_PHASES,read=lambda:copy.deepcopy(row))
        args=(object.__new__(n.Engine),transition,r,intent,store,p,DenyOwnerFixture(),authority,self.authority,self.verifier,signer,recipe,directory)
        return args,row

    def test_discovery_current_guard_uses_actual_dual_signature_without_signing_or_engine_effects(self):
        args,row=self.prepared();o=n.DiscoveryNodeOwner(*args)
        self.assertEqual(o.current(args[3]),row)
        self.assertEqual(list(o.root.iterdir()),[])

    def test_fully_signed_other_phase_intent_cannot_authorize_this_node(self):
        args,_=self.prepared(wrong_intent=True)
        with self.assertRaisesRegex(ValueError,'SIGNED_FULL_DISCOVERY_NODE_INTENT'):n.DiscoveryNodeOwner(*args)

    def test_changed_recipe_is_rejected_before_native_or_signature_issuance(self):
        args,_=self.prepared();o=n.DiscoveryNodeOwner(*args);o.recipe['transactionId']='8'*64
        with self.assertRaisesRegex(ValueError,'SCOPE_DRIFT'):o.current(args[3])
        self.assertEqual(list(o.root.iterdir()),[])

    def test_missing_current_role_signature_stops_node_before_effects(self):
        args,_=self.prepared();o=n.DiscoveryNodeOwner(*args)
        (self.signatures/(sha(self.authority)+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
        with self.assertRaises((signed.PreexecDenied,signed.AuthorityDenied,FileNotFoundError)):o.current(args[3])
        self.assertEqual(list(o.root.iterdir()),[])

    def test_expired_human_window_stops_node_before_effects(self):
        args,_=self.prepared();o=n.DiscoveryNodeOwner(*args);self.now+=121
        with self.assertRaisesRegex(signed.AuthorityDenied,'SIGNED_AUTHORITY_WITHIN_HUMAN_WINDOW_REQUIRED'):o.current(args[3])
        self.assertEqual(list(o.root.iterdir()),[])

    def test_file_only_transition_cannot_enter_discovery_signing_path(self):
        args,_=self.prepared();args[1].execution_profile=object()
        with self.assertRaisesRegex(ValueError,'SIGNING_CONTEXT'):n.DiscoveryNodeOwner(*args)

if __name__=='__main__':unittest.main()
