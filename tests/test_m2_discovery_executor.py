"""Real parent/child Ed25519 and journals; phase/admission effects synthetic."""
import copy,hashlib,sys,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_parent_authority as parent_fixture
from tools.m2_discovery_installation_profile import executor as m
from tools.semantic_lease_recovery.recovery_journal import Journal
from cutover_executor import Executor,CutoverDenied
from cutover_authority import CutoverAuthority
from transition_journal import Transition,PHASES


def fixture_component(root,bindings):
    gateway={'schema':'ouf.discovery-gateway-runtime-component.v2',
        'runtime':{'profile':'ouf.chatbot-file-cohort.gateway-runtime.v1','planHash':'1'*64,
            'oldContainerId':'2'*64,'sameImageId':'sha256:'+'3'*64,'proposalKeyHash':'4'*64,
            'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False},
        'journalDirectory':str(root/'gateway-journal'),'sameRegistryParentAndChildRequired':True,
        'historicalRecoveryAdoptionAllowed':False,'automaticReplayAllowed':False,
        'maximumDispatchAttemptsPerStep':1,'dispatchIndependentOfMutableJournal':True}
    mcp={'schema':'ouf.discovery-mcp-replacement-component.v1','planHash':'5'*64,
        'imageId':'sha256:'+'6'*64,'oldContainerId':'7'*64,'journalDirectory':str(root/'mcp-journal'),
        'readinessDirectory':str(root/'mcp-readiness'),'sameRegistryParentAndChildRequired':True,
        'historicalRecoveryAdoptionAllowed':False,'automaticReplayAllowed':False,'budgetReset':False}
    return {'schema':'ouf.discovery-cohort-installation-scope.v1',**bindings,
        'images':{'schema':'synthetic-image-scope-not-admission'},'gatewayRuntime':gateway,'mcp':mcp,
        'currentAdmission':{'schema':'synthetic-inert-not-admission'},
        'requiresFullCurrentCohortBeforeRelease':True,'automaticReplayAllowed':False,'budgetReset':False}


class DiscoveryExecutor(unittest.TestCase):
    def fixture(self,mutate=None,construct=True):
        case=parent_fixture.Parent();case.setUp();self.addCleanup(case.doCleanups)
        intents={p:{'syntheticPhase':p} for p in PHASES}
        child,raw=case.child(creation_request_hash=m.digest(intents['CREATE_REPLACEMENT']),
            phase_intent_hashes={p:m.digest(v) for p,v in intents.items()})
        component=fixture_component(case.root,{k:case.review[k] for k in
            ('sourceClosureHash','installationInputsHash','desiredProfileHash')})
        case.review['components']['cohortInstallation']=component
        value=m.decode(raw);value.update(copy.deepcopy(m.runtime_sections(component)))
        if mutate:mutate(value)
        raw=parent_fixture.m.encoded(value)
        human=m.decode(Path(child.binding['path']).read_bytes());human['executionAuthorityHash']=hashlib.sha256(raw).hexdigest()
        case.write(Path(child.binding['path']),parent_fixture.m.encoded(human));binding=case.binding(Path(child.binding['path']))
        child=CutoverAuthority(case.verifier,binding,binding['sha256'],case.context,child.expected,lambda:case.now)
        case.review['components']['registryCutover']={'schema':'ouf.discovery-registry-child-scope.v1',
            'authorityHash':hashlib.sha256(raw).hexdigest(),'humanManifestHash':binding['sha256'],**child.expected}
        for role in ('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'):case.sign(raw,role)
        parent=case.fixture();root=case.root/'executor-journal';root.mkdir(mode=0o700);journal=Journal(root)
        initial=Transition.initial(hashlib.sha256(raw).hexdigest(),child.expected['creationRequestHash'],
            child.expected['predecessorHistoryHash'],child.expected['predecessorIncidentRef'])
        journal.initialize(initial);transition=Transition(journal,initial['contextHash']);calls=[]
        def checkpoint(phase,point,row):return {'schema':'ouf.semantic-cutover-native-checkpoint.v1',
            'phase':phase,'point':point,'journalVersion':row['version'],'intentHash':m.digest(intents[phase]),
            'authorityHash':hashlib.sha256(raw).hexdigest(),'sourceClosureHash':child.expected['sourceClosureHash'],
            'nativeEvidenceHash':'f'*64}
        adapters={p:SimpleNamespace(apply=lambda intent,p=p:calls.append(p),
            observe=lambda intent:('APPLIED',{'syntheticNativeEffect':True})) for p in PHASES}
        args=(transition,raw,child,checkpoint,adapters,intents,lambda:case.now)
        return (m.DiscoveryExecutor(*args,parent=parent) if construct else args),calls,case,parent,transition

    def test_current_parent_bound_sections_execute_and_repeat_does_not_replay(self):
        owner,calls,_,_,_=self.fixture();owner.run(1);owner.run(1)
        self.assertEqual(calls,[PHASES[0]])
        self.assertEqual(owner.additional_authority_fields(),{'gatewayRuntimeInstallation','discoveryMcpInstallation'})

    def test_legacy_executor_still_rejects_discovery_extensions_before_claim(self):
        args,calls,_,_,transition=self.fixture(construct=False)
        with self.assertRaisesRegex(CutoverDenied,'EXACT_CUTOVER_AUTHORITY_SCOPE_REQUIRED'):Executor(*args).run(1)
        self.assertEqual(calls,[]);self.assertEqual(transition.read()['version'],0)

    def test_signed_mcp_section_different_from_parent_is_rejected_before_claim(self):
        with self.assertRaisesRegex(ValueError,'SIGNED_DISCOVERY_RUNTIME_SECTIONS'):
            self.fixture(lambda a:a['discoveryMcpInstallation'].update(planHash='f'*64))

    def test_unknown_signed_field_still_denied_before_claim(self):
        owner,calls,_,_,transition=self.fixture(lambda a:a.update(unreviewedScope=True))
        with self.assertRaisesRegex(CutoverDenied,'EXACT_CUTOVER_AUTHORITY_SCOPE_REQUIRED'):owner.run(1)
        self.assertEqual(calls,[]);self.assertEqual(transition.read()['version'],0)

    def test_parent_revocation_after_construction_denies_before_first_effect(self):
        owner,calls,case,parent,transition=self.fixture()
        case.write(Path(parent.binding['path']),b'REVOKED_SYNTHETIC_DISCOVERY_PARENT')
        with self.assertRaisesRegex(ValueError,'DISCOVERY_PARENT_HUMAN_DECISION_CHANGED'):owner.run(1)
        self.assertEqual(calls,[]);self.assertEqual(transition.read()['version'],0)

    def test_changed_parent_component_denies_without_native_work(self):
        owner,calls,_,parent,transition=self.fixture();parent.review['components']['cohortInstallation']['mcp']['planHash']='f'*64
        with self.assertRaisesRegex(ValueError,'DISCOVERY_EXECUTOR_PARENT_CHILD_OR_COMPONENT_DRIFT'):owner.run(1)
        self.assertEqual(calls,[]);self.assertEqual(transition.read()['version'],0)


if __name__=='__main__':unittest.main()
