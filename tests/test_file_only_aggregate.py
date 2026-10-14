"""Real current dual-role signatures and Journal; synthetic phase effects only."""
import copy
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
TOKEN=ROOT if (ROOT/'tools/semantic_policy_token_owner/owner_installation.py').exists() else ROOT.parent/'token-owner-installer-work'
COHORT=ROOT if (ROOT/'tools/chatbot_file_cohort/authorization.py').exists() else ROOT.parent/'cohort-delivery-work'
sys.path[:0]=[str(COHORT),str(TOKEN),str(ROOT),str(ROOT/'tests'),str(TOKEN/'tools/semantic_policy_token_owner'),
    str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_database_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_file_only_cutover as fixture
from cutover_authority import CutoverAuthority
from cutover_executor import Executor,CutoverDenied
from transition_journal import Transition,digest
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from file_only_installation import compile_scope,directory_bindings

SCOPES=('policyTokenOwnerInstallation','policyTokenOutputCustody','policyTokenLegacyRetirement',
    'policyTokenCredentialReestablishment','policyTokenAccountingGapMigration','policyTokenFirstControlledGrant',
    'policyTokenFiniteWorkerSession','tokenOwnerRuntime','applicationCohortInstallation','gatewayRoutePublication',
    'chatbotFileAuthorization','finiteActionProcess','cohortImageImport','gatewayRuntimeInstallation')

class Aggregate(unittest.TestCase):
    def fixture(self):
        helper=fixture.FileOnlyCutover();f,p,e,calls=helper.fixture();self.addCleanup(helper.doCleanups)
        scope={'schema':'ouf.semantic-file-only-installation-scope.v1','preparedHash':'1'*64,
            'creationRequestHash':digest(p.request),'executionProfileHash':p.sha256,
            'sourceClosureHash':f.expected['sourceClosureHash'],'cohortPlanHash':'2'*64,
            'phaseIntentHashes':copy.deepcopy(e.intent_hashes),'directoryPlanHash':'3'*64}
        value=json.loads(f.authority);value.update({k:{'syntheticFixtureOnly':True} for k in SCOPES})
        value['applicationRegistryCutover']=scope
        f.authority=fixture.crypto.encoded(value)
        f.approval['executionAuthorityHash']=fixture.crypto.sha(f.authority)
        f.write(f.mandate,fixture.crypto.encoded(f.approval));f.approved=fixture.crypto.sha(f.mandate.read_bytes())
        for role in f.grant['roles']:f.sign(role)
        authority=CutoverAuthority(f.verifier,f.binding(f.mandate),f.approved,f.context,f.expected,f.clock,execution_profile=p)
        action=AggregateAction(authority,f.authority,f.expected['sourceClosureHash'])
        directory=f.root/'aggregate-journal';directory.mkdir(mode=0o700);journal=Journal(directory)
        initial=Transition.initial_file_only(action.authority_hash,digest(p.request),f.expected['predecessorHistoryHash'],f.expected['predecessorIncidentRef'],p)
        journal.initialize(initial);transition=Transition(journal,initial['contextHash'],execution_profile=p)
        def checkpoint(phase,point,row):
            return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,'journalVersion':row['version'],
                'intentHash':e.intent_hashes[phase],'authorityHash':action.authority_hash,'sourceClosureHash':action.closure,
                'nativeEvidenceHash':'f'*64}
        executor=Executor(transition,f.authority,authority,checkpoint,e.adapters,e.intents,f.clock,
            aggregate_action=action,aggregate_scope=scope)
        return f,p,executor,action,scope,calls

    def test_same_aggregate_raw_and_current_human_bind_all_eleven_phases(self):
        f,p,e,action,scope,calls=self.fixture()
        e.run();self.assertEqual(calls,list(p.compiled['phaseOrder']))
        e.run();self.assertEqual(calls,list(p.compiled['phaseOrder']))
        self.assertIs(e.authenticate,action.authority);self.assertEqual(e.raw,action.raw)

    def test_aggregate_cannot_be_sliced_fake_callback_or_legacy_extra_fields(self):
        f,p,e,action,scope,calls=self.fixture()
        plain=Executor(e.t,e.raw,e.authenticate,e.checkpoint,e.adapters,e.intents,e.clock)
        with self.assertRaisesRegex(CutoverDenied,'EXACT_CUTOVER_AUTHORITY_SCOPE'):plain.run()
        with self.assertRaisesRegex(CutoverDenied,'SHARED_AGGREGATE'):
            Executor(e.t,e.raw,e.authenticate,e.checkpoint,e.adapters,e.intents,e.clock,
                aggregate_action=lambda:True,aggregate_scope=scope)
        self.assertEqual(calls,[])

    def test_registry_scope_tampering_or_current_revocation_denies_before_effect(self):
        for kind in ('scope','human'):
            with self.subTest(kind=kind):
                f,p,e,action,scope,calls=self.fixture()
                if kind=='scope':e.aggregate_scope['cohortPlanHash']='0'*64
                else:f.approval['state']='REVOKED';f.write(f.mandate,fixture.crypto.encoded(f.approval))
                with self.assertRaises(Exception):e.run()
                self.assertEqual(calls,[])

    def test_complete_prepared_scope_binds_paths_migrations_and_independent_recipe(self):
        request,db=fixture.inputs();intents={p:{} for p in fixture.PHASES};intents['CREATE_REPLACEMENT']=request
        root='/fixture/reviewed';paths={'root':root,**{k:root+'/'+k for k in ('transition','evidence','before','retirementBefore','node','backup')}}
        intents['FENCED_BACKUP']={'directory':paths['backup']}
        prepared={'schema':'ouf.semantic-file-only-installation-inputs.v1','creationRequest':request,'configtree':db,
            'intents':intents,'retirementScope':{},'nodeRecipe':{'sourceClosureHash':'a'*64},
            'readinessScope':{'databaseContainerId':'b'*64,'databaseUser':'postgres','database':'semantic','databaseOid':4,
                'flywaySchema':'ouf_sem','flywayHistoryHash':'c'*64,
                'health':{'address':'10.1.0.2','port':8080,'path':'/actuator/health/readiness','timeoutSeconds':5}},
            'postgresRuntimeBinding':{},'imageAudit':{'imageId':request['Image']},'commandBindings':{},
            'directoryPlan':paths,'cohortPlanHash':'d'*64,'adminDatabase':'postgres'}
        result=compile_scope(prepared,'a'*64)
        self.assertEqual(result['preparedHash'],digest(prepared));self.assertEqual(result['directoryPlanHash'],digest(paths))
        prepared['readinessScope']['flywayHistoryHash']='f'*64
        self.assertNotEqual(compile_scope(prepared,'a'*64)['preparedHash'],result['preparedHash'])
        prepared['directoryPlan']['node']='/different/action/node'
        with self.assertRaisesRegex(ValueError,'GROUPED_ROOT'):compile_scope(prepared,'a'*64)

if __name__=='__main__':unittest.main()
