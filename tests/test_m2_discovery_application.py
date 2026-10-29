"""Real dual Ed25519/HUMAN fixture and durable journal; native phase effects synthetic.

Actual node/core channels are independently tested in their existing suites.
This assembly qualification does not prove provider/worker/transport admission.
"""
import copy,hashlib,importlib.util,sys,types,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
             str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_database_cutover'),
             str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as signed
import test_m2_discovery_node_owner as node_fixture
from tools.m2_discovery_installation_profile import application as m
REAL_NODE_OWNER=m.DiscoveryNodeOwner

class Assembly(unittest.TestCase):
    def setUp(self):pass
    native=signed.SignedCutover.native
    write=signed.SignedCutover.write
    binding=signed.SignedCutover.binding
    sign=signed.SignedCutover.sign
    gate=signed.SignedCutover.gate

    def fixture(self,change=None):
        signed.SignedCutover.setUp(self)
        args,_=node_fixture.NodeOwner.prepared(self)
        engine,_,request,node_intent,store,profile,token,_,_,verifier,signer,recipe,directory=args
        intents={p:{'syntheticPhase':p} for p in m.PHASES}
        intents.update(CREATE_REPLACEMENT=request,ATTEST_NEW_OCI_PEER=node_intent)
        auth={'schema':'ouf.semantic-cutover-execution-authority.v1',
            **{k:v for k,v in self.expected.items() if k!='intakeHash'},
            'issuedAt':self.now,'expiresAt':self.now+120,
            'phaseIntentHashes':{p:m.digest(i) for p,i in intents.items()},
            'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,
            'r12ReplayAuthorized':False,'newDistinctLeaseWorkerRequired':True}
        if change:change(auth)
        self.authority=signed.encoded(auth)
        self.approval.update(**self.expected,executionAuthorityHash=signed.sha(self.authority))
        self.write(self.mandate,signed.encoded(self.approval));self.approved=signed.sha(self.mandate.read_bytes())
        for role in self.grant['roles']:self.sign(role)
        authority=self.gate()
        spec=importlib.util.spec_from_file_location('assembly_fixture_journal',ROOT/'tools/semantic_lease_recovery/recovery_journal.py')
        journal_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(journal_module)
        root=self.root/'assembly-journal';root.mkdir(mode=0o700)
        journal=journal_module.Journal(root)
        initial=m.Transition.initial(signed.sha(self.authority),m.digest(request),
            self.expected['predecessorHistoryHash'],self.expected['predecessorIncidentRef'])
        journal.initialize(initial);transition=m.Transition(journal,initial['contextHash'])
        before=self.root/'before';before.mkdir(mode=0o700);before_store=m.NativeEvidenceStore(before)
        state={};calls=[];observations={}
        def owner(phase):
            def apply(intent):
                self.assertEqual(transition.read()['state'],'IN_FLIGHT')
                self.assertEqual(transition.read()['effects'][-1]['phase'],phase)
                calls.append(phase);state[phase]=True
            def observe(intent):
                return observations.get(phase,('APPLIED' if state.get(phase) else 'UNKNOWN',
                    {'syntheticNativeEvidenceOnly':True,'phase':phase,'applied':state.get(phase,False)}))
            return types.SimpleNamespace(phase=phase,transition=transition,store=store,authority=authority,
                authority_raw=self.authority,request_hash=m.digest(request),intent_hash=m.digest(intents[phase]),
                apply=apply,observe=observe)
        owners={p:owner(p) for p in m.PHASES}
        def checkpoint(phase,point,row):
            return {'schema':'ouf.semantic-cutover-native-checkpoint.v1','phase':phase,'point':point,
                'journalVersion':row['version'],'intentHash':m.digest(intents[phase]),
                'authorityHash':signed.sha(self.authority),'sourceClosureHash':self.expected['sourceClosureHash'],
                'nativeEvidenceHash':'f'*64}
        scope={'databaseContainerId':'c'*64,'databaseUser':'postgres','database':'semantic','databaseOid':44,
            'flywaySchema':'ouf_sem','flywayHistoryHash':'d'*64,
            'health':{'address':'10.233.0.13','port':8080,'path':'/actuator/health/readiness','timeoutSeconds':1}}
        captured={}
        def factory(*args,**kwargs):
            captured['owners']=args[6];captured['profile']=kwargs['execution_profile']
            self.assertEqual(set(captured['owners']),set(m.INFRASTRUCTURE_PHASES)|{
                'ATTEST_NEW_OCI_PEER','VERIFY_APPLICATION','RELEASE_PRODUCERS'})
            self.assertIsNone(kwargs['execution_profile'])
            return {**owners,**captured['owners']}
        for name,phase in (('DiscoveryNodeOwner','ATTEST_NEW_OCI_PEER'),
                           ('ApplicationVerificationAdapter','VERIFY_APPLICATION'),
                           ('ProducerReleaseAdapter','RELEASE_PRODUCERS')):
            patch=mock.patch.object(m,name,return_value=owners[phase]);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(m,'configure_owned_core',side_effect=factory);patch.start();self.addCleanup(patch.stop)
        options=dict(engine=engine,transition=transition,request=request,intents=intents,store=store,
            before_store=before_store,admin=None,retirement_channel=None,retirement_before_store=None,
            profile=profile,authority=authority,authority_raw=self.authority,verifier=verifier,
            attestation_signer=signer,token_owner=token,node_recipe=recipe,node_directory=directory,
            readiness_scope=scope,checkpoint=checkpoint,phase_checkpoint=lambda *a:None,
            backup_checkpoint=lambda *a:None,
            infrastructure_owners={p:owners[p] for p in m.INFRASTRUCTURE_PHASES})
        return options,calls,observations,owners,captured

    def test_signed_thirteen_phase_assembly_holds_before_producer_release_and_never_replays(self):
        options,calls,_,owners,captured=self.fixture();app=m.DiscoveryApplication(**options)
        self.assertEqual(calls,[])
        report=app.verify_registry_and_hold()
        self.assertEqual(calls,list(m.PHASES[:-1]));self.assertEqual(report['completedPhaseCount'],12)
        self.assertFalse(report['releaseAcceptance'])
        app.verify_registry_and_hold();self.assertEqual(len(calls),12)
        app.release_after_cohort_verification();app.release_after_cohort_verification()
        self.assertEqual(calls,list(m.PHASES))
        self.assertIs(captured['owners']['START_DISTINCT_LEASE_WORKER'],owners['START_DISTINCT_LEASE_WORKER'])

    def test_preconstructed_node_for_native_owners_must_share_all_exact_action_bindings(self):
        options,calls,*_=self.fixture()
        node=REAL_NODE_OWNER(options['engine'],options['transition'],options['request'],
            options['intents']['ATTEST_NEW_OCI_PEER'],options['store'],options['profile'],
            options['token_owner'],options['authority'],options['authority_raw'],options['verifier'],
            options['attestation_signer'],options['node_recipe'],options['node_directory'])
        with mock.patch.object(m,'DiscoveryNodeOwner',REAL_NODE_OWNER):
            app=m.DiscoveryApplication(**options,node_owner=node)
            self.assertIs(app.node_owner,node);self.assertEqual(calls,[])
            node.store=options['before_store']
            with self.assertRaisesRegex(ValueError,'SHARED_PRECONSTRUCTED_DISCOVERY_NODE_OWNER'):
                m.DiscoveryApplication(**options,node_owner=node)
            self.assertEqual(calls,[])

    def test_release_before_registry_verification_is_denied(self):
        options,calls,*_=self.fixture();app=m.DiscoveryApplication(**options)
        with self.assertRaisesRegex(ValueError,'REGISTRY_VERIFIED'):
            app.release_after_cohort_verification()
        self.assertEqual(calls,[]);self.assertEqual(app.transition.read()['version'],0)

    def test_missing_or_shared_transport_worker_owner_is_denied_before_claim(self):
        for change in ('missing','shared'):
            options,calls,_,owners,_=self.fixture()
            if change=='missing':options['infrastructure_owners'].pop(m.INFRASTRUCTURE_PHASES[0])
            else:options['infrastructure_owners'][m.INFRASTRUCTURE_PHASES[1]]=owners[m.INFRASTRUCTURE_PHASES[0]]
            with self.assertRaisesRegex(ValueError,'COMPLETE_DISTINCT_DISCOVERY'):
                m.DiscoveryApplication(**options)
            self.assertEqual(calls,[])

    def test_foreign_owner_action_or_intent_is_denied_before_claim(self):
        for field in ('transition','store','authority','authority_raw','request_hash','intent_hash','phase'):
            options,calls,_,owners,_=self.fixture()
            setattr(owners[m.INFRASTRUCTURE_PHASES[0]],field,object())
            with self.assertRaisesRegex(ValueError,'SHARED_SIGNED_DISCOVERY'):
                m.DiscoveryApplication(**options)
            self.assertEqual(calls,[])

    def test_signed_reduced_phase_set_or_no_distinct_worker_is_denied(self):
        for mutation in (lambda a:a['phaseIntentHashes'].pop('START_DISTINCT_LEASE_WORKER'),
                         lambda a:a.update(newDistinctLeaseWorkerRequired=False)):
            options,calls,*_=self.fixture(mutation)
            with self.assertRaisesRegex(ValueError,'SIGNED_THIRTEEN_PHASE'):
                m.DiscoveryApplication(**options)
            self.assertEqual(calls,[])

    def test_file_only_profile_or_transition_is_not_projected_to_discovery(self):
        options,calls,*_=self.fixture();options['profile']=object()
        with self.assertRaisesRegex(ValueError,'FULL_DISCOVERY'):
            m.DiscoveryApplication(**options)
        self.assertEqual(calls,[])

    def test_current_signature_and_expiry_are_rechecked_before_any_effect(self):
        for change in ('signature','expiry'):
            options,calls,*_=self.fixture();app=m.DiscoveryApplication(**options)
            if change=='signature':
                (self.signatures/(signed.sha(self.authority)+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
            else:self.now+=121
            with self.assertRaises((signed.AuthorityDenied,signed.PreexecDenied,FileNotFoundError)):
                app.verify_registry_and_hold()
            self.assertEqual(calls,[]);self.assertEqual(app.transition.read()['version'],0)

    def test_ambiguous_transport_holds_worker_and_application_without_replaying_effect(self):
        options,calls,observations,*_=self.fixture();app=m.DiscoveryApplication(**options)
        phase='INSTALL_AUTHENTICATED_TRANSPORT';observations[phase]=('UNKNOWN',{'syntheticAmbiguity':True})
        with self.assertRaises(RuntimeError):app.verify_registry_and_hold()
        self.assertEqual(calls,list(m.PHASES[:8]))
        with self.assertRaises(RuntimeError):app.verify_registry_and_hold()
        self.assertEqual(calls.count(phase),1)
        observations[phase]=('APPLIED',{'syntheticReconciliation':True})
        app.verify_registry_and_hold();self.assertEqual(calls,list(m.PHASES[:-1]))

    def test_mutated_profile_or_owner_is_denied_after_partial_checkpoint(self):
        options,calls,_,owners,_=self.fixture();app=m.DiscoveryApplication(**options)
        app.executor.run(1);self.assertEqual(calls,[m.PHASES[0]])
        owners['START_DISTINCT_LEASE_WORKER'].intent_hash='0'*64
        with self.assertRaisesRegex(ValueError,'SHARED_SIGNED_DISCOVERY'):
            app.verify_registry_and_hold()
        self.assertEqual(calls,[m.PHASES[0]])

if __name__=='__main__':unittest.main()
