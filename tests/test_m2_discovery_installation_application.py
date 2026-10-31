"""Composition/order only: native owners are explicitly modeled here.

Their signing, custody, Engine/kernel and worker sequences are separately
qualified. These cases prove no cohort/target admission or application E2E.
"""
import copy,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import Mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_transaction_profiles'),str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_database_cutover'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile import installation_application as m


class Composition(unittest.TestCase):
    def fixture(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        record=Path(temporary.name)/'sequence.json';calls=[]
        parent,engine,store,child,profile=(object() for _ in range(5))
        request={'syntheticCreation':True};row={'state':'READY','nextPhase':0}
        transition=types.SimpleNamespace(read=lambda:copy.deepcopy(row))
        node=types.SimpleNamespace(engine=engine,request=request)
        worker=object.__new__(m.WorkerMaterialization)
        worker.node=node;worker.parent=parent;worker.authority=child;worker.authority_raw=b'synthetic-child'
        worker.transition=transition;worker.store=store;worker.request_hash='a'*64;worker.phase='START_DISTINCT_LEASE_WORKER'
        worker.check_scope=Mock();worker.continue_installation=Mock(side_effect=lambda _:calls.append('worker-continuation'))
        provider=object.__new__(m.ProviderInstallationPhase);provider.parent=parent
        provider.runtime=types.SimpleNamespace(admission=object());worker.provider=provider.runtime.admission
        window=types.SimpleNamespace(parent=parent,engine=engine,transition=transition,store=store,
            child=child,raw=worker.authority_raw,profile=profile,request=request,request_hash=worker.request_hash,
            boundary=Mock(side_effect=lambda:calls.append('paused-gate-boundary')))
        provider.window=window;provider.journal=types.SimpleNamespace(record=record);provider.current=Mock()
        def apply():calls.append('provider-installation');record.write_text('synthetic-durable-sequence')
        provider.apply=Mock(side_effect=apply)
        provider.observe=Mock(side_effect=lambda:(calls.append('provider-observation') or ('APPLIED',
            {'schema':'ouf.discovery-provider-installation-sequence-complete.v1','registryGateClosedBeforeReturn':True})))
        app=object.__new__(m.DiscoveryApplication);app.node_owner=node;app.transition=transition;app.store=store
        app.authority=child;app.raw=worker.authority_raw;app.profile=profile;app.request=request;app.request_hash=worker.request_hash
        app.infrastructure_owners={worker.phase:worker};app.verify_scope=Mock();app.intents={worker.phase:{'syntheticIntent':True}}
        def run(limit):calls.append(('registry-prefix',limit));row['nextPhase']=limit
        app.executor=types.SimpleNamespace(run=Mock(side_effect=run))
        app.verify_registry_and_hold=Mock(side_effect=lambda:calls.append('registry-and-worker'))
        app.release_after_cohort_verification=Mock(side_effect=lambda:calls.append('sealed-cohort-release'))
        owner=m.DiscoveryInstallationApplication(application=app,provider=provider,worker=worker)
        return owner,calls,row,record

    def test_provider_admission_and_closed_gate_precede_registry_and_worker(self):
        owner,calls,row,_=self.fixture();owner.verify_registry_and_hold()
        self.assertEqual(calls,[('registry-prefix',m.BOUNDARY),'paused-gate-boundary',
            'provider-installation','provider-observation','registry-and-worker'])

    def test_lost_provider_result_observes_without_redispatch_or_gate_reopen(self):
        owner,calls,row,record=self.fixture();original=owner.provider.apply.side_effect
        def lose():original();raise TimeoutError('SYNTHETIC_REPLY_LOST')
        owner.provider.apply.side_effect=lose
        owner.verify_registry_and_hold();owner.verify_registry_and_hold()
        self.assertEqual(owner.provider.apply.call_count,1)
        self.assertEqual(owner.provider.window.boundary.call_count,1)
        self.assertEqual(calls.count('provider-observation'),2)

    def test_unknown_or_unclosed_provider_blocks_downstream_and_release(self):
        for outcome,closed in (('UNKNOWN',True),('APPLIED',False)):
            owner,calls,row,_=self.fixture()
            owner.provider.observe.return_value=None
            owner.provider.observe.side_effect=lambda:(outcome,{'schema':'ouf.discovery-provider-installation-sequence-complete.v1',
                'registryGateClosedBeforeReturn':closed})
            with self.assertRaisesRegex(ValueError,'CURRENT_PROVIDER'):owner.verify_registry_and_hold()
            with self.assertRaisesRegex(ValueError,'CURRENT_PROVIDER'):owner.release_after_cohort_verification()
            self.assertEqual(owner.provider.apply.call_count,1)
            self.assertNotIn('registry-and-worker',calls);self.assertNotIn('sealed-cohort-release',calls)

    def test_permanent_failure_never_advances_or_retries_in_same_invocation(self):
        owner,calls,row,_=self.fixture();owner.provider.apply.side_effect=ValueError('SYNTHETIC_INTEGRITY_DRIFT')
        with self.assertRaisesRegex(ValueError,'INTEGRITY_DRIFT'):owner.verify_registry_and_hold()
        owner.provider.observe.assert_not_called();owner.application.verify_registry_and_hold.assert_not_called()

    def test_later_registry_phase_cannot_create_a_missing_provider_sequence(self):
        owner,calls,row,_=self.fixture();row['nextPhase']=m.BOUNDARY+1
        with self.assertRaisesRegex(ValueError,'BEFORE_REGISTRY_ATTESTATION'):owner.verify_registry_and_hold()
        owner.provider.apply.assert_not_called()

    def test_scope_identity_drift_blocks_before_any_dispatch(self):
        owner,calls,row,_=self.fixture();owner.worker.provider=object()
        with self.assertRaisesRegex(ValueError,'SAME_PARENT_CHILD'):owner.verify_registry_and_hold()
        self.assertEqual(calls,[])

    def test_explicit_worker_continuation_and_cohort_release_reuse_existing_barrier(self):
        owner,calls,row,record=self.fixture();record.write_text('synthetic-existing-sequence');row['nextPhase']=8
        owner.continue_worker_installation();owner.release_after_cohort_verification()
        owner.provider.apply.assert_not_called()
        self.assertEqual(calls,['provider-observation','worker-continuation','registry-and-worker',
            'provider-observation','sealed-cohort-release'])

if __name__=='__main__':unittest.main()
