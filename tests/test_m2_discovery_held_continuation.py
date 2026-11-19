"""READY12 composition; native admission leaves are explicitly modeled.

The existing native/signature suites qualify the two readers independently.
These cases prove fencing and no initial-provider/effect reentry, not VPS E2E.
"""
import copy,sys,unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_selected_runtime as existing
from tools.m2_discovery_installation_profile import selected_runtime as m
from tools.m2_discovery_installation_profile import running_admission, current_operational_worker
from application_verification_adapter import ApplicationVerificationAdapter


class HeldContinuation(unittest.TestCase):
    def fixture(self):
        case=existing.SelectedRuntime();owner,calls,row=case.fixture();app=owner.installation.application
        app.node_owner=object();app.store=object();app.request={'explicit':'fixture'}
        app.intents={'VERIFY_APPLICATION':{'same':'fixture-intent'}}
        adapter=object.__new__(ApplicationVerificationAdapter)
        adapter.engine=owner.images.engine;adapter.transition=app.transition;adapter.store=app.store
        adapter.request=copy.deepcopy(app.request);adapter.intent=copy.deepcopy(app.intents['VERIFY_APPLICATION'])
        adapter.channel=object();app.executor=SimpleNamespace(adapters={'VERIFY_APPLICATION':adapter})
        owner.installation.provider_barrier=Mock(side_effect=AssertionError('INITIAL_PROVIDER_BARRIER_FORBIDDEN'))
        native={'schema':'ouf.discovery-current-running-registry-admission.v1','frame':{
            'sameAttestedGenerationNowRunningJava':True,'sevenCurrentMountsObserved':True,
            'currentMountedTokenAdmissionObserved':True}}
        operational={'schema':'ouf.discovery-current-operational-worker-admission.v1','heldHistoryHash':m.digest(row),
            'currentSignedOperationalInstallationVerified':True,'currentTwoPeerGenerationObserved':True,
            'currentWorkerAndPositiveOwnedLeasesObserved':True,'initialProviderMandateExtended':False,'newGenerationAuthorized':False}
        def registry_read():calls.append('current-registry');return copy.deepcopy(native)
        def worker_read():calls.append('operational-worker');return copy.deepcopy(operational)
        registry=SimpleNamespace(observe=Mock(side_effect=registry_read));worker=SimpleNamespace(observe=Mock(side_effect=worker_read))
        return owner,calls,row,adapter,native,operational,registry,worker

    def readers(self,registry,worker):
        stack=ExitStack()
        stack.enter_context(patch.object(running_admission,'RunningRegistryAdmission',return_value=registry))
        stack.enter_context(patch.object(current_operational_worker,'CurrentOperationalWorker',return_value=worker))
        return stack

    def no_effects(self,owner):
        for method in (owner.images.apply,owner.gateway.apply,owner.mcp.apply,owner.gateway.initialize,owner.mcp.initialize,
            owner.installation.provider_barrier,owner.installation.verify_registry_and_hold,
            owner.installation.release_after_cohort_verification):method.assert_not_called()

    def test_current_handoff_observes_only_and_never_reenters_initial_provider_barrier(self):
        owner,calls,row,_,_,_,registry,worker=self.fixture();before=copy.deepcopy(row)
        with self.readers(registry,worker):result=owner.observe_held()
        self.assertEqual(calls,['images-verify','current-registry','operational-worker','images-verify'])
        self.assertEqual(row,before);self.assertEqual(result['heldHistoryHash'],m.digest(row))
        self.assertTrue(result['currentRunningRegistryAndOperationalWorkerObserved'])
        for key in ('initialProviderBarrierReentered','initialProviderMandateExtended','fullCohortProven',
            'capabilitiesPublished','producerReleaseDispatched','runtimeAuthorityIssued','targetApplyAuthorized','budgetReset','releaseAcceptance'):
            self.assertIs(result[key],False)
        self.no_effects(owner)

    def test_occupied_transition_fence_denies_before_any_native_read(self):
        owner,calls,_,_,_,_,registry,worker=self.fixture()
        with self.readers(registry,worker),owner.images.window.transition.invocation():
            with self.assertRaises(BlockingIOError):owner.observe_held()
        self.assertEqual(calls,[]);registry.observe.assert_not_called();worker.observe.assert_not_called();self.no_effects(owner)

    def test_wrong_readiness_owner_cannot_substitute_another_engine_or_configuration(self):
        for field in ('engine','transition','store','request','intent'):
            owner,calls,_,adapter,_,_,registry,worker=self.fixture();setattr(adapter,field,object())
            with self.subTest(field=field),self.readers(registry,worker),self.assertRaisesRegex(ValueError,'SAME_INSTALLED_REGISTRY_READINESS_OWNER'):
                owner.observe_held()
            self.assertEqual(calls,[]);self.no_effects(owner)

    def test_history_drift_after_registry_read_blocks_worker_and_preserves_changed_history(self):
        owner,_,row,_,_,_,registry,worker=self.fixture()
        def drift():row['version']+=1;return {}
        registry.observe.side_effect=drift
        with self.readers(registry,worker),self.assertRaisesRegex(ValueError,'REGISTRY_HELD_HISTORY_CHANGED'):owner.observe_held()
        self.assertEqual(row['version'],43);worker.observe.assert_not_called();self.no_effects(owner)

    def test_revoked_parent_or_changed_completion_blocks_next_reader(self):
        owner,_,_,_,_,_,registry,worker=self.fixture()
        def revoke():owner.images.guard.side_effect=ValueError('PARENT_REVOKED');return {}
        registry.observe.side_effect=revoke
        with self.readers(registry,worker),self.assertRaisesRegex(ValueError,'PARENT_REVOKED'):owner.observe_held()
        worker.observe.assert_not_called();self.no_effects(owner)

    def test_unproven_registry_or_worker_never_yields_positive_handoff(self):
        for which in ('mount','lease','history','extended','newGeneration'):
            owner,_,_,_,native,operational,registry,worker=self.fixture()
            if which=='mount':native['frame']['sevenCurrentMountsObserved']=False
            elif which=='lease':operational['currentWorkerAndPositiveOwnedLeasesObserved']=False
            elif which=='history':operational['heldHistoryHash']='f'*64
            elif which=='extended':operational['initialProviderMandateExtended']=True
            else:operational['newGenerationAuthorized']=True
            with self.subTest(which=which),self.readers(registry,worker),self.assertRaisesRegex(ValueError,'CURRENT_RUNNING_REGISTRY_AND_SIGNED_OPERATIONAL_HANDOFF'):
                owner.observe_held()
            if which=='mount':worker.observe.assert_not_called()
            self.no_effects(owner)

    def test_native_denial_is_not_retried_and_fence_is_released(self):
        owner,_,_,_,_,_,registry,worker=self.fixture();worker.observe.side_effect=ValueError('LEASE_UNPROVEN')
        with self.readers(registry,worker),self.assertRaisesRegex(ValueError,'LEASE_UNPROVEN'):owner.observe_held()
        self.assertEqual(worker.observe.call_count,1);self.no_effects(owner)
        with owner.images.window.transition.invocation():pass

    def test_image_proof_drift_after_native_reads_is_denied(self):
        owner,_,_,_,_,_,registry,worker=self.fixture()
        owner.images.verify.side_effect=[{'first':'image'},{'changed':'image'}]
        with self.readers(registry,worker),self.assertRaisesRegex(ValueError,'SELECTED_IMAGE_PROOF_CHANGED'):owner.observe_held()
        self.no_effects(owner)


if __name__=='__main__':unittest.main()
