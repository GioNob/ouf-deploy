"""Real current installed signatures; native generation/worker leaves modeled.

The finite initial provider gate remains a separately tested negative control.
No new provider start, real target admission or normal-operation E2E is tested.
"""
import copy,fcntl,hashlib,os,sys,unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_worker as current
from tools.m2_discovery_installation_profile import current_operational_worker as m
from tools.semantic_provider_preexec import PreexecDenied


class OperationalWorker(unittest.TestCase):
    def prepared(self):
        case=current.CurrentWorker();base,w,auth,observed,calls=case.prepared();self.addCleanup(case.doCleanups)
        p=patch.object(m,'RunningWorkloadBinding');p.start().return_value.observe.return_value={'sameRunningRegistryFixture':True};self.addCleanup(p.stop)
        return m.CurrentOperationalWorker(base.selected),base,w,auth,observed,calls

    def test_current_signed_normal_operation_survives_initial_window_without_extending_it(self):
        reader,base,w,auth,_,calls=self.prepared();before=list(calls)
        auth.now+=86
        snapshot=reader.base.material(m.ObservationBudget(90))[2]
        with self.assertRaises(PreexecDenied):w.provider.current(snapshot)
        with patch.object(w.provider,'current',side_effect=AssertionError('INITIAL_GATE_MUST_NOT_BE_REUSED')), \
             patch.object(w.signer,'sign',side_effect=AssertionError('SIGNING_FORBIDDEN')), \
             patch.object(w.node,'verify_retained',side_effect=AssertionError('PAUSED_REENTRY_FORBIDDEN')):
            proof=reader.observe()
        self.assertTrue(proof['currentSignedOperationalInstallationVerified'])
        for key in ('initialProviderMandateExtended','newGenerationAuthorized','fullCohortProven','producerReleaseDispatched','runtimeAuthorityIssued','targetApplyAuthorized','budgetReset','releaseAcceptance'):
            self.assertIs(proof[key],False)
        self.assertEqual(calls,before)

    def test_installed_signature_is_current_and_cannot_be_replaced_by_active_worker(self):
        reader,_,w,_,_,_=self.prepared();root=Path(w.template['installationRoot'])
        raw=(root/'installed.json').read_bytes();signature=root/'receipt-signatures'/(hashlib.sha256(raw).hexdigest()+'.CREATION_ATTESTATION.json')
        signature.unlink()
        with self.assertRaises((OSError,PreexecDenied)):reader.observe()

    def test_missing_installation_commit_is_preserved_and_denied(self):
        reader,_,w,_,_,_=self.prepared();path=Path(w.template['installationRoot'])/'installed.json';path.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'OPERATIONAL_INSTALLATION_PAYLOAD_CHANGED'):reader.observe()
        self.assertEqual(path.read_bytes(),b'{}')

    def test_expired_parent_still_denies_any_installation_continuation(self):
        reader,_,_,auth,_,_=self.prepared();auth.now+=121
        with self.assertRaises(ValueError):reader.observe()

    def test_quiesced_operational_worker_has_no_positive_handoff(self):
        reader,_,_,_,observed,_=self.prepared();observed['workerCheckpointActive']=False
        with self.assertRaisesRegex(ValueError,'OPERATIONAL_WORKER_AND_POSITIVE_LEASES'):reader.observe()

    def test_held_continuation_joins_actual_signed_worker_after_initial_expiry_under_real_fences(self):
        reader,base,w,auth,_,calls=self.prepared();selected=base.selected;app=selected.installation.application
        from application_verification_adapter import ApplicationVerificationAdapter
        from tools.m2_discovery_installation_profile import running_admission
        from tools.m2_discovery_installation_profile.selected_runtime import DiscoverySelectedRuntime
        adapter=object.__new__(ApplicationVerificationAdapter)
        adapter.engine=w.node.engine;adapter.transition=w.transition;adapter.store=w.store
        adapter.request=copy.deepcopy(w.node.request);adapter.intent={'explicit':'modeled-readiness'};adapter.channel=object()
        app.request=copy.deepcopy(adapter.request);app.intents={'VERIFY_APPLICATION':copy.deepcopy(adapter.intent)}
        app.executor=SimpleNamespace(adapters={'VERIFY_APPLICATION':adapter})
        selected.images.engine=w.node.engine;selected.images.verify=lambda:{'imageBoundaryModeled':True}
        selected.images.window=SimpleNamespace(transition=w.transition)
        selected.mcp=SimpleNamespace(cohort_component={'explicit':'modeled-cohort'},
            action=SimpleNamespace(authority_hash=hashlib.sha256(w.authority_raw).hexdigest()))
        fence=w.root/'held-invocation-fixture';fence.write_bytes(b'');fence.chmod(0o600)
        @contextmanager
        def invocation():
            fd=os.open(fence,os.O_RDONLY)
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
            finally:os.close(fd)
        w.transition.invocation=invocation
        native={'schema':'ouf.discovery-current-running-registry-admission.v1','frame':{
            'sameAttestedGenerationNowRunningJava':True,'sevenCurrentMountsObserved':True,
            'currentMountedTokenAdmissionObserved':True}}
        # Registry/selected leaves are modeled; worker files, signatures,
        # clocks, journals and both independent file fences are real.
        auth.now+=86;before=copy.deepcopy(calls);row=copy.deepcopy(w.transition.read())
        fd=os.open(w.template['configurationTemplate']['commonInvocationLock'],os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(running_admission,'RunningRegistryAdmission') as registry, \
                 patch.object(w.provider,'current',side_effect=AssertionError('INITIAL_GATE_FORBIDDEN')), \
                 patch.object(w.signer,'sign',side_effect=AssertionError('SIGNING_FORBIDDEN')):
                registry.return_value.observe.return_value=native
                proof=DiscoverySelectedRuntime.observe_held(selected)
        finally:os.close(fd)
        self.assertTrue(proof['currentRunningRegistryAndOperationalWorkerObserved'])
        self.assertFalse(proof['initialProviderBarrierReentered']);self.assertFalse(proof['fullCohortProven'])
        self.assertEqual(calls,before);self.assertEqual(w.transition.read(),row)

if __name__=='__main__':unittest.main()
