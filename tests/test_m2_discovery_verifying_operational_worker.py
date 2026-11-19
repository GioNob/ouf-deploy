"""Actual installed signatures/material; running native generation is modeled."""
import copy,fcntl,hashlib,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_paused_operational_worker as fixtures
from tools.m2_discovery_installation_profile import verifying_operational_worker as m
from tools.semantic_provider_preexec import PreexecDenied


class VerifyingWorker(unittest.TestCase):
    def prepared(self):
        case=fixtures.PausedWorker();old,w,auth,observed,calls,row=case.prepared(phase=m.PHASE)
        self.addCleanup(case.doCleanups)
        p=patch.object(m,'VerifyingRegistryBinding');running=p.start().return_value.observe
        running.return_value={'modeledSameRunningJavaGeneration':True};self.addCleanup(p.stop)
        return m.VerifyingOperationalWorker(old.app),w,auth,observed,calls,row,running

    def test_all_exact_verification_points_use_normal_handoff_after_initial_expiry_under_real_writer_fence(self):
        reader,w,auth,_,calls,row,_=self.prepared();auth.now+=86;before=copy.deepcopy(calls)
        snapshot=m.read_installed_material(w,m.ObservationBudget(30))[2]
        with self.assertRaises(PreexecDenied):w.provider.current(snapshot)
        fd=os.open(w.template['configurationTemplate']['commonInvocationLock'],os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(w.provider,'current',side_effect=AssertionError('INITIAL_GATE_FORBIDDEN')), \
                 patch.object(w.signer,'sign',side_effect=AssertionError('SIGNING_FORBIDDEN')):
                proofs=[reader.observe(m.PHASE,point,row) for point in sorted(m.POINTS)]
        finally:os.close(fd)
        for proof in proofs:
            self.assertTrue(proof['currentSignedOperationalInstallationVerified']);self.assertTrue(proof['currentWorkerAndPositiveOwnedLeasesObserved'])
            for k in ('initialProviderMandateExtended','newGenerationAuthorized','applicationReadinessProvenHere',
                'fullCohortProven','producerReleaseDispatched','runtimeAuthorityIssued','targetApplyAuthorized','budgetReset','releaseAcceptance'):
                self.assertIs(proof[k],False)
        self.assertEqual(calls,before);self.assertEqual(w.transition.read(),row);w.node.verify_retained.assert_not_called()

    def test_wrong_point_cursor_or_prefix_denies_before_running_native_observation(self):
        reader,w,_,_,_,row,running=self.prepared()
        cases=[('ADMIT_MIGRATION','BEFORE_NATIVE_EFFECT',lambda r:None),
            (m.PHASE,'BEFORE_UNPAUSE',lambda r:None),(m.PHASE,'BEFORE_NATIVE_EFFECT',lambda r:r.update(state='READY')),
            (m.PHASE,'BEFORE_NATIVE_EFFECT',lambda r:r.update(nextPhase=True)),
            (m.PHASE,'BEFORE_NATIVE_EFFECT',lambda r:r['effects'][10].update(state='IN_FLIGHT')),
            (m.PHASE,'BEFORE_NATIVE_EFFECT',lambda r:r['effects'][8].update(intentHash='f'*64))]
        for phase,point,change in cases:
            bad=copy.deepcopy(row);change(bad);w.transition.read.return_value=bad
            with self.subTest(phase=phase,point=point),self.assertRaises(ValueError):reader.observe(phase,point,bad)
        running.assert_not_called();w.node.verify_retained.assert_not_called()

    def test_changed_running_generation_denies_without_initial_gate_or_repair(self):
        reader,_,_,_,calls,row,running=self.prepared();before=copy.deepcopy(calls)
        running.side_effect=[{'modeledGeneration':1},{'modeledGeneration':2}]
        with self.assertRaisesRegex(ValueError,'HANDOFF_CHANGED_DURING_READ'):reader.observe(m.PHASE,'BEFORE_NATIVE_EFFECT',row)
        self.assertEqual(calls,before)

    def test_quiesced_worker_is_not_application_readiness_or_a_restart_request(self):
        reader,_,_,observed,calls,row,_=self.prepared();observed['workerCheckpointActive']=False;before=copy.deepcopy(calls)
        with self.assertRaisesRegex(ValueError,'VERIFYING_WORKER_AND_POSITIVE_LEASES'):reader.observe(m.PHASE,'BEFORE_NATIVE_EFFECT',row)
        self.assertEqual(calls,before)

    def test_expired_parent_denies_before_native_observation(self):
        reader,_,auth,_,_,row,running=self.prepared();auth.now+=121
        with self.assertRaises(ValueError):reader.observe(m.PHASE,'BEFORE_NATIVE_EFFECT',row)
        running.assert_not_called()

    def test_current_installation_signature_remains_mandatory_after_initial_expiry(self):
        reader,w,auth,_,_,row,_=self.prepared();auth.now+=86
        root=Path(w.template['installationRoot']);raw=(root/'installed.json').read_bytes()
        (root/'receipt-signatures'/(hashlib.sha256(raw).hexdigest()+'.CREATION_ATTESTATION.json')).unlink()
        with self.assertRaises((OSError,PreexecDenied)):reader.observe(m.PHASE,'BEFORE_NATIVE_EFFECT',row)


if __name__=='__main__':unittest.main()
