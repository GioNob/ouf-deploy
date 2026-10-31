"""Original material/current signatures; paused native/Java lineage modeled.

Read-only operational handoff is exercised at exact phase9/10 after phase8.
Initial provider expiry remains an independent negative control, without reset.
"""
import copy,fcntl,hashlib,os,sys,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_current_worker as fixtures
from tools.m2_discovery_installation_profile import paused_operational_worker as m
from tools.semantic_provider_preexec import PreexecDenied


class PausedWorker(unittest.TestCase):
    def prepared(self,phase='ADMIT_MIGRATION'):
        case=fixtures.CurrentWorker();base,w,auth,observed,calls=case.prepared();self.addCleanup(case.doCleanups)
        original=w.transition.read()['effects'][0]
        app=object.__new__(m.DiscoveryApplication);app.node_owner=w.node;app.transition=w.transition;app.store=w.store
        app.authority=w.authority;app.raw=w.authority_raw;app.discovery_parent=w.parent;app.infrastructure_owners={m.PHASE:w}
        app.verify_scope=Mock(side_effect=lambda:w.parent.guard('operationalLeaseInstallation',w.component))
        app.intent_hashes={p:m.digest({'modeledIntent':p}) for p in m.PHASES};app.intent_hashes[m.PHASE]=w.intent_hash
        effects=[{'phase':p,'state':'APPLIED','intentHash':app.intent_hashes[p],'nativeEvidenceHash':'e'*64}
            for p in m.PHASES[:m.PHASES.index(phase)+1]]
        effects[m.PHASES.index(m.PHASE)]=copy.deepcopy(original);effects[-1]['state']='IN_FLIGHT'
        row={'state':'IN_FLIGHT','nextPhase':m.PHASES.index(phase),'effects':effects,'version':42,'creationRequestHash':w.request_hash}
        w.transition.read.return_value=copy.deepcopy(row)
        native=patch.object(w.node,'verify_retained',return_value={'modeledPausedNodeAcceptance':True});native.start();self.addCleanup(native.stop)
        return m.PausedOperationalWorker(app),w,auth,observed,calls,row

    def test_normal_handoff_at_both_paused_gates_keeps_original_expired_initial_gate(self):
        reader,w,auth,_,calls,row=self.prepared();auth.now+=86;before=list(calls)
        snapshot=m.read_installed_material(w,m.ObservationBudget(30))[2]
        with self.assertRaises(PreexecDenied):w.provider.current(snapshot)
        fd=os.open(w.template['configurationTemplate']['commonInvocationLock'],os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(w.provider,'current',side_effect=AssertionError('INITIAL_GATE_REENTRY_FORBIDDEN')), \
                 patch.object(w.signer,'sign',side_effect=AssertionError('SIGNING_FORBIDDEN')):
                first=reader.observe('ADMIT_MIGRATION','BEFORE_NATIVE_EFFECT',row)
                row['effects'][-1]['state']='APPLIED';row['effects'].append({'phase':'START_REPLACEMENT','state':'IN_FLIGHT',
                    'intentHash':reader.app.intent_hashes['START_REPLACEMENT'],'nativeEvidenceHash':'f'*64})
                row['nextPhase']=10;row['version']+=1;w.transition.read.return_value=copy.deepcopy(row)
                second=reader.observe('START_REPLACEMENT','BEFORE_UNPAUSE',row)
        finally:os.close(fd)
        for proof in (first,second):
            self.assertTrue(proof['currentSignedOperationalInstallationVerified']);self.assertTrue(proof['currentWorkerAndPositiveOwnedLeasesObserved'])
            for key in ('initialProviderMandateExtended','newGenerationAuthorized','fullCohortProven','runtimeAuthorityIssued','targetApplyAuthorized','budgetReset','releaseAcceptance'):
                self.assertIs(proof[key],False)
        self.assertEqual(calls,before)

    def test_wrong_point_cursor_or_incomplete_worker_phase_denies_before_native_read(self):
        reader,w,_,_,_,row=self.prepared()
        for phase,point,change in [('ADMIT_MIGRATION','BEFORE_UNPAUSE',lambda r:None),
            ('VERIFY_APPLICATION','BEFORE_NATIVE_EFFECT',lambda r:None),
            ('ADMIT_MIGRATION','BEFORE_NATIVE_EFFECT',lambda r:r.update(state='READY')),
            ('ADMIT_MIGRATION','BEFORE_NATIVE_EFFECT',lambda r:r['effects'][8].update(state='IN_FLIGHT'))]:
            bad=copy.deepcopy(row);change(bad);w.transition.read.return_value=bad
            with self.subTest(point=point,phase=phase),self.assertRaises(ValueError):reader.observe(phase,point,bad)
        w.node.verify_retained.assert_not_called()

    def test_quiesced_worker_after_completed_installation_is_not_restarted(self):
        reader,_,_,observed,calls,row=self.prepared();before=list(calls);observed['workerCheckpointActive']=False
        with self.assertRaisesRegex(ValueError,'PAUSED_OPERATIONAL_WORKER_AND_POSITIVE_LEASES'):reader.observe('ADMIT_MIGRATION','BEFORE_NATIVE_EFFECT',row)
        self.assertEqual(calls,before)

    def test_expired_parent_denies_paused_continuation(self):
        reader,w,auth,_,_,row=self.prepared();auth.now+=121
        with self.assertRaises(ValueError):reader.observe('ADMIT_MIGRATION','BEFORE_NATIVE_EFFECT',row)
        w.node.verify_retained.assert_not_called()

    def test_retained_native_denial_is_not_retried_or_repaired(self):
        reader,w,_,_,calls,row=self.prepared();before=list(calls)
        w.node.verify_retained.side_effect=ValueError('CURRENT_PAUSED_NODE_UNPROVEN')
        with self.assertRaisesRegex(ValueError,'PAUSED_NODE_UNPROVEN'):reader.observe('ADMIT_MIGRATION','BEFORE_NATIVE_EFFECT',row)
        w.node.verify_retained.assert_called_once();self.assertEqual(calls,before)

    def test_installed_signature_revocation_denies_after_initial_gate_expiry(self):
        reader,w,auth,_,_,row=self.prepared();auth.now+=86
        root=Path(w.template['installationRoot']);raw=(root/'installed.json').read_bytes()
        (root/'receipt-signatures'/(hashlib.sha256(raw).hexdigest()+'.CREATION_ATTESTATION.json')).unlink()
        with self.assertRaises((OSError,PreexecDenied)):reader.observe('ADMIT_MIGRATION','BEFORE_NATIVE_EFFECT',row)

if __name__=='__main__':unittest.main()
