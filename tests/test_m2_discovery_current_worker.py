"""Real original material/signatures/journals; native leaves explicitly modeled.

No host manager, kernel, Docker, current target worker or E2E is qualified here.
"""
import copy,fcntl,os,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]+[str(ROOT/'tools'/p) for p in
    ('semantic_application_cutover','semantic_frame_compiler','semantic_database_cutover','semantic_policy_token_owner',
     'semantic_lease_recovery','semantic_transaction_profiles','semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_lease_materialization as existing
from tools.m2_discovery_installation_profile import current_worker as m


class CurrentWorker(unittest.TestCase):
    def prepared(self):
        case=existing.Materialization();w,intent,auth,snapshot=case.fixture();self.addCleanup(case.doCleanups)
        phase=w.prepare_once(intent);start=phase.start
        state={'LoadState':'loaded','ActiveState':'inactive','SubState':'dead','MainPID':'0',
            'FragmentPath':start.proposal['configuration']['serviceUnitPath'],'DropInPaths':'','NeedDaemonReload':'no'}
        calls=[]
        def manager(args):
            calls.append(args)
            if args==['daemon-reload']:return b''
            if args[0]=='start':state.update(ActiveState='active',SubState='running',MainPID='12345');return b''
            return ('\n'.join(k+'='+v for k,v in state.items())+'\n').encode()
        start.manager=manager
        observed={'schema':'ouf.discovery-installed-lease-observation.v1',
            'configurationHash':m.digest(start.proposal['configuration']),'scopeHash':m.digest(start.proposal['recipe']['scope']),
            'generationRef':snapshot['generationRef'],'managerProcessId':12345,'managerProcessRunning':True,
            'workerCheckpointActive':True,'bothOwnedLeaseFamiliesPositive':True,'recoveryAttempts':1,'publications':1,
            'runtimeAuthorityIssued':False,'applicationReady':False,'containerStartAuthorized':False,'releaseAcceptance':False}
        for p in (patch.object(m,'boot_id',return_value=snapshot['bootId']),
                  patch.object(m.lease_observation,'observe',return_value=observed)):
            p.start();self.addCleanup(p.stop)
        # The existing start owner independently reads host boot via its own imported helper.
        p=patch.object(existing.m,'boot_id',return_value=snapshot['bootId']);p.start();self.addCleanup(p.stop)
        import tools.m2_discovery_installation_profile.lease_start_owner as starts
        p=patch.object(starts,'boot_id',return_value=snapshot['bootId']);p.start();self.addCleanup(p.stop)
        phase.apply(intent);outcome,retained=phase.observe(intent);self.assertEqual(outcome,'APPLIED')
        row={'state':'READY','nextPhase':12,'effects':[{'phase':m.PHASE,'state':'APPLIED','intentHash':w.intent_hash,
            'nativeEvidenceHash':m.digest(retained)}]}
        p=patch.object(w.transition,'read',return_value=copy.deepcopy(row));p.start();self.addCleanup(p.stop)
        selected=object.__new__(m.DiscoverySelectedRuntime)
        app=SimpleNamespace(node_owner=w.node,transition=w.transition,store=w.store,authority=w.authority,raw=w.authority_raw)
        selected.installation=SimpleNamespace(worker=w,application=app,provider=SimpleNamespace(runtime=SimpleNamespace(admission=w.provider)))
        selected.images=SimpleNamespace(parent=w.parent)
        selected.guard=lambda:w.parent.guard('operationalLeaseInstallation',w.component) # native selected lineage modeled
        def held(expected=None):
            current=w.transition.read();m.require(expected is None or expected==current,'FIXTURE_HELD_HISTORY_CHANGED');return current
        selected.held=held
        p=patch.object(m,'RunningWorkloadBinding');p.start().return_value.observe.return_value={'sameRunningRegistryFixture':True};self.addCleanup(p.stop)
        return m.CurrentInstalledWorker(selected),w,auth,observed,calls

    def test_current_reader_uses_original_material_and_never_reenters_paused_node(self):
        reader,w,auth,observed,calls=self.prepared();before=copy.deepcopy(calls)
        claim=(w.root/'materialization-claim.json').read_bytes();owned=(w.root/'materialization-owned.json').read_bytes()
        with patch.object(w.node,'verify_retained',side_effect=AssertionError('PAUSED_REENTRY_FORBIDDEN')), \
             patch.object(w.signer,'sign',side_effect=AssertionError('SIGNING_FORBIDDEN')):
            result=reader.observe()
        self.assertTrue(result['currentWorkerAndPositiveOwnedLeasesObserved']);self.assertTrue(result['originalMaterialAndClocksRetained'])
        for key in ('fullCohortProven','producerReleaseDispatched','runtimeAuthorityIssued','targetApplyAuthorized','budgetReset','releaseAcceptance'):
            self.assertIs(result[key],False)
        self.assertEqual(calls,before);self.assertEqual((w.root/'materialization-claim.json').read_bytes(),claim)
        self.assertEqual((w.root/'materialization-owned.json').read_bytes(),owned)

    def test_reader_does_not_take_the_running_workers_lifetime_flock(self):
        reader,w,*_=self.prepared();fd=os.open(w.template['configurationTemplate']['commonInvocationLock'],os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertTrue(reader.observe()['originalMaterialAndClocksRetained'])
        finally:os.close(fd)

    def test_quiesced_stale_scope_or_regressed_counters_cannot_prove_current_lease(self):
        reader,_,_,observed,_=self.prepared()
        for key,value in [('workerCheckpointActive',False),('bothOwnedLeaseFamiliesPositive',False),
                          ('generationRef','f'*64),('managerProcessId',12346),('publications',0)]:
            original=observed[key];observed[key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'POSITIVE_LEASES_REQUIRED'):reader.observe()
            observed[key]=original

    def test_native_worker_failure_is_not_repaired_or_retried_by_controller(self):
        reader,_,_,_,calls=self.prepared();before=copy.deepcopy(calls)
        with patch.object(m.lease_observation,'observe',side_effect=ValueError('CURRENT_LEASE_UNPROVEN')) as probe:
            with self.assertRaisesRegex(ValueError,'CURRENT_LEASE_UNPROVEN'):reader.observe()
            self.assertEqual(probe.call_count,1)
        self.assertEqual(calls,before)

    def test_changed_owned_initial_clocks_are_not_rearmed(self):
        reader,w,*_=self.prepared();claim=m.private_json(w.root/'materialization-claim.json');claim['initialTime'][1]+=1
        (w.root/'materialization-claim.json').write_bytes(m.encoded(claim))
        with self.assertRaises(ValueError):reader.observe()

    def test_changed_installed_configuration_is_preserved_and_denied(self):
        reader,w,*_=self.prepared();configuration=Path(w.template['installationRoot'])/'configuration.json'
        configuration.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'INSTALLED_CONFIGURATION_DIFFERS'):reader.observe()
        self.assertEqual(configuration.read_bytes(),b'{}')

    def test_changed_completed_sequence_cannot_replace_phase_evidence(self):
        reader,w,*_=self.prepared();path=Path(w.sequence['journalDirectory'])/'recovery.json'
        sequence=m.private_json(path);sequence['effects'][-1]['evidence']['claimHash']='f'*64
        path.write_bytes(m.encoded(sequence))
        with self.assertRaisesRegex(ValueError,'COMPLETED_PHASE_AND_MATERIAL_DIFFER'):reader.observe()

if __name__=='__main__':unittest.main()
