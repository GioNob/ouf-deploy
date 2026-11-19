"""Signed full worker sequence, actual files/keys/journals; native leaves synthetic."""
import copy,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_lease_attestation as attest
from tools.m2_discovery_installation_profile import lease_installation_phase as m,lease_start_owner as starts
from tools.semantic_registry_operational_owner.guard import private_json


class Sequence(unittest.TestCase):
    def fixture(self):
        f=attest.Attest();issuer,intent,auth,_,_=f.fixture(registration=True,sequence=True);self.addCleanup(f.doCleanups)
        start=issuer.start;reg=m.LeaseRegistration(issuer.installation)
        state={'LoadState':'loaded','ActiveState':'inactive','SubState':'dead','MainPID':'0',
            'FragmentPath':start.proposal['configuration']['serviceUnitPath'],'DropInPaths':'','NeedDaemonReload':'no'}
        calls=[]
        def manager(args):
            calls.append(args)
            if args==['daemon-reload']:return b''
            if args[0]=='start':state.update(ActiveState='active',SubState='running',MainPID='12345');return b''
            return ('\n'.join(k+'='+v for k,v in state.items())+'\n').encode()
        start.manager=manager
        snapshot=start.proposal['nativeObservation']
        boot=patch.object(starts,'boot_id',return_value=snapshot['bootId']);boot.start();self.addCleanup(boot.stop)
        observation={'schema':'ouf.discovery-installed-lease-observation.v1',
            'configurationHash':m.digest(start.proposal['configuration']),'scopeHash':m.digest(start.proposal['recipe']['scope']),
            'generationRef':snapshot['generationRef'],'managerProcessId':12345,'managerProcessRunning':True,
            'workerCheckpointActive':True,'bothOwnedLeaseFamiliesPositive':True,'recoveryAttempts':1,'publications':1,
            'runtimeAuthorityIssued':False,'applicationReady':False,'containerStartAuthorized':False,'releaseAcceptance':False}
        obs=patch.object(starts.lease_observation,'observe',return_value=observation);obs.start();self.addCleanup(obs.stop)
        return m.WorkerInstallationPhase(issuer=issuer,registration=reg),intent,auth,calls,state

    def test_full_ordered_worker_phase_uses_original_native_evidence_hash(self):
        owner,intent,auth,calls,state=self.fixture();owner.apply(intent)
        outcome,evidence=owner.observe(intent);self.assertEqual(outcome,'APPLIED')
        row=m.checked_row(owner.start);self.assertEqual(row['state'],'DONE')
        self.assertEqual([e['stage'] for e in row['effects']],list(m.STAGES))
        self.assertTrue(all(e['dispatches']==1 for e in row['effects']))
        self.assertEqual(calls.count(['daemon-reload']),1)
        self.assertEqual(sum(v[0]=='start' for v in calls),1)
        self.assertEqual(owner.store.read(owner.phase,m.digest(evidence)),evidence)
        self.assertEqual(evidence['workerInstallationSequenceScopeHash'],m.digest(owner.scope))
        with self.assertRaises(FileExistsError):owner.apply(intent)

    def test_lost_reload_does_not_restart_completed_signing_or_file_publication(self):
        owner,intent,auth,calls,state=self.fixture();real=owner.start.manager
        def lose(args):
            result=real(args)
            if args==['daemon-reload']:raise TimeoutError('SYNTHETIC_REPLY_LOST')
            return result
        with patch.object(owner.start,'manager',side_effect=lose),self.assertRaises(TimeoutError):owner.apply(intent)
        self.assertEqual(m.checked_row(owner.start)['stageIndex'],2)
        self.assertEqual(owner.observe(intent)[0],'UNKNOWN')
        self.assertEqual(m.checked_row(owner.start)['stageIndex'],3)
        with (patch.object(owner.issuer,'issue',side_effect=AssertionError('NO_RESIGNING')),
            patch.object(owner.files,'apply',side_effect=AssertionError('NO_REPUBLISH')),
            patch.object(owner.registration,'apply',side_effect=AssertionError('NO_RELOAD'))):
            owner.continue_installation(intent)
        self.assertEqual(owner.observe(intent)[0],'APPLIED');self.assertEqual(calls.count(['daemon-reload']),1)
        self.assertEqual(sum(v[0]=='start' for v in calls),1)

    def test_lost_start_reply_reconciles_without_another_start(self):
        owner,intent,auth,calls,state=self.fixture();real=owner.start.manager
        def lose(args):
            result=real(args)
            if args[0]=='start':raise TimeoutError('SYNTHETIC_START_REPLY_LOST')
            return result
        with patch.object(owner.start,'manager',side_effect=lose),self.assertRaises(TimeoutError):owner.apply(intent)
        self.assertEqual(owner.observe(intent)[0],'APPLIED')
        self.assertEqual(sum(v[0]=='start' for v in calls),1)

    def test_unproven_start_read_retains_safe_denial_through_sequence_without_changing_history(self):
        owner,intent,auth,calls,state=self.fixture();real=owner.start.manager
        def lose(args):
            result=real(args)
            if args[0]=='start':raise TimeoutError('SYNTHETIC_START_REPLY_LOST')
            return result
        with patch.object(owner.start,'manager',side_effect=lose),self.assertRaises(TimeoutError):owner.apply(intent)
        before=owner.journal.record.read_bytes();start_before=owner.start.journal.record.read_bytes()
        code='DISCOVERY_WORKER_CHANGED_DURING_OBSERVATION'
        with patch.object(starts.lease_observation,'observe',side_effect=ValueError(code)) as reader:
            outcome,evidence=owner.observe(intent)
        self.assertEqual(outcome,'UNKNOWN');self.assertEqual(reader.call_count,1)
        self.assertEqual(evidence['unprovenStage'],'START');self.assertEqual(evidence['completedSubstages'],3)
        self.assertFalse(evidence['automaticReplayAllowed'])
        self.assertFalse(evidence['unattemptedSubstagesRequireExplicitContinuation'])
        child=evidence['substageObservation']
        self.assertEqual(child['workerObservationFailure']['reasonCode'],code)
        self.assertFalse(child['startReplayAllowed']);self.assertTrue(child['positiveWorkerLeaseNotProven'])
        self.assertEqual(owner.journal.record.read_bytes(),before)
        self.assertEqual(owner.start.journal.record.read_bytes(),start_before)
        self.assertFalse(owner.store.path(owner.phase).exists())
        self.assertEqual(sum(v[0]=='start' for v in calls),1)
        # A separately requested read can reconcile the original claim. It may
        # not dispatch again or discard either the prefix or current counters.
        self.assertEqual(owner.observe(intent)[0],'APPLIED')
        self.assertEqual(sum(v[0]=='start' for v in calls),1)

    def test_crash_before_unattempted_files_stage_requires_explicit_continuation(self):
        owner,intent,auth,calls,state=self.fixture();owner.journal.initialize(owner.initial())
        row=m.checked_row(owner.start)
        owner.save(row,state='IN_FLIGHT',effects=[{'stage':'ATTEST','dispatches':1,'state':'IN_FLIGHT','evidence':None}])
        owner.issuer.issue(intent)
        with patch.object(owner.files,'apply',side_effect=AssertionError('OBSERVE_MUST_NOT_DISPATCH')):
            self.assertEqual(owner.observe(intent)[0],'UNKNOWN')
        self.assertEqual(m.checked_row(owner.start)['stageIndex'],1);self.assertEqual(calls,[])
        with patch.object(owner.issuer,'issue',side_effect=AssertionError('NO_RESIGNING')):owner.continue_installation(intent)
        self.assertEqual(owner.observe(intent)[0],'APPLIED')

    def test_partial_issuance_remains_inflight_without_continuation_replay(self):
        owner,intent,auth,calls,state=self.fixture()
        with patch.object(owner.issuer.signer,'sign',side_effect=TimeoutError('SYNTHETIC_UNKNOWN_SIGNING')):
            with self.assertRaises(TimeoutError):owner.apply(intent)
        with patch.object(owner.issuer,'issue',side_effect=AssertionError('NO_ISSUANCE_REPLAY')):
            with self.assertRaisesRegex(ValueError,'SUBSTAGE_UNPROVEN'):owner.continue_installation(intent)
        self.assertEqual(owner.observe(intent)[0],'UNKNOWN');self.assertEqual(calls,[])

    def test_active_worker_ledger_is_never_reinitialized_or_required_to_equal_initial(self):
        owner,intent,auth,calls,state=self.fixture();owner.apply(intent)
        ledger=Path(owner.start.proposal['configuration']['ledgerRoot'])/'recovery.json'
        row=private_json(ledger);row.update(state='ACTIVE',attempts=7,publicationCount=9)
        replacement=ledger.with_name('current.json');auth.write(replacement,m.encoded(row));replacement.replace(ledger)
        with patch.object(owner.files,'observe',side_effect=AssertionError('NO_INITIAL_LEDGER_RECHECK')):
            self.assertEqual(owner.observe(intent)[0],'APPLIED')
        self.assertEqual(private_json(ledger)['attempts'],7)

    def test_sequenced_start_cannot_skip_signed_publication_registration_prefix(self):
        owner,intent,auth,calls,state=self.fixture();owner.journal.initialize(owner.initial())
        with self.assertRaisesRegex(ValueError,'PREFIX_REQUIRED'):owner.start.apply(intent)
        self.assertEqual(calls,[])

    def test_revoked_parent_blocks_explicit_continuation_without_effects(self):
        owner,intent,auth,calls,state=self.fixture();owner.journal.initialize(owner.initial())
        (auth.signatures/(owner.start.parent.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
        with self.assertRaises(FileNotFoundError):owner.continue_installation(intent)
        self.assertEqual(m.checked_row(owner.start)['stageIndex'],0);self.assertEqual(calls,[])

    def test_changed_order_or_dispatch_count_blocks_before_native_commands(self):
        owner,intent,auth,calls,state=self.fixture();owner.journal.initialize(owner.initial())
        row=owner.journal.read();wrong={**row,'version':1,'state':'IN_FLIGHT','effects':[{'stage':'FILES','dispatches':2,'state':'IN_FLIGHT','evidence':None}]}
        owner.journal.compare_and_save(row,wrong)
        with self.assertRaisesRegex(ValueError,'STAGE_ORDER'):owner.continue_installation(intent)
        self.assertEqual(calls,[])

    def test_sequence_version_cannot_drift_without_dispatch_or_observation(self):
        owner,intent,auth,calls,state=self.fixture();owner.journal.initialize(owner.initial())
        row=owner.journal.read();owner.journal.compare_and_save(row,{**row,'version':1})
        with self.assertRaisesRegex(ValueError,'SEQUENCE_VERSION_DRIFT'):owner.continue_installation(intent)
        self.assertEqual(calls,[])

    def test_cas_acknowledgement_without_exact_readback_cannot_dispatch(self):
        owner,intent,auth,calls,state=self.fixture();owner.journal.initialize(owner.initial())
        row=m.checked_row(owner.start)
        with patch.object(m,'checked_row',return_value=row):
            with self.assertRaisesRegex(ValueError,'COMMIT_READBACK_DRIFT'):
                owner.save(row,state='IN_FLIGHT',effects=[{'stage':'ATTEST','dispatches':1,'state':'IN_FLIGHT','evidence':None}])
        self.assertEqual(calls,[]);self.assertFalse((owner.issuer.root/'claim.json').exists())

    def test_changed_dispatch_record_after_authority_check_cannot_invoke_owner(self):
        owner,intent,auth,calls,state=self.fixture();owner.journal.initialize(owner.initial())
        real=owner.current;count=0
        def changed(intent):
            nonlocal count
            real(intent);count+=1
            if count==2:
                row=owner.journal.read();owner.journal.compare_and_save(row,owner.initial())
        with patch.object(owner,'current',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'DISPATCH_RECORD_DRIFT'):owner.drive(intent)
        self.assertEqual(calls,[]);self.assertFalse((owner.issuer.root/'claim.json').exists())

    def test_regressed_record_after_effect_cannot_dispatch_a_stage_twice(self):
        owner,intent,auth,calls,state=self.fixture();real=owner.issuer.issue
        def regressed(intent):
            real(intent);row=owner.journal.read();owner.journal.compare_and_save(row,owner.initial())
        with patch.object(owner.issuer,'issue',side_effect=regressed) as issue:
            with self.assertRaisesRegex(ValueError,'INVOKING_RECORD_DRIFT'):owner.apply(intent)
            self.assertEqual(issue.call_count,1)
        self.assertTrue((owner.issuer.root/'claim.json').exists());self.assertEqual(calls,[])

    def test_read_only_completed_observation_works_while_worker_holds_lifetime_fence(self):
        owner,intent,auth,calls,state=self.fixture();owner.apply(intent)
        c=owner.start.proposal['configuration']
        with owner.files.start.journal.invocation():
            from tools.m2_discovery_installation_profile.lease_service import existing_kernel_lock
            with existing_kernel_lock(c['commonInvocationLock'],c['commonLockIdentity']):
                self.assertEqual(owner.observe(intent)[0],'APPLIED')


if __name__=='__main__':unittest.main()
