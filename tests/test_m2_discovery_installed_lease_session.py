"""Actual signed installed authority/journals; coordinator kernel facts synthetic."""
import copy,hashlib,sys,unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_installed_lease_guard as installed
import test_m2_discovery_lease_worker as factory
from tools.m2_discovery_installation_profile import installed_lease_session as m
from tools.m2_discovery_installation_profile import lease_worker


class Session(unittest.TestCase):
    def setUp(self):pass
    native=installed.Installed.native
    write=installed.Installed.write
    binding=installed.Installed.binding
    sign=installed.Installed.sign
    signed_receipt=installed.Installed.signed_receipt

    def fixture(self,state='ACTIVE'):
        installed.Installed.setUp(self)
        guard,c,g,calls,receipt=installed.Installed.fixture(self)
        coordinator,journal,policy,scope,options,callbacks=factory.Worker.fixture(self,state)
        coordinator.owner.backend.active_deadline=None
        scope['sourceClosureHash']=c['sourceManifest']['dependencyClosureHash']
        scope['installationInputsHash']=c['installationInputsHash']
        c['scopePolicyHash']=scope['policyHash'];c['ledgerRoot']=str(journal.root)
        c['sourceManifest']['sourceHashes'][m.MODULE]=hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()
        self.write(guard.path,m.encoded(c));sha=m.digest(c)
        receipt.update(configurationHash=sha,sourceManifestHash=m.digest(c['sourceManifest']),scopePolicyHash=c['scopePolicyHash'])
        self.write(self.root/'installed.json',self.signed_receipt(receipt))
        g.update(configurationHash=sha,scopeHash=m.fingerprint(scope),scopePolicyHash=c['scopePolicyHash'],
            generationRef=scope['generationRef'],ledgerRoot=c['ledgerRoot'])
        self.write(Path(c['generationReceiptPath']),self.signed_receipt(g))
        guard=m.InstalledLeaseGuard(guard.path,sha,generation_probe=guard.probe)
        coordination={'schema':'ouf.semantic-lease-coordination.v1',**coordinator.binding,
            'state':'LEASE_READY' if state=='ACTIVE' else 'QUIESCED','leaseAuthorized':state=='ACTIVE',
            'startAuthorized':False,'leaseAddresses':[['1.1.1.1']] if state=='ACTIVE' else [[]]}
        sets=[['1.1.1.1']] if state=='ACTIVE' else [[]];events=[]
        @contextmanager
        def lock():yield
        coordinator.hold_lock=lock
        coordinator.journal=lambda:copy.deepcopy(coordination)
        coordinator.sets=lambda:copy.deepcopy(sets)
        coordinator.guard=lambda:{'state':coordination['state']}
        def quiesce():
            events.append('REVOKE');coordination.update(state='QUIESCED',leaseAuthorized=False,leaseAddresses=[[]])
            sets[:]=[[]];return {'state':'QUIESCED'}
        coordinator.quiesce=quiesce
        row=journal.read();updated={**row,'discoveryLeaseScopeHash':m.fingerprint(scope)}
        if state=='ACTIVE':updated['resultRef']=m.fingerprint(coordination)
        if state=='RETRY_WAIT':updated.update(nextWall=120.0,nextMonotonic=70.0)
        journal.compare_and_save(row,updated)
        worker=lease_worker.build_worker(coordinator,journal,policy,scope,**options)
        return worker,guard,scope,calls,callbacks,events,coordination

    def test_active_reentry_revokes_before_fresh_attempt_and_preserves_history(self):
        w,g,s,calls,callbacks,events,c=self.fixture();before=w.r.journal.read()
        # Simulate downtime beyond the last independently proven healthy TTL.
        w.r.clock=lambda:(180.0,130.0)
        with m.installed_invocation(w,g,s):
            row=w.r.journal.read();self.assertEqual(row['state'],'NEW');self.assertFalse(w.active_here)
            self.assertEqual(row['attempts'],before['attempts']);self.assertEqual(row['publicationCount'],before['publicationCount'])
            self.assertEqual(row['healthyWallSeconds'],15);self.assertEqual(row['healthyMonotonicSeconds'],15)
            self.assertEqual(row['reentryCount'],1);self.assertEqual(c['state'],'QUIESCED')
            path=w.r.journal.root/('reentry-predecessor-'+row['reentryPredecessorHash']+'.json')
            self.assertEqual(path.read_bytes(),m.encoded(before))
            w.r.adapter.guard()
            self.assertFalse(any(v[0] in {'runtime','generation'} for v in callbacks))
            self.assertGreaterEqual(len(calls),4)
        self.assertEqual(events,['REVOKE']);self.assertEqual(w.r.journal.read()['attempts'],5)

    def test_retry_wait_keeps_original_absolute_deadlines_and_budget(self):
        w,g,s,*_=self.fixture('RETRY_WAIT');before=w.r.journal.read()
        with m.installed_invocation(w,g,s):
            row=w.r.journal.read();self.assertEqual(row['state'],'RETRY_WAIT')
            for k in ('nextWall','nextMonotonic','attempts','publicationCount','startedWall','startedMonotonic'):
                self.assertEqual(row[k],before[k])

    def test_ambiguous_exhausted_cancelled_and_blocked_records_are_not_rearmed(self):
        for state in ('ATTEMPTING','PUBLISHING','RECONCILE_REQUIRED','PAUSED_EXHAUSTED','BLOCKED','CANCELLED'):
            with self.subTest(state=state):
                w,g,s,*_=self.fixture(state);before=w.r.journal.record.read_bytes()
                with m.installed_invocation(w,g,s):self.assertEqual(w.r.journal.record.read_bytes(),before)
                self.assertEqual(w.r.journal.record.read_bytes(),before)
                self.assertFalse(list(w.r.journal.root.glob('reentry-predecessor-*')))

    def test_failed_revocation_leaves_durable_pending_and_does_not_retry_it(self):
        w,g,s,*_=self.fixture()
        def fail():raise RuntimeError('SYNTHETIC_REVOCATION_FAILED')
        w.c.quiesce=fail
        with self.assertRaisesRegex(RuntimeError,'SYNTHETIC_REVOCATION_FAILED'):
            with m.installed_invocation(w,g,s):self.fail('unproven revocation entered runtime')
        row=w.r.journal.read();self.assertEqual(row['state'],'RECONCILE_REQUIRED')
        self.assertEqual(row['reason'],m.REENTRY_REASON);self.assertEqual(row['attempts'],5)
        with self.assertRaises(RuntimeError):
            with m.installed_invocation(w,g,s):self.assertEqual(w.r.journal.read(),row)
        self.assertEqual(w.r.journal.read(),row)

    def test_foreign_publication_or_incomplete_coordination_is_not_adopted(self):
        for change in ({'leaseAddresses':[['8.8.8.8']]},{'state':'LEASE_UPDATING'}):
            w,g,s,_,_,_,c=self.fixture();c.update(change);before=w.r.journal.record.read_bytes()
            with self.assertRaises(ValueError):
                with m.installed_invocation(w,g,s):self.fail('foreign publication adopted')
            self.assertEqual(w.r.journal.record.read_bytes(),before)

    def test_missing_current_signature_prevents_archive_or_retry(self):
        w,g,s,*_=self.fixture();before=w.r.journal.record.read_bytes()
        for p in self.receipt_signatures.glob('*.json'):p.unlink()
        with self.assertRaises(Exception):
            with m.installed_invocation(w,g,s):self.fail('missing receipt accepted')
        self.assertEqual(w.r.journal.record.read_bytes(),before)
        self.assertFalse(list(w.r.journal.root.glob('reentry-predecessor-*')))

    def test_changed_scope_and_parallel_process_fences_are_denied(self):
        w,g,s,*_=self.fixture('NEW')
        with m.installed_invocation(w,g,s):
            with self.assertRaises(BlockingIOError):
                with w.r.journal.invocation():self.fail('parallel recovery invocation accepted')
            other=m.InstalledLeaseGuard(g.path,g.sha,generation_probe=g.probe)
            with self.assertRaises(BlockingIOError):
                with other.invocation():self.fail('parallel installed invocation accepted')
            s['heartbeatSeconds']=2
            with self.assertRaisesRegex(ValueError,'SESSION_SCOPE_CHANGED'):w.r.adapter.guard()

    def test_installed_serve_parks_alive_on_observer_failure_without_external_authority_callbacks(self):
        import threading
        w,g,s,calls,callbacks,events,c=self.fixture('NEW')
        stop=threading.Event();waits=[]
        def wait(delay):waits.append(delay);stop.set();return True
        stop.wait=wait
        def fail(*args):raise RuntimeError('SYNTHETIC_OBSERVER_FAILURE')
        w._serve=fail
        reporter=lease_worker.LeaseReporter(w.r.journal,lambda value:None)
        m.serve_installed(w,g,s,stop,reporter)
        row=w.r.journal.read();self.assertEqual(row['state'],'BLOCKED')
        self.assertEqual(row['attempts'],5);self.assertEqual(row['publicationCount'],3)
        self.assertEqual(waits,[1]);self.assertGreaterEqual(len(calls),4)
        self.assertFalse(any(v[0] in {'runtime','generation'} for v in callbacks))
        with self.assertRaisesRegex(ValueError,'LIFETIME_FENCE'):w.r.adapter.guard()

    def test_clock_regression_cannot_be_treated_as_same_boot_reentry(self):
        w,g,s,*_=self.fixture();w.r.clock=lambda:(99.0,1.0)
        with self.assertRaisesRegex(ValueError,'SAME_BOOT_NONREGRESSING'):
            with m.installed_invocation(w,g,s):self.fail('regressed clock adopted')

if __name__=='__main__':unittest.main()
