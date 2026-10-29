"""Durable factory/accounting/status with synthetic coordinator and admission guards."""
import copy,dataclasses,importlib,json,os,sys,tempfile,threading,types,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile import lease_worker as m

class Worker(unittest.TestCase):
    def fixture(self,state='NEW'):
        directory=tempfile.TemporaryDirectory(dir=ROOT,prefix='discovery-worker-fixture-')
        self.addCleanup(directory.cleanup);root=Path(directory.name);root.chmod(0o700)
        coordinator=object.__new__(m.Coordinator)
        coordinator.configuration={'providerFlows':[{'endpoint':'https://synthetic.invalid'}]}
        coordinator.binding={'transactionId':'a'*64,'configurationHash':'b'*64,'leaseStructureHash':'c'*64}
        coordinator.owner=types.SimpleNamespace(profile={'syntheticDns':True},backend=types.SimpleNamespace(expected='c'*64))
        journal=m.Journal(root);policy=m.Policy();clock=lambda:(100.0,50.0)
        scope={'sourceClosureHash':'d'*64,'installationInputsHash':'e'*64,'contextRef':'a'*64,'generationRef':'b'*64,
            'policyHash':m.fingerprint(dataclasses.asdict(policy)),'coordinatorBindingHash':m.fingerprint(coordinator.binding),
            'configurationHash':m.fingerprint(coordinator.configuration),'dnsProfileHash':m.fingerprint(coordinator.owner.profile),
            'leaseStructureHash':'c'*64,'pollSeconds':1,'heartbeatSeconds':1}
        recovery=m.LeaseRecovery(journal,None,policy,scope['contextRef'],scope['generationRef'],clock,lambda:.5)
        row={**recovery.initial(),'state':state,'attempts':5,'publicationCount':3,
            'discoveryLeaseScopeHash':m.fingerprint(scope)}
        journal.initialize(row);calls=[]
        options=dict(runtime_guard=lambda value:calls.append(('runtime',value)) or True,
            generation_guard=lambda value:calls.append(('generation',value)) or True,
            custody_guard=lambda *value:calls.append(('custody',value)) or True,
            dns=object(),compiler=object(),clock=clock,random_value=lambda:.5)
        return coordinator,journal,policy,scope,options,calls

    def test_build_preserves_exact_retained_budget_journal_and_issues_no_calls(self):
        c,j,p,s,o,calls=self.fixture();raw=j.record.read_bytes()
        worker=m.build_worker(c,j,p,s,**o)
        self.assertFalse(worker.active_here);self.assertEqual(j.record.read_bytes(),raw)
        self.assertEqual(calls,[]);self.assertEqual(j.read()['attempts'],5)
        self.assertEqual(j.read()['publicationCount'],3)

    def test_scope_generation_policy_or_old_journal_cannot_be_silently_adopted(self):
        for field in ('sourceClosureHash','installationInputsHash','generationRef','contextRef','policyHash'):
            c,j,p,s,o,calls=self.fixture();raw=j.record.read_bytes();s[field]='f'*64
            with self.assertRaises(ValueError):m.build_worker(c,j,p,s,**o)
            self.assertEqual(j.record.read_bytes(),raw);self.assertEqual(calls,[])

    def test_guard_rechecks_runtime_generation_and_custody_without_dns_or_publication(self):
        c,j,p,s,o,calls=self.fixture();worker=m.build_worker(c,j,p,s,**o)
        worker.r.adapter.guard()
        self.assertEqual([v[0] for v in calls],['custody','runtime','generation'])
        self.assertEqual(j.read()['attempts'],5)

    def test_missing_or_revoked_runtime_generation_or_custody_stops_guard(self):
        for key in ('runtime_guard','generation_guard','custody_guard'):
            c,j,p,s,o,calls=self.fixture();o[key]=lambda *a:False
            worker=m.build_worker(c,j,p,s,**o)
            with self.assertRaises(m.Permanent):worker.r.adapter.guard()
            self.assertEqual(j.read()['attempts'],5)

    def test_owner_drift_after_construction_is_not_renewed(self):
        c,j,p,s,o,calls=self.fixture();worker=m.build_worker(c,j,p,s,**o)
        c.configuration['unexpected']='changed'
        with self.assertRaises(m.Permanent):worker.r.adapter.guard()
        self.assertEqual(calls,[])

    def test_old_active_invocation_requires_reconciliation_without_new_attempt(self):
        c,j,p,s,o,calls=self.fixture('ACTIVE');worker=m.build_worker(c,j,p,s,**o)
        pauses=[];worker.r.adapter=types.SimpleNamespace(pause=lambda:pauses.append(True))
        row=worker.tick()
        self.assertEqual(row['state'],'RECONCILE_REQUIRED');self.assertEqual(row['attempts'],5)
        self.assertEqual(row['publicationCount'],3);self.assertTrue(pauses)

    def test_status_rejects_extra_private_fields_and_symlinks(self):
        c,j,p,s,o,calls=self.fixture();reporter=m.LeaseReporter(j,lambda _:None)
        status={'state':'BLOCKED','reason':'AUTHORITY_REVOKED','attempts':5,'renewals':3,
            'incidentRef':s['contextRef'],'ready':False,'live':True}
        with self.assertRaises(ValueError):reporter.report({**status,'environment':'private'})
        outside=j.root/'preserved';outside.write_bytes(b'KEEP')
        (j.root/'lease-worker-status.json').symlink_to(outside)
        with self.assertRaises(ValueError):reporter.report(status)
        self.assertEqual(outside.read_bytes(),b'KEEP')

    def test_observer_failure_revokes_and_parks_alive_without_reset_or_dependency_calls(self):
        c,j,p,s,o,calls=self.fixture();worker=m.build_worker(c,j,p,s,**o);pauses=[]
        worker.r.adapter=types.SimpleNamespace(pause=lambda:pauses.append(True))
        worker._serve=lambda *a:(_ for _ in ()).throw(RuntimeError('synthetic-observer-failure'))
        def emit(_):raise RuntimeError('synthetic-log-unavailable')
        reporter=m.LeaseReporter(j,emit);stop=threading.Event();waits=[]
        def wait(delay):waits.append(delay);stop.set();return True
        stop.wait=wait
        m.serve(worker,stop,reporter)
        row=j.read();self.assertEqual(row['state'],'BLOCKED')
        self.assertEqual(row['attempts'],5);self.assertEqual(row['publicationCount'],3)
        self.assertTrue(pauses);self.assertEqual(waits,[1]);self.assertEqual(calls,[])
        status=json.loads((j.root/'lease-worker-status.json').read_bytes())
        self.assertFalse(status['ready']);self.assertFalse(status['applicationReady'])

if __name__=='__main__':unittest.main()
