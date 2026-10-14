"""Full composed native custody/signatures/TLS; simulated systemctl and IAM admin.

Hosted-root gate makes group10001 support mandatory. Local restricted namespaces
may skip the native group case; source/authority-only cases remain executable.
"""
import dataclasses
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT)]
import test_policy_token_first_controlled_grant as fixture
from tools.semantic_policy_token_owner.owner_installation import AggregateAction,OwnerInstallation,finite_worker_scope
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner,LegacyWriterFence
from tools.semantic_policy_token_owner.producer import DomainOwner,Binding
from tools.semantic_policy_token_owner.supervisor import RenewalWorker
from tools.semantic_policy_token_owner.source_stage import FILES
from tools.semantic_lease_recovery.bounded_recovery import Policy

class AggregateAuthorityTest(unittest.TestCase):
    def test_no_callback_or_implicit_budget_authority(self):
        with self.assertRaises(Exception):AggregateAction(lambda raw:True,b'{}','a'*64)
        with self.assertRaises(Exception):finite_worker_scope('a'*64,'b'*64,'c'*64,Policy(), 'd'*64,'e'*64,60)
        p=Policy(max_attempts=2,max_elapsed=300)
        scope=finite_worker_scope('a'*64,'b'*64,'c'*64,p,'d'*64,'e'*64,60)
        self.assertEqual(scope['predecessorGrantAttempts'],1)
        self.assertEqual(scope['policy']['max_attempts'],2)
        self.assertFalse(scope['automaticBudgetRenewalAllowed'])
        self.assertEqual(scope['legacyHistoryDisposition'],'UNKNOWN_RETAINED_NOT_RECONCILED')

class OwnerInstallationTest(unittest.TestCase):
    def setUp(self):
        # Capability check before the fixture that creates actual group custody.
        probe=ROOT/'group-custody-probe'
        probe.mkdir(mode=0o700)
        try:
            try:os.chown(probe,0,10001)
            except OSError:
                if os.environ.get('OUF_NATIVE_UIDS')=='1':raise
                self.skipTest('native group10001 custody is mandatory in hosted-root CI')
        finally:probe.rmdir()
        f=fixture.RootBoundFirstGrantTest();f.setUp();self.addCleanup(f.doCleanups);self.f=f
        # Root migration fixture has a mocked historical boot. Actual new session
        # uses the current kernel boot and the owner independently reads it.
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        p=patch.object(fixture.sessions,'boot_identity',return_value=boot);p.start();self.addCleanup(p.stop)
        self.files={name:(ROOT/('tools/semantic_lease_recovery/'+name.replace('-','_') if name in
            {'bounded-recovery.py','recovery-journal.py'} else 'tools/semantic_policy_token_owner/'+name.replace('-','_'))).read_bytes()for name in FILES}
        self.policy=Policy(max_attempts=2,max_elapsed=300)
        planned=self.make()
        authority=json.loads(f.f.authority);authority.update(planned.scopes())
        f.f.authority=fixture.binding.encoded(authority)
        f.f.approval['executionAuthorityHash']=fixture.binding.sha(f.f.authority)
        f.f.write(f.f.mandate,fixture.binding.encoded(f.f.approval));f.f.approved=fixture.binding.sha(f.f.mandate.read_bytes())
        for role in f.f.grant['roles']:f.f.sign(role)
        self.installation=self.make()
        for p in (patch.object(fixture.legacy,'read_units',side_effect=lambda:dict(f.state)),
            patch.object(fixture.legacy.subprocess,'run',side_effect=f.command),
            patch.object(fixture.fixtures.transaction.SecretAdmin,'call',side_effect=f.admin),
            patch.object(LegacyWriterFence,'guard',return_value=True)):
            p.start();self.addCleanup(p.stop)
    def make(self):
        f=self.f;action=AggregateAction(f.f.gate(),f.f.authority,f.f.expected['sourceClosureHash'])
        output=Path(f.r.paths['durableRecovery'])/'token-output'
        binding=Binding(f.server.profile.token_endpoint,'fixture-client','authorization.bundle.read',str(output),'token.jwt',10001)
        return OwnerInstallation(action,f.r.f.raw,f.root_hash,f.root_source,f.registration,binding,
            f.server.profile,f.transport,'a'*40,self.files,self.policy,'1'*64,'2'*64,60,f.clock)
    def grants(self):return sum(p.endswith('/token')for p,_ in self.f.server.calls)
    def test_same_action_creates_output_rotates_grants_and_admits_real_owner_with_history(self):
        i=self.installation;worker=i.install()
        self.assertIs(type(worker),RenewalWorker)
        self.assertIs(type(i.observer),InstalledTokenOwner);self.assertIsInstance(i.observer,DomainOwner)
        self.assertEqual(self.grants(),1);self.assertEqual(self.f.calls.count(('create','/client-secret')),1)
        row=i.journal.read();self.assertEqual(row['attempts'],0)
        self.assertEqual(row['controlledCumulativeGrantAttempts'],1)
        self.assertIsNone(row['legacyHistory']['cumulativeGrantAttemptCount'])
        self.assertFalse(row['legacyHistory']['reconciled'])
        self.assertEqual(i.owner.store.read()['state'],'ACTIVE')
        self.assertEqual(worker.tick()['state'],'ACTIVE');self.assertEqual(self.grants(),1)
        i.observer.guard(i.first.binding.digest())
        before=(self.grants(),len(self.f.commands),len(self.f.calls))
        with self.assertRaisesRegex(Exception,'ALREADY_RESERVED'):self.make().install()
        self.assertEqual(before,(self.grants(),len(self.f.commands),len(self.f.calls)))
        # Process restart is not a hidden new grant session or adopted ACTIVE.
        restarted=RenewalWorker(worker.r)
        self.assertEqual(restarted.tick()['state'],'RECONCILE_REQUIRED')
        self.assertEqual(self.grants(),1);self.assertEqual(i.owner.store.read()['state'],'BLOCKED')
    def test_missing_new_worker_scope_denies_before_any_effect(self):
        f=self.f;raw=json.loads(f.f.authority);raw.pop('policyTokenFiniteWorkerSession')
        f.f.authority=fixture.binding.encoded(raw)
        with self.assertRaisesRegex(Exception,'COMPONENT_SCOPE|MANDATE|DRIFT'):
            self.make().install()
        self.assertEqual(self.grants(),0);self.assertEqual(self.f.calls,[]);self.assertEqual(self.f.commands,[])
    def test_ambiguous_grant_stays_consumed_and_partial_install_is_not_reset(self):
        self.f.server.active=lambda:{'active':False}
        with self.assertRaises(Exception):self.installation.install()
        self.assertEqual(self.grants(),1)
        first=self.installation.first
        session=json.loads((self.f.root/first.session.name).read_bytes())
        self.assertEqual(session['attemptSlotsConsumed'],1)
        self.assertFalse((self.installation.journal.root/'recovery.json').exists())
        with self.assertRaisesRegex(Exception,'ALREADY_RESERVED'):self.make().install()
        self.assertEqual(self.grants(),1)
    def test_private_history_drift_blocks_observer_and_worker_without_new_grant(self):
        i=self.installation;worker=i.install();path=i.journal.root/'owner-first-grant.json'
        path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(Exception):i.observer.guard(i.first.binding.digest())
        self.assertEqual(worker.tick()['state'],'BLOCKED');self.assertEqual(self.grants(),1)

if __name__=='__main__':unittest.main()
