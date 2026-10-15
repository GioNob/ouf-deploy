"""New worker after a real signed first grant; real TLS and private native roots.

Only systemctl/IAM administration are simulated by the existing owner fixture.
Hosted CI makes root/group10001 and native sockets mandatory. No target access.
"""
import copy
import dataclasses
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_policy_token_owner_installation as existing
from tools.chatbot_file_cohort import postgrant_recovery as p
from tools.semantic_policy_token_owner.owner_installation import AggregateAction,ContinuedOwnerInstallation
from tools.semantic_lease_recovery.bounded_recovery import Policy,fingerprint
from tools.semantic_policy_token_owner.supervisor import RenewalWorker


class PostGrantOwner(unittest.TestCase):
    def setUp(self):
        harness=existing.OwnerInstallationTest('test_same_action_creates_output_rotates_grants_and_admits_real_owner_with_history')
        self.addCleanup(harness.doCleanups);harness.setUp();self.harness=harness;self.f=harness.f
        self.old=harness.installation;worker=self.old.install()
        self.assertEqual(worker.r.step(cancelled=True)['state'],'CANCELLED')
        root=self.old.journal.root
        paths={name:root/name for name in ('owner-first-grant.json','owner-session.json','owner-admission.json','recovery.json')}
        paths['completed']=self.f.f.root/(self.old.intent_name+'.completed')
        read=lambda name:json.loads(paths[name].read_bytes())
        self.predecessor={'firstGrant':read('owner-first-grant.json'),'worker':read('recovery.json'),
            'admission':read('owner-admission.json'),'session':read('owner-session.json'),'completed':read('completed'),
            'prepared':{'owner':{'binding':dataclasses.asdict(self.old.first.binding),
                'iamProfile':dataclasses.asdict(self.old.first.profile)}},'review':{'scopes':self.old.scopes()}}
        self.preserved={str(path):path.read_bytes()for path in paths.values()}
        self.secret=self.old.first.credential.path.read_bytes()
        self.admin_before=list(self.f.calls);self.commands_before=list(self.f.commands)
        self.proof={'profile':p.PROFILE,'recordBindings':[{'path':name,'sha256':hashlib.sha256(raw).hexdigest()}for name,raw in self.preserved.items()],
            'cancelledWorkerHash':fingerprint(self.predecessor['worker']),
            'newBudget':{'actor':{'issuer':'https://human.fixture.test','tenant':'fixture','subject':'human'},
                'reason':'SYNTHETIC_POSTGRANT_NATIVE_QUALIFICATION','decisionRef':'NEW_EXACT_SIGNED_DECISION',
                'priorControlledGrantAttempts':1,'priorWorkerGrantAttempts':0,'maximumNewWorkerAttempts':128,
                'maximumSeconds':300,'automaticRenewalAllowed':False}}
        host=self.f.f.root/'postgrant-host-inputs.private.json';self.f.f.write(host,self.f.r.f.raw)
        self.directory=self.f.f.root/'postgrant-new-worker';self.directory.mkdir(mode=0o700)
        self.value={'hostInputBinding':{'path':str(host),'sha256':hashlib.sha256(self.f.r.f.raw).hexdigest()},
            'rootEvidenceHash':self.f.root_hash,'rootCreationSourceClosureHash':self.f.root_source,
            'binding':dataclasses.asdict(self.old.first.binding),'iamProfile':dataclasses.asdict(self.old.first.profile),
            'tlsTrustSetHash':self.f.transport.trust_digest(),'policy':dataclasses.asdict(Policy(max_attempts=128,max_elapsed=300)),
            'contextRef':'9'*64,'generationRef':'8'*64,'intervalSeconds':60,'sourceCommit':'b'*40}
        # This fixture changes its own exact record pin; production target pins
        # remain immutable in the source and are never relaxed by a CLI option.
        override=patch.object(p,'FIRST_HASH',fingerprint(self.predecessor['firstGrant']))
        override.start();self.addCleanup(override.stop)
        self.f.f.expected['sourceClosureHash']='8'*64
        authority=json.loads(self.f.f.authority);authority['sourceClosureHash']='8'*64
        self.f.f.authority=existing.fixture.binding.encoded(authority)
        planned=self.make();authority.update(planned.scopes())
        self.f.f.authority=existing.fixture.binding.encoded(authority)
        self.f.f.approval['sourceClosureHash']='8'*64
        self.f.f.approval['approvalRef']='NEW_POSTGRANT_NATIVE_FIXTURE_DECISION'
        self.f.f.approval['executionAuthorityHash']=existing.fixture.binding.sha(self.f.f.authority)
        self.f.f.write(self.f.f.mandate,existing.fixture.binding.encoded(self.f.f.approval))
        self.f.f.approved=existing.fixture.binding.sha(self.f.f.mandate.read_bytes())
        for role in self.f.f.grant['roles']:self.f.f.sign(role)
        self.new=self.make()

    def make(self):
        action=AggregateAction(self.f.f.gate(),self.f.f.authority,self.f.f.expected['sourceClosureHash'])
        return ContinuedOwnerInstallation(action,self.value,self.harness.files,self.proof,self.predecessor,
            self.directory,self.f.clock,transport=self.f.transport)

    def unchanged(self):
        for path,raw in self.preserved.items():self.assertEqual(Path(path).read_bytes(),raw)
        self.assertEqual(self.old.first.credential.path.read_bytes(),self.secret)
        self.assertEqual(self.f.calls,self.admin_before);self.assertEqual(self.f.commands,self.commands_before)

    def test_initialization_does_not_adopt_old_token_or_repeat_first_grant(self):
        worker=self.new.install();row=self.new.journal.read()
        self.assertFalse(worker.active_here);self.assertEqual(row['state'],'NEW')
        self.assertEqual(row['attempts'],0);self.assertEqual(row['publicationCount'],0)
        self.assertEqual(row['controlledCumulativeGrantAttempts'],1)
        self.assertEqual(self.harness.grants(),1)
        with self.assertRaises(Exception):self.new.observer.guard(self.new.first.binding.digest())
        self.unchanged()

    def test_new_accounted_tls_grant_is_required_and_old_history_stays_immutable(self):
        worker=self.new.install();row=worker.tick()
        self.assertEqual(row['state'],'ACTIVE');self.assertEqual(row['attempts'],1)
        self.assertEqual(row['controlledCumulativeGrantAttempts'],2)
        self.assertEqual(self.harness.grants(),2)
        self.new.observer.guard(self.new.first.binding.digest());self.unchanged()
        restarted=RenewalWorker(worker.r)
        self.assertEqual(restarted.tick()['state'],'RECONCILE_REQUIRED')
        self.assertEqual(self.harness.grants(),2);self.unchanged()

    def test_partial_initialization_is_not_reset_or_replayed(self):
        native_initialize=self.new.journal.initialize
        def crashed(row):
            native_initialize(row)
            raise OSError('synthetic crash after durable journal initialization')
        with patch.object(self.new.journal,'initialize',side_effect=crashed),self.assertRaises(OSError):self.new.install()
        before={path.name:path.read_bytes()for path in self.directory.iterdir()}
        with self.assertRaisesRegex(Exception,'ALREADY_CONSUMED'):self.make().install()
        self.assertEqual(before,{path.name:path.read_bytes()for path in self.directory.iterdir()})
        self.assertEqual(self.harness.grants(),1);self.unchanged()

    def test_retained_history_drift_denies_before_a_new_grant(self):
        path=Path(next(iter(self.preserved)));path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(Exception):self.new.install()
        self.assertEqual(list(self.directory.iterdir()),[]);self.assertEqual(self.harness.grants(),1)

    def test_revoked_current_human_denies_and_does_not_reuse_predecessor_mandate(self):
        self.f.f.mandate.write_bytes(b'{}')
        with self.assertRaises(Exception):self.new.install()
        self.assertEqual(list(self.directory.iterdir()),[]);self.assertEqual(self.harness.grants(),1);self.unchanged()

    def test_active_or_nonzero_prior_worker_cannot_be_relabelled_as_unused(self):
        for field,value in (('state','ACTIVE'),('attempts',1),('controlledCumulativeGrantAttempts',2)):
            predecessor=copy.deepcopy(self.predecessor);predecessor['worker'][field]=value
            with self.subTest(field=field),self.assertRaises(Exception):
                ContinuedOwnerInstallation(self.new.action,self.value,self.harness.files,self.proof,predecessor,
                    self.directory,self.f.clock,transport=self.f.transport)
        self.assertEqual(self.harness.grants(),1);self.unchanged()


if __name__=='__main__':unittest.main()
