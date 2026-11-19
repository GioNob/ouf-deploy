"""Offline qualification of the v18 emitted sources and recovery projection."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

from test_r3_readers import load as reader
import test_semantic_provider_r3_v16_adapter as v17

C = v17.C


class Clock:
    wall = 100000
    mono = 100

    def now(self):
        return self.wall, self.mono

    def advance(self, seconds):
        self.wall += seconds
        self.mono += seconds


class Checkpoint:
    def __init__(self, validate):
        self.validate = validate

    def read(self):
        return copy.deepcopy(self.value)

    def compare_and_save(self, previous, value):
        if self.value != previous:
            raise AssertionError('CAS mismatch')
        self.validate(value)
        self.value = copy.deepcopy(value)


class Lease:
    """In-memory coordinator and deadline backend for the emitted adapter."""
    address = '192.0.2.5'
    expected = 'b' * 64
    active_deadline = None
    error = None
    deny_only = False
    lock_wait = 0
    lock_timeout = False
    pause_failed = False
    ttl_zero = False
    apply_failed = False
    commit_failed = False
    empty = True

    class DNSDenied(Exception):
        pass

    MISSING = {'DNS_MISSING'}

    def __init__(self, clock):
        self.clock = clock
        self.configuration = {'providerFlows': [dict(
            endpoint='provider.invalid', endpointRef='synthetic', source='192.0.2.10',
            allowedPrivateAddresses=[self.address], resolutionEvidenceRef='fixture', leaseSeconds=30)]}
        self.owner = types.SimpleNamespace(backend=self, configuration=self.configuration,
            profile=dict(resolvers=['192.0.2.11'], resolverPort=53, timeoutSeconds=10,
                         maxLeaseSeconds=30, applyBudgetSeconds=1))
        self.row = dict(state='QUIESCED', leaseAuthorized=False, startAuthorized=False, leaseAddresses=[[]])

    @contextmanager
    def hold_lock(self):
        self.clock.advance(self.lock_wait)
        if self.lock_timeout:
            self.lock_timeout = False
            raise TimeoutError('COMMON_LOCK_TIMEOUT')
        yield

    @contextmanager
    def within(self, deadline):
        self.active_deadline = deadline
        try:
            yield
        finally:
            self.active_deadline = None

    def journal(self):
        return copy.deepcopy(self.row)

    def sets(self):
        return [[] if self.empty else [self.address]]

    def verify_ownership(self, configuration):
        pass

    def read_sets(self, configuration):
        if self.ttl_zero:
            self.ttl_zero = False
            error = RuntimeError('NFT_SET_TTL_UNPROVEN')
            error.nft_readback = dict(expiresType='int', expiresValue=0, duplicateAddress=False)
            raise error
        return {(family, 0): {} if self.empty else {self.address: 29} for family in ('inet', 'bridge')}

    def publish(self, previous, value):
        if previous != self.row:
            raise AssertionError('coordinator CAS mismatch')
        if value['state'] == 'LEASE_READY' and self.commit_failed:
            raise RuntimeError('private native commit details')
        self.row = copy.deepcopy(value)

    def quiesce(self):
        self.clock.advance(1)
        if self.pause_failed:
            raise RuntimeError('native secret data at provider.invalid')
        self.empty = True
        self.row.update(state='QUIESCED', leaseAuthorized=False, leaseAddresses=[[]])

    def observe_many(self, *args, **kwargs):
        if self.error:
            raise self.DNSDenied(self.error)
        return [dict(usableAddresses=[self.address], observedMonotonic=self.clock.mono,
                     expiresMonotonic=self.clock.mono + 30)]

    def compile_refresh(self, configuration, values, now, *, apply_budget_seconds):
        return dict(denyOnly=self.deny_only, nftTransaction=None, mustApplyByMonotonic=now + apply_budget_seconds)

    def apply(self, transaction, deadline):
        if self.apply_failed:
            raise RuntimeError('NFT_ATTEMPT_DEADLINE_UNPROVEN')
        self.empty = False


class Observability(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        v17.DriverBudget.setUpClass()
        cls.inputs = v17.DriverBudget.inputs
        previous = v17.DriverBudget.v16
        cls.old = C.compose(cls.inputs, 17, sequence=17, supersedes=C.sha(previous['authorization']))
        cls.result = C.compose(cls.inputs, 18, sequence=18, supersedes=C.sha(cls.old['authorization']))

    def test_v17_golden(self):
        # Captured on clean 514679b9 before adding the v18 overlay.
        expected = {
            'hashes': '31ab6377342567f0e06089c26d4d090a70e0f6461ec98343c95a40f7eabc63de',
            'inputHashes': '171598725caffbbab4447e4245ed9a7c5bda058f6f49c995c5b970c76e8325af',
            'audit': '302d3b526d20af5f200c95a7258d9351254ce50220df3425aa7a3749db8e8aab',
            'layout': '83ec61849417b6c7932267c207f73918316b795b9a497411a9bd133e58e233ea',
            'authorization': 'ec529e180f7293b5206b8ab467b6b688544cc52cb93bdc5180b82214896c8391',
        }
        actual = {key: C.sha(C.canonical(self.old[key])) for key in expected if key != 'authorization'}
        self.assertEqual(actual | {'authorization': C.sha(self.old['authorization'])}, expected)

    def test_v18_seals_the_existing_closure(self):
        docs = self.result['documents']
        prefix = 'versions/18/'
        sup = C.document(docs[prefix + 'supervisor/configuration.json'])
        module = C.contract_module(docs[prefix + 'source/' + C.SUPERVISOR], 'v18_observed_supervisor')
        self.assertEqual(module.validate(C.canonical(sup)), sup)
        bootstrap = C.contract_module(docs[prefix + 'source/scripts/semantic-provider-lease-supervisor-v2.py'],
                                      'v18_observed_bootstrap')
        self.assertEqual(bootstrap.SOURCES, module.SOURCES)
        for path, digest in sup['sourceHashes'].items():
            raw = docs[prefix + 'source/' + path]
            self.assertEqual(C.sha(raw), digest)
            compile(raw, path, 'exec')
        for name, pin in module.PINS.items():
            self.assertEqual(pin, sup['sourceHashes'][f'tools/semantic_lease_recovery/{name}.py'])

    def test_supervisor_status_tracks_successive_scopes(self):
        raw = self.result['documents']['versions/18/source/' + C.SUPERVISOR]
        module = C.contract_module(raw, 'v18_status_scope')
        seen = []
        scopes = iter(('a' * 48, 'b' * 48))

        def factory(guards):
            journal = types.SimpleNamespace(root=Path(next(scopes)))
            return types.SimpleNamespace(renewals=0, r=types.SimpleNamespace(journal=journal),
                                         serve=lambda stop, observe: observe({'state': 'ACTIVE'}))

        guards = types.SimpleNamespace(sequence=42, epochs={'adapter': 7, 'southbound': 9})
        activations = types.SimpleNamespace(count=lambda now: 1)
        service = module.Service({'statusPath': '/fixture/status'}, None, guards, factory, activations,
                                 clock=lambda: 123, writer=lambda path, value: seen.append(value))
        service.quiesce = lambda: None
        service.status('WAITING')
        service.run_scope()
        service.run_scope()
        self.assertEqual([row['recoveryScope'] for row in seen], [None, 'a' * 48, 'b' * 48])
        self.assertTrue(all(row['updatedAt'] == 123 for row in seen))

    def fixture(self):
        modules = patch.dict(sys.modules)
        modules.start()
        self.addCleanup(modules.stop)
        if os.name == 'nt':
            # The in-memory checkpoint exercises CAS on Windows.
            sys.modules['fcntl'] = types.ModuleType('fcntl')
        loaded = {}
        for name in ('bounded_recovery', 'recovery_journal', 'lease_recovery_budget',
                     'resilient_lease_adapter', 'adaptive_supervisor', 'continuous_supervisor'):
            path = f'versions/18/source/tools/semantic_lease_recovery/{name}.py'
            module = types.ModuleType(name)
            sys.modules[name] = loaded[name] = module
            exec(compile(self.result['documents'][path], path, 'exec'), module.__dict__)
        clock = Clock()
        lease = Lease(clock)
        continuous = loaded['continuous_supervisor']
        adapter = continuous.RenewingLeaseAdapter(lease, lease, lease, lambda: None, lambda: None,
                                                  lambda: clock.mono)
        journal = loaded['recovery_journal']
        adapter.incident = journal.Incident(42, {'adapter': 7, 'southbound': 9},
                                           lambda: clock.wall, lambda: clock.mono)
        checkpoint = Checkpoint(journal.validate_incident)
        recovery = loaded['lease_recovery_budget'].ObservedRecovery(
            checkpoint, adapter, loaded['bounded_recovery'].Policy(), 'a' * 64, 'b' * 64, clock.now, lambda: .5)
        checkpoint.value = recovery.initial()
        supervisor = continuous.Supervisor(recovery, lease, 15)
        first = supervisor.tick()
        self.assertEqual(first['state'], 'ACTIVE')
        self.assertIsNone(first['lastIncident'])
        return clock, lease, supervisor, first

    def test_pause_resume_and_renew_preserve_the_incident(self):
        clock, lease, supervisor, first = self.fixture()
        clock.advance(5)
        lease.error = 'DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE'
        failed_at = clock.wall
        pause = supervisor.renew(first)
        incident = pause['lastIncident']
        self.assertEqual(pause['state'], 'RETRY_WAIT')
        self.assertEqual(lease.row['state'], 'QUIESCED')
        self.assertEqual(incident, {
            'schema': 'ouf.semantic-lease-recovery-incident.v1', 'scopeRef': 'a' * 64,
            'authorizationSequence': 42, 'epochs': {'adapter': 7, 'southbound': 9},
            'incidentCount': 1, 'failedAt': failed_at, 'pausedAt': failed_at + 1,
            'resumedAt': None, 'nextRetryAt': pause['nextWall'], 'phase': 'DNS',
            'code': 'DNS_WINDOW_TOO_SHORT', 'revocation': 'VERIFIED', 'stateAtFailure': 'ACTIVE',
            'leaseRemainingMs': 24000, 'lockWaitMs': None,
            'deadlineMonotonic': first['leaseDeadlineMonotonic'] - 1,
        })
        lease.error = None
        clock.advance(pause['nextMonotonic'] - clock.mono)
        resumed = supervisor.tick()
        self.assertEqual(lease.row['state'], 'LEASE_READY')
        complete = incident | {'resumedAt': clock.wall}
        self.assertEqual(resumed['lastIncident'], complete)
        projection = reader('r3_common.py')['recovery_incident']
        self.assertEqual(projection(resumed['lastIncident'], 'a' * 64), complete)
        clock.advance(5)
        renewed = supervisor.renew(resumed)
        self.assertEqual(renewed['reason'], 'RENEWED')
        self.assertEqual(renewed['lastIncident'], complete)

    def test_unverified_revocation_keeps_pause_null(self):
        _, lease, supervisor, first = self.fixture()
        lease.pause_failed = True
        lease.error = 'DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE'
        blocked = supervisor.renew(first)
        self.assertEqual(blocked['reason'], 'SAFE_PAUSE_UNPROVEN')
        incident = blocked['lastIncident']
        self.assertEqual((incident['revocation'], incident['phase'], incident['code']),
                         ('UNPROVEN', 'DNS', 'DNS_WINDOW_TOO_SHORT'))
        self.assertIsNone(incident['pausedAt'])
        self.assertIsNone(incident['resumedAt'])
        self.assertNotIn('provider.invalid', json.dumps(blocked))

    def test_next_episode_replaces_incident_and_increments_count(self):
        clock, lease, supervisor, active = self.fixture()
        lease.error = 'DNS_MISSING'
        first = supervisor.renew(active)
        clock.advance(first['nextMonotonic'] - clock.mono)
        repeated = supervisor.tick()
        self.assertEqual(repeated['lastIncident'],
                         first['lastIncident'] | {'nextRetryAt': repeated['nextWall']})
        lease.error = None
        clock.advance(repeated['nextMonotonic'] - clock.mono)
        active = supervisor.tick()
        lease.deny_only = True
        second = supervisor.renew(active)['lastIncident']
        self.assertEqual((second['incidentCount'], second['phase'], second['code']),
                         (2, 'COMPILE', 'DNS_WINDOW_TOO_SHORT'))
        self.assertGreater(second['failedAt'], first['lastIncident']['failedAt'])
        self.assertIsNone(second['resumedAt'])

    def test_lock_apply_readback_and_commit_failures_are_distinct(self):
        cases = (
            ('lock_timeout', 'LOCK_ACQUIRE', 'COMMON_LOCK_TIMEOUT'),
            ('apply_failed', 'APPLY', 'NFT_ATTEMPT_DEADLINE_UNPROVEN'),
            ('ttl_zero', 'READBACK', 'DNS_WINDOW_TOO_SHORT'),
            ('commit_failed', 'COMMIT', 'INTEGRITY_UNPROVEN'),
        )
        for problem, phase, code in cases:
            with self.subTest(problem=problem):
                clock, lease, supervisor, active = self.fixture()
                lease.lock_wait = .25
                setattr(lease, problem, True)
                clock.advance(2)
                incident = supervisor.renew(active)['lastIncident']
                self.assertEqual((incident['phase'], incident['code']), (phase, code))
                self.assertEqual(incident['lockWaitMs'], 250)
                self.assertIsNone(incident['resumedAt'])
                if phase == 'APPLY':
                    self.assertEqual(incident['deadlineMonotonic'], 103.25)


if __name__ == '__main__':
    unittest.main()
