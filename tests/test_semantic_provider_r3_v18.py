"""Offline checks for R3 v18 and its v17 composition baseline."""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import math
from pathlib import PurePosixPath
import re
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

import test_semantic_provider_r3_v16_adapter as V16
from tools.semantic_provider_r3 import compose as C, upgrade
from tools.semantic_provider_r3 import lease_renewal_v18 as policy

V12 = V16.V12
PREFIX = 'versions/18/'
CONFIG = 'supervisor/configuration.json'


def fixture():
    inputs, previous = V16.v16_fixture()
    v16 = C.compose(inputs, 16, sequence=16, supersedes=C.sha(previous['authorization']))
    inputs['files']['driverBudget'] = V12.blob('ops/vps/r3-driver-budget.json')
    v17 = C.compose(inputs, 17, sequence=17, supersedes=C.sha(v16['authorization']))
    inputs['files']['leaseRenewal'] = V12.blob('ops/vps/r3-lease-renewal.json')
    inputs['sources'][C.LEASE_RENEWAL_SOURCE] = V12.blob(C.LEASE_RENEWAL_SOURCE)
    return inputs, v17


class CompositionBaseline(unittest.TestCase):
    def test_frozen_v17(self):
        # Captured at 514679b9 before the v18 composition changes.
        inputs, previous = V16.v16_fixture()
        v16 = C.compose(inputs, 16, sequence=16, supersedes=C.sha(previous['authorization']))
        inputs['files']['driverBudget'] = V16.V12.blob('ops/vps/r3-driver-budget.json')
        result = C.compose(inputs, 17, sequence=17, supersedes=C.sha(v16['authorization']))
        actual = {key: C.sha(C.canonical(result[key]))
                  for key in ('hashes', 'inputHashes', 'audit', 'layout')}
        actual['authorization'] = C.sha(result['authorization'])
        self.assertEqual(actual, {
            'hashes': '31ab6377342567f0e06089c26d4d090a70e0f6461ec98343c95a40f7eabc63de',
            'inputHashes': '171598725caffbbab4447e4245ed9a7c5bda058f6f49c995c5b970c76e8325af',
            'audit': '302d3b526d20af5f200c95a7258d9351254ce50220df3425aa7a3749db8e8aab',
            'layout': '83ec61849417b6c7932267c207f73918316b795b9a497411a9bd133e58e233ea',
            'authorization': 'ec529e180f7293b5206b8ab467b6b688544cc52cb93bdc5180b82214896c8391',
        })


class CompositionV18(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs, cls.previous = fixture()

    def compose(self, inputs):
        return C.compose(inputs, 18, sequence=18, supersedes=C.sha(self.previous['authorization']))

    def test_normal_successor_and_source_seals(self):
        inputs, old = self.inputs, self.previous
        result = self.compose(inputs)
        new_auth, old_auth = [C.document(item['authorization']) for item in (result, old)]
        head = dict(decision='OPERATE', sequence=17, sha256=C.sha(old['authorization']), authorization=old_auth)
        issuer = V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v18_issuer')
        self.assertEqual(issuer.compose_next(inputs, head, new_auth['issuedAt']), result)
        self.assertEqual(new_auth['supersedes'], head['sha256'])
        self.assertEqual(new_auth['acceptanceSha256'], old_auth['acceptanceSha256'])
        self.assertEqual(C.ACCEPT.decode_manifest(inputs['files']['acceptance'])['generation'], 7)
        self.assertEqual(new_auth['lease'], old_auth['lease'])
        self.assertEqual(C.DATA_INPUTS_V18 - C.DATA_INPUTS_V17, {'leaseRenewal'})
        self.assertEqual(C.SOURCE_INPUTS_V18 - C.SOURCE_INPUTS_V17, {C.LEASE_RENEWAL_SOURCE})
        self.assertTrue(C.input_set(**inputs))
        self.assertEqual(result['inputHashes']['leaseRenewal'], C.sha(inputs['files']['leaseRenewal']))

        docs, previous = result['documents'], old['documents']
        cfg = C.document(docs[PREFIX + CONFIG])
        upgrade.shared_state(18, C.document(previous['versions/17/' + CONFIG]), cfg, inputs['files'], old_auth)
        runtime, old_runtime = (C.document(d[p + 'runtime-configuration.json'])
                                for d, p in ((docs, PREFIX), (previous, 'versions/17/')))
        self.assertEqual(runtime['candidates'], old_runtime['candidates'])
        self.assertEqual(cfg['schema'], policy.SCHEMA)
        self.assertEqual(cfg['leaseRenewal'], C.document(inputs['files']['leaseRenewal']))
        for role in C.ROLES:
            path = f'documents/{role}/preparer-template.json'
            template = C.document(docs[PREFIX + path])
            self.assertEqual(template, C.document(previous['versions/17/' + path]))
            self.assertEqual(template['budgetSeconds'], 12)
            self.assertEqual(template['kernel']['generation'], 2)
        for target, digest in cfg['sourceHashes'].items():
            path = PREFIX + 'source/' + target
            self.assertEqual(C.sha(docs[path]), digest)
            self.assertEqual(result['hashes'][path], digest)
            compile(docs[path], target, 'exec')

    def test_denies_wrong_version_shape_and_incompatible_budgets(self):
        inputs = self.inputs
        params = C.document(inputs['files']['leaseRenewal'])
        for change, code in (
            ({'renewalMarginSeconds': 20}, policy.INCOMPATIBLE),
            ({'renewalMarginSeconds': 28}, policy.INCOMPATIBLE),
            ({'lockWaitSeconds': 12}, policy.INCOMPATIBLE),
            ({'healthyResetSeconds': True}, policy.INVALID),
            ({'healthyResetSeconds': 0}, policy.INVALID),
            ({'fastRetryCount': 0}, policy.INVALID),
            ({'fastRetryCount': 2, 'fastRetryDelaysSeconds': [2, 1]}, policy.INVALID),
            ({'fastRetryDelaysSeconds': [6]}, policy.INVALID),
            ({'leaseSeconds': 31}, policy.INVALID),
        ):
            denied = inputs | {'files': inputs['files'] | {'leaseRenewal': C.canonical(params | change)}}
            with self.subTest(change=change), self.assertRaisesRegex(C.A.OperationDenied, '^' + code + '$'):
                self.compose(denied)
        with self.assertRaisesRegex(C.A.OperationDenied, policy.INVALID):
            self.compose(inputs | {'files': inputs['files'] | {'leaseRenewal': b'{"lockWaitSeconds":NaN}'}})
        without_input = inputs | {'files': {k: v for k, v in inputs['files'].items() if k != 'leaseRenewal'}}
        self.assertFalse(C.input_set(**without_input))
        with self.assertRaisesRegex(C.A.OperationDenied, 'EXACT_R3_INPUT_SET_REQUIRED'):
            self.compose(without_input)
        with self.assertRaisesRegex(C.A.OperationDenied, 'EXACT_R3_INPUT_SET_REQUIRED'):
            C.compose(inputs, 17, sequence=17, supersedes='f' * 64)

        # The same budget validator is used with the live sealed owner.
        dns = dict(timeoutSeconds=10, maxLeaseSeconds=30, applyBudgetSeconds=1)
        for profile, flows, driver, attempt in (
            (dns | {'maxLeaseSeconds': 24}, [30], 12, 30),
            (dns, [30, 23], 12, 30),
            (dns | {'timeoutSeconds': 15}, [30], 12, 30),
            (dns | {'applyBudgetSeconds': 3}, [30], 12, 30),
            (dns, [30], 12, 20),
            (dns, [30], 13, 30),
        ):
            # The driver case isolates the driver term from DNS + lock.
            selected = params | {'renewalMarginSeconds': 17, 'lockWaitSeconds': 1} if driver == 13 else params
            with self.subTest(profile=profile, flows=flows, driver=driver, attempt=attempt), \
                    self.assertRaisesRegex(ValueError, policy.INCOMPATIBLE):
                policy.budgets(selected, profile, [{'leaseSeconds': lease} for lease in flows], driver, attempt)
        self.compose(inputs | {'files': inputs['files'] | {'leaseRenewal': C.canonical(
            params | {'fastRetryCount': 0, 'fastRetryDelaysSeconds': []})}})

    def test_overlay_refuses_missing_or_duplicate_anchor(self):
        path = C.SOURCE_MAP_V18['scripts/semantic-provider-lease-supervisor-v2.py']
        original = self.inputs['sources'][path]
        anchor = b'RECOVERY_MODULES = ("activation_core",'
        for replacement in (b'RECOVERY_MODULES = ( "activation_core",', anchor + b'\n' + anchor):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(RuntimeError, 'R3_V18_SOURCE_CONTRACT_DRIFT'):
                self.compose(self.inputs | {'sources': self.inputs['sources'] | {
                    path: original.replace(anchor, replacement)}})

    def test_final_seal_rejects_drift_in_unmodified_recovery_source(self):
        path = 'tools/semantic_lease_recovery/deadline_backend.py'
        inputs = self.inputs | {'sources': self.inputs['sources'] | {
            path: self.inputs['sources'][path] + b'\n# Changed before composition.\n'}}
        with self.assertRaisesRegex(C.A.OperationDenied, '^R3_V18_SOURCE_CONTRACT_DRIFT$'):
            self.compose(inputs)

    def test_governed_upgrade_plans_unit_and_wrapper_for_version_18(self):
        result = self.compose(self.inputs)
        fixture = V12.NativeBindingsAndUpgrade().observation_fixture
        with fixture((self.inputs, self.previous, result), version=18) as (args, _, _, _):
            state, verified = upgrade.observe(args)
            self.assertEqual(verified, result)
            self.assertEqual((state['versionBefore'], state['versionAfter']), (17, 18))
            self.assertIn('/versions/18/', state['wrapperProposed']['text'])
            self.assertIn('/versions/18/source/scripts/semantic-provider-lease-supervisor-v2.py',
                          state['unit']['text'])
            self.assertIn(C.sha(result['documents'][PREFIX + CONFIG]), state['unit']['text'])
            self.assertEqual(state['unit']['sha256'], C.sha(state['unit']['text'].encode('ascii')))
            self.assertEqual({row['sha256'] for row in state['writes']['files']},
                             {C.sha(raw) for raw in result['documents'].values()})


class Journal:
    def __init__(self):
        self.row = None
        self.history = []

    def read(self):
        return deepcopy(self.row)

    def compare_and_save(self, previous, value):
        if self.row != previous:
            raise RuntimeError('FIXTURE_CAS_CONFLICT')
        self.row = deepcopy(value)
        self.history.append(self.read())


class AbsolutePosixPath(PurePosixPath):
    def absolute(self):
        if not self.is_absolute():
            raise ValueError('fixture paths must be absolute')
        return self


class RenewalFixture(unittest.TestCase):
    def native_runtime(self, supervisor, configuration):
        return supervisor.runtime(configuration)

    def setUp(self):
        scope = self.enterContext(ExitStack())
        scope.enter_context(V12.I.module_scope())
        scope.enter_context(patch.dict(sys.modules, {'fcntl': ModuleType('fcntl')}))
        self.mono, self.wall = 100., 1000.
        self.release = self.mono
        self.lock_deadlines, self.commands, self.lease_states, self.queries = [], [], [], []
        self.query_outcomes = []
        self.elements = {}
        self.locked = False
        self.owns = self.authorized = True
        self.apply_delay = self.readback_delay = 0
        self.applied_since_read = False
        self.after_wait = lambda: None
        self.stopped = False

        docs = self.result['documents']
        sequence = C.document(self.result['authorization'])['sequence']
        prefix = f'versions/{sequence}/'
        cfg_raw = docs[prefix + CONFIG]
        cfg = C.document(cfg_raw)
        self.cfg, self.coordination = cfg, C.document(self.inputs['files']['coordinationJournal'])
        root = PurePosixPath(cfg['sourceRoot'])
        owner_path = cfg['coordinator']['ownerConfiguration']['path']
        disk = {str(root / p): docs[prefix + 'source/' + p] for p in cfg['sourceHashes']}
        disk.update({str(PurePosixPath(owner_path).parent / 'source' / p): raw for p, raw in self.retained.items()})
        config_path = str(root.parent / CONFIG)
        disk.update({config_path: cfg_raw, owner_path: self.inputs['files']['coordinator'],
                     cfg['coordinator']['dnsProfile']['path']: docs[prefix + 'supervisor/dns-profile.json'],
                     cfg['mandatesModule']['path']: self.inputs['sources'][C.MANDATES]})

        def read(path, expected=None, **kwargs):
            if path == cfg['coordinator']['nftBinding']['path']:
                if kwargs != {'executable': True}:
                    raise AssertionError(kwargs)
                return b'fixture nft'
            raw = disk[str(path).replace('\\', '/')]
            if expected is not None and C.sha(raw) != expected:
                raise RuntimeError('SUPERVISOR_BINDING_HASH_MISMATCH')
            return raw

        bootstrap = V12.F.load('scripts/semantic-provider-lease-supervisor-v3.py', 'v18_boot_namespace')
        entry = root / bootstrap.SELF
        # Load the emitted, versioned bootstrap rather than the historical file.
        exec(compile(disk[str(entry)], str(entry), 'exec'), bootstrap.__dict__)
        bootstrap.Path = AbsolutePosixPath
        bootstrap.__file__ = str(entry)
        bootstrap.private = read
        bootstrap.private_root = lambda path: self.assertEqual(path, root)
        loaded_root, verified = bootstrap.load_sources(config_path, C.sha(cfg_raw))
        path = str(root / C.LEASE_RENEWAL_TARGET)
        sealed_policy = disk[path]
        disk[path] += b'\n'
        with self.assertRaisesRegex(RuntimeError, 'SUPERVISOR_BINDING_HASH_MISMATCH'):
            bootstrap.load_sources(config_path, C.sha(cfg_raw))
        disk[path] = sealed_policy
        self.assertEqual(loaded_root, root)
        self.sup = sup = bootstrap.execute(root, verified)
        sup.Path = PurePosixPath
        sup.read_file = read
        sup.time = SimpleNamespace(monotonic=self.clock)
        original_compile = sup.compiled

        def compile_source(*args):
            module = original_compile(*args)
            if args[2] == 'lease_activation_core_v2':
                original_load = module.load_installed

                def load(*args, **kwargs):
                    modules, retained = original_load(*args, **kwargs)
                    coordination = modules['semantic_provider_lease_coordination']
                    coordination.PrivateJournal = lambda _: SimpleNamespace(
                        read=lambda: deepcopy(self.coordination), write=self.write_coordination)
                    coordination.hold_common_lock = self.raw_lock
                    return modules, retained

                module.load_installed = load
            return module

        sup.compiled = compile_source
        configuration = sup.Configuration(config_path, C.sha(cfg_raw), reader=read)
        configuration.custody = lambda: verified
        self.c, _, _ = self.native_runtime(sup, configuration)
        self.backend = self.c.owner.backend
        self.backend.clock = self.c.owner.clock = self.clock
        self.backend.verify_ownership = self.verify
        self.backend.tables = self.tables
        base = sys.modules['nft_seconds_backend'].NftBackend
        scope.enter_context(patch.object(base, 'run', side_effect=self.run_nft))
        locking = sys.modules['semantic_common_lock_v2']
        locking.time = SimpleNamespace(monotonic=self.clock, sleep=self.advance)
        original_lock = locking.wait_common_lock

        def record_deadline(path, deadline):
            self.lock_deadlines.append(deadline)
            return original_lock(path, deadline)

        locking.wait_common_lock = record_deadline
        self.bounded = sys.modules['bounded_recovery']
        continuous = sys.modules['continuous_supervisor']
        self.dns = sys.modules['dns']
        self.observe_many = self.dns.observe_many
        self.dns.observe_many = self.query
        self.adapter = continuous.RenewingLeaseAdapter(self.c, self.dns, sys.modules['readback_margin_compiler'],
                                                       self.guard, lambda: None, self.clock)
        self.adapter.incident = sys.modules['recovery_journal'].Incident(
            sequence, {'adapter': 7, 'southbound': 9}, lambda: self.wall, self.clock)
        self.journal = Journal()
        self.r = sys.modules['lease_recovery_budget'].ObservedRecovery(
            self.journal, self.adapter, self.bounded.Policy(), 'a' * 64, 'b' * 64,
            lambda: (self.wall, self.mono), lambda: .5)
        self.journal.compare_and_save(None, self.r.initial())
        self.supervisor = continuous.Supervisor(self.r, self.c, 15, heartbeat=5)
        self.stop = SimpleNamespace(is_set=lambda: self.stopped, wait=self.wait)
        self.scheduled = self.supervisor.tick()
        self.assertEqual(self.scheduled['state'], 'ACTIVE')
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY'])
        self.lease_states.clear()
        self.queries.clear()
        self.commands.clear()
        self.lock_deadlines.clear()

    def clock(self):
        return self.mono

    def advance(self, seconds):
        self.mono += seconds
        self.wall += seconds

    def wait(self, seconds):
        self.advance(seconds)
        self.after_wait()
        return self.stopped

    @contextmanager
    def raw_lock(self, _):
        if self.clock() < self.release:
            raise BlockingIOError
        self.assertFalse(self.locked)
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def write_coordination(self, old, new):
        self.assertTrue(self.locked)
        self.assertEqual(old, self.coordination)
        self.coordination = deepcopy(new)
        self.lease_states.append(new['state'])

    def guard(self):
        if not self.authorized:
            raise self.bounded.Permanent('AUTHORITY_REVOKED')

    def verify(self, _):
        self.assertTrue(self.locked)
        if not self.owns:
            raise RuntimeError('NFT_INSTALLATION_STRUCTURE_DRIFT')

    def query(self, requests, *args, deadline, **kwargs):
        self.assertFalse(self.locked)
        self.queries.append((self.clock(), deadline))
        outcome = self.query_outcomes.pop(0) if self.query_outcomes else None
        if isinstance(outcome, str):
            raise self.dns.DNSDenied(outcome)
        ttl = 30 if outcome is None else outcome
        return [{'usableAddresses': ['1.1.1.1'], 'observedMonotonic': self.clock(),
                 'expiresMonotonic': self.clock() + ttl} for _ in requests]

    def tables(self):
        self.assertTrue(self.locked)
        if self.applied_since_read:
            self.applied_since_read = False
            self.advance(self.readback_delay)
        return {family: {'nftables': [
            {'set': {'family': family, 'table': self.backend.table, 'name': f'provider_{index}',
                     'flags': ['timeout'], 'type': 'ipv4_addr',
                     'elem': [{'elem': {'val': address, 'expires': max(0, math.floor(expires - self.clock()))}}
                              for address, expires in self.elements.get((family, index), {}).items()]}}
            for index in range(len(self.c.configuration['providerFlows']))]}
                for family in ('inet', 'bridge')}

    def run_nft(self, arguments, raw=None, timeout=None):
        self.assertTrue(self.locked)
        self.assertEqual(arguments, ['-f', '-'])
        self.commands.append((self.clock(), self.backend.active_deadline, timeout))
        self.elements = {(family, int(index)): {address: self.clock() + int(ttl)}
                         for family, index, address, ttl in re.findall(
                             r'add element (inet|bridge) \w+ provider_(\d+) \{ ([0-9.]+) timeout (\d+)s \}', raw)}
        if self.elements:
            self.advance(self.apply_delay)
            self.applied_since_read = True

    def renew(self):
        return self.supervisor.renew(self.scheduled, self.stop)

    def assert_closed(self):
        self.assertEqual(self.coordination['state'], 'QUIESCED')
        self.assertIs(self.coordination['leaseAuthorized'], False)
        self.assertEqual(self.elements, {})


class RenewalRuntime(RenewalFixture):
    @classmethod
    def setUpClass(cls):
        cls.inputs, previous = fixture()
        cls.result = C.compose(cls.inputs, 18, sequence=18, supersedes=C.sha(previous['authorization']))
        cls.retained = V12.fixture()[2]

    def test_lock_released_before_attempt_deadline(self):
        deadline = self.clock() + 5
        self.release = self.clock() + 3.5
        evidence = self.adapter.prepare_renewal(deadline)
        ref = self.adapter.publish_renewal(evidence, deadline, self.scheduled['leaseJournal'])
        self.assertEqual(len(ref), 64)
        self.assertEqual(self.lock_deadlines, [deadline - policy.COMMIT_SECONDS])
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY'])

    def test_lock_released_after_attempt_deadline(self):
        deadline = self.clock() + 5
        self.release = deadline + .05
        evidence = self.adapter.prepare_renewal(deadline)
        with self.assertRaisesRegex(self.bounded.BeforeLeaseMutation, 'COMMON_LOCK_TIMEOUT'):
            self.adapter.publish_renewal(evidence, deadline, self.scheduled['leaseJournal'])
        self.assertEqual(self.clock(), deadline - policy.COMMIT_SECONDS)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.lease_states, [])
        self.assertEqual(self.coordination, self.scheduled['leaseJournal'])

    def test_rechecks_immediately_after_acquisition(self):
        @contextmanager
        def late_lock(deadline):
            self.advance(deadline - self.clock())
            yield

        evidence = self.adapter.prepare_renewal(self.clock() + 5)
        self.c.hold_until = late_lock
        self.adapter.guard = lambda: self.fail('late lock must stop before the guard')
        with self.assertRaisesRegex(self.bounded.BeforeLeaseMutation, 'DNS_WINDOW_TOO_SHORT'):
            self.adapter.publish_renewal(evidence, self.clock() + 5, self.scheduled['leaseJournal'])
        self.assertEqual(self.commands, [])
        self.assertEqual(self.lease_states, [])

    def test_true_lock_timeout_revokes_on_independent_budget(self):
        start = self.clock()
        self.release = start + 14
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('RETRY_WAIT', 'COMMON_LOCK_TIMEOUT'))
        self.assertEqual(self.lock_deadlines[:2], [start + 6, start + 12])
        self.assertEqual(len(self.queries), 1)
        self.assertEqual(row['fastRenewalRetries'], 0)
        self.assertEqual(self.commands[0][1], start + 12 + policy.REVOCATION_SECONDS)
        self.assert_closed()
        incident = row['lastIncident']
        self.assertEqual((incident['phase'], incident['code'], incident['revocation']),
                         ('LOCK_ACQUIRE', 'COMMON_LOCK_TIMEOUT', 'VERIFIED'))
        self.assertGreater(incident['pausedAt'], incident['failedAt'])
        self.assertEqual(incident['nextRetryAt'], row['nextWall'])

    def test_dns_expiry_limits_lock_and_retry_uses_fresh_dns(self):
        start = self.clock()
        self.query_outcomes[:] = [5, 30]
        self.release = start + 2.1
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('ACTIVE', 'RENEWED'))
        self.assertEqual(self.lock_deadlines[0], start + 2)
        self.assertEqual(len(self.queries), 2)
        self.assertGreater(self.queries[1][0], self.queries[0][0])
        self.assertLessEqual(self.queries[1][1], self.queries[0][1])
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY'])

    def test_composed_fast_retry_keeps_lease_and_records_incident(self):
        before = self.r.remaining(self.journal.read())
        failed_at = self.wall
        self.query_outcomes[:] = ['DNS_UNAVAILABLE', 30]

        def during_wait():
            row = self.journal.read()
            self.assertEqual((row['state'], row['reason']), ('ACTIVE', 'RENEWAL_RETRY_PENDING'))
            self.assertEqual((row['attempts'], row['fastRenewalRetries']), (2, 1))
            self.assertEqual(self.lease_states, [])
            self.assertEqual(len(self.queries), 1)
            self.assertEqual(self.coordination, self.scheduled['leaseJournal'])
            self.assertTrue(all(expiry > self.clock() for members in self.elements.values() for expiry in members.values()))
            incident = row['lastIncident']
            self.assertEqual((incident['phase'], incident['code'], incident['stateAtFailure']),
                             ('DNS', 'DNS_UNAVAILABLE', 'ACTIVE'))
            self.assertEqual((incident['failedAt'], incident['nextRetryAt']), (failed_at, failed_at + 1))
            self.assertIsNone(incident['pausedAt'])
            self.assertIsNone(incident['resumedAt'])

        self.after_wait = during_wait
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('ACTIVE', 'RENEWED'))
        self.assertEqual((row['attempts'], row['fastRenewalRetries'], row['backoffAttempts']), (2, 0, 1))
        self.assertEqual(self.r.remaining(row), before - 1)
        self.assertEqual([when for when, _ in self.queries], [100., 101.])
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY'])
        self.assertEqual({family for family, _ in self.elements}, {'inet', 'bridge'})
        pending, renewed = self.journal.history[-2:]
        self.assertEqual(renewed['lastIncident'], pending['lastIncident'] | {'resumedAt': self.wall})
        self.assertEqual(renewed['lastIncident']['revocation'], 'UNPROVEN')

    def test_insufficient_time_for_early_retry_revokes(self):
        old_query = self.dns.observe_many

        def query(*args, **kwargs):
            self.advance(15)  # delayed post-query control before the error is delivered
            return old_query(*args, **kwargs)

        self.dns.observe_many = query
        self.query_outcomes[:] = ['DNS_UNAVAILABLE']
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('RETRY_WAIT', 'DNS_UNAVAILABLE'))
        self.assertEqual(row['attempts'], 1)
        self.assertEqual(len(self.queries), 1)
        self.assert_closed()

    def test_unclassified_no_effect_flag_does_not_keep_lease(self):
        def failure(_):
            raise self.bounded.Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True)

        self.adapter.prepare_renewal = failure
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('RETRY_WAIT', 'DNS_WINDOW_TOO_SHORT'))
        self.assertEqual(row['fastRenewalRetries'], 0)
        self.assert_closed()

    def test_exhausted_recovery_budget_does_not_admit_fast_retry(self):
        old = self.journal.read()
        self.journal.compare_and_save(old, old | {'attempts': self.r.policy.max_attempts})
        self.query_outcomes[:] = ['DNS_UNAVAILABLE']
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('PAUSED_EXHAUSTED', 'RETRY_BUDGET_EXHAUSTED'))
        self.assertEqual(len(self.queries), 1)
        self.assert_closed()

    def test_lease_authority_revoked_during_wait(self):
        self.query_outcomes[:] = ['DNS_UNAVAILABLE']

        def revoke():
            self.assertEqual(self.journal.read()['reason'], 'RENEWAL_RETRY_PENDING')
            self.authorized = False

        self.after_wait = revoke
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('BLOCKED', 'AUTHORITY_REVOKED'))
        self.assertEqual(len(self.queries), 1)
        self.assertEqual(self.lease_states, ['QUIESCING', 'QUIESCED'])
        self.assert_closed()
        incident = row['lastIncident']
        self.assertEqual((incident['phase'], incident['code'], incident['revocation']),
                         ('DNS', 'DNS_UNAVAILABLE', 'VERIFIED'))
        self.assertEqual(incident['pausedAt'], self.wall)

    def test_cancelled_fast_retry_records_verified_pause(self):
        self.query_outcomes[:] = ['DNS_UNAVAILABLE']

        def cancel():
            self.stopped = True

        self.after_wait = cancel
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('CANCELLED', 'CANCELLED_BY_OWNER'))
        self.assertEqual(len(self.queries), 1)
        self.assert_closed()
        pending = self.journal.history[-2]['lastIncident']
        self.assertEqual(row['lastIncident'], pending | {'revocation': 'VERIFIED', 'pausedAt': self.wall})

    def test_revocation_unproven_has_distinct_result(self):
        self.query_outcomes[:] = ['DNS_UNAVAILABLE']

        def revoke():
            self.authorized = self.owns = False

        self.after_wait = revoke
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('BLOCKED', 'SAFE_PAUSE_UNPROVEN'))
        self.assertEqual(self.coordination['state'], 'QUIESCING')
        self.assertEqual(self.commands, [])
        self.assertEqual(len(self.queries), 1)
        self.assertTrue(self.elements)  # only the original finite kernel TTL remains
        self.assertEqual(row['lastIncident']['revocation'], 'UNPROVEN')
        self.assertIsNone(row['lastIncident']['pausedAt'])

    def test_expires_zero_revokes_without_retaining_lease(self):
        self.elements['bridge', 0]['1.1.1.1'] = self.clock() + .5
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('RETRY_WAIT', 'DNS_WINDOW_TOO_SHORT'))
        self.assertEqual(len(self.queries), 1)
        self.assertEqual(self.lease_states, ['QUIESCING', 'QUIESCED'])
        self.assert_closed()

    def check_overrun(self):
        row = self.renew()
        self.assertEqual(row['state'], 'RECONCILE_REQUIRED')
        self.assertEqual(len(self.queries), 1)
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'QUIESCING', 'QUIESCED'])
        self.assertEqual(self.commands[0][1], 101.)
        self.assertGreater(self.commands[1][1], 101.)
        self.assert_closed()

    def test_apply_overrun_closes_ambiguous_publication(self):
        self.apply_delay = 1.1
        self.check_overrun()

    def test_readback_overrun_closes_ambiguous_publication(self):
        self.readback_delay = 1.1
        self.check_overrun()

    def test_healthy_period_resets_only_backoff_rung(self):
        row = self.journal.read()
        self.journal.compare_and_save(row, row | {'attempts': 7, 'backoffAttempts': 6})
        before = self.r.remaining(row)
        for _ in range(59):
            self.advance(self.scheduled['waitSeconds'])
            row = self.renew()
            self.assertEqual(row['backoffAttempts'], 6)
            self.scheduled = self.supervisor.tick()
        self.advance(self.scheduled['waitSeconds'])
        row = self.renew()
        self.assertEqual((row['attempts'], row['backoffAttempts']), (7, 1))
        self.assertEqual(self.r.remaining(row), before)
        self.scheduled = self.supervisor.tick()
        self.query_outcomes[:] = ['DNS_UNAVAILABLE', 'DNS_UNAVAILABLE']
        row = self.renew()
        self.assertEqual((row['attempts'], row['backoffAttempts']), (8, 1))
        self.assertEqual(row['nextMonotonic'] - self.clock(), 5.)
        self.assertEqual(self.r.remaining(row), before - 1)
        self.assert_closed()
