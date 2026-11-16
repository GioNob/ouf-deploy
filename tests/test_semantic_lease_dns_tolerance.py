"""Portable D-043 tests: no sockets, services, credentials or external clocks."""
import copy
import importlib.util
import json
from contextlib import nullcontext
from pathlib import Path, PurePosixPath
import re
import sys
import threading
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools/semantic_lease_recovery'))
from tools.semantic_lease_recovery import dns_v2 as dns
from tools.semantic_lease_recovery import resilient_lease_adapter_v2 as adapter
from tools.semantic_lease_recovery import adaptive_supervisor_v2 as scheduler
from bounded_recovery import Temporary, Permanent


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Clock:
    def __init__(self): self.now = 100.
    def __call__(self): return self.now


class Threads:
    """Deterministic scheduler: model entire resolver workers, never wall sleeps."""
    def __init__(self, clock, delays):
        self.clock, self.delays, self.threads = clock, delays, []
    def __call__(self, *, target, args, daemon):
        owner = self
        class Thread:
            def __init__(self):
                self.when = owner.clock() + owner.delays[args[0]]
                self.done = self.started = False
                self.daemon = daemon
            def start(self): self.started = True
            def is_alive(self): return self.started and not self.done
            def join(self, timeout):
                if self.done: return
                until = min(self.when, owner.clock() + timeout)
                for thread in sorted(owner.threads, key=lambda t: t.when):
                    if thread.started and not thread.done and thread.when <= until:
                        owner.clock.now = max(owner.clock(), thread.when)
                        thread.finish()
                owner.clock.now = max(owner.clock(), until)
            def finish(self):
                self.done = True
                target(*args)
        thread = Thread()
        self.threads.append(thread)
        return thread


def packet(host, qtype, address='1.1.1.1', ttl=60):
    records = ([{'owner': host, 'type': 1, 'class': 1, 'ttl': ttl, 'value': address, 'section': 'answer'}]
               if qtype == 1 and address else
               [{'owner': host, 'type': 6, 'class': 1, 'ttl': ttl, 'value': ttl, 'section': 'authority'}])
    return {'records': records, 'transport': 'UDP', 'responseHash': 'a'*64, 'authenticatedDataFlag': False}


class DNSPolicy(unittest.TestCase):
    resolvers = ['46.38.225.230', '46.38.252.230']
    def setUp(self):
        self.registry = patch.object(dns, '_workers', {})
        self.registry.start(); self.addCleanup(self.registry.stop)
    def observe(self, delays=(0., 0.), query=None, requests=None):
        dns._workers.clear()  # independent synthetic observation fixture
        self.clock = Clock()
        self.threads = Threads(self.clock, dict(zip(self.resolvers, delays)))
        def default(resolver, port, host, qtype, deadline):
            self.assertEqual(deadline, 110.)
            return packet(host, qtype, '1.1.1.1' if resolver == self.resolvers[0] else '8.8.8.8')
        requests = requests or [('https://fixture.invalid', 4, [])]
        return dns.observe_many(requests, self.resolvers, 53, 10, 30, query or default,
            monotonic=self.clock, wall_clock=lambda: 1000., sleep=lambda n: setattr(self.clock, 'now', self.clock()+n),
            thread_factory=self.threads)

    def test_missing_resolver_uses_full_budget_then_succeeds(self):
        row = self.observe((float('inf'), .08))[0]
        self.assertEqual(row['allAddresses'], ['8.8.8.8'])
        self.assertEqual(row['missedResolvers'], [{'resolver': self.resolvers[0], 'code': 'DNS_DEADLINE_EXPIRED'}])
        self.assertEqual(self.clock(), 110.)
        self.assertEqual(row['remainingLeaseSecondsAtObservation'], 20)
        self.assertEqual(row['expiresMonotonic'], 130.)
        self.assertEqual(len(self.threads.threads), 2)
        self.assertTrue(all(t.daemon for t in self.threads.threads))

    def test_both_valid_union_and_ttl_from_valid_only(self):
        row = self.observe((.05, .08))[0]
        self.assertEqual(row['allAddresses'], ['1.1.1.1', '8.8.8.8'])
        self.assertEqual(row['missedResolvers'], [])
        self.assertEqual(len(row['observations']), 2)
        def query(resolver, port, host, qtype, deadline):
            if resolver == self.resolvers[0]:
                if qtype == 28: raise dns.DNSDenied('DNS_TCP_RESPONSE_INCOMPLETE')
                return packet(host, qtype, '1.1.1.1', 0)
            return packet(host, qtype, '8.8.8.8', 60)
        row = self.observe(query=query)[0]
        self.assertEqual(row['minimumObservedTtlSeconds'], 60)
        self.assertEqual(row['allAddresses'], ['8.8.8.8'])
        self.assertEqual(set(row['missedResolvers'][0]), {'resolver', 'code'})

    def test_invalid_response_is_not_tolerated_even_if_aaaa_missing(self):
        def query(resolver, port, host, qtype, deadline):
            if resolver == self.resolvers[0]:
                if qtype == 28: raise dns.DNSDenied('DNS_RESOLVER_TRANSPORT_FAILED')
                return packet(host, qtype, '10.1.1.1')
            return packet(host, qtype)
        with self.assertRaisesRegex(dns.DNSDenied, 'DNS_PROVIDER_ADDRESS_POLICY_MISMATCH'):
            self.observe(query=query)

    def test_none_valid_is_unavailable_with_safe_evidence(self):
        with self.assertRaisesRegex(dns.DNSDenied, 'DNS_UNAVAILABLE') as caught:
            self.observe((float('inf'), float('inf')))
        self.assertEqual(len(caught.exception.missed_resolvers), 2)
        self.assertEqual(self.clock(), 110.)
        for row in caught.exception.missed_resolvers: self.assertEqual(set(row), {'resolver', 'code'})

    def test_slow_three_seconds_runs_in_parallel(self):
        row = self.observe((3., .05))[0]
        self.assertLess(self.clock()-100., 3.5)
        self.assertEqual(len(row['observations']), 2)
        self.assertEqual(self.clock(), 103.)

    def test_late_worker_cannot_mutate_result(self):
        row = self.observe((11., .05))[0]
        before = copy.deepcopy(row)
        self.clock.now = 111.
        self.threads.threads[0].finish()
        self.assertEqual(row, before)

    def test_only_missing_codes_are_tolerated(self):
        for code in sorted(dns.MISSING):
            def query(resolver, port, host, qtype, deadline):
                if resolver == self.resolvers[0]: raise dns.DNSDenied(code)
                return packet(host, qtype)
            self.assertEqual(self.observe(query=query)[0]['missedResolvers'][0]['code'], code)
        for code in ('DNS_CNAME_ADDRESS_CONFLICT', 'DNS_CNAME_CHAIN_AMBIGUOUS_OR_LONG',
                     'DNS_CNAME_CHAIN_CYCLE', 'DNS_QUESTION_MISMATCH', 'DNS_RECORD_BOUNDS_INVALID'):
            def query(resolver, port, host, qtype, deadline):
                if resolver == self.resolvers[0]: raise dns.DNSDenied(code)
                return packet(host, qtype)
            with self.assertRaisesRegex(dns.DNSDenied, code): self.observe(query=query)

    def test_complete_negative_resolver_can_coexist_with_positive(self):
        def query(resolver, port, host, qtype, deadline):
            return packet(host, qtype, None if resolver == self.resolvers[0] else '1.1.1.1')
        row = self.observe(query=query)[0]
        self.assertEqual(len(row['observations']), 2)
        self.assertEqual(row['usableAddresses'], ['1.1.1.1'])

    def test_two_flows_share_budget_and_resolver_threads(self):
        rows = self.observe((float('inf'), 3.), requests=[('https://a.invalid', 4, []), ('https://b.invalid', 4, [])])
        self.assertEqual(len(self.threads.threads), 2)
        self.assertEqual(self.clock(), 110.)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r['usableAddresses'] == ['8.8.8.8'] for r in rows))

    def test_noncacheable_retries_are_fresh_and_bounded(self):
        calls = []
        def query(resolver, port, host, qtype, deadline):
            calls.append((resolver, qtype, deadline))
            return packet(host, qtype, ttl=0)
        with self.assertRaisesRegex(dns.DNSDenied, 'DNS_OBSERVATION_EXPIRED_OR_NONCACHEABLE') as caught:
            self.observe(query=query)
        self.assertEqual(caught.exception.fresh_observation_attempts, 3)
        self.assertEqual(len(calls), 12)
        self.assertLess(self.clock(), 110.)

    def test_caller_deadline_can_shorten_the_global_budget(self):
        clock = Clock()
        threads = Threads(clock, {self.resolvers[0]: float('inf'), self.resolvers[1]: .05})
        row = dns.observe('https://fixture.invalid', self.resolvers, 53, 4, [], 10, 30,
            lambda r,p,h,t,d: packet(h,t), monotonic=clock, thread_factory=threads, deadline=105.)
        self.assertEqual(clock(), 105.)
        self.assertEqual(row['remainingLeaseSecondsAtObservation'], 25)
        self.assertEqual(row['missedResolvers'][0]['code'], 'DNS_DEADLINE_EXPIRED')

    def test_cname_chain_and_negative_proof_keep_minimum_ttl(self):
        calls = []
        def query(resolver, port, host, qtype, deadline):
            calls.append((resolver, host, qtype))
            if host == 'fixture.invalid':
                return {'records': [{'owner': host, 'type': 5, 'class': 1, 'ttl': 25,
                        'value': 'target.invalid', 'section': 'answer'}], 'transport': 'UDP',
                        'responseHash': 'b'*64, 'authenticatedDataFlag': False}
            return packet(host, qtype, ttl=60)
        row = self.observe(query=query)[0]
        self.assertEqual(row['minimumObservedTtlSeconds'], 25)
        self.assertEqual(row['remainingLeaseSecondsAtObservation'], 25)
        self.assertEqual(len(calls), 8)
        for observation in row['observations']:
            for value in observation['types'].values():
                self.assertEqual(value['cnameChain'], [{'owner': 'fixture.invalid', 'target': 'target.invalid'}])

    def test_families_and_eight_thread_limit(self):
        clock = Clock()
        resolvers = ['1.1.1.'+str(i) for i in range(1, 8)] + ['2001:4860:4860::8888']
        threads = Threads(clock, dict.fromkeys(resolvers, 0))
        row = dns.observe('https://fixture.invalid', resolvers, 53, 4, [], 10, 30,
            lambda r,p,h,t,d: packet(h,t), monotonic=clock, thread_factory=threads)
        self.assertEqual(len(threads.threads), 7)
        self.assertEqual(row['deferredResolvers'], [resolvers[-1]])
        with self.assertRaisesRegex(dns.DNSDenied, 'BOUNDED_EXPLICIT_DNS_PROFILE_REQUIRED'):
            dns.observe('https://fixture.invalid', resolvers + ['8.8.8.8'], 53, 4, [], 10, 30,
                        query=lambda *a: self.fail('no IO before profile validation'))
        with self.assertRaisesRegex(dns.DNSDenied, 'DNS_RESOLVER_FAMILY_MISSING'):
            dns.observe('https://fixture.invalid', resolvers[:1], 53, 6, [], 10, 30)

    def test_repeated_observation_cannot_accumulate_late_daemons(self):
        self.observe((float('inf'), .05))
        first_count = len(self.threads.threads)
        previous = dns._workers[self.resolvers[0]]
        rows = dns.observe_many([('https://fixture.invalid', 4, [])], self.resolvers, 53, 10, 30,
            lambda r,p,h,t,d: packet(h,t), monotonic=self.clock, thread_factory=self.threads)
        self.assertIs(dns._workers[self.resolvers[0]], previous)
        self.assertEqual(len(self.threads.threads), first_count + 1)
        self.assertEqual(rows[0]['missedResolvers'][0]['code'], 'DNS_DEADLINE_EXPIRED')
        self.assertLessEqual(sum(t.is_alive() for t in dns._workers.values()), len(self.resolvers))

    def test_actual_daemon_late_query_is_ignored(self):
        clock = Clock(); gate = threading.Event(); entered = threading.Event(); finished = threading.Event()
        def query(resolver, port, host, qtype, deadline):
            if resolver == self.resolvers[0]:
                entered.set(); gate.wait(2); finished.set()
            return packet(host, qtype)
        real_threads = []
        def factory(**kw):
            thread = threading.Thread(**kw); real_threads.append(thread)
            class Wrapper:
                def start(self): thread.start()
                def is_alive(self): return thread.is_alive()
                def join(self, timeout):
                    if kw['args'][0] == self.resolvers[0]:
                        self.assert_entered()
                        # Let the fast real worker finish before advancing to cutoff.
                        real_threads[1].join(2)
                        clock.now = 110.
                    else: thread.join(2)
                def assert_entered(self):
                    if not entered.wait(2): raise AssertionError('worker not started')
                resolvers = DNSPolicy.resolvers
            return Wrapper()
        try:
            row = dns.observe('https://fixture.invalid', self.resolvers, 53, 4, [], 10, 30, query,
                              monotonic=clock, thread_factory=factory)
            before = copy.deepcopy(row)
            gate.set()
            for thread in real_threads: thread.join(2)
            self.assertTrue(finished.is_set())
            self.assertTrue(all(not t.is_alive() and t.daemon for t in real_threads))
            self.assertEqual(row, before)
        finally: gate.set()


def kernel_configuration():
    return {'tableName': 'fixture', 'guardedInterfaces': ['isolated'], 'existingInterfaces': [], 'staticFlows': [],
        'providerFlows': [{'endpointRef': 'flow'+str(i), 'endpoint': 'https://fixture'+str(i)+'.invalid',
            'source': '172.22.0.2', 'addresses': [], 'leaseSeconds': 30,
            'resolutionEvidenceRef': 'proof'+str(i), 'allowedPrivateAddresses': []} for i in range(2)]}


def owner_modules():
    kernel = load('tools/semantic_cohort_admission/cohort-draft/tools/materialize_southbound_kernel.py', 'v11_kernel')
    with patch.dict(sys.modules, {'tools.materialize_southbound_kernel': kernel}):
        compiler = load('tools/semantic_lease_recovery/readback_margin_compiler.py', 'v11_compiler')
        with patch.dict(sys.modules, {'tools.materialize_southbound_lease_refresh': compiler,
                                     'tools.semantic_provider_dns': dns}):
            owner = load('tools/semantic_lease_recovery/lease_owner_v2.py', 'v11_owner')
    return compiler, owner


class LeasePaths(unittest.TestCase):
    def setUp(self):
        self.registry = patch.object(dns, '_workers', {})
        self.registry.start(); self.addCleanup(self.registry.stop)
    def fixture(self):
        clock = Clock(); cfg = kernel_configuration(); compiler, owner = owner_modules()
        profile = {'resolvers': DNSPolicy.resolvers, 'resolverPort': 53,
                   'timeoutSeconds': 10, 'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1}
        backend = types.SimpleNamespace(expected='a'*64, verify_ownership=lambda _: None)
        obj = owner.LeaseOwner(cfg, profile, backend, clock=clock)
        coordinator = types.SimpleNamespace(configuration=cfg, owner=obj)
        lease = adapter.LeaseAdapter(coordinator, dns, compiler, lambda: None, lambda: None, clock)
        threads = Threads(clock, {DNSPolicy.resolvers[0]: float('inf'), DNSPolicy.resolvers[1]: .08})
        original = dns.observe_many
        def observe(*args, **kw):
            return original(*args, query=lambda r,p,h,t,d: packet(h,t), monotonic=clock,
                            thread_factory=threads)
        return clock, coordinator, lease, observe

    def test_adapter_full_ten_second_budget_and_integrity_classification(self):
        clock, c, lease, observe = self.fixture()
        with patch.object(dns, 'observe_many', side_effect=observe):
            evidence = lease.fresh_evidence(130.)
        self.assertFalse(evidence['plan']['denyOnly'])
        self.assertEqual(clock(), 110.)
        self.assertEqual({v['expiresMonotonic'] for v in evidence['values']}, {130.})
        self.assertIn('timeout 19s', evidence['plan']['nftTransaction'])
        for code, expected, error_type in [('DNS_PROVIDER_ADDRESS_POLICY_MISMATCH', 'INTEGRITY_UNPROVEN', Permanent),
                ('DNS_UNAVAILABLE', 'DNS_UNAVAILABLE', Temporary)]:
            with patch.object(dns, 'observe_many', side_effect=dns.DNSDenied(code)):
                with self.assertRaises(error_type) as caught: lease.fresh_evidence(150.)
                self.assertEqual(caught.exception.code, expected)

    def test_owner_uses_same_dns_and_absolute_expiry(self):
        clock, c, lease, observe = self.fixture()
        applied = []
        c.owner.backend.apply = lambda transaction, deadline: applied.append(transaction)
        c.owner.backend.read_sets = lambda _: {(family, i): {'1.1.1.1': 19}
                                  for family in ('inet', 'bridge') for i in range(2)}
        with patch.object(dns, 'observe_many', side_effect=observe): result = c.owner.refresh()
        self.assertTrue(result['freshDnsQueried'])
        self.assertEqual(clock(), 110.)
        self.assertIn('timeout 19s', applied[0])
        self.assertEqual(len(result['dnsObservations']), 2)

    def test_repeated_full_budget_renewals_publish_before_old_expiry(self):
        clock, c, lease, observe = self.fixture()
        c.hold_lock = nullcontext
        c.journal = lambda: {'state': 'LEASE_READY', 'leaseAuthorized': True,
                            'startAuthorized': False, 'leaseAddresses': [['1.1.1.1']]*2}
        # Use the real DNS, adapter, margin compiler and scheduler repeatedly.
        with patch.object(dns, 'observe_many', side_effect=observe):
            evidence = lease.fresh_evidence(130.)
            for _ in range(5):
                dns._workers.clear()  # prior fake transport has ended; no result reuse
                seconds = int(re.search(r'timeout (\d+)s', evidence['plan']['nftTransaction'])[1])
                old_deadline = clock() + seconds
                clock.now += .5  # publication/readback fits the governed 1 s budget
                c.owner.backend.read_sets = lambda _: {(f,i): {'1.1.1.1': old_deadline-clock()}
                                      for f in ('inet','bridge') for i in range(2)}
                scheduled = scheduler.window(c, 15, clock=clock)
                clock.now += scheduled['waitSeconds']
                # Fresh fake workers for this new observation, same 10 s cutoff.
                evidence = lease.fresh_evidence(old_deadline - 1)
                self.assertLess(clock()+1, old_deadline)
                self.assertEqual(scheduled['deadlineMonotonic'], old_deadline)
                self.assertFalse(evidence['plan']['denyOnly'])


class SealedRuntime(unittest.TestCase):
    def test_real_v11_loader_keeps_owner_original_and_applies_bound_deltas(self):
        sys.path.insert(0, str(ROOT / 'tests'))
        import test_semantic_provider_r3_compose as F
        from tools.semantic_provider_r3 import compose as C, install_common as I
        inputs = F.fixture(11)
        owner = json.loads(inputs['files']['coordinator'])
        kernel = kernel_configuration()
        kernel.update(tableName='ouf_sem_provider', guardedInterfaces=['oufsp-int', 'oufsp-egress'], existingInterfaces=['br-backend'])
        kernel['providerFlows'][1]['source'] = '172.22.0.3'
        owner.update(kernel=kernel, readBudgetSeconds=1)
        names = ('materialize_southbound_kernel', 'semantic_provider_dns', 'materialize_southbound_lease_refresh',
                 'semantic_provider_lease_nft', 'semantic_provider_lease_owner', 'semantic_provider_lease_coordination')
        retained = {'tools/'+n+'.py': (ROOT / 'tools/semantic_cohort_admission/cohort-draft/tools' / (n+'.py')).read_bytes().replace(b'\r\n',b'\n')
                    for n in names}
        retained['tools/semantic_provider_coordinated_supervisor.py'] = (ROOT / 'tools/semantic_lease_recovery/adaptive_supervisor.py').read_bytes().replace(b'\r\n',b'\n')
        retained['scripts/run_semantic_coordinated_lease_owner.py'] = b'# synthetic installed entrypoint, never executed\n'
        owner['sourceHashes'] = {p: C.sha(raw) for p, raw in retained.items()}
        inputs['files']['coordinator'] = C.canonical(owner)
        settings = json.loads(inputs['files']['settings'])
        settings['coordinatorBinding']['sha256'] = C.sha(inputs['files']['coordinator'])
        inputs['files']['settings'] = C.canonical(settings)
        result = C.compose(inputs, 11, sequence=11, supersedes='a'*64)
        prefix = 'versions/11/'
        cfg = json.loads(result['documents'][prefix+'supervisor/configuration.json'])
        verified = {p: result['documents'][prefix+'source/'+p] for p in cfg['sourceHashes']}
        delivered = {str(PurePosixPath(cfg['sourceRoot'])/p): raw for p, raw in verified.items()}
        installed_root = PurePosixPath(settings['coordinatorBinding']['path']).parent / 'source'
        delivered.update({str(installed_root / p): raw for p, raw in retained.items()})
        delivered[settings['coordinatorBinding']['path']] = inputs['files']['coordinator']
        delivered[cfg['coordinator']['dnsProfile']['path']] = result['documents'][prefix+'supervisor/dns-profile.json']
        delivered[cfg['mandatesModule']['path']] = inputs['sources'][C.MANDATES]
        def read(path, expected=None, **kw):
            raw = delivered[str(path).replace(chr(92), chr(47))]
            if expected is not None: self.assertEqual(C.sha(raw), expected)
            return raw
        supervisor = C.contract_module(inputs['sources'][C.SOURCE_MAP_V11[C.SUPERVISOR]], 'v11_loaded')
        configuration = types.SimpleNamespace(value=cfg, custody=lambda: verified)
        real_compile = supervisor.compiled
        def compiled(*args):
            module = real_compile(*args)
            if args[2] == 'lease_activation_core_v2':
                real_load = module.load_installed
                def installed(*a, **kw):
                    modules, retained_bytes = real_load(*a, **kw)
                    # Native journal custody is a boundary, never touch /etc.
                    modules['semantic_provider_lease_coordination'].PrivateJournal = lambda _: types.SimpleNamespace(
                        read=lambda: None, write=lambda *a: None)
                    return modules, retained_bytes
                module.load_installed = installed
            return module
        with I.module_scope(), patch.dict(sys.modules, {'fcntl': types.ModuleType('fcntl')}), \
                patch.object(supervisor, 'read_file', side_effect=read), \
                patch.object(supervisor, 'compiled', side_effect=compiled):
            coordinator, guards, factory = supervisor.runtime(configuration)
            self.assertEqual(coordinator.owner.profile, {**owner['dns'], 'timeoutSeconds': 10})
            self.assertEqual(coordinator.configuration, owner['kernel'])
            self.assertEqual(coordinator.binding, owner['binding'])
            self.assertTrue(hasattr(sys.modules['dns'], 'observe_many'))
            self.assertTrue(hasattr(sys.modules['tools.semantic_provider_dns'], 'observe_many'))
            self.assertIn('observe_many', coordinator.owner.refresh.__code__.co_names)
            self.assertEqual(sys.modules['continuous_supervisor'].LeaseAdapter.fresh_evidence.__code__.co_filename,
                             str(PurePosixPath(cfg['sourceRoot'])/'tools/semantic_lease_recovery/resilient_lease_adapter.py'))
            self.assertEqual(sys.modules['adaptive_supervisor'].window.__code__.co_filename,
                             str(PurePosixPath(cfg['sourceRoot'])/'tools/semantic_lease_recovery/adaptive_supervisor.py'))
            self.assertEqual(json.loads(delivered[settings['coordinatorBinding']['path']])['dns']['timeoutSeconds'], 2)
            # Profile substitution other than the reviewed timeout is rejected.
            profile_path = cfg['coordinator']['dnsProfile']['path']
            delivered[profile_path] = C.canonical({**owner['dns'], 'timeoutSeconds': 9})
            cfg['coordinator']['dnsProfile']['sha256'] = C.sha(delivered[profile_path])
            with self.assertRaisesRegex(supervisor.Denied, 'COORDINATOR_CONFIGURATION_DRIFT'):
                supervisor.runtime(configuration)


if __name__ == '__main__': unittest.main()
