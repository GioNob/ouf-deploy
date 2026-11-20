"""R-022 offline qualification using the emitted bootstrap, DNS and upgrade paths."""
from contextlib import contextmanager
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
import struct
import sys
import threading
import time
import unittest
from unittest.mock import patch

import test_semantic_provider_r3_v21 as v21
from r3_sealed_inputs import sealed_blob
from test_r3_readers import load as reader

v20 = v21.v20
C = v20.C
PREFIX = 'versions/22/'
ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=2)
def fixture(*, sealed=False):
    inputs, _, old = v21.fixture(sealed=sealed)
    policy = 'ops/vps/r3-lease-renewal-v22.json'
    raw = sealed_blob(policy) if sealed else (ROOT / policy).read_text().encode()
    inputs = dict(inputs, files={**inputs['files'], 'leaseRenewal': raw})
    return inputs, old, C.compose(inputs, 22, sequence=22, supersedes=C.sha(old['authorization']))


class Composition(unittest.TestCase):
    def test_v21_golden_and_final_pins(self):
        inputs, old, result = fixture(sealed=True)
        self.assertEqual([C.sha(C.canonical(old[k])) for k in ('hashes', 'inputHashes', 'audit', 'layout')]
                         + [C.sha(old['authorization'])], [
            'bf9acd163bbe67237385240a49320230680d048c40c3cff6df8f123b28ae0149',
            '9b23c1ffd7c65180b07006c1da38cbea528de8420a3fe0f3cb09f1a3b1bb6a5a',
            '302d3b526d20af5f200c95a7258d9351254ce50220df3425aa7a3749db8e8aab',
            '8a9fbb0b98e3c355ca33426b71bae60dde4d6c58d7bbea16ddf2accf9031b39d',
            '77016d2c389fb0816ef76ed2379d0c5b21ad75d919da9bbb5576ed0164a8f5cb'])
        self.assertTrue(C.input_set(**inputs))
        docs = result['documents']
        sup = C.document(docs[PREFIX + v20.SUPERVISOR_CONFIG])
        src = PREFIX + 'source/'
        for path, digest in sup['sourceHashes'].items():
            self.assertEqual(digest, C.sha(docs[src + path]))
        pins = C.contract_module(docs[src + C.SUPERVISOR], 'v22_supervisor').PINS
        for name, digest in pins.items():
            self.assertEqual(digest, C.sha(docs[src + v21.overlay.RECOVERY + name + '.py']))
        self.assertEqual(docs[src + v20.OWNER_DNS], docs[src + v20.RECOVERY_DNS])
        old_runtime = C.document(old['documents'][v21.PREFIX + v20.CONFIG])
        self.assertEqual(C.document(docs[PREFIX + v20.CONFIG])['sourceHash'], old_runtime['sourceHash'])
        prior = C.document(old['authorization'])
        auth = C.document(result['authorization'])
        self.assertEqual(auth['lease'], {**prior['lease'], 'dnsProfileSha256':
                         C.sha(docs[PREFIX + 'supervisor/dns-profile.json'])})
        head = dict(decision='OPERATE', sequence=21, sha256=C.sha(old['authorization']), authorization=prior)
        issuer = v20.V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v22_issuer')
        self.assertEqual(issuer.compose_next(inputs, head, auth['issuedAt']), result)

    def test_ordinary_upgrade(self):
        with v20.V12.NativeBindingsAndUpgrade().observation_fixture(fixture(), version=22) as (args, _, _, _):
            state, result = v20.upgrade.observe(args)
        self.assertEqual(result, fixture()[2])
        self.assertEqual((state['versionBefore'], state['versionAfter']), (21, 22))
        self.assertIn('/' + PREFIX + 'source/' + v20.BOOTSTRAP, state['unit']['text'])
        self.assertIn('/' + PREFIX + 'source/' + C.RUNTIME, state['wrapperProposed']['text'])

    def test_overlay_preserves_line_endings_and_rejects_drift(self):
        from tools.semantic_provider_r3 import renewal_overlay_v22 as overlay
        inputs, old, _ = fixture()
        with patch.object(overlay, 'sources_v22', wraps=overlay.sources_v22) as build:
            C.compose(inputs, 22, sequence=22, supersedes=C.sha(old['authorization']))
        source, mapping = build.call_args.args
        lf = overlay.sources_v22(source, mapping)
        crlf = overlay.sources_v22({k: v.replace(b'\n', b'\r\n') for k, v in source.items()}, mapping)
        self.assertTrue(all(crlf[k] == v.replace(b'\n', b'\r\n') for k, v in lf.items()))
        dns = mapping[v20.OWNER_DNS]
        invalid = source[dns].replace(b'def _udp_response(', b'def obsolete(')
        with self.assertRaisesRegex(C.A.OperationDenied, overlay.DRIFT):
            overlay.sources_v22(source | {dns: invalid}, mapping)

    def test_incompatible_composition(self):
        inputs, old, _ = fixture()
        for change in (dict(immediateMinimumSeconds=18), dict(immediateMinimumSeconds=22),
                       dict(lockWaitSeconds=8), dict(dnsTimeoutSeconds=11), dict(dnsTimeoutSeconds=True)):
            files = inputs['files']
            renewal = C.document(files['leaseRenewal']) | change
            with self.subTest(change=change), self.assertRaisesRegex(C.A.OperationDenied, 'R3_LEASE_RENEWAL_'):
                C.compose(dict(inputs, files=files | {'leaseRenewal': C.canonical(renewal)}),
                          22, sequence=22, supersedes=C.sha(old['authorization']))


class Renewal(v20.SupervisorV20):
    @classmethod
    def setUpClass(cls):
        cls.inputs, _, cls.result = fixture()
        cls.retained = v20.V12.fixture()[2]

    def band(self, ttl=20):
        for members in self.elements.values():
            members['1.1.1.1'] = self.clock() + ttl
        self.scheduled = self.supervisor.tick()
        self.assertEqual(self.scheduled['waitSeconds'], 0)

    def test_startup_revalidates_budgets(self):
        self.assertEqual(self.c.owner.profile['timeoutSeconds'], 6)
        self.assertEqual(self.c.renewal['lockWaitSeconds'], 3)
        self.assertEqual(self.cfg['driverBudgetSeconds'], 12)
        self.assertTrue(all(f['leaseSeconds'] == 30 for f in self.c.configuration['providerFlows']))
        cfg = deepcopy(self.cfg)
        docs = self.result['documents']
        verified = {p: docs[PREFIX + 'source/' + p] for p in cfg['sourceHashes']}
        cfg['leaseRenewal']['lockWaitSeconds'] = 9
        with self.assertRaisesRegex(self.sup.Denied, 'BUDGET_INCOMPATIBLE'):
            self.sup.runtime(SimpleNamespace(value=cfg, custody=lambda: verified))

    def test_five_second_dns_then_immediate_renewal(self):
        # First publish a short lease using the real TTL compiler. The next
        # tick must admit its two-family lower bound, including read latency.
        original_guard = self.adapter.scope_guard
        def guard():
            if self.locked and not self.commands and not getattr(self, 'delayed', False):
                self.delayed = True
                self.advance(1.21)
            original_guard()
        self.adapter.scope_guard = guard
        count = 2 * len(self.c.owner.profile['resolvers']) * len(self.c.configuration['providerFlows'])
        self.advance(self.scheduled['waitSeconds'])
        wire = v20.SocketScript(self.advance, [[(5.05 / count, v20.answer)]] * count)
        first = self.renew_with_transport(wire)
        self.assertEqual(first['reason'], 'RENEWED')
        # Read the integer kernel TTL just after publication. Charge the same
        # 42.6 ms read window as the incident against its conservative start.
        self.advance(.01)
        tables = self.backend.tables
        def sample():
            result = tables()
            self.advance(.0426)
            return result
        with patch.object(self.backend, 'tables', side_effect=sample):
            self.scheduled = self.supervisor.tick()
        residual = self.scheduled['leaseDeadlineMonotonic'] - self.clock()
        self.assertAlmostEqual(residual, 19.9574)
        self.assertEqual(self.scheduled['waitSeconds'], 0)
        second = self.renew_with_transport(v20.SocketScript(self.advance, [[(5.05 / count, v20.answer)]] * count))
        self.assertEqual((second['state'], second['reason'], second['lastIncident']), ('ACTIVE', 'RENEWED', None))
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY'] * 2)
        self.assertEqual(set(self.elements), {(f, i) for f in ('inet', 'bridge') for i in range(2)})

    def test_window_just_below_minimum(self):
        for members in self.elements.values():
            members['1.1.1.1'] = self.clock() + 19
        tables = self.backend.tables
        def delayed_read():
            result = tables()
            self.advance(.0001)
            return result
        self.backend.tables = delayed_read
        self.assertEqual(self.supervisor.tick()['reason'], 'DNS_WINDOW_TOO_SHORT')
        self.assertFalse(self.queries)
        self.assert_closed()

    def test_exact_minimum_publishes_before_original_deadline(self):
        self.band(19)
        self.assertEqual(self.renew()['reason'], 'RENEWED')
        self.assertEqual(self.queries, [(100., 118.)])
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY'])

    def test_22_seconds_selects_ordinary_lane(self):
        self.band(22)
        self.query_outcomes[:] = ['DNS_UNAVAILABLE', 30]
        row = self.renew()
        self.assertTrue(any(r['reason'] == 'RENEWAL_RETRY_PENDING' for r in self.journal.history))
        self.assertEqual(self.queries, [(100., 121.), (101., 121.)])
        self.assertEqual(row['reason'], 'RENEWED')

    def test_recheck_at_entry_below_minimum(self):
        self.band(19)
        self.advance(.001)
        self.assertEqual(self.renew()['reason'], 'DNS_WINDOW_TOO_SHORT')
        self.assertFalse(self.queries)
        self.assert_closed()

    def test_crossing_into_band_and_dns_loss(self):
        self.advance(self.scheduled['leaseDeadlineMonotonic'] - self.clock() - 19)
        self.query_outcomes[:] = ['DNS_UNAVAILABLE', 30]
        row = self.renew()
        self.assertEqual((row['reason'], row['fastRenewalRetries']), ('DNS_UNAVAILABLE', 0))
        self.assertEqual(len(self.queries), 1)
        self.assert_closed()

    def test_lock_three_seconds_abandons_first_attempt(self):
        self.band()
        self.release = self.clock() + 3.01
        row = self.renew()
        self.assertEqual(self.lock_deadlines[1], 103.)
        self.assertEqual(len(self.queries), 1)
        self.assertEqual((row['reason'], row['lastIncident']['revocation']), ('COMMON_LOCK_TIMEOUT', 'VERIFIED'))
        self.assertNotIn('LEASE_UPDATING', self.lease_states)
        self.assert_closed()

    def test_ambiguous_apply_in_band(self):
        self.band()
        self.apply_delay = 1.01
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('RECONCILE_REQUIRED', 'PUBLICATION_OUTCOME_AMBIGUOUS'))
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'QUIESCING', 'QUIESCED'])
        self.assert_closed()

    def test_lock_exit_after_mutation_requires_reconciliation(self):
        self.band()
        hold = self.c.hold_until
        @contextmanager
        def uncertain(deadline):
            with hold(deadline):
                yield
            raise self.bounded.Permanent('INTEGRITY_UNPROVEN')
        self.c.hold_until = uncertain
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('RECONCILE_REQUIRED', 'PUBLICATION_OUTCOME_AMBIGUOUS'))
        self.assert_closed()

    def test_deadline_before_ready_cas(self):
        self.band()
        timing = self.adapter.incident.timing
        event = timing.event
        def delayed(tag, *args, **kwargs):
            event(tag, *args, **kwargs)
            if tag == 'ready':
                self.advance(1.01)
        with patch.object(timing, 'event', side_effect=delayed):
            self.assertEqual(self.renew()['state'], 'RECONCILE_REQUIRED')
        self.assertNotIn('LEASE_READY', self.lease_states)
        self.assert_closed()

    def test_membership_changes_under_lock(self):
        self.band()
        self.elements['bridge', 0]['8.8.8.8'] = self.clock() + 20
        self.assertEqual(self.renew()['state'], 'RECONCILE_REQUIRED')
        self.assertNotIn('LEASE_READY', self.lease_states)
        self.assert_closed()

    def test_short_dns_ttl(self):
        self.band()
        self.query_outcomes[:] = [1]
        self.assertEqual(self.renew()['reason'], 'DNS_WINDOW_TOO_SHORT')
        self.assertNotIn('LEASE_READY', self.lease_states)
        self.assert_closed()

    def test_cancel_after_apply(self):
        self.band()
        write = self.run_nft
        def cancel(arguments, raw, timeout):
            result = write(arguments, raw, timeout)
            if self.elements:
                self.stopped = True
            return result
        with patch.object(sys.modules['nft_seconds_backend'].NftBackend, 'run', side_effect=cancel):
            self.assertEqual(self.renew()['state'], 'RECONCILE_REQUIRED')
        self.assertNotIn('LEASE_READY', self.lease_states)
        self.assert_closed()

    def test_new_events_keep_checkpoint_size_and_scalar_limits(self):
        self.band()
        self.query_outcomes[:] = ['DNS_UNAVAILABLE']
        row = self.renew()
        journal = sys.modules['recovery_journal']
        timing = self.adapter.incident.timing
        for cycle in range(2):
            if cycle:
                timing.attempted = True
                timing.next_cycle()
            for _ in range(1025):
                timing.event('dnsRecv', 7, 31, 1, 8, 3, -1.23456789012345, 2.34567890123456, True)
        trace = row['lastIncident']['timing'] = timing.snapshot(None)
        for frame in (trace['current'], trace['previous']):
            self.assertTrue(frame['truncated'])
            self.assertLessEqual(len(C.canonical(frame['events'])), 28 * 1024)
        self.assertLess(len(journal.encoded(row)), 65536)
        status = reader('r3-status.py')['recovery_incident']
        self.assertEqual(status(row['lastIncident'], row['contextRef'])['timing'], trace)
        journal.validate_incident(row)
        for index, bad in [(2, 8), (3, 32), (4, 2), (5, 9), (6, 0), (7, 'hostname'), (9, 1)]:
            malformed = deepcopy(row)
            event = malformed['lastIncident']['timing']['current']['events'][0]
            event[index] = bad
            with self.assertRaises(ValueError):
                status(malformed['lastIncident'], row['contextRef'])
            with self.assertRaises(ValueError):
                journal.validate_incident(malformed)

    def test_exchange_timing_in_checkpoint(self):
        self.band()
        def wrong(q):
            return v20.answer(q, wrong_id=True)
        wire = v20.SocketScript(self.advance, [[(.25, wrong), (.75, v20.answer)]] + [[]] * 20)
        row = self.renew_with_transport(wire)
        trace = reader('r3-status.py')['recovery_incident'](row['lastIncident'], row['contextRef'])['timing']
        sys.modules['recovery_journal'].validate_incident(row)
        events = trace['current']['events']
        recv = [e for e in events if e[0] == 'dnsRecv']
        self.assertEqual([e[2:7] for e in recv], [[0, 0, 0, 0, 1]] * 2)
        self.assertEqual([e[7:] for e in recv], [[.75, 5.75, True], [0., 5., False]])
        self.assertTrue(any(e[0] == 'dnsTimeout' for e in events))
        self.assertTrue(any(e[0] == 'dnsSend' and e[6] == 2 for e in events))


class DNS(v20.DNSRetransmission):
    @classmethod
    def setUpClass(cls):
        cls.source = fixture()[2]['documents'][PREFIX + 'source/' + v20.OWNER_DNS]

    def test_datagram_resumed_past_attempt(self):
        def resumed(query):
            self.now += .05
            return v20.answer(query)
        wire = self.transport([[(1., resumed)]])
        self.assertEqual(self.dns.exchange(v20.RESOLVERS[0], 53, v20.HOST, 1, 106.)['transport'], 'UDP')
        self.assertEqual(len(wire.peers), 1)

    def test_datagram_resumed_at_round_deadline(self):
        self.transport([[(1., v20.answer)]])
        with self.assertRaisesRegex(self.dns.DNSDenied, 'DNS_DEADLINE_EXPIRED'):
            self.dns.exchange(v20.RESOLVERS[0], 53, v20.HOST, 1, 101.)

    def test_wire_trace_of_followup_cname_and_tcp(self):
        def alias(query):
            target = self.dns.wire_name('alias.invalid')
            rr = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 12, len(target)) + target
            return query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + query[12:] + rr
        self.transport([[(.1, alias)], [(.1, lambda q: v20.answer(q, flags=0x8380))],
                        [(0, lambda q: struct.pack('!H', len(v20.answer(q)))), (1.2, v20.answer)],
                        [(.1, v20.answer)]])
        events = []
        def event(tag, *fields, at=None):
            events.append((tag, fields, at))
        row = self.dns.observe('https://flow.invalid', v20.RESOLVERS[:1], 53, 4, [], 6, 30,
                               monotonic=lambda: self.now, thread_factory=v20.InlineWorker,
                               timing=SimpleNamespace(event=event))
        self.assertEqual(row['minimumObservedTtlSeconds'], 12)
        tcp = [(tag, fields, at) for tag, fields, at in events if tag.startswith('dnsTcp')]
        self.assertEqual([tag for tag, _, _ in tcp], ['dnsTcpFallback', 'dnsTcpSend', 'dnsTcpRecv'])
        self.assertTrue(all(fields[:5] == (0, 0, 0, 1, 1) for _, fields, _ in tcp))
        self.assertAlmostEqual(tcp[2][2] - tcp[1][2], 1.2)
        self.assertLess(tcp[2][1][5], 0)
        self.assertGreater(tcp[2][1][6], 0)

    def test_missing_type_excludes_only_its_resolver(self):
        def query(resolver, port, host, kind, deadline):
            if resolver == v20.RESOLVERS[1] and kind == 28:
                raise self.dns.DNSDenied('DNS_TCP_RESPONSE_INCOMPLETE')
            return self.packet(host, kind)
        row = self.dns.observe('https://flow.invalid', v20.RESOLVERS, 53, 4, [], 6, 30, query)
        self.assertEqual([v['resolver'] for v in row['observations']], v20.RESOLVERS[:1])
        self.assertEqual(row['missedResolvers'], [dict(resolver=v20.RESOLVERS[1], code='DNS_TCP_RESPONSE_INCOMPLETE')])

    def packet(self, host, kind):
        query = bytes(12) + self.dns.wire_name(host) + struct.pack('!HH', kind, 1)
        return self.dns.response(v20.answer(query), 0, host, kind) | dict(transport='UDP', responseHash='a' * 64)

    def test_eight_parallel_pairs_and_dependent_alias(self):
        barrier = threading.Barrier(8)
        requests = [('https://flow%d.invalid' % i, 4, []) for i in range(2)]
        deadlines = []
        def query(resolver, port, host, kind, deadline):
            deadlines.append(deadline)
            if host.startswith('flow'):
                barrier.wait(2)
                record = dict(section='answer', owner=host, type=5, value='alias.invalid', ttl=12)
            elif kind == 1:
                record = dict(section='answer', owner=host, type=1, value='1.1.1.1', ttl=30)
            else:
                record = dict(section='authority', owner=host, type=6, value=25, ttl=30)
            return dict(records=[{**record, 'class': 1}], transport='TCP',
                        responseHash='a' * 64, authenticatedDataFlag=False)
        result = self.dns.observe_many(requests, v20.RESOLVERS, 53, 6, 30, query)
        self.assertEqual(len(deadlines), 16)
        self.assertEqual(len(set(deadlines)), 1)
        self.assertEqual([r['minimumObservedTtlSeconds'] for r in result], [12, 12])
        self.assertTrue(all(len(r['observations']) == 2 for r in result))

    def test_late_workers_do_not_write_or_accumulate(self):
        release = threading.Event()
        self.addCleanup(release.set)
        calls = []
        def stuck(*args):
            calls.append(args)
            release.wait(3)
            raise self.dns.DNSDenied('DNS_QUESTION_MISMATCH')
        requests = [('https://flow%d.invalid' % i, 4, []) for i in range(2)]
        try:
            for _ in range(2):
                with self.assertRaisesRegex(self.dns.DNSDenied, '^DNS_UNAVAILABLE$'):
                    self.dns.observe_many(requests, v20.RESOLVERS, 53, 6, 30, stuck, deadline=time.monotonic()+.3)
                self.assertEqual(len(self.dns._workers), 8)
            self.assertEqual(len(calls), 8)
        finally:
            release.set()
            for thread in self.dns._workers:
                thread.join(1)
        result = self.dns.observe_many(requests, v20.RESOLVERS, 53, 6, 30,
                                      lambda resolver, port, host, kind, deadline: self.packet(host, kind))
        self.assertTrue(all(not r['missedResolvers'] for r in result))

    def test_integrity_overrides_missing_sibling_and_healthy_resolver(self):
        def query(resolver, port, host, kind, deadline):
            if resolver == v20.RESOLVERS[0]:
                raise self.dns.DNSDenied('DNS_DEADLINE_EXPIRED' if kind == 1 else 'DNS_QUESTION_MISMATCH')
            return self.packet(host, kind)
        with self.assertRaisesRegex(self.dns.DNSDenied, '^DNS_QUESTION_MISMATCH$'):
            self.dns.observe('https://flow.invalid', v20.RESOLVERS, 53, 4, [], 6, 30, query)
