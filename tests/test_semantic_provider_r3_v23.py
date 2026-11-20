"""Offline qualification through the sealed v23 bootstrap and ordinary upgrade."""
from functools import lru_cache
from types import SimpleNamespace
import struct
import sys
import unittest
from unittest.mock import patch

import test_semantic_provider_r3_v22 as v22


C, v20 = v22.C, v22.v20
PREFIX = 'versions/23/'


def short_negative(query):
    packet = v20.answer(query)
    return packet[:-4] + struct.pack('!I', 16) if query[-4:-2] == b'\x00\x1c' else packet


@lru_cache(maxsize=2)
def fixture(*, sealed=False):
    inputs, _, old = v22.fixture(sealed=sealed)
    return inputs, old, C.compose(inputs, 23, sequence=23, supersedes=C.sha(old['authorization']))


class Composition(unittest.TestCase):
    def test_frozen_v22_and_successor_pins(self):
        inputs, old, result = fixture(sealed=True)
        self.assertEqual([C.sha(C.canonical(old[k])) for k in ('hashes', 'inputHashes', 'audit', 'layout')]
                         + [C.sha(old['authorization'])], [
            '298b02f21b35202af5b333aee4aa21e7026750610129e2fe36e65d1b8fbb4cc8',
            'a08343d9e31beb977a45e1b3f27e566e806a404618d8897ae6c2e6bbbb52a8c6',
            '302d3b526d20af5f200c95a7258d9351254ce50220df3425aa7a3749db8e8aab',
            '35e2a52edb66e6017e44434809a000913ea4f9cfc50270a57a0d9af9e2250762',
            'b0046ac2027623baa34e6582c9d230cd3da257dd4f3e46280b551181ee0b3a2f'])
        self.assertEqual(set(inputs['files']), C.DATA_INPUTS_V23)
        self.assertEqual(set(inputs['sources']), C.SOURCE_INPUTS_V23)
        self.assertTrue(C.input_set(**inputs))
        self.assertEqual(old['inputHashes'], result['inputHashes'])
        docs = result['documents']
        sup = C.document(docs[PREFIX + v20.SUPERVISOR_CONFIG])
        src = PREFIX + 'source/'
        for path, digest in sup['sourceHashes'].items():
            self.assertEqual(digest, C.sha(docs[src + path]))
            self.assertEqual(result['hashes'][src + path], digest)
        pins = C.contract_module(docs[src + C.SUPERVISOR], 'v23_pins').PINS
        for name, digest in pins.items():
            self.assertEqual(digest, sup['sourceHashes']['tools/semantic_lease_recovery/' + name + '.py'])
        previous, auth = (C.document(r['authorization']) for r in (old, result))
        head = dict(decision='OPERATE', sequence=22, sha256=C.sha(old['authorization']), authorization=previous)
        self.assertEqual(auth['lease'], previous['lease'])
        issuer = v20.V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v23_issuer')
        self.assertEqual(issuer.compose_next(inputs, head, auth['issuedAt']), result)

    def test_normal_upgrade(self):
        with v20.V12.NativeBindingsAndUpgrade().observation_fixture(fixture(), version=23) as (args, _, _, _):
            state, result = v20.upgrade.observe(args)
        self.assertEqual(result, fixture()[2])
        self.assertEqual((state['versionBefore'], state['versionAfter']), (22, 23))
        self.assertIn('/' + PREFIX + 'source/' + v20.BOOTSTRAP, state['unit']['text'])
        self.assertIn('/' + PREFIX + 'source/' + C.RUNTIME, state['wrapperProposed']['text'])

    def test_anchors_and_crlf(self):
        from tools.semantic_provider_r3 import cache_rollover_overlay_v23 as overlay
        inputs, old, _ = fixture()
        with patch.object(overlay, 'sources_v23', wraps=overlay.sources_v23) as build:
            C.compose(inputs, 23, sequence=23, supersedes=C.sha(old['authorization']))
        blobs, mapping = build.call_args.args
        lf = overlay.sources_v23(blobs, mapping)
        crlf = overlay.sources_v23({p: b.replace(b'\n', b'\r\n') for p, b in blobs.items()}, mapping)
        self.assertTrue(all(crlf[p] == b.replace(b'\n', b'\r\n') for p, b in lf.items()))
        path = mapping[overlay.CONTINUOUS]
        with self.assertRaisesRegex(C.A.OperationDenied, overlay.DRIFT):
            overlay.sources_v23(blobs | {path: blobs[path].replace(b'def renew(', b'def drift(')}, mapping)


class Renewal(v22.Renewal):
    @classmethod
    def setUpClass(cls):
        cls.inputs, _, cls.result = fixture()
        cls.retained = v20.V12.fixture()[2]

    def query(self, requests, *args, **kwargs):
        rows = super().query(requests, *args, **kwargs)
        for row in rows:
            row['minimumObservedTtlSeconds'] = int(row['expiresMonotonic'] - row['observedMonotonic'])
        return rows

    def test_startup_revalidates_budgets(self):
        # The v22 test loads configuration from the emitted version prefix.
        with patch.object(v22, 'PREFIX', PREFIX):
            super().test_startup_revalidates_budgets()

    def test_negative_soa_16_then_full_ttl(self):
        # Eight wire answers per round. Only negative SOA.MINIMUM is short.
        self.band(22)
        before = self.elements.copy()
        def during_wait():
            self.assertFalse(self.locked)
            self.assertEqual(self.elements, before)
            self.assertEqual(self.commands, [])
            self.assertEqual(self.journal.read()['lastCacheRollover'][0], 'cacheWait')
        self.after_wait = during_wait
        wire = v20.SocketScript(self.advance, [[(.001, short_negative)]] * 8 + [[(.001, v20.answer)]] * 8)
        row = self.renew_with_transport(wire)
        self.assertEqual((row['state'], row['reason'], row['lastIncident']), ('ACTIVE', 'RENEWED', None))
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY'])
        self.assertEqual(len(wire.peers), 16)
        event, ready, expiry, due, collected = row['lastCacheRollover']
        self.assertEqual(event, 'cacheRenewed')
        self.assertAlmostEqual(expiry, 116.008)
        self.assertEqual(due, expiry + 1)
        self.assertGreaterEqual(collected, due)
        self.assertLess(ready, self.scheduled['leaseDeadlineMonotonic'])
        self.assertEqual(len(self.commands), 1)
        events = self.adapter.incident.timing.current['events']
        self.assertEqual([e[2:] for e in events if e[0] == 'ttl'][:2], [[0, 16, True], [1, 16, True]])
        starts = [e[1] for e in events if e[0] == 'dnsStart']
        self.assertEqual(starts, [100., collected])
        sys.modules['recovery_journal'].validate_incident(row)
        self.assertTrue(v22.reader('r3-status.py')['valid_timing_event'](row['lastCacheRollover']))

    def test_persistently_short_revokes_once_then_normal_backoff(self):
        self.query_outcomes[:] = [16, 16, 16, 3600]
        row = self.renew()
        self.assertEqual([t for t, _ in self.queries], [100, 117])
        self.assertEqual(row['lastCacheRollover'][0], 'cacheShort')
        self.assertEqual(row['lastIncident']['revocation'], 'VERIFIED')
        self.assertEqual(self.lease_states, ['QUIESCING', 'QUIESCED'])
        self.advance(row['nextMonotonic'] - self.clock())
        row = self.supervisor.tick()
        self.assertEqual((row['state'], row['lastCacheRollover'][0]), ('RETRY_WAIT', 'cacheShort'))
        self.assert_closed()
        self.advance(row['nextMonotonic'] - self.clock())
        self.assertEqual(self.supervisor.tick()['state'], 'ACTIVE')

    def test_noncacheable_second_collection_gets_one_round(self):
        def zero(query):
            packet = short_negative(query)
            return packet[:-4] + bytes(4) if query[-4:-2] == b'\x00\x1c' else packet
        wire = v20.SocketScript(self.advance, [[(.001, short_negative)]] * 8 + [[(.001, zero)]] * 8)
        row = self.renew_with_transport(wire)
        self.assertEqual(len(wire.peers), 16)
        self.assertEqual((row['reason'], row['lastCacheRollover'][0]), ('DNS_WINDOW_TOO_SHORT', 'cacheShort'))
        self.assert_closed()

    def test_loss_of_authority_during_wait(self):
        self.query_outcomes[:] = [16, 3600]
        self.after_wait = lambda: setattr(self, 'authorized', False)
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('BLOCKED', 'AUTHORITY_REVOKED'))
        self.assertEqual(len(self.queries), 1)
        self.assert_closed()

    def test_one_limiting_flow_and_exact_threshold(self):
        for ttl, short in ((20, True), (21, False), (3600, False)):
            with self.subTest(ttl=ttl):
                def typed(requests, *args, **kwargs):
                    rows = self.query(requests, *args, **kwargs)
                    rows[0].update(minimumObservedTtlSeconds=3600, expiresMonotonic=self.clock()+30)
                    rows[1].update(minimumObservedTtlSeconds=ttl, expiresMonotonic=self.clock()+min(ttl, 30))
                    return rows
                self.dns.observe_many = typed
                evidence = self.adapter.prepare_renewal(self.clock() + 25)
                self.assertEqual(evidence['cacheExpiry'], self.clock() + ttl if short else None)

    def test_late_fresh_evidence_cannot_extend_outgoing_deadline(self):
        self.band(22)
        self.query_outcomes[:] = [16, 30]
        def late(*args, **kwargs):
            if self.queries:
                self.advance(5)
            return self.query(*args, **kwargs)
        self.dns.observe_many = late
        row = self.renew()
        self.assertEqual(row['lastCacheRollover'][0], 'cacheFailed')
        self.assertEqual(len(self.queries), 2)
        self.assertNotIn('LEASE_UPDATING', self.lease_states)
        self.assert_closed()

    def test_serve_waits_on_installed_lease_and_recovers(self):
        row = self.r.retry(self.journal.read(), self.bounded.Temporary('DNS_UNAVAILABLE'))
        self.advance(row['nextMonotonic'] - self.clock())
        self.query_outcomes[:] = [16, 30]
        projections = []
        def observe(row):
            projections.append(row['state'])
            if len(self.queries) == 2:
                self.stopped = True
        self.supervisor._serve(self.stop, observe)
        self.assertEqual([t for t, _ in self.queries], [105, 122])
        self.assertEqual(projections[0], 'ACTIVE')
        self.assertIn('RETRY_WAIT', projections)
        self.assertEqual(projections[-1], 'ACTIVE')
        self.assertEqual(self.lease_states.count('LEASE_READY'), 2)

    def test_exhausted_attempts_do_not_arm_rollover(self):
        old = self.journal.read()
        self.journal.compare_and_save(old, old | {'attempts': self.r.policy.max_attempts})
        self.query_outcomes[:] = [16, 3600]
        row = self.renew()
        self.assertEqual((row['state'], row['reason']), ('PAUSED_EXHAUSTED', 'RETRY_BUDGET_EXHAUSTED'))
        self.assertEqual(len(self.queries), 1)
        self.assert_closed()

    def test_expiry_before_collection_pauses_until_exact_cache_due(self):
        self.band(19)
        self.query_outcomes[:] = [16, 3600]
        def delayed(*args, **kwargs):
            if not self.queries:
                self.advance(4)
            return self.query(*args, **kwargs)
        self.dns.observe_many = delayed
        def kernel_expiry():
            self.assertFalse(self.locked)
            self.assertFalse(self.commands)
            for members in self.elements.values():
                for address, expiry in list(members.items()):
                    if expiry <= self.clock():
                        del members[address]
        self.after_wait = kernel_expiry
        row = self.renew()
        self.assertEqual(self.clock(), 119)
        self.assertEqual((row['state'], row['nextMonotonic']), ('RETRY_WAIT', 121))
        self.assertEqual(row['lastCacheRollover'], ['cachePaused', 119, 120, 121, 0])
        self.assert_closed()
        self.advance(1.99)
        self.assertEqual(self.supervisor.tick()['state'], 'RETRY_WAIT')
        self.advance(.01)
        row = self.supervisor.tick()
        self.assertEqual((row['state'], row['lastCacheRollover'][0]), ('ACTIVE', 'cacheRenewed'))
        self.assertEqual([t for t, _ in self.queries], [104, 121])

    def test_installed_recovery_lease_13_then_12_and_10_97_remaining(self):
        row = self.r.retry(self.journal.read(), self.bounded.Temporary('DNS_UNAVAILABLE'))
        self.advance(row['nextMonotonic'] - self.clock())
        self.lease_states.clear()
        timing = self.adapter.incident.timing
        record = timing.event
        timeouts = []
        def event(tag, *values, **options):
            record(tag, *values, **options)
            if tag == 'dnsEnd':
                self.advance(.36)
            if tag == 'timeout' and values[0] == 0:
                timeouts.append(values[1])
            if tag == 'planLimit' and len(timeouts) == 1:
                self.advance(1.1)
            if tag == 'readyEnd':
                self.advance(.01)
        wire = v20.SocketScript(self.advance, [[(.001, short_negative)]] * 8)
        clock = SimpleNamespace(monotonic=self.clock)
        def observe(*args, **kwargs):
            return self.observe_many(*args, **kwargs, wall_clock=lambda: self.wall, thread_factory=v20.InlineWorker)
        tables = self.backend.tables
        def sample():
            result = tables()
            if self.adapter.cache_lease_ref is not None:
                self.advance(.03)
            return result
        with patch.multiple(self.dns, observe_many=observe, socket=wire.module, time=clock), \
                patch.dict(self.adapter.fresh_evidence.__func__.__globals__, {'time': clock}), \
                patch.object(self.backend, 'tables', side_effect=sample), patch.object(timing, 'event', side_effect=event):
            row = self.supervisor.tick()
        self.assertEqual(timeouts, [13, 12])
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY'])
        self.assertAlmostEqual(self.adapter.cache_lease_end - self.clock(), 10.97)
        self.assertTrue(row['cacheWaitOnly'])
        cache_due = row['lastCacheRollover'][3]
        expired = []
        while row['state'] in ('ACTIVE', 'WAITING'):
            self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY'])
            self.advance(row['waitSeconds'])
            for key, members in self.elements.items():
                if members and max(members.values()) <= self.clock():
                    expired.append(key)
                    members.clear()
            row = self.supervisor.tick()
        self.assertEqual(set(expired), {(family, i) for family in ('inet', 'bridge') for i in range(2)})
        self.assertEqual((row['state'], row['nextMonotonic']), ('RETRY_WAIT', cache_due))
        self.assertEqual(row['lastCacheRollover'][0], 'cachePaused')
        self.assert_closed()
        self.advance(cache_due - self.clock())
        row = self.supervisor.tick()
        self.assertEqual(row['lastCacheRollover'][0], 'cacheRenewed')
        self.assertEqual(self.lease_states.count('LEASE_READY'), 2)

    def test_cancellation_during_cache_wait(self):
        self.query_outcomes[:] = [16]
        self.after_wait = lambda: setattr(self, 'stopped', True)
        row = self.renew()
        self.assertEqual((row['state'], row['lastCacheRollover'][0]), ('CANCELLED', 'cacheFailed'))
        self.assertEqual(len(self.queries), 1)
        self.assert_closed()

    def test_membership_drift_during_wait(self):
        self.query_outcomes[:] = [16]
        self.after_wait = lambda: self.elements['bridge', 0].update({'8.8.8.8': self.clock() + 10})
        row = self.renew()
        self.assertEqual((row['state'], row['lastCacheRollover'][0]), ('BLOCKED', 'cacheFailed'))
        self.assertEqual(len(self.queries), 1)
        self.assert_closed()


class DNS(v22.DNS):
    @classmethod
    def setUpClass(cls):
        cls.source = fixture()[2]['documents'][PREFIX + 'source/' + v20.OWNER_DNS]
