"""R-022 offline proof through the emitted bootstrap, ordinary issuer and upgrade."""
from functools import lru_cache
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_semantic_provider_r3_v23 as v23

C, v20 = v23.C, v23.v20
PREFIX = 'versions/24/'


@lru_cache(maxsize=1)
def fixture():
    inputs, _, old = v23.fixture()
    return inputs, old, C.compose(inputs, 24, sequence=24, supersedes=C.sha(old['authorization']))


class Composition(unittest.TestCase):
    def test_v23_golden_and_successor(self):
        inputs, old, result = fixture()
        self.assertEqual([C.sha(C.canonical(old[k])) for k in ('hashes', 'inputHashes', 'audit', 'layout')]
                         + [C.sha(old['authorization'])], [
            'd9e5606e169ff9e073734f2e8d4bc885f11938d70a304bcd2d4ca4f476b07024',
            'a08343d9e31beb977a45e1b3f27e566e806a404618d8897ae6c2e6bbbb52a8c6',
            '302d3b526d20af5f200c95a7258d9351254ce50220df3425aa7a3749db8e8aab',
            '100978943f534f4d549e15fdca9a6f29b41cfd048f7af0bf6da8d85cf40f32e0',
            '6b3d0d43d2adcd64bd742593fc61340c46b610521d02a38562d85e04722307f4'])
        self.assertEqual(C.SOURCE_MAP_V24, C.SOURCE_MAP_V23)
        self.assertEqual(set(inputs['sources']), C.SOURCE_INPUTS_V24)
        self.assertEqual(set(inputs['files']), C.DATA_INPUTS_V24)
        self.assertEqual(old['inputHashes'], result['inputHashes'])
        auth = C.document(result['authorization'])
        head = dict(decision='OPERATE', sequence=23, sha256=C.sha(old['authorization']),
                    authorization=C.document(old['authorization']))
        issuer = v20.V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v24_issuer')
        self.assertEqual(issuer.compose_next(inputs, head, auth['issuedAt']), result)

    def test_single_seal_and_final_pins(self):
        from tools.semantic_provider_r3 import lease_renewal_overlay_v18 as seal
        inputs, old, result = fixture()
        counts = []
        original = seal.seal_v18
        def counted(base, emitted, mapping, recovery, sha):
            calls = []
            def digest(blob):
                calls.append(blob)
                return sha(blob)
            sealed, hashes = original(base, emitted, mapping, recovery, digest)
            self.assertCountEqual(calls, [sealed[path] for path in set(mapping.values())])
            counts.append(len(calls))
            return sealed, hashes
        with patch.object(seal, 'seal_v18', counted):
            self.assertEqual(C.compose(inputs, 24, sequence=24, supersedes=C.sha(old['authorization'])), result)
        self.assertEqual(len(counts), 1)
        docs = result['documents']
        src = PREFIX + 'source/'
        hashes = C.document(docs[PREFIX + v20.SUPERVISOR_CONFIG])['sourceHashes']
        for path, digest in hashes.items():
            self.assertEqual(digest, C.sha(docs[src + path]))
            self.assertEqual(digest, result['hashes'][src + path])
        pins = C.contract_module(docs[src + C.SUPERVISOR], 'v24_pins').PINS
        for name, digest in pins.items():
            self.assertEqual(digest, hashes['tools/semantic_lease_recovery/' + name + '.py'])

    def test_normal_upgrade(self):
        with v20.V12.NativeBindingsAndUpgrade().observation_fixture(fixture(), version=24) as (args, _, _, _):
            state, result = v20.upgrade.observe(args)
        self.assertEqual(result, fixture()[2])
        self.assertEqual((state['versionBefore'], state['versionAfter']), (23, 24))
        self.assertEqual(state['previousAuthorizationSha256'], C.sha(fixture()[1]['authorization']))
        self.assertIn('/' + PREFIX + 'source/' + v20.BOOTSTRAP, state['unit']['text'])
        self.assertIn('/' + PREFIX + 'source/' + C.RUNTIME, state['wrapperProposed']['text'])
        self.assertEqual({r['path']: r['sha256'] for r in state['writes']['files']}, {
            f'{args.install_root}/{path}': result['hashes'][path] for path in result['documents']})

    def test_overlay_anchors_and_line_endings(self):
        from tools.semantic_provider_r3 import cache_watch_overlay_v24 as overlay
        inputs, old, _ = fixture()
        with patch.object(overlay, 'sources_v24', wraps=overlay.sources_v24) as build:
            C.compose(inputs, 24, sequence=24, supersedes=C.sha(old['authorization']))
        blobs, mapping = build.call_args.args
        lf = overlay.sources_v24(blobs, mapping)
        crlf = overlay.sources_v24({p: b.replace(b'\n', b'\r\n') for p, b in blobs.items()}, mapping)
        self.assertTrue(all(crlf[p] == b.replace(b'\n', b'\r\n') for p, b in lf.items()))
        path = mapping[overlay.CONTINUOUS]
        with self.assertRaisesRegex(C.A.OperationDenied, overlay.DRIFT):
            overlay.sources_v24(blobs | {path: blobs[path].replace(b'def prior_lease(', b'def drift(')}, mapping)


class IncidentControl(unittest.TestCase):
    def test_same_wire_inputs_trigger_v23_branch_280(self):
        old = v23.Renewal()
        old.setUpClass()
        self.addCleanup(old.doCleanups)
        old.setUp()
        Renewal.incident(old)
        last = old.elements['inet', 1]['1.1.1.1']
        old.advance(last - .5 - old.clock())
        row = old.supervisor.tick()
        incident = row['lastIncident']
        self.assertEqual((incident['phase'], incident['revocation']), ('PLAN', 'VERIFIED'))
        self.assertEqual(incident['timing']['branch'], [1, 280])
        self.assertEqual([e[0] for e in incident['timing']['current']['events'][:4]],
                         ['tick', 'guardEnd', 'cachePaused', 'deny'])
        old.assert_closed()


class Renewal(v23.Renewal):
    @classmethod
    def setUpClass(cls):
        cls.inputs, _, cls.result = fixture()
        cls.retained = v20.V12.fixture()[2]

    def tables(self):
        # nft drops each address on its own timer, even between family dumps.
        if getattr(getattr(self, 'adapter', None), 'cache_lease_ref', None):
            for key, members in list(self.elements.items()):
                for address, expiry in list(members.items()):
                    if expiry <= self.clock():
                        del members[address]
                if not members:
                    del self.elements[key]
        return super().tables()

    def test_startup_revalidates_budgets(self):
        with patch.object(v23.v22, 'PREFIX', PREFIX):
            v23.v22.Renewal.test_startup_revalidates_budgets(self)

    def incident(self, second_ttl=26):
        for (_, index), members in self.elements.items():
            members['1.1.1.1'] = self.clock() + 24 + index
        self.scheduled = self.supervisor.tick()
        samples = self.adapter.incident.timing.current['events']
        self.assertEqual([e[2:] for e in samples if e[0] == 'expires'], [[0, 24, 24], [1, 25, 25]])
        self.advance(self.scheduled['waitSeconds'])
        def soa(query):
            packet = v20.answer(query)
            if query[-4:-2] == b'\x00\x1c':
                return packet[:-4] + struct.pack('!I', second_ttl if b'fixture1' in query else 25)
            return packet
        wire = v20.SocketScript(self.advance, [[(.001, soa)]] * 8)
        timing = self.adapter.incident.timing
        record = timing.event
        plans = []
        def event(tag, *values, **options):
            record(tag, *values, **options)
            if tag == 'dnsEnd':
                self.advance(.36)
            if tag == 'timeout':
                plans.append(values)
            if tag == 'planLimit' and len(plans) == 2:
                self.advance(1.1)
            if tag == 'verifyEnd':
                self.advance(.38)
        self.apply_delay = .03
        with patch.object(timing, 'event', side_effect=event):
            row = self.renew_with_transport(wire)
        capped = min(second_ttl, 30)
        self.assertEqual(plans, [(0, 22), (1, capped - 3), (0, 21), (1, capped - 4)])
        self.assertEqual([e[2:] for e in timing.current['events'] if e[0] == 'ttl'],
                         [[0, 25, True], [1, second_ttl, True]])
        self.assertEqual(row['lastCacheRollover'][0], 'cacheWait')
        self.assertEqual(len(wire.peers), 8)
        return row['lastCacheRollover'][3]

    def test_incident_25_26_next_tick_and_rollover(self):
        due = self.incident()
        # Resume as in the incident, after the first flow expired and while
        # the second has a real subsecond residual (nft integer expires=0).
        last = self.elements['inet', 1]['1.1.1.1']
        self.advance(last - .5 - self.clock())
        partial = self.supervisor.tick()
        self.assertEqual(partial['state'], 'WAITING')
        self.assertIn('cachePaused', [e[0] for e in self.adapter.incident.timing.current['events']])
        self.assertEqual(self.elements['bridge', 1], {'1.1.1.1': last})
        self.assertEqual(len(self.commands), 1)
        self.advance(last - self.clock())
        drained = self.supervisor.tick()
        self.assertEqual((drained['state'], drained['nextMonotonic']), ('RETRY_WAIT', due))
        self.assertIsNone(drained['lastIncident'])
        self.assert_closed()
        self.advance(due - self.clock())
        wire = v20.SocketScript(self.advance, [[(.001, v20.answer)]] * 8)
        clock = SimpleNamespace(monotonic=self.clock)
        starts = []
        def observe(*args, **kwargs):
            self.assertFalse(self.locked)
            self.assertTrue(kwargs['single_round'])
            starts.append(self.clock())
            rows = self.observe_many(*args, **kwargs, wall_clock=lambda: self.wall, thread_factory=v20.InlineWorker)
            self.assertEqual([r['minimumObservedTtlSeconds'] for r in rows], [v20.TTL] * 2)
            return rows
        with patch.multiple(self.dns, observe_many=observe, socket=wire.module, time=clock), \
                patch.dict(self.adapter.fresh_evidence.__func__.__globals__, {'time': clock}):
            resumed = self.supervisor.tick()
        self.assertEqual((resumed['state'], resumed['lastCacheRollover'][0]), ('ACTIVE', 'cacheRenewed'))
        self.assertIsNone(resumed['lastIncident'])
        self.assertEqual(starts, [due])
        self.assertEqual(len(wire.peers), 8)
        self.assertEqual(resumed['attempts'], drained['attempts'] + 1)
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY', 'QUIESCED',
                                            'LEASE_UPDATING', 'LEASE_READY'])
        self.assertEqual(len(self.commands), 2)

    def test_supervised_tick_rechecks_live_lease_below_minimum(self):
        due = self.incident()
        self.advance(4)
        row = self.supervisor.tick()
        self.assertTrue(row['cacheWaitOnly'])
        self.assertEqual(row['state'], 'ACTIVE')
        events = self.adapter.incident.timing.current['events']
        self.assertIn('cacheWait', [e[0] for e in events])
        self.assertLessEqual(self.clock() + row['waitSeconds'], due)
        self.assertEqual(len(self.commands), 1)
        self.authorized = False
        self.assertEqual(self.supervisor.tick()['reason'], 'AUTHORITY_REVOKED')
        self.assert_closed()

    def test_late_tick_reads_all_empty_without_revocation(self):
        due = self.incident()
        self.advance(due - self.clock())
        drained = self.supervisor.tick()
        self.assertEqual((drained['state'], drained['nextMonotonic']), ('RETRY_WAIT', due))
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(self.supervisor.tick()['lastCacheRollover'][0], 'cacheRenewed')
        self.assertEqual(self.queries[0][0], due)

    def test_second_short_round_after_installed_lease(self):
        due = self.incident()
        self.advance(due - self.clock())
        self.supervisor.tick()
        self.query_outcomes[:] = [16, 30]
        paused = self.supervisor.tick()
        self.assertEqual(paused['lastCacheRollover'][0], 'cacheShort')
        self.assertEqual(paused['state'], 'RETRY_WAIT')
        self.assertGreater(paused['nextMonotonic'], due)
        self.supervisor.tick()
        self.assertEqual([t for t, _ in self.queries], [due])
        self.advance(paused['nextMonotonic'] - self.clock())
        self.assertEqual(self.supervisor.tick()['state'], 'ACTIVE')

    def test_collect_on_time_while_last_flow_drains(self):
        due = self.incident(second_ttl=30)
        final_expiry = self.elements['bridge', 1]['1.1.1.1']
        self.assertGreater(final_expiry, due)
        self.advance(due - self.clock())
        self.scheduled = self.supervisor.tick()
        self.assertEqual(self.scheduled['state'], 'WAITING')
        self.assertTrue(self.scheduled['cacheTarget'])
        result = self.renew()
        self.assertEqual((result['state'], result['lastCacheRollover'][0]), ('ACTIVE', 'cacheRenewed'))
        self.assertEqual([t for t, _ in self.queries], [due])
        self.assertEqual(len(self.commands), 2)
        self.assertGreaterEqual(self.commands[-1][0], final_expiry)
        self.assertNotIn('QUIESCING', self.lease_states)

    def test_cancel_at_mixed_publication_ready_is_ambiguous(self):
        due = self.incident(second_ttl=30)
        self.advance(due - self.clock())
        self.scheduled = self.supervisor.tick()
        timing = self.adapter.incident.timing
        record = timing.event
        def cancel(tag, *args, **kwargs):
            record(tag, *args, **kwargs)
            if tag == 'ready':
                self.stopped = True
        with patch.object(timing, 'event', side_effect=cancel):
            result = self.renew()
        self.assertEqual((result['state'], result['reason']),
                         ('RECONCILE_REQUIRED', 'PUBLICATION_OUTCOME_AMBIGUOUS'))
        self.assertEqual(self.lease_states.count('LEASE_READY'), 1)
        self.assert_closed()

    def test_service_dispatches_collection_from_waiting_projection(self):
        due = self.incident(second_ttl=30)
        self.advance(due - self.clock())
        projections = []
        def observe(value):
            projections.append(value['state'])
            if value['state'] == 'ACTIVE':
                self.assertEqual(self.journal.read()['lastCacheRollover'][0], 'cacheRenewed')
                self.assertEqual(len(self.commands), 2)
                self.assertNotIn('QUIESCING', self.lease_states)
                self.stopped = True
        self.supervisor._serve(self.stop, observe)
        self.assertEqual(projections, ['WAITING', 'ACTIVE'])
        self.assertEqual([t for t, _ in self.queries], [due])

    def test_installed_cache_wait_rejects_early_loss(self):
        self.incident()
        self.elements['bridge', 0].clear()
        self.assertEqual(self.supervisor.tick()['state'], 'BLOCKED')
        self.assert_closed()

    def test_installed_cache_wait_rejects_extended_ttl(self):
        self.incident()
        self.elements['inet', 1]['1.1.1.1'] += 4
        self.assertEqual(self.supervisor.tick()['state'], 'BLOCKED')
        self.assert_closed()

    def test_installed_cache_wait_rejects_zero_too_early(self):
        self.incident()
        self.elements['inet', 0]['1.1.1.1'] = self.clock() + .5
        self.assertEqual(self.supervisor.tick()['state'], 'BLOCKED')
        self.assert_closed()

    def test_cache_wait_rejects_journal_change_after_all_expired(self):
        due = self.incident()
        self.advance(due - self.clock())
        self.coordination['leaseAddresses'][0] = ['8.8.8.8']
        self.assertEqual(self.supervisor.tick()['state'], 'BLOCKED')
        self.assert_closed()


class DNS(v23.DNS):
    @classmethod
    def setUpClass(cls):
        cls.source = fixture()[2]['documents'][PREFIX + 'source/' + v20.OWNER_DNS]
