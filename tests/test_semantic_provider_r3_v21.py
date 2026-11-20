"""Exercise timing on the sealed closure with the v20 offline transports and clock."""
from copy import deepcopy
from functools import lru_cache
import json
import struct
import sys
import unittest
from unittest.mock import patch

import test_semantic_provider_r3_v18 as v18
import test_semantic_provider_r3_v20 as v20
from test_r3_readers import load as reader
from tools.semantic_provider_r3 import lease_timing_overlay_v21 as overlay


C = v20.C
PREFIX = 'versions/21/'
RECOVERY = PREFIX + 'source/' + overlay.RECOVERY


@lru_cache(maxsize=2)
def fixture(*, sealed=False):
    inputs, _, old = v20.fixture(sealed=sealed)
    return inputs, old, C.compose(inputs, 21, sequence=21, supersedes=C.sha(old['authorization']))


class Composition(unittest.TestCase):
    def test_golden_v20_and_successor(self):
        inputs, old, result = fixture(sealed=True)
        actual = {k: C.sha(C.canonical(old[k])) for k in ('hashes', 'inputHashes', 'audit', 'layout')}
        self.assertEqual(actual | {'authorization': C.sha(old['authorization'])}, {
            'hashes': 'be41276688f5b2865a23d1072062978f74fd16d99aa49cbf1a677a27a21be5cb',
            'inputHashes': '9b23c1ffd7c65180b07006c1da38cbea528de8420a3fe0f3cb09f1a3b1bb6a5a',
            'audit': '302d3b526d20af5f200c95a7258d9351254ce50220df3425aa7a3749db8e8aab',
            'layout': 'be57761c51c76f4c919bff294619600b1ee722e5573461cdb3612779ea4d1592',
            'authorization': 'a132bdb0f608bd0d1118b1b666d10874347d00fe3e9672eedcc8fe3f71bf7517',
        })
        self.assertEqual((C.DATA_INPUTS_V21, C.SOURCE_INPUTS_V21, C.SOURCE_MAP_V21),
                         (C.DATA_INPUTS_V20, C.SOURCE_INPUTS_V20, C.SOURCE_MAP_V20))
        self.assertEqual(result['inputHashes'], old['inputHashes'])
        auth = C.document(result['authorization'])
        head = dict(decision='OPERATE', sequence=20, sha256=C.sha(old['authorization']),
                    authorization=C.document(old['authorization']))
        issuer = v20.V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v21_issuer')
        self.assertEqual(issuer.compose_next(inputs, head, auth['issuedAt']), result)
        docs = result['documents']
        runtime = C.document(docs[PREFIX + v20.CONFIG])
        self.assertEqual(runtime['sourceHash'], C.document(old['documents'][v20.PREFIX + v20.CONFIG])['sourceHash'])
        self.assertEqual(runtime['leaseQuiesce']['entrypoint']['sha256'],
                         C.sha(docs[PREFIX + 'source/' + v20.BOOTSTRAP]))
        cfg = C.document(docs[PREFIX + v20.SUPERVISOR_CONFIG])
        sup = C.contract_module(docs[PREFIX + 'source/' + C.SUPERVISOR], 'v21_pins')
        for name, digest in sup.PINS.items():
            self.assertEqual(digest, C.sha(docs[RECOVERY + name + '.py']))
        for path, digest in cfg['sourceHashes'].items():
            self.assertEqual(digest, C.sha(docs[PREFIX + 'source/' + path]))

    def test_governed_upgrade(self):
        observe = v20.V12.NativeBindingsAndUpgrade().observation_fixture
        with observe(fixture(), version=21) as (args, _, _, _):
            state, composed = v20.upgrade.observe(args)
        self.assertEqual(composed, fixture()[2])
        self.assertEqual((state['versionBefore'], state['versionAfter']), (20, 21))
        self.assertIn('/versions/21/source/' + C.RUNTIME, state['wrapperProposed']['text'])
        self.assertIn('/versions/21/source/' + v20.BOOTSTRAP, state['unit']['text'])
        self.assertIn(composed['hashes'][PREFIX + v20.SUPERVISOR_CONFIG], state['unit']['text'])

    def test_exact_anchors_and_line_endings(self):
        # Use the exact pre-seal bytes seen by the overlay.
        with patch.object(overlay, 'sources_v21', wraps=overlay.sources_v21) as called:
            inputs, old, _ = fixture()
            C.compose(inputs, 21, sequence=21, supersedes=C.sha(old['authorization']))
        base, mapping = called.call_args.args
        lf = overlay.sources_v21(base, mapping)
        crlf = overlay.sources_v21({k: v.replace(b'\n', b'\r\n') for k, v in base.items()}, mapping)
        for key in lf:
            self.assertEqual(crlf[key], lf[key].replace(b'\n', b'\r\n'), key)
        key = mapping[overlay.JOURNAL]
        for replacement in (b'', b'class Incident:class Incident:'):
            with self.assertRaisesRegex(C.A.OperationDenied, overlay.DRIFT):
                overlay.sources_v21(base | {key: base[key].replace(b'class Incident:', replacement)}, mapping)


class DNSParity(v20.DNSRetransmission):
    @classmethod
    def setUpClass(cls):
        cls.source = fixture()[2]['documents'][PREFIX + 'source/' + v20.OWNER_DNS]


class EmittedV21:
    @classmethod
    def setUpClass(cls):
        cls.inputs, _, cls.result = fixture()
        cls.retained = v20.V12.fixture()[2]


class RenewalParity(EmittedV21, v18.RenewalRuntime):
    """Repeat the established admission, deadline, retry, revoke and CAS scenarios."""


class Supervisor(EmittedV21, v20.SupervisorV20):
    def check_checkpoint(self, row):
        journal = sys.modules['recovery_journal']
        journal.validate_incident(row)
        public = reader('r3-status.py')['recovery_incident'](row['lastIncident'], row['contextRef'])
        self.assertEqual(public, row['lastIncident'])
        for raw in (journal.encoded(row).decode(), json.dumps(public)):
            for forbidden in ('1.1.1.1', 'fixture0', 'fixture1', 'add element', 'flush set', 'SECRET_SENTINEL'):
                self.assertNotIn(forbidden, raw)
        return public['timing']

    def test_slow_renewal_and_next_tick(self):
        original_guard = self.adapter.scope_guard
        def slow_guard():
            if self.locked and self.queries and not self.commands and not getattr(self, 'delayed', False):
                self.delayed = True
                self.advance(6.5)
            original_guard()
        self.adapter.scope_guard = slow_guard

        # Use the real two-family dump loop; only the child command is simulated.
        backend = sys.modules['nft_seconds_backend'].NftBackend
        del self.backend.tables
        def command(arguments, raw=None, timeout=None):
            if arguments == ['-f', '-']:
                return self.run_nft(arguments, raw, timeout)
            family = arguments[3]
            result = json.dumps(self.tables()[family])
            if self.commands and self.lease_states[-1] == 'LEASE_READY' and family == 'bridge':
                self.advance(.25)
            return result
        def observe(value):
            if value['state'] == 'RETRY_WAIT':
                self.stopped = True
        first = len(self.journal.history)
        with patch.object(backend, 'run', side_effect=command):
            self.supervisor._serve(self.stop, observe)
        writes = self.journal.history[first:]
        incident_row = next(r for r in writes if r['state'] == 'RETRY_WAIT')
        self.assertEqual([r['state'] for r in writes], ['ACTIVE', 'RETRY_WAIT', 'CANCELLED'])
        self.assertIsNone(writes[0]['lastIncident'])
        i = incident_row['lastIncident']
        self.assertEqual((i['phase'], i['code'], i['deadlineMonotonic'], i['leaseRemainingMs']),
                         ('READBACK', 'DNS_WINDOW_TOO_SHORT', None, 22000))
        trace = self.check_checkpoint(incident_row)
        prev, cur = trace['previous'], trace['current']
        self.assertEqual(prev['sequence'] + 1, cur['sequence'])
        self.assertFalse(prev['truncated'] or cur['truncated'])
        def rows(frame, tag):
            return [row[1:] for row in frame['events'] if row[0] == tag]
        self.assertEqual(rows(prev, 'plan'), [[100., 5]])
        self.assertEqual(rows(prev, 'wait'), [[100., 5]])
        self.assertEqual(rows(prev, 'wake'), rows(prev, 'renew'))
        self.assertEqual(rows(prev, 'compile'), [[105.], [111.5]])
        self.assertIn([105., 1], rows(prev, 'acquired'))
        self.assertIn([111.5], rows(prev, 'guardEnd'))
        self.assertEqual(rows(prev, 'timeout')[-2:], [[111.5, 0, 22], [111.5, 1, 22]])
        for tag in ('verify', 'verifyEnd', 'ready', 'readyEnd', 'apply'):
            self.assertEqual(rows(prev, tag), [[111.5]])
        self.assertEqual(rows(prev, 'applyEnd'), [[111.5, True]])
        self.assertIn([111.5, 1], rows(prev, 'released'))
        self.assertEqual(rows(cur, 'tick'), [[111.5]])
        self.assertEqual(rows(cur, 'sampleBefore'), [[111.5, 22]])
        self.assertEqual(rows(cur, 'expires'), [[111.75, 0, 22, 22], [111.75, 1, 22, 22]])
        self.assertEqual(rows(cur, 'sampleAfter'), [[111.75, 21.75, 133.5]])
        self.assertEqual(rows(cur, 'dumpEnd'), [[111.5, 0, True], [111.75, 1, True]])
        module, line = trace['branch']
        source = self.result['documents'][RECOVERY + 'adaptive_supervisor.py'].decode().splitlines()
        self.assertEqual(module, 0)
        self.assertIn('require(remaining >= reserve', source[line-1])

    def test_short_negative_ttl_only_one_flow(self):
        def reply(query):
            data = v20.answer(query)
            if b'fixture1' in query and query[-4:-2] == b'\x00\x1c':
                # Change only the negative SOA minimum in this flow.
                data = data[:-4] + struct.pack('!I', 8)
            return data
        count = 4 * len(self.c.owner.profile['resolvers'])
        wire = v20.SocketScript(self.advance, [[], *([[(.01, reply)]] * count)])
        self.assertEqual(self.renew_with_transport(wire)['reason'], 'RENEWED')
        trace = self.check_checkpoint(self.supervisor.tick())
        events = trace['previous']['events']
        self.assertEqual([e[2:] for e in events if e[0] == 'ttl'], [[0, v20.TTL, True], [1, 8, True]])
        self.assertEqual([e[2] for e in events if e[0] == 'dnsEnd'], [count + 1])
        self.assertEqual([e[2:] for e in events if e[0] == 'timeout'][-2:], [[0, 27], [1, 5]])

    def test_short_cname_before_negative_soa(self):
        def reply(query):
            if b'fixture1' not in query or query[-4:-2] != b'\x00\x1c':
                return v20.answer(query)
            # A short CNAME followed by a longer SOA in the negative answer.
            ident = int.from_bytes(query[:2], 'big')
            target = b'\x01z\x07invalid\x00'
            alias = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 8, len(target)) + target
            soa = b'\x00\x00' + struct.pack('!5I', 1, 1, 1, 1, 3600)
            authority = target + struct.pack('!HHIH', 6, 1, 3600, len(soa)) + soa
            return struct.pack('!6H', ident, 0x8180, 1, 1, 1, 0) + query[12:] + alias + authority
        queries = 4 * len(self.c.owner.profile['resolvers'])
        wire = v20.SocketScript(self.advance, [[(.01, reply)]] * queries)
        self.assertEqual(self.renew_with_transport(wire)['reason'], 'RENEWED')
        trace = self.check_checkpoint(self.supervisor.tick())
        ttl = [e[2:] for e in trace['previous']['events'] if e[0] == 'ttl']
        self.assertEqual(ttl, [[0, v20.TTL, True], [1, 8, False]])

    def test_failed_child_and_late_revocation_keep_first_apply_outcome(self):
        backend = sys.modules['nft_seconds_backend'].NftBackend
        def command(arguments, raw=None, timeout=None):
            if 'add element' in raw:
                self.advance(.1)
                raise RuntimeError('SECRET_SENTINEL 1.1.1.1 fixture1.invalid')
            return self.run_nft(arguments, raw, timeout)
        with patch.object(backend, 'run', side_effect=command):
            row = self.renew()
        self.assertEqual(row['state'], 'RECONCILE_REQUIRED')
        trace = self.check_checkpoint(row)
        outcomes = [e for e in trace['current']['events'] if e[0] == 'applyEnd']
        self.assertEqual(outcomes, [['applyEnd', 100.1, False]])
        self.assertEqual(trace['current']['events'][-1][0], 'deny')

    def test_first_failure_frozen_and_reader_rejects_invalid_timing(self):
        self.query_outcomes[:] = ['DNS_UNAVAILABLE', 'DNS_UNAVAILABLE']
        recorder = self.adapter.incident.timing
        with patch.object(recorder, 'snapshot', wraps=recorder.snapshot) as snapshot:
            result = self.renew()
        snapshot.assert_called_once()
        timing = self.check_checkpoint(result)
        pending = next(r for r in self.journal.history if r['reason'] == 'RENEWAL_RETRY_PENDING')
        self.assertEqual(pending['lastIncident']['timing'], timing)
        validate = reader('r3-status.py')['recovery_incident']
        journal = sys.modules['recovery_journal']
        for event in (['dnsEnd', 1, -1], ['ttl', 1, 32, 0, True], ['dump', 1, True],
                      ['ready', float('nan')], ['applyEnd', 1, 'SECRET_SENTINEL'],
                      ['SECRET_SENTINEL', 1], ['compile', 1, '1.1.1.1']):
            bad = deepcopy(result)
            bad['lastIncident']['timing']['current']['events'].append(event)
            with self.subTest(event=event), self.assertRaises(ValueError):
                validate(bad['lastIncident'], bad['contextRef'])
            with self.assertRaises(ValueError):
                journal.validate_incident(bad)
        for _ in range(journal.TIMING_MAX_EVENTS + 1):
            recorder.event('renew')
        self.assertTrue(recorder.current['truncated'])
        self.assertEqual(len(recorder.current['events']), journal.TIMING_MAX_EVENTS)
        # Maximum legal timestamp lengths and R values fit the CAS even with two full rings.
        for _ in range(journal.TIMING_MAX_EVENTS):
            recorder.event('sampleAfter', -1.111111111111111e-100, 2.222222222222222e-100,
                           at=3.333333333333333e-100)
        recorder.attempted = True
        recorder.next_cycle()
        recorder.event('ready', at=float('nan'))
        for _ in range(journal.TIMING_MAX_EVENTS - 2):
            recorder.event('sampleAfter', -1.111111111111111e-100, 2.222222222222222e-100,
                           at=3.333333333333333e-100)
        full = deepcopy(result)
        full_trace = full['lastIncident']['timing'] = recorder.snapshot(None)
        self.assertTrue(full_trace['previous']['truncated'] and full_trace['current']['truncated'])
        journal.validate_incident(full)
        self.assertLess(len(journal.encoded(full)), 65536)
        validate(full['lastIncident'], full['contextRef'])
        bad = deepcopy(result)
        bad['lastIncident']['timing']['current']['events'] = [['ready', 1]] * (journal.TIMING_MAX_EVENTS + 1)
        with self.assertRaises(ValueError):
            validate(bad['lastIncident'], bad['contextRef'])


if __name__ == '__main__':
    unittest.main()
