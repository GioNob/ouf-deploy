"""Qualify the emitted v20 DNS client and the stopped-provider upgrade offline."""
from collections import deque
import math
import socket
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from r3_sealed_inputs import sealed_legacy_inputs
from test_semantic_provider_r3_v18 import C, V12, RenewalFixture, upgrade
from test_semantic_provider_r3_v19 import composition_fixture as v19_fixture
from tools.semantic_provider_r3 import dns_retransmit_overlay_v20 as overlay


PREFIX = 'versions/20/'
CONFIG = 'runtime-configuration.json'
SUPERVISOR_CONFIG = 'supervisor/configuration.json'
OWNER_DNS, RECOVERY_DNS = overlay.DNS_TARGETS
BOOTSTRAP = 'scripts/semantic-provider-lease-supervisor-v2.py'
RESOLVERS = ['192.0.2.1', '192.0.2.2']
HOST = 'fixture.invalid'
TTL = 86400


def fixture(*, sealed=False):
    if sealed:
        with sealed_legacy_inputs(V12):
            inputs, _, old = v19_fixture()
    else:
        inputs, _, old = v19_fixture()
    return inputs, old, C.compose(inputs, 20, sequence=20, supersedes=C.sha(old['authorization']))


class CompositionV20(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs, cls.old, cls.result = fixture()

    def test_issuance_and_final_source_seal(self):
        old, new = self.old, self.result
        self.assertEqual(C.SOURCE_MAP_V20, C.SOURCE_MAP_V19)
        self.assertEqual(C.SOURCE_INPUTS_V20, C.SOURCE_INPUTS_V19)
        self.assertEqual(C.DATA_INPUTS_V20, C.DATA_INPUTS_V19)
        self.assertTrue(C.input_set(**self.inputs))
        self.assertEqual(new['inputHashes'], old['inputHashes'])
        self.assertEqual(new['audit'], old['audit'])

        previous, auth = (C.document(r['authorization']) for r in (old, new))
        head = dict(decision='OPERATE', sequence=19, sha256=C.sha(old['authorization']), authorization=previous)
        issuer = V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v20_issuer')
        self.assertEqual(issuer.compose_next(self.inputs, head, auth['issuedAt']), new)
        self.assertEqual((auth['sequence'], auth['supersedes']), (20, head['sha256']))
        self.assertEqual(auth['lease'], previous['lease'])
        for role in C.ROLES:
            self.assertEqual(auth['roles'][role]['containerId'], previous['roles'][role]['containerId'])
        self.assertEqual(auth['runtimeConfigurationSha256'], new['hashes'][PREFIX + CONFIG])

        docs, old_docs = new['documents'], old['documents']
        sources = PREFIX + 'source/'
        changed = {path.removeprefix(sources) for path, raw in docs.items() if path.startswith(sources)
                   and raw != old_docs['versions/19/' + path.removeprefix(PREFIX)]}
        alias = C.SOURCE_MAP_V20[OWNER_DNS]
        self.assertEqual(changed, {target for target, original in C.SOURCE_MAP_V20.items() if original == alias}
                         | {C.SUPERVISOR})
        self.assertEqual(docs[sources + OWNER_DNS], docs[sources + RECOVERY_DNS])
        cfg = C.document(docs[PREFIX + CONFIG])
        old_cfg = C.document(old_docs['versions/19/' + CONFIG])
        self.assertEqual(cfg['sourceHash'], old_cfg['sourceHash'])
        self.assertEqual(cfg['leaseQuiesce']['entrypoint']['sha256'], C.sha(docs[sources + BOOTSTRAP]))

        sup = C.document(docs[PREFIX + SUPERVISOR_CONFIG])
        supervisor = C.contract_module(docs[sources + C.SUPERVISOR], 'v20_pins')
        for path, digest in sup['sourceHashes'].items():
            self.assertEqual(digest, new['hashes'][sources + path])
            self.assertEqual(digest, C.sha(docs[sources + path]))
        self.assertEqual(supervisor.PINS['dns'], sup['sourceHashes'][RECOVERY_DNS])

    def test_overlay_preserves_lf_and_crlf_and_requires_exact_anchor(self):
        path = C.SOURCE_MAP_V20[OWNER_DNS]
        raw = self.inputs['sources'][path]
        edited = overlay.sources_v20({path: raw}, C.SOURCE_MAP_V20)[path]
        crlf = overlay.sources_v20({path: raw.replace(b'\n', b'\r\n')}, C.SOURCE_MAP_V20)[path]
        self.assertEqual(crlf, edited.replace(b'\n', b'\r\n'))
        anchor = overlay.UDP_START.encode('ascii')
        for replacement in (anchor.replace(b'def exchange', b'def replaced'), anchor + anchor):
            with self.subTest(replacement=replacement[:45]), self.assertRaisesRegex(C.A.OperationDenied, overlay.DRIFT):
                overlay.sources_v20({path: raw.replace(anchor, replacement)}, C.SOURCE_MAP_V20)

    def test_retry_budget_must_fit_dns_profile(self):
        with patch.object(overlay, 'UDP_ATTEMPT_SECONDS', 4), self.assertRaisesRegex(
                C.A.OperationDenied, '^R3_V20_DNS_RETRY_BUDGET_INCOMPATIBLE$'):
            C.compose(self.inputs, 20, sequence=20, supersedes=C.sha(self.old['authorization']))

    def test_normal_upgrade_plan_binds_v20_wrapper_unit_and_documents(self):
        observe = V12.NativeBindingsAndUpgrade().observation_fixture
        with observe((self.inputs, self.old, self.result), version=20) as (args, _, _, _):
            state, composed = upgrade.observe(args)
        self.assertEqual(composed, self.result)
        self.assertEqual((state['versionBefore'], state['versionAfter']), (19, 20))
        self.assertEqual(state['previousAuthorizationSha256'], C.sha(self.old['authorization']))
        self.assertIn(f'/{PREFIX}source/{C.RUNTIME}', state['wrapperProposed']['text'])
        self.assertIn(f'/{PREFIX}{CONFIG}', state['wrapperProposed']['text'])
        self.assertIn(f'/{PREFIX}source/{BOOTSTRAP}', state['unit']['text'])
        self.assertIn(composed['hashes'][PREFIX + SUPERVISOR_CONFIG], state['unit']['text'])
        self.assertEqual({row['path']: row['sha256'] for row in state['writes']['files']}, {
            f'{args.install_root}/{path}': composed['hashes'][path] for path in composed['documents']})


def answer(query, *, flags=0x8180, wrong_id=False, wrong_type=False):
    ident = int.from_bytes(query[:2], 'big') ^ (0x8000 if wrong_id else 0)
    question = query[12:]
    qtype = int.from_bytes(question[-4:-2], 'big')
    if wrong_type:
        question = question[:-4] + struct.pack('!HH', 28 if qtype == 1 else 1, 1)
    if flags & 0x0200:
        return struct.pack('!6H', ident, flags, 1, 0, 0, 0) + question
    if qtype == 1:
        rtype, data = 1, bytes([1, 1, 1, 1])
    else:
        rtype, data = 6, b'\0\0' + struct.pack('!5I', 1, 1, 1, 1, TTL)
    header = struct.pack('!6H', ident, flags, 1, int(qtype == 1), int(qtype == 28), 0)
    return header + question + b'\xc0\x0c' + struct.pack('!HHIH', rtype, 1, TTL, len(data)) + data


class InlineWorker:
    """Execute the current resolver worker deterministically with the fake clock."""
    def __init__(self, *, target, args, daemon):
        self.run = lambda: target(*args)

    def start(self):
        self.run()

    def is_alive(self):
        return False

    def join(self, _):
        pass


class SocketScript:
    def __init__(self, advance, scripts):
        self.advance = advance
        self.scripts = deque(scripts)
        self.peers = []
        self.module = SimpleNamespace(socket=self.open, AF_INET=socket.AF_INET, AF_INET6=socket.AF_INET6,
                                      SOCK_DGRAM=socket.SOCK_DGRAM, SOCK_STREAM=socket.SOCK_STREAM)

    def open(self, family, kind):
        peer = ScriptedSocket(family, kind, self.advance, self.scripts.popleft())
        self.peers.append(peer)
        return peer


class ScriptedSocket:
    def __init__(self, family, kind, advance, steps):
        self.family, self.kind, self.advance = family, kind, advance
        self.steps = deque(steps)
        self.waits = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def settimeout(self, value):
        self.timeout = value

    def connect(self, address):
        self.address = address

    def send(self, query):
        self.query = query
        return len(query)

    def sendall(self, message):
        self.tcp_request = message
        self.query = message[2:]

    def recv(self, count):
        self.waits.append(self.timeout)
        if not self.steps:
            self.advance(self.timeout)
            raise TimeoutError
        delay, reply = self.steps.popleft()
        if delay > self.timeout:
            raise AssertionError('test reply exceeds socket timeout')
        self.advance(delay)
        raw = reply(self.query)
        if len(raw) > count:
            raise AssertionError('test reply exceeds read length')
        return raw


class DNSRetransmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = fixture()[2]['documents'][PREFIX + 'source/' + OWNER_DNS]

    def setUp(self):
        self.dns = C.contract_module(self.source, 'emitted_v20_dns')
        self.now = 100.
        self.dns.time = SimpleNamespace(monotonic=lambda: self.now)

    def transport(self, scripts):
        def advance(seconds):
            self.now += seconds
        wire = SocketScript(advance, scripts)
        self.dns.socket = wire.module
        return wire

    def test_first_loss_retries_with_new_id_and_charges_only_elapsed_time(self):
        wire = self.transport([[], *([[(.03, answer)]] * 4)])
        result = self.dns.observe('https://' + HOST, RESOLVERS, 53, 4, [], 10, 30,
                                  monotonic=lambda: self.now, wall_clock=lambda: 1000., thread_factory=InlineWorker)
        self.assertAlmostEqual(self.now - 100, 1.12)
        self.assertEqual(result['minimumObservedTtlSeconds'], TTL)
        self.assertEqual(result['remainingLeaseSecondsAtObservation'], 30 - math.ceil(self.now - 100))
        self.assertAlmostEqual(result['expiresMonotonic'], self.now + 28)
        self.assertEqual([row['resolver'] for row in result['observations']], RESOLVERS)
        self.assertEqual(result['missedResolvers'], [])
        first, second = wire.peers[:2]
        self.assertNotEqual(first.query[:2], second.query[:2])
        self.assertEqual(first.query[2:], second.query[2:])
        self.assertTrue(all(peer.closed for peer in wire.peers))

    def test_repeated_loss_stops_at_shared_deadline_and_denies(self):
        wire = self.transport([[], [], []])
        with self.assertRaisesRegex(self.dns.DNSDenied, '^DNS_DEADLINE_EXPIRED$'):
            self.dns.exchange(RESOLVERS[0], 53, HOST, 1, 102.25)
        self.assertEqual(self.now, 102.25)
        self.assertEqual([peer.waits for peer in wire.peers], [[1.], [1.], [.25]])
        self.assertEqual(len({peer.query[:2] for peer in wire.peers}), 3)
        self.assertTrue(all(peer.closed for peer in wire.peers))

    def test_repeated_loss_stops_at_attempt_cap_even_with_budget_left(self):
        wire = self.transport([[], [], []])
        with self.assertRaisesRegex(self.dns.DNSDenied, '^DNS_RESOLVER_TRANSPORT_FAILED$'):
            self.dns.exchange(RESOLVERS[0], 53, HOST, 1, 110.)
        self.assertEqual(self.now, 103.)
        self.assertEqual(len(wire.peers), 3)

    def test_wrong_ident_is_ignored_within_original_attempt(self):
        wire = self.transport([[(.25, lambda query: answer(query, wrong_id=True)), (.05, answer)]])
        parsed = self.dns.exchange(RESOLVERS[0], 53, HOST, 1, 110.)
        self.assertEqual(parsed['responseHash'], C.sha(answer(wire.peers[0].query)))
        self.assertEqual([peer.waits for peer in wire.peers], [[1., .75]])

    def test_wrong_qtype_on_matching_ident_is_still_denied(self):
        self.transport([[(.05, lambda query: answer(query, wrong_type=True))]])
        with self.assertRaisesRegex(self.dns.DNSDenied, '^DNS_QUESTION_MISMATCH$'):
            self.dns.exchange(RESOLVERS[0], 53, HOST, 1, 110.)

    def test_tc_keeps_tcp_fallback_and_uses_shared_budget(self):
        wire = self.transport([[(.25, lambda query: answer(query, flags=0x8380))],
                               [(0., lambda query: struct.pack('!H', len(answer(query)))), (1.5, answer)]])
        parsed = self.dns.exchange(RESOLVERS[0], 53, HOST, 1, 110.)
        udp, tcp = wire.peers
        self.assertEqual((udp.kind, tcp.kind), (socket.SOCK_DGRAM, socket.SOCK_STREAM))
        self.assertEqual(udp.address, tcp.address)
        self.assertEqual(tcp.tcp_request, struct.pack('!H', len(udp.query)) + udp.query)
        self.assertEqual(tcp.waits, [9.75, 9.75])
        self.assertEqual(self.now, 101.75)
        self.assertEqual(parsed['transport'], 'TCP')
        self.assertEqual(parsed['responseHash'], C.sha(answer(udp.query)))


class SupervisorV20(RenewalFixture):
    @classmethod
    def setUpClass(cls):
        cls.inputs, _, cls.result = fixture()
        cls.retained = V12.fixture()[2]

    def renew_with_transport(self, wire):
        clock = SimpleNamespace(monotonic=self.clock)

        def observe(*args, **kwargs):
            self.assertFalse(self.locked)
            return self.observe_many(*args, **kwargs, wall_clock=lambda: self.wall, thread_factory=InlineWorker)

        with patch.multiple(self.dns, observe_many=observe, socket=wire.module, time=clock), \
                patch.dict(self.adapter.fresh_evidence.__func__.__globals__, {'time': clock}):
            return self.renew()

    def test_one_udp_loss_does_not_pause_renewal(self):
        normal_queries = 2 * len(self.c.owner.profile['resolvers']) * len(self.c.configuration['providerFlows'])
        wire = SocketScript(self.advance, [[], *([[(.03, answer)]] * normal_queries)])
        started = self.clock()
        row = self.renew_with_transport(wire)
        self.assertAlmostEqual(self.clock() - started, 1 + normal_queries * .03)
        self.assertEqual(len(wire.peers), normal_queries + 1)
        self.assertEqual((row['state'], row['reason'], row['lastIncident']), ('ACTIVE', 'RENEWED', None))
        self.assertEqual(row['fastRenewalRetries'], 0)
        self.assertEqual(self.lease_states, ['LEASE_UPDATING', 'LEASE_READY'])
        self.assertTrue(self.coordination['leaseAuthorized'])
        self.assertEqual(len(self.commands), 1)

    def test_persistent_loss_revokes_with_existing_dns_incident(self):
        resolvers = len(self.c.owner.profile['resolvers'])
        flows = len(self.c.configuration['providerFlows'])
        collections = self.c.renewal['fastRetryCount'] + 1
        max_sockets = resolvers * flows * collections * overlay.UDP_MAX_ATTEMPTS
        wire = SocketScript(self.advance, [[] for _ in range(max_sockets)])
        row = self.renew_with_transport(wire)
        self.assertEqual((row['state'], row['reason']), ('RETRY_WAIT', 'DNS_UNAVAILABLE'))
        incident = row['lastIncident']
        self.assertEqual((incident['phase'], incident['code'], incident['revocation']),
                         ('DNS', 'DNS_UNAVAILABLE', 'VERIFIED'))
        self.assertEqual(self.lease_states, ['QUIESCING', 'QUIESCED'])
        self.assert_closed()


if __name__ == '__main__':
    unittest.main()
