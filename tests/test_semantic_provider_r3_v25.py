"""R-002 admission, ordinary upgrade and comparison with a reauthorized v24."""
from contextlib import contextmanager, nullcontext
from functools import lru_cache
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_semantic_provider_r3_v13 as backend
import test_semantic_provider_r3_v24 as v24
from tools.semantic_provider_r3 import semantic_identity_v25 as live

C = v24.C
PREFIX = 'versions/25/'


def docker_row(p):
    cid = 'b' * 64
    return {'Id': cid, 'Name': '/' + p['containerName'], 'Image': p['image'],
                'Config': {'Hostname': cid[:12], 'Env': ['FIXTURE=1']},
                'Path': '/app', 'Args': [], 'HostConfig': {'Privileged': False}, 'Mounts': [],
                'State': {'Running': True, 'Status': 'running', 'Pid': 401, 'StartedAt': 'first'},
                'NetworkSettings': {'Networks': {p['network']: {'EndpointID': 'e' * 64,
                                        'NetworkID': p['networkId'], 'IPAddress': p['ipv4']}}}}


@lru_cache
def fixture(cadence=20):
    inputs, _, old = v24.fixture()
    profile = dict(role='semantic', containerName='semantic-fixture', image='sha256:' + 'a' * 64,
                   direction='semantic-to-southbound')
    network = C.document(inputs['files']['identityProviderPeer'])['southbound']
    flow = C.document(inputs['files']['semanticPeer'])['proposedIngress']
    profile.update({k: network[k] for k in ('network', 'networkId', 'bridge')},
                   ipv4=flow['sourceIpv4'], destination=flow['destinationIpv4'],
                   protocol=flow['protocol'], port=flow['destinationPort'])
    profile['configurationSha256'] = live.semantic_configuration(docker_row(profile))
    renewal = {**C.document(inputs['files']['leaseRenewal']), 'semanticTickBudgetSeconds': .70,
               'semanticCloseReserveSeconds': .2, 'semanticFullObservationSeconds': cadence}
    inputs = {'sources': {**inputs['sources'], C.SEMANTIC_IDENTITY:
                         (Path(__file__).resolve().parents[1] / C.SEMANTIC_IDENTITY).read_bytes()},
              'files': {**inputs['files'], 'semanticProfile': C.canonical(profile), 'leaseRenewal': C.canonical(renewal)}}
    return inputs, old, C.compose(inputs, 25, sequence=25, supersedes=C.sha(old['authorization']))


def reauthorized_v24(index):
    """Compose a separate v24 payload from synthetic A2 and acceptance on this port."""
    inputs, _, original = v24.fixture()
    files = dict(inputs['files'])
    peer = C.document(files['semanticPeer'])
    peer['binding']['hostIfindex'] = peer['proposedIngress']['ifindex'] = index
    files['semanticPeer'] = C.canonical(peer)
    manifest = C.document(files['a2Manifest'])
    acceptance = C.document(files['acceptance'])
    bindings = acceptance['preparationA']['files']
    manifest['manifest']['semanticPeer'] = peer
    entry, = [e for e in manifest['manifest']['filesCreated'] if e['path'] == bindings['semanticPeer']['path']]
    entry['sha256'] = bindings['semanticPeer']['sha256'] = C.sha(files['semanticPeer'])
    files['a2Manifest'] = C.canonical(manifest)
    bindings['manifest']['sha256'] = C.sha(files['a2Manifest'])
    files['acceptance'] = C.canonical(acceptance)
    return C.compose({**inputs, 'files': files}, 24, sequence=25, supersedes=C.sha(original['authorization']))


class Composition(unittest.TestCase):
    def test_ordinary_issue_and_upgrade(self):
        inputs, old, result = fixture()
        self.assertTrue(C.input_set(inputs['files'], inputs['sources']))
        self.assertFalse(C.input_set(inputs['files'], v24.fixture()[0]['sources']))
        issuer = v24.v20.V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'issuer25')
        auth = C.document(old['authorization'])
        head = dict(decision='OPERATE', sequence=24, sha256=C.sha(old['authorization']), authorization=auth)
        self.assertEqual(issuer.compose_next(inputs, head, auth['issuedAt']), result)
        with patch.object(live, 'semantic_kernel') as kernel:
            with v24.v20.V12.NativeBindingsAndUpgrade().observation_fixture(fixture(), version=25) as (args, *_):
                state, rebuilt = v24.v20.upgrade.observe(args)
        kernel.assert_called_once()
        self.assertEqual(rebuilt, result)
        self.assertEqual((state['versionBefore'], state['versionAfter']), (24, 25))

    def test_rules_match_reauthorized_v24(self):
        inputs, _, new = fixture()
        profile = C.document(inputs['files']['semanticProfile'])
        raw = new['documents'][PREFIX + 'documents/southbound/transport.json']
        role = C.document(new['authorization'])['roles']['southbound']
        self.assertEqual(role['transportSha256'], C.sha(raw))
        flow, = [f for f in C.document(raw)['transport'] if f['purpose'] == 'WORKLOAD_GATEWAY']
        self.assertEqual(flow['peerIngress'], {'kind': 'SEMANTIC_PROFILE', 'declaration': profile})
        def rules(result, version, index):
            with backend.I.module_scope():
                backend.load_modules(result, version=version)
                policy = backend.backend_policy(result, semantic_ifindex=index, version=version)
                return sys.modules['tools.materialize_semantic_shared_faces'].materialize(policy)['nftRules']
        for port in (22, 707, 28001):
            actual = rules(new, 25, port)
            self.assertEqual([s.strip() for s in actual.splitlines() if s.startswith(' set semantic_open')],
                             ['set semantic_open { type ipv4_addr; size 1; }'] * 2)
            self.assertEqual(actual.count('meta iif @semantic_port ip saddr @semantic_open '), 1)
            # Specialize the single-element sets to this live, reconciled port.
            # All remaining rules including ct, default drop and ARP must be byte identical.
            projected = '\n'.join(s for s in actual.split('\n') if not s.startswith(' set semantic_'))
            projected = projected.replace('meta iif @semantic_port ', f'meta iif {port} ')
            for field in ('saddr', 'daddr'):
                projected = projected.replace('ip ' + field + ' @semantic_open ', '')
            reference = reauthorized_v24(port)
            reference_auth = C.document(reference['authorization'])['roles']['southbound']
            self.assertEqual(reference_auth['transportSha256'],
                             C.sha(reference['documents'][v24.PREFIX + 'documents/southbound/transport.json']))
            baseline = rules(reference, 24, None)
            self.assertEqual(projected, baseline)
            suffix = (f"ip saddr {flow['source']} ip daddr {flow['destination']} tcp dport {flow['port']} "
                      "ct state { new, established } counter accept")
            for name, device, expected in (
                    ('new veth before reconciliation', port + 1, False),
                    ('reconciled restart or recreation', port, True),
                    ('administrative rename before tick', port, True),
                    ('same tuple from shared netns', port, True)):
                with self.subTest(case=name, installed=port):
                    rule = f'meta iif {device} {suffix}'
                    for emitted in (baseline, projected):
                        self.assertEqual(rule in emitted.split('table bridge ', 1)[1], expected)


class Predecessor(unittest.TestCase):
    def test_frozen_v24(self):
        import test_semantic_provider_r3_v24 as v24

        result = v24.fixture()[2]
        for field, expected in {
            "hashes": "36e6dcc61f485da752003c514afaaa40c22f5debf894df12931417fc1a941932",
            "inputHashes": "a08343d9e31beb977a45e1b3f27e566e806a404618d8897ae6c2e6bbbb52a8c6",
            "audit": "302d3b526d20af5f200c95a7258d9351254ce50220df3425aa7a3749db8e8aab",
            "layout": "4c422657305df3c44a42770d805475a819492e4e08c53d8ca2d3193f11ec11a1",
        }.items():
            with self.subTest(field=field):
                self.assertEqual(v24.C.sha(v24.C.canonical(result[field])), expected)
        self.assertEqual(v24.C.sha(result["authorization"]),
                         "fe8a59c03d2f0148320f546c7b16b69dfbf2e5af0e8083f5bf164ba2d265475e")


class PeerFixture:
    """Docker and rtnetlink reads at the native observer boundary."""
    def __init__(self):
        self.profile = C.document(fixture()[0]['files']['semanticProfile'])
        p = self.profile
        self.index = 27
        self.row = docker_row(p)
        self.ip = p['ipv4']
        self.master = p['bridge']
        self.docker_reads = 0
        cid = self.row['Id']
        self.net = {'Name': p['network'], 'Id': p['networkId'], 'Driver': 'bridge',
                    'Options': {'com.docker.network.bridge.name': p['bridge']},
                    'Containers': {cid: {'Name': p['containerName'], 'IPv4Address': p['ipv4'] + '/24',
                                         'EndpointID': 'e' * 64}}}

    def observe(self, epoch=None):
        p = self.profile
        def run(binding, args):
            if 'container' in args:
                self.docker_reads += 1
                row = self.row
            elif 'network' in args:
                self.docker_reads += 1
                row = self.net
            elif 'addr' in args:
                row = {'link_index': self.index, 'ifindex': 2, 'linkinfo': {'info_kind': 'veth'},
                       'addr_info': [{'family': 'inet', 'local': self.ip}]}
            else:
                row = {'link_index': 2, 'ifindex': self.index, 'ifname': 'testport',
                       'master': self.master, 'linkinfo': {'info_kind': 'veth'}}
            return json.dumps([row]).encode()
        commands = {k: {'path': '/' + k} for k in ('docker', 'ip', 'nsenter')}
        def gen(pid):
            if pid != self.row['State']['Pid']:
                raise ProcessLookupError()
            return dict(pid=pid, startTicks=pid * 2, namespaceDevice=1, namespaceInode=pid + 2)
        with patch.object(live.socket, 'if_indextoname', return_value='testport'):
            if epoch is not None:
                return live.semantic_link(p, commands, epoch['generation'], run, gen, lambda _: None)
            return live.semantic_observe(p, {**commands, 'socket': '/fixture'}, run, gen, 'fixture-boot',
                                         check_executable=lambda binding: None)[0]

    def replace(self, recreate):
        self.index += 1
        self.row['State']['Pid'] += 1
        self.row['State']['StartedAt'] = 'second'
        if recreate:
            cid = C.sha(self.row['Id'].encode())
            self.net['Containers'][cid] = self.net['Containers'].pop(self.row['Id'])
            self.row.update(Id=cid)
            self.row['Config']['Hostname'] = cid[:12]


@contextmanager
def virtual_phase(end, clock, expired=live.SemanticDeadline):
    if clock() >= end:
        raise expired()
    yield
    if clock() >= end:
        raise expired()


class TickFixture:
    def __init__(self, gate, clock, phase, link_observer=live.semantic_link, nft_binding=None):
        self.locked = False
        self.releases = []
        self.clock = clock
        inputs, _, result = fixture()
        cfg = C.document(result['documents'][PREFIX + 'supervisor/configuration.json'])
        kernel = C.document(inputs['files']['coordinator'])['kernel']
        self.lease_seconds = min(f['leaseSeconds'] for f in kernel['providerFlows'])
        if nft_binding is not None:
            cfg['coordinator']['nftBinding'] = nft_binding
        self.policy = cfg['leaseRenewal']
        self.lease = {'state': 'LEASE_READY', 'leaseAuthorized': True}
        self.c = SimpleNamespace(hold_until=self.lock, publish=self.publish, journal=lambda: self.lease,
                                 semantic_horizon=self.policy['semanticTickBudgetSeconds']
                                 + self.policy['semanticCloseReserveSeconds'] + .05)
        cid = cfg['semanticIngress']['containerId']
        row = dict(containerId=cid, epoch=9, generation={'pid': 7}, state='STARTED', driverHash='f' * 64)
        self.guards = SimpleNamespace(scope_guard=lambda: {'southbound': row}, current=lambda *_: row,
                                      deny=self.deny)
        self.expected = 'template'
        def read(*_):
            flow = {'peerIngress': {'kind': 'SEMANTIC_PROFILE', 'declaration': gate.profile}}
            return C.canonical({'profile': {'expectedFootprint': self.expected,
                                'policy': {'flows': [flow], 'tableName': gate.table}}})
        def capture_callbacks(table, profile, nft, observe):
            self.nft, self.observe = nft, observe
            return gate
        with patch.object(live, 'time', SimpleNamespace(monotonic=clock)), patch.object(live, 'SemanticGate', capture_callbacks):
            live.bind_semantic_gate(cfg, self.c, self.guards, read, phase=phase, link_observer=link_observer)

    @contextmanager
    def lock(self, end):
        assert not self.locked and self.clock() < end
        self.locked = True
        try:
            yield
        finally:
            self.locked = False
            self.releases.append(self.clock())

    def deny(self, code, detail):
        assert not self.locked
        raise ValueError(code)

    def publish(self, previous, following):
        assert self.locked and previous == self.lease
        self.lease = following

    def tick(self, wait=10):
        self.c.semantic_tick(self.clock() + wait, self.clock() + self.lease_seconds, self.lease)
        return self.c.semantic_result['outcome']


class Admission(unittest.TestCase):
    def setUp(self):
        self.peer = PeerFixture()
        self.platform = patch.object(live, 'semantic_kernel', side_effect=lambda: self.kernel())
        self.kernel = lambda: None
        self.platform.start()
        self.addCleanup(self.platform.stop)
        self.state = ([], [], [])
        self.gate = live.SemanticGate('fixture', self.peer.profile, None, self.peer.observe)
        self.gate.write = self.write
        self.gate.read = lambda footprint: self.state
        self.now = 100.
        def link(profile, commands, generation, run):
            return self.peer.observe({'generation': generation})
        self.owner = TickFixture(self.gate, lambda: self.now, virtual_phase, link)

    def reconcile(self):
        self.assertEqual(self.owner.tick(), 'VERIFIED')
        return self.gate.epoch

    def test_steady_and_periodic_docker_audit(self):
        first = self.reconcile()
        reads = self.peer.docker_reads
        self.assertGreater(reads, 0)
        self.assertEqual(self.reconcile(), first)
        self.assertEqual(self.peer.docker_reads, reads)
        self.now += self.owner.policy['semanticFullObservationSeconds']
        self.reconcile()
        self.assertGreater(self.peer.docker_reads, reads)

    def test_changed_link_or_netns_address(self):
        self.reconcile()
        before = self.peer.docker_reads
        self.peer.index += 1
        self.assertEqual(self.reconcile()['binding']['hostIfindex'], self.peer.index)
        self.assertGreater(self.peer.docker_reads, before)
        self.peer.ip = self.peer.profile['destination']
        self.assertEqual(self.owner.tick(), 'CLOSED')
        self.assertEqual(self.state, ([], [], []))
        self.peer.ip = self.peer.profile['ipv4']
        self.reconcile()
        self.peer.master += '-other'
        self.assertEqual(self.owner.tick(), 'CLOSED')
        self.assertEqual(self.state, ([], [], []))

    def test_no_lock_or_refresh_on_short_slot(self):
        self.reconcile()
        count = len(self.owner.releases)
        before = self.peer.docker_reads, self.state, self.gate.refresh_at
        self.assertEqual(self.owner.tick(wait=.1), 'DEFERRED')
        self.assertEqual(len(self.owner.releases), count)
        self.assertEqual(before, (self.peer.docker_reads, self.state, self.gate.refresh_at))
        self.gate.close()
        self.now += self.owner.policy['semanticFullObservationSeconds']
        self.assertEqual(self.owner.tick(wait=0), 'DEFERRED')
        self.assertIsNone(self.owner.c.semantic_epoch())
        self.assertEqual(self.state, ([], [], []))

    def exercise_close_deadline(self, fault=None):
        self.reconcile()
        self.gate.refresh_at = 0
        self.gate.observe = self.owner.observe
        budget = self.owner.policy['semanticTickBudgetSeconds']
        reserve = self.owner.policy['semanticCloseReserveSeconds']
        start = self.now
        commands = []
        def command(binding, argv, data=None, *, deadline):
            self.assertTrue(self.owner.locked)
            commands.append((argv, deadline))
            if 'inspect' in argv:
                self.assertAlmostEqual(deadline, start + budget)
                self.now = deadline
                raise subprocess.TimeoutExpired('docker', budget)
            self.assertAlmostEqual(deadline, start + budget + reserve)
            if data and fault == 'transaction':
                raise OSError()
            if not data and fault == 'late read':
                self.now = deadline + .005
            else:
                self.now += .01
        # Use the bound command callbacks for the slow inspect and the recovery
        # transaction/read. The simulated kernel can apply before readback stalls.
        writes = self.gate.write
        def write(port=None, enabled=False):
            if self.now >= start + budget:
                self.owner.nft(['-f', '-'], b'flush')
            writes(port, enabled)
        def read(_):
            if self.now >= start + budget:
                self.owner.nft(['-j', 'list', 'table'])
                if fault == 'nonempty':
                    return ([self.peer.index], [], [])
            return self.state
        with patch.object(live, 'semantic_command', command), patch.object(self.gate, 'write', write), \
                patch.object(self.gate, 'read', read):
            if fault:
                with self.assertRaisesRegex(ValueError, '^R3_SEMANTIC_CLOSE_UNVERIFIED$'):
                    self.owner.tick()
                self.assertEqual(self.owner.c.semantic_result['outcome'], 'R3_SEMANTIC_CLOSE_UNVERIFIED')
            else:
                self.assertEqual(self.owner.tick(), 'CLOSED')
        self.assertEqual(sum(argv == ['-f', '-'] for argv, _ in commands), 1)
        self.assertFalse(self.owner.locked)
        self.assertLessEqual(self.owner.releases[-1] - start, budget + reserve + .05)
        if fault == 'transaction':
            self.assertTrue(all(self.state))
        else:
            self.assertEqual(self.state, ([], [], []))
        if not fault:
            self.gate.observe = self.peer.observe
            self.reconcile()

    def test_slow_docker_closes_and_recovers(self):
        self.exercise_close_deadline()

    def test_applied_close_but_late_readback_fails_scope(self):
        self.exercise_close_deadline('late read')

    def test_failed_close_transaction_fails_scope(self):
        self.exercise_close_deadline('transaction')

    def test_nonempty_close_readback_fails_scope(self):
        self.exercise_close_deadline('nonempty')

    def test_journal_read_also_spends_ordinary_budget(self):
        self.reconcile()
        budget = self.owner.policy['semanticTickBudgetSeconds']
        start = self.now
        def delayed_journal():
            self.now += budget
            return self.owner.lease
        self.owner.c.journal = delayed_journal
        self.owner.guards.scope_guard = Mock(side_effect=AssertionError('late scope read'))
        def empty(binding, argv, data=None, *, deadline):
            self.assertAlmostEqual(deadline, start + budget + self.owner.policy['semanticCloseReserveSeconds'])
            family, table, name = argv[-3:]
            return C.canonical({'nftables': [{'set': {'family': family, 'table': table, 'name': name}}]})
        with patch.object(live, 'semantic_command', empty):
            self.assertEqual(self.owner.tick(), 'CLOSED')
        self.owner.guards.scope_guard.assert_not_called()
        self.assertFalse(self.owner.locked)
        self.assertEqual(self.state, ([], [], []))

    def write(self, port=None, enabled=False):
        addr = [self.peer.profile['ipv4']] if enabled else []
        self.state = ([port] if port else [], addr, addr)

    def test_lifecycle(self):
        for running in (False, True):
            for recreate in (False, True):
                with self.subTest(provider_running=running, recreate=recreate):
                    self.exercise_lifecycle(running, recreate)

    def exercise_lifecycle(self, running, recreate):
        self.peer = PeerFixture()
        self.gate.close()
        self.gate.last_verified = None
        self.gate.observe = self.peer.observe
        before = self.reconcile()
        if not running:
            self.gate.close()
        self.peer.replace(recreate)
        self.assertNotIn(self.peer.index, self.state[0])
        current = self.reconcile()
        self.assertEqual(self.state[0], [self.peer.index])
        self.assertEqual(current['profileSha256'], before['profileSha256'])
        self.assertNotEqual(before['generation'], current['generation'])
        self.assertEqual(before['containerId'] == current['containerId'], not recreate)

    def test_tick_denials_and_recovery(self):
        for case in ('image', 'configuration', 'rename', 'ip', 'two-generations', 'bridge', 'kernel'):
            with self.subTest(case=case):
                self.peer = PeerFixture()
                self.gate.observe = self.peer.observe
                self.gate.close()
                self.reconcile()
                if case == 'image':
                    self.peer.row['Image'] = 'sha256:' + '3' * 64
                elif case == 'configuration':
                    self.peer.row['Config']['Env'] = []
                elif case == 'rename':
                    self.peer.row['Name'] += '-retired'
                elif case == 'ip':
                    self.peer.row['NetworkSettings']['Networks'][self.peer.profile['network']]['IPAddress'] = '192.0.2.1'
                elif case == 'two-generations':
                    members = self.peer.net['Containers']
                    members['f' * 64] = dict(next(iter(members.values())))
                elif case == 'bridge':
                    self.peer.net['Options'] = {}
                else:
                    self.kernel = Mock(side_effect=ValueError('R3_MONOTONE_KERNEL_REQUIRED'))
                self.now += self.owner.policy['semanticFullObservationSeconds']
                self.assertEqual(self.owner.tick(), 'CLOSED')
                self.assertEqual(self.state, ([], [], []))
                self.assertIsNone(self.gate.epoch)

    def test_change_during_observation_stage_or_publication(self):
        for changed_at in (2, 3, 4):
            self.gate.close()
            count = 0
            def changing():
                nonlocal count
                count += 1
                if count == changed_at:
                    self.peer.replace(False)
                return self.peer.observe()
            self.gate.observe = changing
            self.assertEqual(self.owner.tick(), 'CLOSED')
            self.assertEqual(self.state, ([], [], []))
            self.assertEqual(self.reconcile()['binding']['hostIfindex'], self.peer.index)

    def test_readback_failure_closes_both_families(self):
        self.gate.read = Mock(side_effect=[([], [], []), ([self.peer.index], [], []), OSError(), ([], [], [])])
        self.assertEqual(self.owner.tick(), 'CLOSED')
        self.assertEqual(self.state, ([], [], []))

    def test_changed_generation_cannot_reuse_or_regress_index(self):
        self.reconcile()
        self.peer.replace(True)
        for index in (27, 26):
            self.peer.index = index
            self.assertEqual(self.owner.tick(), 'CLOSED')
            self.assertEqual(self.state, ([], [], []))


class Kernel(unittest.TestCase):
    def test_legacy_timed_set_or_timed_member_is_drift(self):
        profile = PeerFixture().profile
        for extra in ({'flags': ['timeout']}, {'timeout': 1000},
                      {'elem': [{'elem': {'val': profile['ipv4'], 'timeout': 1000, 'expires': 900}}]}):
            with self.subTest(extra=extra):
                listing = {'set': {'family': 'bridge', 'table': 'fixture', 'name': 'semantic_open', **extra}}
                nft = Mock(return_value=C.canonical({'nftables': [listing]}))
                gate = live.SemanticGate('fixture', profile, nft, None)
                with self.assertRaisesRegex(ValueError, 'R3_SEMANTIC_TABLE_DRIFT'):
                    gate.read('unused')
                nft.assert_called_once()

    def test_atomic_enable_preserves_staged_device(self):
        nft = Mock()
        gate = live.SemanticGate('fixture', PeerFixture().profile, nft, None)
        gate.write(27)
        gate.write(27, True)
        stage, enable = [call.args[1].decode() for call in nft.call_args_list]
        self.assertIn('add element bridge fixture semantic_port { 27 }', stage)
        self.assertNotIn('semantic_port', enable)
        self.assertNotIn('timeout', enable)
        for family in ('bridge', 'inet'):
            self.assertIn(f'flush set {family} fixture semantic_open', stage)
            self.assertIn(f'add element {family} fixture semantic_open', enable)

    def test_qualified_kernel(self):
        live.semantic_kernel('Linux', '6.12.0-3-amd64')
        for system, release in [('Linux', '6.5.9'), ('Windows', '10.0'), ('Linux', 'unknown')]:
            with self.assertRaisesRegex(ValueError, 'MONOTONE'):
                live.semantic_kernel(system, release)


class IngressTables:
    """The three synthetic role sets survive a supervisor restart."""
    def __init__(self):
        self.members = {(family, name): [] for family, name in (
            ('bridge', 'semantic_port'), ('bridge', 'semantic_open'), ('inet', 'semantic_open'))}
        self.batches = []

    def listing(self, family, table):
        return {'nftables': [{'set': {'family': family, 'table': table, 'name': name, 'size': 1,
                'type': 'iface_index' if name == 'semantic_port' else 'ipv4_addr',
                **({'elem': members} if members else {})}}
                for (f, name), members in self.members.items() if f == family]}

    def command(self, args, table, raw):
        if raw is not None:
            for line in raw.decode().splitlines():
                verb, _, family, target, name, *element = line.split()
                assert target == table
                if verb == 'flush':
                    self.members[family, name] = []
                else:
                    left, value, right = element
                    assert (verb, left, right) == ('add', '{', '}')
                    self.members[family, name] = [int(value) if name == 'semantic_port' else value]
            self.batches.append(dict(self.members))
            return b''
        if args[-1] == 'tables':
            return C.canonical({'nftables': [{'table': {'name': table, 'family': f}} for f in ('inet', 'bridge')]})
        if 'set' in args:
            family, _, name = args[-3:]
            return C.canonical({'nftables': [r for r in self.listing(family, table)['nftables']
                                             if r['set']['name'] == name]})
        return C.canonical(self.listing(args[-2], table))


class Consumers(unittest.TestCase):
    def replay(self, cadence=20, peer=None, tables=None, startup=None):
        # The lease fixture has synthetic provider epochs, clock and nft. Keep
        # the production v25 tick and publication callbacks in the replay.
        case = v24.Renewal('test_incident_25_26_next_tick_and_rollover')
        case.inputs, _, case.result = fixture(cadence)
        case.retained = v24.v20.V12.fixture()[2]
        def runtime(sup, configuration):
            spec = configuration.value['semanticIngress']
            policy = {'tableName': spec['table'], 'flows': [{'peerIngress': {
                'kind': 'SEMANTIC_PROFILE', 'declaration': spec['profile']}}]}
            footprint = 'c' * 64
            if tables is None:
                self.runtime_gate = Mock(epoch=None, table=spec['table'], profile=spec['profile'])
                gate_patch = patch.object(sup, 'SemanticGate', return_value=self.runtime_gate)
                sup.semantic_command = Mock(return_value=b'{"nftables":[]}')
            else:
                gate_patch = nullcontext()
                empty = IngressTables()
                footprint = live.semantic_digest({f: empty.listing(f, spec['table']) for f in ('bridge', 'inet')})
                def command(binding, args, raw=None, *, deadline):
                    self.assertTrue(case.locked)
                    return tables.command(args, spec['table'], raw)
                sup.semantic_command = command
                sup.semantic_observe = lambda *_: (peer.observe(), peer.row)
            raw = C.canonical({'profile': {'policy': policy, 'expectedFootprint': footprint}})
            bind = sup.bind_semantic_gate
            generation = {'pid': 7, 'startTicks': 7}
            row = {'epoch': 9, 'containerId': spec['containerId'], 'generation': generation,
                   'state': 'STARTED', 'driverHash': C.sha(raw)}
            def synthetic(cfg, coordinator, guards, read):
                bind(cfg, coordinator, SimpleNamespace(scope_guard=lambda: {'southbound': row},
                     current=lambda *args: row, deny=guards.deny), lambda path, digest: raw,
                     phase=lambda end, clock: virtual_phase(end, clock, sup.SemanticDeadline),
                     link_observer=lambda p, cmds, gen, run: peer.observe({'generation': gen}))
            with gate_patch, patch.object(sup, 'bind_semantic_gate', synthetic):
                owner = sup.runtime(configuration)
            if startup:
                continuous = sys.modules['continuous_supervisor']
                tick = continuous.Supervisor.tick
                def first_tick(supervisor):
                    continuous.Supervisor.tick = tick
                    startup(case, owner[0])
                    return tick(supervisor)
                case.enterContext(patch.object(continuous.Supervisor, 'tick', first_tick))
            return owner
        case.native_runtime = runtime
        self.addCleanup(case.doCleanups)
        case.setUp()
        return case

    def test_v24_dns_cache_rollover_on_v25_bootstrap(self):
        case = self.replay()
        self.runtime_gate.reconcile.side_effect = lambda *_, **kw: case.advance(.05)
        case.test_incident_25_26_next_tick_and_rollover()
        self.assertGreater(self.runtime_gate.reconcile.call_count, 1)

    @staticmethod
    def service(case, coordinator, **kwargs):
        guards = SimpleNamespace(sequence=25, epochs={'adapter': 7, 'southbound': 9})
        return case.sup.Service(case.cfg, coordinator, guards, None, Mock(count=lambda _: 0),
                                clock=lambda: case.wall, **kwargs)

    def test_immediate_renewals_then_first_verification(self):
        for cadence, change in ((5, 'restart'), (30, 'recreate'), (60, 'veth'), (60, 'ip')):
            with self.subTest(cadence=cadence, change=change), patch.object(live, 'semantic_kernel'):
                peer, tables = PeerFixture(), IngressTables()
                case = self.replay(cadence, peer, tables)
                epoch = case.c.semantic_epoch()
                enabled = dict(tables.members)
                self.assertIsNotNone(epoch)
                self.assertTrue(all(enabled.values()))
                writes, reads = len(tables.batches), peer.docker_reads
                verified = case.clock()
                writer = Mock()
                service = self.service(case, case.c, writer=writer)
                case.supervisor.heartbeat = case.cfg['limits']['heartbeatSeconds']
                case.advance(case.scheduled['leaseDeadlineMonotonic'] - case.clock()
                             - case.cfg['leaseRenewal']['renewalMarginSeconds'])
                count = 2 * len(case.c.owner.profile['resolvers']) * len(case.c.configuration['providerFlows'])
                def renew(dns_time):
                    wire = v24.v20.SocketScript(case.advance, [[(dns_time / count, v24.v20.answer)]] * count)
                    previous_end = case.scheduled['leaseDeadlineMonotonic']
                    self.assertEqual(case.renew_with_transport(wire)['reason'], 'RENEWED')
                    self.assertLess(case.clock(), previous_end)
                    self.assertTrue(case.coordination['leaseAuthorized'])
                for _ in range(12):
                    case.scheduled = case.supervisor.tick()
                    self.assertEqual(case.scheduled['waitSeconds'], 0)
                    self.assertEqual(case.c.semantic_result['outcome'], 'DEFERRED')
                    renew(5.05)
                    service.status('ACTIVE')
                    status = writer.call_args.args[1]
                    self.assertEqual(status['semanticEpoch'], epoch)
                    age = int((case.clock() - verified) * 1000)
                    self.assertEqual(status['lastSemanticVerifiedAgeMs'], age)
                    self.assertEqual(case.journal.read()['lastSemanticVerifiedAgeMs'], age)
                    self.assertEqual((tables.members, len(tables.batches), peer.docker_reads), (enabled, writes, reads))
                self.assertGreater(case.clock() - verified, cadence)
                case.scheduled = case.supervisor.tick()
                renew(.01)
                if change == 'ip':
                    peer.ip = peer.profile['destination']
                elif change == 'veth':
                    peer.index += 1
                else:
                    peer.replace(recreate=change == 'recreate')
                case.supervisor.tick()
                self.assertFalse(any(tables.batches[writes].values()))
                if change == 'ip':
                    self.assertEqual(case.c.semantic_result['outcome'], 'CLOSED')
                    self.assertFalse(any(tables.members.values()))
                    self.assertIsNone(case.c.semantic_epoch())
                    peer.ip = peer.profile['ipv4']
                    case.supervisor.tick()
                else:
                    self.assertNotEqual(case.c.semantic_epoch(), epoch)
                self.assertEqual(case.c.semantic_result['outcome'], 'VERIFIED')
                self.assertEqual(case.c.semantic_verified_age_ms(), 0)
                self.assertEqual(tables.members['bridge', 'semantic_port'], [peer.index])
                self.assertTrue(all(tables.members.values()))
                case.doCleanups()

    def test_service_restart_quiesces_retained_sets_before_first_observation(self):
        peer, tables = PeerFixture(), IngressTables()
        with patch.object(live, 'semantic_kernel'):
            previous = self.replay(peer=peer, tables=tables)
            self.assertTrue(all(tables.members.values()))
            previous.doCleanups()
            reads = peer.docker_reads
            def startup(case, coordinator):
                self.assertTrue(all(tables.members.values()))
                def after_quiesce():
                    self.assertEqual(case.coordination['state'], 'QUIESCED')
                    self.assertFalse(any(tables.members.values()))
                    self.assertIsNone(coordinator.semantic_epoch())
                    self.assertIsNone(coordinator.semantic_verified_age_ms())
                    self.assertEqual(peer.docker_reads, reads)
                    return True
                # Observe the first loop condition of the emitted Service.run.
                stop = SimpleNamespace(is_set=Mock(side_effect=after_quiesce))
                service = self.service(case, coordinator, stop=stop, writer=Mock())
                self.assertEqual(service.run(), 0)
                stop.is_set.assert_called_once()
                case.lease_states.clear()
            case = self.replay(peer=peer, tables=tables, startup=startup)
            self.assertGreater(peer.docker_reads, reads)
            self.assertEqual(case.c.semantic_result['outcome'], 'VERIFIED')
            self.assertTrue(all(tables.members.values()))
            write = case.c.write
            def check_publish(previous, following):
                if following['state'] == 'QUIESCED':
                    self.assertTrue(case.locked)
                    self.assertFalse(any(tables.members.values()))
                write(previous, following)
            with patch.object(case.c, 'write', check_publish), \
                    patch.object(case.c, 'hold_lock', wraps=case.c.hold_lock) as lock:
                case.c.quiesce()
            lock.assert_called_once()
            self.assertEqual(case.coordination['state'], 'QUIESCED')
            self.assertFalse(any(tables.members.values()))
            self.assertIsNone(case.c.semantic_epoch())

    def test_semantic_work_consumes_the_scheduled_wait(self):
        case = self.replay()
        wake = case.scheduled['wakeMonotonic']
        self.runtime_gate.reconcile.side_effect = lambda *_, **kw: case.advance(.25)
        scheduled = case.supervisor.tick()
        self.assertEqual(case.c.semantic_result, {'outcome': 'VERIFIED', 'durationMs': 250})
        self.assertAlmostEqual(case.clock() + scheduled['waitSeconds'], wake)

    def test_bootstrap_defers_at_renewal_and_at_cache_target(self):
        case = self.replay()
        calls = self.runtime_gate.reconcile.call_count
        for members in case.elements.values():
            members['1.1.1.1'] = case.clock() + case.cfg['leaseRenewal']['renewalMarginSeconds']
        row = case.supervisor.tick()
        self.assertEqual((row['state'], row['waitSeconds']), ('ACTIVE', 0))
        self.assertEqual(case.c.semantic_result, {'outcome': 'DEFERRED', 'durationMs': 0})
        self.assertEqual(self.runtime_gate.reconcile.call_count, calls)
        due = case.incident(second_ttl=30)
        case.advance(due - case.clock())
        calls = self.runtime_gate.reconcile.call_count
        row = case.supervisor.tick()
        self.assertTrue(row['cacheTarget'])
        self.assertEqual(case.c.semantic_result, {'outcome': 'DEFERRED', 'durationMs': 0})
        self.assertEqual(self.runtime_gate.reconcile.call_count, calls)

    def test_bootstrap_persists_unverified_after_unlock(self):
        case = self.replay()
        self.runtime_gate.reconcile.side_effect = TimeoutError()
        self.runtime_gate.close.side_effect = OSError()
        row = case.supervisor.tick()
        code = 'R3_SEMANTIC_CLOSE_UNVERIFIED'
        self.assertEqual((row['state'], row['reason'], row['lastIncident']['code']), ('BLOCKED', code, code))
        self.assertEqual(case.journal.read()['lastSemanticTick'], {'outcome': code, 'durationMs': 0})
        self.assertFalse(case.locked)
        self.runtime_gate.close.assert_called_once()

    def test_bootstrap_late_close_readback_blocks_scope(self):
        case = self.replay()
        policy = case.cfg['leaseRenewal']
        self.runtime_gate.reconcile.side_effect = lambda *_, **kw: case.advance(policy['semanticTickBudgetSeconds'])
        def late(_):
            self.assertTrue(case.locked)
            case.advance(policy['semanticCloseReserveSeconds'] + .005)
            return [], [], []
        self.runtime_gate.read.side_effect = late
        row = case.supervisor.tick()
        self.assertEqual((row['state'], row['reason']), ('BLOCKED', 'R3_SEMANTIC_CLOSE_UNVERIFIED'))
        sample = case.journal.read()['lastSemanticTick']
        self.assertEqual(sample['outcome'], row['reason'])
        self.assertLessEqual(sample['durationMs'], case.c.semantic_horizon * 1000)
        self.runtime_gate.close.assert_called_once()
        self.assertFalse(case.locked)

    def test_compose_and_startup_charge_the_close_reserve(self):
        case = self.replay()
        inputs, old, result = fixture()
        files = dict(inputs['files'])
        settings = C.document(files['settings'])
        settings['supervisorLimits']['heartbeatSeconds'] = 5
        files['settings'] = C.canonical(settings)
        policy = {**case.cfg['leaseRenewal'], 'semanticTickBudgetSeconds': 2.5,
                  'semanticCloseReserveSeconds': .4, 'lockWaitSeconds': 4}
        files['leaseRenewal'] = C.canonical(policy)
        def compose():
            return C.compose({**inputs, 'files': files}, 25, sequence=25, supersedes=C.sha(old['authorization']))
        compose()  # 19 + 2.5 + .4 + .05 <= 22
        policy['semanticCloseReserveSeconds'] = .5
        files['leaseRenewal'] = C.canonical(policy)
        with self.assertRaisesRegex(C.A.OperationDenied, 'BUDGET_INCOMPATIBLE'):
            compose()
        docs = result['documents']
        verified = {p: docs[PREFIX + 'source/' + p] for p in case.cfg['sourceHashes']}
        cfg = {**case.cfg, 'limits': settings['supervisorLimits'], 'leaseRenewal': policy}
        with self.assertRaisesRegex(case.sup.Denied, 'BUDGET_INCOMPATIBLE'):
            case.sup.runtime(SimpleNamespace(value=cfg, custody=lambda: verified))

    def test_c_requires_same_admitted_epoch_and_nft_members(self):
        from tools.semantic_provider_c import probe
        peer = PeerFixture()
        with patch.object(live, 'semantic_kernel'):
            epoch = peer.observe()
        context = {'spec': {'profile': peer.profile, 'table': 'fixture', 'commands': {}}, 'nft': {},
                   'epochHash': live.semantic_digest(epoch), 'footprint': 'approved'}
        addr = [peer.profile['ipv4']]
        for admitted, port, changed, permitted in [
                (context['epochHash'], peer.index, False, True),
                (context['epochHash'], peer.index, True, False),
                ('0' * 64, peer.index, False, False),
                (context['epochHash'], peer.index + 1, False, False)]:
            later = {**epoch, 'endpointId': '0' * 64} if changed else epoch
            with self.subTest(port=port, changed=changed, admitted=admitted), \
                    patch.object(live, 'semantic_observe', side_effect=[(epoch, peer.row), (later, peer.row)]), \
                    patch.object(live.SemanticGate, 'read', return_value=([port], addr, addr)):
                if permitted:
                    self.assertEqual(probe.current_semantic(context), (epoch, peer.row))
                else:
                    with self.assertRaisesRegex(probe.I.A.OperationDenied, 'IDENTITY_DRIFT'):
                        probe.current_semantic({**context, 'epochHash': admitted})

    def test_sealed_supervisor_reads_current_driver_under_lock(self):
        inputs, _, result = fixture()
        cfg = C.document(result['documents'][PREFIX + 'supervisor/configuration.json'])
        sup = C.contract_module(result['documents'][PREFIX + 'source/' + C.SUPERVISOR], 'supervisor25')
        ingress = cfg['semanticIngress']
        self.assertEqual(ingress['profile'], C.document(inputs['files']['semanticProfile']))
        gate = Mock(table=ingress['table'], profile=ingress['profile'], epoch=None)
        coord = SimpleNamespace(hold_until=Mock(return_value=nullcontext()), publish=Mock(), semantic_horizon=2.55,
                                journal=Mock(return_value=dict(state='LEASE_READY', leaseAuthorized=True)))
        snapshot = dict(containerId=ingress['containerId'], epoch=7, generation={'pid': 10, 'startTicks': 20})
        guards = SimpleNamespace(scope_guard=Mock(return_value={'southbound': snapshot}), current=Mock(
            return_value={**snapshot, 'state': 'STARTED', 'driverHash': 'a' * 64}))
        policy = {'tableName': gate.table, 'flows': [{'peerIngress': {'kind': 'SEMANTIC_PROFILE',
                                                                      'declaration': gate.profile}}]}
        read = Mock(return_value=C.canonical({'profile': {'policy': policy, 'expectedFootprint': 'f' * 64}}))
        with patch.object(sup, 'SemanticGate', return_value=gate):
            sup.bind_semantic_gate(cfg, coord, guards, read, phase=virtual_phase)
        def tick():
            coord.semantic_tick(time.monotonic() + 5, time.monotonic() + 30, coord.journal.return_value)
        tick()
        self.assertEqual(gate.reconcile.call_args.args, ('f' * 64,))
        self.assertEqual(read.call_args.args[1], 'a' * 64)
        self.assertIn('/epochs/7/driver.json', read.call_args.args[0].as_posix())
        guards.current.return_value['epoch'] += 1
        def empty_set(binding, argv, data=None, *, deadline):
            family, table, name = argv[-3:]
            return C.canonical({'nftables': [{'set': {'family': family, 'table': table, 'name': name}}]})
        with patch.object(sup, 'semantic_command', empty_set), self.assertRaises(ValueError):
            tick()
        self.assertIsNone(gate.epoch)

    def test_offline_input_manifest_promotes_only_approved_profile_and_source(self):
        cli = v24.v20.V12.F.load('scripts/prepare-semantic-provider-r3-v25-inputs.py', 'inputs25')
        index = {'schema': 'ouf.semantic-provider-r3-inputs.v1',
                 'files': dict.fromkeys(C.DATA_INPUTS_V24, {}), 'sources': dict.fromkeys(C.SOURCE_INPUTS_V24, {})}
        args = SimpleNamespace(mode='inputs', v24_inputs='/old', v24_inputs_sha256='a' * 64,
                               profile='/approved', profile_sha256='b' * 64, source_sha256='c' * 64,
                               lease_renewal='/timing', lease_renewal_sha256='d' * 64)
        reader = Mock()
        reader.read.return_value = C.canonical(index)
        reader.bound.side_effect = [fixture()[0]['files']['semanticProfile'], fixture()[0]['files']['leaseRenewal'],
                                    v24.fixture()[0]['files']['leaseRenewal'], b'source']
        new = cli.prepare(args, reader)
        self.assertTrue(C.input_set(new['files'], new['sources']))
        self.assertEqual(new['files']['leaseRenewal'], {'path': '/timing', 'sha256': 'd' * 64})
        self.assertEqual(new['files']['semanticProfile'], {'path': '/approved', 'sha256': 'b' * 64})
        self.assertEqual({k: new['sources'][k] for k in index['sources']}, index['sources'])


@unittest.skipUnless(os.environ.get("OUF_R3_V25_NATIVE") == "1", "requires explicit native opt-in")
class NativePortLifetime(unittest.TestCase):
    def private_worker(self, mode):
        self.assertEqual(sys.platform, "linux")
        self.assertEqual((os.geteuid(), os.getegid()), (0, 0))
        subprocess.run(["unshare", "--mount", "--net", "--propagation", "private",
                        sys.executable, "-I", "-B", str(Path(__file__).resolve()), mode],
                       check=True, timeout=60)

    def test_nft_readback_and_common_lock_do_not_pin_bridge_port(self):
        self.private_worker("--private")

    def test_automatic_replacement_drops_previously_admitted_tcp(self):
        self.private_worker("--automatic")

    def test_composed_two_family_gate_reconciles_live_port(self):
        self.private_worker("--reconcile")


def create_native_common_lock():
    # Both workers have already mounted a fresh tmpfs on /run in their namespace.
    runtime = Path('/run')
    runtime.chmod(0o700)
    directory = runtime / 'r3-v25'
    directory.mkdir(mode=0o700)
    lock = directory / 'common.lock'
    lock.touch(mode=0o600, exist_ok=False)
    return lock


def native_reconcile():
    from native_semantic_provider_r3_v13 import IdentityProof, run
    import shutil
    import socket
    proof = IdentityProof()
    try:
        # configure() independently requires private network and mount namespaces.
        with patch.dict(os.environ, OUF_R3_V13_NATIVE='1'):
            proof.configure()
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                               'tools/semantic_cohort_admission/cohort-draft/tools'))
        from semantic_provider_lease_coordination import hold_common_lock
        lock = create_native_common_lock()
        result = fixture()[2]
        with backend.I.module_scope():
            backend.load_modules(result, version=25)
            policy = backend.backend_policy(result, socket.if_nametoindex('v-southbound'), version=25)
            rules = sys.modules['tools.materialize_semantic_shared_faces'].materialize(policy)['nftRules']
            footprint = sys.modules['tools.semantic_provider_preexec_native'].footprint
        profile, = [f['peerIngress']['declaration'] for f in policy['flows'] if f['purpose'] == 'WORKLOAD_GATEWAY']
        def nft(argv, raw=None):
            return run('nft', *argv, raw=raw.decode() if raw else None)
        commands = {'socket': '/fixture', 'docker': 'fixture'}
        for binary in ('ip', 'nsenter', 'nft'):
            path = Path(shutil.which(binary)).resolve(strict=True)
            commands[binary] = {'path': str(path), 'sha256': C.sha(path.read_bytes())}
        live.semantic_kernel_probe(commands['ip'])
        peer = PeerFixture()
        def engine_or_native(binding, argv):
            if binding == 'fixture':
                return C.canonical([peer.net if 'network' in argv else peer.row])
            return live.semantic_command(binding, argv)
        def task():
            proc = proof.start('semantic', "import sys; print('READY', flush=True); sys.stdin.read()")
            assert proof.line(proc) == 'READY'
            peer.row['State']['Pid'] = proc.pid
            return proc
        proc = task()
        def observe():
            return live.semantic_observe(profile, commands, engine_or_native)[0]
        table = policy['tableName']
        def owner_and_gate():
            gate = live.SemanticGate(table, profile, nft, observe)
            def link(p, _, generation, bounded):
                return live.semantic_link(p, commands, generation, bounded)
            owner = TickFixture(gate, time.monotonic, live.semantic_phase, link, commands['nft'])
            @contextmanager
            def common_lock(end):
                with hold_common_lock(lock), owner.lock(end):
                    yield
            owner.c.hold_until = common_lock
            return owner, gate
        owner, gate = owner_and_gate()
        def timed_tick(label):
            started = time.monotonic()
            outcome = owner.tick()
            seconds = time.monotonic() - started
            print(f'{label} {seconds:.4f}s', flush=True)
            assert outcome == 'VERIFIED' and seconds <= owner.policy['semanticTickBudgetSeconds'] + .05
            assert not owner.locked
            return gate.epoch
        for mode, provider_running in ((0, False), (0, True), (1, False), (1, True)):
            Path('/proc/sys/net/bridge/bridge-nf-call-iptables').write_text(str(mode))
            nft(['-f', '-'], rules.encode())
            tables = {f: json.loads(nft(['-j', '-n', 'list', 'table', f, table])) for f in ('bridge', 'inet')}
            expected = footprint(tables)
            owner.expected = expected
            proof.tcp('semantic', 'southbound', profile['port'], False)
            first = timed_tick('initial')
            assert timed_tick('steady') == first
            proof.tcp('semantic', 'southbound', profile['port'], True)
            if not provider_running:
                gate.close()
                for family in tables:
                    nft(['delete', 'table', family, table])
            proc.stdin.close()
            assert proc.wait(timeout=3) == 0
            run('ip', 'link', 'del', 'v-semantic')
            run('ip', 'netns', 'del', 'semantic')
            run('ip', 'netns', 'add', 'semantic')
            peer.replace(recreate=bool(mode))
            run('ip', 'link', 'add', 'v-semantic', 'type', 'veth', 'peer', 'name', 'n-semantic')
            run('ip', 'link', 'set', 'n-semantic', 'netns', 'semantic')
            run('ip', 'link', 'set', 'v-semantic', 'master', profile['bridge'])
            run('ip', 'link', 'set', 'v-semantic', 'up')
            run('ip', '-n', 'semantic', 'link', 'set', 'n-semantic', 'name', 'eth0')
            run('ip', '-n', 'semantic', 'addr', 'add', profile['ipv4'] + '/24', 'dev', 'eth0')
            run('ip', '-n', 'semantic', 'link', 'set', 'eth0', 'up')
            run('ip', '-n', 'southbound', 'neigh', 'flush', 'all')
            proc = task()
            assert observe()['binding']['hostIfindex'] > first['binding']['hostIfindex']
            if not provider_running:
                nft(['-f', '-'], rules.encode())
                owner, gate = owner_and_gate()
                owner.expected = expected
            proof.tcp('semantic', 'southbound', profile['port'], False)
            successor = timed_tick('veth-replaced')
            assert (successor['containerId'] != first['containerId']) == bool(mode)
            proof.tcp('semantic', 'southbound', profile['port'], True)
            if mode and provider_running:
                for family in tables:
                    obj, = [r['set'] for r in tables[family]['nftables']
                            if r.get('set', {}).get('name') == 'semantic_open']
                    assert not obj.get('flags') and 'timeout' not in obj
                addr = [profile['ipv4']]
                admitted = ([successor['binding']['hostIfindex']], addr, addr)
                end = time.monotonic() + owner.lease_seconds
                for _ in range(3):
                    now = time.monotonic()
                    assert now < end
                    owner.c.semantic_tick(now, end, owner.lease)
                    assert owner.c.semantic_result['outcome'] == 'DEFERRED'
                    pending = {**owner.lease, 'state': 'LEASE_UPDATING'}
                    ready = dict(owner.lease)
                    with owner.c.hold_until(time.monotonic() + owner.c.semantic_horizon):
                        owner.c.publish(owner.lease, pending)
                        owner.c.publish(pending, ready)
                        end = time.monotonic() + owner.lease_seconds
                    assert gate.read(expected) == admitted
                with owner.c.hold_until(time.monotonic() + owner.c.semantic_horizon):
                    owner.c.publish(owner.lease, {'state': 'QUIESCED', 'leaseAuthorized': False})
                assert gate.read(expected) == ([], [], [])
            gate.close()
            proof.tcp('semantic', 'southbound', profile['port'], False)
            for family in tables:
                nft(['delete', 'table', family, table])
    finally:
        proof.close()


def private_probe(mode):
    # Follow the native v13 fixture: every mutable resource lives in private
    # network/mount namespaces. No service, Docker socket or host table access.
    if os.environ.get("OUF_R3_V25_NATIVE") != "1" or sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("native opt-in and Linux root required")
    for kind in ("mnt", "net"):
        if os.path.samefile("/proc/self/ns/" + kind, "/proc/1/ns/" + kind):
            raise RuntimeError("private namespaces required")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                           "tools/semantic_cohort_admission/cohort-draft/tools"))
    from semantic_provider_lease_coordination import hold_common_lock

    def run(*argv, **options):
        return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=5, **options).stdout

    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run")
    Path("/run/netns").mkdir()
    lock = create_native_common_lock()
    run("ip", "netns", "add", "workload")
    run("ip", "link", "add", "fixture-br", "type", "bridge")

    def attach(*options):
        run("ip", "link", "add", "name", "fixture-port", *options, "type", "veth",
            "peer", "name", "fixture-nic")
        run("ip", "link", "set", "fixture-nic", "netns", "workload")
        run("ip", "link", "set", "fixture-port", "master", "fixture-br")

    def observation(fd):
        host, = json.loads(run("ip", "-j", "link", "show", "dev", "fixture-port"))
        peer, = json.loads(run("nsenter", f"--net=/proc/self/fd/{fd}", "ip", "-j", "link",
                               "show", "dev", "fixture-nic", pass_fds=(fd,)))
        assert host["master"] == "fixture-br"
        assert host["link_index"] == peer["ifindex"] and peer["link_index"] == host["ifindex"]
        return host["ifindex"], peer["ifindex"], os.fstat(fd).st_ino

    def read_closed_pair():
        pair = {}
        for family in ("bridge", "inet"):
            rows = json.loads(run("nft", "-j", "-n", "list", "table", family, "test_scope"))["nftables"]
            chain, = [r["chain"] for r in rows if "chain" in r]
            assert (chain["family"], chain["hook"], chain["policy"]) == (family, "forward", "drop")
            rules = [r["rule"] for r in rows if "rule" in r]
            assert len(rules) == int(family == "bridge") and all(r["expr"][-1] == {"drop": None} for r in rules)
            pair[family] = [r for r in rows if "metainfo" not in r]
        return pair

    attach()
    fd = os.open("/run/netns/workload", os.O_RDONLY | os.O_CLOEXEC)
    try:
        with hold_common_lock(lock):
            first = observation(fd)
            assert observation(fd) == first
            if mode == "--automatic":
                automatic_replacement(run, attach, lambda: observation(fd))
                return
            # Both families stay deny-only for the entire control experiment.
            run("nft", "-f", "-", input=f"""
table bridge test_scope {{
 chain guard {{ type filter hook forward priority 0; policy drop;
   meta iif {first[0]} drop
 }}
}}
table inet test_scope {{
 chain guard {{ type filter hook forward priority 0; policy drop; }}
}}
""")
            before = read_closed_pair()
            run("ip", "link", "del", "dev", "fixture-port")
            assert all(row["ifname"] != "fixture-port" for row in json.loads(run("ip", "-j", "link", "show")))
            attach("index", str(first[0]))
            current = observation(fd)
            assert current[0] == first[0] and current[2] == first[2]
            assert read_closed_pair() == before
    finally:
        os.close(fd)


def automatic_replacement(run, attach, observe):
    """Exercise the fixed iif predicate with a working flow in two private netns."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from native_semantic_lease_kernel_v2 import CLIENT, Proof

    sender, receiver = "192.0.2.1", "192.0.2.2"
    port = 10443
    run("ip", "link", "set", "fixture-br", "up")
    run("ip", "netns", "add", "sink")
    run("ip", "link", "add", "sink-port", "type", "veth", "peer", "name", "sink-nic")
    run("ip", "link", "set", "sink-nic", "netns", "sink")
    run("ip", "link", "set", "sink-port", "master", "fixture-br")
    run("ip", "link", "set", "sink-port", "up")
    run("ip", "-n", "sink", "addr", "add", receiver + "/24", "dev", "sink-nic")
    run("ip", "-n", "sink", "link", "set", "sink-nic", "up")

    def enable_sender():
        run("ip", "link", "set", "fixture-port", "up")
        run("ip", "-n", "workload", "addr", "add", sender + "/24", "dev", "fixture-nic")
        run("ip", "-n", "workload", "link", "set", "fixture-nic", "up")

    proof = Proof()
    def request(expected):
        child = proof.start("workload", CLIENT, sender, receiver, str(port))
        assert proof.line(child) == expected
        if expected == "CONNECTED":
            proof.echo(child, "R-002", "ECHO")
        child.stdin.close()
        assert child.wait(timeout=3) == 0

    try:
        enable_sender()
        original, _, namespace = observe()
        run("nft", "-f", "-", input=f"""
table bridge test_binding {{
 chain forward {{
  type filter hook forward priority 0; policy accept;
  meta iif {original} ip saddr {sender} ip daddr {receiver} tcp dport {port} ct state {{ new, established }} counter accept
  ip daddr {receiver} tcp dport {port} counter drop
 }}
}}
""")
        proof.server("sink", receiver, port)
        request("CONNECTED")
        previous = original
        for _ in range(3):
            run("ip", "link", "del", "fixture-port")
            attach()
            current, _, same_namespace = observe()
            assert current > previous and same_namespace == namespace
            previous = current
        enable_sender()
        request("DROP")
        rows = json.loads(run("nft", "-j", "list", "chain", "bridge", "test_binding", "forward"))["nftables"]
        accept, drop = (row["rule"]["expr"] for row in rows if "rule" in row)
        for expr, verdict in ((accept, "accept"), (drop, "drop")):
            assert expr[-1] == {verdict: None}
            assert any(item.get("counter", {}).get("packets", 0) > 0 for item in expr)
    finally:
        proof.close()


if __name__ == "__main__":
    if sys.argv[1:] == ['--reconcile'] and os.environ.get('OUF_R3_V25_NATIVE') == '1':
        native_reconcile()
    elif sys.argv[1:] in (["--private"], ["--automatic"]):
        private_probe(sys.argv[1])
    else:
        unittest.main()
