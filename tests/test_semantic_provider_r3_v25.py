"""R-002 admission, ordinary upgrade and comparison with a reauthorized v24."""
from contextlib import nullcontext
from functools import lru_cache
import json
import os
from pathlib import Path
import subprocess
import sys
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


@lru_cache(maxsize=1)
def fixture():
    inputs, _, old = v24.fixture()
    profile = dict(role='semantic', containerName='semantic-fixture', image='sha256:' + 'a' * 64,
                   direction='semantic-to-southbound')
    network = C.document(inputs['files']['identityProviderPeer'])['southbound']
    flow = C.document(inputs['files']['semanticPeer'])['proposedIngress']
    profile.update({k: network[k] for k in ('network', 'networkId', 'bridge')},
                   ipv4=flow['sourceIpv4'], destination=flow['destinationIpv4'],
                   protocol=flow['protocol'], port=flow['destinationPort'])
    profile['configurationSha256'] = live.semantic_configuration(docker_row(profile))
    inputs = {'sources': {**inputs['sources'], C.SEMANTIC_IDENTITY:
                         (Path(__file__).resolve().parents[1] / C.SEMANTIC_IDENTITY).read_bytes()},
              'files': {**inputs['files'], 'semanticProfile': C.canonical(profile)}}
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
        cid = self.row['Id']
        self.net = {'Name': p['network'], 'Id': p['networkId'], 'Driver': 'bridge',
                    'Options': {'com.docker.network.bridge.name': p['bridge']},
                    'Containers': {cid: {'Name': p['containerName'], 'IPv4Address': p['ipv4'] + '/24',
                                         'EndpointID': 'e' * 64}}}

    def observe(self):
        p = self.profile
        def run(binding, args):
            if 'container' in args:
                row = self.row
            elif 'network' in args:
                row = self.net
            elif 'addr' in args:
                row = {'link_index': self.index, 'ifindex': 2, 'linkinfo': {'info_kind': 'veth'},
                       'addr_info': [{'family': 'inet', 'local': p['ipv4']}]}
            else:
                row = {'link_index': 2, 'ifindex': self.index, 'ifname': 'testport',
                       'master': p['bridge'], 'linkinfo': {'info_kind': 'veth'}}
            return json.dumps([row]).encode()
        commands = {k: {'path': '/' + k} for k in ('docker', 'ip', 'nsenter')}
        gen = lambda pid: dict(pid=pid, startTicks=pid * 2, namespaceDevice=1, namespaceInode=pid + 2)
        with patch.object(live.socket, 'if_indextoname', return_value='testport'):
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
        self.gate = live.SemanticGate('fixture', self.peer.profile, None, self.peer.observe)
        self.gate.write = self.write
        self.gate.read = lambda footprint: self.state
        self.gate.observe = self.peer.observe
        before = self.gate.reconcile('template')
        if not running:
            self.gate.close()
        self.peer.replace(recreate)
        self.assertNotIn(self.peer.index, self.state[0])
        current = self.gate.reconcile('template')
        self.assertEqual(self.state[0], [self.peer.index])
        self.assertEqual(current['profileSha256'], before['profileSha256'])
        self.assertNotEqual(before['generation'], current['generation'])
        self.assertEqual(before['containerId'] == current['containerId'], not recreate)

    def test_tick_denials_and_recovery(self):
        for case in ('image', 'configuration', 'rename', 'ip', 'two-generations', 'bridge', 'kernel'):
            with self.subTest(case=case):
                self.peer = PeerFixture()
                self.gate.observe = self.peer.observe
                self.gate.reconcile('template')
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
                with self.assertRaises(ValueError):
                    self.gate.reconcile('template')
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
            with self.assertRaises(ValueError):
                self.gate.reconcile('template')
            self.assertEqual(self.state, ([], [], []))
            self.assertEqual(self.gate.reconcile('template')['binding']['hostIfindex'], self.peer.index)

    def test_readback_failure_closes_both_families(self):
        self.gate.read = Mock(side_effect=[([], [], []), ([self.peer.index], [], []), OSError()])
        with self.assertRaises(OSError):
            self.gate.reconcile('template')
        self.assertEqual(self.state, ([], [], []))

    def test_changed_generation_cannot_reuse_or_regress_index(self):
        self.gate.reconcile('template')
        self.peer.replace(True)
        for index in (27, 26):
            self.peer.index = index
            with self.assertRaisesRegex(ValueError, 'NONMONOTONE'):
                self.gate.reconcile('template')
            self.assertEqual(self.state, ([], [], []))


class Kernel(unittest.TestCase):
    def test_atomic_enable_preserves_staged_device(self):
        nft = Mock()
        gate = live.SemanticGate('fixture', PeerFixture().profile, nft, None)
        gate.write(27)
        gate.write(27, True)
        stage, enable = [call.args[1].decode() for call in nft.call_args_list]
        self.assertIn('add element bridge fixture semantic_port { 27 }', stage)
        self.assertNotIn('semantic_port', enable)
        self.assertEqual(enable.count('add element'), 2)
        for family in ('bridge', 'inet'):
            self.assertIn(f'flush set {family} fixture semantic_open', stage)
            self.assertIn(f'add element {family} fixture semantic_open', enable)

    def test_qualified_kernel(self):
        live.semantic_kernel('Linux', '6.12.0-3-amd64')
        for system, release in [('Linux', '6.5.9'), ('Windows', '10.0'), ('Linux', 'unknown')]:
            with self.assertRaisesRegex(ValueError, 'MONOTONE'):
                live.semantic_kernel(system, release)


class Consumers(unittest.TestCase):
    def test_v24_dns_cache_rollover_on_v25_bootstrap(self):
        # The lease fixture has synthetic provider epochs, clock and nft. Keep
        # the production v25 tick and publication callbacks in the replay.
        case = v24.Renewal('test_incident_25_26_next_tick_and_rollover')
        case.inputs, _, case.result = fixture()
        case.retained = v24.v20.V12.fixture()[2]
        def runtime(sup, configuration):
            gate = Mock(epoch=None)
            cfg = configuration.value
            spec = cfg['semanticIngress']
            gate.table, gate.profile = spec['table'], spec['profile']
            policy = {'tableName': gate.table, 'flows': [{'peerIngress': {
                'kind': 'SEMANTIC_PROFILE', 'declaration': gate.profile}}]}
            raw = C.canonical({'profile': {'policy': policy, 'expectedFootprint': 'c' * 64}})
            bind = sup.bind_semantic_gate
            generation = {'pid': 7, 'startTicks': 7}
            row = {'epoch': 9, 'containerId': spec['containerId'], 'generation': generation,
                   'state': 'STARTED', 'driverHash': C.sha(raw)}
            def synthetic(cfg, coordinator, guards, read):
                bind(cfg, coordinator, SimpleNamespace(scope_guard=lambda: {'southbound': row},
                     current=lambda *args: row), lambda path, digest: raw)
            with patch.object(sup, 'bind_semantic_gate', synthetic), patch.object(sup, 'SemanticGate', return_value=gate):
                owner = sup.runtime(configuration)
            sup.semantic_command = Mock(return_value=b'{"nftables":[]}')
            self.runtime_gate = gate
            return owner
        case.native_runtime = runtime
        try:
            case.setUp()
            case.test_incident_25_26_next_tick_and_rollover()
            self.assertGreater(self.runtime_gate.reconcile.call_count, 1)
        finally:
            case.doCleanups()

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
        coord = SimpleNamespace(hold_lock=Mock(side_effect=nullcontext), publish=Mock(),
                                journal=Mock(return_value=dict(state='LEASE_READY', leaseAuthorized=True)))
        snapshot = dict(containerId=ingress['containerId'], epoch=7, generation={'pid': 10, 'startTicks': 20})
        guards = SimpleNamespace(scope_guard=Mock(return_value={'southbound': snapshot}), current=Mock(
            return_value={**snapshot, 'state': 'STARTED', 'driverHash': 'a' * 64}))
        policy = {'tableName': gate.table, 'flows': [{'peerIngress': {'kind': 'SEMANTIC_PROFILE',
                                                                      'declaration': gate.profile}}]}
        read = Mock(return_value=C.canonical({'profile': {'policy': policy, 'expectedFootprint': 'f' * 64}}))
        with patch.object(sup, 'SemanticGate', return_value=gate):
            sup.bind_semantic_gate(cfg, coord, guards, read)
        coord.semantic_tick()
        gate.reconcile.assert_called_once_with('f' * 64)
        self.assertEqual(read.call_args.args[1], 'a' * 64)
        self.assertIn('/epochs/7/driver.json', read.call_args.args[0].as_posix())
        guards.current.return_value['epoch'] += 1
        with self.assertRaises(ValueError):
            coord.semantic_tick()
        gate.close.assert_called_once()

    def test_offline_input_manifest_promotes_only_approved_profile_and_source(self):
        cli = v24.v20.V12.F.load('scripts/prepare-semantic-provider-r3-v25-inputs.py', 'inputs25')
        index = {'schema': 'ouf.semantic-provider-r3-inputs.v1',
                 'files': dict.fromkeys(C.DATA_INPUTS_V24, {}), 'sources': dict.fromkeys(C.SOURCE_INPUTS_V24, {})}
        args = SimpleNamespace(mode='inputs', v24_inputs='/old', v24_inputs_sha256='a' * 64,
                               profile='/approved', profile_sha256='b' * 64, source_sha256='c' * 64)
        reader = Mock()
        reader.read.return_value = C.canonical(index)
        reader.bound.side_effect = [fixture()[0]['files']['semanticProfile'], b'source']
        new = cli.prepare(args, reader)
        self.assertTrue(C.input_set(new['files'], new['sources']))
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


def native_reconcile():
    from native_semantic_provider_r3_v13 import IdentityProof, run
    import shutil
    import socket
    proof = IdentityProof()
    try:
        # configure() independently requires private network and mount namespaces.
        with patch.dict(os.environ, OUF_R3_V13_NATIVE='1'):
            proof.configure()
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
        for binary in ('ip', 'nsenter'):
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
        gate = live.SemanticGate(table, profile, nft, observe)
        for mode, provider_running in ((0, False), (0, True), (1, False), (1, True)):
            Path('/proc/sys/net/bridge/bridge-nf-call-iptables').write_text(str(mode))
            nft(['-f', '-'], rules.encode())
            tables = {f: json.loads(nft(['-j', '-n', 'list', 'table', f, table])) for f in ('bridge', 'inet')}
            expected = footprint(tables)
            proof.tcp('semantic', 'southbound', profile['port'], False)
            first = gate.reconcile(expected)
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
                gate = live.SemanticGate(table, profile, nft, observe)
            proof.tcp('semantic', 'southbound', profile['port'], False)
            successor = gate.reconcile(expected)
            assert (successor['containerId'] != first['containerId']) == bool(mode)
            proof.tcp('semantic', 'southbound', profile['port'], True)
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
    lock = Path("/run/test-common.lock")
    lock.touch(mode=0o600, exist_ok=False)
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
