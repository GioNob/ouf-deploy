"""D-051 portable: frozen historical bytes, declared MAC flow and live denials."""
import copy
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import types
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
from r3_sealed_inputs import sealed_legacy_inputs
import test_semantic_provider_r3_v12 as V12
from tools.semantic_provider_r3 import compose as C, install_common as I, upgrade as U
from tools.semantic_provider_r3 import identity_provider_v13 as P, read_identity_provider_v13 as R


def fixture():
    inputs, old, _, _ = V12.fixture()
    previous = V12.composed(inputs, old)
    inputs['sources'] = {p: V12.blob(p) for p in C.SOURCE_INPUTS_V13}
    files = inputs['files']
    peer = {'containerId': 'c' * 64, 'containerName': 'fixture-caddy', 'network': 'fixture-backend',
        'networkId': 'd' * 64, 'bridge': 'br-backend', 'ipv4': '172.18.0.4', 'mac': '02:42:ac:12:00:04',
        'alias': 'fixture0.invalid', 'aliases': ['fixture-caddy', 'fixture0.invalid'], 'port': 443,
        'dockerBinding': {'path': '/usr/bin/docker', 'sha256': '5' * 64}, 'dockerSocket': '/run/docker.sock'}
    identity = {'schema': 'ouf.semantic-identity-provider-peer.v1', 'peer': peer,
        'southbound': {'containerId': C.document(files['southbound/context'])['containerId'], 'ipv4': '172.18.0.14',
                      'network': peer['network'], 'networkId': peer['networkId'], 'bridge': peer['bridge']},
        'observationHashes': dict.fromkeys(('identityProvider', 'southbound', 'network'), '6' * 64)}
    files['identityProviderPeer'] = C.canonical(identity)
    return inputs, previous


def composed(inputs, previous):
    return C.compose(inputs, 13, sequence=13, supersedes=C.sha(previous['authorization']))


def live(peer):
    return {'Id': peer['containerId'], 'Name': '/' + peer['containerName'], 'Running': True,
            'Networks': {peer['network']: {'NetworkID': peer['networkId'], 'IPAddress': peer['ipv4'],
                         'MacAddress': peer['mac'], 'Aliases': peer['aliases']}}}


def network(peer):
    return {'Id': peer['networkId'], 'Name': peer['network'], 'Driver': 'bridge',
            'Options': {'com.docker.network.bridge.name': peer['bridge']}}


def load_modules(result, version=13):
    """Load the real closed broker source package in its real dependency order."""
    prefix = f'versions/{version}/'
    cfg = C.document(result['documents'][prefix + 'broker/southbound.json'])
    config_path = '/broker/config.json'
    disk = {cfg['sourceRoot'] + '/' + p: result['documents'][prefix + 'source/' + p]
            for p in cfg['sourceHashes']}
    disk[config_path] = C.canonical(cfg)
    class PrivateRoot(PurePosixPath):
        def lstat(self):
            return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
    if sys.platform != 'linux': sys.modules.setdefault('fcntl', types.ModuleType('fcntl'))
    with patch.object(C.B, 'Path', PrivateRoot), patch.object(C.B, 'private', side_effect=lambda p: disk[str(p)]):
        C.B.load(config_path)


def backend_policy(result, own_ifindex=11, semantic_ifindex=12, interface='v-southbound', bridge='br-backend',
                   version=13):
    """Actual composed backend face; the other faces remain in the role table."""
    t = C.document(result['documents'][f'versions/{version}/documents/southbound/transport.json'])
    attachments = []
    for i, nic in enumerate(t['networkBindings']):
        a = {k: nic[k] for k in ('bridge', 'mac', 'ipv4', 'workloadRef', 'bindingRef')}
        a.update(interface=interface if nic['bindingRef'] == 'southbound-backend' else 'v-face' + str(i),
                 ifindex=own_ifindex if nic['bindingRef'] == 'southbound-backend' else 1000 + i,
                 mac='02:00:00:00:02:02' if nic['bindingRef'] == 'southbound-backend' else '02:00:00:00:01:0' + str(i))
        if nic['bindingRef'] == 'southbound-backend': a['bridge'] = bridge
        attachments.append(a)
    flows = copy.deepcopy(t['transport'])
    for f in flows:
        if f['peerIngress']['kind'] == 'CREATED_CANDIDATE':
            f['peerIngress'] = {'kind': 'BRIDGE_PORT', 'ifindex': 2000}
        elif f['peerIngress']['kind'] == 'BRIDGE_PORT':
            if semantic_ifindex is not None:
                f['peerIngress']['ifindex'] = semantic_ifindex
        else:
            f['peerIngress']['declaration']['bridge'] = bridge
    guarded = [n for n in t['networkBindings'] if 'leaseGuard' in n]
    policy = {'schema': 'ouf.semantic-shared-faces.v2', 'tableName': t['tableName'],
              'attachments': attachments, 'flows': flows,
              'globalLeaseGuard': {**guarded[0]['leaseGuard'], 'bridges': sorted({n['bridge'] for n in guarded})}}
    return policy


class Composition(unittest.TestCase):
    def test_independent_issuer_must_be_unique_and_https(self):
        inputs, old = fixture()
        owner = C.document(inputs['files']['coordinator'])
        candidate = C.document(inputs['files']['southbound/historicalTemplate'])['candidate']
        self.assertEqual(P.issuer_endpoint(owner['kernel'], candidate), ('fixture0.invalid', 443))
        kernel = copy.deepcopy(owner['kernel'])
        kernel['providerFlows'].append(copy.deepcopy(kernel['providerFlows'][0]))
        with self.assertRaisesRegex(ValueError, 'ISSUER_AMBIGUOUS'): P.issuer_endpoint(kernel, candidate)
        kernel['providerFlows'] = []
        with self.assertRaisesRegex(ValueError, 'ISSUER_AMBIGUOUS'): P.issuer_endpoint(kernel, candidate)
        kernel['providerFlows'] = [dict(owner['kernel']['providerFlows'][0], endpoint='http://fixture0.invalid')]
        with self.assertRaisesRegex(ValueError, 'ISSUER_REQUIRED'): P.issuer_endpoint(kernel, candidate)

    def test_v13_requires_closed_input_pair_and_exact_source_anchors(self):
        inputs, old = fixture()
        inputs['files'].pop('identityProviderPeer')
        self.assertFalse(C.input_set(inputs['files'], inputs['sources']))
        with self.assertRaisesRegex(RuntimeError, 'EXACT_R3_INPUT_SET_REQUIRED'): composed(inputs, old)
        inputs, old = fixture()
        path = C.SOURCE_MAP['tools/materialize_semantic_shared_faces.py']
        inputs['sources'][path] = inputs['sources'][path].replace(b"        fields(peer, ('kind', 'ifindex'))", b'        pass')
        with self.assertRaisesRegex(RuntimeError, 'R3_V13_SOURCE_CONTRACT_DRIFT'): composed(inputs, old)

    def test_real_role_materializer_mac_arp_tuple_and_mirrors(self):
        inputs, old = fixture(); result = composed(inputs, old)
        with I.module_scope():
            load_modules(result)
            faces = sys.modules['tools.materialize_semantic_shared_faces']
            admission = sys.modules['tools.semantic_provider_deployment_admission']
            policy = backend_policy(result)
            rules = faces.materialize(policy)['nftRules']
            self.assertIn('ether daddr 02:42:ac:12:00:04 ip saddr 172.18.0.14 ip daddr 172.18.0.4 tcp dport 443 ct state { new, established }', rules)
            self.assertIn('ether saddr 02:42:ac:12:00:04 ip saddr 172.18.0.4 ip daddr 172.18.0.14 tcp sport 443 ct state established', rules)
            self.assertIn('arp saddr ether 02:42:ac:12:00:04 arp daddr ether 02:00:00:00:02:02', rules)
            self.assertIn('ip saddr 172.18.0.6 ip daddr 172.18.0.14 tcp dport 10443', rules)
            # Neither the native template nor its mirror set asks for an IdP veth index.
            hosts = [{'ifindex': a['ifindex'], 'ifname': a['interface']} for a in policy['attachments']]
            hosts += [{'ifindex': 12, 'ifname': 'v-semantic'}, {'ifindex': 2000, 'ifname': 'v-adapter'}]
            mirrors = admission.mirrors({'policy': policy}, hosts)
            self.assertEqual(len(mirrors), len(policy['attachments']) + 2)
            self.assertNotIn('IDENTITY_PROVIDER_MAC', rules)

    def test_frozen_v1_v12_input_and_output_bytes(self):
        golden = json.loads(V12.blob('tests/fixtures/r3-v1-v12-pre-v13-hashes.json'))
        for version in range(1, 13):
            with self.subTest(version=version), sealed_legacy_inputs(V12):
                if version == 12:
                    x, old, _, _ = V12.fixture()
                    r = V12.composed(x, old)
                else:
                    r = C.compose(V12.F.fixture(version), version,
                        **({} if version == 1 else dict(sequence=version, supersedes='a' * 64)))
                self.assertEqual({k: r[k] for k in ('hashes', 'inputHashes')}, golden[str(version)])

    def test_frozen_v13_v14_input_and_output_bytes(self):
        # Recorded at b16113055d4c before the v15 composition changes.
        golden = {
            13: ('bca8a3fbb335c5e49c00f9b4af6a3a530afae5c52ec2dec29b010148d71f6a31',
                 '1a88811ef19b4c6485700bfbb1970afffa1a8ad079ce36db367dc3519333be37',
                 'd2af995334a42fb314ff94d8ae22010dd45aa7c760987cc1145de4f95bc8321e',
                 '66f045ebcbc086bf658c5681f1db239a4bfc150fd091c119f3207718af9f298b'),
            14: ('ac151373ea2181aa95c7af6909d826061fceb9fd72470d592ee6f92a9845f6e4',
                 '1a88811ef19b4c6485700bfbb1970afffa1a8ad079ce36db367dc3519333be37',
                 'd2af995334a42fb314ff94d8ae22010dd45aa7c760987cc1145de4f95bc8321e',
                 'ea87a0e4779aed3e411a8d14cdd22baeda035afcdf65b7148c35a776951015a3'),
        }
        with sealed_legacy_inputs(V12):
            inputs, previous = fixture()
        for version, expected in golden.items():
            with self.subTest(version=version):
                result = C.compose(inputs, version, sequence=version, supersedes=C.sha(previous['authorization']))
                self.assertEqual(tuple(C.sha(C.canonical(result[key]))
                                       for key in ('hashes', 'inputHashes', 'audit', 'layout')), expected)

    def test_v13_closure_one_flow_and_normal_upgrade(self):
        inputs, previous = fixture()
        before = copy.deepcopy(inputs)
        result = composed(inputs, previous)
        self.assertEqual(inputs, before)
        self.assertEqual(result, composed(inputs, previous))
        self.assertTrue(C.input_set(inputs['files'], inputs['sources']))
        self.assertEqual(C.DATA_INPUTS_V13, C.DATA_INPUTS_V12 | {'identityProviderPeer'})
        for role in C.ROLES:
            def transport(r, v):
                return C.document(r['documents'][f'versions/{v}/documents/{role}/transport.json'])
            new, old = transport(result, 13), transport(previous, 12)
            self.assertEqual(new['networkBindings'], old['networkBindings'])
            self.assertEqual(new['transport'][:len(old['transport'])], old['transport'])
            self.assertEqual(len(new['transport']) - len(old['transport']), int(role == 'southbound'))
            if role == 'southbound':
                self.assertEqual(new['transport'][-1]['peerIngress']['kind'], P.IDENTITY_KIND)
                self.assertNotIn('ifindex', new['transport'][-1]['peerIngress'])
        old_sup = C.document(previous['documents']['versions/12/supervisor/configuration.json'])
        new_sup = C.document(result['documents']['versions/13/supervisor/configuration.json'])
        U.shared_state(13, old_sup, new_sup, inputs['files'], C.document(previous['authorization']))
        self.assertEqual(old_sup['coordinator']['ownerConfiguration'], new_sup['coordinator']['ownerConfiguration'])
        for target in (C.KERNEL_V1, 'tools/materialize_southbound_kernel.py'):
            self.assertEqual(result['documents']['versions/13/source/' + target],
                             previous['documents']['versions/12/source/' + target])
        issuer = V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v13_issuer')
        head = {'sequence': 12, 'decision': 'OPERATE', 'sha256': C.sha(previous['authorization']),
                'authorization': C.document(previous['authorization'])}
        self.assertEqual(issuer.compose_next(inputs, head, head['authorization']['issuedAt']), result)
        with I.module_scope():
            load_modules(result)
            for path, raw in result['documents'].items():
                if path.endswith('.py'):
                    compile(raw, path, 'exec')

    def test_alias_port_and_shared_network_denials(self):
        for field, value, reason in (
            ('alias', 'other.invalid', 'ISSUER_DRIFT'), ('port', 444, 'ISSUER_DRIFT'),
            ('bridge', 'br-unshared', 'NETWORK_NOT_SHARED'),
            ('network', 'unshared', 'NETWORK_NOT_SHARED'), ('networkId', 'f' * 64, 'NETWORK_NOT_SHARED')):
            inputs, old = fixture()
            d = C.document(inputs['files']['identityProviderPeer'])
            d['peer'][field] = value
            if field == 'alias': d['peer']['aliases'] = sorted([value, 'fixture-caddy'])
            inputs['files']['identityProviderPeer'] = C.canonical(d)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, reason): composed(inputs, old)
        inputs, old = fixture()
        d = C.document(inputs['files']['identityProviderPeer'])
        d['southbound']['ipv4'] = '172.18.0.99'
        inputs['files']['identityProviderPeer'] = C.canonical(d)
        with self.assertRaisesRegex(ValueError, 'NETWORK_NOT_SHARED'): composed(inputs, old)



class LiveAdmission(unittest.TestCase):
    def test_reader_binds_executable_before_after_and_pins_api_without_context(self):
        binding = {'path': '/usr/bin/docker', 'sha256': 'a' * 64}
        def execute(argv, **kw):
            self.assertEqual(argv, ['/verified/docker', 'inspect', 'fixture'])
            self.assertEqual(kw['env'], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                        'LC_ALL': 'C', 'DOCKER_API_VERSION': '1.44'})
            self.assertEqual(kw['stdin'], R.subprocess.DEVNULL)
            self.assertEqual(kw['stderr'], R.subprocess.DEVNULL)
            kw['stdout'].write(b'public')
            return types.SimpleNamespace(returncode=0)
        with patch.object(I.V, 'executable_hash', return_value='/verified/docker') as program, \
             patch.object(R.subprocess, 'run', side_effect=execute):
            self.assertEqual(R.bound_docker(binding, ['inspect', 'fixture'], 131072), b'public')
        self.assertEqual(program.call_args_list, [unittest.mock.call(binding['path'], binding['sha256'])] * 2)

    def test_ip_mac_alias_network_name_and_state_live_denials(self):
        inputs, old = fixture()
        result = composed(inputs, old)
        peer = C.document(inputs['files']['identityProviderPeer'])['peer']
        with I.module_scope():
            load_modules(result)
            peers = sys.modules['tools.semantic_provider_peer_bindings']
            flow = C.document(result['documents']['versions/13/documents/southbound/transport.json'])['transport'][-1]
            for changed, value in (('IPAddress', '172.18.0.99'), ('MacAddress', '02:42:ac:12:00:99'),
                                   ('Aliases', ['other.invalid']), ('NetworkID', 'f' * 64)):
                row = live(peer); row['Networks'][peer['network']][changed] = value
                run = Mock(return_value=C.canonical(row))
                with self.subTest(field=changed), self.assertRaisesRegex(ValueError, 'LIVE_DRIFT'):
                    peers.verify_identity_flows([flow], run)
                self.assertEqual(run.call_count, 1)
            for changed, value in (('Id', 'f' * 64), ('Name', '/other'), ('Running', False), ('Networks', {})):
                row = live(peer); row[changed] = value
                with self.subTest(field=changed), self.assertRaisesRegex(ValueError, 'LIVE_DRIFT'):
                    peers.verify_identity_flows([flow], Mock(return_value=C.canonical(row)))
            calls = []
            def run(binding, argv, limit):
                calls.append(argv)
                self.assertEqual(binding, peer['dockerBinding'])
                return C.canonical(network(peer) if 'network' in argv else live(peer))
            peers.verify_identity_flows([flow], run)
            self.assertEqual(len(calls), 4)
            self.assertTrue(all('inspect' in a and '--format' in a for a in calls))
            self.assertTrue(all('ifindex' not in a for a in calls))

    def test_real_driver_rechecks_identity_before_peer_collection(self):
        inputs, old = fixture(); result = composed(inputs, old)
        policy = C.document(result['documents']['versions/13/documents/southbound/transport.json'])
        raw = result['documents']['versions/13/source/tools/semantic_provider_admission_v2/driver_v7.py']
        with I.module_scope(), patch.dict(sys.modules, {'fcntl': types.ModuleType('fcntl')}):
            load_modules(result)
            driver = types.ModuleType('tools.semantic_provider_admission_v2.v13_test_driver')
            driver.__package__ = 'tools.semantic_provider_admission_v2'
            exec(compile(raw, '<sealed-v13-driver>', 'exec'), driver.__dict__)
            peers = sys.modules['tools.semantic_provider_peer_bindings']
            bad = live(policy['transport'][-1]['peerIngress']['declaration'])
            bad['Networks']['fixture-backend']['IPAddress'] = '172.18.0.77'
            value = {'peerBinding': {'declaredPolicy': policy}, 'profile': {'containerId': 'a' * 64}}
            with patch.object(peers, 'collect') as collect, self.assertRaisesRegex(ValueError, 'LIVE_DRIFT'):
                driver.verify_peers(value, C.sha(C.canonical(policy)), Mock(), Mock(return_value=C.canonical(bad)))
            collect.assert_not_called()

    def test_reader_only_formatted_inspect_stable_hashes_and_existing_recipe(self):
        inputs, old = fixture()
        d = C.document(inputs['files']['identityProviderPeer']); peer = d['peer']
        owner = C.document(inputs['files']['coordinator'])
        template = C.document(inputs['files']['southbound/historicalTemplate'])
        args = types.SimpleNamespace(coordinator='owner', coordinator_sha256='1' * 64,
            historical_template='template', historical_template_sha256='2' * 64,
            docker=peer['dockerBinding']['path'],
            docker_sha256=peer['dockerBinding']['sha256'], docker_socket=peer['dockerSocket'],
            container=peer['containerName'], network=peer['network'], southbound_id=d['southbound']['containerId'])
        reader = Mock(); reader.read.side_effect = [C.canonical(owner), C.canonical(template)]
        own = live(peer); own['Id'] = args.southbound_id
        own['Networks'][args.network]['IPAddress'] = d['southbound']['ipv4']
        calls = []
        def run(binding, argv, limit):
            calls.append(argv)
            if 'network' in argv: return C.canonical(network(peer))
            return C.canonical(own if argv[-1] == args.southbound_id else live(peer))
        result = R.observe(args, reader, run)
        self.assertEqual(result['peer'], peer)
        self.assertEqual(result['observationHashes']['identityProvider'], C.sha(C.canonical(live(peer))))
        self.assertTrue(all('inspect' in a and '--format' in a for a in calls))
        reader.verify.assert_called_once_with()

    def test_v14_moves_live_identity_read_out_of_driver_only(self):
        inputs, old = fixture()
        a = C.compose(inputs, 13, sequence=13, supersedes=C.sha(old['authorization']))
        b = C.compose(inputs, 14, sequence=14, supersedes=C.sha(old['authorization']))
        da = {k.replace('versions/13/', 'versions/N/'): v for k, v in a['documents'].items()}
        db = {k.replace('versions/14/', 'versions/N/'): v for k, v in b['documents'].items()}
        self.assertEqual(set(da), set(db))
        drv = 'versions/N/source/tools/semantic_provider_admission_v2/driver_v7.py'
        prep = 'versions/N/source/tools/semantic_provider_admission_v2/preparer_v2.py'
        # Only the driver source and the documents carrying source hashes or the version root.
        self.assertEqual({k for k in da if da[k] != db[k]},
                         {drv, 'versions/N/broker/adapter.json', 'versions/N/broker/southbound.json',
                          'versions/N/runtime-configuration.json', 'versions/N/supervisor/configuration.json'})
        call = (b'    from tools.semantic_provider_peer_bindings import verify_identity_flows\n'
                b'    verify_identity_flows(policy["transport"], run)\n')
        self.assertEqual(da[drv].count(call), 1)
        self.assertEqual(da[drv].replace(call, b''), db[drv])
        self.assertNotIn(b'verify_identity_flows', db[drv])
        self.assertEqual(da[prep], db[prep])
        self.assertEqual(db[prep].count(b'verify_identity_flows(candidate["transport"]'), 1)
        # Same declared flow and nft-bound identity in both versions.
        for r in (a, b):
            v = next(k for k in r['documents'] if k.endswith('documents/southbound/transport.json'))
            self.assertEqual(C.document(r['documents'][v])['transport'][-1]['peerIngress']['kind'],
                             'IDENTITY_PROVIDER_MAC')

    def test_reader_denial_reports_only_public_code(self):
        import io
        argv = ['reader'] + [x for f in ('docker', 'docker-sha256', 'docker-socket', 'container', 'network',
                'southbound-id', 'coordinator', 'coordinator-sha256', 'historical-template',
                'historical-template-sha256') for x in ('--' + f, 'x')]
        for exc, expected in ((P.Denied('R3_IDENTITY_PROVIDER_LIVE_DRIFT'),
                               'R3_IDENTITY_PROVIDER_READ_DENIED R3_IDENTITY_PROVIDER_LIVE_DRIFT\n'),
                              (KeyError('/secret/path value'), 'R3_IDENTITY_PROVIDER_READ_DENIED\n')):
            err = io.StringIO()
            with patch.object(sys, 'argv', argv), patch.object(sys, 'stderr', err), \
                    patch.object(R, 'observe', side_effect=exc), patch.object(R.P, 'identity_require'):
                self.assertEqual(R.main(), 1)
            self.assertEqual(err.getvalue(), expected)

    def test_reader_source_from_bound_template_stopped_or_matching_live(self):
        inputs, old = fixture()
        d = C.document(inputs['files']['identityProviderPeer']); peer = d['peer']
        owner = C.document(inputs['files']['coordinator'])
        template = C.document(inputs['files']['southbound/historicalTemplate'])
        args = types.SimpleNamespace(coordinator='owner', coordinator_sha256='1' * 64,
            historical_template='template', historical_template_sha256='2' * 64,
            docker=peer['dockerBinding']['path'],
            docker_sha256=peer['dockerBinding']['sha256'], docker_socket=peer['dockerSocket'],
            container=peer['containerName'], network=peer['network'], southbound_id=d['southbound']['containerId'])
        def attempt(running, address):
            reader = Mock(); reader.read.side_effect = [C.canonical(owner), C.canonical(template)]
            own = live(peer); own['Id'] = args.southbound_id; own['Running'] = running
            own['Networks'][args.network]['IPAddress'] = address
            def run(binding, argv, limit):
                if 'network' in argv: return C.canonical(network(peer))
                return C.canonical(own if argv[-1] == args.southbound_id else live(peer))
            return R.observe(args, reader, run)
        stopped = attempt(False, '')
        self.assertEqual(stopped['southbound']['ipv4'], d['southbound']['ipv4'])
        self.assertEqual(stopped['peer'], peer)
        for running, address in ((True, '172.18.0.77'), (True, ''), (False, '172.18.0.77')):
            with self.assertRaisesRegex(ValueError, 'R3_IDENTITY_PROVIDER_SOUTHBOUND_DRIFT'):
                attempt(running, address)


if __name__ == '__main__': unittest.main()
