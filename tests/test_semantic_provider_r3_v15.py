"""D-052.2 route custody, closed egress and normal versioned upgrade."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_semantic_provider_r3_v13 as V13
from tools.semantic_provider_r3 import compose as C, egress_v15 as E, operate as O, upgrade as U
from tools.semantic_provider_r3 import read_routes_v15 as R
from tools.semantic_provider_routes import routes


ROUTE = '/fixture/apisix.yaml'
CERT = '/fixture/server.crt'
HOST = 'fixture-adapter.invalid'
OTHER = 'other-adapter.invalid'
SYNTHETIC_KEY = '-----BEGIN PRIVATE KEY----- fixture-only'


def put(files, key, value):
    files[key] = C.canonical(value) + b'\n'


def route_bytes():
    upstream = {'scheme': 'https', 'nodes': {'172.21.0.3:9443': 1}, 'upstream_host': HOST, 'pass_host': 'rewrite'}
    oidc = {'discovery': 'https://fixture0.invalid/realm/.well-known/openid-configuration',
            'issuer': 'https://fixture0.invalid:443/realm', 'client_secret': 'synthetic-oidc-secret',
            'ssl_verify': True, 'bearer_only': True}
    return C.canonical({'routes': [{'uri': '/' + name, 'methods': ['GET'], 'upstream': upstream,
                                    'plugins': {'openid-connect': oidc}} for name in ('search', 'fetch')],
                        'ssls': [{'cert': 'synthetic-ssl-certificate', 'key': SYNTHETIC_KEY}]}) + b'\n' + routes.TRAILER


def source(path, target, digest):
    return dict(source=str(path), target=target, sha256=digest, readOnly=True,
                uid=636, gid=636, mode=0o600, maxBytes=131072)


def fixture():
    inputs, old = V13.fixture()
    files = inputs['files']
    route = source(ROUTE, E.ROUTE_TARGET, C.sha(b'old routes'))
    cert = source(CERT, '/run/adapter/server.crt', C.sha(b'fixture certificate'))
    acceptance = C.document(files['acceptance'])

    def compile_recipe(role, template, launch):
        context = C.document(files[role + '/context'])
        put(files, role + '/template', template)
        put(files, role + '/launch', launch)
        put(files, role + '/policy', C.compile_policy(template, launch, context))
        for part in ('template', 'launch', 'policy'):
            acceptance['roles'][role]['recipe'][part]['sha256'] = C.sha(files[role + '/' + part])

    for role, entry in (('adapter', cert), ('southbound', route)):
        template = C.document(files[role + '/template'])
        launch = C.document(files[role + '/launch'])
        template['expectedOci']['mounts'].append(dict(type='bind', source=entry['source'],
                                                      destination=entry['target'], options=['ro']))
        launch['manifest']['mounts'].append({key: entry[key] for key in ('source', 'target', 'readOnly')})
        launch['sources'].append(entry)
        compile_recipe(role, template, launch)
    files['acceptance'] = C.ACCEPT.build_acceptance(**(acceptance | {'generation': 5}))
    v14 = C.compose(inputs, 14, sequence=14, supersedes=C.sha(old['authorization']))
    route['sha256'] = C.sha(route_bytes())
    compile_recipe('southbound', template, launch)
    files['acceptance'] = C.ACCEPT.build_acceptance(**(acceptance | {'generation': 6}))
    projection = routes.project(ROUTE, route_bytes())
    projection['adapterTlsIdentity'] = {'certificateSha256': cert['sha256'], 'dnsNames': [HOST]}
    put(files, E.ROUTE_INPUT, projection)
    inputs['sources'].update({p: V13.V12.blob(p) for p in C.SOURCE_INPUTS_V15 - C.SOURCE_INPUTS_V13})
    return inputs, v14


class Composition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs, cls.previous = fixture()

    def compose(self, inputs):
        return C.compose(inputs, 15, sequence=15, supersedes=C.sha(self.previous['authorization']))

    def test_new_exact_input_pair_and_normal_upgrade(self):
        files, sources = self.inputs['files'], self.inputs['sources']
        self.assertEqual(C.DATA_INPUTS_V15, C.DATA_INPUTS_V13 | {E.ROUTE_INPUT})
        self.assertTrue(C.input_set(files, sources))
        for key in C.SOURCE_INPUTS_V15 - C.SOURCE_INPUTS_V13:
            self.assertFalse(C.input_set(files, {k: v for k, v in sources.items() if k != key}))
        without_projection = {k: v for k, v in files.items() if k != E.ROUTE_INPUT}
        self.assertFalse(C.input_set(without_projection, sources))
        with self.assertRaisesRegex(RuntimeError, 'EXACT_R3_INPUT_SET_REQUIRED'):
            self.compose(dict(files=without_projection, sources=sources))
        result = self.compose(self.inputs)
        self.assertEqual(result, self.compose(self.inputs))
        self.assertEqual(result['inputHashes'][E.ROUTE_INPUT], C.sha(files[E.ROUTE_INPUT]))

        old, new = (C.document(r['authorization']) for r in (self.previous, result))
        head = {'sequence': 14, 'sha256': C.sha(self.previous['authorization']), 'decision': 'OPERATE', 'authorization': old}
        issuer = V13.V12.F.load('scripts/issue-semantic-provider-operation-authorization.py', 'v15_issuer')
        self.assertEqual(issuer.compose_next(self.inputs, head, new['issuedAt']), result)
        new_head = dict(head, sequence=15, sha256=C.sha(result['authorization']), authorization=new)
        self.assertTrue(U.I.payload_match(result, new_head, result['authorization'])['payloadByteMatch'])

        before = self.previous['documents']; after = result['documents']

        def pair(path):
            return (C.document(before['versions/14/' + path]), C.document(after['versions/15/' + path]))

        old_cfg, new_cfg = pair('runtime-configuration.json')
        self.assertEqual(old_cfg['candidates'], new_cfg['candidates'])
        self.assertEqual(old['lease'], new['lease'])
        old_sup, new_sup = pair('supervisor/configuration.json')
        U.shared_state(15, old_sup, new_sup, files, old)
        for role in C.ROLES:
            base = 'documents/' + role + '/'
            for name in ('transport.json', 'rootfs-seal.json', 'preparer-template.json'):
                self.assertEqual(*pair(base + name))
            old_policy, new_policy = pair(base + 'frame-policy.json')
            self.assertEqual(old_policy['expectedOci'], new_policy['expectedOci'])
            self.assertEqual(old_policy != new_policy, role == 'southbound')
        self.assertEqual(C.document(files['acceptance'])['generation'], 6)
        self.assertNotEqual(old['acceptanceSha256'], new['acceptanceSha256'])
        terminal = dict(state='DELETED', authorizationSha256=head['sha256'],
                        configurationHash=old['runtimeConfigurationSha256'])
        runtime = SimpleNamespace(read=lambda path: self.previous['authorization'] if path.name == '14.json' else b'')
        O.terminal_binding(runtime, new_cfg, new_head, terminal)

    def test_projection_denials(self):
        def node(value):
            return lambda p: p['routes'][0]['upstream'].update(nodes={value: 1})

        def extra_route(p):
            route = copy.deepcopy(p['routes'][0])
            route['uri'] = '/unbound'
            route['upstream']['nodes'] = {'192.0.2.15:9443': 1}
            p['routes'].append(route)

        def different_valid_hosts(p):
            p['adapterTlsIdentity']['dnsNames'].append(OTHER)
            p['routes'][1]['upstream']['upstream_host'] = OTHER

        for name, code, change in (
            ('egress nic', E.UPSTREAM, node('172.22.0.3:9443')),
            ('wrong port', E.UPSTREAM, node('172.21.0.3:9444')),
            ('hostname node', E.UPSTREAM, node(HOST + ':9443')),
            ('extra route', E.MISSING, extra_route),
            ('unknown plugin', E.MISSING, lambda p: p['routes'][0].update(forward='https://other.invalid')),
            ('wrong host', E.TLS, lambda p: p['routes'][0]['upstream'].update(upstream_host=OTHER)),
            ('different names in SAN', E.TLS, different_valid_hosts),
            ('SAN without host', E.TLS, lambda p: p['adapterTlsIdentity'].update(dnsNames=[OTHER])),
            ('wrong certificate', E.TLS, lambda p: p['adapterTlsIdentity'].update(certificateSha256='0' * 64)),
            ('wrong route hash', E.CONFIG, lambda p: p.update(sha256='0' * 64)),
            ('wrong route path', E.CONFIG, lambda p: p.update(source='/fixture/different.yaml')),
            ('wrong discovery host', E.NETWORK,
             lambda p: p['routes'][0]['openid-connect']['discovery'].update(host='elsewhere.invalid')),
            ('wrong discovery port', E.NETWORK, lambda p: p['routes'][1]['openid-connect']['discovery'].update(port=444)),
            ('wrong issuer port', E.NETWORK, lambda p: p['routes'][1]['openid-connect']['issuer'].update(port=444)),
        ):
            inputs = copy.deepcopy(self.inputs)
            projection = C.document(inputs['files'][E.ROUTE_INPUT])
            change(projection)
            put(inputs['files'], E.ROUTE_INPUT, projection)
            with self.subTest(name=name), self.assertRaisesRegex(C.A.OperationDenied, '^' + code + '$'):
                self.compose(inputs)

    def test_lease_guarded_internal_nic_is_the_declared_destination(self):
        # VPS 18/11: oufsp-int is lease-guarded, so the adapter internal NIC carries leaseGuard.
        inputs = copy.deepcopy(self.inputs)
        value = C.document(inputs['files']['adapter/historicalTemplate'])
        nics = [n for n in value['candidate']['networkBindings'] if n['bindingRef'] == 'adapter-internal']
        self.assertEqual(len(nics), 1)
        guard = next((n['leaseGuard'] for n in value['candidate']['networkBindings'] if 'leaseGuard' in n), None)
        if guard is not None and 'leaseGuard' not in nics[0]:
            nics[0]['leaseGuard'] = copy.deepcopy(guard)
        projection = C.document(inputs['files'][E.ROUTE_INPUT])
        south = C.document(inputs['files']['southbound/historicalTemplate'])['candidate']
        kernel = C.document(inputs['files']['coordinator'])['kernel']
        from tools.semantic_provider_r3 import identity_provider_v13 as I
        from tools.semantic_provider_routes import routes as R
        self.assertIsInstance(E.check_routes(projection, south, value['candidate'], kernel, I, R), int)

    def test_bound_flow_or_certificate_recipe_drift(self):
        def change_flows(row, code, name, path, change):
            inputs = copy.deepcopy(self.inputs)
            value = C.document(inputs['files'][name])
            field = value
            for key in path:
                field = field[key]
            change(field, row)
            put(inputs['files'], name, value)
            with self.assertRaisesRegex(C.A.OperationDenied, '^' + code + '$'):
                self.compose(inputs)

        for name, path in (('southbound/historicalTemplate', ('candidate', 'transport')),
                           ('coordinator', ('kernel', 'staticFlows'))):
            with self.subTest(name=name):
                change_flows(0, E.MISSING, name, path, lambda flows, i: flows.pop(i))
                change_flows(0, E.AMBIGUOUS, name, path, lambda flows, i: flows.append(flows[i]))
        change_flows(0, E.MISSING, 'coordinator', ('kernel', 'staticFlows'),
                     lambda flows, i: flows[i].update(port=8443))
        change_flows(-1, E.TLS, 'adapter/policy', ('sources',),
                     lambda sources, i: sources[i].update(sha256='0' * 64))


def reader_inputs(certificate, directory='/fixture'):
    raw = route_bytes()
    root = PurePosixPath(directory)
    route = source(root / 'apisix.yaml', E.ROUTE_TARGET, C.sha(raw))
    cert = source(root / 'server.crt', '/run/adapter/server.crt', C.sha(certificate))
    data = {route['source']: raw, cert['source']: certificate}
    args = SimpleNamespace(routes=route['source'], routes_sha256=route['sha256'], openssl='/usr/bin/openssl',
                           openssl_sha256='f' * 64)
    for name, entry in (('southbound_launch', route), ('southbound_policy', route), ('adapter_launch', cert)):
        recipe = C.canonical({'sources': [entry]}) + b'\n'
        filename = str(root / (name + '.json'))
        setattr(args, name, filename)
        setattr(args, name + '_sha256', C.sha(recipe))
        data[filename] = recipe
    return args, data


def generate_certificate(directory, program, sans):
    path = Path(directory)
    subprocess.run([program, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=ignored-cn.invalid', '-addext', 'subjectAltName=' + sans,
                    '-keyout', str(path / 'synthetic.key'), '-out', str(path / 'synthetic.crt')],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    return (path / 'synthetic.crt').read_bytes()


class Reader(unittest.TestCase):
    def test_real_openssl_san_and_public_projection(self):
        program = shutil.which('openssl')
        self.assertIsNotNone(program, 'OpenSSL is required for the v15 fixture')
        with tempfile.TemporaryDirectory() as directory:
            certificate = generate_certificate(directory, program, f'DNS:{OTHER},IP:192.0.2.1,DNS:{HOST},DNS:{HOST}')
        args, data = reader_inputs(certificate)
        args.openssl = program
        args.openssl_sha256 = C.sha(Path(program).read_bytes())
        reads = []

        def read(path, expected, **options):
            reads.append((path, options))
            self.assertEqual(C.sha(data[path]), expected)
            return data[path]

        with patch.object(R.custody, 'executable') as executable:
            projection = R.observe(args, read=read)
        self.assertEqual(executable.call_args_list, [unittest.mock.call(program, args.openssl_sha256)] * 2)
        self.assertEqual(reads[:5], reads[5:])
        self.assertEqual(reads[2][1], {'metadata': (636, 636, 0o600), 'limit': 131072})
        self.assertEqual(reads[4][1], {'metadata': (636, 636, 0o600), 'limit': R.CERT_LIMIT})
        self.assertEqual(projection['adapterTlsIdentity'], {'certificateSha256': C.sha(certificate), 'dnsNames': [HOST, OTHER]})
        output = C.canonical(projection)
        for secret in (SYNTHETIC_KEY, 'ssls', 'client_secret', 'synthetic-oidc-secret', 'synthetic-ssl-certificate',
                       'ignored-cn.invalid', '192.0.2.1', 'BEGIN CERTIFICATE'):
            self.assertNotIn(secret.encode(), output)

    def test_private_key_and_sha256_denied_before_openssl(self):
        args, data = reader_inputs(SYNTHETIC_KEY.encode())

        def read(path, expected, **options):
            routes.require(C.sha(data[path]) == expected, 'INPUT_SHA256_MISMATCH')
            return data[path]

        extract = Mock()
        with self.assertRaisesRegex(C.A.OperationDenied, R.PRIVATE_KEY):
            R.observe(args, read=read, extract=extract)
        data[CERT] += b' changed'
        with self.assertRaisesRegex(C.A.OperationDenied, R.CERT_READ):
            R.observe(args, read=read, extract=extract)
        for field in ('routes_sha256', 'southbound_launch_sha256', 'southbound_policy_sha256'):
            changed = SimpleNamespace(**(vars(args) | {field: 'a' * 64}))
            with self.subTest(field=field), self.assertRaisesRegex(C.A.OperationDenied, E.CONFIG):
                R.observe(changed, read=read, extract=extract)
        extract.assert_not_called()

    def test_cli_denial_does_not_print_values(self):
        err, out = io.StringIO(), io.StringIO()
        with redirect_stderr(err), redirect_stdout(out):
            self.assertEqual(R.main(['--bad-option', SYNTHETIC_KEY]), 1)
        self.assertEqual(err.getvalue(), R.ARGUMENT_INVALID + '\n')
        self.assertEqual(out.getvalue(), '')

    @unittest.skipUnless(os.environ.get('OUF_R3_V15_NATIVE') == '1', 'enable Linux root custody test explicitly')
    def test_native_root_cli(self):
        self.assertEqual((sys.platform, os.geteuid(), os.getegid()), ('linux', 0, 0))
        with tempfile.TemporaryDirectory(dir='/root') as directory:
            program = '/usr/bin/openssl'
            args, data = reader_inputs(generate_certificate(directory, program, f'DNS:{HOST}'), directory)
            args.openssl_sha256 = C.sha(Path(program).read_bytes())
            for path, raw in data.items():
                Path(path).write_bytes(raw)
                os.chmod(path, 0o600)
                if not path.endswith('.json'):
                    os.chown(path, 636, 636)
            command = [sys.executable, '-I', '-B', str(Path(R.__file__))]
            for flag in R.ARGUMENTS:
                command += ['--' + flag, getattr(args, flag.replace('-', '_'))]
            result = subprocess.run(command, capture_output=True, check=True, timeout=15)
            projection = C.document(result.stdout)
            self.assertEqual(result.stdout, C.canonical(projection) + b'\n')
            self.assertEqual(result.stderr, b'')
            self.assertEqual(projection['adapterTlsIdentity']['dnsNames'], [HOST])
            self.assertNotIn(SYNTHETIC_KEY.encode(), result.stdout)
            os.chmod(args.routes, 0o644)
            denied = subprocess.run(command, capture_output=True, timeout=15)
            self.assertEqual((denied.returncode, denied.stdout, denied.stderr), (1, b'', E.CONFIG.encode() + b'\n'))
