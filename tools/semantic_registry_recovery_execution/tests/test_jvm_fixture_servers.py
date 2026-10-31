"""Real loopback TLS, confidential grants and HTTP forwarding; no Registry JVM."""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import urlencode

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jvm_fixture_inputs as inputs
import jvm_fixture_servers as servers


def certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    certfile, keyfile = directory / 'tls.pem', directory / 'tls-key.pem'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    keyfile.chmod(0o600)
    return certfile, keyfile


def exchange(connection, method, path, body=None, headers=None):
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def decode(segment):
    return base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4))


class TlsIamFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.certfile, self.keyfile = certificate(Path(self.temp.name))
        self.clock = [int(time.time())]
        self.app = servers.IamApplication(signing_key=self.signing_key,
            client_secret='DISPOSABLE_FIXTURE_SECRET', clock=lambda: self.clock[0])
        self.server = servers.make_tls_server(('127.0.0.1', 0), self.certfile, self.keyfile, self.app)
        self.enterContext(servers.running(self.server))
        self.context = ssl.create_default_context(cafile=str(self.certfile))

    def request(self, method, path, fields=None, bearer=None):
        headers = {}
        body = None
        if fields is not None:
            body = urlencode(fields)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if bearer is not None:
            headers['Authorization'] = 'Bearer ' + bearer
        result = exchange(http.client.HTTPSConnection('127.0.0.1', self.server.server_port,
            context=self.context, timeout=2), method, path, body, headers)
        return result[0], json.loads(result[2])

    def fields(self, **extra):
        return {'client_id': 'fixture-client', 'client_secret': 'DISPOSABLE_FIXTURE_SECRET', **extra}

    def grant(self):
        code, result = self.request('POST', self.app.issuer_path + servers.TOKEN_SUFFIX,
            self.fields(grant_type='client_credentials', scope='authorization.bundle.read'))
        self.assertEqual(code, 200)
        return result['access_token']

    def introspect(self, token):
        return self.request('POST', self.app.issuer_path + servers.TOKEN_SUFFIX + '/introspect',
                            self.fields(token=token, token_type_hint='access_token'))

    def test_real_tls_discovery_signed_grant_introspection_and_policy_share_exact_owner(self):
        code, discovery = self.request('GET', self.app.issuer_path + '/.well-known/openid-configuration')
        self.assertEqual(code, 200)
        self.assertEqual(discovery['issuer'], self.app.issuer)
        self.assertEqual(discovery['token_endpoint'], self.app.token_endpoint)
        self.assertEqual(discovery['introspection_endpoint'], self.app.introspection_endpoint)
        code, jwks = self.request('GET', self.app.issuer_path + '/jwks')
        self.assertEqual(code, 200)
        token = self.grant()
        head, body, signature = token.split('.')
        jwk, = jwks['keys']
        public = rsa.RSAPublicNumbers(int.from_bytes(decode(jwk['e']), 'big'),
            int.from_bytes(decode(jwk['n']), 'big')).public_key()
        public.verify(decode(signature), (head + '.' + body).encode(), padding.PKCS1v15(), hashes.SHA256())
        code, active = self.introspect(token)
        self.assertEqual(code, 200)
        self.assertTrue(active.pop('active'))
        self.assertEqual(active, json.loads(decode(body)))
        profile = self.app.profile_values(('127.0.0.1',))
        self.assertEqual(active['client_id'], profile['client_id'])
        self.assertEqual(active['sub'], profile['subject_id'])
        self.assertEqual(active['tenant_id'], profile['tenant_id'])
        self.assertEqual(active['aud'], profile['audience'])
        self.assertEqual(active['scope'], 'authorization.bundle.read')
        code, envelope = self.request('GET', self.app.active_path, bearer=token)
        self.assertEqual(code, 200)
        self.assertEqual(hashlib.sha256(inputs.compact(envelope['bundle'])).hexdigest(), envelope['contentHash'])
        self.clock[0] += 1
        self.assertEqual(self.request('GET', self.app.active_path, bearer=token), (200, envelope))
        self.assertEqual(self.app.grant_count, 1)
        diagnostics = json.dumps(self.app.calls)
        self.assertNotIn(token, diagnostics)
        self.assertNotIn('DISPOSABLE_FIXTURE_SECRET', diagnostics)

    def test_wrong_client_scope_duplicate_parameters_never_issue_a_grant(self):
        path = self.app.issuer_path + servers.TOKEN_SUFFIX
        for fields, status in ((self.fields(grant_type='client_credentials', scope='privileged.write'), 400),
                ({**self.fields(grant_type='client_credentials', scope='authorization.bundle.read'),
                    'client_secret': 'wrong'}, 401),
                ({**self.fields(grant_type='password', scope='authorization.bundle.read')}, 400)):
            self.assertEqual(self.request('POST', path, fields)[0], status)
        duplicate = list(self.fields(grant_type='client_credentials', scope='authorization.bundle.read').items())
        duplicate.append(('client_id', 'other-client'))
        self.assertEqual(self.request('POST', path, duplicate)[0], 400)
        self.assertEqual(self.app.grant_count, 0)
        self.assertEqual(self.introspect('never-issued'), (200, {'active': False}))

    def test_revocation_expiry_and_caller_service_token_do_not_authorize_bundle_refresh(self):
        token = self.grant()
        caller_token = inputs.rs256_jwt(self.signing_key,
            inputs.service_claims(self.app.issuer, self.clock[0]))
        self.assertNotEqual(json.loads(decode(token.split('.')[1]))['client_id'], inputs.SERVICE_CLIENT)
        self.assertEqual(self.request('GET', self.app.active_path, bearer=caller_token)[0], 401)
        self.app.revoke(token)
        self.assertEqual(self.introspect(token), (200, {'active': False}))
        self.assertEqual(self.request('GET', self.app.active_path, bearer=token)[0], 401)
        later = self.grant()
        self.clock[0] += self.app.token_seconds
        self.assertEqual(self.introspect(later), (200, {'active': False}))
        self.assertEqual(self.request('GET', self.app.active_path, bearer=later)[0], 401)

    def test_untrusted_ca_and_wrong_tls_hostname_fail_before_application_dispatch(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            exchange(http.client.HTTPSConnection('127.0.0.1', self.server.server_port,
                context=ssl.create_default_context(), timeout=2), 'GET', self.app.issuer_path + '/jwks')
        raw = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2)
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.context.wrap_socket(raw, server_hostname='wrong.disposable.test')
        finally:
            raw.close()
        self.assertEqual(self.app.calls, [])
        self.assertEqual(self.app.grant_count, 0)

    def test_concurrent_valid_grants_have_distinct_tokens_and_exact_count(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            tokens = list(pool.map(lambda _: self.grant(), range(8)))
        self.assertEqual(len(set(tokens)), 8)
        self.assertEqual(self.app.grant_count, 8)
        self.assertTrue(all(self.introspect(token)[1]['active'] for token in tokens))


class UpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        state = self.server.state
        with state['lock']:
            state['requests'].append((self.path, self.headers.get('Authorization'),
                                      self.headers.get('X-Correlation-ID')))
        if state.get('disconnect'):
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if state.get('delay'):
            time.sleep(state['delay'])
        body = state['body']
        self.send_response(state['status'])
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        if state['status'] == 302:
            self.send_header('Location', '/must-not-follow')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class GatewayFixtureTest(unittest.TestCase):
    def upstream(self, port=0):
        server = ThreadingHTTPServer(('127.0.0.1', port), UpstreamHandler)
        server.daemon_threads = True
        server.state = {'status': 200, 'body': b'{"source":"actual-loopback-upstream"}',
                        'requests': [], 'lock': threading.Lock()}
        return server

    def gateway(self, upstream_port, timeout=1):
        routes = {'semantic': {'id': 'semantic', 'uri': '/api/semantic/v1/references:resolve',
                              'upstream': {'nodes': {'127.0.0.1:' + str(upstream_port): 1}}}}
        self.app = servers.GatewayApplication('http://127.0.0.1:' + str(upstream_port), routes,
                                              'DISPOSABLE_ADMIN_KEY', timeout=timeout)
        self.admin, self.data = servers.make_gateway_servers(('127.0.0.1', 0), ('127.0.0.1', 0), self.app)
        self.enterContext(servers.running(self.admin, self.data))

    def get(self, port, path, headers=None):
        return exchange(http.client.HTTPConnection('127.0.0.1', port, timeout=2), 'GET', path, headers=headers)

    def test_query_authorization_and_status_body_are_forwarded_without_success_substitution(self):
        upstream = self.upstream()
        self.enterContext(servers.running(upstream))
        self.gateway(upstream.server_port)
        path = inputs.resolve_path()
        headers = {'Authorization': 'Bearer DISPOSABLE_CALLER', 'X-Correlation-ID': 'disposable-correlation'}
        for status in (200, 401, 403, 404, 503, 302):
            upstream.state['status'] = status
            upstream.state['body'] = inputs.compact({'actual_upstream_status': status})
            observed, response_headers, body = self.get(self.data.server_port, path, headers)
            self.assertEqual(observed, status)
            self.assertEqual(body, upstream.state['body'])
            self.assertEqual(upstream.state['requests'][-1], (path, headers['Authorization'], 'disposable-correlation'))
            if status == 302:
                self.assertEqual(response_headers['Location'], '/must-not-follow')
        self.assertEqual(len(upstream.state['requests']), 6)
        self.assertEqual(len(self.app.upstream_requests), 6)

    def test_same_gateway_changes_from_actual_connection_502_to_actual_upstream_200(self):
        closed = self.upstream()
        port = closed.server_port
        closed.server_close()
        self.gateway(port)
        status, _, body = self.get(self.data.server_port, inputs.resolve_path())
        self.assertEqual(status, 502)
        self.assertEqual(json.loads(body)['error'], 'fixture_upstream_connect_failed')
        self.assertEqual(self.app.upstream_requests, [])
        restarted = self.upstream(port)
        self.enterContext(servers.running(restarted))
        status, _, body = self.get(self.data.server_port, inputs.resolve_path())
        self.assertEqual((status, body), (200, restarted.state['body']))
        self.assertEqual(len(restarted.state['requests']), 1)

    def test_admin_key_is_required_and_nonsemantic_paths_never_reach_upstream(self):
        upstream = self.upstream()
        self.enterContext(servers.running(upstream))
        self.gateway(upstream.server_port)
        self.assertEqual(self.get(self.admin.server_port, '/apisix/admin/routes')[0], 401)
        status, _, body = self.get(self.admin.server_port, '/apisix/admin/routes',
                                   {'X-API-KEY': 'DISPOSABLE_ADMIN_KEY'})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {'list': list(self.app.routes.values()), 'total': 1})
        self.assertEqual(self.get(self.data.server_port, '/unapproved')[0], 404)
        self.assertEqual(upstream.state['requests'], [])

    def test_connected_timeout_and_protocol_failure_are_not_mislabeled_connect_502(self):
        upstream = self.upstream()
        self.enterContext(servers.running(upstream))
        self.gateway(upstream.server_port, timeout=.05)
        upstream.state['delay'] = .2
        self.assertEqual(self.get(self.data.server_port, inputs.resolve_path())[0], 504)
        upstream.state['delay'] = 0
        upstream.state['disconnect'] = True
        self.assertEqual(self.get(self.data.server_port, inputs.resolve_path())[0], 500)
        self.assertEqual(len(self.app.upstream_requests), 2)


class FixtureCliTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def available_port(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    def launch(self, mode, config):
        path = self.root / (mode + '.json')
        path.write_bytes(inputs.compact(config))
        self.process = subprocess.Popen([sys.executable, str(Path(servers.__file__)), mode,
            '--config', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.close_process)

    def close_process(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.communicate(timeout=5)

    def ready(self, attempt):
        deadline = time.monotonic() + 5
        while True:
            try:
                return attempt()
            except (ConnectionRefusedError, ConnectionResetError):
                self.assertIsNone(self.process.poll(), 'fixture CLI terminated before serving')
                self.assertLess(time.monotonic(), deadline, 'fixture CLI did not become available')
                time.sleep(.02)

    def test_iam_cli_reads_secret_files_serves_verified_tls_and_stops_cleanly(self):
        certfile, keyfile = certificate(self.root)
        secret = self.root / 'client-secret'
        secret.write_text('DISPOSABLE_FIXTURE_SECRET')
        secret.chmod(0o400)
        port = self.available_port()
        self.launch('iam', {'bind_host': '127.0.0.1', 'tls_port': port,
            'signing_key_file': str(keyfile), 'tls_key_file': str(keyfile),
            'certificate_file': str(certfile), 'client_secret_file': str(secret)})
        context = ssl.create_default_context(cafile=str(certfile))
        status, _, body = self.ready(lambda: exchange(http.client.HTTPSConnection('127.0.0.1', port,
            context=context, timeout=1), 'GET', '/realms/fixture/.well-known/openid-configuration'))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['issuer'], 'https://127.0.0.1:' + str(port) + '/realms/fixture')
        self.process.terminate()
        out, err = self.process.communicate(timeout=5)
        self.assertEqual(self.process.returncode, 0)
        self.assertEqual((out, err), (b'', b''))

    def test_gateway_cli_uses_both_listeners_and_forwards_to_real_upstream(self):
        upstream = ThreadingHTTPServer(('127.0.0.1', 0), UpstreamHandler)
        upstream.state = {'status': 403, 'body': b'{"actual":"upstream-denial"}',
                          'requests': [], 'lock': threading.Lock()}
        self.enterContext(servers.running(upstream))
        admin_port, data_port = self.available_port(), self.available_port()
        while data_port == admin_port:
            data_port = self.available_port()
        keyfile = self.root / 'admin-key'
        keyfile.write_text('DISPOSABLE_ADMIN_KEY')
        keyfile.chmod(0o400)
        routes = {'semantic': {'id': 'semantic', 'uri': '/api/semantic/v1/references:resolve'}}
        self.launch('gateway', {'bind_host': '127.0.0.1', 'admin_port': admin_port,
            'data_port': data_port, 'admin_key_file': str(keyfile), 'routes': routes,
            'upstream_origin': 'http://127.0.0.1:' + str(upstream.server_port)})
        status, _, body = self.ready(lambda: exchange(http.client.HTTPConnection('127.0.0.1', admin_port,
            timeout=1), 'GET', '/apisix/admin/routes', headers={'X-API-KEY': 'DISPOSABLE_ADMIN_KEY'}))
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {'list': list(routes.values()), 'total': 1})
        status, _, body = exchange(http.client.HTTPConnection('127.0.0.1', data_port, timeout=1),
            'GET', inputs.resolve_path(), headers={'Authorization': 'Bearer DISPOSABLE_CALLER'})
        self.assertEqual((status, body), (403, upstream.state['body']))
        self.assertEqual(upstream.state['requests'], [(inputs.resolve_path(), 'Bearer DISPOSABLE_CALLER', None)])


if __name__ == '__main__':
    unittest.main()
