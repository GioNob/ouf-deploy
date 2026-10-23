"""Disposable TLS IAM/Authorization and forwarding Gateway fixtures.

This is test infrastructure, never an issuer or Gateway for an installation.
IAM validates its one confidential fixture client and tracks actual grants.
The Gateway forwards GETs to its fixed upstream; it never invents data-plane
success. Its admin route JSON is an APISIX-shaped fixture, not APISIX itself.
Request journals contain only method/path/status, never credentials or tokens.
"""
import argparse
from contextlib import contextmanager
import copy
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import signal
import socket
import ssl
import threading
import time
from urllib.parse import parse_qs, urlsplit
import uuid

try:
    from . import jvm_fixture_inputs as inputs
except ImportError:
    import jvm_fixture_inputs as inputs


MAX_BODY = 2 * 1024 * 1024
TOKEN_SUFFIX = '/protocol/openid-connect/token'


def _same(left, right):
    return (type(left) is str and type(right) is str
            and hmac.compare_digest(left.encode(), right.encode()))


def _origin(raw, schemes):
    parsed = urlsplit(raw)
    if (parsed.scheme not in schemes or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('invalid disposable fixture endpoint')
    _ = parsed.port
    return parsed


class IamApplication:
    """An exact fixture client, genuine RS256 grants and a frozen policy bundle."""
    def __init__(self, issuer=None, *, signing_key, client_secret,
                 client_id='fixture-client', subject_id='fixture-service-subject',
                 tenant_id='fixture-tenant', audience='fixture-audience',
                 owner_scope='authorization.bundle.read', token_seconds=300,
                 active_path='/authorization/active', clock=time.time):
        if (not all(type(v) is str and v and not any(c.isspace() for c in v)
                    for v in (client_id, subject_id, tenant_id, audience, owner_scope))
                or owner_scope != 'authorization.bundle.read'
                or type(client_secret) is not str or not client_secret
                or type(token_seconds) is not int or not 90 <= token_seconds <= 3600
                or not active_path.startswith('/') or '?' in active_path or '#' in active_path):
            raise ValueError('invalid disposable IAM binding')
        self.signing_key = signing_key
        self.jwk = inputs.public_jwk(signing_key)
        self.client_id, self.client_secret = client_id, client_secret
        self.subject_id, self.tenant_id, self.audience = subject_id, tenant_id, audience
        self.owner_scope, self.token_seconds = owner_scope, token_seconds
        self.active_path, self.clock = active_path, clock
        self.issuer = None
        self.calls, self.grant_count = [], 0
        self._issued, self._revoked = {}, set()
        self._lock = threading.RLock()
        # Same version must retain the same hash across every refresh.
        self.envelope = inputs.policy_envelope(int(clock()), valid_seconds=3600)
        if issuer is not None:
            self.bind_issuer(issuer)

    def bind_issuer(self, issuer):
        parsed = _origin(issuer, {'https'})
        if (self.issuer is not None or not parsed.path.startswith('/')
                or issuer.endswith('/') or any(c.isspace() for c in issuer)):
            raise ValueError('fixture issuer must be bound once before serving')
        self.issuer = issuer
        self.issuer_path = parsed.path
        self.token_endpoint = issuer + TOKEN_SUFFIX
        self.introspection_endpoint = self.token_endpoint + '/introspect'
        self.jwks_uri = issuer + '/jwks'

    def profile_values(self, peer_addresses):
        if self.issuer is None:
            raise ValueError('bind the fixture issuer first')
        return {'issuer': self.issuer, 'token_endpoint': self.token_endpoint,
                'introspection_endpoint': self.introspection_endpoint,
                'client_id': self.client_id, 'subject_id': self.subject_id,
                'tenant_id': self.tenant_id, 'audience': self.audience,
                'required_scopes': (self.owner_scope,), 'allowed_scopes': (self.owner_scope,),
                'peer_addresses': tuple(peer_addresses), 'minimum_remaining': 90,
                'maximum_token_seconds': 3600}

    def record(self, method, path, status):
        # Query/body/headers are intentionally excluded from diagnostics.
        with self._lock:
            self.calls.append((method, urlsplit(path).path, status))

    def revoke(self, token):
        with self._lock:
            self._revoked.add(token)

    def _active(self, token):
        with self._lock:
            value = self._issued.get(token)
            if value is None or token in self._revoked or value['exp'] <= self.clock():
                return {'active': False}
            return {'active': True, **copy.deepcopy(value)}

    def dispatch(self, method, path, headers, body):
        if self.issuer is None:
            raise ValueError('fixture issuer is unbound')
        route = urlsplit(path)
        if route.query or route.fragment:
            return 400, {'error': 'fixture_query_not_allowed'}
        if method == 'GET' and path == self.issuer_path + '/.well-known/openid-configuration':
            return 200, {'issuer': self.issuer, 'jwks_uri': self.jwks_uri,
                         'token_endpoint': self.token_endpoint,
                         'introspection_endpoint': self.introspection_endpoint,
                         'grant_types_supported': ['client_credentials'],
                         'token_endpoint_auth_methods_supported': ['client_secret_post'],
                         'id_token_signing_alg_values_supported': ['RS256']}
        if method == 'GET' and path == self.issuer_path + '/jwks':
            return 200, {'keys': [copy.deepcopy(self.jwk)]}
        if method == 'GET' and path == self.active_path:
            bearer = headers.get('Authorization', '')
            token = bearer[7:] if bearer.startswith('Bearer ') else ''
            if not self._active(token)['active']:
                return 401, {'error': 'invalid_registry_workload_token'}
            return 200, copy.deepcopy(self.envelope)
        expected = {self.issuer_path + TOKEN_SUFFIX, self.issuer_path + TOKEN_SUFFIX + '/introspect'}
        if method != 'POST' or path not in expected:
            return 404, {'error': 'fixture_endpoint_not_found'}
        if headers.get('Content-Type', '').split(';', 1)[0].strip() != 'application/x-www-form-urlencoded':
            return 415, {'error': 'fixture_form_required'}
        try:
            fields = parse_qs(body.decode('ascii'), keep_blank_values=True,
                              strict_parsing=True, max_num_fields=8)
        except (UnicodeError, ValueError):
            return 400, {'error': 'invalid_request'}
        if any(len(values) != 1 for values in fields.values()):
            return 400, {'error': 'invalid_request'}
        fields = {name: values[0] for name, values in fields.items()}
        if not (_same(fields.get('client_id'), self.client_id)
                and _same(fields.get('client_secret'), self.client_secret)):
            return 401, {'error': 'invalid_client'}
        if path.endswith('/introspect'):
            if (not {'token', 'client_id', 'client_secret'} <= set(fields)
                    or set(fields) - {'token', 'token_type_hint', 'client_id', 'client_secret'}
                    or fields.get('token_type_hint', 'access_token') != 'access_token'):
                return 400, {'error': 'invalid_request'}
            return 200, self._active(fields['token'])
        if (set(fields) != {'grant_type', 'client_id', 'client_secret', 'scope'}
                or fields['grant_type'] != 'client_credentials'
                or fields['scope'] != self.owner_scope):
            return 400, {'error': 'invalid_grant_or_scope'}
        now = int(self.clock())
        claims = {'iss': self.issuer, 'client_id': self.client_id, 'sub': self.subject_id,
                  'tenant_id': self.tenant_id, 'ouf_actor_type': 'SERVICE',
                  'aud': self.audience, 'scope': self.owner_scope, 'acr': '1',
                  'iat': now, 'exp': now + self.token_seconds, 'jti': uuid.uuid4().hex}
        token = inputs.rs256_jwt(self.signing_key, claims)
        with self._lock:
            self._issued[token] = claims
            self.grant_count += 1
        return 200, {'access_token': token, 'token_type': 'Bearer',
                     'expires_in': self.token_seconds, 'scope': self.owner_scope}


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def handle_error(self, *_):
        # A fixture transport error must not leak request or credential state.
        pass


class _Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass

    def reply(self, status, body, content_type='application/json', headers=()):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def json(self, status, value):
        self.reply(status, inputs.compact(value))

    def do_POST(self):
        self.json(405, {'error': 'fixture_method_not_allowed'})


class _IamHandler(_Handler):
    def do_GET(self):
        self.respond(b'')

    def do_POST(self):
        length = self.headers.get('Content-Length', '')
        if not length.isdigit() or not 0 <= int(length) <= 65536 or self.headers.get('Transfer-Encoding'):
            self.json(400, {'error': 'fixture_bounded_body_required'})
            return
        self.respond(self.rfile.read(int(length)))

    def respond(self, body):
        status, value = self.server.application.dispatch(self.command, self.path, self.headers, body)
        self.server.application.record(self.command, self.path, status)
        self.json(status, value)


def make_tls_server(address, certfile, keyfile, application, *,
                    public_hostname=None, issuer_path='/realms/fixture'):
    server = _Server(address, _IamHandler)
    try:
        if application.issuer is None:
            host = public_hostname or address[0]
            if ':' in host:
                host = '[' + host + ']'
            application.bind_issuer('https://' + host + ':' + str(server.server_port) + issuer_path)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile, keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.application = application
        return server
    except BaseException:
        server.server_close()
        raise


class GatewayApplication:
    """Two listeners, fixed route source and a real, bounded HTTP GET forwarder."""
    def __init__(self, upstream_origin, routes, admin_key, *, timeout=4, upstream_ca=None):
        parsed = _origin(upstream_origin, {'http', 'https'})
        if parsed.path not in ('', '/') or type(routes) is not dict or not routes or not admin_key:
            raise ValueError('invalid disposable gateway configuration')
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise ValueError('invalid disposable gateway timeout')
        self.upstream, self.routes = parsed, copy.deepcopy(routes)
        self.admin_key, self.timeout = admin_key, timeout
        self.context = ssl.create_default_context(cafile=upstream_ca) if parsed.scheme == 'https' else None
        self.calls, self.upstream_requests = [], []
        self._lock = threading.RLock()

    def record(self, method, path, status, upstream=False):
        with self._lock:
            self.calls.append((method, urlsplit(path).path, status))
            if upstream:
                self.upstream_requests.append((method, urlsplit(path).path, status))

    def connection(self):
        if self.upstream.scheme == 'https':
            return http.client.HTTPSConnection(self.upstream.hostname, self.upstream.port or 443,
                                               timeout=self.timeout, context=self.context)
        return http.client.HTTPConnection(self.upstream.hostname, self.upstream.port or 80,
                                          timeout=self.timeout)


class _AdminHandler(_Handler):
    def do_GET(self):
        app = self.server.application
        if self.path != '/apisix/admin/routes':
            status, body = 404, {'error': 'fixture_endpoint_not_found'}
        elif not _same(self.headers.get('X-API-KEY'), app.admin_key):
            status, body = 401, {'error': 'fixture_admin_key_required'}
        else:
            status, body = 200, {'list': list(copy.deepcopy(app.routes).values()), 'total': len(app.routes)}
        app.record('GET', self.path, status)
        self.json(status, body)


class _DataHandler(_Handler):
    def do_GET(self):
        app = self.server.application
        if urlsplit(self.path).path != '/api/semantic/v1/references:resolve' or not self.path.startswith('/'):
            app.record('GET', self.path, 404)
            self.json(404, {'error': 'fixture_endpoint_not_found'})
            return
        connection = app.connection()
        try:
            # Only an actual connection failure generates a synthetic 502.
            try:
                connection.connect()
            except (OSError, TimeoutError):
                app.record('GET', self.path, 502)
                self.json(502, {'error': 'fixture_upstream_connect_failed'})
                return
            headers = {'Connection': 'close'}
            for name in ('Authorization', 'Accept', 'X-Correlation-ID'):
                if self.headers.get(name) is not None:
                    headers[name] = self.headers[name]
            try:
                connection.request('GET', self.path, headers=headers)
                response = connection.getresponse()
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise ValueError('bounded fixture response required')
            except (socket.timeout, TimeoutError):
                app.record('GET', self.path, 504, upstream=True)
                self.json(504, {'error': 'fixture_upstream_timeout'})
                return
            except (OSError, http.client.HTTPException, ValueError):
                app.record('GET', self.path, 500, upstream=True)
                self.json(500, {'error': 'fixture_upstream_io_failed'})
                return
            # No redirects, fallback body, success translation or retry.
            forwarded = [(name, value) for name, value in response.getheaders()
                         if name.lower() in {'location', 'cache-control', 'retry-after', 'www-authenticate'}]
            app.record('GET', self.path, response.status, upstream=True)
            self.reply(response.status, body, response.getheader('Content-Type', 'application/octet-stream'), forwarded)
        finally:
            connection.close()


def make_gateway_servers(admin_address, data_address, application):
    admin = _Server(admin_address, _AdminHandler)
    try:
        data = _Server(data_address, _DataHandler)
    except BaseException:
        admin.server_close()
        raise
    admin.application = data.application = application
    return admin, data


@contextmanager
def running(*servers):
    """Start actual listeners and close their sockets on every exit path."""
    threads = []
    try:
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
            thread.start()
            threads.append((server, thread))
        yield servers
    finally:
        for server, _ in threads:
            server.shutdown()
        for server, thread in threads:
            thread.join(2)
            server.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('iam', 'gateway'))
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)
    config = json.loads(Path(args.config).read_bytes())
    host = config.get('bind_host', '0.0.0.0')
    if args.mode == 'iam':
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(Path(config['signing_key_file']).read_bytes(), password=None)
        app = IamApplication(config.get('issuer'), signing_key=key,
            client_secret=Path(config['client_secret_file']).read_text().strip(),
            **{name: config[name] for name in ('client_id', 'subject_id', 'tenant_id', 'audience',
                'owner_scope', 'token_seconds', 'active_path') if name in config})
        servers = (make_tls_server((host, config.get('tls_port', 8443)), config['certificate_file'],
            config['tls_key_file'], app, public_hostname=config.get('public_hostname'),
            issuer_path=config.get('issuer_path', '/realms/fixture')),)
    else:
        app = GatewayApplication(config['upstream_origin'], config['routes'],
            Path(config['admin_key_file']).read_text().strip(), timeout=config.get('timeout', 4),
            upstream_ca=config.get('upstream_ca'))
        servers = make_gateway_servers((host, config.get('admin_port', 9180)),
                                       (host, config.get('data_port', 9080)), app)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    with running(*servers):
        stop.wait()


if __name__ == '__main__':
    main()
