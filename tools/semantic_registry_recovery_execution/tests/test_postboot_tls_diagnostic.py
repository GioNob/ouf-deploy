"""Actual DNS/TLS child in a held own namespace plus exact capsule/metadata tests.

No real OUF state is available in CI; the full target diagnostic controller is
not claimed qualified. No HTTP bearer or recovery code is dispatched by tests.
"""
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'scripts/diagnose-registry-postboot-tls-20261023.py'
spec = importlib.util.spec_from_file_location('tls_diagnostic_fixture', SCRIPT)
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        self.server.http_calls += 1; self.send_response(500); self.end_headers()


class Diagnostic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(dir=ROOT); cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name); cls.cert = cls.root / 'ca.pem'; cls.key = cls.root / 'tls.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(cls.key),
            '-out', str(cls.cert), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-days', '1'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
        cls.cert.chmod(0o444); cls.key.chmod(0o600)

    def setUp(self):
        self.server = HTTPServer(('127.0.0.1', 0), Handler); self.server.http_calls = 0
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.close)
        self.origin = 'https://localhost:' + str(self.server.server_port)

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)

    def invoke(self, mode='CALLER_DNS_TLS', origin=None, ca=None):
        fd = os.open('/proc/self/ns/net', os.O_RDONLY)
        try:
            return d.run_child(mode, origin or self.origin,
                self.cert.read_bytes() if ca is None else ca, {'path': sys.executable}, fd)
        finally: os.close(fd)

    def test_actual_host_dns_sends_no_http_or_tls(self):
        value = self.invoke('HOST_DNS')
        self.assertTrue(value['resolverSucceeded']); self.assertEqual(value['phase'], 'COMPLETE')
        self.assertFalse(value['tcpConnectAttempted']); self.assertFalse(value['tlsHandshakeAttempted'])
        self.assertEqual(self.server.http_calls, 0)

    def test_actual_held_namespace_verified_tls_sends_no_http_or_bearer(self):
        value = self.invoke()
        self.assertEqual(value['status'], 'OBSERVED'); self.assertTrue(value['certificateChainVerified'])
        self.assertTrue(value['hostnameVerified']); self.assertIsNotNone(value['peerCertificateSha256'])
        self.assertEqual(self.server.http_calls, 0)
        projected = d.public_child(value)
        self.assertNotIn('peerCertificateSha256', projected); self.assertNotIn('addressSetHash', projected)
        self.assertNotIn('localhost', json.dumps(projected))

    def test_wrong_hostname_reports_numeric_certificate_code_without_raw_error(self):
        value = self.invoke(origin=self.origin.replace('localhost', '127.0.0.1'))
        self.assertEqual(value['phase'], 'TLS_HANDSHAKE')
        self.assertEqual(value['errorClass'], 'SSLCertVerificationError'); self.assertIs(type(value['verifyCode']), int)
        self.assertFalse(value['certificateChainVerified']); self.assertEqual(self.server.http_calls, 0)
        self.assertEqual(d.finding({}, value), 'CALLER_TLS_CERTIFICATE_REJECTED')
        self.assertNotIn('certificate verify failed', json.dumps(value).lower())

    def test_bad_ca_is_a_ca_load_failure_not_a_dns_failure(self):
        value = self.invoke(ca=b'NOT_A_CA')
        self.assertEqual(value['phase'], 'LOAD_CA'); self.assertEqual(d.finding({}, value), 'CALLER_CA_CONTEXT_REJECTED')
        self.assertFalse(value['tcpConnectAttempted']); self.assertFalse(value['tlsHandshakeAttempted'])

    def test_connection_refusal_is_separate_from_dns_and_tls(self):
        from socket import socket
        with socket() as holder:
            holder.bind(('127.0.0.1', 0)); port = holder.getsockname()[1]
            value = self.invoke(origin='https://localhost:' + str(port))
        self.assertTrue(value['resolverSucceeded']); self.assertEqual(value['phase'], 'TCP_CONNECT')
        self.assertEqual(value['status'], 'REJECTED'); self.assertFalse(value['tlsHandshakeAttempted'])
        self.assertIs(type(value['errno']), int); self.assertEqual(d.finding({}, value), 'CALLER_TCP_CONNECTION_FAILED')

    def test_reserved_invalid_hostname_reports_dns_stage_without_tls(self):
        value = self.invoke(origin='https://ouf-diagnostic-fixture.invalid')
        self.assertEqual(value['phase'], 'DNS_RESOLUTION'); self.assertFalse(value['resolverSucceeded'])
        self.assertIn(value['errorClass'], ('gaierror', 'TimeoutError'))
        self.assertFalse(value['tcpConnectAttempted']); self.assertFalse(value['tlsHandshakeAttempted'])
        self.assertEqual(d.finding({'resolverSucceeded': True}, value), 'CALLER_DNS_FAILED_HOST_RESOLVES')

    def test_resolver_shapes_report_only_classes_and_comparison_material_stays_private(self):
        private, public = d.resolver_shape(b'nameserver 127.0.0.53\nsearch PRIVATE_DOMAIN\n')
        self.assertEqual(private, ['127.0.0.53']); self.assertTrue(public['loopbackOtherThanDockerPresent'])
        _, docker = d.resolver_shape(b'nameserver 127.0.0.11\noptions ndots:0\n')
        self.assertTrue(docker['dockerEmbeddedPresent']); self.assertNotIn('127.0.0.53', json.dumps(public))
        self.assertNotIn('PRIVATE_DOMAIN', json.dumps(public))
        with self.assertRaises(d.Stop): d.resolver_shape(b'nameserver INVALID_NAME\n')

    def test_missing_and_inconsistent_child_fields_are_rejected(self):
        value = self.invoke('HOST_DNS')
        for key in ('phase', 'verifyCode'):
            changed = copy.deepcopy(value); changed.pop(key)
            with self.subTest(key=key), self.assertRaises(d.Stop): d.check_child(changed)
        changed = copy.deepcopy(value); changed['certificateChainVerified'] = True
        with self.assertRaises(d.Stop): d.check_child(changed)

    def test_exact_retained_capsule_preloads_without_application_entry(self):
        raw = (ROOT / 'releases/semantic-registry-postboot-tls-20261023.py').read_bytes()
        case, manifest, loader, sources = d.unpack(raw)
        self.assertEqual(len(sources), 132); self.assertEqual(d.digest(manifest), d.CLOSURE_HASH)
        program = ('ns={}\nexec(' + repr(loader) + ',ns)\nentry,m=ns["load_entry"]('
            + repr(manifest['sourceCommit']) + ',' + repr(sources) + ',' + repr(loader) + ','
            + repr(d.CLOSURE_HASH) + ',' + repr(manifest['sourcePins']) + ')\n'
            + 'assert callable(entry.execute)\nprint("RETAINED_PRELOAD_NO_ENTRY")\n')
        child = subprocess.run([sys.executable, '-I', '-B', '-S', '-'], input=program.encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, cwd='/')
        self.assertEqual(child.returncode, 0, child.stderr); self.assertEqual(child.stdout.strip(), b'RETAINED_PRELOAD_NO_ENTRY')
        self.assertEqual(case['preparation']['originalRequestTls']['maximumTlsHandshakes'], 1)

    def test_tampered_capsule_and_symlink_are_rejected_before_preload(self):
        raw = (ROOT / 'releases/semantic-registry-postboot-tls-20261023.py').read_bytes()
        with tempfile.TemporaryDirectory(dir=ROOT) as name:
            target = Path(name) / 'capsule.py'; target.write_bytes(raw)
            self.assertEqual(d.read_capsule(str(target)), raw)
            target.write_bytes(raw + b'\n')
            with self.assertRaises(d.Stop): d.read_capsule(str(target))
            target.unlink(); target.symlink_to(ROOT / 'releases/semantic-registry-postboot-tls-20261023.py')
            with self.assertRaises(OSError): d.read_capsule(str(target))

    def test_child_has_no_http_dispatch_insecure_context_or_credential_field(self):
        tree = ast.parse(d.CHILD)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, {'request', 'putrequest', '_create_unverified_context'})
        self.assertNotIn('CERT_NONE', d.CHILD)
        self.assertIn("set(v)!={'mode','origin','ca'}", d.CHILD)
        source = ast.parse(SCRIPT.read_text())
        for node in ast.walk(source):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, {'execute', 'prepare', '_prepare', 'admin_routes', 'read_frozen', 'issue'})


if __name__ == '__main__': unittest.main()
