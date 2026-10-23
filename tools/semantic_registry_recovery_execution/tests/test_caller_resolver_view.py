"""Actual private mounts, configured DNS and TLS, without application HTTP."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'scripts/verify-registry-caller-resolver-20261023.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


d = load('caller_resolver_view_fixture', SCRIPT)
old = vars(load('retained_tls_fixture', ROOT / 'scripts/diagnose-registry-postboot-tls-20261023.py'))


class Dns(socketserver.BaseRequestHandler):
    def handle(self):
        query, server = self.request
        if len(query) < 17: return
        end = 12
        while end < len(query) and query[end]: end += query[end] + 1
        end += 1
        if end + 4 != len(query): return
        kind, cls = struct.unpack('!HH', query[end:end + 4])
        if cls != 1: return
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton(self.server.address)
        payload = query[:2] + struct.pack('!HHHHH', 0x8180, 1, int(kind == 1), 0, 0) + query[12:]
        if kind == 1: payload += answer
        self.server.queries += 1
        server.sendto(payload, self.client_address)


class Http(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        self.server.http_calls += 1; self.send_response(500); self.end_headers()


class CallerResolver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(dir=ROOT); cls.addClassCleanup(cls.tmp.cleanup)
        cls.cert = Path(cls.tmp.name) / 'cert.pem'; cls.key = Path(cls.tmp.name) / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(cls.key),
            '-out', str(cls.cert), '-subj', '/CN=ouf-resolver-fixture.test',
            '-addext', 'subjectAltName=DNS:ouf-resolver-fixture.test', '-addext', 'basicConstraints=critical,CA:TRUE', '-days', '1'],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)

    def setUp(self):
        self.dns = socketserver.ThreadingUDPServer(('127.0.0.1', 53), Dns)
        self.dns.address = '127.0.0.1'; self.dns.queries = 0
        self.addCleanup(self.dns.server_close)
        self.dt = threading.Thread(target=self.dns.serve_forever, daemon=True); self.dt.start()
        self.addCleanup(self.dns.shutdown)
        self.server = HTTPServer(('127.0.0.1', 0), Http); self.server.http_calls = 0
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(self.cert, self.key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.addCleanup(self.server.server_close)
        self.st = threading.Thread(target=self.server.serve_forever, daemon=True); self.st.start()
        self.addCleanup(self.server.shutdown)
        self.views = {'resolv.conf': 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n',
                      'hosts': '127.0.0.1 localhost\n', 'nsswitch.conf': 'hosts: files dns\n'}
        self.origin = 'https://ouf-resolver-fixture.test:' + str(self.server.server_port)

    def invoke(self, views=None, origin=None, ca=None, source=None):
        fd = os.open('/proc/self/ns/net', os.O_RDONLY)
        try:
            if source is None:
                return d.run_child(old, origin or self.origin, ca or self.cert.read_bytes(),
                                   self.views if views is None else views, {'path': sys.executable}, fd)
            payload = d.encoded({'mode': 'CALLER_DNS_TLS', 'origin': origin or self.origin,
                'ca': (ca or self.cert.read_bytes()).decode(), 'views': self.views if views is None else views})
            result = subprocess.run([sys.executable, '-I', '-B', '-S', '-c', source, str(fd)],
                input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(fd,), timeout=12)
            self.assertEqual(result.returncode, 0, result.stderr)
            return d.check_result(json.loads(result.stdout), old)
        finally: os.close(fd)

    def host_snapshot(self):
        return (os.stat('/proc/self/ns/mnt').st_ino, (os.stat('/tmp').st_dev, os.stat('/tmp').st_ino),
            {n: (os.stat('/etc/' + n).st_ino, Path('/etc/' + n).read_bytes()) for n in d.VIEWS})

    def test_actual_copied_resolver_dns_tls_and_host_files_unchanged(self):
        before = self.host_snapshot(); result = self.invoke()
        self.assertEqual(result['status'], 'OBSERVED', result); self.assertTrue(result['privateLookupViewInstalled'])
        self.assertTrue(result['certificateChainVerified']); self.assertTrue(result['hostnameVerified'])
        self.assertGreater(self.dns.queries, 0); self.assertEqual(self.server.http_calls, 0)
        self.assertEqual(before, self.host_snapshot())
        public = old['public_child'](result)
        self.assertNotIn('ouf-resolver-fixture.test', json.dumps(public)); self.assertNotIn('peerCertificateSha256', public)

    def test_configured_hosts_and_nondefault_port_used_without_dns(self):
        self.views['hosts'] += '127.0.0.1 ouf-resolver-fixture.test\n'
        result = self.invoke()
        self.assertTrue(result['certificateChainVerified']); self.assertEqual(self.dns.queries, 0)
        self.assertEqual(self.server.http_calls, 0)

    def test_private_mount_failure_stops_before_dns_or_connection(self):
        source = d.child_source(old['CHILD']).replace('os.unshare(os.CLONE_NEWNS)', 'raise PermissionError(1, "PRIVATE")')
        result = self.invoke(source=source)
        self.assertEqual(result['phase'], 'PRIVATE_LOOKUP_VIEW'); self.assertFalse(result['privateLookupViewInstalled'])
        self.assertFalse(result['resolverSucceeded']); self.assertFalse(result['tcpConnectAttempted'])
        self.assertEqual(self.dns.queries, 0); self.assertNotIn('PRIVATE', json.dumps(result).replace('PRIVATE_LOOKUP_VIEW', ''))

    def test_unknown_nss_provider_rejected_before_child(self):
        self.views['nsswitch.conf'] = 'hosts: files resolve dns\n'
        with self.assertRaises(d.Stop): self.invoke()
        self.assertEqual(self.dns.queries, 0)

    def test_wrong_certificate_name_stays_rejected_in_correct_view(self):
        self.views['hosts'] += '127.0.0.1 wrong-resolver-fixture.test\n'
        result = self.invoke(origin=self.origin.replace('ouf-resolver-fixture.test', 'wrong-resolver-fixture.test'))
        self.assertEqual(result['errorClass'], 'SSLCertVerificationError'); self.assertIs(type(result['verifyCode']), int)
        self.assertFalse(result['certificateChainVerified']); self.assertEqual(self.server.http_calls, 0)

    def test_malformed_ca_stops_before_dns(self):
        result = self.invoke(ca=b'INVALID_CA')
        self.assertEqual(result['phase'], 'LOAD_CA'); self.assertFalse(result['resolverSucceeded'])
        self.assertEqual(self.dns.queries, 0); self.assertEqual(self.server.http_calls, 0)

    def test_view_protocol_cannot_claim_resolution_without_mount(self):
        result = self.invoke(); result['privateLookupViewInstalled'] = False
        with self.assertRaises(d.Stop): d.check_result(result, old)


class Offline(unittest.TestCase):
    def test_retained_script_exact_preload_without_entry(self):
        loaded = d.previous(str(ROOT / 'scripts/diagnose-registry-postboot-tls-20261023.py'))
        self.assertEqual(loaded['CAPSULE_HASH'], old['CAPSULE_HASH'])
        self.assertEqual(hashlib.sha256((ROOT / 'scripts/diagnose-registry-postboot-tls-20261023.py').read_bytes()).hexdigest(), d.PREVIOUS_HASH)

    def test_claim_identity_is_incident_boot_and_purpose_not_source(self):
        claim = {'bootId': 'one', 'retainedClaimHash': 'a'}
        self.assertEqual(d.observation_root('/test', claim, 'one'), d.observation_root('/test', dict(claim), 'one'))
        self.assertNotEqual(d.observation_root('/test', claim, 'one'), d.observation_root('/test', claim, 'two'))

    def test_no_application_http_tokens_insecure_tls_or_fixed_target(self):
        source = d.child_source(old['CHILD']); ast.parse(source)
        for forbidden in ('http.client', 'Authorization', 'CERT_NONE', 'check_hostname=False', '.request(', 'verify=False'):
            self.assertNotIn(forbidden, source)
        # Configuration values come from the copied files/origin, not code.
        self.assertNotIn('127.0.0.11', SCRIPT.read_text())
        self.assertNotIn('http://', SCRIPT.read_text()); self.assertNotIn('https://', SCRIPT.read_text())


class Launcher(unittest.TestCase):
    def fixture(self, directory, content):
        binary = directory / 'bin'; binary.mkdir()
        for name, text in {
            'gh': '#!/bin/sh\nprintf "%s\\n" "$*" >> "$HOME/gh.calls"\ncat "$HOME/source.py"\n',
            'sudo': '#!/bin/sh\ntest "$1" = -- || exit 9\nshift\nexec "$@"\n'}.items():
            target = binary / name; target.write_text(text); target.chmod(0o700)
        (directory / 'source.py').write_bytes(content)
        return {**os.environ, 'HOME': str(directory), 'PATH': str(binary) + ':/usr/bin:/bin'}

    def test_missing_retained_source_stops_before_engine_or_dns(self):
        self.assertFalse(Path(d.PREVIOUS).exists())
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            home = Path(temporary); env = self.fixture(home, SCRIPT.read_bytes())
            result = subprocess.run(['bash', str(ROOT / 'releases/semantic-registry-caller-resolver-20261023.sh')],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 2)
            rows = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith('{')]
            self.assertEqual(rows[0]['stage'], 'VERIFY_RETAINED_SOURCE')
            self.assertEqual(rows[0]['exceptionClass'], 'FileNotFoundError'); self.assertEqual(rows[0]['errno'], 2)
            self.assertEqual(rows[0]['runtimeEffectsDispatched'], 0); self.assertEqual(rows[0]['bearersSent'], 0)
            calls = (home / 'gh.calls').read_text().splitlines(); self.assertEqual(len(calls), 1)
            self.assertIn('ref=6791a0972b82a1a743c167571e886d48c4bc7543', calls[0])
            self.assertIn('verify-registry-caller-resolver-20261023.py', calls[0])
            private = next(home.glob('ouf-caller-resolver.*'))
            self.assertEqual((private / 'read.stderr').read_bytes(), b'')

    def test_tamper_rejected_before_code_execution(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            home = Path(temporary); env = self.fixture(home, b'raise RuntimeError("NEVER_EXECUTE")\n')
            result = subprocess.run(['bash', str(ROOT / 'releases/semantic-registry-caller-resolver-20261023.sh')],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'EXACT_CALLER_RESOLVER_ROOT_LAUNCH_UNPROVEN', result.stdout)
            self.assertNotIn(b'NEVER_EXECUTE', result.stdout + result.stderr)

    def test_no_arguments_or_retry_before_download(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            home = Path(temporary); env = self.fixture(home, SCRIPT.read_bytes())
            result = subprocess.run(['bash', str(ROOT / 'releases/semantic-registry-caller-resolver-20261023.sh'), 'retry'],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 2); self.assertFalse((home / 'gh.calls').exists())


if __name__ == '__main__': unittest.main()
