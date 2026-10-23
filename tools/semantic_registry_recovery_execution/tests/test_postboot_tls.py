"""Real TLS chain/name tests; namespace handoff is isolated only in this suite.

The full native JVM fixture separately exercises the unmodified child via a
held real caller namespace. No target credential, HTTP call or trust edit here.
"""
import ast
import copy
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from tools.semantic_registry_recovery_execution import original_tls as t, postboot_prepare as p


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        self.server.http_calls += 1
        self.send_response(500); self.end_headers()


class OriginalTls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.cert = cls.root / 'root-and-server.pem'; cls.key = cls.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(cls.key), '-out', str(cls.cert), '-subj', '/CN=localhost',
            '-addext', 'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:TRUE', '-days', '1'],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        cls.cert.chmod(0o444); cls.key.chmod(0o600)

    def setUp(self):
        server = HTTPServer(('127.0.0.1', 0), Handler); server.http_calls = 0
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(self.cert, self.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        self.server = server; self.thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.thread.start(); self.addCleanup(self.close)
        self.origin = 'https://localhost:' + str(server.server_port)

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(3)

    def child(self, origin=None, ca=None, extra=None):
        raw = {'origin': origin or self.origin, 'ca': ca if ca is not None else self.cert.read_text()}
        if extra: raw.update(extra)
        # Explicit local fixture only: preserve the production TLS client body,
        # removing just setns because this suite owns the listening namespace.
        self.assertEqual(t.TLS_CHILD_SOURCE.count('os.setns(fd,0);os.close(fd)'), 1)
        source = t.TLS_CHILD_SOURCE.replace('os.setns(fd,0);os.close(fd)', 'os.close(fd)')
        fd = os.open('/dev/null', os.O_RDONLY)
        try:
            return subprocess.run([sys.executable, '-I', '-B', '-S', '-c', source, str(fd)],
                input=json.dumps(raw).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=12, pass_fds=(fd,), env={'LC_ALL': 'C'}, cwd='/')
        finally: os.close(fd)

    def test_chain_and_hostname_validated_before_leaf_pin_without_http_or_bearer(self):
        result = self.child(); self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt, {'certificateChainVerified': True, 'hostnameVerified': True,
            'peerCertificateSha256': hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert.read_text())).hexdigest()})
        self.assertEqual(self.server.http_calls, 0)
        self.assertEqual(result.stderr, b'')

    def test_large_valid_ca_bundle_over_256k_is_bounded_and_supported(self):
        ca = self.cert.read_text() * 300
        self.assertGreater(len(ca), 262144); self.assertLess(len(ca), 1048576)
        result = self.child(ca=ca)
        self.assertEqual(result.returncode, 0); self.assertEqual(self.server.http_calls, 0)

    def test_untrusted_ca_wrong_hostname_and_non_https_are_denied_without_http(self):
        cases = [dict(ca='NOT_A_CA'), dict(origin=self.origin.replace('localhost', '127.0.0.1')),
                 dict(origin=self.origin.replace('https:', 'http:'))]
        for values in cases:
            with self.subTest(values=values):
                result = self.child(**values)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'')
        self.assertEqual(self.server.http_calls, 0)

    def test_expired_certificate_is_rejected_without_http(self):
        csr = self.root / 'expired.csr'; expired = self.root / 'expired.pem'
        for command in ([
                'openssl', 'req', '-new', '-key', str(self.key), '-out', str(csr),
                '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], [
                'openssl', 'x509', '-req', '-in', str(csr), '-signkey', str(self.key),
                '-out', str(expired), '-days', '-1', '-copy_extensions', 'copy']):
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        self.server.socket.context.load_cert_chain(expired, self.key)
        result = self.child(ca=expired.read_text())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'')
        self.assertEqual(self.server.http_calls, 0)

    def test_oversize_ca_and_any_credential_field_are_refused(self):
        for values in (dict(ca='A' * 1048577), dict(extra={'token': 'NEVER_SEND_THIS'})):
            with self.subTest(values=list(values)):
                result = self.child(**values)
                self.assertNotEqual(result.returncode, 0); self.assertEqual(result.stdout, b'')
        self.assertEqual(self.server.http_calls, 0)

    def test_system_ca_selection_ignores_environment_and_binds_root_owned_links(self):
        link = self.root / 'compiled-ca-link'; link.symlink_to(self.cert)
        self.addCleanup(link.unlink)
        with patch.object(t.ssl, 'get_default_verify_paths', return_value=SimpleNamespace(
                openssl_cafile=str(link), cafile='/DO_NOT_READ_ENV_SELECTED_FILE')):
            profile, source = t.system_ca(p.Files())
            self.assertEqual(profile['path'], str(self.cert)); self.assertEqual(len(source['links']), 1)
            self.assertEqual(source['compiledPath'], str(link))
            self.assertEqual(source['links'][0]['target'], str(self.cert))

    def test_unowned_ca_link_and_writable_ca_file_are_refused(self):
        link = self.root / 'unowned-link'; link.symlink_to(self.cert); os.lchown(link, 65534, 65534)
        self.addCleanup(link.unlink)
        with patch.object(t.ssl, 'get_default_verify_paths', return_value=SimpleNamespace(openssl_cafile=str(link))):
            with self.assertRaisesRegex(Exception, 'ROOT_CONTROLLED_SYSTEM_CA_PATH'): t.resolve_system_ca()
        self.cert.chmod(0o666)
        try:
            with patch.object(t.ssl, 'get_default_verify_paths', return_value=SimpleNamespace(openssl_cafile=str(self.cert))):
                with self.assertRaisesRegex(Exception, 'ROOT_CONTROLLED_CA_ANCESTRY'): t.system_ca(p.Files())
        finally: self.cert.chmod(0o444)

    def test_compiled_system_ca_resolution_is_available_without_target_call(self):
        source = t.resolve_system_ca()
        self.assertTrue(Path(source['resolvedPath']).is_file())
        self.assertNotIn('SSL_CERT_FILE', source['compiledPath'])

    def test_tls_child_contains_no_http_dispatch_or_insecure_context(self):
        tree = ast.parse(t.TLS_CHILD_SOURCE)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, {'request', 'putrequest', 'send', '_create_unverified_context'})
        self.assertNotIn('CERT_NONE', t.TLS_CHILD_SOURCE)

    def test_both_old_claims_and_attempts_survive_and_any_advance_stops(self):
        case = json.loads((ROOT / 'releases/semantic-registry-postboot-tls-case-20261023.json').read_bytes())['preparation']
        boot = '00000000-1111-2222-3333-444444444444'
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            parent = Path(directory); roots = []
            for prior in case['priorPreparations']:
                root = parent / ('semantic-registry-postboot-inputs-' + p.digest({
                    'case': prior['case'], 'closure': prior['sourceClosureHash'], 'boot': boot}))
                root.mkdir(mode=0o700); roots.append(root)
                p.publish(root, 'claim.json', {'schema': p.SCHEMA, 'caseHash': prior['caseHash'],
                    'sourceClosureHash': prior['sourceClosureHash'], 'bootId': boot,
                    'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
                    'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False})
                for n in range(1, 7):
                    p.publish(root, 'engine-get-' + str(n) + '.json', {'requestPathHash': 'a' * 64, 'attempt': n})
                p.publish(root, 'admin-get.json', {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1})
            before = {str(f): (f.read_bytes(), f.stat().st_ino) for root in roots for f in root.iterdir()}
            with patch.object(p, 'PARENT', directory):
                proof = p.reconcile_prior_preparation(case, p.Files(), boot)
                self.assertEqual(proof['priorAttemptCounts'], {'engineGets': 12, 'adminGets': 2, 'frozenConfigurationGets': 0})
                self.assertEqual(proof['cumulativeAttemptCeilings'], {
                    'engineGets': 24, 'adminGets': 3, 'frozenConfigurationGets': 1, 'tlsHandshakes': 1})
                self.assertFalse(proof['oldPreparationReplayed']); self.assertFalse(proof['budgetReset'])
                after = {str(f): (f.read_bytes(), f.stat().st_ino) for root in roots for f in root.iterdir()}
                self.assertEqual(before, after)
                p.publish(roots[1], 'tls-handshake.json', {'attempt': 1})
                with self.assertRaisesRegex(Exception, 'ADVANCED_RECONCILE'):
                    p.reconcile_prior_preparation(case, p.Files(), boot)

    def test_new_case_links_both_consumed_preparations_without_changing_scope(self):
        case = json.loads((ROOT / 'releases/semantic-registry-postboot-tls-case-20261023.json').read_bytes())['preparation']
        p.validate_case(case)
        for update in ('engineAttempts', 'caseHash', 'sourceClosureHash', 'duplicate', 'reference'):
            changed = copy.deepcopy(case)
            if update in ('engineAttempts', 'caseHash', 'sourceClosureHash'):
                changed['priorPreparations'][1][update] = {'engineAttempts': 0, 'caseHash': '0' * 64, 'sourceClosureHash': 'NOT_A_HASH'}[update]
            elif update == 'duplicate': changed['priorPreparations'][1] = changed['priorPreparations'][0]
            else: changed['frozenReference']['sourceId'] = 'DIFFERENT'
            with self.subTest(update=update), self.assertRaises(Exception): p.validate_case(changed)


if __name__ == '__main__': unittest.main()
