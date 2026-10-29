"""Actual private SERVICE GET through a held Linux network namespace FD.

This disposable HTTP/TLS fixture qualifies the new frozen-configuration getter.
It does not contact OUF or count a fixture bearer as production admission.
"""
import hashlib
import json
import ssl
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_semantic_request as service
from tools.semantic_registry_recovery_execution import postboot_prepare as p
from tools.semantic_registry_recovery_execution.core import RecoveryDenied


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.calls.append({'path': self.path,
            'sameWorkloadBearer': self.headers.get('Authorization') == 'Bearer FIXTURE_ORIGINAL_SERVICE_TOKEN'})
        status = self.server.status if self.server.calls[-1]['sameWorkloadBearer'] else 403
        raw = self.server.raw if self.server.raw is not None else json.dumps(self.server.frozen).encode()
        # Complete a fixture mutation before the client can receive any response.
        # A callback after write(raw) races the client's final custody check.
        if self.server.callback:
            self.server.callback()
        self.send_response(status)
        if status == 302:
            self.send_header('Location', 'http://127.0.0.1:1/no-fallback')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers(); self.wfile.write(raw)


class FrozenTransport(unittest.TestCase):
    native = service.ServiceRequest.native
    write = service.ServiceRequest.write
    binding = service.ServiceRequest.binding
    sign = service.ServiceRequest.sign
    resign = service.ServiceRequest.resign
    close_server = service.ServiceRequest.close_server

    def setUp(self):
        service.ServiceRequest.setUp(self)
        self.server.RequestHandlerClass = Handler
        self.server.frozen = self.profile_request['frozenConfiguration']
        self.server.frozen['sourceId'] = 'fixture-original-source'
        self.server.raw = None
        self.reference = {key: self.server.frozen[key]
            for key in ('sourceId', 'onboardingVersionId', 'configurationHash')}

    def get(self):
        return p.read_frozen(self.profile_request, self.caller, self.reference)

    def test_exact_configuration_get_uses_private_stdin_and_same_mounted_service_token(self):
        with patch.object(p.subprocess, 'Popen', wraps=p.subprocess.Popen) as launch:
            result = self.get()
        self.assertEqual(result, self.server.frozen)
        self.assertEqual(p.frozen_configuration(result, self.reference), [self.ref])
        self.assertEqual(len(self.server.calls), 1)
        call = self.server.calls[0]
        self.assertTrue(call['sameWorkloadBearer'])
        self.assertEqual(urlsplit(call['path']).path, p.FROZEN_PATH)
        self.assertEqual(parse_qs(urlsplit(call['path']).query), {k: [v] for k, v in self.reference.items()})
        self.assertNotIn('FIXTURE_ORIGINAL_SERVICE_TOKEN', str(launch.call_args.args))
        self.assertNotIn('FIXTURE_ORIGINAL_SERVICE_TOKEN', str(launch.call_args.kwargs['env']))
        self.assertNotIn('FIXTURE_ORIGINAL_SERVICE_TOKEN', json.dumps(result))
        self.assertEqual(launch.call_args.kwargs['stderr'], p.subprocess.DEVNULL)

    def test_401_403_502_and_redirect_do_not_login_retry_or_follow(self):
        for status in (401, 403, 502, 302):
            self.server.status = status
            with self.subTest(status=status), self.assertRaisesRegex(RecoveryDenied, 'GET_UNCONFIRMED'):
                self.get()
        self.assertEqual(len(self.server.calls), 4)

    def test_duplicate_configuration_keys_fail_in_child_without_raw_output(self):
        self.server.raw = b'{"sourceId":"first","sourceId":"second"}'
        with self.assertRaisesRegex(RecoveryDenied, 'GET_UNCONFIRMED'):
            self.get()
        self.assertEqual(len(self.server.calls), 1)

    def test_response_above_two_mebibytes_is_rejected_without_retry(self):
        self.server.raw = b' ' * 2097153
        with self.assertRaisesRegex(RecoveryDenied, 'GET_UNCONFIRMED'):
            self.get()
        self.assertEqual(len(self.server.calls), 1)

    def test_token_atomic_rotation_during_get_cannot_be_retained(self):
        rotated = threading.Event()
        def rotate():
            import os
            changed = self.root / 'replaced-token.jwt'
            changed.write_text('FIXTURE_CHANGED_TOKEN'); changed.chmod(0o600)
            os.replace(changed, self.token)
            rotated.set()
        self.server.callback = rotate
        with self.assertRaisesRegex(RecoveryDenied, 'ORIGINAL_MOUNTED_SERVICE_TOKEN_CHANGED'):
            self.get()
        self.assertTrue(rotated.is_set())
        self.assertEqual(len(self.server.calls), 1)

    def test_https_certificate_name_ca_and_exact_leaf_pin_are_required(self):
        self.close_server(); self._cleanups.pop()
        cert = self.root / 'frozen.crt'; key = self.root / 'frozen.key'
        self.native('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert),
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-days', '1')
        key.chmod(0o600); cert.chmod(0o600)
        server = HTTPServer(('127.0.0.1', 0), Handler)
        server.calls = []; server.status = 200; server.raw = None; server.callback = None
        server.frozen = self.server.frozen
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True); self.server = server
        self.server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.server_thread.start(); self.addCleanup(self.close_server)
        self.profile_request.update(origin='https://localhost:' + str(server.server_address[1]),
            ca=service.fixture.file_profile(cert),
            peerCertificateSha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest())
        self.assertEqual(self.get(), server.frozen)
        self.profile_request['peerCertificateSha256'] = '0' * 64
        with self.assertRaisesRegex(RecoveryDenied, 'GET_UNCONFIRMED'):
            self.get()
        self.assertEqual(len(server.calls), 1)


if __name__ == '__main__':
    unittest.main()
