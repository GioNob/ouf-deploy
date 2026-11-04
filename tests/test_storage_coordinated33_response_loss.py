"""Real loopback traffic plus fail-closed request and durable-intent checks."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
import storage_response_loss as loss
spec = importlib.util.spec_from_file_location('loss33', ROOT / 'scripts/run-storage-coordinated33-lab.py')
cut = importlib.util.module_from_spec(spec); spec.loader.exec_module(cut)
BODY = cut.BODIES['lab-ambiguous']
PATH = '/ouf-recovery-fixture/lab-ambiguous'
HOST = '127.0.0.1:18333'


class ResponseLossTests(unittest.TestCase):
    def wire(self):
        return (f'PUT {PATH} HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: {len(BODY)}\r\n\r\n'.encode() + BODY)

    def test_request_preserved_byte_for_byte(self):
        self.assertEqual(self.wire(), loss.read_request(io.BytesIO(self.wire()), PATH, HOST, BODY))

    def test_malformed_or_ambiguous_request_never_forwarded(self):
        raw = self.wire()
        for bad in (raw.replace(b'PUT ', b'POST '), raw.replace(b'lab-ambiguous', b'other'),
                    raw.replace(b'18333', b'18334'), raw.replace(b'\r\n', b'\n'),
                    raw.replace(b'Content-Length:', b'Transfer-Encoding: chunked\r\nContent-Length:'),
                    raw.replace(b'Content-Length:', b'Expect: 100-continue\r\nContent-Length:'),
                    raw.replace(b'Host:', b'Host: duplicate\r\nHost:'), raw[:-1],
                    raw[:-1] + b'X', raw.replace(b'45\r\n', b'44\r\n'), b'X' * 8193):
            with self.subTest(request=bad[:50]), self.assertRaises(RuntimeError):
                loss.read_request(io.BytesIO(bad), PATH, HOST, BODY)

    def backend(self, response):
        server = socket.socket(); server.bind(('127.0.0.1', 0)); server.listen(2); server.settimeout(3)
        port = server.getsockname()[1]
        observed = []; errors = []
        def serve():
            try:
                with server:
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(3)
                        with conn.makefile('rb') as stream:
                            observed.append(loss.read_request(stream, PATH, HOST, BODY))
                            conn.sendall(response)
                    server.settimeout(0.1)
                    try:
                        extra, _ = server.accept(); extra.close(); observed.append(b'EXTRA_REQUEST')
                    except socket.timeout:
                        pass
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=serve); thread.start()
        self.addCleanup(thread.join, 4)
        return port, observed, errors, thread

    def invoke(self, response):
        port, observed, errors, thread = self.backend(response)
        try:
            return loss.lose_response(PATH, BODY, {'host': HOST, 'connection': 'close'}, backend_port=port)
        finally:
            thread.join(4)
            self.assertFalse(thread.is_alive())
            self.assertEqual([], errors)
            self.assertEqual(1, len(observed))
            self.assertTrue(observed[0].endswith(BODY))

    def test_backend_success_is_consumed_client_gets_only_eof(self):
        report = self.invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        self.assertEqual(200, report['upstreamStatus'])
        self.assertEqual(1, report['forwardedRequests'])
        self.assertEqual(0, report['downstreamResponseBytes'])
        self.assertEqual('RemoteDisconnected', report['clientError'])
        self.assertEqual(cut.sha(BODY), report['sha256'])
        self.assertTrue(report['relayTerminated'])

    def test_upstream_error_is_not_successful_response_loss(self):
        for code in (403, 500):
            with self.subTest(code=code), self.assertRaisesRegex(RuntimeError, 'UPSTREAM_PUT_200'):
                self.invoke(f'HTTP/1.1 {code} Error\r\nContent-Length: 0\r\n\r\n'.encode())

    def test_truncated_success_response_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'COMPLETE_BOUNDED_RESPONSE'):
            self.invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nx')

    def test_oversized_success_response_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'COMPLETE_BOUNDED_RESPONSE'):
            self.invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 4097\r\n\r\n' + b'x' * 4097)

    def test_missing_upstream_response_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'RESPONSE_LOSS_INJECTION_FAILED'):
            self.invoke(b'')

    def test_pending_retry_preserves_history_and_refuses_new_authority(self):
        ledger = {'control': {'singleton': True, 'epoch': 1, 'version': 0, 'phase': 'ACTIVE'},
                  'intents': [{'operation': 'lab-acked', 'state': 'ACKED'},
                              {'operation': 'lab-ambiguous', 'state': 'PENDING'}], 'events': [1, 2, 3]}
        class Calls:
            def __init__(self, decision='EXISTING_PENDING', mutate=False):
                self.decision = decision; self.value = copy.deepcopy(ledger); self.mutate = mutate
            def raw(self, sql): return json.dumps(self.value)
            def call(self, *args, **kwargs):
                if self.mutate: self.value['events'].append(4)
                return self.decision
        with tempfile.TemporaryDirectory() as temp:
            report = cut.verify_response_loss_pending(Calls(), Path(temp))
            self.assertEqual(0, report['recoveryPutRequests'])
            for calls in (Calls('RESERVED'), Calls(mutate=True)):
                with self.assertRaises(RuntimeError):
                    cut.verify_response_loss_pending(calls, Path(temp))

    def test_two_fault_modes_cannot_be_combined(self):
        with self.assertRaisesRegex(RuntimeError, 'ONE_FAULT_PER_LAB'):
            cut.run(None, None, None, None, crash_after_put=True, lose_put_response=True)


if __name__ == '__main__':
    unittest.main()
