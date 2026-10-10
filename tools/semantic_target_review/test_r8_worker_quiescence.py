"""Verify privileged read scope and redaction, without reading a target."""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).with_name('read_r8_worker_quiescence.py')


class WorkerReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = SOURCE.read_text()
        cls.scope = {'__name__': 'fixture_not_cli', '__file__': str(SOURCE)}
        exec(compile(cls.code, str(SOURCE), 'exec'), cls.scope)

    def test_metadata_only_commands_reject_mutation_or_other_units_before_io(self):
        for args in (['start', self.scope['UNIT']], ['restart', self.scope['UNIT']],
                     ['stop', self.scope['UNIT']], ['reset-failed', self.scope['UNIT']],
                     ['daemon-reload'], ['show', 'unrelated.service', '--all'],
                     ['show', self.scope['UNIT'], '--property=Environment'], ['status', self.scope['UNIT']]):
            with self.subTest(args=args), self.assertRaises(self.scope['ReadDenied']):
                self.scope['service_read']({'path': '/never/read', 'sha256': '0' * 64}, args)

    def test_projection_excludes_raw_messages_env_credentials_and_paths(self):
        record = {'status': 'LEASE_WORKER_FAILED', 'refreshCount': 9, 'reason': 'secret password=Abcd',
                  'Environment': ['TOKEN=secret'], 'rawMessage': 'Bearer secret', 'providerResponse': 'private',
                  'exceptionChain': [{'errorType': 'OSError', 'reason': 'REFRESH_FAILED_GATE_BLOCKED',
                     'message': 'Bearer secret', 'exceptionPoints': [{'file': '/run/secrets/key',
                       'function': 'refresh', 'line': 42}]}]}
        output = self.scope['failure_projection'](record)
        text = str(output)
        for forbidden in ('password', 'Abcd', 'Bearer', 'TOKEN', '/run/secrets', 'providerResponse', 'rawMessage'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(output['exceptionChain'][0]['reason'], 'REFRESH_FAILED_GATE_BLOCKED')
        self.assertEqual(output['reason'], 'DETAIL_REDACTED')

    def test_oversized_failure_chain_refused(self):
        with self.assertRaises(self.scope['ReadDenied']):
            self.scope['failure_projection']({'exceptionChain': [{}] * 7})

    def test_no_installed_import_or_common_lock_acquisition(self):
        imports = {'hashlib', 'ipaddress', 'json', 'os', 'pathlib', 're', 'stat', 'subprocess', 'sys', 'traceback'}
        for node in ast.walk(ast.parse(self.code)):
            if isinstance(node, ast.Import):
                self.assertTrue(all(n.name in imports for n in node.names))
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module, imports)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, ('flock', 'replace', 'unlink', 'chmod', 'mkdir', 'write_text', 'write_bytes'))


if __name__ == '__main__':
    unittest.main()
