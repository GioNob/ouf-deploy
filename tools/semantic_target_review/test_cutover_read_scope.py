"""Reject privileged operations even if a caller puts them in its allowed list."""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).with_name('read_cutover_inputs.py')


class ReadScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = SOURCE.read_text()
        cls.scope = {'__name__': 'not_the_cli', '__file__': str(SOURCE)}
        exec(compile(cls.code, str(SOURCE), 'exec'), cls.scope)

    def test_no_installed_module_import(self):
        allowed = {'fcntl', 'hashlib', 'ipaddress', 'json', 'os', 'pathlib', 're', 'stat',
                   'subprocess', 'sys', 'traceback', 'socket', 'time'}
        for node in ast.walk(ast.parse(self.code)):
            if isinstance(node, ast.Import):
                self.assertTrue(all(v.name in allowed for v in node.names))
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module, allowed)

    def test_mutation_and_unbounded_access_denied_before_any_io(self):
        scopes = [
            ['-f', '-'], ['flush', 'ruleset'], ['-j', 'list', 'ruleset'],
            ['exec', 'ouf-semantic', 'sh'], ['restart', 'ouf-semantic'],
            ['inspect', '--type', 'container', '--format', '{{json .Config.Env}}', self.scope['SEMANTIC_ID']],
            ['inspect', '--type', 'container', '--format', self.scope['SEMANTIC_FORMAT'], 'foreign-container'],
            ['--net=/proc/1/ns/net', '/usr/bin/python3', '-c', 'pass'],
            ['-j', 'link', 'set', 'dev', 'veth0'], ['-j', '-n', 'list', 'table', 'inet', 'bad;flush'],
        ]
        for args in scopes:
            with self.subTest(args=args), self.assertRaises(self.scope['ReadDenied']):
                self.scope['native_read']({'path': '/not/read', 'sha256': '0' * 64}, args, [args])

    def test_reader_cannot_contend_with_nonblocking_lease_worker(self):
        self.assertNotIn('flock(', self.code)
        self.assertNotIn('import fcntl', self.code)
        self.assertIn("base['commonLockAcquired'] = False", self.code)

    def test_peer_plan_and_reader_never_call_operational_guard(self):
        forbidden = ('systemd-run', 'attestation verify', 'nft flush', 'docker stop', 'docker start')
        self.assertTrue(all(value not in self.code for value in forbidden))
        self.assertNotIn('from tools.', self.code)


if __name__ == '__main__':
    unittest.main()
