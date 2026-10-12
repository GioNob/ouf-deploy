import contextlib, importlib.util, io, json, os, stat, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('observer', ROOT/'scripts/observe-semantic-token-source.py')
observer = importlib.util.module_from_spec(spec); spec.loader.exec_module(observer)

class StaticObservation(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name)/'producer.py'
        path.write_bytes(b'raise RuntimeError("DO_NOT_EXECUTE")\n')
        path.chmod(0o755)
        expected = {}
        parent = Path('/')
        for part in path.parts[1:-1]:
            parent /= part; s = parent.lstat()
            expected[str(parent)] = (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode))
        return path, expected

    def test_native_snapshot_does_not_execute_source(self):
        path, expected = self.fixture()
        raw, seal = observer.snapshot(path, expected)
        self.assertIn(b'DO_NOT_EXECUTE', raw)
        self.assertEqual(seal, observer.identity(path.lstat()))

    def test_uid1000_parent_is_observable_but_not_root_custody(self):
        path, expected = self.fixture()
        try: os.chown(path.parent, 1000, 1000)
        except OSError:
            if os.environ.get('OUF_NATIVE_UIDS') == '1': raise
            self.skipTest('Requires native ownership fixture capability')
        path.parent.chmod(0o750)
        expected[str(path.parent)] = (1000, 1000, 0o750)
        raw, _ = observer.snapshot(path, expected)
        self.assertIn(b'DO_NOT_EXECUTE', raw)
        self.assertEqual(path.parent.lstat().st_uid, 1000)
        wrong = dict(expected); wrong[str(path.parent)] = (0, 0, 0o750)
        with self.assertRaises(ValueError): observer.snapshot(path, wrong)

    def test_literals_redacted_including_public_words_used_as_values(self):
        out = observer.redact(b'password="client_secret"\nx=10001\ncfg={"client_secret":"RAW_SECRET", "grant_type":"client_credentials"}\n')
        text = out['redactedSource']
        self.assertIn("'client_secret':", text)
        for secret in ('RAW_SECRET', '10001', "password = 'client_secret'", 'client_credentials'):
            self.assertNotIn(secret, text)

    def test_source_and_parent_symlinks_denied(self):
        path, expected = self.fixture()
        link = path.parent/'link.py'; link.symlink_to(path)
        with self.assertRaises(ValueError): observer.snapshot(link, expected)
        parent_link = path.parent/'alias'; parent_link.symlink_to(path.parent)
        with self.assertRaises(ValueError): observer.snapshot(parent_link/path.name, expected)

    def test_hardlinks_and_changed_custody_denied(self):
        path, expected = self.fixture()
        os.link(path, path.parent/'hardlink')
        with self.assertRaises(ValueError): observer.snapshot(path, expected)
        (path.parent/'hardlink').unlink()
        path.chmod(0o644)
        with self.assertRaises(ValueError): observer.snapshot(path, expected)

    def test_replacement_during_read_is_denied(self):
        path, expected = self.fixture(); original = os.read; replaced = False
        def read(fd, count):
            nonlocal replaced
            chunk = original(fd, count)
            if not replaced:
                replacement = path.parent/'replacement'
                replacement.write_bytes(path.read_bytes()); replacement.chmod(0o755)
                replacement.replace(path); replaced = True
            return chunk
        with patch.object(observer.os, 'read', side_effect=read):
            with self.assertRaises(ValueError): observer.snapshot(path, expected)

    def test_command_route_rejects_inline_and_wrong_unit_custody(self):
        good = 'Type=oneshot\nUser=root\nExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /opt/ouf/ops/refresh-policy-token.py semantic ; }'
        for wire in (good.replace('User=root', 'User=1000'),
                     'ExecStart={ path=/bin/sh ; argv[]=/bin/sh unsafe ; }\n'+good,
                     good.replace('/opt/ouf/ops/refresh-policy-token.py', '-c "do_bad_things"')):
            result = type('Result', (), {'returncode': 0, 'stdout': wire.encode()})()
            with patch.object(observer.subprocess, 'run', return_value=result):
                with self.assertRaises(ValueError): observer.routing()

    def test_nonregular_or_oversized_source_denied_before_read(self):
        path, expected = self.fixture()
        path.write_bytes(b'x' * 131073)
        with self.assertRaises(ValueError): observer.snapshot(path, expected)
        path.unlink(); os.mkfifo(path, 0o755)
        with self.assertRaises(ValueError): observer.snapshot(path, expected)

    def test_successful_observation_never_promotes_authentication_or_authority(self):
        path, expected = self.fixture(); raw, seal = observer.snapshot(path, expected)
        flags = type('Flags', (), {'isolated': 1})()
        stream = io.StringIO()
        with patch('sys.flags', flags), patch('sys.dont_write_bytecode', True), \
             patch.object(observer, 'routing', return_value=('sealed-route',)), \
             patch.object(observer, 'snapshot', return_value=(raw, seal)), \
             contextlib.redirect_stdout(stream):
            self.assertEqual(observer.main(), 0)
        report = json.loads(stream.getvalue().partition('=')[2])
        for name in ('sourceAuthenticationProven', 'writerAuthorityProven',
                     'runtimeAuthorityIssued', 'outputBindingProven', 'producerExecuted'):
            self.assertFalse(report[name])
        self.assertEqual(report['sourceContentBytesRead'], 2 * len(raw))
        self.assertNotIn('DO_NOT_EXECUTE', report['redactedSource'])

if __name__ == '__main__': unittest.main()
