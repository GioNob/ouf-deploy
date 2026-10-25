"""Real root-owned fixture files/umask; synthetic retained target history only."""
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / 'releases/resume-acquisition-descriptor-read-mode-20261025.sh'


def helper_source():
    source = WRAPPER.read_text()
    return source[source.index('import errno,'):source.index('\nPY\n')]


class ModeContinuationTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, 'Run this native filesystem fixture as root; do not skip it.')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.root.chmod(0o755)
        self.owner = 1001
        self.scope = {'__name__': 'fixture'}
        exec(compile(helper_source(), str(WRAPPER), 'exec'), self.scope)
        home = self.root / 'operator'
        boot = home / 'ouf-descriptor-bootstrap.mIZy6zES'
        delivery = home / 'ouf-acquisition-descriptor-read-delivery.XdyYVHv1'
        public = self.root / 'code'
        for path in (home, boot, delivery, delivery / 'permission-mode-v1'):
            path.mkdir(mode=0o700)
            os.chown(path, self.owner, self.owner)
        public.mkdir(mode=0o755)
        self.scope.update(HOME=str(home), BOOTSTRAP=str(boot), DELIVERY=str(delivery), CODEDIR=str(public),
                          CODE=str(public / 'read.py'), CLAIM=str(home / 'ouf-acquisition-permission-descriptor-read-20261025'),
                          JOURNAL=str(public / 'permission-mode-v1.json'))
        original = (ROOT / 'tests/fixtures/acquisition-descriptor-retained-wrapper-077065.sh').read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), self.scope['WRAPPERHASH'])
        code = (ROOT / 'scripts/read-acquisition-permission-descriptors-20261025.py').read_bytes()
        self.assertEqual(hashlib.sha256(code).hexdigest(), self.scope['CODEHASH'])
        for path, raw in ((boot / 'run.sh', original), (delivery / 'read.py', code)):
            path.write_bytes(raw)
            path.chmod(0o600)
            os.chown(path, self.owner, self.owner)
        log = ('ProtectedCode=' + str(public / 'read.py') + '\n'
               + str(public / 'read.py') + ': FAILED open or read\nDeliveryExit=1\nDeliveryDirectory=' + str(delivery) + '\n')
        (delivery / 'bootstrap.log').write_text(log)
        (delivery / 'bootstrap.log').chmod(0o600)
        os.chown(delivery / 'bootstrap.log', self.owner, self.owner)
        # Reproduce the old root copy with a real restrictive umask, not a mocked stat.
        previous = os.umask(0o077)
        try:
            fd = os.open(public / 'read.py', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
            os.write(fd, code)
            os.fsync(fd)
            os.close(fd)
        finally:
            os.umask(previous)
        public.chmod(0o555)
        self.code = public / 'read.py'
        self.assertEqual(stat.S_IMODE(self.code.stat().st_mode), 0o400)
        self.log_hash = hashlib.sha256((delivery / 'bootstrap.log').read_bytes()).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def run_helper(self):
        return self.scope['reconcile'](self.owner)

    def assert_blocked(self, reason):
        with self.assertRaisesRegex(self.scope['Stop'], reason):
            self.run_helper()
        self.assertFalse(Path(self.scope['JOURNAL']).exists())

    def unprivileged_read(self, allowed):
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([])
                os.setgid(self.owner)
                os.setuid(self.owner)
                try:
                    raw = self.code.read_bytes()
                except PermissionError:
                    os._exit(0 if not allowed else 3)
                os._exit(0 if allowed and hashlib.sha256(raw).hexdigest() == self.scope['CODEHASH'] else 4)
            except BaseException:
                os._exit(5)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_real_umask_077_reproduces_denial_then_one_fd_chmod_restores_operator_read(self):
        before = self.code.stat()
        self.unprivileged_read(False)
        result = self.run_helper()
        after = self.code.stat()
        self.unprivileged_read(True)
        self.assertEqual(result['state'], 'APPLIED')
        self.assertEqual(result['chmodOperations'], 1)
        self.assertEqual(self.scope['identity'](before), self.scope['identity'](after))
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o444)
        self.assertEqual(stat.S_IMODE(Path(self.scope['JOURNAL']).stat().st_mode), 0o400)
        self.assertEqual(hashlib.sha256((Path(self.scope['DELIVERY']) / 'bootstrap.log').read_bytes()).hexdigest(), self.log_hash)
        self.assertFalse(Path(self.scope['CLAIM']).exists())
        self.assertEqual(result['iamRequests'], 0)
        self.assertEqual(result['ownerRequests'], 0)

    def test_replay_blocked_and_retained_proof_unchanged(self):
        self.run_helper()
        journal = Path(self.scope['JOURNAL']).read_bytes()
        with self.assertRaisesRegex(self.scope['Stop'], 'CONSUMED_OR_STARTED_SCOPE_NO_REPLAY'):
            self.run_helper()
        self.assertEqual(Path(self.scope['JOURNAL']).read_bytes(), journal)

    def test_mode_already_0444_is_unknown_failure_not_a_repair(self):
        self.code.chmod(0o444)
        self.assert_blocked('EXACT_RETAINED_FILE_REQUIRED')

    def test_wrong_bytes_block_before_claim(self):
        self.code.write_bytes(b'changed-public-code')
        self.assert_blocked('RETAINED_CODE_HASH_MISMATCH')

    def test_wrong_code_owner_blocked(self):
        os.chown(self.code, self.owner, self.owner)
        self.assert_blocked('EXACT_RETAINED_FILE_REQUIRED')

    def test_hardlink_blocked(self):
        os.link(self.code, self.root / 'other-link')
        self.assert_blocked('EXACT_RETAINED_FILE_REQUIRED')

    def test_symlink_blocked(self):
        self.code.unlink()
        self.code.symlink_to(Path(self.scope['DELIVERY']) / 'read.py')
        with self.assertRaises(OSError):
            self.run_helper()
        self.assertFalse(Path(self.scope['JOURNAL']).exists())

    def test_non_traversable_parent_is_not_chmodded(self):
        Path(self.scope['CODEDIR']).chmod(0o500)
        self.assert_blocked('EXACT_DIRECTORY_MODE_REQUIRED')
        self.assertEqual(stat.S_IMODE(Path(self.scope['CODEDIR']).stat().st_mode), 0o500)

    def test_started_diagnostic_scope_blocks(self):
        Path(self.scope['CLAIM']).mkdir()
        self.assert_blocked('CONSUMED_OR_STARTED_SCOPE_NO_REPLAY')

    def test_existing_operator_log_blocks(self):
        (Path(self.scope['DELIVERY']) / 'operator.log').write_text('retained')
        self.assert_blocked('CONSUMED_OR_STARTED_SCOPE_NO_REPLAY')

    def test_wrong_retained_bootstrap_blocks(self):
        (Path(self.scope['DELIVERY']) / 'bootstrap.log').write_text('unrelated failure')
        self.assert_blocked('EXACT_PRELOGIN_DELIVERY_FAILURE_REQUIRED')

    def test_explicit_acl_not_ignored_or_removed(self):
        real = os.getxattr
        def acl(path, name, **kwargs):
            if str(path) == str(self.code):
                return b'synthetic-explicit-acl'
            return real(path, name, **kwargs)
        with patch('os.getxattr', side_effect=acl):
            self.assert_blocked('EXPLICIT_ACL_REQUIRES_RECONCILIATION')

    def test_ambiguous_chmod_keeps_claimed_and_never_replays(self):
        original_fsync = os.fsync
        def fail_after_chmod(fd):
            info = os.fstat(fd)
            if info.st_ino == self.code.stat().st_ino and stat.S_IMODE(info.st_mode) == 0o444:
                raise OSError('synthetic lost persistence after chmod')
            return original_fsync(fd)
        with patch('os.fsync', side_effect=fail_after_chmod), self.assertRaises(OSError):
            self.run_helper()
        self.assertEqual(json.loads(Path(self.scope['JOURNAL']).read_text())['state'], 'CLAIMED')
        with self.assertRaisesRegex(self.scope['Stop'], 'CONSUMED_OR_STARTED_SCOPE_NO_REPLAY'):
            self.run_helper()


if __name__ == '__main__':
    unittest.main()
