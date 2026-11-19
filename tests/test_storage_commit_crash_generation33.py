import copy
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('commit33', ROOT/'scripts/storage-generation33-commit-crash.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)

class PhaseTests(unittest.TestCase):
    def fixture(self):
        before = {'.dat': {'bytes': 5243072, 'sha256': 'old', 'inode': 1}, '.idx': {'bytes': 48, 'inode': 2}}
        frozen = {**copy.deepcopy(before), '.cpd': {'bytes': 1048688, 'sha256': 'new', 'inode': 3},
                  '.cpx': {'bytes': 16, 'inode': 4}, '.cpc': {'bytes': 0}}
        syncs = [{'kind': 'marker', 'returnValue': 0}, {'kind': 'directory', 'returnValue': 0}]
        return before, frozen, {'12': 't', '13': 't'}, syncs

    def test_marker_copies_old_pair_and_ordered_syncs(self): c.validate_phase(*self.fixture())

    def test_missing_marker_or_copy(self):
        for ext in ('.cpc', '.cpd', '.cpx'):
            args = self.fixture(); del args[1][ext]
            with self.assertRaisesRegex(ValueError, 'BOTH_COPIES'): c.validate_phase(*args)

    def test_first_or_second_rename_already_happened(self):
        for ext in ('.dat', '.idx'):
            args = self.fixture(); args[1][ext]['inode'] += 100
            with self.assertRaisesRegex(ValueError, 'UNRENAMED'): c.validate_phase(*args)

    def test_partial_stop_or_sigstop_cannot_claim_ptrace_entry(self):
        for state in ('T', 'R', 'S'):
            args = self.fixture(); args[2]['13'] = state
            with self.assertRaisesRegex(ValueError, 'PTRACE'): c.validate_phase(*args)

    def test_missing_failed_or_reversed_fsync(self):
        for syncs in ([], [{'kind': 'directory', 'returnValue': 0}, {'kind': 'marker', 'returnValue': 0}],
                      [{'kind': 'marker', 'returnValue': -5}, {'kind': 'directory', 'returnValue': 0}]):
            args = self.fixture()
            with self.assertRaisesRegex(ValueError, 'FSYNC'): c.validate_phase(*args[:3], syncs)

    def test_preexisting_marker_or_empty_copy(self):
        args = self.fixture(); args[0]['.cpc'] = {'bytes': 0}
        with self.assertRaisesRegex(ValueError, 'CLEAN'): c.validate_phase(*args)
        for ext, size in (('.cpd', 8), ('.cpx', 0)):
            args = self.fixture(); args[1][ext]['bytes'] = size
            with self.assertRaisesRegex(ValueError, 'NONEMPTY'): c.validate_phase(*args)

    def test_exact_temporary_pair_promoted(self):
        frozen = self.fixture()[1]
        c.validate_pair(frozen, {'.dat': frozen['.cpd'], '.idx': frozen['.cpx']})

    def test_old_mixed_pair_or_copied_inode_rejected(self):
        frozen = self.fixture()[1]
        for ext in ('.dat', '.idx'):
            recovered = {'.dat': copy.deepcopy(frozen['.cpd']), '.idx': copy.deepcopy(frozen['.cpx'])}
            recovered[ext]['inode'] += 100
            with self.assertRaisesRegex(ValueError, 'INODES'): c.validate_pair(frozen, recovered)

    def test_lingering_commit_marker_rejected(self):
        frozen = self.fixture()[1]
        with self.assertRaisesRegex(ValueError, 'REMOVES'):
            c.validate_pair(frozen, {'.dat': frozen['.cpd'], '.idx': frozen['.cpx'], '.cpc': frozen['.cpc']})

    def test_mode_is_exclusive_before_any_environment_action(self):
        spec = importlib.util.spec_from_file_location('lab33_commit', ROOT/'scripts/run-storage-generation33-lateral-isolation.py')
        lab = importlib.util.module_from_spec(spec); spec.loader.exec_module(lab)
        for flag in ('crash_volume', 'crash_filer', 'crash_master', 'crash_all', 'interrupt_stream', 'cleanup_stream',
                     'compact_stream', 'restart_compact', 'relocate_live', 'crash_compact'):
            with self.assertRaisesRegex(ValueError, 'ONE_CRASH_ROLE'): lab.run(None, None, None, None, crash_commit=True, **{flag: True})

@unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Linux ptrace mechanics required')
class NativeObserverTests(unittest.TestCase):
    def test_hold_actual_syscall_and_new_thread_until_sigkill(self):
        # Own disposable child, native syscalls, no candidate storage and no mocking.
        code = '''
import os, pathlib, sys, threading, time
root=pathlib.Path(sys.argv[1]); stem=root/'ouf-identity-fixture_3'
threading.Thread(target=lambda: time.sleep(60),daemon=True).start()
(root/'ready').write_text('ready')
while not (root/'go').exists(): time.sleep(.002)
def commit():
    stem.with_suffix('.cpd').write_bytes(b'compacted-data-contents')
    stem.with_suffix('.cpx').write_bytes(b'compacted-index!')
    fd=os.open(stem.with_suffix('.cpc'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    os.fsync(fd);os.close(fd)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    os.rename(stem.with_suffix('.cpd'),stem.with_suffix('.dat'))
    os.rename(stem.with_suffix('.cpx'),stem.with_suffix('.idx'))
    (root/'unexpected-rename-completed').write_text('failed')
threading.Thread(target=commit).start()
time.sleep(60)
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); target = 'ouf-identity-fixture_3.dat'
            (root/target).write_bytes(b'old-data'*100)
            (root/target).with_suffix('.idx').write_bytes(b'old-index')
            before = c.pre.files(root, target)
            child = subprocess.Popen([sys.executable, '-I', '-B', '-S', '-c', code, tmp])
            observer = None
            try:
                deadline = time.monotonic()+10
                while not (root/'ready').exists():
                    self.assertLess(time.monotonic(), deadline); self.assertIsNone(child.poll()); time.sleep(.01)
                observer = c.Observer(child.pid, root, target, namespace_root=tmp)
                observer.attach(); (root/'go').write_text('go')
                phase = observer.observe(timeout=15); frozen = c.pre.files(root, target)
                c.validate_phase(before, frozen, phase['threadStates'], phase['successfulSyncs'])
                self.assertTrue(phase['cloneEvents']); self.assertGreaterEqual(len(phase['threadStates']), 3)
                self.assertEqual(phase['operation'], 'entry'); self.assertTrue(phase['syscallNotResumed'])
                self.assertFalse((root/'unexpected-rename-completed').exists())
                os.kill(child.pid, signal.SIGKILL); exits = observer.wait_for_kill(timeout=10)
                self.assertTrue(exits); self.assertEqual(c.pre.files(root, target), frozen)
                self.assertFalse((root/'unexpected-rename-completed').exists())
            finally:
                try: os.kill(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                if observer and observer.tids:
                    try: observer.wait_for_kill(timeout=5)
                    except (ValueError, ChildProcessError): pass
                child.wait(timeout=10)

if __name__ == '__main__': unittest.main()
