"""Deadline contracts and Linux/root contention on the unchanged v1 lock."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.semantic_provider_admission_v2 import locking as L

NATIVE = os.environ.get("OUF_ADMISSION_V2_NATIVE") == "1"
if NATIVE and (sys.platform != "linux" or os.geteuid() != 0 or os.getegid() != 0):
    raise RuntimeError("OUF_ADMISSION_V2_NATIVE requires Linux root:root; refusing to skip")


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.now = 10.0
        self.attempts, self.sleeps, self.closed = [], [], []
        self.errors = []

        @contextmanager
        def lock(path):
            self.attempts.append(path)
            error = self.errors.pop(0) if self.errors else None
            if error:
                raise error
            try:
                yield
            finally:
                self.closed.append(path)

        def sleep(delay):
            self.sleeps.append(delay)
            self.now += delay

        self.enterContext(patch.dict(sys.modules, {
            "tools.semantic_provider_lease_coordination": SimpleNamespace(hold_common_lock=lock)}))
        self.enterContext(patch.object(L, "time", SimpleNamespace(monotonic=lambda: self.now, sleep=sleep)))

    def test_contention_then_success_reuses_deadline(self):
        self.errors = [BlockingIOError(), BlockingIOError()]
        with L.wait_common_lock(Path("common.lock"), 10.2):
            self.assertEqual(len(self.attempts), 3)
        self.assertEqual(self.closed, [Path("common.lock")])
        self.assertEqual(self.sleeps, [.05, .05])

    def test_timeout_has_public_code_and_caps_last_sleep(self):
        self.errors = [BlockingIOError()] * 10
        with self.assertRaisesRegex(L.CommonLockTimeout, "^COMMON_LOCK_TIMEOUT$"):
            with L.wait_common_lock(Path("common.lock"), 10.075):
                self.fail("expired lock entered")
        self.assertEqual(len(self.attempts), 2)
        self.assertLessEqual(max(self.sleeps), .05)
        self.assertAlmostEqual(sum(self.sleeps), .075)

    def test_custody_permission_inode_errors_never_retry(self):
        for error in (PermissionError(), RuntimeError("PRIVATE_FILE_UNPROVEN"), FileNotFoundError()):
            with self.subTest(error=error):
                self.errors = [error]
                before = len(self.attempts)
                with self.assertRaises(type(error)) as caught:
                    with L.wait_common_lock(Path("common.lock"), 11):
                        self.fail("unproven custody entered")
                self.assertIs(caught.exception, error)
                self.assertEqual(len(self.attempts), before + 1)
                self.assertEqual(self.sleeps, [])

    def test_blocking_error_in_body_is_not_retried(self):
        error = BlockingIOError("body")
        with self.assertRaises(BlockingIOError) as caught:
            with L.wait_common_lock(Path("common.lock"), 11):
                raise error
        self.assertIs(caught.exception, error)
        self.assertEqual(len(self.attempts), 1)
        self.assertEqual(len(self.closed), 1)

    def test_expired_and_nonfinite_deadline_never_attempt(self):
        for deadline in (9, 10):
            with self.assertRaises(L.CommonLockTimeout):
                with L.wait_common_lock(Path("common.lock"), deadline):
                    self.fail("expired lock entered")
        for deadline in (float("inf"), float("nan"), None, True):
            with self.assertRaisesRegex(ValueError, "COMMON_LOCK_DEADLINE_REQUIRED"):
                with L.wait_common_lock(Path("common.lock"), deadline):
                    self.fail("unbounded lock entered")
        self.assertEqual(self.attempts, [])


CHILD = r'''
import importlib.util,json,pathlib,sys,time
root,lock,mode,seconds=sys.argv[1:]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec); sys.modules[name]=m; spec.loader.exec_module(m)
    return m
v1=load('tools.semantic_provider_lease_coordination',pathlib.Path(root)/'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_lease_coordination.py')
v2=load('common_lock_test',pathlib.Path(root)/'tools/semantic_provider_admission_v2/locking.py')
if mode=='hold':
    with v1.hold_common_lock(pathlib.Path(lock)):
        print('HELD',flush=True); time.sleep(float(seconds))
else:
    start=time.monotonic()
    try:
        with v2.wait_common_lock(pathlib.Path(lock),start+float(seconds)): result='ACQUIRED'
    except Exception as error: result=str(error)
    print(json.dumps({'result':result,'elapsed':time.monotonic()-start}))
'''


@unittest.skipUnless(NATIVE, "set OUF_ADMISSION_V2_NATIVE=1 under Linux root:root")
class NativeTests(unittest.TestCase):
    def contention(self, budget, expected, corrupt=False):
        with tempfile.TemporaryDirectory(prefix="ouf-v2-lock-", dir="/var/lib") as folder:
            lock = Path(folder) / "common.lock"
            lock.write_bytes(b"")
            lock.chmod(0o600)
            identity = lock.stat().st_ino
            argv = [sys.executable, "-I", "-B", "-c", CHILD, str(ROOT), str(lock)]
            holder = subprocess.Popen([*argv, "hold", "1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                # communicate/poll are bounded even if custody fails before HELD.
                import selectors
                with selectors.DefaultSelector() as ready:
                    ready.register(holder.stdout, selectors.EVENT_READ)
                    self.assertTrue(ready.select(5), "holder did not acquire lock")
                self.assertEqual(holder.stdout.readline().strip(), "HELD")
                if corrupt:
                    lock.chmod(0o640)
                result = subprocess.run([*argv, "wait", str(budget)], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                row = json.loads(result.stdout)
                self.assertEqual(row["result"], expected)
                self.assertLess(row["elapsed"], budget + .5)
                self.assertEqual(lock.stat().st_ino, identity)
                if expected == "ACQUIRED":
                    self.assertGreater(row["elapsed"], .1)
                elif expected == "COMMON_LOCK_TIMEOUT":
                    self.assertGreaterEqual(row["elapsed"], budget)
                else:
                    self.assertLess(row["elapsed"], .5)
            finally:
                holder.communicate(timeout=5)
            self.assertEqual(holder.returncode, 0)

    def test_second_process_waits_then_acquires(self):
        self.contention(3, "ACQUIRED")

    def test_second_process_times_out(self):
        self.contention(.15, "COMMON_LOCK_TIMEOUT")

    def test_bad_custody_denied_while_another_process_holds_lock(self):
        self.contention(3, "PRIVATE_FILE_UNPROVEN", corrupt=True)


if __name__ == "__main__":
    unittest.main()
