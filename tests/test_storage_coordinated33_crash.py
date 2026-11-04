"""Crash evidence must establish process death and a durable post-PUT boundary."""
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('crash33', ROOT / 'scripts/run-storage-coordinated33-lab.py')
cut = importlib.util.module_from_spec(spec); spec.loader.exec_module(cut)


class WorkerCrashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.marker = Path(self.temp.name) / 'marker.json'
        self.marker.write_text(json.dumps(cut.worker_marker()))

    def result(self, code=-signal.SIGKILL, stdout=b'', stderr=b''):
        return subprocess.CompletedProcess(['fixture-worker'], code, stdout, stderr)

    def test_real_sigkill_is_observed_from_distinct_process(self):
        result = cut.postgres.native.run([sys.executable, '-I', '-B', '-S', '-c',
            'import os,signal;os.kill(os.getpid(),signal.SIGKILL)'], timeout=5)
        report = cut.validate_crash(result, self.marker)
        self.assertEqual(-9, report['workerReturnCode'])
        self.assertEqual(1, report['putRequests'])
        self.assertEqual(cut.postgres.native.digest(self.marker), report['markerSha256'])

    def test_normal_exit_or_other_signal_is_not_injected_crash(self):
        for code in (0, 1, 137, -signal.SIGTERM):
            with self.subTest(code=code), self.assertRaisesRegex(RuntimeError, 'EXACT_WORKER_SIGKILL'):
                cut.validate_crash(self.result(code), self.marker)

    def test_output_or_traceback_prevents_success(self):
        for result in (self.result(stdout=b'ACK'), self.result(stderr=b'error')):
            with self.assertRaisesRegex(RuntimeError, 'OUTPUT_MUST_BE_EMPTY'):
                cut.validate_crash(result, self.marker)

    def test_missing_marker_cannot_claim_post_put_crash(self):
        self.marker.unlink()
        with self.assertRaisesRegex(RuntimeError, 'BOUNDED_DURABLE_CRASH_MARKER'):
            cut.validate_crash(self.result(), self.marker)

    def test_symlink_or_oversized_marker_rejected(self):
        linked = self.marker.with_name('link'); linked.symlink_to(self.marker)
        with self.assertRaisesRegex(RuntimeError, 'BOUNDED_DURABLE_CRASH_MARKER'):
            cut.validate_crash(self.result(), linked)
        self.marker.write_bytes(b'x' * 4097)
        with self.assertRaisesRegex(RuntimeError, 'BOUNDED_DURABLE_CRASH_MARKER'):
            cut.validate_crash(self.result(), self.marker)

    def test_wrong_phase_body_or_second_put_rejected(self):
        for key, value in [('phase', 'BEFORE_PUT'), ('sha256', '0' * 64), ('bytes', 0),
                           ('putRequests', 2), ('operation', 'lab-other')]:
            changed = cut.worker_marker(); changed[key] = value
            self.marker.write_text(json.dumps(changed))
            with self.assertRaisesRegex(RuntimeError, 'EXACT_POST_PUT_CRASH_PHASE'):
                cut.validate_crash(self.result(), self.marker)

    def test_marker_persistence_is_exclusive(self):
        with self.assertRaises(FileExistsError):
            cut.fence.persist_body(self.marker, b'cannot replace evidence')

    def test_existing_marker_denies_launch_before_effect(self):
        with self.assertRaisesRegex(RuntimeError, 'FRESH_CRASH_MARKER'):
            cut.crash_client(self.marker)


if __name__ == '__main__': unittest.main()
