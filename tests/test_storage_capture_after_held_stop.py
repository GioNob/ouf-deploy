"""Capture continuation boundaries; no target, engine or systemd operations."""
import importlib.util
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('capture_only', ROOT / 'scripts/capture-storage-after-held-stop-20261107.py')
c = importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class FakeCaptureRunner:
    def __init__(self, root, seconds):self.calls = []
    def docker(self, *args, **kwargs):self.calls.append(args);return b''

class ContinuationTests(unittest.TestCase):
    def test_provider_mutations_are_rejected_by_capture_runner(self):
        run = c.capture_runner({'Runner': FakeCaptureRunner}, None, time.monotonic()+60)
        for args in [('update','x'),('kill','x'),('start','x'),('exec','x'),('rm','x'),('restart','x'),('image','rm','x'),('network','create','x')]:
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, 'CAPTURE_DOCKER_READ_ONLY'):run.docker(*args)
        self.assertEqual(run.calls, [])
        run.docker('image','save','x');run.docker('export','x')
        self.assertEqual(len(run.calls),2)

    def test_explicit_exact_decision_required_before_reads(self):
        with self.assertRaisesRegex(ValueError, 'EXACT_CAPTURE_CONTINUATION_DECISION'):
            c.execute(None,None,None,None,None,None,None,'wrong','unused')

    def test_existing_scope_cannot_be_replayed_or_adopted(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(c,'AREA',Path(directory)):
            with self.assertRaisesRegex(ValueError,'CAPTURE_CONTINUATION_ALREADY_CLAIMED'):
                c.execute(None,None,None,None,None,None,None,c.DECISION,'unused')

    def test_expiry_not_renewed_and_no_new_claim(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(c,'AREA',Path(directory)/'absent'):
            with patch.object(c,'sealed_stop',return_value={'plan':{'validUntilEpoch':time.time()+100}}):
                with self.assertRaisesRegex(ValueError,'ORIGINAL_CAPTURE_WINDOW_INSUFFICIENT'):
                    c.execute(None,None,None,None,None,None,None,c.DECISION,'unused')
            self.assertFalse(c.AREA.exists())

    def test_operator_report_digest_mismatch_stops_before_other_reads(self):
        reader = types.SimpleNamespace(review=lambda *a: {})
        h = {'canonical':lambda x:b'{}', 'digest':lambda x:'different'}
        with self.assertRaisesRegex(ValueError,'EXACT_OPERATOR_READBACK_REQUIRED'):
            c.sealed_stop(h,reader,None,None,None)

if __name__ == '__main__':unittest.main()
