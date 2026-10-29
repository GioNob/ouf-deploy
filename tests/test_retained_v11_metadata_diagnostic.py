"""Drift classification without mounted file reads or baseline updates."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

diag = load('metadata_diagnostic', 'scripts/read-retained-v11-metadata-drift.py')
fixtures = load('expectations_fixture', 'tests/test_retained_v11_source_expectations.py')
planner_raw = (ROOT / 'scripts/prepare-retained-v11-source-expectations.py').read_bytes()
atomic_raw = (ROOT / 'tools/semantic_application_cutover/atomic_review_intake.py').read_bytes()


class Diagnostic(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.Expectations()
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        bindings, self.originals = self.fixture.fixture(mixed=True)
        self.p = diag.planner(planner_raw)
        for key, value in bindings.items():
            if key != 'sys': setattr(self.p, key, value)
        self.atomic = self.p.atomic_source(atomic_raw)

    def entry(self):
        output = io.StringIO()
        scoped = types.SimpleNamespace(flags=types.SimpleNamespace(isolated=1),
                                       dont_write_bytecode=True, argv=['fixture'])
        with patch.object(diag, 'planner', return_value=self.p), patch.object(diag, 'sys', scoped), \
                patch.dict(diag.__dict__, {'__atomic_source__': atomic_raw}), contextlib.redirect_stdout(output):
            code = diag.main()
        return code, json.loads(output.getvalue().split('=', 1)[1]), output.getvalue()

    def test_stable_metadata_diagnosis_never_accepts_or_writes_baseline(self):
        code, report, text = self.entry()
        self.assertEqual(code, 0); self.assertFalse(report['metadataDriftDetected'])
        self.assertFalse(report['baselineRefreshed']); self.assertFalse(report['runtimeAuthorityIssued'])
        self.assertEqual(report['sourceContentBytesRead'], 0); self.assertEqual(report['protectedFileWrites'], 0)
        self.assertNotIn('DO_NOT_PRINT', text); self.assertNotIn('legacy.private', text)
        self.assertEqual(len(list(self.p.BASE.iterdir())), 1)
        for name, raw in self.originals.items(): self.assertEqual((self.p.PARENT / name).read_bytes(), raw)

    def test_directory_mode_member_mode_and_extra_entry_drift_are_redacted(self):
        self.fixture.directory.chmod(0o700); self.fixture.member.chmod(0o600)
        (self.fixture.directory / 'PRIVATE_NEW_MEMBER_NAME').write_bytes(b'PRIVATE_NEW_MEMBER_CONTENT')
        code, report, text = self.entry()
        self.assertEqual(code, 0); self.assertTrue(report['metadataDriftDetected'])
        mount = report['metadataComparison'][0]
        self.assertIn('mode', mount['entries'][0]['changedFields'])
        self.assertIn('mode', mount['entries'][1]['changedFields'])
        self.assertFalse(mount['entrySetMatchesBaseline'])
        self.assertEqual(mount['currentDirectoryEntryCount'], 2)
        self.assertNotIn('PRIVATE_NEW', text); self.assertNotIn(str(self.fixture.directory), text)
        self.assertFalse(report['baselineRefreshed'])

    def test_snapshot_reads_no_file_bytes_and_never_follows_member_symlink(self):
        expected = self.fixture.metadata(self.fixture.directory)
        self.fixture.member.unlink(); self.fixture.member.symlink_to(self.fixture.file)
        with patch.object(diag.os, 'read', side_effect=AssertionError('SOURCE_CONTENT_READ')):
            rows, shape = diag.snapshot(self.p, self.fixture.binding(self.fixture.directory), expected)
        self.assertEqual(rows[1]['kind'], 'other')
        self.assertTrue(shape['entrySetMatchesBaseline'])

    def test_changed_between_observations_is_blocked_without_private_error_text(self):
        actual = diag.snapshot; calls = []
        def changing(*args):
            value = actual(*args)
            if not calls:
                calls.append(True); self.fixture.directory.chmod(0o700)
            return value
        with patch.object(diag, 'snapshot', side_effect=changing): code, report, text = self.entry()
        self.assertEqual(code, 1); self.assertEqual(report['reason'], 'RETAINED_DIAGNOSTIC_CHANGED_BETWEEN_READS')
        self.assertNotIn('legacy.private', text); self.assertEqual(report['protectedFileWrites'], 0)

    def test_pinned_dependency_and_unknown_error_redaction(self):
        with self.assertRaises(diag.Denied): diag.planner(planner_raw + b'\n')
        with patch.object(diag, 'snapshot', side_effect=RuntimeError('PRIVATE_ERROR_PAYLOAD')):
            code, report, text = self.entry()
        self.assertEqual(code, 1); self.assertEqual(report['reason'], 'RETAINED_METADATA_DIAGNOSTIC_UNPROVEN')
        self.assertNotIn('PRIVATE_ERROR_PAYLOAD', text)


if __name__ == '__main__': unittest.main()
