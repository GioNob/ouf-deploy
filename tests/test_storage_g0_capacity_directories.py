import importlib.util
import builtins
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_storage_g0_package as fixture
from tools.storage_planning import g0_package as p, g0_host as h

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('capacity_directories', ROOT / 'scripts/prepare-storage-g0-capacity-directories-20261106.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CapacityDirectoriesTests(unittest.TestCase):
    def setUp(self):
        self.mask = os.umask(0o077)
        original = tempfile.TemporaryDirectory
        anchor = '/var/lib' if os.environ.get('GITHUB_ACTIONS') == 'true' else str(Path.cwd())
        self.f = fixture.PackageTest()
        with patch.object(fixture.tempfile, 'TemporaryDirectory', lambda: original(dir=anchor)):
            self.f.setUp()
        self.stage = self.f.root / 'stage'
        self.inputs = self.stage / 'inputs'
        self.inputs.mkdir(parents=True, mode=0o700)
        self.old_dir = self.inputs / 'database-draft-continuation-20261106'
        self.old_dir.mkdir(mode=0o700)
        self.source = self.f.root / 'source'
        self.source.mkdir(mode=0o700)
        self.parent = self.f.root / 'data-parent'
        self.parent.mkdir(mode=0o700)
        self.area = self.parent / 'ouf-storage-migration'
        self.f.config['collectionDecisionRef'] = None
        self.f.config['capacityPaths'] = {'source': str(self.source),
            'destination': '/var/lib/ouf/seaweedfs', 'backup': '/opt/ouf/backup/seaweedfs'}
        self.old_path = self.old_dir / 'package-input.review.json'
        fixture.put(self.old_path, self.f.config)
        self.old_bytes = self.old_path.read_bytes()
        self.old_sha = m.sha(self.old_bytes)
        self.bindings = {'connection:' + key: m.sha(Path(value).read_bytes())
                         for key, value in self.f.config['connectionFiles'].items()}
        self.bindings['operator:runtime'] = m.sha(Path(self.f.config['operatorEvidenceFiles']['runtime']).read_bytes())

    def tearDown(self):
        self.f.doCleanups()
        os.umask(self.mask)

    def run_prepare(self, **kwargs):
        def observed_capacity(paths):
            # Local sandbox has no /proc/meminfo. CI must use the real proc file.
            if os.environ.get('GITHUB_ACTIONS') != 'true' and not Path('/proc/meminfo').exists():
                original_open = builtins.open
                def fixture_open(path, *args, **options):
                    if str(path) == '/proc/meminfo':
                        return io.BytesIO(b'MemTotal: 1024 kB\nMemAvailable: 512 kB\nSwapFree: 0 kB\n')
                    return original_open(path, *args, **options)
                with patch('builtins.open', side_effect=fixture_open):
                    return h.capacity(paths)
            return h.capacity(paths)
        options = dict(staging=self.stage, area=self.area, bundle=self.f.bundle,
            manifest_sha=self.f.digest, input_sha=self.old_sha, preflight=p.preflight, capacity=observed_capacity,
            expected_bindings=self.bindings)
        options.update(kwargs)
        return m.prepare(**options)

    def test_new_empty_directories_and_changed_input_pass_original_check(self):
        with patch.object(p, 'Engine', side_effect=AssertionError('provider forbidden')):
            result = self.run_prepare()
        self.assertEqual(result['status'], 'CAPACITY_DIRECTORIES_PREPARED_LOCAL_INPUTS_BOUND_REVIEW_REQUIRED')
        self.assertEqual(result['dataDirectoriesCreated'], 3)
        self.assertTrue(result['capacityEvidencePrepared'])
        self.assertNotIn('OPERATOR_CAPACITY', result['operatorInputsMissing'])
        self.assertIn('COLLECTION_DECISION_REFERENCE', result['operatorInputsMissing'])
        self.assertFalse(result['capacitySufficiencyProven'])
        self.assertFalse(result['independentBackupVerified'])
        self.assertEqual(self.old_path.read_bytes(), self.old_bytes)
        self.assertEqual(list(self.f.output.iterdir()), [])
        for name in ('seaweedfs', 'backup-staging'):
            directory = self.area / name
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(directory.iterdir()), [])
        candidate = json.loads(Path(result['candidateInputFile']).read_text())
        self.assertEqual(candidate['connectionFiles'], self.f.config['connectionFiles'])
        self.assertEqual(candidate['priorReceiptFiles'], self.f.config['priorReceiptFiles'])
        self.assertIsNone(candidate['collectionDecisionRef'])
        doc = json.loads(Path(candidate['operatorEvidenceFiles']['capacity']).read_text())
        self.assertFalse(doc['operatorAcceptance'])
        self.assertFalse(doc['sourceCustodyAdmitted'])
        self.assertEqual(doc['observation']['schema'], 'ouf.storage-g0-capacity-observation.v1')

    def test_existing_area_and_contents_are_never_adopted_or_changed(self):
        self.area.mkdir(mode=0o755)
        sentinel = self.area / 'keep'
        sentinel.write_bytes(b'existing-content')
        before = (self.area.stat().st_mode, sentinel.read_bytes())
        with self.assertRaisesRegex(m.Held, 'CAPACITY_AREA_ALREADY_EXISTS_NO_ADOPTION'):
            self.run_prepare()
        self.assertEqual(before, (self.area.stat().st_mode, sentinel.read_bytes()))
        self.assertFalse((self.inputs / m.SCOPE).exists())

    def test_area_symlink_is_denied_without_following_it(self):
        self.area.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(m.Held, 'CAPACITY_AREA_ALREADY_EXISTS_NO_ADOPTION'):
            self.run_prepare()
        self.assertTrue(self.area.is_symlink())
        self.assertEqual(list(self.source.iterdir()), [])

    def test_changed_input_denied_before_any_creation(self):
        self.old_path.write_bytes(self.old_bytes + b'\n')
        with self.assertRaisesRegex(m.Held, 'CAPACITY_EXACT_CHECKED_INPUT_REQUIRED'):
            self.run_prepare()
        self.assertFalse(self.area.exists())
        self.assertFalse((self.inputs / m.SCOPE).exists())

    def test_writable_parent_is_denied_without_permission_repair(self):
        self.parent.chmod(0o777)
        with self.assertRaisesRegex(m.Held, 'CAPACITY_ROOT_PROTECTED_ANCESTRY'):
            self.run_prepare()
        self.assertEqual(self.parent.stat().st_mode & 0o777, 0o777)
        self.assertFalse(self.area.exists())

    def test_changed_connection_binding_denied_before_any_creation(self):
        path = Path(self.f.config['connectionFiles']['udp'])
        row = json.loads(path.read_text())
        row['user'] = 'different'
        fixture.put(path, row)
        with self.assertRaisesRegex(m.Held, 'CAPACITY_CHECKED_BINDING_CHANGED'):
            self.run_prepare()
        self.assertFalse(self.area.exists())
        self.assertFalse((self.inputs / m.SCOPE).exists())

    def test_partial_directory_failure_preserved_without_retry(self):
        mkdir = os.mkdir
        def fail(path, *args, **kwargs):
            if path == 'backup-staging':
                raise OSError('private filesystem detail')
            return mkdir(path, *args, **kwargs)
        with patch.object(m.os, 'mkdir', side_effect=fail):
            result = self.run_prepare()
        self.assertEqual(result['status'], 'HELD')
        self.assertEqual(result['dataDirectoriesCreated'], 2)
        self.assertEqual(result['dataDirectoryCreatesAttempted'], 3)
        self.assertNotIn('private filesystem detail', json.dumps(result))
        self.assertTrue((self.area / 'seaweedfs').exists())
        with patch.object(m.os, 'mkdir', side_effect=AssertionError('replayed')):
            again = self.run_prepare()
        self.assertTrue(again.pop('existingResultReadOnly'))
        self.assertEqual(again, result)

    def test_deadline_does_not_create_data_directories_or_reset(self):
        times = iter([0, 61])
        result = self.run_prepare(clock=lambda: next(times))
        self.assertEqual(result['reason'], 'CAPACITY_PREPARATION_DEADLINE')
        self.assertEqual(result['dataDirectoriesCreated'], 0)
        self.assertFalse(self.area.exists())
        self.assertTrue(self.run_prepare()['existingResultReadOnly'])

    def test_scope_without_result_is_preserved(self):
        scope = self.inputs / m.SCOPE
        scope.mkdir(mode=0o700)
        fixture.put(scope / 'claim.json', {'consumed': True})
        with self.assertRaises(FileNotFoundError):
            self.run_prepare()
        self.assertTrue((scope / 'claim.json').exists())
        self.assertFalse(self.area.exists())

    def test_original_preflight_failure_keeps_new_files_and_no_collection(self):
        def failed(*args):
            raise ValueError('private connection detail')
        result = self.run_prepare(preflight=failed)
        self.assertEqual(result['status'], 'HELD')
        self.assertEqual(result['dataDirectoriesCreated'], 3)
        self.assertNotIn('private connection', json.dumps(result))
        self.assertTrue((self.inputs / m.SCOPE / 'package-input.review.json').exists())
        self.assertEqual(list(self.f.output.iterdir()), [])
        self.assertTrue(self.run_prepare(preflight=lambda *_: self.fail('replayed'))['existingResultReadOnly'])

    def test_package_integrity_before_import(self):
        m.verify_bundle(self.f.bundle, self.f.digest)
        fixture.put(self.f.bundle / 'member', b'changed')
        with self.assertRaisesRegex(m.Held, 'CAPACITY_PACKAGE_SOURCE_CHANGED'):
            m.verify_bundle(self.f.bundle, self.f.digest)


if __name__ == '__main__':
    unittest.main()
