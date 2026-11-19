"""Boundary fixtures only: these tests never create a real generation29 receipt."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cohort29', ROOT / 'scripts/verify-seaweedfs-452-generation29-cohort.py')
cohort = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cohort)


class BoundaryTests(unittest.TestCase):
    def fixture_lock(self):
        manifest = cohort.MANIFEST
        return {'schema': 'ouf.storage-candidate-lock.v2', 'status': 'EVIDENCE_PREPARED_NOT_ADMITTED',
                'generation': 29, 'orderedPatchCount': 29, 'producerCommit': 'a' * 40,
                'buildManifest': {'sha256': cohort.sha(cohort.MANIFEST_PATH),
                                  'patchedSourceTree': manifest['build']['patchedSourceTree']},
                'buildProfile': copy.deepcopy(manifest['build']),
                'image': {'upstreamLicenceSha256': cohort.UPSTREAM_LICENCE_SHA},
                'qualification': {'allJobsPassed': True, 'runId': 1, 'runAttempt': 1,
                                  'workflow': '.github/workflows/storage-452-generation29-image.yml',
                                  'vulnerabilitySubgate': 'PASS_RAW',
                                  'rawSeverityCounts': {s: 0 for s in ['HIGH', 'CRITICAL', 'UNKNOWN', 'LOW', 'MEDIUM']}},
                'licenceRebinding': {'path': 'evidence/seaweedfs-452-generation29-licence-rebinding-local-20261103.json', 'sha256': '3' * 64},
                'producerArtifact': {'id': 1, 'bytes': 1, 'digest': 'sha256:' + '1' * 64},
                'independentReadback': {'id': 2, 'bytes': 1, 'digest': 'sha256:' + '2' * 64},
                'releaseAdmitted': False, 'runtimeAuthorityIssued': False, 'targetOperations': 0}

    def test_generation15_and_old_binary_are_denied(self):
        for field, value in [('generation', 15), ('orderedPatchCount', 15), ('schema', 'ouf.storage-candidate-lock.v1')]:
            lock = self.fixture_lock();lock[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'GENERATION29_LOCK'):
                cohort.validate_lock(lock)
        lock = self.fixture_lock();lock['buildProfile']['binarySha256'] = cohort.OLD_BINARY
        with self.assertRaisesRegex(ValueError, 'REVIEWED_GENERATION29_BUILD'):
            cohort.validate_lock(lock)

    def test_authority_or_release_claim_is_denied(self):
        for field, value in [('releaseAdmitted', True), ('runtimeAuthorityIssued', True), ('targetOperations', 1)]:
            lock = self.fixture_lock();lock[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'NO_ADMISSION_OR_AUTHORITY'):
                cohort.validate_lock(lock)

    def test_unfinished_failed_or_other_workflow_is_denied(self):
        for key, value in [('allJobsPassed', False), ('vulnerabilitySubgate', 'HELD_RAW_FINDINGS'), ('workflow', '.github/workflows/storage-sdk-lifecycle.yml')]:
            lock = self.fixture_lock();lock['qualification'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'SUCCESSFUL_GENERATION29'):
                cohort.validate_lock(lock)

    def test_high_critical_unknown_cannot_be_transferred_as_pass(self):
        for severity in ['HIGH', 'CRITICAL', 'UNKNOWN']:
            lock = self.fixture_lock();lock['qualification']['rawSeverityCounts'][severity] = 1
            with self.subTest(severity=severity), self.assertRaisesRegex(ValueError, 'SUCCESSFUL_GENERATION29'):
                cohort.validate_lock(lock)

    def test_all_raw_severities_required_without_boolean_counts(self):
        for value in [True, -1, '0']:
            lock = self.fixture_lock();lock['qualification']['rawSeverityCounts']['LOW'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'COMPLETE_RAW_SEVERITY'):
                cohort.validate_lock(lock)
        lock = self.fixture_lock();del lock['qualification']['rawSeverityCounts']['MEDIUM']
        with self.assertRaisesRegex(ValueError, 'COMPLETE_RAW_SEVERITY'):
            cohort.validate_lock(lock)

    def test_low_medium_are_recorded_without_implying_legal_acceptance(self):
        lock = self.fixture_lock();lock['qualification']['rawSeverityCounts'].update(LOW=2, MEDIUM=1)
        cohort.validate_lock(lock)
        self.assertFalse(lock['releaseAdmitted'])

    def test_changed_manifest_tree_toolchain_or_licence_is_denied(self):
        for group, key, value in [('buildManifest', 'sha256', '0' * 64), ('buildManifest', 'patchedSourceTree', '0' * 40),
                                  ('buildProfile', 'go', '1.27.2'), ('buildProfile', 'tags', ['rclone']),
                                  ('image', 'upstreamLicenceSha256', '0' * 64)]:
            lock = self.fixture_lock();lock[group][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'REVIEWED_GENERATION29_BUILD'):
                cohort.validate_lock(lock)

    def test_artifact_identity_cannot_be_null_or_placeholder(self):
        for value in [None, 0, True, 'pending']:
            lock = self.fixture_lock();lock['producerArtifact']['id'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'EXACT_PUBLISHED_ARTIFACT'):
                cohort.validate_lock(lock)

    def test_module_inventory_versions_and_sums_are_exact(self):
        raw = b'fixture: go1.27.3\n\tdep\texample.org/a\tv1.0.0\th1:fixture\n'
        row = raw.decode().splitlines()[1] + '\n'
        manifest = {'build': {'binaryModuleRows': 1, 'binaryModuleInventorySha256': hashlib.sha256(row.encode()).hexdigest()}}
        self.assertEqual(cohort.binary_modules(raw, manifest), [('example.org/a', 'v1.0.0', 'h1:fixture')])
        for changed in [raw.replace(b'v1.0.0', b'v1.0.1'), raw.replace(b'h1:fixture', b'h1:other'), raw + b'\t=>\texample.org/replaced\tv1.0.0\n']:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                cohort.binary_modules(changed, manifest)

    def test_archive_tamper_duplicate_and_traversal_are_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'fixture.zip'
            with zipfile.ZipFile(path, 'w') as z:z.writestr('../escape', b'fixture')
            with self.assertRaisesRegex(ValueError, 'SAFE_ARCHIVE_PATH'):
                cohort.checked_archive(path, cohort.sha(path))
            with zipfile.ZipFile(path, 'w') as z:z.writestr('safe', b'fixture')
            with self.assertRaisesRegex(ValueError, 'EXACT_ARCHIVE_REQUIRED'):
                cohort.checked_archive(path, '0' * 64)
            with warnings.catch_warnings(), zipfile.ZipFile(path, 'a') as z:
                warnings.simplefilter('ignore', UserWarning);z.writestr('safe', b'duplicate')
            with self.assertRaisesRegex(ValueError, 'UNIQUE_BOUNDED'):
                cohort.checked_archive(path, cohort.sha(path))

    def test_manifest_must_cover_all_retained_texts_and_hashes(self):
        raw = b'licence fixture';digest = hashlib.sha256(raw).hexdigest()
        good = {'LICENSE': raw, 'SHA256SUMS': (digest + '  LICENSE\n').encode()}
        cohort.check_manifest_members(good)
        for changed in [dict(good, LICENSE=b'other'), dict(good, EXTRA=b'hidden')]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                cohort.check_manifest_members(changed)

    def test_existing_output_prevents_any_reprocessing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'NEW_COHORT_OUTPUT'):
                cohort.verify(*([path / 'missing'] * 8), path)


if __name__ == '__main__':
    unittest.main()
