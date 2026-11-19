"""Boundary fixtures only: these tests never create a real generation32 receipt."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import shutil
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cohort32', ROOT / 'scripts/verify-seaweedfs-452-generation32-cohort.py')
cohort = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cohort)


class BoundaryTests(unittest.TestCase):
    def fixture_lock(self):
        manifest = cohort.MANIFEST
        return {'schema': 'ouf.storage-candidate-lock.v2', 'status': 'EVIDENCE_PREPARED_NOT_ADMITTED',
                'generation': 32, 'orderedPatchCount': 32, 'producerCommit': 'a' * 40,
                'buildManifest': {'path': cohort.readback.candidate.MANIFEST_PATH, 'sha256': cohort.sha(cohort.MANIFEST_PATH),
                                  'patchedSourceTree': manifest['build']['patchedSourceTree']},
                'buildProfile': copy.deepcopy(manifest['build']),
                'image': {'upstreamLicenceSha256': cohort.UPSTREAM_LICENCE_SHA},
                'modifiedMplSource': {'archiveSha256': cohort.MODIFIED_SOURCE_ARCHIVE_SHA, 'manifestSha256': cohort.MODIFIED_SOURCE_MANIFEST_SHA},
                'dependencyMaintenance': {'status': 'OPEN', 'allDependenciesMaintained': False},
                'sourceRevision': copy.deepcopy(manifest['sourceRevision']),
                'compiledDependencyPolicy': copy.deepcopy(manifest['compiledDependencyPolicy']),
                'mongoV2LegalDelta': {'path': cohort.MONGO_DELTA, 'sha256': cohort.sha(ROOT / cohort.MONGO_DELTA)},
                'qualification': {'allJobsPassed': True, 'runId': 1, 'runAttempt': 1,
                                  'workflow': '.github/workflows/storage-452-generation32-image.yml',
                                  'vulnerabilitySubgate': 'PASS_RAW',
                                  'rawSeverityCounts': {s: 0 for s in ['HIGH', 'CRITICAL', 'UNKNOWN', 'LOW', 'MEDIUM']}},
                'licenceRebinding': {'path': 'evidence/seaweedfs-452-generation32-licence-rebinding-local-20261103.json', 'sha256': '3' * 64},
                'producerArtifact': {'id': 1, 'bytes': 1, 'digest': 'sha256:' + '1' * 64},
                'independentReadback': {'id': 2, 'bytes': 1, 'digest': 'sha256:' + '2' * 64},
                'releaseAdmitted': False, 'runtimeAuthorityIssued': False, 'targetOperations': 0}

    def test_generation15_and_old_binary_are_denied(self):
        for field, value in [('generation', 15), ('orderedPatchCount', 15), ('schema', 'ouf.storage-candidate-lock.v1')]:
            lock = self.fixture_lock();lock[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'GENERATION32_LOCK'):
                cohort.validate_lock(lock)
        lock = self.fixture_lock();lock['buildProfile']['binarySha256'] = cohort.OLD_BINARY
        with self.assertRaisesRegex(ValueError, 'REVIEWED_GENERATION32_BUILD'):
            cohort.validate_lock(lock)

    def test_same_binary_predecessor_cannot_be_relabelled(self):
        lock = self.fixture_lock()
        lock['generation'] = lock['orderedPatchCount'] = 30
        with self.assertRaisesRegex(ValueError, 'GENERATION32_LOCK'):
            cohort.validate_lock(lock)
        lock = self.fixture_lock()
        lock['buildManifest']['patchedSourceTree'] = '13b3de2f130667ed060e94291fcf64b37b7f037a'
        with self.assertRaisesRegex(ValueError, 'REVIEWED_GENERATION32_BUILD'):
            cohort.validate_lock(lock)

    def test_authority_or_release_claim_is_denied(self):
        for field, value in [('releaseAdmitted', True), ('runtimeAuthorityIssued', True), ('targetOperations', 1)]:
            lock = self.fixture_lock();lock[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'NO_ADMISSION_OR_AUTHORITY'):
                cohort.validate_lock(lock)

    def test_unfinished_failed_or_other_workflow_is_denied(self):
        for key, value in [('allJobsPassed', False), ('vulnerabilitySubgate', 'HELD_RAW_FINDINGS'), ('workflow', '.github/workflows/storage-sdk-lifecycle.yml')]:
            lock = self.fixture_lock();lock['qualification'][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'SUCCESSFUL_GENERATION32'):
                cohort.validate_lock(lock)

    def test_high_critical_unknown_cannot_be_transferred_as_pass(self):
        for severity in ['HIGH', 'CRITICAL', 'UNKNOWN']:
            lock = self.fixture_lock();lock['qualification']['rawSeverityCounts'][severity] = 1
            with self.subTest(severity=severity), self.assertRaisesRegex(ValueError, 'SUCCESSFUL_GENERATION32'):
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
                                  ('buildProfile', 'go', '1.27.2'), ('buildProfile', 'binaryModuleRows', 262), ('buildProfile', 'compiledPackagesSha256', '0' * 64), ('buildProfile', 'tags', ['rclone']),
                                  ('image', 'upstreamLicenceSha256', '0' * 64)]:
            lock = self.fixture_lock();lock[group][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'REVIEWED_GENERATION32_BUILD'):
                cohort.validate_lock(lock)

    def test_artifact_identity_cannot_be_null_or_placeholder(self):
        for value in [None, 0, True, 'pending']:
            lock = self.fixture_lock();lock['producerArtifact']['id'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'EXACT_PUBLISHED_ARTIFACT'):
                cohort.validate_lock(lock)

    def test_google_profile_and_mongo_legal_delta_cannot_be_relabelled(self):
        lock = self.fixture_lock()
        lock['sourceRevision']['excludedGoogleFeatures'].pop()
        with self.assertRaisesRegex(ValueError, 'EXACT_GENERATION32_SOURCE_PROFILE'):
            cohort.validate_lock(lock)
        lock = self.fixture_lock()
        lock['mongoV2LegalDelta']['sha256'] = '1' * 64
        with self.assertRaisesRegex(ValueError, 'EXACT_MONGODB_V2_LEGAL_DELTA'):
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


class ModifiedMplSourceTests(unittest.TestCase):
    def fixture_checkout(self, root):
        manifest = json.loads((ROOT / cohort.MODIFIED_SOURCE_MANIFEST_PATH).read_bytes())
        import gzip, io, tarfile
        raw = gzip.decompress((ROOT / cohort.MODIFIED_SOURCE_ARCHIVE_PATH).read_bytes())
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for path in manifest['files']:
                dest = root / path; dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(archive.extractfile(path).read())
        return manifest

    def test_modified_mpl_archive_matches_all_six_exact_source_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.fixture_checkout(root)
            result = cohort.verify_modified_source(root)
            self.assertEqual(result['sourceFilesVerified'], 6)
            self.assertTrue(result['moduleSourcesModified'])
            self.assertFalse(result['redistributionAccepted'])
            self.assertEqual(result['sourceTree'], cohort.MANIFEST['build']['patchedSourceTree'])

    def test_changed_source_deleted_file_and_symlink_are_denied(self):
        for mutation in ('changed', 'deleted', 'symlink'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); self.fixture_checkout(root)
                target = root / 'weed/util/raftstore/bolt_store.go'
                if mutation == 'changed':target.write_bytes(b'other source')
                elif mutation == 'deleted':target.unlink()
                else:
                    original = target.read_bytes(); target.unlink(); other = root / 'outside'; other.write_bytes(original); target.symlink_to(other)
                with self.assertRaisesRegex(ValueError, 'MODIFIED_SOURCE_CHECKOUT_CHANGED'):
                    cohort.verify_modified_source(root)

    def test_changed_archive_or_manifest_digest_is_denied(self):
        for field in ('MODIFIED_SOURCE_ARCHIVE_SHA', 'MODIFIED_SOURCE_MANIFEST_SHA'):
            with self.subTest(field=field), patch.object(cohort, field, '0' * 64):
                with self.assertRaisesRegex(ValueError, 'EXACT_MODIFIED_MPL_SOURCE_ARCHIVE'):
                    cohort.verify_modified_source(ROOT)


if __name__ == '__main__':
    unittest.main()
