import copy
import hashlib
import importlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
m = importlib.import_module('tools.storage_planning.delta_manifest')
base = importlib.import_module('tools.storage_planning.inventory_manifest')


def fixture(objects, *, advertised=True):
    rows, bodies = [], {}
    for key, raw in objects.items():
        row = {'bucket': 'private-bucket', 'key': key, 'versionId': None,
               'isLatest': True, 'deleteMarker': False, 'size': len(raw),
               'sha256': None, 'metadataSha256': None,
               'metadata': {'ouf-content-hash': 'sha256:' + hashlib.sha256(raw).hexdigest()}
                           if advertised else {},
               'headMetadata': {'contentLength': len(raw), 'contentType': 'text/csv',
                                'etag': 'opaque-etag', 'lastModified': '2026-11-02T00:00:00Z'},
               'tags': []}
        rows.append(row)
        bodies[base.sha(base.canonical(['private-bucket', key, None]))] = raw
    features = {'bucket': 'private-bucket', **{name: {'status': 'PRESENT', 'value': {}}
                                             for name in base.FEATURES}}
    inventory = {'schema': 'ouf.storage-private-inventory.v1', 'complete': True,
                 'bucketFeaturesInventoried': True, 'bucketFeatureValuesComplete': True,
                 'writerInventoryComplete': False, 'requests': 1,
                 'objectBodiesRead': 0, 'targetWrites': 0, 'records': rows,
                 'bucketFeatures': [features], 'multipartUploads': [],
                 'summary': {'buckets': 1, 'objectVersions': len(rows), 'versionedRecords': 0,
                             'deleteMarkers': 0, 'bytesAcrossVersions': sum(map(len, objects.values())),
                             'objectsWithAdvertisedOufHash': len(rows) if advertised else 0,
                             'fileDirectoryCollisions': 0, 'unsafePathKeys': 0,
                             'trailingSlashKeys': 0, 'namespaceGate': 'PASS',
                             'unsupportedBucketFeatures': 0, 'versioningEnabledBuckets': 0,
                             'defaultEncryptedBuckets': 0, 'objectLockEnabledBuckets': 0,
                             'replicatedBuckets': 0, 'lifecycleBuckets': 0,
                             'notificationConfiguredBuckets': 0,
                             'incompleteMultipartUploads': 0, 'incompleteMultipartBytes': 0}}
    return inventory, bodies


def plan(old, new, **kwargs):
    return m.compile_delta(old[0], new[0], old[1], new[1],
                           source_profile_sha256=kwargs.get('source', 'a' * 64),
                           destination_profile_sha256=kwargs.get('destination', 'b' * 64))


class DeltaTests(unittest.TestCase):
    def test_add_overwrite_metadata_delete_observation_and_unchanged_are_distinct(self):
        old = fixture({k: b'old' for k in 'abcdef'})
        new = fixture({'a': b'old', 'b': b'new', 'c': b'old', 'e': b'old', 'f': b'old', 'g': b'add'})
        new[0]['records'][2]['headMetadata']['contentType'] = 'application/octet-stream'
        new[0]['records'][3]['headMetadata']['lastModified'] = '2026-11-05T00:00:00Z'
        result, public = plan(old, new)
        classes = {a['key']: a['classification'] for a in result['intent']['actions']}
        self.assertEqual(classes, {'a': 'UNCHANGED', 'b': 'REPLACE_BODY', 'c': 'REPLACE_METADATA',
                                  'd': 'REMOVE', 'e': 'SOURCE_OBSERVATION_CHANGED',
                                  'f': 'UNCHANGED', 'g': 'ADD'})
        self.assertEqual(public['candidateCopyBytes'], 9)
        self.assertEqual(public['candidateRemovedBytes'], 3)
        self.assertEqual(public['localBodiesHashed'], 12)
        deletion = next(a for a in result['intent']['actions'] if a['key'] == 'd')
        self.assertTrue(deletion['requiresSourceAbsenceUnderFence'])
        self.assertFalse(deletion['destinationObserved'])
        self.assertFalse(result['executionEnabled'])
        self.assertFalse(public['migrationReady'])

    def test_all_120_local_bodies_hashed_including_ten_without_advertised_hash(self):
        data = {f'key-{i:03}': bytes([i]) * (1000 if i < 119 else 84743) for i in range(120)}
        old = fixture(data)
        for row in old[0]['records'][-10:]:
            row['metadata'] = {}
        old[0]['summary']['objectsWithAdvertisedOufHash'] = 110
        result, public = plan(old, copy.deepcopy(old))
        self.assertEqual(old[0]['summary']['bytesAcrossVersions'], 203743)
        self.assertEqual(public['classifications']['UNCHANGED'], 120)
        self.assertEqual(public['localBodiesHashed'], 240)
        self.assertEqual(public['targetBodiesVerified'], 0)
        self.assertFalse(result['sourceReadProven'])

    def test_same_size_overwrite_with_unchanged_etag_is_detected_from_bytes(self):
        old, new = fixture({'key': b'abc'}, advertised=False), fixture({'key': b'xyz'}, advertised=False)
        self.assertEqual(old[0], new[0])
        result, _ = plan(old, new)
        self.assertEqual(result['intent']['actions'][0]['classification'], 'REPLACE_BODY')

    def test_advertised_hash_cannot_replace_missing_or_wrong_body(self):
        old = fixture({'key': b'abc'})
        for replacement in ({}, {next(iter(old[1])): b'xyz'}, {next(iter(old[1])): b'ab'}):
            with self.subTest(replacement=replacement):
                new = (copy.deepcopy(old[0]), replacement)
                with self.assertRaises(base.PlanError):
                    plan(old, new)

    def test_missing_extra_and_wrong_identity_body_sets_deny(self):
        old = fixture({'key': b'abc'})
        for bodies in ({'wrong': b'abc'}, {**old[1], 'extra': b'abc'}, {next(iter(old[1])): 'abc'}):
            with self.subTest(bodies=bodies):
                with self.assertRaises(base.PlanError):
                    plan(old, (old[0], bodies))

    def test_empty_current_inventory_only_plans_removal_and_never_authorizes_it(self):
        result, public = plan(fixture({'key': b'abc'}), fixture({}))
        self.assertEqual(public['classifications']['REMOVE'], 1)
        self.assertIsNone(result['authority'])
        self.assertFalse(result['automaticReplayAllowed'])
        self.assertFalse(public['targetApplyAuthorized'])
        self.assertIn('CURRENT_BACKEND_FENCE_AND_GOVERNED_AUTHORITY', result['intent']['requirements'])

    def test_incomplete_capture_cannot_manufacture_deletions(self):
        old, new = fixture({'key': b'abc'}), fixture({})
        new[0]['complete'] = False
        with self.assertRaisesRegex(base.PlanError, 'COMPLETE_CAPTURE'):
            plan(old, new)

    def test_changed_bucket_scope_and_features_deny(self):
        old = fixture({})
        new = copy.deepcopy(old)
        new[0]['bucketFeatures'][0]['bucket'] = 'other-bucket'
        with self.assertRaisesRegex(base.PlanError, 'BUCKET_SCOPE_OR_FEATURE_DRIFT'):
            plan(old, new)
        new = copy.deepcopy(old)
        new[0]['bucketFeatures'][0]['acl']['value'] = {'Grants': ['different']}
        with self.assertRaisesRegex(base.PlanError, 'BUCKET_SCOPE_OR_FEATURE_DRIFT'):
            plan(old, new)

    def test_unsupported_bucket_control_remains_unresolved(self):
        old = fixture({'key': b'abc'})
        old[0]['bucketFeatures'][0]['publicAccessBlock'] = {'status': 'UNSUPPORTED', 'code': 'NotImplemented'}
        old[0]['bucketFeatureValuesComplete'] = False
        old[0]['summary']['unsupportedBucketFeatures'] = 1
        result, public = plan(old, copy.deepcopy(old))
        self.assertIn('RESOLVE_UNSUPPORTED_BUCKET_FEATURE_CONTROLS', result['intent']['requirements'])
        self.assertEqual(public['gatesClosed'], 0)

    def test_versioning_even_without_historical_records_is_held(self):
        old = fixture({'key': b'abc'})
        old[0]['bucketFeatures'][0]['versioning']['value'] = {'Status': 'Enabled'}
        old[0]['summary']['versioningEnabledBuckets'] = 1
        with self.assertRaisesRegex(base.PlanError, 'VERSION_HISTORY_HELD'):
            plan(old, old)

    def test_nonlatest_and_head_version_cannot_enter_nonversioned_plan(self):
        for field, value in [('isLatest', False), ('headVersion', 'v1')]:
            old = fixture({'key': b'abc'})
            if field == 'headVersion':
                old[0]['records'][0]['headMetadata']['versionId'] = value
            else:
                old[0]['records'][0][field] = value
            with self.assertRaises(base.PlanError):
                plan(old, old)

    def test_suspended_versioning_delete_markers_and_multipart_are_held(self):
        old = fixture({'key': b''})
        old[0]['bucketFeatures'][0]['versioning']['value'] = {'Status': 'Suspended'}
        with self.assertRaisesRegex(base.PlanError, 'VERSION_HISTORY_HELD'):
            plan(old, old)
        old = fixture({'key': b''}, advertised=False)
        old[0]['records'][0]['deleteMarker'] = True
        old[0]['summary'].update(objectVersions=0, deleteMarkers=1)
        with self.assertRaisesRegex(base.PlanError, 'VERSION_HISTORY_HELD'):
            plan(old, old)
        old = fixture({'key': b'abc'})
        old[0]['multipartUploads'] = [{'bucket': 'private-bucket', 'key': 'key',
                                      'uploadId': 'pending', 'bytes': 0, 'parts': []}]
        old[0]['summary']['incompleteMultipartUploads'] = 1
        with self.assertRaisesRegex(base.PlanError, 'MULTIPART_HELD'):
            plan(old, old)

    def test_lifecycle_and_replication_require_separate_profile(self):
        for name, value, count in [
                ('lifecycle', {'Rules': [{'Status': 'Enabled'}]}, 'lifecycleBuckets'),
                ('replication', {'ReplicationConfiguration': {'Rules': [{}]}}, 'replicatedBuckets')]:
            old = fixture({'key': b'abc'})
            old[0]['bucketFeatures'][0][name]['value'] = value
            old[0]['summary'][count] = 1
            with self.subTest(name=name), self.assertRaisesRegex(base.PlanError, 'FEATURE_PROFILE_HELD'):
                plan(old, old)

    def test_protected_attributes_unknown_headers_and_duplicate_tags_are_held(self):
        for field, value in [('serverSideEncryption', 'AES256'), ('kmsKeyId', 'private-kms'),
                             ('retainUntilDate', '2030-01-01'), ('legalHoldStatus', 'ON'),
                             ('newUnknownHeader', 'not-silently-dropped'), ('contentType', 42)]:
            old = fixture({'key': b'abc'})
            old[0]['records'][0]['headMetadata'][field] = value
            with self.subTest(field=field), self.assertRaises(base.PlanError):
                plan(old, old)
        old = fixture({'key': b'abc'})
        old[0]['records'][0]['tags'] = [{'Key': 't', 'Value': '1'}, {'Key': 't', 'Value': '2'}]
        with self.assertRaisesRegex(base.PlanError, 'UNIQUE_DELTA_TAG'):
            plan(old, old)

    def test_tag_order_does_not_schedule_metadata_rewrite(self):
        old = fixture({'key': b'abc'})
        old[0]['records'][0]['tags'] = [{'Key': 'a', 'Value': '1'}, {'Key': 'b', 'Value': '2'}]
        new = copy.deepcopy(old)
        new[0]['records'][0]['tags'].reverse()
        result, public = plan(old, new)
        self.assertEqual(public['classifications']['REPLACE_METADATA'], 0)
        self.assertEqual(result['intent']['actions'][0]['classification'], 'SOURCE_OBSERVATION_CHANGED')

    def test_namespace_collision_and_unsafe_keys_are_held(self):
        old = fixture({'a': b'a', 'a/b': b'b'})
        old[0]['summary'].update(fileDirectoryCollisions=1, namespaceGate='HELD')
        with self.assertRaisesRegex(base.PlanError, 'NAMESPACE_HELD'):
            plan(old, old)
        old = fixture({'../escape': b'a'})
        old[0]['summary'].update(unsafePathKeys=1, namespaceGate='HELD')
        with self.assertRaisesRegex(base.PlanError, 'NAMESPACE_HELD'):
            plan(old, old)

    def test_unicode_reserved_keys_are_exact_and_never_normalized(self):
        old = fixture({'è/%2F?&+#': b'a', 'é': b'b', 'e\u0301': b'c'})
        result, _ = plan(old, old)
        self.assertEqual({a['key'] for a in result['intent']['actions']}, {'è/%2F?&+#', 'é', 'e\u0301'})

    def test_file_directory_transition_between_individually_valid_snapshots_is_held(self):
        for old, new in [(fixture({'a': b'a'}), fixture({'a/b': b'b'})),
                         (fixture({'a/b': b'b'}), fixture({'a': b'a'}))]:
            with self.assertRaisesRegex(base.PlanError, 'CROSS_SNAPSHOT_NAMESPACE_TRANSITION_HELD'):
                plan(old, new)

    def test_bounds_are_finite(self):
        old = fixture({str(i): b'a' for i in range(257)})
        with self.assertRaisesRegex(base.PlanError, 'OBJECT_BUDGET'):
            plan(old, old)
        old = fixture({'key': b'a'})
        old[0]['records'][0]['size'] = m.MAX_OBJECT_BYTES + 1
        old[0]['records'][0]['headMetadata']['contentLength'] = m.MAX_OBJECT_BYTES + 1
        old[0]['summary']['bytesAcrossVersions'] = m.MAX_OBJECT_BYTES + 1
        with self.assertRaisesRegex(base.PlanError, 'OBJECT_SIZE_BUDGET'):
            plan(old, old)

    def test_profile_drift_changes_intent_and_never_renews_authority(self):
        old = fixture({'key': b'abc'})
        first, _ = plan(old, old)
        second, _ = plan(old, old, destination='c' * 64)
        self.assertNotEqual(first['intentSha256'], second['intentSha256'])
        self.assertTrue(second['changedIntentRequiresGovernedReprocessing'])
        self.assertIsNone(second['authority'])
        for value in ('a' * 64, 'invalid', True):
            with self.subTest(value=value), self.assertRaisesRegex(base.PlanError, 'PROFILE_DIGESTS'):
                plan(old, old, destination=value)

    def test_private_outputs_detached_and_redacted_public_summary(self):
        old = fixture({'private-key-sentinel': b'private-body-sentinel'})
        old[0]['records'][0]['metadata']['private-meta'] = 'private-value-sentinel'
        preserved = copy.deepcopy(old)
        result, public = plan(old, old)
        self.assertEqual(old, preserved)
        raw = json.dumps(public)
        for secret in ('private-bucket', 'private-key-sentinel', 'private-body-sentinel',
                       'private-value-sentinel', 'a' * 64, next(iter(old[1]))):
            self.assertNotIn(secret, raw)
        result['intent']['actions'][0]['previousSource']['sourceObservation']['key'] = 'changed'
        self.assertEqual(old, preserved)

    def test_plan_is_deterministic_but_changed_bytes_change_exact_intent(self):
        old = fixture({'key': b'abc'}, advertised=False)
        first, _ = plan(old, old)
        second, _ = plan(old, old)
        self.assertEqual(first, second)
        third, _ = plan(old, fixture({'key': b'xyz'}, advertised=False))
        self.assertNotEqual(first['intentSha256'], third['intentSha256'])


if __name__ == '__main__':
    unittest.main()
