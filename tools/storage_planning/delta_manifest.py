"""Offline, PRIVATE delta planning for the existing bounded copy profile.

Hashes are computed from supplied bytes, never accepted from S3 metadata. Input
origin, current source stability, destination ownership and runtime authority are
NOT established here. No network, filesystem, credentials, execution or retries.
"""
import copy
import re

from .inventory_manifest import canonical, compile_plan, require, sha

MAX_OBJECTS = 256
MAX_OBJECT_BYTES = 16 << 20
MAX_TOTAL_BYTES = 64 << 20
MAX_INVENTORY_BYTES = 4 << 20
HEAD_FIELDS = {
    'contentLength', 'contentType', 'contentEncoding', 'cacheControl',
    'contentDisposition', 'expires', 'etag', 'lastModified', 'versionId',
    'serverSideEncryption', 'kmsKeyId', 'objectLockMode', 'retainUntilDate',
    'legalHoldStatus',
}
OBSERVATION_FIELDS = {'etag', 'lastModified', 'versionId'}
PROTECTED_FIELDS = {'serverSideEncryption', 'kmsKeyId', 'objectLockMode', 'retainUntilDate'}


def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _snapshot(inventory, bodies):
    require(type(inventory) is dict and len(canonical(inventory)) <= MAX_INVENTORY_BYTES,
            'BOUNDED_DELTA_INVENTORY_REQUIRED')
    private, public = compile_plan(inventory)
    require(len(private['entries']) <= MAX_OBJECTS, 'DELTA_OBJECT_BUDGET')
    summary = public['sourceSummary']
    require(summary['namespaceGate'] == 'PASS', 'DELTA_NAMESPACE_HELD')
    require(not summary['versionedRecords'] and not summary['deleteMarkers']
            and not summary['versioningEnabledBuckets'], 'DELTA_VERSION_HISTORY_HELD')
    require(all((b['versioning'].get('value') or {}).get('Status') in (None, '')
                for b in private['bucketFeatures']), 'DELTA_VERSION_HISTORY_HELD')
    require(not summary['incompleteMultipartUploads'], 'DELTA_MULTIPART_HELD')
    require(not any(summary[k] for k in ('defaultEncryptedBuckets', 'objectLockEnabledBuckets',
                                       'replicatedBuckets', 'lifecycleBuckets',
                                       'notificationConfiguredBuckets')),
            'DELTA_BUCKET_FEATURE_PROFILE_HELD')
    require(type(bodies) is dict and len(bodies) == len(private['entries']),
            'EXACT_LOCAL_BODY_SET_REQUIRED')
    require(summary['bytesAcrossVersions'] <= MAX_TOTAL_BYTES, 'DELTA_TOTAL_BODY_BUDGET')
    result, body_set = {}, {}
    for entry in private['entries']:
        row = entry['source']
        identity = (row['bucket'], row['key'])
        require(identity not in result and row['isLatest'] is True,
                'SINGLE_CURRENT_OBJECT_REQUIRED')
        require(row['size'] <= MAX_OBJECT_BYTES, 'DELTA_OBJECT_SIZE_BUDGET')
        raw = bodies.get(entry['entryId'])
        require(type(raw) is bytes and len(raw) == row['size'], 'LOCAL_BODY_SIZE_OR_SET_MISMATCH')
        body_hash = sha(raw)
        hint = (row.get('metadata') or {}).get('ouf-content-hash', '')
        require(not hint or re.fullmatch(r'(?:sha256:)?[0-9a-fA-F]{64}', hint)
                and hint.removeprefix('sha256:').lower() == body_hash,
                'ADVERTISED_HASH_MISMATCH')
        head = row['headMetadata']
        require(set(head) <= HEAD_FIELDS, 'UNSUPPORTED_DELTA_HEAD_FIELD')
        require(not any(head.get(k) for k in PROTECTED_FIELDS)
                and head.get('legalHoldStatus') in (None, '', 'OFF'),
                'DELTA_ENCRYPTION_RETENTION_HELD')
        require(head.get('versionId') in (None, 'null'), 'DELTA_HEAD_VERSION_HELD')
        require(all(value is None or type(value) is str
                    for key, value in head.items() if key != 'contentLength'),
                'TYPED_DELTA_HEAD_REQUIRED')
        tags = {}
        for tag in row.get('tags') or []:
            require(set(tag) == {'Key', 'Value'} and tag['Key'] not in tags,
                    'EXACT_UNIQUE_DELTA_TAG_REQUIRED')
            tags[tag['Key']] = tag['Value']
        representation = {
            'size': row['size'], 'metadata': row.get('metadata') or {}, 'tags': tags,
            'headers': {k: v for k, v in head.items()
                        if k not in OBSERVATION_FIELDS | PROTECTED_FIELDS | {'legalHoldStatus'}},
        }
        result[identity] = {
            'entryId': entry['entryId'], 'bodySha256': body_hash,
            'representationSha256': sha(canonical(representation)),
            'sourceObservationSha256': sha(canonical(row)),
            'sourceObservation': copy.deepcopy(row),
        }
        body_set[entry['entryId']] = {'bytes': len(raw), 'sha256': body_hash}
    require(set(bodies) == set(body_set), 'EXACT_LOCAL_BODY_SET_REQUIRED')
    return result, public, sha(canonical(body_set))


def compile_delta(baseline, current, baseline_bodies, current_bodies, *,
                  source_profile_sha256, destination_profile_sha256):
    """Return (private candidate plan, redacted summary), without admission.

    Both inventories use ouf.storage-private-inventory.v1 (metadata capture only).
    Body dictionaries map the existing compiler's entryId to exact local bytes.
    Profile digests are caller-supplied binding inputs, NOT identity attestations.
    The baseline describes the previous source, not proven destination contents.
    """
    require(digest(source_profile_sha256) and digest(destination_profile_sha256)
            and source_profile_sha256 != destination_profile_sha256,
            'DISTINCT_EXACT_PROFILE_DIGESTS_REQUIRED')
    before, _, old_body_set = _snapshot(baseline, baseline_bodies)
    after, new_summary, new_body_set = _snapshot(current, current_bodies)
    old_features = {b['bucket']: b for b in baseline['bucketFeatures']}
    new_features = {b['bucket']: b for b in current['bucketFeatures']}
    require(canonical(old_features) == canonical(new_features), 'DELTA_BUCKET_SCOPE_OR_FEATURE_DRIFT')
    combined = before.keys() | after.keys()
    for bucket, key in combined:
        parts = key.split('/')
        require(not any((bucket, '/'.join(parts[:i])) in combined for i in range(1, len(parts))),
                'DELTA_CROSS_SNAPSHOT_NAMESPACE_TRANSITION_HELD')
    actions = []
    counts = {kind: 0 for kind in ('ADD', 'REPLACE_BODY', 'REPLACE_METADATA', 'REMOVE',
                                  'SOURCE_OBSERVATION_CHANGED', 'UNCHANGED')}
    bytes_to_copy = bytes_removed = 0
    for identity in sorted(combined):
        previous, desired = before.get(identity), after.get(identity)
        if previous is None:
            kind = 'ADD'
        elif desired is None:
            kind = 'REMOVE'
        elif previous['bodySha256'] != desired['bodySha256']:
            kind = 'REPLACE_BODY'
        elif previous['representationSha256'] != desired['representationSha256']:
            kind = 'REPLACE_METADATA'
        elif previous['sourceObservationSha256'] != desired['sourceObservationSha256']:
            kind = 'SOURCE_OBSERVATION_CHANGED'
        else:
            kind = 'UNCHANGED'
        counts[kind] += 1
        if kind in ('ADD', 'REPLACE_BODY', 'REPLACE_METADATA'):
            bytes_to_copy += desired['sourceObservation']['size']
        if kind == 'REMOVE':
            bytes_removed += previous['sourceObservation']['size']
        actions.append({
            'bucket': identity[0], 'key': identity[1], 'classification': kind,
            'previousSource': previous, 'desiredSource': desired,
            'expectedDestination': 'ABSENT' if previous is None else 'OWNED_BASELINE_REPRESENTATION',
            'destinationObserved': False, 'executionEnabled': False,
            'requiresSourceAbsenceUnderFence': kind == 'REMOVE',
            'requiresFreshDestinationBodyRead': True,
        })
    requirements = [
        'AUTHENTICATED_COMPLETE_CAPTURE_AND_CONDITIONAL_BODY_READS',
        'COMPLETE_WRITER_AND_DATABASE_REFERENCE_INVENTORY',
        'CURRENT_BACKEND_FENCE_AND_GOVERNED_AUTHORITY',
        'DESTINATION_OWNERSHIP_AND_FRESH_FULL_BODY_METADATA_READBACK',
        'COORDINATED_BACKUP_AND_GOVERNED_REPROCESSING_OF_CHANGED_INTENT',
        'DURABLE_EFFECT_JOURNAL_AND_OWNER_BUDGETS_WITH_AMBIGUOUS_OUTCOME_RECONCILIATION',
        'VERIFIED_EXECUTOR_FOR_REPLACE_AND_DELETE_AND_REPRESENTATIVE_REHEARSAL',
        'POST_DELTA_FULL_SET_BODY_METADATA_AND_DATABASE_RECONCILIATION',
        'G0_THROUGH_G5_AND_SEPARATE_TARGET_EXECUTION_ADMISSION',
    ]
    if new_summary['sourceSummary']['unsupportedBucketFeatures']:
        requirements.append('RESOLVE_UNSUPPORTED_BUCKET_FEATURE_CONTROLS')
    intent = {
        'schema': 'ouf.storage-private-delta-intent.v1',
        'sourceProfileSha256': source_profile_sha256,
        'destinationProfileSha256': destination_profile_sha256,
        'baselineInventorySha256': sha(canonical(baseline)),
        'currentInventorySha256': sha(canonical(current)),
        'baselineLocalBodySetSha256': old_body_set, 'currentLocalBodySetSha256': new_body_set,
        'actions': actions, 'requirements': requirements,
    }
    plan = {
        'schema': 'ouf.storage-private-delta-plan.v1', 'intent': intent,
        'intentSha256': sha(canonical(intent)),
        'status': 'OFFLINE_DELTA_CANDIDATE_NOT_ADMITTED', 'executionEnabled': False,
        'authority': None, 'automaticReplayAllowed': False,
        'changedIntentRequiresGovernedReprocessing': True,
        'sourceReadProven': False, 'pointInTimeSnapshotProven': False,
        'destinationParityProven': False, 'databaseReferencesReconciled': False,
        'retentionAndLastModifiedTranslationRequired': True,
    }
    # No bucket/key, object digest, profile digest, private metadata or raw bytes.
    summary = {
        'schema': 'ouf.storage-delta-summary.v1', 'status': plan['status'],
        'baselineObjects': len(before), 'currentObjects': len(after),
        'classifications': counts, 'candidateCopyBytes': bytes_to_copy,
        'candidateRemovedBytes': bytes_removed,
        'localBodiesHashed': len(before) + len(after),
        'targetBodiesVerified': 0, 's3Requests': 0, 'targetWrites': 0,
        'migrationReady': False, 'releaseAcceptance': False,
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
        'gatesClosed': 0, 'acceptanceTestsPassed': 0,
    }
    return plan, summary
