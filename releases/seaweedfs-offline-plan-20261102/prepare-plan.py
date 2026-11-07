#!/usr/bin/env python3
"""Compile a PRIVATE migration plan from captured metadata; no network or copying.

Advertised hashes are hints, never verification. Unsupported API responses remain
unknown. Full body checks, writer fencing and separate destination admission are
required even when this offline analysis succeeds.
"""
import hashlib
import json
import re

FEATURES = ('versioning', 'encryption', 'policy', 'objectLock', 'lifecycle',
            'replication', 'notification', 'cors', 'acl', 'publicAccessBlock')
ABSENT_CODES = {'NoSuchBucketPolicy', 'NoSuchLifecycleConfiguration',
 'ReplicationConfigurationNotFoundError', 'ServerSideEncryptionConfigurationNotFoundError',
 'ObjectLockConfigurationNotFoundError', 'NoSuchObjectLockConfiguration',
 'NoSuchCORSConfiguration', 'NoSuchTagSet', 'NoSuchPublicAccessBlockConfiguration'}
MAX_RECORDS = 25000

class PlanError(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise PlanError(reason)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def decode(raw):
    def pairs(rows):
        result = dict(rows)
        require(len(result) == len(rows), 'DUPLICATE_JSON_KEY')
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'NONFINITE_JSON_VALUE'))

def integer(value, maximum=9223372036854775807):
    return type(value) is int and 0 <= value <= maximum

def active(feature, value):
    if feature == 'versioning':
        return value.get('Status') == 'Enabled'
    if feature == 'encryption':
        return bool((value.get('ServerSideEncryptionConfiguration') or {}).get('Rules'))
    if feature == 'objectLock':
        return (value.get('ObjectLockConfiguration') or {}).get('ObjectLockEnabled') == 'Enabled'
    if feature == 'replication':
        return bool((value.get('ReplicationConfiguration') or {}).get('Rules'))
    if feature == 'lifecycle':
        return bool(value.get('Rules'))
    if feature == 'notification':
        return any(value.get(k) for k in ('LambdaFunctionConfigurations',
                   'QueueConfigurations', 'TopicConfigurations')) or value.get('EventBridgeConfiguration') is not None
    return False

def compile_plan(inventory):
    require(type(inventory) is dict and inventory.get('schema') == 'ouf.storage-private-inventory.v1',
            'EXACT_INVENTORY_SCHEMA_REQUIRED')
    require(inventory.get('complete') is True and inventory.get('bucketFeaturesInventoried') is True
            and inventory.get('writerInventoryComplete') is False,
            'COMPLETE_CAPTURE_WITH_WRITER_GAP_REQUIRED')
    require(type(inventory.get('objectBodiesRead')) is int and inventory['objectBodiesRead'] == 0
            and type(inventory.get('targetWrites')) is int and inventory['targetWrites'] == 0,
            'READ_ONLY_METADATA_CAPTURE_REQUIRED')
    require(integer(inventory.get('requests'), 10000), 'BOUNDED_SOURCE_REQUEST_COUNT_REQUIRED')
    rows, buckets, multipart = (inventory.get(k) for k in ('records', 'bucketFeatures', 'multipartUploads'))
    require(type(rows) is list and len(rows) <= MAX_RECORDS and type(buckets) is list
            and len(buckets) <= 10000 and type(multipart) is list and len(multipart) <= MAX_RECORDS,
            'BOUNDED_CAPTURE_COLLECTIONS_REQUIRED')
    matrix = {f: {'PRESENT': 0, 'ABSENT': 0, 'UNSUPPORTED': 0, 'configured': 0} for f in FEATURES}
    names = set()
    for bucket in buckets:
        require(type(bucket) is dict and set(bucket) == {'bucket', *FEATURES}, 'COMPLETE_BUCKET_FEATURE_SET_REQUIRED')
        name = bucket['bucket']
        require(type(name) is str and 0 < len(name.encode()) <= 255 and '\x00' not in name and name not in names,
                'UNIQUE_BUCKET_IDENTITY_REQUIRED')
        names.add(name)
        for feature in FEATURES:
            entry = bucket[feature]
            require(type(entry) is dict and entry.get('status') in ('PRESENT', 'ABSENT', 'UNSUPPORTED'),
                    'TYPED_FEATURE_OBSERVATION_REQUIRED')
            status = entry['status']
            if status == 'PRESENT':
                require(set(entry) == {'status', 'value'} and type(entry['value']) is dict,
                        'PRESENT_FEATURE_VALUE_REQUIRED')
                matrix[feature]['configured'] += int(active(feature, entry['value']))
            else:
                require(set(entry) == {'status', 'code'} and
                        (entry['code'] in ABSENT_CODES if status == 'ABSENT' else entry['code'] == 'NotImplemented'),
                        'EXACT_FEATURE_ABSENCE_OR_UNSUPPORTED_CODE_REQUIRED')
            matrix[feature][status] += 1
    unsupported = sum(v['UNSUPPORTED'] for v in matrix.values())
    require(inventory.get('bucketFeatureValuesComplete') is (unsupported == 0), 'FEATURE_COMPLETENESS_MISMATCH')
    entries, identities, latest, keys = [], set(), set(), {}
    objects = versions = markers = total = advertised = invalid_advertised = 0
    attributes = dict.fromkeys(['encryptedObjects', 'objectsWithKmsKeyReference', 'objectsWithRetentionDate', 'objectsWithLegalHold', 'objectsWithContentEncoding', 'objectsWithCacheControl', 'objectsWithTags'], 0)
    required_fields = {'bucket', 'key', 'versionId', 'isLatest', 'deleteMarker', 'size', 'sha256', 'metadataSha256'}
    for row in rows:
        require(type(row) is dict and required_fields <= set(row)
                and set(row) <= required_fields | {'metadata', 'headMetadata', 'tags'},
                'TYPED_INVENTORY_ROW_REQUIRED')
        bucket, key, version = (row[k] for k in ('bucket', 'key', 'versionId'))
        require(type(bucket) is str and bucket in names and type(key) is str and 0 < len(key.encode()) <= 1024
                and (version is None or type(version) is str and 0 < len(version.encode()) <= 4096),
                'BOUNDED_ROW_IDENTITY_REQUIRED')
        identity = (bucket, key, version)
        require(identity not in identities, 'DUPLICATE_SOURCE_OBJECT_VERSION')
        identities.add(identity)
        require(type(row['isLatest']) is bool and type(row['deleteMarker']) is bool and integer(row['size']),
                'TYPED_ROW_FLAGS_AND_SIZE_REQUIRED')
        if row['isLatest']:
            require((bucket, key) not in latest, 'MULTIPLE_LATEST_SOURCE_VERSIONS')
            latest.add((bucket, key))
        keys.setdefault(bucket, set()).add(key)
        versions += int(version not in (None, 'null'))
        require(row['sha256'] is None and row['metadataSha256'] is None, 'METADATA_CAPTURE_CANNOT_ASSERT_VERIFIED_HASHES')
        metadata = row.get('metadata')
        metadata = {} if metadata is None else metadata
        require(type(metadata) is dict and all(type(k) is type(v) is str for k, v in metadata.items()),
                'STRING_METADATA_REQUIRED')
        hint = metadata.get('ouf-content-hash', '')
        if row['deleteMarker']:
            require(row['size'] == 0, 'CONTENT_ON_DELETE_MARKER')
            markers += 1
        else:
            objects += 1
            total += row['size']
            require(total <= 9223372036854775807, 'SOURCE_SIZE_OVERFLOW')
            advertised += bool(hint)
            invalid_advertised += bool(hint and not re.fullmatch(r'(?:sha256:)?[0-9a-fA-F]{64}', hint))
            head = row.get('headMetadata')
            require(type(head) is dict and head.get('contentLength') == row['size']
                    and type(head.get('contentLength')) is int, 'SOURCE_HEAD_SIZE_MISMATCH')
            require(type(row.get('tags')) in (list, type(None)), 'TYPED_TAGS_REQUIRED')
            for tag in row.get('tags') or []:
                require(type(tag) is dict and type(tag.get('Key')) is str and type(tag.get('Value')) is str, 'STRING_OBJECT_TAG_REQUIRED')
            for name, field in [('encryptedObjects', 'serverSideEncryption'), ('objectsWithKmsKeyReference', 'kmsKeyId'), ('objectsWithRetentionDate', 'retainUntilDate'), ('objectsWithContentEncoding', 'contentEncoding'), ('objectsWithCacheControl', 'cacheControl')]:
                attributes[name] += bool(head.get(field))
            attributes['objectsWithLegalHold'] += head.get('legalHoldStatus') == 'ON'
            attributes['objectsWithTags'] += bool(row.get('tags'))
        # sha256/metadataSha256 from an unverified metadata capture are NEVER body proof.
        entries.append({'source': row, 'entryId': sha(canonical(list(identity))),
            'destination': {'preserveBucketAndKey': True, 'versionId': None},
            'state': 'PLANNED_NOT_COPIED', 'bodySha256Verified': None,
            'metadataToPreserveSha256': sha(canonical({k: row.get(k) for k in ('metadata', 'headMetadata', 'tags')})),
            'requirements': ['SOURCE_BODY_SHA256', 'DESTINATION_REREAD_SHA256', 'VERIFY_METADATA_AND_TAGS',
                             'SOURCE_FENCE_OR_FRESH_CONDITIONAL_READ'] if not row['deleteMarker'] else ['PRESERVE_DELETE_MARKER_HISTORY'],
            'advertisedHashIsVerification': False})
    unsafe = trailing = conflicts = 0
    for bucket_keys in keys.values():
        for key in bucket_keys:
            parts = key.split('/')
            unsafe += bool(key.startswith('/') or '//' in key or '\\' in key or '\x00' in key
                           or any(p in ('.', '..') for p in parts))
            trailing += key.endswith('/')
            conflicts += any('/'.join(parts[:i]) in bucket_keys for i in range(1, len(parts)))
    upload_ids, part_count, incomplete_bytes = set(), 0, 0
    for upload in multipart:
        require(type(upload) is dict and type(upload.get('bucket')) is str and upload['bucket'] in names
                and type(upload.get('key')) is str and type(upload.get('uploadId')) is str
                and type(upload.get('parts')) is list and integer(upload.get('bytes')), 'TYPED_MULTIPART_REQUIRED')
        identity = (upload['bucket'], upload['key'], upload['uploadId'])
        require(identity not in upload_ids, 'DUPLICATE_MULTIPART_UPLOAD')
        upload_ids.add(identity)
        part_numbers, size = set(), 0
        for part in upload['parts']:
            part_count += 1
            require(part_count <= MAX_RECORDS and type(part) is dict
                    and integer(part.get('partNumber'), 10000) and part['partNumber'] > 0
                    and part['partNumber'] not in part_numbers and integer(part.get('size')),
                    'TYPED_BOUNDED_MULTIPART_PART_REQUIRED')
            part_numbers.add(part['partNumber']); size += part['size']
        require(size == upload['bytes'], 'MULTIPART_BYTE_MISMATCH')
        incomplete_bytes += size
        require(incomplete_bytes <= 9223372036854775807, 'MULTIPART_SIZE_OVERFLOW')
    summary = {'buckets': len(names), 'objectVersions': objects, 'versionedRecords': versions,
      'deleteMarkers': markers, 'bytesAcrossVersions': total, 'objectsWithAdvertisedOufHash': advertised,
      'fileDirectoryCollisions': conflicts, 'unsafePathKeys': unsafe, 'trailingSlashKeys': trailing,
      'namespaceGate': 'HELD' if unsafe or trailing or conflicts else 'PASS',
      'unsupportedBucketFeatures': unsupported, 'versioningEnabledBuckets': matrix['versioning']['configured'],
      'defaultEncryptedBuckets': matrix['encryption']['configured'], 'objectLockEnabledBuckets': matrix['objectLock']['configured'],
      'replicatedBuckets': matrix['replication']['configured'], 'lifecycleBuckets': matrix['lifecycle']['configured'],
      'notificationConfiguredBuckets': matrix['notification']['configured'],
      'incompleteMultipartUploads': len(multipart), 'incompleteMultipartBytes': incomplete_bytes}
    require(canonical(inventory.get('summary')) == canonical(summary), 'RECOMPUTED_INVENTORY_SUMMARY_MISMATCH')
    public = {'schema': 'ouf.storage-offline-plan-summary.v1', 'status': 'PRIVATE_PLAN_PREPARED_NOT_ADMITTED',
      'records': len(rows), 'sourceSummary': summary, 'bucketFeatureStatusCounts': matrix,
      'objectAttributeCounts': attributes,
      'policyDocumentsToTranslate': sum(bool((b['policy'].get('value') or {}).get('Policy')) for b in buckets),
      'objectsWithoutAdvertisedHash': objects - advertised, 'unrecognizedAdvertisedHashFormats': invalid_advertised,
      'objectsRequiringFullBodyVerification': objects, 'verifiedBodies': 0,
      'historicalVersionCopyOrderProven': False, 'writerInventoryComplete': False,
      'pointInTimeSnapshotProven': False, 'externalConsumersProvenAbsent': False,
      'migrationReady': False, 'releaseAcceptance': False, 'targetApplyAuthorized': False,
      'runtimeAuthorityIssued': False, 'objectBodiesRead': 0, 's3Requests': 0,
      'directEngineGets': 0, 'credentialFilesOpened': 0, 'automaticReplayAllowed': False}
    private = {'schema': 'ouf.storage-private-copy-plan.v1', 'entries': entries, 'bucketFeatures': buckets,
      'multipartUploads': multipart, 'assessment': public,
      'executionEnabled': False, 'authority': None, 'copiedObjects': 0, 'verifiedObjects': 0,
      'requiredGates': ['SW-G0', 'SW-G1', 'SW-G2', 'SW-G3', 'SW-G4', 'SW-G5'],
      'retentionAndLastModifiedTranslationRequired': True, 'databaseReferenceReconciliationRequired': True,
      'unknownFeatureResolutionRequired': bool(unsupported)}
    return private, public


PUBLIC_ROLES = {'mcp', 'onboarding', 'postgres', 'minio', 'keycloak', 'semantic',
 'gateway-owner', 'udp', 'ingestion-evidence-read', 'caddy', 'udp-evidence-read', 'apisix', 'ingestion'}
BINDING_NAMES = {'OUF_ONBOARDING_STAGING_ENDPOINT', 'OUF_ONBOARDING_STAGING_BUCKET',
 'OUF_UDP_S3_ENDPOINT', 'OUF_UDP_S3_BUCKET', 'OUF_UDP_LAKE_S3_ENDPOINT', 'OUF_UDP_LAKE_S3_BUCKET',
 'OUF_ONBOARDING_OBJECT_STORE_GATEWAY_BASE_URL', 'OUF_ONBOARDING_OBJECT_STORE_READ_PATH',
 'AWS_REGION', 'AWS_DEFAULT_REGION'}

def host_assessment(host):
    require(type(host) is dict and host.get('pointInTimeSnapshotProven') is False
            and host.get('externalConsumersProvenAbsent') is False and type(host.get('bindings')) is list,
            'EXACT_RETAINED_HOST_BASELINE_REQUIRED')
    bindings = host['bindings']
    require(len(bindings) == 13 and all(type(r) is dict and type(r.get('role')) is str for r in bindings)
            and {r['role'] for r in bindings} == PUBLIC_ROLES, 'EXACT_THIRTEEN_RETAINED_ROLES_REQUIRED')
    configured, counts = [], {name: 0 for name in sorted(BINDING_NAMES)}
    for row in bindings:
        values = row.get('storageBindingValues')
        require(type(values) is dict and set(values) <= BINDING_NAMES
                and all(type(v) is str for v in values.values()), 'FILTERED_STORAGE_REFERENCES_ONLY')
        if any(k.endswith('_ENDPOINT') or k.endswith('_BUCKET') or k.endswith('_GATEWAY_BASE_URL') for k in values):
            configured.append(row['role'])
        for name in values:
            counts[name] += 1
    return {'retainedContainerSnapshots': 13, 'configuredStorageRolesAtControl14': sorted(configured),
            'storageReferenceNameCountsAtControl14': counts,
            'otherTwelveContainerBindingsRefreshed': False, 'activeWritersProven': False}

"""Installation-bound offline control17. Reads only retained metadata artifacts.

The packaged entry includes the generic compiler before this source. No target
network, credential source, Docker socket, database or object body is opened.
"""
import os
from pathlib import Path
import stat
import sys
import time

INPUT = Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-inputs-20261102-v1')
HOST = Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-reconciliation-20261102-v1/host-baseline.private.json')
HOST_SHA = '49aaea817bff55ff5ab901f2f54784e97ac85b7e2bbf2ec489055bab94c790c4'
SCOPE = Path('/etc/ouf/deploy-snapshots/seaweedfs-offline-plan-20261102-v1')
EXPECTED_RECEIPT = {'allFifteenPriorScopesPreserved': True, 'automaticReplayAllowed': False, 'capacityAndMemoryObservedAtControl': 14, 'credentialInputMetadata': {'candidates': [{'kind': 'MISSING', 'location': 'SECRETS_PREFIX', 'required': False, 'source': 'LEGACY_USER'}, {'kind': 'MISSING', 'location': 'DECLARED', 'required': True, 'source': 'LEGACY_USER'}, {'kind': 'MISSING', 'location': 'SECRETS_PREFIX', 'required': False, 'source': 'LEGACY_PASSWORD'}, {'kind': 'MISSING', 'location': 'DECLARED', 'required': True, 'source': 'LEGACY_PASSWORD'}, {'kind': 'MISSING', 'location': 'SECRETS_PREFIX', 'required': False, 'source': 'ROOT_USER'}, {'kind': 'MISSING', 'location': 'DECLARED', 'required': True, 'source': 'ROOT_USER'}, {'kind': 'MISSING', 'location': 'SECRETS_PREFIX', 'required': False, 'source': 'ROOT_PASSWORD'}, {'kind': 'REGULAR', 'location': 'DECLARED', 'mode': '0600', 'previousGuardFailedPredicates': ['NON_ROOT_OWNER'], 'required': True, 'rootOwned': False, 'singleLink': True, 'sizeWithinLimit': True, 'source': 'ROOT_PASSWORD'}, {'kind': 'MISSING', 'location': 'DECLARED', 'required': True, 'source': 'CONFIG_ENV'}], 'filesOpened': 1, 'metadataComplete': True, 'policyBlocked': False, 'rawValuesSpooled': False, 'readPolicy': 'EXISTING_DECLARED_REGULAR_BOUNDED_STABLE_INPUTS_ONLY', 'sourceBytesRead': 65, 'sourceCustodyAdmitted': False}, 'credentialSourceCustodyAdmitted': False, 'credentialSources': {'metadataCandidates': 7, 'rawValuesSpooled': False, 'secretFilesOpened': 1, 'selectedSources': ['EXPLICIT_ENV', 'DECLARED_SECRET_FILE'], 'sourceBytesRead': 65}, 'credentialValuesSpooled': False, 'cumulativeControlAttempts': 16, 'cumulativeDirectEngineGets': 52, 'directEngineGets': 2, 'externalConsumersProvenAbsent': False, 'hostBaselineFromControl': 14, 'inventorySummary': {'buckets': 2, 'bytesAcrossVersions': 203743, 'defaultEncryptedBuckets': 0, 'deleteMarkers': 0, 'fileDirectoryCollisions': 0, 'incompleteMultipartBytes': 0, 'incompleteMultipartUploads': 0, 'lifecycleBuckets': 0, 'namespaceGate': 'PASS', 'notificationConfiguredBuckets': 0, 'objectLockEnabledBuckets': 0, 'objectVersions': 120, 'objectsWithAdvertisedOufHash': 110, 'replicatedBuckets': 0, 'trailingSlashKeys': 0, 'unsafePathKeys': 0, 'unsupportedBucketFeatures': 2, 'versionedRecords': 0, 'versioningEnabledBuckets': 0}, 'memoryAvailableBytes': 11830857728, 'otherTwelveContainerBindingsRefreshed': False, 'pointInTimeSnapshotProven': False, 'privateInventorySha256': '43571bb43921f74adfa5974a0903acb54ee1eadecbc9d5d0d70539ce5cadba55', 'readerFailureCategory': 'NONE', 'records': 120, 'releaseAcceptance': False, 'retainedContainerSnapshots': 13, 'retainedHostBaselineHash': '49aaea817bff55ff5ab901f2f54784e97ac85b7e2bbf2ec489055bab94c790c4', 'runtimeAuthorityIssued': False, 's3Complete': True, 's3Requests': 265, 'status': 'PRIVATE_STORAGE_BASELINE_CAPTURED_NOT_ADMITTED', 'storageDataFreeBytes': 293381369856, 'storageDataTotalBytes': 539792977920, 'targetApplyAuthorized': False, 'thirteenInspectScanReplayed': False}  # Bound to the public operator receipt by the packager.
INVENTORY_SHA = '43571bb43921f74adfa5974a0903acb54ee1eadecbc9d5d0d70539ce5cadba55'
PROFILE = {'schema': 'ouf.storage-offline-plan-control.v1', 'maximumAttempts': 1,
 'controlAttempt': 17, 'previousControlAttempts': 16, 'previousEngineGets': 52,
 'maximumEngineGets': 0, 'maximumS3Requests': 0, 'maximumCredentialFileReads': 0,
 'maximumInputFiles': 4, 'maximumInputInventoryBytes': 67108864,
 'maximumOutputPlanBytes': 67108864, 'maximumSeconds': 45, 'maximumMemoryBytes': 536870912,
 'objectBodiesRead': 0, 'sqlRequests': 0, 'containerLifecycleOperations': 0,
 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False, 'migrationAuthorized': False}


def frame(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                                          'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


class OfflineFiles:
    def __init__(self):
        self.seals = {}; self.opened = 0; self.bytes = 0; self.until = time.monotonic() + 45

    def check(self):
        require(time.monotonic() < self.until, 'OFFLINE_PLAN_DEADLINE')

    def ancestry(self, path):
        require(path.is_absolute() and '..' not in path.parts, 'ABSOLUTE_CANONICAL_PATH_REQUIRED')
        for parent in reversed(path.parents):
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'ROOT_PROTECTED_ANCESTRY_REQUIRED')
            self.seals[str(parent)] = frame(info)

    def read(self, path, maximum):
        self.check(); self.ancestry(path)
        require(self.opened < 4, 'OFFLINE_ARTIFACT_FILE_LIMIT')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        self.opened += 1
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                    and 0 < before.st_size <= maximum, 'PRIVATE_REGULAR_METADATA_ARTIFACT_REQUIRED')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                raw = stream.read(maximum + 1)
            self.bytes += len(raw)
            require(len(raw) == before.st_size and frame(before) == frame(os.fstat(fd)) == frame(path.lstat()),
                    'RETAINED_ARTIFACT_CHANGED_DURING_READ')
            self.seals[str(path)] = frame(before)
            self.check(); return raw
        finally:
            os.close(fd)

    def stable(self):
        self.check()
        require(all(frame(Path(p).lstat()) == f for p, f in self.seals.items()),
                'RETAINED_METADATA_ARTIFACTS_CHANGED')


def put(scope, name, record):
    raw = canonical(record)
    require(0 < len(raw) <= PROFILE['maximumOutputPlanBytes'], 'BOUNDED_PRIVATE_PLAN_REQUIRED')
    fd = os.open(scope / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(scope, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return sha(raw)


def collect_plan(control):
    claim = decode(control.read(INPUT / 'capture.claim.json', 4096))
    require(canonical(claim) == canonical({'schema': 'ouf.m2-discovery-custody-capture-claim.v1', 'automaticReplayAllowed': False}),
            'EXACT_CONTROL16_CAPTURE_CLAIM_REQUIRED')
    receipt = decode(control.read(INPUT / 'result.json', 32768))
    require(type(EXPECTED_RECEIPT) is dict and canonical(receipt) == canonical(EXPECTED_RECEIPT),
            'EXACT_COMPLETE_CONTROL16_RECEIPT_REQUIRED')
    host = decode(control.read(HOST, 2097152))
    require(sha(canonical(host)) == HOST_SHA == receipt['retainedHostBaselineHash'], 'EXACT_RETAINED_HOST_HASH_REQUIRED')
    host_public = host_assessment(host)
    raw = control.read(INPUT / 's3/inventory.private.json', PROFILE['maximumInputInventoryBytes'])
    require(sha(raw) == INVENTORY_SHA == receipt['privateInventorySha256'],
            'EXACT_PRIVATE_INVENTORY_HASH_REQUIRED')
    inventory = decode(raw)
    require(canonical(inventory.get('summary')) == canonical(receipt['inventorySummary'])
            and len(inventory.get('records', [])) == receipt['records']
            and inventory.get('requests') == receipt['s3Requests'], 'RECEIPT_AND_PRIVATE_INVENTORY_MISMATCH')
    private, public = compile_plan(inventory)
    private.update(retainedHostBaseline=host, sourcePrivateInventorySha256=INVENTORY_SHA,
                   sourceReceiptSha256=sha(canonical(receipt)), controlProfile=PROFILE)
    public.update(host_public)
    control.stable()
    plan_sha = put(SCOPE, 'migration-plan.private.json', private)
    control.stable()
    public.update(privatePlanSha256=plan_sha, sourcePrivateInventorySha256=INVENTORY_SHA,
      control16EvidenceStableDuringAnalysis=True, priorScopesModified=False,
      sourceInventoryControl=16, retainedHostBaselineControl=14,
      capacityAndMemoryReobserved=False, cumulativeControlAttempts=17,
      cumulativeDirectEngineGets=52, privateMetadataFilesOpened=control.opened,
      privateMetadataBytesRead=control.bytes, scopeConsumed=True)
    return public


def main():
    created = False; control = None
    try:
        require(not sys.argv[1:] and os.geteuid() == os.getegid() == 0 and sys.flags.isolated
                and sys.flags.no_site and sys.dont_write_bytecode, 'ROOT_ISOLATED_NO_ARGUMENT_ENTRY_REQUIRED')
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (PROFILE['maximumMemoryBytes'], PROFILE['maximumMemoryBytes']))
        resource.setrlimit(resource.RLIMIT_CPU, (40, 40))
        import signal
        signal.signal(signal.SIGALRM, lambda *_: require(False, 'OFFLINE_PLAN_DEADLINE'))
        signal.alarm(45)
        os.umask(0o077); control = OfflineFiles(); control.ancestry(SCOPE)
        require(not os.path.lexists(SCOPE), 'OFFLINE_PLAN_SCOPE_CONSUMED_NO_REPLAY')
        os.mkdir(SCOPE, 0o700); created = True
        parent_fd = os.open(SCOPE.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        # Parent mtime changes only when creating this NEW scope; do not compare
        # it against its own pre-creation frame when preserving input artifacts.
        control.seals = {}
        put(SCOPE, 'claim.json', {'profile': PROFILE, 'automaticReplayAllowed': False})
        report = collect_plan(control); put(SCOPE, 'result.json', report)
        print(json.dumps(report, sort_keys=True)); return 0
    except Exception as error:
        reason = str(error) if type(error) is PlanError and re.fullmatch('[A-Z0-9_]{1,128}', str(error)) else 'OFFLINE_PLAN_UNPROVEN_PRIVATE_DETAILS_NOT_PRINTED'
        report = {'status': 'STOP_RECONCILE', 'reasonCode': reason,
          'scopeConsumed': os.path.lexists(SCOPE), 'newAnalysisClaimCreated': created,
          'cumulativeControlAttempts': 17 if os.path.lexists(SCOPE) else 16,
          'cumulativeDirectEngineGets': 52, 'directEngineGets': 0, 's3Requests': 0,
          'objectBodiesRead': 0, 'credentialFilesOpened': 0, 'runtimeAuthorityIssued': False,
          'targetApplyAuthorized': False, 'automaticReplayAllowed': False}
        if control:
            report.update(privateMetadataFilesOpened=control.opened, privateMetadataBytesRead=control.bytes)
        if created:
            try:
                put(SCOPE, 'result.json', report)
            except Exception:
                pass
        print(json.dumps(report, sort_keys=True)); return 1

SOURCE_MANIFEST = {'tools/storage_planning/inventory_manifest.py': '5aabd44d0df99e08f95cfa7d085e449b05ad1d4fd5c5c581364675d2930baec1', 'tools/storage_planning/target_plan_20261102.py': '4cb27cc2f190fb2a21a35acd391294383f7ddb476292cd533cc1afd7b9c07670'}
if __name__ == '__main__':
    if sys.argv[1:] == ['--inspect-source']:
        print(json.dumps({'status':'OFFLINE_PLAN_SOURCE_INSPECTED','sources':SOURCE_MANIFEST,'targetOperations':0,'runtimeAuthorityIssued':False},sort_keys=True))
    else:
        raise SystemExit(main())
