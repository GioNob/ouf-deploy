"""Offline inventory checks. Inputs remain private; public output contains counts only.

Not a target reader or migrator. No S3, Docker or lifecycle calls are made.
"""
import hashlib
import json
import re

HASH = re.compile(r'^sha256:[0-9a-f]{64}$')


def validate(records, require_hashes=False):
    seen = set(); buckets = {}; latest = set(); versions = 0; markers = 0; total = 0
    for row in records:
        if not isinstance(row, dict) or not {'bucket','key','versionId','isLatest','deleteMarker','size','sha256','metadataSha256'} <= set(row):
            raise ValueError('INCOMPLETE_INVENTORY_RECORD')
        bucket, key, version = row['bucket'], row['key'], row['versionId']
        if not isinstance(bucket,str) or not bucket or not isinstance(key,str) or not key or not (version is None or (isinstance(version,str) and bool(version))):
            raise ValueError('INVALID_INVENTORY_IDENTITY')
        if type(row['isLatest']) is not bool or type(row['deleteMarker']) is not bool or type(row['size']) is not int or row['size'] < 0:
            raise ValueError('INVALID_INVENTORY_FLAGS_OR_SIZE')
        identity = (bucket,key,version)
        if identity in seen:raise ValueError('DUPLICATE_OBJECT_VERSION')
        seen.add(identity)
        if row['isLatest']:
            if (bucket,key) in latest:raise ValueError('MULTIPLE_LATEST_VERSIONS')
            latest.add((bucket,key))
        for field in ['sha256','metadataSha256']:
            value = row[field]
            if value is not None and (not isinstance(value,str) or not HASH.fullmatch(value)):
                raise ValueError('INVALID_HASH')
            if require_hashes and not row['deleteMarker'] and value is None:raise ValueError('VERIFIED_HASH_REQUIRED')
        if row['deleteMarker']:
            if row['size'] != 0:raise ValueError('DELETE_MARKER_WITH_CONTENT')
            markers += 1
        else:total += row['size']
        if version is not None:versions += 1
        buckets.setdefault(bucket,set()).add(key)
    # Check ALL versions, including keys hidden by current delete markers.
    conflicts = 0; unsafe = 0; trailing = 0
    for keys in buckets.values():
        for key in keys:
            if key.endswith('/'):trailing += 1
            parts = key.split('/')
            if any(p in ('.','..') for p in parts) or '\\' in key or '\x00' in key or '//' in key or key.startswith('/'):
                unsafe += 1
            if any('/'.join(parts[:i]) in keys for i in range(1,len(parts))):conflicts += 1
    canonical = json.dumps(sorted(records,key=lambda x:(x['bucket'],x['key'],x['versionId'] or '')),sort_keys=True,separators=(',',':')).encode()
    return {'schema':'ouf.storage-inventory-summary.v1','records':len(seen),'buckets':len(buckets),'bytesAcrossVersions':total,
            'versionedRecords':versions,'deleteMarkers':markers,'fileDirectoryCollisions':conflicts,'unsafePathKeys':unsafe,
            'trailingSlashKeys':trailing,'inventorySha256':hashlib.sha256(canonical).hexdigest(),
            'namespaceGate':'HELD' if conflicts or unsafe or trailing else 'PASS','targetInventoryCompletenessProven':False}


def compare_verified(source, destination):
    for records in [source,destination]:
        if validate(records,require_hashes=True)['namespaceGate'] != 'PASS':
            raise ValueError('UNRESOLVED_NAMESPACE_DIFFERENCE')
    # Version IDs can change: destination must carry the source identity mapping.
    def mapping(rows, mapped):
        result={}
        for r in rows:
            version=r.get('sourceVersionId',r['versionId']) if mapped else r['versionId']
            key=(r['bucket'],r['key'],version)
            if key in result:raise ValueError('DUPLICATE_SOURCE_VERSION_MAPPING')
            result[key]=tuple(r[f] for f in ['isLatest','deleteMarker','size','sha256','metadataSha256'])
        return result
    a,b=mapping(source,False),mapping(destination,True)
    return {'missing':len(a.keys()-b.keys()),'extra':len(b.keys()-a.keys()),'mismatch':sum(a[k]!=b[k] for k in a.keys()&b.keys())}
