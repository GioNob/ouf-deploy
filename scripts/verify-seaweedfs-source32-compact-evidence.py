#!/usr/bin/env python3
"""Verify lossless source32 publication; optionally reconstruct original evidence."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(root, relative):
    path = PurePosixPath(relative)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('unsafe evidence path: ' + relative)
    result = root.joinpath(*path.parts)
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError('evidence path escapes root: ' + relative)
    return result


def verify(root, materialize=None):
    mapping_path = root / 'evidence/seaweedfs-source32-compact-publication-20261103.json'
    mapping_bytes = mapping_path.read_bytes()
    mapping = json.loads(mapping_bytes)
    if mapping['schema'] != 'ouf.seaweedfs-source32-compact-publication.v1':
        raise ValueError('unexpected compact publication schema')
    manifest_ref = mapping['originalDeliveryManifest']
    manifest_bytes = safe_path(root, manifest_ref['publishedPath']).read_bytes()
    if digest(manifest_bytes) != manifest_ref['sha256']:
        raise ValueError('original delivery manifest hash mismatch')
    original = json.loads(manifest_bytes)['files']
    if set(original) != set(mapping['files']) or len(original) != 117:
        raise ValueError('incomplete or unexpected original evidence coverage')
    if materialize is not None:
        materialize.mkdir(parents=True, exist_ok=False)
    physical_paths = set()
    count = total = compressed = 0
    for logical, expected in sorted(original.items()):
        entry = mapping['files'][logical]
        physical = entry['publishedPath']
        if physical in physical_paths:
            raise ValueError('duplicate physical payload: ' + physical)
        physical_paths.add(physical)
        data = safe_path(root, physical).read_bytes()
        if len(data) != entry['publishedBytes'] or digest(data) != entry['publishedSha256']:
            raise ValueError('published payload mismatch: ' + physical)
        if entry['encoding'] == 'gzip':
            with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as stream:
                decoded = stream.read(expected['bytes'] + 1)
            compressed += 1
        elif entry['encoding'] == 'identity':
            decoded = data
        else:
            raise ValueError('unsupported encoding: ' + entry['encoding'])
        if expected != {'bytes': entry['originalBytes'], 'sha256': entry['originalSha256']}:
            raise ValueError('original manifest mapping mismatch: ' + logical)
        if len(decoded) != expected['bytes'] or digest(decoded) != expected['sha256']:
            raise ValueError('decoded original mismatch: ' + logical)
        if materialize is not None:
            destination = safe_path(materialize, logical)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(decoded)
        count += 1
        total += len(decoded)
    frozen = mapping['frozenQualificationReceipt']
    receipt_entry = mapping['files'][frozen['logicalPath']]
    if receipt_entry['encoding'] != 'identity' or receipt_entry['originalSha256'] != frozen['sha256']:
        raise ValueError('frozen qualification receipt changed or not direct')
    return {'status': 'PASS', 'originalInputsVerified': count,
            'originalBytesVerified': total, 'gzipPayloadsVerified': compressed,
            'identityPayloadsVerified': count - compressed,
            'frozenReceiptSha256': frozen['sha256'],
            'compactMappingSha256': digest(mapping_bytes),
            'materialized': materialize is not None}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--materialize', type=Path,
                        help='new, nonexistent directory for all117 original files')
    args = parser.parse_args()
    print(json.dumps(verify(args.root, args.materialize), indent=2))
