#!/usr/bin/env python3
"""Assess AWS SDK v1 in an independently authenticated SeaweedFS image archive."""
import argparse
import hashlib
import json
import re
import sys
import zipfile

SDK_V1 = 'github.com/aws/aws-sdk-go'
WEED = 'github.com/seaweedfs/seaweedfs/weed'
INPUTS = (
    'original-candidate.json', 'original-compiled-packages.json',
    'image-record.json', 'fresh-image-scan.json', 'image.spdx.json',
)
MAX_METADATA = 16 * 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sdk_v1(path):
    path = path.removeprefix('vendor/').rsplit('/vendor/', 1)[-1]
    return path == SDK_V1 or path.startswith(SDK_V1 + '/')


def read_evidence(archive):
    def read(name):
        entries = [entry for entry in archive.infolist() if entry.filename == name]
        require(len(entries) == 1 and 0 < entries[0].file_size <= MAX_METADATA,
                'ONE_BOUNDED_MEMBER_REQUIRED:' + name)
        return archive.read(entries[0])

    manifest = read('SHA256SUMS').decode().splitlines()
    evidence = {}
    for name in INPUTS:
        data = read(name)
        entries = [line for line in manifest if line.endswith('  ' + name)]
        require(entries == [sha256(data) + '  ' + name], 'MEMBER_CHECKSUM_MISMATCH:' + name)
        evidence[name] = data
    return evidence


def assess(evidence):
    candidate, graph, image, scan, spdx = (json.loads(evidence[name]) for name in INPUTS)
    binary_sha = candidate['binarySha256']
    source = candidate['declaredSource']
    require(re.fullmatch(r'[0-9a-f]{64}', binary_sha)
            and re.fullmatch(r'[0-9a-f]{40}', source)
            and (image['binarySha256'], image['sourceCommit']) == (binary_sha, source),
            'EXACT_BINARY_AND_SOURCE_REQUIRED')
    require(sha256(evidence['original-compiled-packages.json']) == candidate['compiledPackagesSha256'],
            'COMPILED_GRAPH_CHANGED')
    packages = graph['packages']
    require(isinstance(packages, list) and all(isinstance(p, str) and p for p in packages)
            and len(set(packages)) == len(packages)
            and {WEED, WEED + '/s3api'} <= set(packages), 'WEED_S3_PACKAGE_GRAPH_REQUIRED')

    metadata = scan['Metadata']
    config = metadata['ImageConfig']['config']
    labels = config['Labels']
    image_id = image['configDigest']
    require(scan['SchemaVersion'] == 2 and re.fullmatch(r'sha256:[0-9a-f]{64}', image_id)
            and metadata['ImageID'] == image_id
            and labels['org.ouf.binary.sha256'] == binary_sha
            and labels['org.opencontainers.image.revision'] == source
            and config['Entrypoint'] == ['/usr/local/bin/weed'], 'EXACT_IMAGE_SCAN_REQUIRED')
    results = scan['Results']
    require(isinstance(results, list) and len(results) == 1, 'ONE_WEED_SCAN_TARGET_REQUIRED')
    result = results[0]
    require(result['Target'].lstrip('/') == 'usr/local/bin/weed'
            and result['Class'] == 'lang-pkgs' and result['Type'] == 'gobinary',
            'WEED_GO_BINARY_INVENTORY_REQUIRED')
    scanned = {(p['Name'], p['Version']) for p in result['Packages']}
    require(len(scanned) > 1 and any(name == 'stdlib' for name, _ in scanned)
            and all(isinstance(name, str) and name and isinstance(version, str) and version
                    for name, version in scanned), 'NONEMPTY_BINARY_MODULE_INVENTORY_REQUIRED')

    require(spdx['spdxVersion'] == 'SPDX-2.3' and bool(spdx['documentNamespace']),
            'SPDX_23_REQUIRED')
    bom = {(p['name'], p.get('versionInfo')) for p in spdx['packages']}
    require(scanned <= bom, 'SBOM_MUST_INCLUDE_ALL_SCANNED_PACKAGES')
    graph_hits = sorted(p for p in packages if sdk_v1(p))
    scan_hits = sorted({name + '@' + version for name, version in scanned if sdk_v1(name)})
    bom_hits = sorted({name + '@' + (version or 'UNSPECIFIED') for name, version in bom if sdk_v1(name)})
    return {
        'schema': 'ouf.storage-sdk-lifecycle-assessment.v1',
        'status': 'HELD_AWS_SDK_V1_PRESENT' if graph_hits or scan_hits or bom_hits else 'AWS_SDK_V1_ABSENT',
        'binarySha256': binary_sha,
        'sourceCommit': source,
        'imageConfigDigest': image_id,
        'compiledPackageCount': len(packages),
        'scannedModuleCount': len(scanned),
        'compiledSdkV1Packages': graph_hits,
        'scannedSdkV1Modules': scan_hits,
        'sbomSdkV1Modules': bom_hits,
        'releaseAdmitted': False,
        'targetOperations': 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('verified_archive', help='ZIP from the independently verified image qualification')
    args = parser.parse_args()
    try:
        with zipfile.ZipFile(args.verified_archive) as archive:
            result = assess(read_evidence(archive))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile) as exc:
        print(f'INVALID_EVIDENCE: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'AWS_SDK_V1_ABSENT' else 1


if __name__ == '__main__':
    sys.exit(main())
