#!/usr/bin/env python3
"""Verify a pinned SeaweedFS 4.52 artifact and independently reproduce its assessment."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('candidate', ROOT / 'scripts/qualify-seaweedfs-452-generation29-image.py')
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)
require = candidate.image.require
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_EXPANDED = 1024 * 1024 * 1024
CHECKSUM = re.compile(r'([a-f0-9]{64})  (.+)')


def file_hash(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checksum_map(lines):
    sums = {}
    for line in lines:
        match = CHECKSUM.fullmatch(line)
        require(match is not None, 'INVALID_CHECKSUM_LINE')
        digest, name = match.groups()
        p = PurePosixPath(name)
        require(str(p) == name and not p.is_absolute() and '..' not in p.parts
                and '\\' not in name and name not in sums, 'UNSAFE_OR_DUPLICATE_CHECKSUM_PATH')
        sums[name] = digest
    return sums


def unpack(path, root):
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        names = {entry.filename for entry in members}
        require(len(members) == len(names) == 22, 'EXACT_UNIQUE_ARCHIVE_MEMBERS_REQUIRED')
        require(sum(entry.file_size for entry in members) <= MAX_EXPANDED,
                'UNCOMPRESSED_ARCHIVE_BUDGET')
        manifest = archive.getinfo('SHA256SUMS')
        require(manifest.file_size <= 16384, 'BOUNDED_CHECKSUM_MANIFEST_REQUIRED')
        sums = checksum_map(archive.read(manifest).decode().splitlines())
        require(set(sums) == names - {'SHA256SUMS', 'provenance.json'}, 'COMPLETE_CHECKSUM_CLOSURE_REQUIRED')
        for entry in members:
            name = PurePosixPath(entry.filename)
            require(str(name) == entry.filename and not name.is_absolute() and '..' not in name.parts
                    and '\\' not in entry.filename, 'SAFE_ARCHIVE_PATH_REQUIRED')
            require(not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16),
                    'REGULAR_ARCHIVE_MEMBER_REQUIRED')
            dest = root / entry.filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as inp, dest.open('xb') as out:
                shutil.copyfileobj(inp, out)
            if entry.filename in sums:
                require(file_hash(dest) == sums[entry.filename], 'CHECKSUM_MISMATCH:' + entry.filename)
        return sums


def verify(path, output, expected_sha, producer, run_id):
    require(not output.exists(), 'NEW_READBACK_OUTPUT_REQUIRED')
    require(0 < path.stat().st_size <= MAX_ARCHIVE and file_hash(path) == expected_sha,
            'EXACT_IMAGE_ARTIFACT_REQUIRED')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        sums = unpack(path, root)
        sources = checksum_map((root / 'source-SHA256SUMS').read_text().splitlines())
        require(set(sources) == candidate.source_names(), 'EXACT_GENERATION29_SOURCE_SET_REQUIRED')
        candidate.verify_patch_sources()
        for name, digest in sources.items():
            require(file_hash(ROOT / name) == digest, 'QUALIFIED_SOURCE_CHANGED:' + name)
        image_id = (root / 'daemon-image-id.txt').read_text().strip()
        actual = candidate.assess(root, image_id, producer, run_id)
        require(actual == json.loads((root / 'assessment.json').read_bytes()),
                'ASSESSMENT_REPRODUCTION_REQUIRED')
        require(actual['vulnerabilitySubgate'] == 'PASS_RAW', 'UNRESOLVED_RAW_VULNERABILITIES')
        require(actual['sdkLifecycle']['status'] == 'AWS_SDK_V1_ABSENT'
                and not actual['deprecatedS3ManagerPresent'], 'LEGACY_IMAGE_DEPENDENCY_PRESENT')
        require(bool((root / 'version-smoke.txt').read_text().strip()), 'VERSION_SMOKE_REQUIRED')
        output.mkdir()
        for name in ('SHA256SUMS', 'provenance.json', 'assessment.json', 'source-SHA256SUMS',
                     'generation-manifest.json', 'build-source.json'):
            shutil.copyfile(root / name, output / name)
        result = {
            'schema': 'ouf.seaweedfs-452-generation29-image-readback.v1', 'generation': 29,
            'archiveSha256': expected_sha, 'producerCommit': producer, 'producerRunId': run_id,
            'checksumMembersVerified': len(sums), 'patchedSourceTree': actual['patchedSourceTree'], 'sourceFilesVerified': len(sources),
            'ociManifestDigest': actual['manifestDigest'], 'imageConfigDigest': image_id,
            'binarySha256': actual['binarySha256'], 'rawSeverityCounts': actual['rawSeverityCounts'],
            'vulnerabilitySubgate': actual['vulnerabilitySubgate'],
            'sdkLifecycle': actual['sdkLifecycle']['status'],
            'publisherSignatureVerifiedByThisScript': False, 'targetOperations': 0,
        }
        (output / 'byte-readback.json').write_bytes(candidate.image.canonical(result))
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('archive_sha256')
    parser.add_argument('producer_commit')
    parser.add_argument('run_id', type=int)
    args = parser.parse_args(argv)
    try:
        result = verify(args.archive, args.output, args.archive_sha256, args.producer_commit, args.run_id)
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile) as error:
        print('INVALID_GENERATION29_READBACK: ' + str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
