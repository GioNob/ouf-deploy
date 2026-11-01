#!/usr/bin/env python3
"""Verify and retain the two original deliveries; no build or target access.

The complete original ZIP and original signed checksum subject remain the
provenance boundary. A subset receipt is not a new installation package.
The workflow verifies the original publisher's signature separately.
"""
import argparse, hashlib, json, re, shutil, stat, sys, zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from tools.semantic_application_cutover.image_custody import archive, native_identity

ZIP_SHA = 'be55c6eda4485a4c90da9872f63e2533abe21c741c4926ecc129626cc01530f9'
PRODUCER = 'f31a653ee1da56b29a6171c159f9c601523735b9'
SOURCES = {'mcp': 'f249b3dcc58c2a96742092d90fa09fd90b705bd0',
    'udp': 'b49c0d6f50c574c11684361ce4e8040e9cbddee2'}
NATIVE = {'mcp': 'sha256:4dfefd95c88048b86cc13006bca1b0dbfd173feed12e0e1e32f35691f593eaeb',
    'udp': 'sha256:ae78f604ef485dda3751222ce418e03027d2db87bc49d8cb1faf8de3e2b60b52'}
METADATA = ('COHORT_SHA256SUMS', 'COHORT_SHA256SUMS.sigstore.json', 'cohort-manifest.json', 'source-lock.json')


def require(ok, reason):
    if not ok: raise ValueError(reason)


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def relative(name):
    require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.@/-]+', name)
        and not name.startswith('/') and str(PurePosixPath(name)) == name
        and '..' not in PurePosixPath(name).parts, 'EXACT_ORIGINAL_MEMBER_PATH_REQUIRED')
    return name


def checksums(raw):
    result = {}
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  (.+)', line)
        require(match is not None, 'EXACT_ORIGINAL_CHECKSUM_LINE_REQUIRED')
        name = relative(match[2]); require(name not in result, 'DUPLICATE_ORIGINAL_CHECKSUM_DENIED')
        result[name] = match[1]
    require(1 <= len(result) <= 256, 'BOUNDED_ORIGINAL_CHECKSUM_SET_REQUIRED')
    return result


def preserve(source, output):
    require(not output.exists() and source.is_file() and not source.is_symlink()
        and source.stat().st_size == 1708468889 and sha(source) == ZIP_SHA,
        'EXACT_ORIGINAL_COHORT_ZIP_REQUIRED')
    with zipfile.ZipFile(source) as zipped:
        entries = {}
        total = 0
        for entry in zipped.infolist():
            name = relative(entry.filename)
            require(name not in entries and len(entries) < 512 and not entry.is_dir()
                and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG)
                and 0 < entry.file_size <= 2147483648, 'BOUNDED_UNIQUE_REGULAR_ORIGINAL_ZIP_MEMBERS_REQUIRED')
            entries[name] = entry; total += entry.file_size
        require(total <= 6*1024**3, 'BOUNDED_ORIGINAL_DELIVERY_EXPANSION_REQUIRED')

        def raw(name, expected=None):
            require(name in entries and entries[name].file_size <= 8388608, 'BOUNDED_ORIGINAL_METADATA_REQUIRED')
            value = zipped.read(entries[name])
            require(expected is None or hashlib.sha256(value).hexdigest() == expected,
                'ORIGINAL_METADATA_CHECKSUM_DIFFERS')
            return value

        declared = checksums(raw('COHORT_SHA256SUMS'))
        require(set(entries) == set(declared) | set(METADATA[:2]), 'EXACT_ORIGINAL_ZIP_CHECKSUM_CLOSURE_REQUIRED')
        manifest = json.loads(raw('cohort-manifest.json', declared['cohort-manifest.json']))
        lock = raw('source-lock.json', declared['source-lock.json'])
        require(manifest['schema'] == 'ouf.chatbot-file-cohort-package.v1'
            and manifest['producer']['sourceCommit'] == PRODUCER
            and manifest['sourceLockSha256'] == hashlib.sha256(lock).hexdigest()
            and manifest['runtimeAuthorityIssued'] is manifest['targetApplyAuthorized'] is False,
            'EXACT_ORIGINAL_COHORT_MANIFEST_REQUIRED')
        records = {v['module']: v for v in manifest['modules']}
        require(len(records) == len(manifest['modules']) == 6, 'EXACT_ORIGINAL_SIX_MODULES_REQUIRED')
        for name, commit in SOURCES.items():
            record = records[name]
            require(record['sourceCommit'] == commit and record['cohortSourceLockSha256'] == manifest['sourceLockSha256']
                and record['artifactKind'] == 'DOCKER_SAVE'
                and record['scanGate'] == 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
                and checksums(raw(name+'/SHA256SUMS', declared[name+'/SHA256SUMS'])) == record['files']
                and all(declared.get(name+'/'+relative(member)) == value for member, value in record['files'].items()),
                'EXACT_ORIGINAL_MODULE_AND_MEMBER_CLOSURE_REQUIRED')
        output.mkdir(mode=0o700)
        for name in METADATA:
            destination = output/'origin'/name; destination.parent.mkdir(mode=0o700, exist_ok=True)
            destination.write_bytes(raw(name, declared.get(name)))
        observed = {}
        for name, commit in SOURCES.items():
            record = records[name]; folder = output/name; folder.mkdir(mode=0o700)
            for member in sorted(set(record['files']) | {'SHA256SUMS'}):
                expected = declared[name+'/'+member]; destination = folder/member
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with zipped.open(entries[name+'/'+member]) as original, destination.open('xb') as copy:
                    shutil.copyfileobj(original, copy, length=1048576)
                require(sha(destination) == expected, 'ORIGINAL_PAYLOAD_BYTES_DIFFER')
            package = json.loads((folder/'package-record.json').read_bytes())
            candidate = json.loads((folder/'candidate-manifest.json').read_bytes())
            require(candidate == {k: v for k, v in record.items() if k != 'files'}
                and package['schema'] == 'ouf.unsigned-offline-candidate-package.v1'
                and package['sourceCommit'] == commit and package['module'] == name
                and package['imageId'] == record['imageId'], 'EXACT_ORIGINAL_PRODUCER_RECORDS_REQUIRED')
            with (folder/'image.docker.tar').open('rb') as image:
                proof = archive(image, record['files']['image.docker.tar'], record['imageId'], commit)
            identity = native_identity(proof)
            require(identity['nativeImageId'] == NATIVE[name], 'EXACT_ORIGINAL_NATIVE_IMAGE_ID_REQUIRED')
            observed[name] = {'sourceCommit': commit, 'imageId': record['imageId'],
                'nativeImageId': identity['nativeImageId'], 'originalArchiveSha256': record['files']['image.docker.tar'],
                'rawPackageHash': digest(package), 'deliveryManifestHash': digest(candidate),
                'imageAudit': proof, 'originalFiles': record['files']}
        receipt = {'schema': 'ouf.m2-original-mcp-udp-members.v1', 'originalZipSha256': ZIP_SHA,
            'originalProducer': PRODUCER, 'originalRun': 38536134146, 'originalArtifact': 11880585559,
            'modules': observed, 'imageRebuilt': False, 'candidateSelectionChanged': False,
            'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}
        (output/'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n')
        return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('source', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args(); preserve(args.source, args.output)
