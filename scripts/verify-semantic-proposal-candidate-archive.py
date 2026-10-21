#!/usr/bin/env python3
"""Inspect exact GitHub CI archives without loading images or executing binaries."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

SOURCES = {
    'semantic': 'bdfe0f75a5fc4790a5c5ff36e201c3d99713ecc0',
    'mcp': 'd43f5604976b07c66d58c5180d871c5656c44d4d',
    'gateway': '23b02bd2195d36499b6618750d52dd49d65c9a60',
}

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def sha(stream):
    h = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1048576), b''):
        h.update(chunk)
    return h.hexdigest()

def verify(path, module, expected_digest):
    with path.open('rb') as stream:
        require(sha(stream) == expected_digest, 'CI_ARCHIVE_DIGEST_MISMATCH')
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        require(0 < len(infos) <= 32, 'ARCHIVE_ENTRY_LIMIT')
        names = [i.filename for i in infos]
        require(len(set(names)) == len(names), 'DUPLICATE_ARCHIVE_ENTRY')
        require(sum(i.file_size for i in infos) <= 2147483648, 'ARCHIVE_SIZE_LIMIT')
        for info in infos:
            name = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            require(not name.is_absolute() and '..' not in name.parts
                    and str(name) == info.filename and '\\' not in info.filename
                    and not info.is_dir() and not info.flag_bits & 1
                    and (not stat.S_IFMT(mode) or stat.S_ISREG(mode)), 'UNSAFE_ARCHIVE_ENTRY')
        checks = {}
        for line in archive.read('SHA256SUMS').decode().splitlines():
            match = re.fullmatch(r'([0-9a-f]{64})  ([^\r\n]+)', line)
            require(match is not None, 'CHECKSUM_LINE_INVALID')
            digest, name = match.groups()
            require(name not in checks, 'DUPLICATE_CHECKSUM_ENTRY')
            checks[name] = digest
        require(set(checks) == set(names) - {'SHA256SUMS'}, 'CHECKSUM_COVERAGE_MISMATCH')
        for name, digest in checks.items():
            with archive.open(name) as stream:
                require(sha(stream) == digest, 'PACKAGE_FILE_DIGEST_MISMATCH')
        manifest = json.loads(archive.read('candidate-manifest.json'))
        require(manifest.get('schema') == 'ouf.semantic-proposal-unsigned-candidate.v1'
                and manifest.get('module') == module
                and manifest.get('sourceCommit') == SOURCES[module], 'SOURCE_MANIFEST_MISMATCH')
        for key, value in {'runtimeAuthorityIssued': False, 'signatureIssued': False,
                           'targetApplyAuthorized': False, 'notReleaseAcceptance': True,
                           'vpsOperations': 0, 'r12Touched': False, 'budgetReset': False}.items():
            require(type(manifest.get(key)) is type(value) and manifest[key] == value,
                    'CANDIDATE_AUTHORITY_FLAGS_INVALID')
        inventory = json.loads(archive.read('source-inventory.json'))
        require(inventory.get('truncated') is False and bool(inventory.get('tree')),
                'SOURCE_INVENTORY_MISSING')
        scan = json.loads(archive.read('trivy-image.json'))
        require(scan.get('SchemaVersion') == 2 and type(scan.get('Results')) is list
                and bool(scan['Results']), 'SCANNER_REPORT_MISSING')
        required = {'semantic': 'jar', 'mcp': 'gobinary', 'gateway': 'pip'}[module]
        require(any(r.get('Type') == required and r.get('Packages') for r in scan['Results']),
                'SCANNER_PACKAGE_COVERAGE_MISSING')
        for result in scan['Results']:
            require(result.get('Class') in {'os-pkgs', 'lang-pkgs'}, 'SCANNER_CLASS_INVALID')
            for finding in result.get('Vulnerabilities', []):
                require(finding.get('Severity') in {'LOW', 'MEDIUM'}, 'VULNERABILITY_GATE_REJECTED')
        if module == 'semantic':
            require(any(r.get('Class') == 'os-pkgs' and r.get('Packages') for r in scan['Results']),
                    'OS_SCANNER_COVERAGE_MISSING')
            record = json.loads(archive.read('package-record.json'))
            require(record.get('sourceCommit') == SOURCES[module]
                    and record.get('imageId') == manifest.get('imageId')
                    and scan.get('Metadata', {}).get('ImageID') == manifest.get('imageId'),
                    'IMAGE_IDENTITY_MISMATCH')
            require('image.docker.tar' in checks and 'application.jar' in checks,
                    'IMAGE_PACKAGE_INCOMPLETE')
        if module == 'mcp':
            build = json.loads(archive.read('build-record.json'))
            require(build.get('sourceCommit') == SOURCES[module]
                    and build.get('executableSha256') == checks.get('ouf-mcp')
                    and manifest.get('executableSha256') == checks.get('ouf-mcp'),
                    'EXECUTABLE_IDENTITY_MISMATCH')
        if module == 'gateway':
            require(manifest.get('requirementsSha256') == checks.get('gateway-scan/requirements.txt')
                    and manifest.get('transitivePythonRuntimeQualificationProven') is False,
                    'DEPENDENCY_SCOPE_MISMATCH')
        require('source.tar' in checks, 'SOURCE_ARCHIVE_MISSING')
        return {'module': module, 'sourceCommit': SOURCES[module], 'archiveSha256': expected_digest,
                'fileSha256': checks, 'imageId': manifest.get('imageId'),
                'targetApplyAuthorized': False, 'notReleaseAcceptance': True}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--module', choices=list(SOURCES), required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    try:
        require(re.fullmatch('[0-9a-f]{64}', args.sha256) is not None, 'EXPECTED_DIGEST_INVALID')
        result = verify(args.archive, args.module, args.sha256)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(json.dumps({'phase': 'OFFLINE_ARCHIVE_VERIFY', 'reason': reason,
                          'module': args.module, 'evidenceLocation': str(args.archive),
                          'automaticRetry': False, 'targetApplyAuthorized': False}))
        raise SystemExit(1)
    print(json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    main()
