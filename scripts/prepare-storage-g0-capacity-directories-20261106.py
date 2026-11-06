#!/usr/bin/env python3
"""Create one fresh private capacity staging area, then check a new input.

No existing directory is adopted, chmod/chown'd or removed. No provider call,
runtime grant or migration. The original package supplies capacity/preflight.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from datetime import datetime, timezone

STAGING = Path('/var/lib/ouf-g0-network-preparation-20261106')
AREA = Path('/var/lib/ouf-storage-migration')
SCOPE = 'capacity-directory-preparation-20261106'
MANIFEST_SHA = '1e542f786ac1606cf72f273bc079eaa5b06b6bd22a210d615c10d13a9d9f8adf'
INPUT_SHA = '8643c92990916d9717d92d3dcc18d1c89f1a33e4d31e4c2a3f4b7dae91ce6a7b'
REUSED_BINDINGS = {
    'connection:ingestion': 'a8886bbd14fed01aa863179a3364946fcc577139b973e414239cbd59346bcc75',
    'connection:onboarding': '6578413567754d9598ff3e53eabd64fe4d22228f0d01f09366f3b26002164952',
    'connection:s3': '42dba0ef889090707f48566340a06e20cb504b9c98ec6fc2442b6a8a55e1f512',
    'connection:udp': '6ab5f2a0f7fdddbae7f09ea8d3192038226254404d982b233c7cdd6807715ca0',
    'network': 'c0700c8f6b35e6e00d58458c39ccc24a0c3994298a822e74a046ac3bd00e4ecb',
    'operator:runtime': 'c958f52f6fc25c07a42a0a2b48ddab2f185316895dc449df1a14defe6b22ba97',
}


class Held(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Held(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def directory(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.path.normpath(path), 'CAPACITY_CANONICAL_PATH')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in ('', *path.parts[1:]):
            if part:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'CAPACITY_ROOT_PROTECTED_ANCESTRY')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path, limit, private=True):
    path = Path(path)
    parent = directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and 0 < before.st_size <= limit and not before.st_mode & 0o022,
                'CAPACITY_BOUNDED_ROOT_FILE')
        if private:
            require(stat.S_IMODE(before.st_mode) == 0o600, 'CAPACITY_PRIVATE_FILE_MODE')
        raw = os.read(fd, limit + 1)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'CAPACITY_FILE_CHANGED')
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def verify_bundle(bundle, expected):
    raw = read(bundle / 'package-manifest.json', 262144, private=False)
    require(sha(raw) == expected, 'CAPACITY_EXACT_PACKAGE_MANIFEST')
    manifest = json.loads(raw)
    require(manifest.get('schema') == 'ouf.storage-g0-package.v1'
            and manifest.get('runtimeAuthorityIssued') is False, 'CAPACITY_PACKAGE_SCHEMA')
    expected_files = set(manifest['files']) | {'package-manifest.json'}
    observed = set()
    for root, dirs, files in os.walk(bundle, followlinks=False):
        require(len(observed) <= 64, 'CAPACITY_BOUNDED_PACKAGE')
        for name in dirs:
            require(not (Path(root) / name).is_symlink(), 'CAPACITY_PACKAGE_DIRECTORY_LINK')
        observed.update(str((Path(root) / name).relative_to(bundle)) for name in files)
    require(observed == expected_files, 'CAPACITY_EXACT_PACKAGE_FILE_SET')
    for name, digest in manifest['files'].items():
        p = Path(name)
        require(not p.is_absolute() and '..' not in p.parts, 'CAPACITY_PACKAGE_MEMBER')
        require(sha(read(bundle / p, 64 << 20, private=False)) == digest, 'CAPACITY_PACKAGE_SOURCE_CHANGED')


def put(root, name, value):
    raw = encode(value)
    parent = directory(root)
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def absent(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def prepare(staging, area, bundle, manifest_sha, input_sha, preflight, capacity, *, clock=time.monotonic,
            expected_bindings=REUSED_BINDINGS):
    require(os.geteuid() == os.getegid() == 0, 'CAPACITY_ROOT_ONLY')
    scope = staging / 'inputs' / SCOPE
    if os.path.lexists(scope):
        result = json.loads(read(scope / 'result.json', 65536))
        result['existingResultReadOnly'] = True
        return result
    original_path = staging / 'inputs/database-draft-continuation-20261106/package-input.review.json'
    original = read(original_path, 65536)
    require(sha(original) == input_sha, 'CAPACITY_EXACT_CHECKED_INPUT_REQUIRED')
    config = json.loads(original)
    reused_paths = {'connection:' + key: value for key, value in config['connectionFiles'].items()}
    reused_paths['operator:runtime'] = config['operatorEvidenceFiles']['runtime']
    if config.get('networkBindingFile'):
        reused_paths['network'] = config['networkBindingFile']
    require(set(reused_paths) == set(expected_bindings), 'CAPACITY_CHECKED_BINDING_DOMAIN')
    for key, value in reused_paths.items():
        require(sha(read(Path(value), 1 << 20)) == expected_bindings[key], 'CAPACITY_CHECKED_BINDING_CHANGED')
    require(config['collectionDecisionRef'] is None and config['capacityPaths']['destination'] == '/var/lib/ouf/seaweedfs'
            and config['capacityPaths']['backup'] == '/opt/ouf/backup/seaweedfs', 'CAPACITY_EXACT_PRIOR_PLAN')
    source_fd = directory(Path(config['capacityPaths']['source']))
    os.close(source_fd)
    parent = directory(area.parent)
    new_fd = None
    try:
        require(absent(parent, area.name), 'CAPACITY_AREA_ALREADY_EXISTS_NO_ADOPTION')
        inputs_fd = directory(staging / 'inputs')
        try:
            os.mkdir(SCOPE, 0o700, dir_fd=inputs_fd)
            os.fsync(inputs_fd)
        finally:
            os.close(inputs_fd)
        put(scope, 'claim.json', {'schema': 'ouf.storage-g0-capacity-preparation-claim.v1',
            'maximumAttempts': 1, 'maximumSeconds': 60, 'maximumDataDirectoriesCreated': 3,
            'originalInputSha256': input_sha, 'newArea': str(area), 'automaticReplayAllowed': False,
            'providerRequests': 0, 'runtimeAuthorityIssued': False})
        until = clock() + 60
        report = {'schema': 'ouf.storage-g0-capacity-preparation-result.v1', 'status': 'HELD',
            'dataDirectoryCreatesAttempted': 0, 'dataDirectoriesCreated': 0,
            'directoryOwnershipOrModesChanged': False, 'oldInputModified': False,
            'oldBackupAreaTouched': False, 'credentialCopiesRecreated': False,
            'localPreflightInvoked': False, 'collectionScopeCreated': False, 'providerRequests': 0,
            'runtimeAuthorityIssued': False, 'targetInputCheckPassed': False, 'g0Complete': False,
            'independentBackupVerified': False, 'capacitySufficiencyProven': False,
            'acceptanceCreditAdded': 0, 'automaticReplayAllowed': False}

        def guard():
            require(clock() < until, 'CAPACITY_PREPARATION_DEADLINE')
            require(read(original_path, 65536) == original, 'CAPACITY_ORIGINAL_INPUT_CHANGED')
            info = os.stat(area.parent, follow_symlinks=False)
            require((info.st_dev, info.st_ino) == (os.fstat(parent).st_dev, os.fstat(parent).st_ino),
                    'CAPACITY_PARENT_REBOUND')

        try:
            guard()
            report['dataDirectoryCreatesAttempted'] += 1
            os.mkdir(area.name, 0o700, dir_fd=parent)
            report['dataDirectoriesCreated'] += 1
            os.fsync(parent)
            new_fd = os.open(area.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            for name in ('seaweedfs', 'backup-staging'):
                guard()
                report['dataDirectoryCreatesAttempted'] += 1
                os.mkdir(name, 0o700, dir_fd=new_fd)
                report['dataDirectoriesCreated'] += 1
                os.fsync(new_fd)
            paths = {'source': config['capacityPaths']['source'],
                     'destination': str(area / 'seaweedfs'), 'backup': str(area / 'backup-staging')}
            for key in ('destination', 'backup'):
                fd = directory(Path(paths[key]))
                try:
                    info = os.fstat(fd)
                    require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700
                            and not os.listdir(fd), 'CAPACITY_NEW_PRIVATE_EMPTY_DIRECTORIES')
                finally:
                    os.close(fd)
            guard()
            observed = capacity(paths)
            guard()
            capacity_doc = {'schema': 'ouf.storage-g0-operator-evidence.v1',
                'installationRef': config['installationRef'], 'section': 'CAPACITY',
                'provenance': 'TECHNICAL_OBSERVATION', 'ownerRef': 'LOCAL_ROOT_CAPACITY_PREPARATION',
                'capturedAt': datetime.now(timezone.utc).isoformat(),
                'evidenceRefs': [str(scope / 'claim.json'), str(scope / 'capacity-observation.private.json')],
                'observation': observed, 'capacitySufficiencyProven': False,
                'growthAndThroughputProven': False, 'independentBackupVerified': False,
                'operatorAcceptance': False, 'sourceCustodyAdmitted': False}
            put(scope, 'capacity-observation.private.json', observed)
            put(scope, 'capacity-evidence.review.json', capacity_doc)
            config['capacityPaths'] = paths
            config['operatorEvidenceFiles']['capacity'] = str(scope / 'capacity-evidence.review.json')
            put(scope, 'package-input.review.json', config)
            guard()
            report['localPreflightInvoked'] = True
            checked = preflight(scope / 'package-input.review.json', bundle, manifest_sha)[-1]
            require(checked['status'] == 'LOCAL_INPUTS_BOUND_EXTERNAL_ADMISSION_REQUIRED'
                    and checked['targetReads'] == 0 and checked['runtimeAuthorityIssued'] is False,
                    'CAPACITY_LOCAL_PREFLIGHT_REQUIRED')
            require(all(checked['boundInputSha256'].get(key) == digest for key, digest in expected_bindings.items()),
                    'CAPACITY_REUSED_BINDING_CHANGED_DURING_CHECK')
            guard()
            put(scope, 'preflight.private.json', checked)
            report.update(status='CAPACITY_DIRECTORIES_PREPARED_LOCAL_INPUTS_BOUND_REVIEW_REQUIRED',
                inputSha256=checked['inputSha256'], operatorInputsMissing=checked['operatorInputsMissing'],
                localPreflightStatus=checked['status'], capacityEvidencePrepared=True,
                candidateInputFile=str(scope / 'package-input.review.json'),
                destination=paths['destination'], localBackupStaging=paths['backup'],
                capacityPathsExistAndMatchCollectorGuard=True,
                dataDirectoriesEmptyAtObservation=True)
        except Exception as e:
            report['reason'] = str(e) if type(e) is Held else 'CAPACITY_PREPARATION_UNPROVEN_PRESERVE_PARTIAL_STATE'
        put(scope, 'result.json', report)
        return report
    finally:
        if new_fd is not None:
            os.close(new_fd)
        os.close(parent)


def main():
    try:
        require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0
                and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                'CAPACITY_ISOLATED_ROOT_ENTRY')
        os.umask(0o077)
        bundle = STAGING / 'package'
        verify_bundle(bundle, MANIFEST_SHA)
        sys.path.insert(0, str(bundle))
        from tools.storage_planning.g0_package import preflight
        from tools.storage_planning.g0_host import capacity
        report = prepare(STAGING, AREA, bundle, MANIFEST_SHA, INPUT_SHA, preflight, capacity)
    except Exception as e:
        report = {'status': 'HELD', 'reason': str(e) if type(e) is Held else 'CAPACITY_ENTRY_UNPROVEN',
                  'providerRequests': 0, 'runtimeAuthorityIssued': False}
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'CAPACITY_DIRECTORIES_PREPARED_LOCAL_INPUTS_BOUND_REVIEW_REQUIRED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
