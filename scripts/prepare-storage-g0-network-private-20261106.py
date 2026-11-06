#!/usr/bin/env python3
"""Stage the exact qualified bundle and a non-operational input draft.

Local files only. No provider calls, credential reads, historical entry points,
runtime admission, collector invocation or changes to existing custody.
"""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

PACKAGE_SHA = 'a1b477789a08b109b54b7decf5ca66099c8ad4dcd63d07c147f283d24d3aef67'
MANIFEST_SHA = '1e542f786ac1606cf72f273bc079eaa5b06b6bd22a210d615c10d13a9d9f8adf'
HISTORY_SOURCE_COMMIT = '59a523b65972ec5a5c3934eb463d9103de73b392'
# Control order follows the original producers at HISTORY_SOURCE_COMMIT.
HISTORY = (
    'm2-retained-mount-custody-14e42ac9-20261101-v1',
    'm2-retained-mount-role-correction-0922ad73-20261101-v1',
    'm2-retained-readonly-hashes-46f6e635-20261101-v1',
    'm2-retained-hash-reconciliation-a7a7601c-20261101-v1',
    'm2-retained-static-custody-050ba14d-20261101-v1',
    'm2-retained-kernel-views-de4546d0-20261101-v1',
    'm2-native-image-archives-9f1d571b-20261101-v1',
    'm2-image-byte-verification-fa95a719-20261101-v1',
    'm2-image-byte-reconciliation-fa95a719-20261101-v1',
    'm2-image-graph-diagnostic-fa95a719-20261101-v1',
    'm2-selected-runtime-bytes-fa95a719-20261101-v1',
    'm2-runtime-origins-c52a0e2a-20261101-v1',
    'seaweedfs-inventory-20261102-v1',
    'seaweedfs-inventory-reconciliation-20261102-v1',
    'seaweedfs-inventory-credentials-20261102-v1',
    'seaweedfs-inventory-inputs-20261102-v1',
    'seaweedfs-offline-plan-20261102-v1',
)


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def protected_directory(path):
    for p in (path, *path.parents):
        s = p.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'PREP_ROOT_PROTECTED_DIRECTORY_REQUIRED')


def bounded_read(path, limit, private=False):
    if private:
        protected_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= limit,
                'PREP_BOUNDED_REGULAR_FILE_REQUIRED')
        if private:
            require(s.st_uid == s.st_gid == 0 and stat.S_IMODE(s.st_mode) == 0o600,
                    'PREP_EXISTING_ROOT_0600_CUSTODY_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(len(raw) == s.st_size and
                all(getattr(s, k) == getattr(after, k) == getattr(path.lstat(), k) for k in fields),
                'PREP_INPUT_CHANGED')
        return raw
    finally:
        os.close(fd)


def qualified_files(archive):
    raw = bounded_read(archive, 7274165)
    require(len(raw) == 7274165 and sha(raw) == PACKAGE_SHA, 'PREP_EXACT_PACKAGE_REQUIRED')
    files = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as t:
        for m in t:
            p = PurePosixPath(m.name)
            require(m.isfile() and not p.is_absolute() and '..' not in p.parts
                    and str(p) == m.name and m.name not in files and len(files) < 15
                    and 0 < m.size <= 32 << 20, 'PREP_SAFE_PACKAGE_MEMBERS_REQUIRED')
            total += m.size
            require(total <= 48 << 20, 'PREP_PACKAGE_SIZE_LIMIT')
            files[m.name] = t.extractfile(m).read()
    require(len(files) == 15 and sha(files['package-manifest.json']) == MANIFEST_SHA,
            'PREP_EXACT_MANIFEST_REQUIRED')
    manifest = json.loads(files['package-manifest.json'])
    require(set(files) == set(manifest['files']) | {'package-manifest.json'} and
            all(sha(files[p]) == h for p, h in manifest['files'].items()), 'PREP_PACKAGE_BYTES')
    return files


def receipt_bindings(history):
    rows = []
    for number, directory in enumerate(HISTORY, 1):
        path = history / directory / 'result.json'
        try:
            raw = bounded_read(path, 2 << 20, private=True)
            doc = json.loads(raw)
            require(type(doc) is dict, 'PREP_RESULT_OBJECT_REQUIRED')
            if 'cumulativeControlAttempts' in doc:
                require(type(doc['cumulativeControlAttempts']) is int and
                        doc['cumulativeControlAttempts'] == number, 'PREP_CONTROL_NUMBER_MISMATCH')
        except Exception as error:
            raise ValueError('PREP_HISTORY_CONTROL_' + str(number) + '_UNPROVEN') from error
        rows.append({'control': number, 'path': str(path), 'sha256': sha(raw)})
    return rows


def put(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def prepare(archive, destination, history, previous):
    protected_directory(destination.parent)
    require(not os.path.lexists(destination), 'PREP_DESTINATION_ALREADY_EXISTS_NO_OVERWRITE')
    files = qualified_files(archive)
    receipts = receipt_bindings(history)
    prior = json.loads(bounded_read(previous / 'preparation.json', 16384, private=True))
    old_draft = json.loads(bounded_read(previous / 'inputs/package-input.json', 65536, private=True))
    require(prior['packageSha256'] == 'e06ce7c10427fb23291cc0a6938c77ad32db772e780505f588d0793fb4dd3295'
            and prior['manifestSha256'] == 'b789786ca9c129c7e80e19ba59c2927162a3f2b2c44fa1adbccecef7ff99ba5e'
            and prior['historyFilesBound'] == 17 and old_draft['priorReceiptFiles'] == receipts,
            'PREP_PREVIOUS_HISTORY_BINDING_CHANGED')
    draft = json.loads(files['input-template.json'])
    require(draft['operationId'] is None and draft['installationRef'] is None and
            draft['collectionDecisionRef'] is None, 'PREP_UNBOUND_TEMPLATE_REQUIRED')
    draft['outputParent'] = str(destination / 'evidence')
    draft['connectionFiles'] = {k: str(destination / 'inputs' / (k + '.json'))
                               for k in ('s3', 'onboarding', 'udp', 'ingestion')}
    draft['priorReceiptFiles'] = receipts
    draft['networkBindingFile'] = str(destination / 'inputs/network.json')
    destination.mkdir(mode=0o700)
    for name in ('package', 'inputs', 'evidence'):
        (destination / name).mkdir(mode=0o700)
    for name, raw in files.items():
        target = destination / 'package' / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        put(target, raw, 0o500 if name == 'bin/inventory' else 0o400)
    require(receipt_bindings(history) == receipts, 'PREP_HISTORY_CHANGED_DURING_STAGING')
    put(destination / 'inputs/package-input.json', (json.dumps(draft, indent=2) + '\n').encode())
    report = {'schema': 'ouf.storage-g0-network-private-preparation.v1',
              'status': 'NETWORK_DRAFT_STAGED_BINDINGS_REQUIRED',
              'previousPreparationPreserved': True,
              'historyMatchesPreviousPreparation': True,
              'networkBindingPresent': False, 'packageSha256': PACKAGE_SHA,
              'manifestSha256': MANIFEST_SHA, 'historyFilesBound': 17,
              'historyMappingSourceCommit': HISTORY_SOURCE_COMMIT,
              'historicalIntegrityAgainstPriorTrustedDigestProven': False,
              'historicalFilesModified': False, 'credentialsRead': 0,
              'providerRequests': 0, 'collectionScopeCreated': False,
              'targetInputCheckPassed': False, 'runtimeAuthorityIssued': False,
              'g0Complete': False, 'acceptanceCreditAdded': 0,
              'missingInputs': ['operation and installation identity', '13 current role bindings',
                                'capacity paths', 'four private connections', 'exact current network binding',
                                'operator evidence and window', 'separate collection decision']}
    put(destination / 'preparation.json', (json.dumps(report, indent=2) + '\n').encode())
    directories = [p for p in destination.rglob('*') if p.is_dir()] + [destination, destination.parent]
    for p in directories:
        fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return report


def main():
    try:
        require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0 and
                sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
                'PREP_ROOT_ISOLATED_NO_ARGUMENT_ENTRY_REQUIRED')
        os.umask(0o077)
        report = prepare(Path('/home/oufadmin/ouf-g0-package-9053aa38.tar.gz'),
                         Path('/var/lib/ouf-g0-network-preparation-20261106'),
                         Path('/etc/ouf/deploy-snapshots'),
                         Path('/var/lib/ouf-g0-preparation-20261106'))
        print(json.dumps(report, sort_keys=True))
        return 0
    except Exception as error:
        reason = str(error)
        if not reason.startswith('PREP_') or not all(c.isupper() or c.isdigit() or c == '_' for c in reason):
            reason = 'PREP_LOCAL_INPUT_OR_STAGING_UNPROVEN'
        print(json.dumps({'status': 'HELD', 'reason': reason, 'providerRequests': 0,
                          'runtimeAuthorityIssued': False, 'automaticCleanup': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
