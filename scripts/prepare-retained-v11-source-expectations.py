"""Hash only the two source scopes already captured in the selected private plan.

Byte expectations stay private. No OCI input, key parsing, signing, Docker,
systemd, nft, SQL, provider call or runtime authority. Original intakes stay intact.
These are historical candidate expectations, not independent acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import types

BASE = Path('/etc/ouf/deploy-snapshots')
PARENT_HASH = '005f6a7afad7d493a52d9b183816fa0346f1bb1a4de5ab4b63c8b0b39f3fb092'
PARENT = BASE / ('semantic-native-v11-intake-' + PARENT_HASH)
REQUEST_HASH = '37b517eda22f5997504687222679d458c9478ee66ba5ef2377cf5588ef3f0a9d'
METADATA_HASHES = (
    'edd17c66ebb3c64747bcb69fa17a69380198ae0b2a4dadf86d941473b55dfa02',
    '22ce221e8216648947bd861cb18c8b3c888467d8e2eec8bda057d08a03ce79ed',
)
ATOMIC_HASH = 'c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6'
NAMES = ('gated-creation-request.private.json', 'gate-proposal.json',
         'retained-mount-metadata.private.json', 'parent-review-reference.json')
MAX_BYTES = 1048576
MAX_SECONDS = 120


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'DUPLICATE_PRIVATE_JSON_MEMBER')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'NONFINITE_PRIVATE_JSON'))


def atomic_source(raw):
    require(type(raw) is bytes and len(raw) <= 131072 and sha(raw) == ATOMIC_HASH,
            'EXACT_SEALED_ATOMIC_PUBLISHER_REQUIRED')
    module = types.ModuleType('sealed_retained_source_atomic')
    exec(compile(raw, '<sealed-atomic-publisher>', 'exec'), module.__dict__)
    return module


def identity(info):
    return tuple(getattr(info, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def metadata(info, relative):
    kind = 'directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'other'
    return {'path': relative, 'kind': kind, 'device': info.st_dev, 'inode': info.st_ino,
            'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
            'links': info.st_nlink, 'size': info.st_size,
            'mtimeNs': info.st_mtime_ns, 'ctimeNs': info.st_ctime_ns}


def exact_path(value):
    require(type(value) is str and len(value) <= 4096
            and re.fullmatch('/[A-Za-z0-9_./-]+', value)
            and '..' not in value.split('/') and str(Path(value)) == value and value != '/',
            'EXACT_RETAINED_SOURCE_PATH_REQUIRED')
    return Path(value)


def review_scope(path):
    """The selected immutable intake and every ancestor must be protected dirs."""
    current = Path('/')
    result = []
    for part in exact_path(str(path)).parts[1:]:
        current = current / part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'ROOT_PROTECTED_REVIEW_ANCESTOR_REQUIRED')
        result.append((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid))
    require(stat.S_IMODE(info.st_mode) == 0o700, 'EXACT_PRIVATE_PARENT_DIRECTORY_REQUIRED')
    return result


def request_mount_shape(request):
    """Count both Docker representations without rewriting the sealed request."""
    host = request.get('HostConfig')
    require(type(host) is dict, 'EXACT_GATED_HOST_CONFIG_REQUIRED')
    binds = host.get('Binds')
    mounts = host.get('Mounts')
    binds = [] if binds is None else binds
    mounts = [] if mounts is None else mounts
    require(type(binds) is list and type(mounts) is list
            and len(binds) + len(mounts) == 6,
            'EXACT_SIX_COMBINED_MOUNT_DECLARATIONS_REQUIRED')
    targets = []
    for row in binds:
        require(type(row) is str and len(row) <= 8192,
                'EXACT_GATED_BIND_DECLARATION_REQUIRED')
        parts = row.split(':')
        require(len(parts) == 3 and parts[0] and parts[2] == 'ro',
                'EXPLICIT_READONLY_GATED_BIND_REQUIRED')
        targets.append(str(exact_path(parts[1])))
    for row in mounts:
        require(type(row) is dict and row.get('Type') in ('bind', 'volume')
                and type(row.get('Source')) is str and row['Source']
                and row.get('ReadOnly') is True,
                'EXPLICIT_READONLY_STRUCTURED_GATED_MOUNT_REQUIRED')
        targets.append(str(exact_path(row.get('Target'))))
    require(len(set(targets)) == 6 and not any(
        a != b and (a.startswith(b + '/') or b.startswith(a + '/'))
        for a in targets for b in targets), 'GATED_MOUNT_TARGET_SHADOWING_DENIED')
    return {'bindCount': len(binds), 'structuredMountCount': len(mounts),
            'totalMountCount': 6, 'sealedRequestRewritten': False}


def source_scope(binding, expected, counted=lambda amount: None):
    """FD-relative traversal, exact old metadata, two hashes, no byte spooling."""
    require(type(binding) is dict and binding.get('Type') in ('bind', 'volume')
            and binding.get('RW') is False, 'EXACT_RETAINED_READONLY_BINDING_REQUIRED')
    source = exact_path(binding['Source'])
    exact_path(binding['Destination'])
    require(type(expected) is list and 1 <= len(expected) <= 2
            and expected[0].get('path') == '', 'EXACT_BOUNDED_RETAINED_METADATA_REQUIRED')
    is_directory = expected[0].get('kind') == 'directory'
    require((is_directory and len(expected) == 2 and expected[1].get('kind') == 'file')
            or (not is_directory and len(expected) == 1 and expected[0].get('kind') == 'file'),
            'ONE_DIRECTORY_MEMBER_OR_ONE_FILE_REQUIRED')
    fds = []
    ancestors = []
    try:
        current = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(current)
        for part in source.parts[1:-1]:
            following = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            fds.append(following)
            info = os.fstat(following)
            require(info.st_uid == 0 and not info.st_mode & 0o022,
                    'ROOT_PROTECTED_SOURCE_ANCESTOR_REQUIRED')
            ancestors.append((current, part, following, identity(info)))
            current = following
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        rootfd = os.open(source.name, flags | (os.O_DIRECTORY if is_directory else 0), dir_fd=current)
        fds.append(rootfd)
        rootinfo = os.fstat(rootfd)
        require(metadata(rootinfo, '') == expected[0]
                and identity(rootinfo) == identity(os.stat(source.name, dir_fd=current, follow_symlinks=False)),
                'RETAINED_SOURCE_METADATA_DRIFT')
        if is_directory:
            name = expected[1].get('path')
            require(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]{1,255}', name)
                    and name not in ('.', '..') and os.listdir(rootfd) == [name],
                    'EXACT_RETAINED_SINGLETON_DIRECTORY_REQUIRED')
            filefd = os.open(name, flags, dir_fd=rootfd)
            fds.append(filefd)
            fileinfo = os.fstat(filefd)
            require(metadata(fileinfo, name) == expected[1], 'RETAINED_DIRECTORY_MEMBER_METADATA_DRIFT')
        else:
            name = None
            filefd, fileinfo = rootfd, rootinfo
        require(stat.S_ISREG(fileinfo.st_mode) and fileinfo.st_nlink == 1
                and 0 < fileinfo.st_size <= MAX_BYTES, 'BOUNDED_SINGLE_LINK_RETAINED_FILE_REQUIRED')
        hashes = []
        for _ in range(2):
            os.lseek(filefd, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            total = 0
            while True:
                block = os.read(filefd, min(65536, MAX_BYTES + 1 - total))
                if not block:
                    break
                total += len(block)
                counted(len(block))
                require(total <= MAX_BYTES, 'RETAINED_SOURCE_BYTE_BOUND_EXCEEDED')
                digest.update(block)
            require(total == fileinfo.st_size and identity(os.fstat(filefd)) == identity(fileinfo),
                    'RETAINED_FILE_CHANGED_DURING_HASH')
            hashes.append(digest.hexdigest())
        require(hashes[0] == hashes[1], 'RETAINED_CONTENT_CHANGED_BETWEEN_HASHES')
        require(identity(rootinfo) == identity(os.fstat(rootfd))
                == identity(os.stat(source.name, dir_fd=current, follow_symlinks=False)),
                'RETAINED_SOURCE_CHANGED_DURING_HASH')
        if is_directory:
            require(os.listdir(rootfd) == [name]
                    and identity(os.stat(name, dir_fd=rootfd, follow_symlinks=False)) == identity(fileinfo),
                    'RETAINED_DIRECTORY_MEMBER_CHANGED_DURING_HASH')
        for parentfd, part, opened, before in ancestors:
            require(identity(os.fstat(opened)) == before
                    == identity(os.stat(part, dir_fd=parentfd, follow_symlinks=False)),
                    'RETAINED_SOURCE_ANCESTOR_CHANGED')
        return {'binding': binding, 'sourceMetadata': expected, 'kind': expected[0]['kind'],
                'fileName': name, 'fileUid': fileinfo.st_uid, 'fileGid': fileinfo.st_gid,
                'fileMode': stat.S_IMODE(fileinfo.st_mode), 'maxBytes': MAX_BYTES,
                'sha256': hashes[0], 'observationsAreHistorical': True}, total * 2
    finally:
        for fd in reversed(fds):
            os.close(fd)


def prepare(atomic, report):
    parent_scope = review_scope(PARENT)
    raw_manifest = atomic.read(PARENT / 'intake.json', 0)
    require(sha(raw_manifest) == PARENT_HASH, 'EXACT_GATED_PARENT_INTAKE_REQUIRED')
    manifest = decode(raw_manifest)
    require(manifest.get('schema') == 'ouf.native-v11-atomic-review-intake.v1'
            and manifest.get('purpose') == 'GATED_REQUEST_AND_FULL_RETAINED_MOUNT_METADATA_ONLY'
            and set(manifest.get('fileHashes', {})) == set(NAMES)
            and all(manifest.get(k) is False for k in
                    ('applicationCutoverAuthorized', 'productionApplyReady', 'runtimeAuthorityIssued')),
            'EXACT_UNAPPLIED_GATED_PARENT_REQUIRED')
    files = {name: atomic.read(PARENT / name, 0) for name in NAMES}
    require(manifest['fileHashes'] == {name: sha(raw) for name, raw in files.items()},
            'GATED_PARENT_FILE_HASH_DRIFT')
    atomic.verify(PARENT, files, raw_manifest, 0)
    request = decode(files[NAMES[0]])
    require(sha(files[NAMES[0]]) == REQUEST_HASH, 'EXACT_GATED_REQUEST_BYTES_REQUIRED')
    report['requestMountShape'] = request_mount_shape(request)
    old = decode(files[NAMES[2]])
    require(type(old) is list and len(old) == 2
            and tuple(sha(encoded(item['sourceMetadata'])) for item in old) == METADATA_HASHES,
            'EXACT_TWO_RETAINED_METADATA_SEALS_REQUIRED')
    results = []
    def counted(amount):
        report['mountedSourceContentBytesHashed'] += amount
    for item in old:
        require(type(item) is dict and set(item) == {'binding', 'sourceMetadata'},
                'EXACT_RETAINED_METADATA_ENTRY_REQUIRED')
        result, _ = source_scope(item['binding'], item['sourceMetadata'], counted)
        results.append(result)
    require(all(atomic.read(PARENT / name, 0) == raw for name, raw in files.items())
            and atomic.read(PARENT / 'intake.json', 0) == raw_manifest,
            'GATED_PARENT_CHANGED_DURING_EXPECTATION_CAPTURE')
    # Reconcile both sources a second time before publication. A late changed
    # source never silently becomes the expected policy for the old snapshot.
    for item, expected in zip(old, results):
        actual, _ = source_scope(item['binding'], item['sourceMetadata'], counted)
        require(actual == expected, 'RETAINED_SCOPE_CHANGED_BEFORE_PUBLICATION')
    atomic.verify(PARENT, files, raw_manifest, 0)
    require(review_scope(PARENT) == parent_scope, 'PRIVATE_PARENT_SCOPE_CHANGED')
    program_hash = globals().get('__sealed_program_sha__')
    require(type(program_hash) is str and re.fullmatch('[0-9a-f]{64}', program_hash),
            'SEALED_RETAINED_EXPECTATIONS_PROGRAM_REQUIRED')
    prepared = {
        'retained-source-expectations.private.json': encoded({
            'schema': 'ouf.retained-v11-source-expectations.v1', 'creationRequestHash': REQUEST_HASH,
            'parentIntakeHash': PARENT_HASH, 'sources': results,
            'sourceContentsSpooled': False, 'sourceAuthenticationProven': False,
            'completeSixMountClosureProven': False, 'notReleaseAcceptance': True}),
        'parent-review-reference.json': encoded({'parentIntakeHash': PARENT_HASH,
                                                 'creationRequestHash': REQUEST_HASH,
                                                 'fileHashes': manifest['fileHashes']}),
    }
    output_manifest = {
        'schema': 'ouf.native-v11-atomic-review-intake.v1',
        'purpose': 'RETAINED_SOURCE_BYTE_EXPECTATIONS_ONLY_NOT_ACCEPTANCE',
        'fileHashes': {name: sha(raw) for name, raw in prepared.items()},
        'sourceHashes': {'program': program_hash, 'atomic': ATOMIC_HASH},
        'parentIntakeHash': PARENT_HASH, 'creationRequestHash': REQUEST_HASH,
        'applicationCutoverAuthorized': False, 'productionApplyReady': False,
        'runtimeAuthorityIssued': False, 'observationsAreHistorical': True,
        'notReleaseAcceptance': True,
    }
    def checkpoint(point):
        if point.startswith('BEFORE_FILE_'):
            report['protectedFileWriteAttempts'] += 1
        if point.startswith('AFTER_FILE_'):
            report['protectedFileWrites'] += 1
    report['privatePublicationAttempted'] = True
    report.update(atomic.publish(BASE, prepared, output_manifest, 0, checkpoint))
    report.update(status='RETAINED_V11_PRIVATE_SOURCE_EXPECTATIONS_PREPARED_NOT_ACCEPTED',
                  parentIntakePreserved=True, retainedMountCount=2,
                  sourceExpectationHash=sha(prepared['retained-source-expectations.private.json']),
                  retainedSources=[{'mountType': item['binding']['Type'], 'kind': item['kind'],
                                    'sourceUid': item['sourceMetadata'][0]['uid'],
                                    'sourceGid': item['sourceMetadata'][0]['gid'],
                                    'sourceMode': item['sourceMetadata'][0]['mode'],
                                    'fileUid': item['fileUid'], 'fileGid': item['fileGid'],
                                    'fileMode': item['fileMode']} for item in results])


def main():
    os.umask(0o077)
    report = {'schema': 'ouf.retained-v11-source-expectations-preparation.v1',
              'preparationProfile': 'ouf.retained-source-expectations.v1',
              'maxPreparationSeconds': MAX_SECONDS, 'maxBytesPerSource': MAX_BYTES,
              'protectedFileWrites': 0, 'protectedFileWriteAttempts': 0,
              'privatePublicationAttempted': False,
              'mountedSourceContentBytesHashed': 0, 'sourceContentsSpooled': False,
              'sourceContentsPrinted': False, 'sourcePathsPrinted': False,
              'sourceByteHashesPrinted': False, 'privateKeyClassificationNotInferred': True,
              'sourceAuthenticationProven': False, 'completeSixMountClosureProven': False,
              'containerLifecycleOperations': 0, 'databaseQueries': 0, 'databaseWrites': 0,
              'providerCalls': 0, 'dnsQueries': 0, 'firewallWrites': 0, 'imageImports': 0,
              'signaturesIssued': 0, 'runtimeAuthorityIssued': False,
              'applicationCutoverAuthorized': False, 'productionApplyReady': False,
              'r12Touched': False, 'budgetReset': False, 'commonLeaseLockAcquired': False,
              'observationsAreHistorical': True, 'notReleaseAcceptance': True}
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode
                and len(sys.argv) == 1, 'ISOLATED_ROOT_RETAINED_EXPECTATIONS_REQUIRED')
        def deadline(*_):
            raise Denied('RETAINED_EXPECTATIONS_DEADLINE_EXCEEDED')
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(MAX_SECONDS)
        atomic = atomic_source(globals().get('__atomic_source__'))
        prepare(atomic, report)
        code = 0
    except Exception as error:
        reason = str(error)
        report.update(status='RETAINED_V11_SOURCE_EXPECTATIONS_BLOCKED',
                      reason=reason if type(error) is Denied and re.fullmatch('[A-Z][A-Z0-9_]{0,120}', reason)
                      else 'RETAINED_SOURCE_EXPECTATIONS_UNPROVEN')
        if report['protectedFileWriteAttempts'] > report['protectedFileWrites']:
            report.update(protectedFileWrites=None, privateWriteOutcomeRequiresReconciliation=True)
        if report['privatePublicationAttempted']:
            report['privateWriteOutcomeRequiresReconciliation'] = True
        code = 1
    finally:
        signal.alarm(0)
    print('OUF_RETAINED_V11_SOURCE_EXPECTATIONS=' + json.dumps(report, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
