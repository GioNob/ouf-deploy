"""Read-only redacted metadata diagnosis; never refresh or accept a baseline."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import types

PLANNER_HASH = 'c89caa119ef7c4fea07ac6a65dd5d2b173c144cf6a802e646929418acc859d56'
FIELDS = ('kind', 'device', 'inode', 'uid', 'gid', 'mode', 'links', 'size', 'mtimeNs', 'ctimeNs')
CUSTODY = ('kind', 'uid', 'gid', 'mode')


class Denied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def planner(raw):
    require(type(raw) is bytes and len(raw) <= 131072
            and hashlib.sha256(raw).hexdigest() == PLANNER_HASH, 'EXACT_DIAGNOSTIC_PLANNER_SOURCE_REQUIRED')
    module = types.ModuleType('sealed_metadata_diagnostic_planner')
    exec(compile(raw, '<sealed-metadata-planner>', 'exec'), module.__dict__)
    return module


def snapshot(p, binding, expected):
    p.require(type(binding) is dict and binding.get('Type') in ('bind', 'volume')
              and binding.get('RW') is False, 'EXACT_DIAGNOSTIC_READONLY_SOURCE_REQUIRED')
    source = p.exact_path(binding['Source'])
    p.require(type(expected) is list and 1 <= len(expected) <= 2
              and expected[0].get('path') == '', 'EXACT_DIAGNOSTIC_METADATA_SCOPE_REQUIRED')
    fds = []
    parents = []
    try:
        current = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(current)
        for part in source.parts[1:-1]:
            following = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            fds.append(following)
            info = os.fstat(following)
            p.require(info.st_uid == 0 and not info.st_mode & 0o022,
                      'ROOT_PROTECTED_DIAGNOSTIC_ANCESTOR_REQUIRED')
            parents.append((current, part, following, p.identity(info)))
            current = following
        rootfd = os.open(source.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=current)
        fds.append(rootfd)
        root = os.fstat(rootfd)
        rows = [p.metadata(root, '')]
        names = set()
        if stat.S_ISDIR(root.st_mode):
            directory = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=rootfd)
            fds.append(directory)
            with os.scandir(directory) as entries:
                for entry in entries:
                    p.require(len(names) < 512, 'DIAGNOSTIC_DIRECTORY_BOUND_EXCEEDED')
                    names.add(entry.name)
            for old in expected[1:]:
                name = old.get('path')
                p.require(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]{1,255}', name)
                          and name not in ('.', '..'), 'EXACT_DIAGNOSTIC_MEMBER_REQUIRED')
                try:
                    rows.append(p.metadata(os.stat(name, dir_fd=rootfd, follow_symlinks=False), name))
                except FileNotFoundError:
                    rows.append(None)
        else:
            rows += [None for _ in expected[1:]]
        p.require(p.identity(root) == p.identity(os.fstat(rootfd))
                  == p.identity(os.stat(source.name, dir_fd=current, follow_symlinks=False)),
                  'DIAGNOSTIC_SOURCE_CHANGED_DURING_READ')
        for parentfd, part, opened, before in parents:
            p.require(before == p.identity(os.fstat(opened))
                      == p.identity(os.stat(part, dir_fd=parentfd, follow_symlinks=False)),
                      'DIAGNOSTIC_ANCESTOR_CHANGED_DURING_READ')
        expected_names = {row['path'] for row in expected[1:]}
        return rows, {'entrySetMatchesBaseline': names == expected_names,
                      'currentDirectoryEntryCount': len(names)}
    finally:
        for fd in reversed(fds):
            os.close(fd)


def diagnose(p, atomic):
    scope = p.review_scope(p.PARENT)
    manifest_raw = atomic.read(p.PARENT / 'intake.json', 0)
    p.require(p.sha(manifest_raw) == p.PARENT_HASH, 'EXACT_DIAGNOSTIC_PARENT_INTAKE_REQUIRED')
    manifest = p.decode(manifest_raw)
    p.require(manifest.get('purpose') == 'GATED_REQUEST_AND_FULL_RETAINED_MOUNT_METADATA_ONLY'
              and set(manifest.get('fileHashes', {})) == set(p.NAMES), 'EXACT_DIAGNOSTIC_PARENT_FILE_SET_REQUIRED')
    files = {name: atomic.read(p.PARENT / name, 0) for name in p.NAMES}
    p.require(manifest['fileHashes'] == {name: p.sha(raw) for name, raw in files.items()},
              'DIAGNOSTIC_PARENT_FILE_HASH_DRIFT')
    atomic.verify(p.PARENT, files, manifest_raw, 0)
    p.require(p.sha(files[p.NAMES[0]]) == p.REQUEST_HASH, 'EXACT_DIAGNOSTIC_REQUEST_BYTES_REQUIRED')
    shape = p.request_mount_shape(p.decode(files[p.NAMES[0]]))
    old = p.decode(files[p.NAMES[2]])
    p.require(type(old) is list and len(old) == 2
              and tuple(p.sha(p.encoded(item['sourceMetadata'])) for item in old) == p.METADATA_HASHES,
              'EXACT_DIAGNOSTIC_RETAINED_METADATA_SEALS_REQUIRED')
    first = [snapshot(p, item['binding'], item['sourceMetadata']) for item in old]
    again = [snapshot(p, item['binding'], item['sourceMetadata']) for item in old]
    p.require(first == again, 'RETAINED_DIAGNOSTIC_CHANGED_BETWEEN_READS')
    atomic.verify(p.PARENT, files, manifest_raw, 0)
    p.require(p.review_scope(p.PARENT) == scope, 'DIAGNOSTIC_PARENT_SCOPE_CHANGED')
    result = []
    for index, (item, (rows, directory)) in enumerate(zip(old, first)):
        entries = []
        for member, (before, now) in enumerate(zip(item['sourceMetadata'], rows)):
            changed = ['presence'] if now is None else [field for field in FIELDS if before.get(field) != now.get(field)]
            entries.append({'scope': 'SOURCE_ROOT' if member == 0 else 'DIRECTORY_MEMBER',
                            'changedFields': changed, 'exists': now is not None,
                            'expectedCustody': {key: before[key] for key in CUSTODY},
                            'currentCustody': None if now is None else {key: now[key] for key in CUSTODY}})
        result.append({'mountIndex': index, 'entries': entries, **directory})
    return {'status': 'RETAINED_V11_METADATA_DIAGNOSED_NOT_ACCEPTED', 'requestMountShape': shape,
            'baselineIntakeHash': p.PARENT_HASH, 'metadataComparison': result, 'stableDoubleRead': True,
            'metadataDriftDetected': any(any(row['changedFields'] for row in mount['entries'])
                                       or not mount['entrySetMatchesBaseline'] for mount in result)}


def main():
    report = {'schema': 'ouf.retained-v11-metadata-diagnostic.v1', 'maxDiagnosticSeconds': 120,
              'sourceContentBytesRead': 0, 'sourceContentBytesHashed': 0, 'protectedFileWrites': 0,
              'sourcePathsPrinted': False, 'memberNamesPrinted': False, 'sourceInodesPrinted': False,
              'sourceTimestampValuesPrinted': False, 'baselineRefreshed': False, 'automaticRetry': False,
              'containerLifecycleOperations': 0, 'databaseQueries': 0, 'databaseWrites': 0,
              'providerCalls': 0, 'dnsQueries': 0, 'firewallWrites': 0, 'signaturesIssued': 0,
              'r12Touched': False, 'budgetReset': False, 'runtimeAuthorityIssued': False,
              'applicationCutoverAuthorized': False, 'productionApplyReady': False,
              'completeSixMountClosureProven': False, 'notReleaseAcceptance': True}
    p = None
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode
                and len(sys.argv) == 1, 'ISOLATED_ROOT_METADATA_DIAGNOSTIC_REQUIRED')
        def deadline(*_):
            raise Denied('RETAINED_METADATA_DIAGNOSTIC_DEADLINE')
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(120)
        p = planner(globals().get('__planner_source__'))
        atomic = p.atomic_source(globals().get('__atomic_source__'))
        report.update(diagnose(p, atomic))
        code = 0
    except Exception as error:
        trusted = type(error) is Denied or p is not None and type(error) is p.Denied
        reason = str(error)
        report.update(status='RETAINED_V11_METADATA_DIAGNOSTIC_BLOCKED',
                      reason=reason if trusted and re.fullmatch('[A-Z][A-Z0-9_]{0,120}', reason)
                      else 'RETAINED_METADATA_DIAGNOSTIC_UNPROVEN')
        code = 1
    finally:
        signal.alarm(0)
    print('OUF_RETAINED_V11_METADATA_DIAGNOSTIC=' + json.dumps(report, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
