#!/usr/bin/env python3
"""Read the retained capture outcome. No provider calls, writes or replay."""
import contextlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


AREA = Path('/var/lib/ouf-storage-migration/capture-after-held-stop-20261107-v1')
DECISION = 'GIOVANNI-NONPROD-CAPTURE-ONLY-20261107-01'
ORIGINAL_PLAN = 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d'
JOURNAL = '5f3416a62555adf1d6b4dc00370bd72cf33c0844bb7d671aaae05c08f4bc741f'
READER_SCHEMA = 'ouf.storage-capture-claim-readback.v1'
SUCCESS = 'ENCRYPTED_OFFLINE_RECOVERY_SET_CAPTURED'
LIMIT = 64 << 30


class ReadbackHeld(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise ReadbackHeld(reason)


def same_fields(document, expected):
    return all(type(document.get(key)) is type(value) and document[key] == value
               for key, value in expected.items())


def unique_object(pairs):
    obj = dict(pairs)
    need(len(obj) == len(pairs), 'DUPLICATE_RECEIPT_KEY')
    return obj


def frame(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def file_info(parent, name):
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600, 'UNPROTECTED_CAPTURE_FILE')
    return info


def receipt(parent, name):
    info = file_info(parent, name)
    need(info is not None and 0 < info.st_size <= 8192, 'RECEIPT_MISSING_OR_INVALID_SIZE')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME, dir_fd=parent)
    with os.fdopen(fd, 'rb') as stream:
        need(frame(info) == frame(os.fstat(fd)), 'RECEIPT_CHANGED')
        raw = stream.read(8193)
        current = file_info(parent, name)
        need(len(raw) == info.st_size and current is not None
             and frame(info) == frame(os.fstat(fd)) == frame(current), 'RECEIPT_CHANGED')
    result = json.loads(raw, object_pairs_hook=unique_object)
    need(isinstance(result, dict), 'RECEIPT_OBJECT_REQUIRED')
    return result


def open_directory(stack, path, parent=None, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    need(info.st_uid == 0 and not info.st_mode & 0o022, 'UNPROTECTED_CAPTURE_DIRECTORY')
    if private:
        need(stat.S_IMODE(info.st_mode) == 0o700, 'UNPROTECTED_CAPTURE_DIRECTORY')
    return fd


def capture_processes(area, proc_root='/proc'):
    """Observe the exact launcher and workers retaining scope output descriptors."""
    program = b'/var/lib/ouf-storage-capture-after-held-stop-20261107.py'
    python = os.path.realpath(sys.executable)
    scope = str(area) + '/'
    launchers, workers, complete = 0, 0, True
    deadline = time.monotonic() + 5
    try:
        processes = os.scandir(proc_root)
    except OSError:
        return {'launcherMatches': 0, 'scopeOutputProcessMatches': 0,
                'localProcessScanCompleted': False}
    with processes:
        for index, entry in enumerate(processes):
            if index >= 8192 or time.monotonic() >= deadline:
                complete = False
                break
            if not entry.name.isdecimal():
                continue
            try:
                if entry.stat(follow_symlinks=False).st_uid != 0:
                    continue
                try:
                    executable = os.readlink(entry.path + '/exe')
                except FileNotFoundError:
                    executable = None
                if executable in (python, python + ' (deleted)'):
                    with open(entry.path + '/cmdline', 'rb') as command:
                        args = command.read(8193).split(b'\0')
                    if args[1:7] == [b'-I', b'-B', b'-S', program,
                                     b'--decision-reference', DECISION.encode()]:
                        launchers += 1
                for number in ('1', '2'):
                    try:
                        if os.readlink(entry.path + '/fd/' + number).startswith(scope):
                            workers += 1
                            break
                    except FileNotFoundError:
                        pass
            except FileNotFoundError:
                continue
            except PermissionError:
                complete = False
    return {'launcherMatches': launchers, 'scopeOutputProcessMatches': workers,
            'localProcessScanCompleted': complete}


def stderr_hints(capture, name, info):
    if not info.st_size:
        return []
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME, dir_fd=capture)
    with os.fdopen(fd, 'rb') as stream:
        need(frame(info) == frame(os.fstat(fd)), 'COMMAND_METADATA_CHANGED')
        stream.seek(max(info.st_size - 16384, 0))
        sample = stream.read(16384).lower()
        need(frame(info) == frame(os.fstat(fd)), 'COMMAND_METADATA_CHANGED')
    indicators = (
        (b'no space left on device', 'NO_SPACE_REPORTED'),
        (b'file size limit exceeded', 'FILE_SIZE_LIMIT_REPORTED'),
        (b'file changed as we read it', 'TAR_SOURCE_CHANGE_REPORTED'),
        (b'no such file or directory', 'PATH_MISSING_REPORTED'),
        (b'permission denied', 'PERMISSION_DENIED_REPORTED'),
        (b'input/output error', 'IO_ERROR_REPORTED'),
    )
    return [label for needle, label in indicators if needle in sample]


def unsealed_progress(capture, scope, area, stack, include_processes):
    if capture is None:
        return {}
    processes = capture_processes(area) if include_processes else {}
    commands = []
    for ordinal in range(1, 257):
        name = 'command-%03d.stderr.private' % ordinal
        info = file_info(capture, name)
        if info is not None:
            commands.append((ordinal, name, info))
    result = dict(processes, startedCommandMarkers=len(commands))
    if commands:
        ordinal, name, info = commands[-1]
        result.update(lastCommandOrdinal=ordinal, lastCommandStderrBytes=info.st_size)
        if (not processes or processes['localProcessScanCompleted']
                and not (processes['launcherMatches'] or processes['scopeOutputProcessMatches'])):
            result['lastCommandStderrHints'] = stderr_hints(capture, name, info)
    try:
        payload = open_directory(stack, 'payload', capture, private=True)
    except FileNotFoundError:
        payload = None
    claim = file_info(scope, 'claim.private.json')
    space = os.fstatvfs(capture)
    result.update(
        scopeClaimAgeSeconds=None if claim is None else max(0, int(time.time() - claim.st_mtime)),
        captureAvailableBytes=space.f_bavail * space.f_frsize,
        payloadPresent=payload is not None,
        sourceTarMarkers=0 if payload is None else sum(file_info(payload, 'source-%03d.tar' % i) is not None
                                                       for i in range(34)),
        sourceManifestsPresent=payload is not None and file_info(payload, 'source-manifests.private.json') is not None,
        imageTarPresent=payload is not None and file_info(payload, 'images.tar') is not None,
        memberManifestPresent=payload is not None and file_info(payload, 'manifest.private.json') is not None,
        plaintextBundleMarker=file_info(capture, 'backup.tar.partial') is not None,
    )
    return result


def readback(area, include_processes=False):
    report = {'schema': READER_SCHEMA, 'providerRequests': 0, 'targetWrites': 0,
              'archiveRehashed': False, 'acceptanceCreditAdded': 0}
    with contextlib.ExitStack() as stack:
        parent = open_directory(stack, '/')
        for part in area.parts[1:-1]:
            parent = open_directory(stack, part, parent)
        try:
            scope = open_directory(stack, area.name, parent, private=True)
        except FileNotFoundError:
            return dict(report, status='CAPTURE_SCOPE_NOT_OBSERVED')
        try:
            capture = open_directory(stack, 'capture', scope, private=True)
        except FileNotFoundError:
            capture = None
        report.update(
            claimPresent=file_info(scope, 'claim.private.json') is not None,
            planPresent=file_info(scope, 'plan.private.json') is not None,
            captureDirectoryPresent=capture is not None,
            innerClaimPresent=capture is not None and file_info(capture, 'capture-claim.private.json') is not None,
            innerReceiptPresent=capture is not None and file_info(capture, 'result.json') is not None,
            encryptedPartialPresent=capture is not None and file_info(capture, 'backup.tar.age.partial') is not None,
        )
        archive = None if capture is None else file_info(capture, 'backup.tar.age')
        report['archivePresent'] = archive is not None
        if file_info(scope, 'result.json') is None:
            return dict(report, status='CAPTURE_OUTCOME_UNSEALED',
                        progress=unsealed_progress(capture, scope, area, stack, include_processes))

        need(archive is not None and not report['encryptedPartialPresent'] and report['planPresent'],
             'FINAL_CAPTURE_FILES_REQUIRED')
        claim = receipt(scope, 'claim.private.json')
        inner_claim = receipt(capture, 'capture-claim.private.json')
        inner = receipt(capture, 'result.json')
        final = receipt(scope, 'result.json')
        plan_sha = claim.get('planSha256')
        archive_sha = final.get('archiveSha256')
        recipient_sha = inner_claim.get('recipientSha256')
        need(all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value)
                 for value in (plan_sha, archive_sha, recipient_sha)), 'INVALID_RECEIPT_DIGEST')
        need(same_fields(claim, {
            'schema': 'ouf.storage-capture-after-held-stop-claim.v1', 'decisionReference': DECISION,
            'originalPlanSha256': ORIGINAL_PLAN, 'retainedJournalDigest': JOURNAL, 'attempts': 1,
            'priorCumulativeStopCommandCalls': 184, 'legacyValidUntilEpoch': 1794081219,
        }), 'CONTINUATION_CLAIM_MISMATCH')
        need(same_fields(inner_claim, {'decisionReference': DECISION, 'planSha256': plan_sha,
                                      'attempts': 1}), 'INNER_CLAIM_MISMATCH')
        expected = {
            'status': SUCCESS, 'archive': str(area / 'capture' / 'backup.tar.age'),
            'archiveBytes': archive.st_size, 'archiveSha256': archive_sha,
            'planSha256': plan_sha, 'recipientSha256': recipient_sha, 'roles': 14, 'sources': 34,
            'attempts': 1, 'providerMutationCommands': 0, 'automaticReplayAllowed': False,
            'automaticRestartAllowed': False, 'restorePerformed': False, 'g3Complete': False,
            'acceptanceCreditAdded': 0,
        }
        need(0 < archive.st_size <= LIMIT and same_fields(inner, dict(expected,
             schema='ouf.storage-cold-backup-result.v1')), 'INNER_CAPTURE_RESULT_MISMATCH')
        need(same_fields(final, dict(expected, schema='ouf.storage-capture-after-held-stop-result.v1',
             priorStopJournalPreserved=True, priorCumulativeStopCommandCalls=184,
             stopSignalsSent=0, restartPoliciesChanged=0, hostMutations=0, cumulativeHostReadCalls=3,
             unattributedEtcdExecSequencesPreserved=3, legacyExpiryExtended=False,
             priorCaptureAttemptReplayed=False, runtimeAuthorityIssued=False)), 'FINAL_CAPTURE_RESULT_MISMATCH')
        current = file_info(capture, 'backup.tar.age')
        need(current is not None and frame(archive) == frame(current), 'ARCHIVE_METADATA_CHANGED')
        return dict(report, status='CAPTURE_RESULT_RETAINED', captureStatus=SUCCESS,
                    archive=expected['archive'], archiveBytes=archive.st_size, archiveSha256=archive_sha)


def main():
    try:
        need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
             and sys.dont_write_bytecode and len(sys.argv) == 1, 'ROOT_ISOLATED_READBACK_REQUIRED')
        report = readback(AREA, include_processes=True)
    except (ReadbackHeld, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, ReadbackHeld) else 'LOCAL_READBACK_UNAVAILABLE'
        print(json.dumps({'schema': READER_SCHEMA, 'status': 'READBACK_HELD', 'reason': reason,
                          'providerRequests': 0, 'targetWrites': 0, 'acceptanceCreditAdded': 0}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
