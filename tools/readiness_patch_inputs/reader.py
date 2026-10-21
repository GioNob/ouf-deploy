"""Retained installation patch inputs only: bounded Engine GETs and private snapshot files."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import sys
import time


class Stop(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Stop(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def regular(path, maximum, root_owned=False):
    """Open every path component without symlinks and retain ancestor identities."""
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts, 'EXACT_ABSOLUTE_FILE_REQUIRED')
    held = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    seals = []
    try:
        for part in p.parts[1:-1]:
            parent = held[-1]
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            held.append(fd)
            s = os.fstat(fd)
            if root_owned:
                require(s.st_uid == 0 and not s.st_mode & 0o022, 'ROOT_METADATA_ANCESTRY_REQUIRED')
            seals.append((parent, part, fd, (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)))
        parent = held[-1]
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= maximum,
                'BOUNDED_SINGLE_REGULAR_FILE_REQUIRED')
        require(not root_owned or s.st_uid == 0 and not s.st_mode & 0o022,
                'ROOT_OWNED_RETAINED_METADATA_REQUIRED')
        return fd, s, held, seals, p.name
    except BaseException:
        if 'fd' in locals() and fd not in held:
            os.close(fd)
        for fd in reversed(held):
            os.close(fd)
        raise


def signature(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def close_checked(opened):
    fd, before, held, seals, name = opened
    try:
        require(signature(before) == signature(os.fstat(fd))
                == signature(os.stat(name, dir_fd=held[-1], follow_symlinks=False)), 'INPUT_FILE_CHANGED')
        for parent, part, child, pin in seals:
            for s in (os.fstat(child), os.stat(part, dir_fd=parent, follow_symlinks=False)):
                require((s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode) == pin,
                        'INPUT_ANCESTRY_CHANGED')
    finally:
        os.close(fd)
        for held_fd in reversed(held):
            os.close(held_fd)


def read_json(path, expected=None, root_owned=False):
    opened = regular(path, 8_388_608, root_owned)
    try:
        raw = os.read(opened[0], 8_388_609)
        require(len(raw) == opened[1].st_size, 'INPUT_READ_INCOMPLETE')
        require(expected is None or hashlib.sha256(raw).hexdigest() == expected, 'PUBLIC_INPUT_HASH_CHANGED')
        return json.loads(raw), raw
    finally:
        close_checked(opened)


def stable(actual, profile='ouf.runtime-binding.native-mount-order.v1'):
    mounts = actual['Mounts']
    require(profile in ('ouf.runtime-binding.native-mount-order.v1',
                        'ouf.runtime-binding.mounts-sorted-destination.v1'), 'EXACT_BINDING_PROFILE_REQUIRED')
    if profile.endswith('mounts-sorted-destination.v1'):
        mounts = sorted(mounts, key=lambda row: row['Destination'])
    return {'containerId': actual['Id'], 'imageId': actual['Image'], 'pid': actual['State']['Pid'],
            'startedAt': actual['State']['StartedAt'], 'configHash': digest(actual['Config']),
            'hostConfigHash': digest(actual['HostConfig']), 'mountsHash': digest(mounts),
            'networkSettingsHash': digest(actual['NetworkSettings'])}


def generation(actual, pin, restarts):
    s = actual['State']
    require(actual['Id'] == pin['containerId'] and s['Pid'] == pin['pid']
            and s['StartedAt'] == pin['startedAt'] and s['Running'] is True
            and not s.get('Paused') and not s.get('Restarting') and not s.get('Dead')
            and actual['RestartCount'] == restarts, 'RETAINED_RUNTIME_GENERATION_CHANGED')


class Engine:
    def __init__(self, binding, ids):
        require(len(ids) == 6 and all(re.fullmatch('[a-f0-9]{64}', i) for i in ids), 'EXACT_SIX_IDS_REQUIRED')
        self.binding, self.ids, self.calls = binding, ids, 0

    def check(self):
        p = Path(self.binding['socketPath'])
        require(p.is_absolute() and '..' not in p.parts and str(p.resolve()) == str(p), 'EXACT_ENGINE_PATH_REQUIRED')
        s = p.lstat()
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) in (0o600, 0o660)
                and [s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
                == self.binding['socketBinding'], 'ENGINE_SOCKET_BINDING_CHANGED')

    def inspect(self, cid):
        require(cid in self.ids and self.calls < 12, 'CLOSED_TWELVE_GET_BUDGET')
        self.check()
        selected = self.binding['socketPath']

        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout)
                connection.sock.connect(selected)

        client = Connection('retained-engine', timeout=4)
        try:
            self.calls += 1
            client.request('GET', '/v1.44/containers/' + cid + '/json', headers={'Connection': 'close'})
            response = client.getresponse()
            raw = response.read(4_194_305)
            require(response.status == 200 and 0 < len(raw) <= 4_194_304, 'BOUNDED_ENGINE_REPLY_REQUIRED')
            actual = json.loads(raw)
            require(actual['Id'] == cid, 'ENGINE_REPLY_IDENTITY_CHANGED')
            self.check()
            return actual
        finally:
            client.close()


def copy_public(source, destination, expected, maximum):
    opened = regular(source, maximum)
    out = None
    try:
        out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        h = hashlib.sha256()
        total = 0
        while True:
            raw = os.read(opened[0], 1048576)
            if not raw:
                break
            total += len(raw)
            require(total <= maximum, 'PUBLIC_ARTIFACT_LIMIT')
            h.update(raw)
            view = memoryview(raw)
            while view:
                count = os.write(out, view)
                require(count > 0, 'PRIVATE_COPY_INCOMPLETE')
                view = view[count:]
        require(total == opened[1].st_size and h.hexdigest() == expected, 'PUBLIC_ARTIFACT_HASH_MISMATCH')
        os.fsync(out)
        return total
    finally:
        if out is not None:
            os.close(out)
        close_checked(opened)


def write_private(path, value):
    raw = encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, 'PRIVATE_SNAPSHOT_WRITE_INCOMPLETE')
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(case, artifacts):
    require(case['schema'] == 'ouf.readiness-patch-input-case.v1'
            and case['purpose'] == 'EXACT_RETAINED_INSTALLATION_NOT_PORTABLE_DEFAULT', 'EXACT_CASE_REQUIRED')
    base = Path(case['snapshotRoot'])
    s = base.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022
            and str(base.resolve()) == str(base), 'ROOT_SNAPSHOT_CUSTODY_REQUIRED')
    target = base / ('ingestion-readiness-patch-inputs-' + digest(case))
    require(not os.path.lexists(target), 'INPUT_SNAPSHOT_ALREADY_EXISTS_DO_NOT_REPLAY')
    root = Path(case['retainedContext'])
    review, review_raw = read_json(root / 'review.json', root_owned=True)
    row, row_raw = read_json(root / 'recovery.json', root_owned=True)
    native = review['executionReview']
    require(row['nextStage'] == len(native['stages']) == len(row['effects']) == 28
            and all(e['state'] == 'APPLIED' and e['stage'] == native['stages'][i]['name']
                    and e['intentHash'] == native['stages'][i]['intentHash'] for i, e in enumerate(row['effects']))
            and row['budgetReset'] is False, 'EXACT_COMPLETED_RETAINED_SEQUENCE_REQUIRED')
    pins = {}
    for name in ('ingestion', 'gateway'):
        i = next(i for i, s in enumerate(native['stages']) if s['name'] == name + '.START_REPLACEMENT')
        pin = row['effects'][i]['nativeResource']
        require(pin['containerId'] == case['replacementIds'][name], 'RETAINED_REPLACEMENT_ID_REQUIRED')
        pins[name] = {'binding': pin, 'restartCount': 0}
    pins.update(native['runtimeGuardProfile']['unchangedApplications'])
    database = native['databaseControlProfile']
    pins['postgres'] = {'binding': database['postgresRuntimeBinding'],
                        'restartCount': database['postgresRestartCount']}
    engine = Engine(native['engineBinding'], {v['binding']['containerId'] for v in pins.values()})
    before = {}
    for name, pin in pins.items():
        actual = engine.inspect(pin['binding']['containerId'])
        generation(actual, pin['binding'], pin['restartCount'])
        if name in native['runtimeGuardProfile']['unchangedApplications']:
            require(stable(actual, pin['bindingProfile']) == pin['binding'], 'UNCHANGED_APPLICATION_CONFIG_DRIFT')
        if name == 'postgres':
            require(stable(actual, database['runtimeBindingProfile']) == pin['binding'], 'DATABASE_RUNTIME_CONFIG_DRIFT')
        before[name] = actual
    require(before['ingestion']['Config']['Labels']['org.opencontainers.image.revision']
            == case['baselineSourceCommit'], 'EXPECTED_INSTALLED_SOURCE_LABEL_REQUIRED')
    require('--spring.flyway.enabled=false' in before['ingestion']['Config']['Cmd']
            and '--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY' in before['ingestion']['Config']['Cmd'],
            'RETAINED_VALIDATE_ONLY_STARTUP_REQUIRED')
    artifact_root = Path(artifacts)
    metadata, _ = read_json(artifact_root / 'metadata.json', case['files']['metadata.json']['sha256'])
    require(metadata['schema'] == 'ouf.ingestion-readiness-workload-candidate.v1'
            and metadata['sourceCommit'] == case['candidateSourceCommit']
            and metadata['baselineSourceCommit'] == case['baselineSourceCommit']
            and metadata['buildRecipeCommit'] == case['buildRecipeCommit']
            and metadata['imageId'] == case['candidateImageId'] and metadata['migrationChanges'] == 0
            and metadata['highCriticalVulnerabilityGatePassed'] is True
            and metadata['imageStartedByCandidateExport'] is False
            and metadata['runtimeAuthorityIssued'] is False, 'EXACT_QUALIFIED_CANDIDATE_REQUIRED')
    os.mkdir(target, 0o700)
    sync_directory(base)
    write_private(target / 'claim.json', {'caseHash': digest(case), 'state': 'CAPTURING_INPUTS',
                                         'runtimeAuthorityIssued': False})
    sync_directory(target)
    copied = {}
    require(set(case['files']) == {'image.tar.gz', 'metadata.json', 'image-inspect.json', 'trivy-image.json'},
            'EXACT_FOUR_PUBLIC_CANDIDATE_FILES_REQUIRED')
    for name, pin in case['files'].items():
        require(type(pin['maximumBytes']) is int and 0 < pin['maximumBytes'] <= 536870912,
                'FINITE_PUBLIC_ARTIFACT_BOUND_REQUIRED')
        copied[name] = copy_public(artifact_root / name, target / name, pin['sha256'], pin['maximumBytes'])
    for name, pin in pins.items():
        after = engine.inspect(pin['binding']['containerId'])
        generation(after, pin['binding'], pin['restartCount'])
        require(stable(after) == stable(before[name]), 'LIVE_BINDINGS_CHANGED_DURING_CAPTURE')
    require(read_json(root / 'review.json', root_owned=True)[1] == review_raw
            and read_json(root / 'recovery.json', root_owned=True)[1] == row_raw, 'RETAINED_CONTEXT_CHANGED')
    snapshot = {'schema': 'ouf.readiness-patch-private-inputs.v1', 'case': case, 'candidateMetadata': metadata,
                'retainedReviewHash': hashlib.sha256(review_raw).hexdigest(),
                'retainedJournalHash': hashlib.sha256(row_raw).hexdigest(), 'runtimeBefore': before,
                'engineBinding': native['engineBinding'], 'observedAtUnix': time.time(),
                'runtimeFrameApproved': False, 'runtimeAuthorityIssued': False}
    write_private(target / 'snapshot.json', snapshot)
    write_private(target / 'complete.json', {'caseHash': digest(case), 'snapshotHash': digest(snapshot),
                                            'complete': True, 'runtimeAuthorityIssued': False})
    sync_directory(target)
    return {'schema': 'ouf.readiness-patch-input-result.v1', 'status': 'PRIVATE_INPUTS_CAPTURED_NO_AUTHORITY',
            'complete': True, 'contextPath': str(target), 'candidateImageId': metadata['imageId'],
            'sourceCommit': metadata['sourceCommit'], 'migrationChanges': 0, 'engineGets': engine.calls,
            'maximumEngineGets': 12, 'runtimeReadOnly': True, 'privateSnapshotWritten': True,
            'runtimeFrameApproved': False, 'runtimeAuthorityIssued': False, 'runtimeEffectsDispatched': 0,
            'imagesImported': 0, 'oauthRequests': 0, 'credentialFilesOpened': 0,
            'privateValuesPrinted': False, 'automaticReplayAllowed': False, 'releaseAcceptance': False}


if __name__ == '__main__':
    try:
        def deadline(*_):
            raise Stop('INPUT_CAPTURE_DEADLINE')
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(55)
        require(len(sys.argv) == 4, 'CASE_AND_ARTIFACT_DIRECTORY_REQUIRED')
        require(re.fullmatch('[a-f0-9]{64}', sys.argv[2]), 'EXACT_PUBLIC_CASE_HASH_REQUIRED')
        case, _ = read_json(sys.argv[1], sys.argv[2])
        print(json.dumps(run(case, sys.argv[3]), sort_keys=True), flush=True)
    except Exception as error:
        code = str(error) if isinstance(error, Stop) else 'INPUT_CAPTURE_UNCONFIRMED_' + type(error).__name__
        print(json.dumps({'schema': 'ouf.readiness-patch-input-result.v1', 'status': 'STOP_RECONCILE',
                          'reasonCode': code, 'automaticReplayAllowed': False,
                          'runtimeAuthorityIssued': False, 'runtimeEffectsDispatched': 0,
                          'privateSnapshotMayBePartial': True}), flush=True)
        sys.exit(1)
