"""Offline diagnostic only; never compiles, claims, imports or changes a review."""
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import types

IO_SHA = 'c97ae9fd8af1a554df372abd3342e7057c14fc0a7d40acffb82181625e3e9e4d'
FIELDS = ('OpenStdin', 'StdinOnce', 'Tty', 'AttachStdin', 'AttachStdout',
          'AttachStderr', 'ArgsEscaped', 'NetworkDisabled', 'Hostname',
          'Domainname', 'Image', 'MacAddress', 'StopTimeout')


def load_io(root):
    fd = os.open(root / 'input_reader.py', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = os.read(fd, 65537)
        if hashlib.sha256(raw).hexdigest() != IO_SHA:
            raise ValueError('support')
    finally:
        os.close(fd)
    module = types.ModuleType('retained_input_reader')
    exec(compile(raw, 'qualified_input_reader', 'exec'), module.__dict__)
    return module


def observation(config, key):
    if key not in config:
        return {'present': False}
    value = config[key]
    result = {'present': True, 'type': type(value).__name__}
    if value is None or type(value) is bool:
        result['value'] = value
    elif type(value) is str:
        result['isEmpty'] = value == ''
    return result


def compare(old, new, actual):
    # Only a closed set of booleans/nulls may be printed. Strings/objects never leave the reader.
    return {key: {'oldImage': observation(old, key), 'candidateImage': observation(new, key),
                  'capturedContainer': observation(actual, key)} for key in FIELDS}


def run(io, case):
    io.require(case['schema'] == 'ouf.readiness-patch-review-case.v1', 'EXACT_REVIEW_CASE_REQUIRED')
    root = Path(case['inputContext'])
    reads = []

    def read(path, pin=None):
        value, raw = io.read_json(path, pin, root_owned=True)
        reads.append((path, raw))
        return value

    snapshot = read(root / 'snapshot.json')
    complete = read(root / 'complete.json')
    io.require(io.digest(snapshot['case']) == case['inputCaseHash'] == complete['caseHash']
               and io.digest(snapshot) == complete['snapshotHash'] and complete['complete'] is True
               and complete['runtimeAuthorityIssued'] is False, 'EXACT_COMPLETED_INPUT_SNAPSHOT_REQUIRED')
    retained = Path(snapshot['case']['retainedContext'])
    review = read(retained / 'review.json', snapshot['retainedReviewHash'])
    read(retained / 'recovery.json', snapshot['retainedJournalHash'])
    ref = review['executionReview']['packetBinding']
    packet = read(ref['path'])
    io.require(io.digest(packet) == ref['sha256'], 'RETAINED_PACKET_BYTES_CHANGED')
    pin = snapshot['case']['files']['image-inspect.json']['sha256']
    images = read(root / 'image-inspect.json', pin)
    io.require(len(images) == 1 and images[0]['Id'] == case['candidateImageId']
               == snapshot['candidateMetadata']['imageId'], 'EXACT_CANDIDATE_IMAGE_REQUIRED')
    actual = snapshot['runtimeBefore']['ingestion']
    io.require(actual['Id'] == case['oldIngestionId'], 'EXACT_CAPTURED_INGESTION_REQUIRED')
    result = compare(packet['candidate']['imageConfig'], images[0]['Config'], actual['Config'])
    # Parent custody was checked by reading retained inputs; explicitly check this distinct root too.
    base = Path(case['snapshotRoot'])
    parent = base.lstat()
    io.require(parent.st_uid == 0 and not parent.st_mode & 0o022 and str(base.resolve()) == str(base),
               'ROOT_REVIEW_PARENT_REQUIRED')
    target = base / ('ingestion-readiness-patch-review-' + io.digest(case))
    exists = os.path.lexists(target)
    for path, raw in reads:
        io.require(io.read_json(path, root_owned=True)[1] == raw, 'RETAINED_METADATA_CHANGED_DURING_READ')
    io.require(os.path.lexists(target) == exists, 'REVIEW_PRESENCE_CHANGED_DURING_READ')
    return {'schema': 'ouf.readiness-defaults-reconciliation.v1',
            'status': 'RETAINED_DEFAULTS_OBSERVED_NO_AUTHORITY', 'complete': True,
            'reviewContextExists': exists, 'reviewContextPath': str(target),
            'reviewContentsRead': False, 'reviewReplayAuthorized': False,
            'fields': result, 'inputSnapshotHash': complete['snapshotHash'],
            'liveRuntimeObserved': False, 'compatibilityEstablished': False,
            'readOnly': True, 'engineRequests': 0, 'oauthRequests': 0,
            'credentialFilesOpened': 0, 'runtimeAuthorityIssued': False,
            'runtimeEffectsDispatched': 0, 'automaticReplayAllowed': False,
            'releaseAcceptance': False}


if __name__ == '__main__':
    try:
        def deadline(*_):
            raise TimeoutError()
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(30)
        if len(sys.argv) != 3:
            raise ValueError()
        io = load_io(Path(__file__).resolve().parent)
        case, _ = io.read_json(sys.argv[1], sys.argv[2])
        print(json.dumps(run(io, case), sort_keys=True), flush=True)
    except Exception as error:
        print(json.dumps({'schema': 'ouf.readiness-defaults-reconciliation.v1',
                          'status': 'STOP_RECONCILE', 'reasonCode': 'DEFAULTS_READ_UNCONFIRMED_' + type(error).__name__,
                          'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False,
                          'runtimeEffectsDispatched': 0}), flush=True)
        sys.exit(1)
