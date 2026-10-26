#!/usr/bin/env python3
"""Capture a new read-only MCP update input; no consumed procedure is run.

Exact installed history + bounded local Engine GETs. No SQL, OAuth, signing,
credential-file read, audit/log read, image import, lifecycle or acquisition.
"""
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import struct
import sys

NATIVE_HASH = '5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591'
NATIVE = Path('/etc/ouf/deploy-snapshots/acquisition-native-execution-inputs-47b206e2eb602c11/native-inputs.json')
CAPTURED = Path('/etc/ouf/deploy-snapshots/acquisition-evidence-current-inputs-v1/inputs.json')
INSTALLED = Path('/etc/ouf/deploy-snapshots/acquisition-read-apply-' + NATIVE_HASH + '/terminal-continuation-v1/detached-mcp-recovery-v1')
INSTALLED_RESULT_HASH = '7a738f1d8b15baf7f1b9992919e348d19a60f2c54bd6a97ad6d6379c29c87045'
INSTALLED_REVIEW_HASH = 'c77171d86ab5af4c81926fb9a0c3402f4f2c79f6dd7e946fc280a1354d1808de'
AUTHORITY_HASH = '6147d3a683cebcd66a6c076dc8f5970777d3c824b7d697b95aa0b4e34f5047ee'
CANDIDATE = {'sourceCommit': '9a374dd07745f059de3ad39757c68f02db6d29c3',
             'imageId': 'sha256:ffc78ca5e7fc1a1941cd4c4347d43e061df97d06c9fca44df0e8a5c47b5b839d',
             'workflowRun': 40284011851, 'artifactId': 12633545900,
             'artifactZipSHA256': '6c31a1b5698942ddbb47b96ec1b49860c690c44aac8106beb1ca4b1ed7bba56a',
             'imageArchiveSHA256': '19fd036f973e52734d209d20671240f8973cd55d7183968ce605254b94cbd5bb',
             'manifestSHA256': 'f2a6f20ff15969c068b87cbd15cf8485e5680f63123d60e90b58c7a09b7b37ae'}
ROOT = Path('/etc/ouf/deploy-snapshots/mcp-denial-update-inputs-9a374dd07745f059-v1')
MAXIMUMS = {'engineGets': 10, 'privateMetadataReads': 8, 'responseBytes': 2*1024*1024, 'totalBytes': 20*1024*1024, 'seconds': 90}


class Stop(Exception):
    pass


def require(value, code):
    if not value:
        raise Stop(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'DUPLICATE_PRIVATE_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Stop('NONFINITE_PRIVATE_JSON')))


def frame(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def ancestry(path):
    require(path.is_absolute() and path.resolve() == path and '..' not in path.parts, 'CANONICAL_ROOT_PATH_REQUIRED')
    for parent in (path, *path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022, 'PROTECTED_ROOT_ANCESTRY_REQUIRED')


class Capture:
    def __init__(self, root=ROOT):
        self.root = Path(root)
        ancestry(self.root.parent)
        require(not os.path.lexists(self.root), 'MCP_INPUT_CAPTURE_SCOPE_CONSUMED_NO_REPLAY')
        os.mkdir(self.root, 0o700)
        os.chmod(self.root, 0o700)
        self.counts = {'engineGets': 0, 'privateMetadataReads': 0, 'bytes': 0}
        self.seals = {}
        self.sync(self.root.parent)
        self.put('claim.json', {'schema': 'ouf.mcp-denial-input-capture-claim.v1', 'maximums': MAXIMUMS,
                               'containerWrites': 0, 'automaticReplayAllowed': False, 'budgetReset': False})

    def sync(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def put(self, name, value):
        require(re.fullmatch(r'[a-z0-9-]+\.json', name) is not None, 'CLOSED_CAPTURE_FILENAME_REQUIRED')
        fd = os.open(self.root/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(encoded(value)); out.flush(); os.fsync(out.fileno())
        self.sync(self.root)

    def private(self, path, expected=None):
        require(self.counts['privateMetadataReads'] < MAXIMUMS['privateMetadataReads'], 'PRIVATE_CAPTURE_READ_LIMIT')
        self.counts['privateMetadataReads'] += 1
        path = Path(path)
        self.put('private-read-'+str(self.counts['privateMetadataReads'])+'-claim.json', {'path': str(path), 'attemptNotCompletion': True})
        ancestry(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) in (0o400, 0o600) and 0 < before.st_size <= 6*1024*1024, 'SEALED_PRIVATE_CAPTURE_INPUT_REQUIRED')
            raw = b''
            while len(raw) <= before.st_size:
                part = os.read(fd, min(65536, before.st_size+1-len(raw)))
                if not part:
                    break
                raw += part
            require(len(raw) == before.st_size and frame(before) == frame(os.fstat(fd)) == frame(path.lstat()), 'CAPTURE_HISTORY_CHANGED')
            value = decode(raw)
            require(expected is None or digest(value) == expected, 'EXACT_INSTALLED_CAPTURE_HASH_REQUIRED')
            self.seals[str(path)] = {'metadata': list(frame(before)), 'sha256': hashlib.sha256(raw).hexdigest()}
            return value
        finally:
            os.close(fd)


def process_pin(pid):
    require(type(pid) is int and pid > 1, 'POSITIVE_CAPTURE_PID_REQUIRED')
    raw = Path('/proc/'+str(pid)+'/stat').read_bytes()
    require(0 < len(raw) < 16384 and b') ' in raw, 'BOUNDED_CAPTURE_PROCESS_REQUIRED')
    namespaces = {}
    for name in ('net', 'mnt'):
        info = Path('/proc/'+str(pid)+'/ns/'+name).stat()
        namespaces[name] = [info.st_dev, info.st_ino]
    return {'pid': pid, 'startTicks': int(raw.rsplit(b') ', 1)[1].split()[19]), 'namespaces': namespaces}


def stable_binding(actual):
    return {'containerId': actual['Id'], 'imageId': actual['Image'], 'name': actual['Name'], 'pid': actual['State']['Pid'], 'startedAt': actual['State']['StartedAt'],
            'configHash': digest(actual['Config']), 'hostConfigHash': digest(actual['HostConfig']),
            'mountsHash': digest(sorted(actual['Mounts'], key=lambda v: v['Destination'])), 'networkSettingsHash': digest(actual['NetworkSettings']),
            'profile': 'ouf.acquisition-read.mount-set-binding.v1'}


class Engine:
    def __init__(self, capture, binding, ids):
        self.capture, self.binding = capture, binding
        require(len(ids) == 7 and len(set(ids)) == 7 and all(re.fullmatch('[a-f0-9]{64}', cid) for cid in ids), 'EXACT_SEVEN_CAPTURE_IDS_REQUIRED')
        self.allowed = {'/v1.44/info'} | {'/v1.44/containers/'+cid+'/json' for cid in ids}

    def get(self, path):
        c = self.capture
        require(path in self.allowed and c.counts['engineGets'] < MAXIMUMS['engineGets'], 'CLOSED_READ_ONLY_ENGINE_CAPTURE_REQUIRED')
        selected = Path(self.binding['socketPath']); ancestry(selected.parent)
        info = selected.lstat()
        require(stat.S_ISSOCK(info.st_mode) and [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)] == self.binding['socketBinding'], 'EXACT_CAPTURE_ENGINE_SOCKET_REQUIRED')
        c.counts['engineGets'] += 1
        c.put('engine-get-'+str(c.counts['engineGets'])+'-claim.json', {'method': 'GET', 'path': path, 'attemptNotCompletion': True})
        binding = self.binding
        class Local(http.client.HTTPConnection):
            def connect(conn):
                conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); conn.sock.settimeout(4); conn.sock.connect(str(selected))
                peer = list(struct.unpack('3i', conn.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)))
                require(peer == binding['peerCredentials'] and peer[1] == 0, 'EXACT_CAPTURE_ROOT_ENGINE_PEER_REQUIRED')
        conn = Local('root-local-engine', timeout=4)
        try:
            conn.request('GET', path, headers={'Connection': 'close'})
            response = conn.getresponse(); raw = response.read(MAXIMUMS['responseBytes']+1)
            c.counts['bytes'] += len(raw)
            require(response.status == 200 and 0 < len(raw) <= MAXIMUMS['responseBytes'] and c.counts['bytes'] <= MAXIMUMS['totalBytes'], 'BOUNDED_SUCCESSFUL_ENGINE_CAPTURE_REQUIRED')
            value = decode(raw)
            c.put('engine-get-'+str(c.counts['engineGets'])+'-response.json', value)
            return value
        finally:
            conn.close()


def prepare(capture, *, native_path=NATIVE, captured_path=CAPTURED, installed=INSTALLED, engine_factory=Engine, pin=process_pin, boot_path=Path('/proc/sys/kernel/random/boot_id')):
    c = capture
    native = c.private(native_path, NATIVE_HASH)
    require(native['schema'] == 'ouf.acquisition-native-execution-inputs.v1' and digest(native['nativeProposal']) == native['nativeProposalHash'], 'EXACT_ORIGINAL_NATIVE_INPUT_REQUIRED')
    original = c.private(captured_path, native['nativeProposal']['capturedInputsHash'])
    result = c.private(installed/'result.json', INSTALLED_RESULT_HASH)
    review = c.private(installed/'review.json', INSTALLED_REVIEW_HASH)
    journal = c.private(installed/'recovery.json')
    require(result['complete'] is True and result['status'] == 'ACQUISITION_READ_PATH_INSTALLED_E2E_NOT_ACCEPTED'
            and result['reviewHash'] == journal['reviewHash'] == INSTALLED_REVIEW_HASH
            and journal['authorityHash'] == result['authorityHash'] == AUTHORITY_HASH
            and journal['state'] == 'COMPLETE' and journal['counts'] == result['counts']
            and journal['nextStage'] == len(review['stages']) == len(journal['effects']) == 16
            and all(e['state'] == 'APPLIED' and e['stage'] == review['stages'][i] for i, e in enumerate(journal['effects']))
            and set(journal['candidates']) == {'ingestion', 'udp', 'mcp'}, 'EXACT_COMPLETED_INSTALLED_PREFIX_REQUIRED')
    require(boot_path.read_text().strip() == native['bootId'] == original['bootId'], 'SAME_CAPTURE_HOST_BOOT_REQUIRED')
    prior_plan = review['nativePlan']['proposal']
    ids = {role: row['containerId'] for role, row in prior_plan['existingApplications'].items() if role != 'mcp'}
    require(set(ids) == {'gateway', 'postgres', 'ingestion', 'udp'}, 'FOUR_UNCHANGED_ORIGINALS_REQUIRED')
    for role in ('ingestion', 'udp', 'mcp'):
        candidate = journal['candidates'][role]
        require(candidate['configurationVerified'] is True and candidate['readinessProven'] is True and isinstance(candidate['generation'], dict), 'VERIFIED_INSTALLED_CANDIDATE_REQUIRED')
        ids[role if role == 'mcp' else role+'-read'] = candidate['id']
    engine = engine_factory(c, prior_plan['engineBinding'], list(ids.values()))
    info = engine.get('/v1.44/info')
    observations, generations = {}, {}
    for role, cid in ids.items():
        actual = engine.get('/v1.44/containers/'+cid+'/json')
        require(actual['Id'] == cid and actual['State']['Running'] is True and actual['State']['Paused'] is False
                and actual['State']['Restarting'] is False, 'CURRENT_RUNNING_INSTALLED_COHORT_REQUIRED')
        generation = pin(actual['State']['Pid'])
        if role in ('mcp', 'ingestion-read', 'udp-read'):
            prior_role = role.removesuffix('-read')
            require(generation == journal['candidates'][prior_role]['generation']
                    and actual['Image'] == native['candidateFacts'][prior_role]['nativeImageId'], 'SAME_INSTALLED_CANDIDATE_GENERATION_REQUIRED')
        else:
            require(stable_binding(actual) == prior_plan['existingApplications'][role]
                    and generation == original['currentProcessPins'][role], 'UNCHANGED_ORIGINAL_COHORT_REQUIRED')
        observations[role] = actual; generations[role] = generation
    current = observations['mcp']
    require(current['Name'] == '/'+prior_plan['mcpReplacement']['name'] and current['Config']['Cmd'] == ['server']
            and current['HostConfig'].get('AutoRemove') is False, 'EXACT_CURRENT_MCP_MANAGER_REQUIRED')
    again = engine.get('/v1.44/containers/'+ids['mcp']+'/json')
    require(stable_binding(again) == stable_binding(current) and pin(again['State']['Pid']) == generations['mcp'], 'MCP_CHANGED_DURING_CAPTURE')
    for path, seal in c.seals.items():
        require(list(frame(Path(path).lstat())) == seal['metadata'], 'CONSUMED_CAPTURE_HISTORY_DRIFT')
    payload = {'schema': 'ouf.mcp-denial-update-inputs.v1', 'candidate': CANDIDATE, 'bootId': native['bootId'],
               'engineBinding': prior_plan['engineBinding'], 'engineInfo': info, 'currentObservations': observations,
               'currentProcessPins': generations, 'installedResultHash': INSTALLED_RESULT_HASH,
               'installedReviewHash': INSTALLED_REVIEW_HASH, 'installedCounts': result['counts'],
               'historySeals': c.seals, 'counts': c.counts, 'executionEntryQualified': False,
               'targetUpdateAuthorized': False, 'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False, 'budgetReset': False}
    c.put('inputs.json', payload)
    output = {'schema': 'ouf.mcp-denial-update-input-capture-result.v1', 'status': 'MCP_DIAGNOSTIC_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED',
              'complete': True, 'contextPath': str(c.root), 'inputsHash': digest(payload), 'counts': dict(c.counts),
              'originalsObservedUnchanged': 4, 'installedCandidatesObservedSameGeneration': 3,
              'candidateSourceCommit': CANDIDATE['sourceCommit'], 'candidateImageId': CANDIDATE['imageId'],
              'containerWrites': 0, 'imageImports': 0, 'gatewayRequests': 0, 'sqlSessions': 0, 'oauthRequests': 0,
              'serviceCredentialFilesRead': 0, 'installationSigningKeysRead': False, 'acquisitionsExecuted': 0,
              'sourceActivations': 0, 'runtimeAuthorityIssued': False, 'continuationAuthorized': False,
              'mcpOAuthScopesVerified': False, 'mcpLoadedPolicyVersionObserved': False,
              'applicationE2EProven': False, 'releaseAcceptance': False, 'automaticReplayAllowed': False, 'budgetReset': False}
    c.put('result.json', output)
    return output


def main():
    c = None
    try:
        require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
                and sys.dont_write_bytecode and os.environ.get('SUDO_UID') == str(pwd.getpwnam('oufadmin').pw_uid), 'ISOLATED_OUFADMIN_ROOT_CAPTURE_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('FINITE_CAPTURE_WINDOW_EXPIRED')))
        signal.alarm(MAXIMUMS['seconds'])
        c = Capture(); output = prepare(c)
    except BaseException as error:
        reason = str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,120}', str(error)) else 'PRIVATE_CAPTURE_FAILURE_RECONCILE'
        output = {'schema': 'ouf.mcp-denial-update-input-capture-result.v1', 'status': 'STOP_RECONCILE', 'complete': False,
                  'reasonCode': reason, 'contextPath': str(c.root) if c else None, 'runtimeAuthorityIssued': False,
                  'containerWrites': 0, 'automaticReplayAllowed': False, 'budgetReset': False, 'applicationE2EProven': False, 'releaseAcceptance': False}
        if c is not None:
            output['counts'] = dict(c.counts)
            if not (c.root/'result.json').exists():
                c.put('result.json', output)
    finally:
        signal.alarm(0)
    print(json.dumps(output, sort_keys=True, separators=(',', ':')), flush=True)
    return 0 if output['complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
