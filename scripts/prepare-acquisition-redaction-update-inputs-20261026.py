#!/usr/bin/env python3
"""Capture new read-only inputs for the two installed acquisition READ replicas.

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

INPUTS = Path('/etc/ouf/deploy-snapshots/mcp-denial-update-inputs-9a374dd07745f059-v1/inputs.json')
INPUTS_HASH = 'fb4b7c9ae832e779192f1ff6e032e49c696752e182a57b8e9464f5a76000b3e4'
INSTALLED = Path('/etc/ouf/deploy-snapshots/mcp-diagnostic-update-ff06ec1afc5da65d-v1/retained-host-policy-continuation-v1')
REVIEW_HASH = '53baa1e1be6b600da78f5f4915a21e19e6e553b0f610bc66080fd6bf3a4af86e'
AUTHORITY_HASH = 'e2d940ff16896bae706efe9acdf3cf1b5cabc79aa36c0c6260b91294ec564be6'
MCP_BINDING_HASH = 'f5a014435647efb7aa059abb1ee84a60c347641399b2eef012c88c2a83d27550'
MCP_IMAGE = 'sha256:9a1af5be94ff3dda4084b829e824482c5cf863525375c6f104a3fe89517e781e'
CANDIDATES = {'ingestion': '7d85bfe0d1423bcb13e115f06c92d8a0baa1ebf7', 'udp': '125510cf9d970aff7db66a0a8f27eb98b50bb6de'}
ROOT = Path('/etc/ouf/deploy-snapshots/acquisition-redaction-update-inputs-v1')
MAXIMUMS = {'engineGets': 10, 'privateMetadataReads': 4, 'responseBytes': 2*1024*1024, 'totalBytes': 20*1024*1024, 'seconds': 90}
STAGES = ['VERIFY_CURRENT_ADMISSION','IMPORT_MCP','DISABLE_OLD_MCP_RESTART','STOP_OLD_MCP','DETACH_OLD_MCP','RENAME_OLD_MCP','CREATE_MCP','START_MCP','VERIFY_MCP_READINESS','RESTORE_MCP_RESTART','VERIFY_FINAL']
COUNTS = {'adminGets':0,'adminPuts':0,'engineGets':116,'engineWrites':8,'imageLoadAttempts':1,'ownerConfigurationReads':12,'quarantineStops':0,'readinessGets':2,'serviceCredentialFileReads':0}


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
        require(not os.path.lexists(self.root), 'REDACTION_INPUT_CAPTURE_SCOPE_CONSUMED_NO_REPLAY')
        os.mkdir(self.root, 0o700)
        os.chmod(self.root, 0o700)
        self.counts = {'engineGets': 0, 'privateMetadataReads': 0, 'bytes': 0}
        self.seals = {}
        self.sync(self.root.parent)
        self.put('claim.json', {'schema': 'ouf.acquisition-redaction-input-capture-claim.v1', 'maximums': MAXIMUMS,
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
            require(expected is None or hashlib.sha256(raw).hexdigest() == expected, 'EXACT_INSTALLED_CAPTURE_HASH_REQUIRED')
            value = decode(raw)
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


def prepare(capture, *, inputs_path=INPUTS, installed=INSTALLED, engine_factory=Engine,
            pin=process_pin, boot_path=Path('/proc/sys/kernel/random/boot_id')):
    c = capture
    inputs = c.private(inputs_path, INPUTS_HASH)
    review = c.private(installed/'review.json', REVIEW_HASH)
    result = c.private(installed/'result.json')
    journal = c.private(installed/'recovery.json')
    require(inputs['schema'] == 'ouf.mcp-denial-update-inputs.v1'
            and review['schema'] == 'ouf.mcp-diagnostic-update-review.v1'
            and review['nativePlanHash'] == digest(review['nativePlan'])
            and review['nativePlan']['proposal']['capturedInputsHash'] == INPUTS_HASH,
            'EXACT_COMPLETED_MCP_REVIEW_AND_PRIOR_INPUTS_REQUIRED')
    require(result['schema'] == 'ouf.mcp-diagnostic-update-result.v1'
            and result['complete'] is True and result['status'] == 'MCP_DIAGNOSTIC_UPDATE_INSTALLED_E2E_NOT_ACCEPTED'
            and result['reviewHash'] == journal['reviewHash'] == REVIEW_HASH
            and result['authorityHash'] == journal['authorityHash'] == AUTHORITY_HASH
            and result['nativeImageId'] == MCP_IMAGE and result['nativeBindingHash'] == MCP_BINDING_HASH
            and result['counts'] == journal['counts'] == COUNTS
            and result['originalsAndReadReplicasUnchanged'] == 6
            and result['registryWorkerTouched'] is False and result['componentReadinessProven'] is True
            and journal['schema'] == 'ouf.mcp-diagnostic-update-journal.v1'
            and journal['state'] == 'COMPLETE' and journal['quarantine'] is None
            and journal['nextStage'] == len(STAGES) and review['stages'] == STAGES
            and len(journal['effects']) == len(STAGES)
            and all(e['state'] == 'APPLIED' and e['stage'] == STAGES[i] for i,e in enumerate(journal['effects']))
            and set(journal['candidates']) == {'mcp'}, 'EXACT_COMPLETED_MCP_UPDATE_REQUIRED')
    require(boot_path.read_text().strip() == inputs['bootId'] == review['bootId'], 'SAME_CAPTURE_HOST_BOOT_REQUIRED')
    candidate = journal['candidates']['mcp']
    require(candidate['configurationVerified'] is True and candidate['readinessProven'] is True
            and isinstance(candidate['generation'], dict), 'COMPLETED_CURRENT_MCP_GENERATION_REQUIRED')
    prior = inputs['currentObservations']
    roles = {'gateway','postgres','ingestion','udp','ingestion-read','udp-read','mcp'}
    require(set(prior) == roles and set(inputs['currentProcessPins']) == roles, 'EXACT_SEVEN_CAPTURE_ROLES_REQUIRED')
    ids = {role: prior[role]['Id'] for role in roles if role != 'mcp'}
    ids['mcp'] = candidate['id']
    require(candidate['id'] != prior['mcp']['Id'], 'NEW_MCP_LINEAGE_REQUIRED')
    engine = engine_factory(c, inputs['engineBinding'], list(ids.values()))
    info = engine.get('/v1.44/info')
    observations, generations = {}, {}
    for role in sorted(roles):
        actual = engine.get('/v1.44/containers/'+ids[role]+'/json')
        require(actual['Id'] == ids[role] and actual['State']['Running'] is True
                and actual['State']['Paused'] is False and actual['State']['Restarting'] is False,
                'CURRENT_RUNNING_CAPTURE_COHORT_REQUIRED')
        generation = pin(actual['State']['Pid'])
        if role == 'mcp':
            require(actual['Image'] == MCP_IMAGE and digest(stable_binding(actual)) == MCP_BINDING_HASH
                    and generation == candidate['generation'], 'SAME_COMPLETED_CURRENT_MCP_REQUIRED')
        else:
            require(stable_binding(actual) == stable_binding(prior[role])
                    and generation == inputs['currentProcessPins'][role], 'UNCHANGED_SIX_ORIGINAL_AND_READ_GENERATIONS_REQUIRED')
        observations[role] = actual; generations[role] = generation
    for role in ('ingestion-read','udp-read'):
        again = engine.get('/v1.44/containers/'+ids[role]+'/json')
        require(stable_binding(again) == stable_binding(observations[role])
                and pin(again['State']['Pid']) == generations[role], 'READ_REPLICA_CHANGED_DURING_CAPTURE')
    for path, seal in c.seals.items():
        require(list(frame(Path(path).lstat())) == seal['metadata'], 'CAPTURE_HISTORY_CHANGED')
    payload = {'schema':'ouf.acquisition-redaction-update-inputs.v1', 'bootId':inputs['bootId'],
               'engineBinding':inputs['engineBinding'], 'engineInfo':info, 'currentObservations':observations,
               'currentProcessPins':generations, 'candidateSourceCommits':CANDIDATES,
               'historySeals':c.seals, 'counts':dict(c.counts), 'retainedMcpCounts':COUNTS,
               'retainedMcpReviewHash':REVIEW_HASH, 'retainedMcpAuthorityHash':AUTHORITY_HASH,
               'runtimeAuthorityIssued':False, 'executionEntryQualified':False,
               'automaticReplayAllowed':False, 'budgetReset':False}
    c.put('inputs.json', payload)
    output = {'schema':'ouf.acquisition-redaction-update-input-capture-result.v1',
              'status':'ACQUISITION_REDACTION_UPDATE_INPUTS_CAPTURED_NOT_AUTHORIZED',
              'complete':True, 'contextPath':str(c.root), 'inputsHash':digest(payload), 'counts':dict(c.counts),
              'unchangedOriginalsAndReadReplicas':6, 'currentInstalledMcpMatched':True,
              'candidateSourceCommits':CANDIDATES, 'containerWrites':0, 'imageImports':0,
              'gatewayRequests':0, 'sqlSessions':0, 'oauthRequests':0, 'credentialFileReads':0,
              'installationSigningKeysRead':False, 'acquisitionsExecuted':0, 'sourceActivations':0,
              'historicalAuthorityReused':False, 'runtimeAuthorityIssued':False, 'continuationAuthorized':False,
              'currentApplicationPolicyOrLabelsObserved':False, 'applicationE2EProven':False,
              'releaseAcceptance':False, 'automaticReplayAllowed':False, 'budgetReset':False}
    c.put('result.json', output)
    return output


def main():
    c = None
    try:
        require(len(sys.argv) == 1 and os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
                and sys.dont_write_bytecode and os.environ.get('SUDO_UID') == str(pwd.getpwnam('oufadmin').pw_uid),
                'ISOLATED_OUFADMIN_ROOT_CAPTURE_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Stop('FINITE_CAPTURE_WINDOW_EXPIRED')))
        signal.alarm(MAXIMUMS['seconds'])
        c = Capture(); output = prepare(c)
    except BaseException as error:
        reason = str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,120}',str(error)) else 'PRIVATE_CAPTURE_FAILURE_RECONCILE'
        output = {'schema':'ouf.acquisition-redaction-update-input-capture-result.v1', 'status':'STOP_RECONCILE',
                  'complete':False, 'reasonCode':reason, 'contextPath':str(c.root) if c else None,
                  'runtimeAuthorityIssued':False, 'containerWrites':0, 'automaticReplayAllowed':False,
                  'budgetReset':False, 'applicationE2EProven':False, 'releaseAcceptance':False}
        if c is not None:
            output['counts'] = dict(c.counts)
            if not (c.root/'result.json').exists():c.put('result.json',output)
    finally:signal.alarm(0)
    print(json.dumps(output,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if output['complete'] else 2


if __name__ == '__main__':raise SystemExit(main())

