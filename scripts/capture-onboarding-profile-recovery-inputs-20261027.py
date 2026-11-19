#!/usr/bin/env python3
"""Capture current installed diagnostic Onboarding metadata for a NEW profiling-recovery plan.

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

INPUTS = Path('/etc/ouf/deploy-snapshots/onboarding-diagnostic-current-inputs-20261026-v1/inputs.json')
INPUTS_HASH = '5909d1003e88231c1d41a799a12539127d27386f79a04ed345ad9d29eaaddb6d'
INSTALLED = Path('/etc/ouf/deploy-snapshots/onboarding-diagnostic-update-c22586172070809d-v1/retained-peer-credentials-continuation-v1/pid1-peer-continuation-v1')
REVIEW_HASH = 'd77154b3e734c0b249f315fe10961d99baa380d4625d920b917cbe7c270b134b'
AUTHORITY_HASH = 'fa906ab28f8268e7b62a8df59c9825b8c2524bf28da44821801db7b916c1f4ce'
INSTALLED_NATIVE_IMAGE = 'sha256:074bd16ec8ebd98cbf1ee085af9767a5f7e322072a541e85bd37925002fa5df2'
INSTALLED_NATIVE_BINDING_HASH = '1bda483e8138353f4ada203a6b19fa532344393b5e0f995c963d01c90584eb78'
ROOT = Path('/etc/ouf/deploy-snapshots/onboarding-profile-recovery-current-inputs-20261027-v1')
MAXIMUMS = {'engineGets': 3, 'privateMetadataReads': 4, 'responseBytes': 2*1024*1024, 'totalBytes': 24*1024*1024, 'seconds': 90}



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
        require(not os.path.lexists(self.root), 'ONBOARDING_PROFILE_RECOVERY_CAPTURE_CONSUMED_NO_REPLAY')
        os.mkdir(self.root, 0o700)
        os.chmod(self.root, 0o700)
        self.counts = {'engineGets': 0, 'privateMetadataReads': 0, 'bytes': 0}
        self.seals = {}
        self.sync(self.root.parent)
        self.put('claim.json', {'schema': 'ouf.onboarding-profile-recovery-input-capture-claim.v1', 'maximums': MAXIMUMS,
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
            self.counts['bytes'] += len(raw)
            require(self.counts['bytes'] <= MAXIMUMS['totalBytes'], 'PRIVATE_CAPTURE_BYTE_LIMIT')
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
        require(len(ids) == 1 and len(set(ids)) == 1 and all(re.fullmatch('[a-f0-9]{64}', cid) for cid in ids), 'ONE_EXACT_ONBOARDING_CAPTURE_ID_REQUIRED')
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
    require(inputs['schema'] == 'ouf.onboarding-diagnostic-current-inputs.v1'
            and inputs['automaticReplayAllowed'] is False and inputs['budgetReset'] is False,
            'EXACT_RETAINED_ENGINE_METADATA_REQUIRED')
    require(review['schema'] == 'ouf.onboarding-diagnostic-update-review.v1'
            and review['executionRoot'] == str(installed) and digest(review) == REVIEW_HASH
            and review['nativePlan']['proposal']['engineBinding'] == inputs['engineBinding'],
            'EXACT_COMPLETED_DIAGNOSTIC_REVIEW_REQUIRED')
    require(result['schema'] == 'ouf.onboarding-diagnostic-update-result.v1'
            and result['status'] == 'ONBOARDING_DIAGNOSTIC_UPDATE_INSTALLED_E2E_NOT_ACCEPTED'
            and result['complete'] is True and result['reviewHash'] == REVIEW_HASH
            and result['authorityHash'] == AUTHORITY_HASH
            and result['contextPath'] == str(installed)
            and result['candidateSourceCommit'] == 'a5ed8b05c264a8221783a6e323ba00117aed891d'
            and result['nativeImageId'] == INSTALLED_NATIVE_IMAGE
            and result['nativeBindingHash'] == INSTALLED_NATIVE_BINDING_HASH
            and result['registryWorkerTouched'] is False and result['componentReadinessProven'] is True
            and result['databaseMigrationsByRepair'] == result['newGrantsGranted'] == result['sourceActivations'] == result['acquisitionsExecuted'] == 0
            and result['budgetReset'] is False and result['automaticReplayAllowed'] is False,
            'EXACT_COMPLETED_ONBOARDING_RECEIPT_REQUIRED')
    stages = review['stages']
    require(journal['schema'] == 'ouf.onboarding-diagnostic-update-journal.v1'
            and journal['state'] == 'COMPLETE' and journal['reviewHash'] == REVIEW_HASH
            and journal['authorityHash'] == AUTHORITY_HASH and journal['quarantine'] is None
            and journal['automaticReplayAllowed'] is False and journal['budgetReset'] is False
            and journal['nextStage'] == len(stages) == len(journal['effects'])
            and set(journal['candidates']) == {'onboarding'}, 'EXACT_COMPLETED_NATIVE_JOURNAL_REQUIRED')
    for stage,effect in zip(stages,journal['effects']):
        require(effect['stage'] == stage and effect['state'] == 'APPLIED'
                and effect['intentHash'] == digest({'reviewHash':REVIEW_HASH,'stage':stage}), 'NO_UNRECONCILED_RETAINED_EFFECT_REQUIRED')
    proof = next(e['proof'] for e in journal['effects'] if e['stage'] == 'VERIFY_FINAL')
    candidate = journal['candidates']['onboarding']
    require(candidate['configurationVerified'] is True and candidate['readinessProven'] is True
            and proof['nativeBindingHash'] == INSTALLED_NATIVE_BINDING_HASH
            and candidate['generation'] == proof['generation'], 'RETAINED_NATIVE_CANDIDATE_PROOF_REQUIRED')
    require(boot_path.read_text().strip() == inputs['bootId'] == review['bootId'], 'SAME_CAPTURE_HOST_BOOT_REQUIRED')
    cid = candidate['id']
    require(type(cid) is str and re.fullmatch('[a-f0-9]{64}',cid), 'ONE_RETAINED_ONBOARDING_ID_REQUIRED')
    engine = engine_factory(c, inputs['engineBinding'], [cid])
    info = engine.get('/v1.44/info')
    actual = engine.get('/v1.44/containers/'+cid+'/json')
    require(actual['Id'] == cid and actual['Image'] == INSTALLED_NATIVE_IMAGE
            and actual['State']['Running'] is True and actual['State']['Paused'] is False and actual['State']['Restarting'] is False,
            'CURRENT_RUNNING_ONBOARDING_REQUIRED')
    generation = pin(actual['State']['Pid'])
    require(generation == candidate['generation'] and digest(stable_binding(actual)) == INSTALLED_NATIVE_BINDING_HASH,
            'RETAINED_INSTALLED_ONBOARDING_GENERATION_CHANGED')
    again = engine.get('/v1.44/containers/'+cid+'/json')
    require(stable_binding(actual) == stable_binding(again) and generation == pin(again['State']['Pid']), 'ONBOARDING_CHANGED_DURING_CAPTURE')
    for path,seal in c.seals.items():
        require(list(frame(Path(path).lstat())) == seal['metadata'], 'CAPTURE_HISTORY_CHANGED')
    payload = {'schema':'ouf.onboarding-profile-recovery-current-inputs.v1','bootId':inputs['bootId'],
        'engineBinding':inputs['engineBinding'],'engineInfo':info,'onboardingObservation':actual,
        'onboardingProcessPin':generation,'historySeals':c.seals,'counts':dict(c.counts),
        'retainedReviewHash':REVIEW_HASH,'retainedAuthorityHash':AUTHORITY_HASH,
        'retainedNativeBindingHash':INSTALLED_NATIVE_BINDING_HASH,'retainedInstalledSource':'a5ed8b05c264a8221783a6e323ba00117aed891d',
        'retainedDiagnosticApplyCounts':result['counts'],'retainedDiagnosticOperationalStateProof':result['operationalStateProof'],
        'retainedScopeConsumed':True,'observedConfigurationAcceptedAsRuntimeAuthority':False,
        'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    c.put('inputs.json',payload)
    output = {'schema':'ouf.onboarding-profile-recovery-current-input-capture-result.v1',
        'status':'ONBOARDING_PROFILE_RECOVERY_CURRENT_INPUTS_CAPTURED_NOT_AUTHORIZED','complete':True,
        'contextPath':str(c.root),'inputsHash':digest(payload),'counts':dict(c.counts),
        'retainedCandidateIdentityObserved':True,'retainedProcessGenerationMatched':True,'currentApplicationPolicyOrLabelsObserved':False,
        'currentReadinessObserved':False,'currentJobOrBudgetStateObserved':False,
        'containerWrites':0,'imageImports':0,'sqlSessions':0,'oauthRequests':0,'credentialFileReads':0,
        'installationSigningKeysRead':False,'sourceActivations':0,'acquisitionsExecuted':0,
        'historicalAuthorityReused':False,'runtimeAuthorityIssued':False,'continuationAuthorized':False,
        'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
    c.put('result.json',output)
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
        output = {'schema':'ouf.onboarding-profile-recovery-current-input-capture-result.v1', 'status':'STOP_RECONCILE',
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



