"""Reusable read-only capture from completed installation receipts.

Reuses the already qualified private-file, Unix Engine and stable-binding
algorithms. Historical review/authority are provenance only. No old entrypoint
is invoked. The fresh case binds the exact completed receipt and output scope.
"""
import copy, hashlib, http.client, json, os, re, socket, stat, struct
from pathlib import Path

MAXIMUMS = {'engineGets': 65, 'privateMetadataReads': 5,
            'responseBytes': 2*1024*1024, 'totalBytes': 24*1024*1024, 'seconds': 90}

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
    def __init__(self, root, cohort_size, reconcile=False):
        require(type(cohort_size) is int and 1 <= cohort_size <= 32, 'BOUNDED_CAPTURE_COHORT_REQUIRED')
        require(type(reconcile) is bool, 'EXPLICIT_RECONCILIATION_MODE_REQUIRED')
        self.maximums = {**MAXIMUMS, 'engineGets': 1 + 2*cohort_size,
                         'privateMetadataReads': 5 if reconcile else 3}
        self.root = Path(root)
        ancestry(self.root.parent)
        require(not os.path.lexists(self.root), 'CSV_RECOVERY_CAPTURE_CONSUMED_NO_REPLAY')
        os.mkdir(self.root, 0o700)
        os.chmod(self.root, 0o700)
        self.counts = {'engineGets': 0, 'privateMetadataReads': 0, 'bytes': 0}
        self.seals = {}
        self.sync(self.root.parent)
        self.put('claim.json', {'schema': 'ouf.managed-csv-recovery-input-capture-claim.v1', 'maximums': self.maximums,
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
        require(self.counts['privateMetadataReads'] < self.maximums['privateMetadataReads'], 'PRIVATE_CAPTURE_READ_LIMIT')
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
    require(type(pid) is int and pid >= 1, 'POSITIVE_CAPTURE_PID_REQUIRED')
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
        require(0 < len(ids) <= 32 and len(set(ids)) == len(ids) and all(re.fullmatch('[a-f0-9]{64}', cid) for cid in ids), 'EXACT_DISTINCT_COHORT_IDS_REQUIRED')
        self.allowed = {'/v1.44/info'} | {'/v1.44/containers/'+cid+'/json' for cid in ids}

    def get(self, path):
        c = self.capture
        require(path in self.allowed and c.counts['engineGets'] < c.maximums['engineGets'], 'CLOSED_READ_ONLY_ENGINE_CAPTURE_REQUIRED')
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


def retained_targets(cohort, case):
    require(len(cohort) == case['cohortSize'] and set(case['targets']) == {'onboarding', 'mcp'}
            and 'onboarding' in cohort, 'EXACT_RETAINED_COHORT_REQUIRED')
    ids = [row['containerId'] for row in cohort.values()]
    require(len(set(ids)) == len(ids)
            and all(type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) for cid in ids),
            'EXACT_DISTINCT_RETAINED_CONTAINER_IDS_REQUIRED')
    require(all(role == 'onboarding' or role == 'peer-'+row['containerId'][:16]
                for role, row in cohort.items()), 'EXACT_RETAINED_PEER_KEYS_REQUIRED')
    matches = [role for role, row in cohort.items() if role != 'onboarding'
               and digest(row) == case['installedMcpNativeBindingHash']
               and row['imageId'] == case['installedMcpNativeImageId']]
    require(len(matches) == 1, 'ONE_EXACT_RETAINED_MCP_BINDING_REQUIRED')
    return {'onboarding': 'onboarding', 'mcp': matches[0]}


def reconcile_prior_stop(capture, case):
    previous = case.get('reconcilePriorStop')
    if previous is None:
        return None
    root = Path(previous['root'])
    require(capture.root.parent == root and capture.root.name == previous['continuationName'],
            'EXACT_NEW_RECONCILIATION_CHILD_SCOPE_REQUIRED')
    claim = capture.private(root/'claim.json', previous['claimSha256'])
    result = capture.private(root/'result.json', previous['resultSha256'])
    require(claim == previous['claim'] and result == previous['result']
            and result['status'] == 'STOP_RECONCILE' and result['complete'] is False
            and result['reasonCode'] == 'EXACT_RETAINED_COHORT_REQUIRED'
            and result['counts'] == previous['counts']
            and result['counts']['engineGets'] == result['containerWrites'] == 0
            and result['counts']['privateMetadataReads'] == claim['maximums']['privateMetadataReads'] == 3
            and result['runtimeAuthorityIssued'] is False and result['automaticReplayAllowed'] is False
            and result['budgetReset'] is False, 'EXACT_CONSUMED_PRE_ENGINE_STOP_REQUIRED')
    return {'scope': str(root), 'counts': copy.deepcopy(result['counts']),
            'claimSha256': previous['claimSha256'], 'resultSha256': previous['resultSha256'],
            'scopeConsumed': True, 'historicalAuthorityReused': False}


def capture_accounting(capture, previous):
    prior = previous['counts'] if previous else {key: 0 for key in capture.counts}
    return {'currentScopeCounts': dict(capture.counts), 'retainedConsumedScopeCounts': copy.deepcopy(prior),
            'cumulativeCounts': {key: prior[key]+value for key, value in capture.counts.items()}}


def retained(review, result, journal, case):
    require(review['schema'] == 'ouf.onboarding-profile-recovery-update-review.v1'
            and digest(review) == case['reviewHash'] and review['executionRoot'] == case['installedRoot'],
            'EXACT_COMPLETED_INSTALLATION_REVIEW_REQUIRED')
    require(result['schema'] == 'ouf.onboarding-profile-recovery-update-result.v1'
            and result['status'] == 'ONBOARDING_PROFILE_RECOVERY_UPDATE_INSTALLED_E2E_NOT_ACCEPTED'
            and result['complete'] is True and result['componentReadinessProven'] is True
            and result['contextPath'] == case['installedRoot']
            and result['reviewHash'] == case['reviewHash'] and result['authorityHash'] == case['authorityHash']
            and result['candidateSourceCommit'] == case['installedSource']
            and result['nativeImageId'] == case['installedNativeImageId']
            and result['nativeBindingHash'] == case['installedNativeBindingHash']
            and result['humanBudgetsGranted'] == result['newGrantsGranted'] == result['sourceActivations'] == result['acquisitionsExecuted'] == 0
            and result['registryWorkerTouched'] is False and result['automaticReplayAllowed'] is False
            and result['budgetReset'] is False, 'EXACT_COMPLETED_INSTALLATION_RECEIPT_REQUIRED')
    stages = review['stages']
    require(journal['schema'] == 'ouf.onboarding-profile-recovery-update-journal.v1'
            and journal['state'] == 'COMPLETE' and journal['reviewHash'] == case['reviewHash']
            and journal['authorityHash'] == case['authorityHash'] and journal['quarantine'] is None
            and journal['automaticReplayAllowed'] is False and journal['budgetReset'] is False
            and journal['nextStage'] == len(stages) == len(journal['effects'])
            and set(journal['candidates']) == {'onboarding'}, 'COMPLETED_JOURNAL_WITHOUT_AMBIGUITY_REQUIRED')
    for stage, effect in zip(stages, journal['effects']):
        require(effect['stage'] == stage and effect['state'] == 'APPLIED'
                and effect['intentHash'] == digest({'reviewHash': case['reviewHash'], 'stage': stage}),
                'NO_UNRECONCILED_RETAINED_EFFECT_REQUIRED')
    proofs = [effect['proof'] for effect in journal['effects'] if effect['stage'] == 'VERIFY_FINAL']
    require(len(proofs) == 1, 'ONE_FINAL_INSTALLATION_PROOF_REQUIRED')
    proof = proofs[0]; candidate = journal['candidates']['onboarding']
    require(candidate['configurationVerified'] is True and candidate['readinessProven'] is True
            and proof['nativeBindingHash'] == case['installedNativeBindingHash']
            and candidate['generation'] == proof['generation'], 'EXACT_RETAINED_CANDIDATE_REQUIRED')
    cohort = copy.deepcopy(review['nativePlan']['proposal']['existingApplications'])
    targets = retained_targets(cohort, case)
    cohort['onboarding']['containerId'] = candidate['id']
    return cohort, candidate, targets


def prepare(capture, case, *, engine_factory=Engine, pin=process_pin,
            boot_path=Path('/proc/sys/kernel/random/boot_id')):
    c = capture; installed = Path(case['installedRoot'])
    previous = reconcile_prior_stop(c, case)
    c.priorConsumedStop = previous
    review = c.private(installed/'review.json', case['reviewHash'])
    result = c.private(installed/'result.json')
    journal = c.private(installed/'recovery.json')
    cohort, candidate, targets = retained(review, result, journal, case)
    require(boot_path.read_text().strip() == review['bootId'], 'SAME_RETAINED_HOST_BOOT_REQUIRED')
    binding = review['nativePlan']['proposal']['engineBinding']
    ids = [row['containerId'] for row in cohort.values()]
    require(len(set(ids)) == len(ids), 'DISTINCT_COHORT_CONTAINER_IDS_REQUIRED')
    engine = engine_factory(c, binding, ids)
    root_pins = {'pid1': pin(1), 'engine': pin(binding['peerCredentials'][0])}
    info = engine.get('/v1.44/info'); observations = {}; generations = {}
    for role, expected in sorted(cohort.items()):
        actual = engine.get('/v1.44/containers/'+expected['containerId']+'/json')
        observed = stable_binding(actual)
        if role == 'onboarding':
            require(digest(observed) == case['installedNativeBindingHash']
                    and actual['Image'] == case['installedNativeImageId']
                    and actual['State']['Running'] is True and actual['State']['Paused'] is False
                    and actual['State']['Restarting'] is False, 'EXACT_INSTALLED_ONBOARDING_GENERATION_REQUIRED')
        else:
            require(observed == expected, 'RETAINED_PEER_GENERATION_CHANGED')
        generation = pin(actual['State']['Pid'])
        if role == 'onboarding':
            require(generation == candidate['generation'], 'INSTALLED_ONBOARDING_PROCESS_CHANGED')
        observations[role] = actual; generations[role] = generation
    for role, first in sorted(observations.items()):
        again = engine.get('/v1.44/containers/'+first['Id']+'/json')
        require(stable_binding(first) == stable_binding(again)
                and generations[role] == pin(again['State']['Pid']), 'COHORT_CHANGED_DURING_CAPTURE')
    require(root_pins == {'pid1': pin(1), 'engine': pin(binding['peerCredentials'][0])}
            and boot_path.read_text().strip() == review['bootId'], 'ENGINE_ROOT_OR_BOOT_CHANGED_DURING_CAPTURE')
    for path, seal in c.seals.items():
        require(list(frame(Path(path).lstat())) == seal['metadata'], 'RETAINED_METADATA_CHANGED')
    payload = {'schema': 'ouf.managed-csv-recovery-current-inputs.v1', 'bootId': review['bootId'],
               'engineBinding': binding, 'engineInfo': info, 'currentObservations': observations,
               'currentProcessPins': generations, 'currentRootProcessPins': root_pins,
               'retainedInstallation': {'reviewHash': case['reviewHash'], 'authorityHash': case['authorityHash'],
                                        'scopeConsumed': True, 'counts': result['counts']},
               'historySeals': c.seals, 'counts': dict(c.counts), 'targets': case['targets'],
               'resolvedTargetRoles': targets, 'priorConsumedStop': previous,
               'captureAccounting': capture_accounting(c, previous),
               'currentApplicationPolicyOrLabelsObserved': False, 'currentJobOrBudgetStateObserved': False,
               'runtimeAuthorityIssued': False, 'automaticReplayAllowed': False, 'budgetReset': False}
    c.put('inputs.json', payload)
    output = {'schema': 'ouf.managed-csv-recovery-input-capture-result.v1',
              'status': 'MANAGED_CSV_RECOVERY_CURRENT_INPUTS_CAPTURED_NOT_AUTHORIZED', 'complete': True,
              'contextPath': str(c.root), 'inputsHash': digest(payload), 'counts': dict(c.counts),
              'cohortSize': len(cohort), 'targetRoles': case['targets'],
              'captureAccounting': capture_accounting(c, previous),
              'currentJobOrBudgetStateObserved': False, 'currentApplicationPolicyOrLabelsObserved': False,
              'containerWrites': 0, 'sqlSessions': 0, 'credentialFileReads': 0,
              'oauthRequests': 0, 'installationSigningKeysRead': False, 'imageImports': 0,
              'historicalAuthorityReused': False, 'runtimeAuthorityIssued': False,
              'humanBudgetsGranted': 0, 'resumes': 0, 'newGrantsGranted': 0,
              'acquisitionsExecuted': 0, 'sourceActivations': 0, 'applicationE2EProven': False,
              'releaseAcceptance': False, 'automaticReplayAllowed': False, 'budgetReset': False}
    c.put('result.json', output)
    return output

