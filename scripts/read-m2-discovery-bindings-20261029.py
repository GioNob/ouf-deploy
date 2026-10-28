#!/usr/bin/env python3
"""New finite M2 installation metadata read. No provider, SQL, IAM or runtime effects."""
import copy,hashlib,http.client,json,os,pwd,re,signal,socket,stat,struct,sys,time
from pathlib import Path
MAXIMUMS={'engineGets':27,'privateMetadataReads':3,'responseBytes':2097152,'totalBytes':25165824,'seconds':90}
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

class Logger:
    def __init__(self, path):
        self.original = sys.stdout
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        self.file = os.fdopen(fd, "w", buffering=1)

    def write(self, value):
        self.file.write(value); self.file.flush(); os.fsync(self.file.fileno())
        return self.original.write(value)

    def flush(self):
        self.file.flush(); os.fsync(self.file.fileno()); self.original.flush()

    def isatty(self):
        return self.original.isatty()

    def fileno(self):
        return self.original.fileno()

"""Read current installation bindings from one consumed V38 receipt, never execute it."""
CASE = {
    'installedRoot': '/etc/ouf/deploy-snapshots/managed-file-owner-v38-update-b03d681a-20261028-v1',
    'outputRoot': '/etc/ouf/deploy-snapshots/m2-discovery-current-bindings-0601fdfa-20261029-v1',
    'reviewHash': '3eb5712707a63aef0cf0c09d2ad71c84575671c96d9d4fa1cba42598f8ac8f83',
    'resultHash': '0601fdfadd157eedbdd35144e7913e152d3d1f1a67e4927317e2de6a566a61ca',
    'authorityHash': '8f8d2c438e4200e2dfc1cdd33018ac173dc87a34b33486d3b7caffcd943e1d5e',
    'frozenPlanHash': '6d256f8874e721bcd2d349e7efdd0ee2d881cd0cd4edca14ffc5b4ec330139ee',
    'executionInputsHash': 'b03d681a8070b31ab29ab9515846421e98ff55a197e963f447d645b1c824a120',
    'nativeBindingHash': 'c6f72349b8b3a9f7d11f7b9c63fe0f67a159e3be3ea56f9b2a349a9e8f48a2d7',
    'nativeImageId': 'sha256:7b9d3e918beea500929cb9e3e88165b6c574cedac6067e56206fb2ffa1d65b51',
    'sourceCommit': '9d19fad3dd750dd5b9e77253d3e7e82029c1aca7',
}
STAGES = ('VERIFY_CURRENT_ADMISSION', 'IMPORT_ONBOARDING_OWNER', 'VERIFY_PRESTOP_STATE',
          'DISABLE_OLD_RESTART_ONBOARDING_OWNER', 'STOP_OLD_ONBOARDING_OWNER',
          'VERIFY_QUIESCED_BACKUP', 'DETACH_OLD_ONBOARDING_OWNER', 'RENAME_OLD_ONBOARDING_OWNER',
          'CREATE_ONBOARDING_OWNER', 'VERIFY_PRESTART_STATE', 'START_ONBOARDING_OWNER',
          'VERIFY_READINESS_ONBOARDING_OWNER', 'VERIFY_POSTMIGRATION_STATE',
          'RESTORE_RESTART_ONBOARDING_OWNER', 'VERIFY_FINAL', 'VERIFY_FINAL_STATE')
FLAG_KEYS = ('OUF_SCHEMA_GOV_ENABLED', 'OUF_DISCOVERY_WORKER_ENABLED')
KNOWN_SOURCES = tuple('https://github.com/GioNob/'+name for name in (
    'ouf-source-onboarding', 'ouf-mcp-server', 'ouf-api-gateway', 'ouf-semantic-registry',
    'ouf-ingestion-runtime', 'ouf-udp-object-resolution'))


def consumed_history(review, result, journal, case):
    require(digest(review) == case['reviewHash'] and digest(result) == case['resultHash'],
            'EXACT_CONSUMED_V38_REVIEW_AND_RESULT_REQUIRED')
    proposal = review['nativePlan']['proposal']
    require(review['schema'] == 'ouf.managed-file-owner-v38-update-review.v1'
            and review['executionRoot'] == case['installedRoot']
            and review['frozenPlanHash'] == case['frozenPlanHash'] == digest(proposal)
            and review['nativePlan']['frozenPlanHash'] == case['frozenPlanHash']
            and review['bootId'] and review['stages'] == list(STAGES)
            and review['targetRoles'] == ['onboarding']
            and review['automaticReplayAllowed'] is False and review['budgetReset'] is False,
            'EXACT_CONSUMED_V38_NATIVE_PLAN_REQUIRED')
    require(result['schema'] == 'ouf.managed-file-owner-v38-update-result.v1'
            and result['status'] == 'MANAGED_FILE_OWNER_V38_INSTALLED_E2E_NOT_ACCEPTED'
            and result['complete'] is True and result['componentReadinessProven'] is True
            and result['contextPath'] == case['installedRoot']
            and result['reviewHash'] == case['reviewHash']
            and result['authorityHash'] == case['authorityHash']
            and result['executionInputsHash'] == case['executionInputsHash']
            and result['frozenPlanHash'] == case['frozenPlanHash']
            and result['nativeBindingHash'] == case['nativeBindingHash']
            and result['nativeImageId'] == case['nativeImageId']
            and result['sourceCommit'] == case['sourceCommit']
            and result['installedSchemaVersion'] == 38
            and result['unchangedPeers'] == 12 and result['mcpUnchanged'] is True
            and result['registryWorkerTouched'] is False
            and result['automaticReplayAllowed'] is False and result['budgetReset'] is False,
            'EXACT_SUCCESSFUL_CONSUMED_V38_RESULT_REQUIRED')
    require(journal['schema'] == 'ouf.managed-csv-control-update-journal.v1'
            and journal['state'] == 'COMPLETE' and journal['reviewHash'] == case['reviewHash']
            and journal['authorityHash'] == case['authorityHash'] and journal['quarantine'] is None
            and journal['nextStage'] == len(STAGES) == len(journal['effects'])
            and set(journal['candidates']) == {'onboarding'}
            and journal['automaticReplayAllowed'] is False and journal['budgetReset'] is False,
            'COMPLETE_UNAMBIGUOUS_CONSUMED_V38_JOURNAL_REQUIRED')
    for stage, effect in zip(STAGES, journal['effects']):
        require(effect['stage'] == stage and effect['state'] == 'APPLIED'
                and effect['intentHash'] == digest({'reviewHash': case['reviewHash'], 'stage': stage}),
                'CONSUMED_V38_EFFECT_NOT_RECONCILED')
    candidate = journal['candidates']['onboarding']
    require(candidate['configurationVerified'] is True and candidate['readinessProven'] is True
            and candidate['generation'] == result['generation'],
            'EXACT_RETAINED_V38_CANDIDATE_REQUIRED')
    cohort = copy.deepcopy(proposal['existingApplications'])
    require(len(cohort) == 13 and 'onboarding' in cohort
            and len({row['containerId'] for row in cohort.values()}) == 13,
            'EXACT_RETAINED_COHORT13_REQUIRED')
    cohort['onboarding']['containerId'] = candidate['id']
    require(len({row['containerId'] for row in cohort.values()}) == 13,
            'DISTINCT_CURRENT_COHORT13_REQUIRED')
    return cohort, candidate, proposal['engineBinding']


def public_binding(actual, generation):
    config = actual['Config']
    env = {}
    rows = config.get('Env')
    if rows is None:
        rows = []
    require(type(rows) is list and len(rows) <= 512,
            'BOUNDED_ENV_METADATA_REQUIRED')
    for row in rows:
        require(type(row) is str and '=' in row and len(row) <= 1048576,
                'TYPED_ENV_METADATA_REQUIRED')
        key, value = row.split('=', 1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', key) and key not in env,
                'UNIQUE_ENV_METADATA_REQUIRED')
        env[key] = value
    flags = {key: ('ABSENT' if key not in env else
                   'TRUE' if env[key] == 'true' else
                   'FALSE' if env[key] == 'false' else 'UNRECOGNIZED')
             for key in FLAG_KEYS}
    labels = config.get('Labels') or {}
    require(type(labels) is dict, 'TYPED_CONTAINER_LABEL_METADATA_REQUIRED')
    source = labels.get('org.opencontainers.image.source')
    source_ref = source if source in KNOWN_SOURCES else None
    host = actual['HostConfig']
    restart = host.get('RestartPolicy') or {}
    name = actual['Name']
    require(type(name) is str and re.fullmatch('/[A-Za-z0-9][A-Za-z0-9_.-]{0,255}', name),
            'BOUNDED_CONTAINER_NAME_REQUIRED')
    require(re.fullmatch('sha256:[a-f0-9]{64}', actual['Image']) is not None,
            'EXACT_IMAGE_METADATA_REQUIRED')
    require(restart.get('Name') in ('no', 'always', 'unless-stopped', 'on-failure')
            and type(restart.get('MaximumRetryCount')) is int
            and 0 <= restart['MaximumRetryCount'] <= 100000,
            'TYPED_RESTART_POLICY_METADATA_REQUIRED')
    return {
        'containerId': actual['Id'], 'name': name, 'imageId': actual['Image'],
        'nativeBindingHash': digest(stable_binding(actual)), 'generation': generation,
        'sourceRepositoryDeclaredByContainerLabel': source_ref,
        'sourceRepositoryLabelPresent': source is not None,
        'declaredDiscoveryFlags': flags,
        'springJsonPresent': bool(env.get('SPRING_APPLICATION_JSON')),
        'springConfigImportPresent': bool(env.get('SPRING_CONFIG_IMPORT')),
        'jvmOptionEnvironmentPresent': any(bool(env.get(key)) for key in
            ('JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'JAVA_OPTS')),
        'effectiveDiscoveryConfigurationProven': False,
        'providerGatewayValuePresent': any(bool(env.get(key)) for key in (
            'OUF_SCHEMA_GOV_GATEWAY_BASE_URL', 'OUF_SEMANTIC_PROVIDERS_SCHEMA_GOV_GATEWAY_BASE_URL')),
        'providerCredentialValueOrFileContentRead': False,
        'restartPolicy': copy.deepcopy(restart),
        'restartCountObserved': actual.get('RestartCount'),
        'readOnlyMounts': sum(row.get('RW') is False for row in actual['Mounts']),
        'readWriteMounts': sum(row.get('RW') is True for row in actual['Mounts']),
        'networkCount': len(actual['NetworkSettings'].get('Networks') or {}),
        'applicationReadinessOrProviderReachabilityProven': False,
    }


def capture_bindings(c, case=None, *, engine_factory=Engine, pin=process_pin,
                     boot_path=Path('/proc/sys/kernel/random/boot_id')):
    case = CASE if case is None else case
    require(str(c.root) == case['outputRoot'], 'EXACT_NEW_BINDING_CAPTURE_SCOPE_REQUIRED')
    old = Path(case['installedRoot'])
    review = c.private(old/'review.json', case['reviewHash'])
    result = c.private(old/'result.json')
    journal = c.private(old/'recovery.json')
    cohort, candidate, binding = consumed_history(review, result, journal, case)
    require(boot_path.read_text().strip() == review['bootId'], 'SAME_RETAINED_HOST_BOOT_REQUIRED')
    roots = {'pid1': pin(1), 'engine': pin(binding['peerCredentials'][0])}
    engine = engine_factory(c, binding, [row['containerId'] for row in cohort.values()])
    require(engine.get('/v1.44/info').get('ServerVersion') == '29.8.1',
            'QUALIFIED_CURRENT_ENGINE_REQUIRED')
    observations, pins = {}, {}
    for role, expected in sorted(cohort.items()):
        actual = engine.get('/v1.44/containers/'+expected['containerId']+'/json')
        require(actual['State']['Running'] is True and actual['State']['Paused'] is False
                and actual['State']['Restarting'] is False, 'CURRENT_RETAINED_COHORT_RUNNING_REQUIRED')
        observed = stable_binding(actual)
        generation = pin(actual['State']['Pid'])
        if role == 'onboarding':
            require(digest(observed) == case['nativeBindingHash']
                    and actual['Image'] == case['nativeImageId']
                    and generation == candidate['generation'], 'EXACT_CURRENT_V38_OWNER_REQUIRED')
        else:
            require(observed == expected, 'RETAINED_PEER_BINDING_CHANGED')
        observations[role], pins[role] = actual, generation
    summaries = [public_binding(observations[role], pins[role]) for role in sorted(observations)]
    for role, first in sorted(observations.items()):
        again = engine.get('/v1.44/containers/'+first['Id']+'/json')
        require(stable_binding(first) == stable_binding(again)
                and pin(again['State']['Pid']) == pins[role], 'COHORT_BINDING_CHANGED_DURING_CAPTURE')
    require(roots == {'pid1': pin(1), 'engine': pin(binding['peerCredentials'][0])}
            and boot_path.read_text().strip() == review['bootId'], 'ROOT_PEER_OR_BOOT_CHANGED')
    for path, seal in c.seals.items():
        require(list(frame(Path(path).lstat())) == seal['metadata'], 'CONSUMED_HISTORY_METADATA_CHANGED')
    private = {
        'schema': 'ouf.m2-discovery-current-private-bindings.v1', 'bootId': review['bootId'],
        'engineBinding': binding, 'observations': observations, 'processPins': pins,
        'rootProcessPins': roots, 'retainedReview': review, 'retainedResult': result,
        'historySeals': c.seals, 'counts': dict(c.counts),
        'historicalAuthorityReused': False, 'runtimeAuthorityIssued': False,
        'automaticReplayAllowed': False, 'budgetReset': False,
    }
    c.put('inputs.json', private)
    out = {
        'schema': 'ouf.m2-discovery-current-bindings-result.v1',
        'status': 'M2_DISCOVERY_CURRENT_BINDINGS_CAPTURED_NOT_AUTHORIZED', 'complete': True,
        'contextPath': str(c.root), 'inputsHash': digest(private), 'counts': dict(c.counts),
        'cohortSize': 13, 'bindings': summaries, 'retainedInstallationResultHash': case['resultHash'],
        'currentJobOrBudgetStateRead': False, 'effectiveProviderConfigurationProven': False,
        'applicationReadinessOrProviderReachabilityProven': False,
        'databaseAdmissionProven': False, 'sqlSessions': 0, 'engineWrites': 0,
        'configurationFileContentReads': 0, 'credentialFileReads': 0, 'signingKeyReads': 0,
        'iamRequests': 0, 'oauthRequests': 0, 'imageImports': 0, 'containerLifecycleOperations': 0,
        'newGrantsGranted': 0, 'humanBudgetsGranted': 0, 'resumes': 0, 'newJobs': 0,
        'uploads': 0, 'acquisitionsExecuted': 0, 'sourceActivations': 0,
        'nativePlanPrepared': False, 'runtimeAuthorityIssued': False,
        'historicalAuthorityReused': False, 'targetApplyAuthorized': False,
        'automaticReplayAllowed': False, 'budgetReset': False,
        'applicationE2EProven': False, 'releaseAcceptance': False,
    }
    c.put('result.json', out)
    return out



def main():
    c=None
    try:
        require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated
            and sys.flags.no_site and sys.dont_write_bytecode
            and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),
            'ISOLATED_OUFADMIN_BINDING_CAPTURE_REQUIRED')
        require(sys.stdin.isatty() and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve(); ancestry(code.parent); info=code.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
            and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o400,'ROOT400_BINDING_CAPTURE_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'M2_BINDING_CAPTURE_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_BINDING_CAPTURE_WINDOW_EXPIRED'))
        signal.alarm(90)
        c=Capture(CASE['outputRoot'],13)
        print('Nuova sola lettura: 3 metadata della manutenzione V38 consumata; 27 GET Engine sulla stessa coorte di13. Pin processi, socket e boot.90s/24MiB. Nessun SQL, fileconfig, credenziale, chiave, OAuth/IAM, import, lifecycle, grant, budget, resume o acquisizione. Le risposte Engine possono contenere Env preesistenti: restano private root0600. Nessuna authority o attivazione; STOP conserva e consuma, non rilanciare.',flush=True)
        result=capture_bindings(c)
    except BaseException as error:
        reason=str(error) if isinstance(error,Stop) and re.fullmatch('[A-Z0-9_]{1,120}',str(error)) else 'PRIVATE_M2_BINDING_CAPTURE_FAILURE_RECONCILE'
        result={'schema':'ouf.m2-discovery-current-bindings-result.v1','status':'STOP_RECONCILE',
            'complete':False,'reasonCode':reason,'contextPath':str(c.root) if c else None,
            'counts':dict(c.counts) if c else {},'engineWrites':0,'sqlSessions':0,'iamRequests':0,
            'oauthRequests':0,'humanBudgetsGranted':0,'resumes':0,'runtimeAuthorityIssued':False,
            'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c is not None and not (c.root/'result.json').exists(): c.put('result.json',result)
    finally:
        signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete'] else 2


if __name__=='__main__':
    raise SystemExit(main())
