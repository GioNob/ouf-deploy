"""V5-only runc adapter; the historical v1-v4 adapter remains unchanged.

No daemon configuration, registration or journal provisioning. Candidate create
requires B2 staging and verified arming. Recovery never replays create.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone


class Denied(RuntimeError): pass


def require(value, reason='ADAPTER_BINDING_UNPROVEN'):
    if not value:
        if reason == 'ADAPTER_BINDING_UNPROVEN': reason += '_L'+str(sys._getframe(1).f_lineno)
        raise Denied(reason)


def digest(value): return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE_ADAPTER_JSON_KEY'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def ancestors(path):
    require(path.is_absolute() and '..' not in path.parts)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)


def read(path, private=True):
    ancestors(path); fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and before.st_gid == 0
                and (stat.S_IMODE(before.st_mode) == 0o600 if private else not before.st_mode & 0o022)
                and before.st_size <= 131072)
        raw = os.read(fd, 131073); after = os.fstat(fd)
        require(len(raw) == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(path.lstat(), k)
                for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')))
        return raw
    finally: os.close(fd)


def executable(path, expected):
    path = Path(path); ancestors(path); info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and info.st_mode & 0o111)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        h = hashlib.sha256(); count = 0
        while True:
            raw = os.read(fd, 65536)
            if not raw: break
            count += len(raw); require(count <= 64000000); h.update(raw)
        require(h.hexdigest() == expected, 'ADAPTER_EXECUTABLE_DRIFT')
    finally: os.close(fd)


def save(path, old, value):
    require(parse(read(path)) == old, 'ADAPTER_JOURNAL_DRIFT')
    # Caller holds the existing per-CID lock. Never borrow the guard lock here.
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.adapter-', delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(json.dumps(value, sort_keys=True).encode()); stream.flush(); os.fsync(stream.fileno())
        except BaseException:
            temp.unlink(); raise
    try:
        require(parse(read(path)) == old, 'ADAPTER_JOURNAL_DRIFT'); os.replace(temp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if temp.exists(): temp.unlink()


def arguments(argv):
    require(0 < len(argv) <= 40 and all(len(v) <= 4096 for v in argv), 'RUNTIME_ARGUMENTS_UNBOUNDED')
    values = {}; operation = None; position = 0
    global_values = {'--root', '--log', '--log-format'}
    while position < len(argv):
        item = argv[position]
        if item in ('--debug', '--systemd-cgroup'): position += 1; continue
        if item in global_values:
            require(item not in values and position+1 < len(argv)); values[item] = argv[position+1]; position += 2; continue
        operation = item; position += 1; break
    require(operation in ('create','start','state','delete','kill','--version','version','features'), 'UNSUPPORTED_RUNTIME_OPERATION')
    if operation in ('--version','version','features'):
        require(position == len(argv)); return operation, None, values
    require('--root' in values)
    opts = {'create': {'--bundle', '-b', '--pid-file', '--console-socket', '--preserve-fds'},
            'start': set(), 'state': set(), 'delete': set(), 'kill': set()}[operation]
    bools = {'create': {'--no-pivot', '--no-new-keyring'}, 'start': set(), 'state': set(),
             'delete': {'--force', '-f'}, 'kill': {'--all', '-a'}}[operation]
    while position < len(argv) and argv[position].startswith('-'):
        item = argv[position]; position += 1
        require(item not in values)
        if item in bools: values[item] = True
        else:
            require(item in opts and position < len(argv)); values[item] = argv[position]; position += 1
    require(position < len(argv)); cid = argv[position]; position += 1
    require(re.fullmatch('[0-9a-f]{64}', cid), 'EXACT_DOCKER_CID_REQUIRED')
    if operation == 'kill':
        require(position+1 == len(argv) and re.fullmatch('[0-9]{1,2}|SIG[A-Z]{2,10}', argv[position]))
    else: require(position == len(argv))
    if operation == 'create':
        require(('--bundle' in values) != ('-b' in values) and values.get('--preserve-fds', '0') == '0')
    return operation, cid, values


def capture(argv, timeout=20):
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                                timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        output.seek(0); raw = output.read(16385)
        require(result.returncode == 0 and len(raw) <= 16384, 'ADMISSION_OR_DRIVER_FAILED')
        return raw


def binding(config, cid):
    return digest({**{k: v for k, v in config.items() if k != 'candidates'}, 'candidate': config['candidates'][cid]})


SCHEMA = 'ouf.semantic-docker-runtime-adapter.v5'
ARMING_SCHEMA = 'ouf.semantic-docker-runtime-arming.v1'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
CONFIG_FIELDS = {'schema','sourceHash','runtimePath','runtimeSha256','pythonPath','pythonSha256',
    'driverPath','driverSha256','admissionPath','admissionSha256','registryRoot','runtimeStateRoot',
    'acceptance','b1b2TrustPolicy','armingRoot','candidates','armingVerifierPath','armingVerifierSha256',
    'b1b2AuthorityModule','opensslBinding','armingIssuerRef'}


def hashed(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def identity(value):
    return type(value) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value) is not None


def absolute(value):
    require(type(value) is str, 'EXPLICIT_V5_PATH_REQUIRED')
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts and str(path) == value, 'EXPLICIT_V5_PATH_REQUIRED')
    return path


def file_binding(value):
    require(type(value) is dict and set(value) == {'path','sha256'} and hashed(value['sha256']),
            'EXACT_V5_FILE_BINDING_REQUIRED')
    absolute(value['path'])


def private_directory(path):
    ancestors(path/'custody'); info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_V5_DIRECTORY_REQUIRED')


def load_configuration(config_path):
    """Read sealed v5 configuration and arming root, without executing anything."""
    raw = read(config_path); config = parse(raw)
    require(type(config) is dict and set(config) == CONFIG_FIELDS and config['schema'] == SCHEMA,
            'EXACT_RUNTIME_V5_CONFIGURATION_REQUIRED')
    for key in ('sourceHash','runtimeSha256','pythonSha256','driverSha256','admissionSha256','armingVerifierSha256'):
        require(hashed(config[key]), 'V5_SHA256_REQUIRED')
    for key in ('runtimePath','pythonPath','driverPath','admissionPath','registryRoot','runtimeStateRoot',
                'armingRoot','armingVerifierPath'):
        absolute(config[key])
    for key in ('acceptance','b1b2TrustPolicy','b1b2AuthorityModule'):
        file_binding(config[key])
    ssl = config['opensslBinding']
    require(type(ssl) is dict and set(ssl) == {'path','sha256','version'}
            and type(ssl['version']) is str and re.fullmatch('[0-9]+[.][0-9]+[.][0-9]+[a-z]?', ssl['version']),
            'EXACT_V5_OPENSSL_BINDING_REQUIRED')
    file_binding({k: ssl[k] for k in ('path','sha256')})
    require(identity(config['armingIssuerRef']), 'V5_ISSUER_REQUIRED')
    candidates = config['candidates']
    require(type(candidates) is dict and len(candidates) == 2 and all(hashed(cid) for cid in candidates),
            'EXACT_V5_CANDIDATES_REQUIRED')
    for entry in candidates.values():
        require(type(entry) is dict and set(entry) == {'phase','bundleParents'} and entry['phase'] == 'INACTIVE'
                and type(entry['bundleParents']) is list and 1 <= len(entry['bundleParents']) <= 4,
                'EXACT_INACTIVE_CANDIDATE_REQUIRED')
        for parent in entry['bundleParents']: absolute(parent)
    private_directory(Path(config['armingRoot']))
    return config, raw


def verify_files(config):
    require(hashlib.sha256(read(Path(__file__))).hexdigest() == config['sourceHash'], 'ADAPTER_SOURCE_DRIFT')
    for prefix in ('runtime','python'):
        executable(config[prefix+'Path'], config[prefix+'Sha256'])
    for prefix in ('driver','admission','armingVerifier'):
        require(hashlib.sha256(read(Path(config[prefix+'Path']))).hexdigest() == config[prefix+'Sha256'],
                'V5_BOUND_FILE_DRIFT')
    for key in ('acceptance','b1b2TrustPolicy','b1b2AuthorityModule'):
        value = config[key]
        require(hashlib.sha256(read(Path(value['path']))).hexdigest() == value['sha256'], 'V5_BOUND_FILE_DRIFT')
    executable(config['opensslBinding']['path'], config['opensslBinding']['sha256'])


def arming_inventory(config):
    root = Path(config['armingRoot']); private_directory(root)
    generations = set(); markers = []
    for path in root.iterdir():
        require(len(generations) <= 1024 and len(markers) <= 2048, 'ARMING_INVENTORY_UNBOUNDED')
        name = path.name
        match = re.fullmatch('([1-9][0-9]*)[.](?:RUNTIME_ARMING[.])?json', name)
        if match:
            read(path); generations.add(int(match[1]))
        else:
            require(re.fullmatch('[1-9][0-9]*[.][0-9a-f]{64}[.]consumed', name), 'UNKNOWN_ARMING_ROOT_ENTRY')
            read(path); markers.append(name)
    require(len(generations) <= 1024 and len(markers) <= 2048, 'ARMING_INVENTORY_UNBOUNDED')
    return sorted(generations), sorted(markers)


def arming_absence(config_path):
    """Read-only inventory: generation numbers (including orphan signatures), marker names.

    Only two empty lists prove absence; malformed/foreign entries fail closed.
    Does not verify signatures, invoke children or create journals/locks/markers.
    """
    config, _ = load_configuration(Path(config_path))
    generations, markers = arming_inventory(config)
    return {'armingGenerations': generations, 'consumedMarkers': markers}


def load_arming(config, configuration_raw, generation):
    require(type(generation) is int and generation >= 1, 'ARMING_GENERATION_REQUIRED')
    root = Path(config['armingRoot']); private_directory(root)
    raw = read(root/(str(generation)+'.json')); arming = parse(raw)
    read(root/(str(generation)+'.RUNTIME_ARMING.json'))  # custody only; no cryptography here
    require(type(arming) is dict and set(arming) == {'schema','installationRef','entityRef','generation',
            'runtimeConfigurationSha256','acceptanceSha256','candidates','issuedAt'}
            and arming['schema'] == ARMING_SCHEMA and type(arming['generation']) is int
            and arming['generation'] == generation and identity(arming['installationRef'])
            and identity(arming['entityRef']) and type(arming['issuedAt']) is int and arming['issuedAt'] >= 0,
            'EXACT_RUNTIME_ARMING_REQUIRED')
    require(arming['runtimeConfigurationSha256'] == hashlib.sha256(configuration_raw).hexdigest(),
            'ARMING_CONFIGURATION_DRIFT')
    require(arming['acceptanceSha256'] == config['acceptance']['sha256'], 'ARMING_ACCEPTANCE_DRIFT')
    require(type(arming['candidates']) is dict and set(arming['candidates']) == set(config['candidates']),
            'ARMING_CANDIDATES_DRIFT')
    for entry in arming['candidates'].values():
        require(type(entry) is dict and set(entry) == {'intentRef','admissionConfiguration','admissionConfigurationHash'}
                and hashed(entry['intentRef']) and hashed(entry['admissionConfigurationHash']),
                'EXACT_ARMING_CANDIDATE_REQUIRED')
        absolute(entry['admissionConfiguration'])
    return arming, raw


def select_arming(config, configuration_raw, cid):
    generations, markers = arming_inventory(config)
    available = [n for n in generations if str(n)+'.'+cid+'.consumed' not in markers]
    require(available, 'RUNTIME_PHASE_INACTIVE')
    require(len(available) == 1, 'ARMING_GENERATION_AMBIGUOUS')
    return load_arming(config, configuration_raw, available[0])


def binding_v5(config, cid, arming):
    """B2 STAGED binding. `arming` is the exact payload bytes, not re-encoded JSON.

    Canonical digest of all v5 fields except candidates, the merged candidate,
    armingGeneration and SHA256 of the exact signed arming payload bytes.
    """
    require(type(arming) is bytes, 'EXACT_ARMING_PAYLOAD_BYTES_REQUIRED')
    value = parse(arming)
    return digest({**{k: v for k, v in config.items() if k != 'candidates'},
        'candidate': {**config['candidates'][cid], **value['candidates'][cid]},
        'armingGeneration': value['generation'], 'armingPayloadSha256': hashlib.sha256(arming).hexdigest()})


def verify_arming(config_path, config, cid, generation):
    raw = capture([config['pythonPath'], '-I', '-B', config['armingVerifierPath'],
        '--configuration', str(config_path), '--container-id', cid, '--generation', str(generation)], timeout=20)
    require(raw == b'RUNTIME_ARMING_VERIFIED\n', 'RUNTIME_ARMING_VERIFIER_DENIED')


def consume_arming(config, cid, arming_raw):
    arming = parse(arming_raw); root = Path(config['armingRoot']); private_directory(root)
    path = root/(str(arming['generation'])+'.'+cid+'.consumed')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        os.fchmod(fd, 0o600); info = os.fstat(fd)
        require(info.st_uid == info.st_gid == 0 and info.st_nlink == 1, 'PRIVATE_CONSUMPTION_MARKER_REQUIRED')
        raw = json.dumps({'generation': arming['generation'], 'armingPayloadSha256': hashlib.sha256(arming_raw).hexdigest()},
                         sort_keys=True).encode()
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally: os.close(fd)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def inactive(config, cid, operation, root, argv):
    require(operation in ('state','delete'), 'RUNTIME_PHASE_INACTIVE')
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run([config['runtimePath'], '--root', str(root), 'state', cid],
            stdin=subprocess.DEVNULL, stdout=output, stderr=errors, timeout=10, env=ENV)
        output.seek(0); raw = output.read(16385); errors.seek(0); error = errors.read(16385)
    require(len(raw) <= 16384 and len(error) <= 16384, 'INACTIVE_RUNTIME_STATE_UNPROVEN')
    require(result.returncode != 0, 'RUNTIME_PHASE_INACTIVE_UNEXPECTED_CONTAINER')
    # Never interpret a timeout, permission error or generic exit 1 as absence.
    missing = error.strip() == b'container does not exist' or re.fullmatch(
        rb'time="[^"\r\n]+" level=(?:error|fatal) msg="container does not exist"', error.strip())
    require(result.returncode == 1 and missing, 'INACTIVE_RUNTIME_ABSENCE_UNPROVEN')
    return subprocess.run([config['runtimePath'], *argv], stderr=subprocess.DEVNULL, env=ENV, timeout=10).returncode


@contextmanager
def admission_schedule(registry, timeout=20):
    """Serialize admission/start on the existing sealed registry directory.

    This is a separate scheduling inode, not the guard/lease lock borrowed by
    child processes. Create and peer readiness remain concurrent. No inode is
    created or replaced and no common-lock failure is ignored.
    """
    ancestors(registry/'adapter-schedule'); fd = os.open(registry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o700, 'PRIVATE_REGISTRY_REQUIRED')
        deadline = time.monotonic()+timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); break
            except BlockingIOError:
                require(time.monotonic() < deadline, 'ADMISSION_SCHEDULE_TIMEOUT')
                time.sleep(min(0.05, max(0, deadline-time.monotonic())))
        current = registry.lstat()
        require((current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_gid)
                == (before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid),
                'ADMISSION_REGISTRY_DRIFT')
        yield
    finally: os.close(fd)


def operate(config_path, argv):
    config_path = Path(config_path)
    config, original = load_configuration(config_path)
    verify_files(config)
    operation, cid, options = arguments(argv)
    if cid is None:
        return subprocess.run([config['runtimePath'], *argv], stderr=subprocess.DEVNULL,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=5).returncode
    require(cid in config['candidates'], 'UNSTAGED_DOCKER_CANDIDATE')
    root = Path(options['--root']).resolve()
    state_parent = Path(config['runtimeStateRoot'])
    require(root.is_relative_to(state_parent) and root != state_parent, 'RUNTIME_STATE_ROOT_UNPROVEN')
    selected = select_arming(config, original, cid) if operation == 'create' else None
    directory = Path(config['registryRoot'])/cid
    record_path = directory/'adapter.json'
    # Absence does not provision a journal, candidate directory or lock.
    if not os.path.lexists(record_path):
        return inactive(config, cid, operation, root, argv)
    private_directory(directory)
    lock = directory/'operation.lock'; read(lock)
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        record = parse(read(record_path))
        require(set(record) == {'schema','containerId','configurationHash','state','runtimeRoot','bundleHash','driverHash','armingGeneration'}
                and record['schema'] == 'ouf.semantic-docker-runtime-journal.v1'
                and record['containerId'] == cid)
        if record['state'] == 'STAGED' and operation != 'create':
            return inactive(config, cid, operation, root, argv)
        arming, arming_raw = selected if selected is not None else load_arming(config, original, record['armingGeneration'])
        require(type(record['armingGeneration']) is int and record['armingGeneration'] == arming['generation']
                and record['configurationHash'] == binding_v5(config, cid, arming_raw), 'V5_JOURNAL_BINDING_DRIFT')
        if operation != 'create':
            marker = parse(read(Path(config['armingRoot'])/(str(arming['generation'])+'.'+cid+'.consumed')))
            require(marker == {'generation': arming['generation'], 'armingPayloadSha256': hashlib.sha256(arming_raw).hexdigest()},
                    'CONSUMED_ARMING_BINDING_DRIFT')
        entry = {**config['candidates'][cid], **arming['candidates'][cid]}
        admission_config = entry
        require(hashlib.sha256(read(Path(entry['admissionConfiguration']))).hexdigest()
                == entry['admissionConfigurationHash'], 'CANDIDATE_ADMISSION_CONFIGURATION_DRIFT')
        require(record['runtimeRoot'] in (None, str(root)))
        require(read(config_path) == original, 'ADAPTER_CONFIGURATION_DRIFT')
        shadow = directory/'bundle'; driver = directory/'driver.json'
        python = [config['pythonPath'], '-I', '-B']
        admission = [*python, config['admissionPath'], '--configuration', admission_config['admissionConfiguration'],
                     '--container-id', cid, '--bundle', str(shadow), '--runtime-root', str(root)]
        def broker_phase(mode, state):
            with tempfile.TemporaryFile() as output:
                result = subprocess.run([*admission, '--mode', mode], input=json.dumps(state).encode(),
                    stdout=output, stderr=subprocess.DEVNULL, timeout=20,
                    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
                require(result.returncode == 0, 'TWO_PHASE_BROKER_DENIED')
        def publish(state, **extra):
            nonlocal record
            value = {**record, 'state': state, **extra}; save(record_path, record, value); record = value
        def driver_call(mode):
            require(hashlib.sha256(read(driver)).hexdigest() == record['driverHash'], 'SEALED_ADMISSION_DRIVER_DRIFT')
            return capture([*python, config['driverPath'], '--configuration', str(driver), '--mode', mode])
        def admit(hook_state):
            require(record['state'] == 'PREPARING' and record['driverHash'] is None
                    and hook_state['bundle'] == str(shadow) and hook_state['id'] == cid
                    and hook_state['status'] == 'created' and type(hook_state['pid']) is int
                    and hook_state['pid'] > 1, 'EXCLUSIVE_OCI_ADMISSION_REQUIRED')
            oci = parse(read(shadow/'config.json')); require(digest(oci) == record['bundleHash'])
            raw_state = json.dumps(hook_state).encode()
            with tempfile.TemporaryFile() as output:
                result = subprocess.run([*admission, '--mode', 'prepare'], input=raw_state,
                    stdout=output, stderr=subprocess.DEVNULL, timeout=20,
                    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
                require(result.returncode == 0, 'ADMISSION_PREPARATION_FAILED')
            grant_raw = read(driver); grant = parse(grant_raw)
            expected_drivers = ('ouf.semantic-preexec-driver.v5','ouf.semantic-preexec-driver.v6')
            require(grant['schema'] in expected_drivers, 'EXACT_DURABLE_DRIVER_VERSION_REQUIRED')
            if grant['schema'] == 'ouf.semantic-preexec-driver.v6':
                peer_binding=grant.get('peerBinding',{})
                require(set(peer_binding)=={'declaredPolicy','observations','commandBindings'}
                    and bool(peer_binding['observations'])
                    and digest(peer_binding['declaredPolicy'])==grant['authorityScope']['transportHash'],
                    'SEALED_COHORT_DRIVER_REQUIRED')
            sealed = grant['consumptionBinding']; receipt = parse(read(Path(sealed['journalPath'])))
            require(sealed['binding']['intentHash'] == entry['intentRef']
                    and receipt['configurationHash'] == sealed['binding']['configurationHash']
                        == entry['admissionConfigurationHash']
                    and receipt['state'] == 'READY' and receipt['intentHash'] == entry['intentRef']
                    and receipt['evidenceHash'] == sealed['evidenceHash']
                    and receipt['driverHash'] == hashlib.sha256(grant_raw).hexdigest()
                    and receipt['bundleHash'] == digest(oci)
                    and receipt['approvalHash'] == grant['authorityBinding']['sha256']
                    and receipt['generation']['pid'] == hook_state['pid']
                    and receipt['generation']['namespaceInode'] == grant['profile']['namespaceInode']
                    and all(receipt[k] == sealed['binding'][k] == grant['authorityScope'][k]
                        for k in ('installationRef','entityRef','containerId','transactionId')),
                    'DURABLE_ADMISSION_CUSTODY_DRIFT')
            require(grant['schema'] in ('ouf.semantic-preexec-driver.v2','ouf.semantic-preexec-driver.v3','ouf.semantic-preexec-driver.v4','ouf.semantic-preexec-driver.v5','ouf.semantic-preexec-driver.v6') and grant['profile']['containerId'] == cid
                    and grant['profile']['bundlePath'] == str(shadow) and grant['profile']['bundleHash'] == digest(oci)
                    and grant['profile']['applicationStartAuthorized'] is True
                    and grant['profile']['infrastructureAuthorityComplete'] is True
                    and grant['sourceRoot']+'/scripts/semantic_provider_preexec_hook.py' == config['driverPath']
                    and grant['sourceHashes']['scripts/semantic_provider_preexec_hook.py'] == config['driverSha256']
                    and grant['runtimeBinding'] == {'path':config['runtimePath'],'sha256':config['runtimeSha256'],'root':str(root)})
            publish('PREPARING', driverHash=hashlib.sha256(grant_raw).hexdigest())
            result = subprocess.run([*python, config['driverPath'], '--configuration', str(driver), '--mode', 'hook'],
                input=raw_state, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            require(result.returncode == 0, 'OCI_ADMISSION_GATE_DENIED')
            publish('ADMITTED')
        if operation == 'create':
            require(record['state'] == 'STAGED', 'DO_NOT_REPLAY_RUNTIME_CREATE')
            bundle = Path(options.get('--bundle', options.get('-b'))).resolve()
            require(str(bundle.parent) in entry['bundleParents'] and bundle.name == cid)
            oci = parse(read(bundle/'config.json', private=False))
            rootfs = Path(oci['root']['path'])
            require('..' not in rootfs.parts and str(rootfs) not in ('', '.'), 'ROOTFS_PATH_ESCAPE_DENIED')
            if not rootfs.is_absolute():
                rootfs = (bundle/rootfs).resolve(strict=True)
                require(rootfs.is_relative_to(bundle), 'ROOTFS_PATH_ESCAPE_DENIED')
                oci['root']['path'] = str(rootfs)
            require(not set(oci.get('hooks', {})) - {'prestart','createRuntime'}, 'UNSUPPORTED_DOCKER_HOOK_PHASE')
            networks = [v for v in oci['linux']['namespaces'] if v.get('type') == 'network']
            require(len(networks) == 1 and set(networks[0]) in ({'type'},{'type','path'}), 'DOCKER_NETWORK_NAMESPACE_REQUIRED')
            # Docker commonly spells the root-owned /run alias /var/run. The
            # admission broker still verifies the actual inode and live links.
            if networks[0].get('path'): networks[0]['path'] = str(Path(networks[0]['path']).resolve(strict=True))
            verify_arming(config_path, config, cid, arming['generation'])
            require(read(config_path) == original, 'ADAPTER_CONFIGURATION_DRIFT')
            # Verify the same sealed bytes survived verification, before burning
            # the single-use generation. Failures thereafter never undo it.
            require(load_arming(config, original, arming['generation'])[1] == arming_raw, 'ARMING_PAYLOAD_DRIFT')
            consume_arming(config, cid, arming_raw)
            broker_phase('authorize-create', {'id':cid,'bundleHash':digest(oci)})
            publish('PREPARING', runtimeRoot=str(root), bundleHash=digest(oci))
            shadow.mkdir(mode=0o700)
            target = shadow/'config.json'
            with target.open('xb') as stream:
                os.chmod(target, 0o600); stream.write(json.dumps(oci).encode()); stream.flush(); os.fsync(stream.fileno())
            for parent in (shadow, directory):
                directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(directory_fd)
                finally: os.close(directory_fd)
            publish('CREATING')
            rewritten = list(argv); option = '--bundle' if '--bundle' in options else '-b'
            rewritten[rewritten.index(option)+1] = str(shadow)
            require(read(config_path) == original, 'ADAPTER_CONFIGURATION_DRIFT')
            # Preserve the init process's inherited stderr, which becomes the
            # container's application stderr stream after explicit start.
            result = subprocess.run([config['runtimePath'], *rewritten],
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}, timeout=40)
            require(result.returncode == 0, 'RUNTIME_CREATE_DENIED')
            state = parse(capture([config['runtimePath'], '--root', str(root), 'state', cid]))
            require(state['id'] == cid and state['bundle'] == str(shadow) and state['status'] == 'created',
                    'TWO_PHASE_CREATED_STATE_REQUIRED')
            broker_phase('record-created', state)
            publish('CREATED'); return 0
        require(record['state'] in {'PREPARING','CREATING','ADMITTED','CREATED','STARTING','STARTED','DELETING','DELETED'})
        if operation == 'start':
            require(record['state'] == 'CREATED', 'OWNED_CREATED_RUNTIME_REQUIRED')
            # Docker prepares OCI-created network interfaces after NewTask
            # (runc create) and before Task.Start. Admission must inspect that
            # final live network here, before releasing runc's exec FIFO.
            state = parse(capture([config['runtimePath'], '--root', str(root), 'state', cid]))
            broker_phase('cohort-ready',state)
            with admission_schedule(Path(config['registryRoot'])):
                require(read(config_path) == original, 'ADAPTER_CONFIGURATION_DRIFT')
                state = parse(capture([config['runtimePath'], '--root', str(root), 'state', cid]))
                publish('PREPARING'); admit(state)
                publish('STARTING'); driver_call('start'); publish('STARTED'); return 0
        require(read(config_path) == original, 'ADAPTER_CONFIGURATION_DRIFT')
        if operation == 'delete':
            require(record['state'] != 'DELETED', 'DO_NOT_REPLAY_RUNTIME_DELETE'); publish('DELETING')
        result = subprocess.run([config['runtimePath'], *argv], stderr=subprocess.DEVNULL,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=10)
        if operation == 'delete' and result.returncode == 0:
            # Successful runc delete is followed by the driver's independent
            # dead-generation and owned-handle rollback proof.
            require(record['driverHash'] is not None, 'UNPREPARED_DELETE_REQUIRES_RECOVERY')
            driver_call('rollback'); capture([*admission, '--mode', 'cleanup']); publish('DELETED')
        return result.returncode
    finally: os.close(fd)


def main():
    try:
        os.umask(0o077)
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode)
        require(len(sys.argv) >= 4 and sys.argv[1] == '--configuration')
        return operate(Path(sys.argv[2]), sys.argv[3:])
    except Exception as error:
        reason = str(error) if isinstance(error, Denied) and re.fullmatch('[A-Z0-9_]{1,80}', str(error)) else 'DOCKER_RUNTIME_OPERATION_UNPROVEN'
        # containerd retrieves the standard runc JSON log on failure. Preserve
        # that protocol with a constant redacted message, never raw exceptions.
        try:
            if '--log' in sys.argv:
                path = Path(sys.argv[sys.argv.index('--log')+1]); ancestors(path)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
                try:
                    info = os.fstat(fd)
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                            and not info.st_mode & 0o022 and info.st_size < 131072)
                    value = {'level':'error','msg':'SEMANTIC_DOCKER_RUNTIME_BLOCKED_'+reason,
                             'time':datetime.now(timezone.utc).isoformat()}
                    os.write(fd, (json.dumps(value)+'\n').encode())
                finally: os.close(fd)
        except Exception: pass
        print('SEMANTIC_DOCKER_RUNTIME=BLOCKED REASON='+reason, file=sys.stderr); return 1


if __name__ == '__main__': raise SystemExit(main())
