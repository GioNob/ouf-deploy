"""Governed OCI runtime v5.2: durable authorization and append-only epochs."""
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
import types
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


SCHEMA = 'ouf.semantic-docker-runtime-adapter.v5.2'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
CONFIG_FIELDS = {'schema', 'sourceHash', 'runtimePath', 'runtimeSha256', 'pythonPath', 'pythonSha256',
    'registryRoot', 'runtimeStateRoot', 'opensslBinding', 'candidates', 'admissionPath', 'admissionSha256',
    'admissionConfigurations', 'driverPath', 'driverSha256', 'operation', 'leaseQuiesce', 'limits',
    'authorizationModule', 'epochsModule'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def hashed(value): return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def absolute(value):
    require(type(value) is str and '\x00' not in value, 'EXPLICIT_V52_PATH_REQUIRED')
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts and str(path) == value, 'EXPLICIT_V52_PATH_REQUIRED')
    return path


def file_binding(value):
    require(type(value) is dict and set(value) == {'path', 'sha256'} and hashed(value['sha256']),
            'EXACT_V52_FILE_BINDING_REQUIRED')
    absolute(value['path'])


def private_directory(path):
    ancestors(path/'custody'); info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_V52_DIRECTORY_REQUIRED')


def load_configuration(config_path):
    raw = read(config_path); config = parse(raw)
    require(type(config) is dict and set(config) == CONFIG_FIELDS and config['schema'] == SCHEMA
            and canonical(config) == raw, 'EXACT_RUNTIME_V52_CONFIGURATION_REQUIRED')
    for key in ('sourceHash', 'runtimeSha256', 'pythonSha256', 'admissionSha256', 'driverSha256'):
        require(hashed(config[key]), 'V52_SHA256_REQUIRED')
    for key in ('runtimePath', 'pythonPath', 'admissionPath', 'driverPath', 'registryRoot', 'runtimeStateRoot'):
        absolute(config[key])
    for key in ('authorizationModule', 'epochsModule'): file_binding(config[key])
    ssl = config['opensslBinding']
    require(type(ssl) is dict and set(ssl) == {'path', 'sha256', 'version'}
            and type(ssl['version']) is str and re.fullmatch('[0-9][0-9A-Za-z.+_-]{0,63}', ssl['version']),
            'EXACT_V52_OPENSSL_BINDING_REQUIRED')
    file_binding({k: ssl[k] for k in ('path', 'sha256')})
    op = config['operation']
    require(type(op) is dict and set(op) == {'authorizationRoot', 'anchorBinding', 'mandateRoot', 'mandatesModule',
            'installationRef', 'entityRef', 'issuerRef'}, 'EXACT_V52_OPERATION_REQUIRED')
    for key in ('authorizationRoot', 'mandateRoot'): absolute(op[key])
    for key in ('anchorBinding', 'mandatesModule'): file_binding(op[key])
    for key in ('installationRef', 'entityRef', 'issuerRef'):
        require(type(op[key]) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', op[key]),
                'V52_OPERATION_IDENTITY_REQUIRED')
    candidates = config['candidates']
    require(type(candidates) is dict and len(candidates) == 2 and all(hashed(cid) for cid in candidates),
            'EXACT_V52_CANDIDATES_REQUIRED')
    for entry in candidates.values():
        require(type(entry) is dict and set(entry) == {'role', 'bundleParents'}
                and entry['role'] in ('adapter', 'southbound') and type(entry['bundleParents']) is list
                and 1 <= len(entry['bundleParents']) <= 4, 'EXACT_V52_CANDIDATE_REQUIRED')
        for parent in entry['bundleParents']: absolute(parent)
    require({v['role'] for v in candidates.values()} == {'adapter', 'southbound'}, 'EXACT_V52_ROLES_REQUIRED')
    admissions = config['admissionConfigurations']
    require(type(admissions) is dict and set(admissions) == set(candidates), 'EXACT_V52_ADMISSIONS_REQUIRED')
    for bound in admissions.values(): file_binding(bound)
    q = config['leaseQuiesce']
    require(type(q) is dict and set(q) == {'entrypoint', 'configuration'}, 'EXACT_V52_QUIESCE_REQUIRED')
    for bound in q.values(): file_binding(bound)
    limits = config['limits']
    require(type(limits) is dict and set(limits) == {'maxEpochsPerHour'}
            and type(limits['maxEpochsPerHour']) is int and limits['maxEpochsPerHour'] == 6,
            'EXACT_V52_LIMITS_REQUIRED')
    return config, raw


def bound_bytes(binding):
    raw = read(Path(binding['path']))
    require(sha(raw) == binding['sha256'], 'V52_BOUND_FILE_DRIFT')
    return raw


def compiled(raw, path, name):
    module = types.ModuleType(name); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def verify_files(config):
    require(sha(read(Path(__file__))) == config['sourceHash'], 'ADAPTER_SOURCE_DRIFT')
    for prefix in ('runtime', 'python'): executable(config[prefix+'Path'], config[prefix+'Sha256'])
    for prefix in ('driver', 'admission'):
        bound_bytes({'path': config[prefix+'Path'], 'sha256': config[prefix+'Sha256']})
    for key in ('authorizationModule', 'epochsModule'): bound_bytes(config[key])
    for bound in config['admissionConfigurations'].values(): bound_bytes(bound)
    for bound in config['leaseQuiesce'].values(): bound_bytes(bound)
    for key in ('anchorBinding', 'mandatesModule'): bound_bytes(config['operation'][key])
    executable(config['opensslBinding']['path'], config['opensslBinding']['sha256'])


def operation_modules(config):
    # epochs has a historical top-level import. Temporarily resolve it only to
    # the module compiled from the verified bytes, never through sys.path.
    auth_raw = bound_bytes(config['authorizationModule']); epoch_raw = bound_bytes(config['epochsModule'])
    auth = compiled(auth_raw, config['authorizationModule']['path'], 'runtime_v52_authorization')
    previous = sys.modules.get('authorization')
    sys.modules['authorization'] = auth
    try:
        epochs = compiled(epoch_raw, config['epochsModule']['path'], 'runtime_v52_epochs')
    finally:
        if previous is None: sys.modules.pop('authorization', None)
        else: sys.modules['authorization'] = previous
    return auth, epochs


def authorization_head(config, raw, cid, auth):
    op = config['operation']; bound = op['mandatesModule']
    mandates = compiled(bound_bytes(bound), bound['path'], 'runtime_v52_mandates')
    head = auth.head(mandates, op['anchorBinding'], op['mandateRoot'], config['opensslBinding'],
        op['authorizationRoot'], op['installationRef'], op['entityRef'], op['issuerRef'], time.time)
    require(head['decision'] == 'OPERATE', 'OPERATION_NOT_OPERATE')
    require(head['authorization']['runtimeConfigurationSha256'] == sha(raw), 'OPERATION_RUNTIME_CONFIGURATION_DRIFT')
    role = head['authorization']['roles'][config['candidates'][cid]['role']]
    require(role['containerId'] == cid and role['admissionConfigurationSha256']
            == config['admissionConfigurations'][cid]['sha256'], 'OPERATION_ADMISSION_CONFIGURATION_DRIFT')
    return head


def driver_validator(config, cid):
    # Reuse the pinned broker bootstrap to collect ALL of its stable closure
    # before executing any application byte, including driver_v7.validate.
    raw = bound_bytes({'path': config['admissionPath'], 'sha256': config['admissionSha256']})
    bootstrap = compiled(raw, config['admissionPath'], 'runtime_v52_admission_bootstrap')
    stable = config['admissionConfigurations'][cid]
    cfg = parse(bound_bytes(stable))
    for key, relative in (('authorizationModule', 'authorization'), ('epochsModule', 'epochs')):
        source = 'tools/semantic_provider_operation/'+relative+'.py'
        require(config[key] == {'path': str(Path(cfg['sourceRoot'])/source), 'sha256': cfg['sourceHashes'][source]},
                'V52_OPERATION_SOURCE_CLOSURE_DRIFT')
    require(str(Path(cfg['sourceRoot'])/'scripts/semantic-provider-preexec-hook-v2.py') == config['driverPath']
            and cfg['sourceHashes']['scripts/semantic-provider-preexec-hook-v2.py'] == config['driverSha256'],
            'V52_DRIVER_SOURCE_CLOSURE_DRIFT')
    root, verified = bootstrap.load_sources(stable['path'])
    broker = bootstrap.execute(root, verified)
    broker.validate(bound_bytes(stable))
    bound_bytes(stable)
    return sys.modules['tools.semantic_provider_admission_v2.driver_v7'], cfg


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally: os.close(fd)
    sync_directory(path.parent)


def pointer_bytes(base):
    return read(base/'current') if os.path.lexists(base/'current') else None


def replace_cas(path, old, raw):
    def unchanged():
        actual = read(path) if os.path.lexists(path) else None
        require(actual == old, 'EPOCH_CAS_DRIFT')
    unchanged()
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.epoch-', delete=False) as stream:
        temp = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        except BaseException:
            temp.unlink(); raise
    try:
        unchanged(); os.replace(temp, path); sync_directory(path.parent)
    finally:
        if temp.exists(): temp.unlink()


def publish_epoch(base, old, value, epochs):
    """CAS both files under operation.lock. A torn pair fails closed on read."""
    raw = canonical(value); epochs.validate_journal(raw, value['containerId'], value['epoch'])
    path = base/'epochs'/str(value['epoch'])/'adapter.json'
    old_raw = read(path)
    require(parse(old_raw) == old, 'EPOCH_CAS_DRIFT')
    pointer = pointer_bytes(base)
    require(pointer == canonical({'epoch': old['epoch'], 'journalSha256': sha(old_raw)}), 'EPOCH_CAS_DRIFT')
    require(epochs.current(base.parent, value['containerId']) == old, 'EPOCH_CAS_DRIFT')
    replace_cas(path, old_raw, raw)
    replace_cas(base/'current', pointer, canonical({'epoch': value['epoch'], 'journalSha256': sha(raw)}))


def epoch_inventory(base, epochs, current):
    folder = base/'epochs'; private_directory(folder)
    values = []
    for path in folder.iterdir():
        require(re.fullmatch('[1-9][0-9]{0,9}', path.name) and int(path.name) <= epochs.MAX_EPOCH,
                'EPOCH_INVENTORY_DRIFT')
        private_directory(path)
        value = epochs.validate_journal(read(path/'adapter.json'), base.name, int(path.name))
        values.append(value)
    numbers = sorted(v['epoch'] for v in values)
    require(len(numbers) == (current['epoch'] if current else 0)
            and all(number == index for index, number in enumerate(numbers, 1)), 'EPOCH_INVENTORY_DRIFT')
    return values


def quiesce(config):
    q = config['leaseQuiesce']
    try:
        verify_files(config)
        try:
            capture([config['pythonPath'], '-I', '-B', q['entrypoint']['path'], '--configuration',
                     q['configuration']['path'], '--configuration-sha256', q['configuration']['sha256'], '--quiesce-only'])
        finally:
            verify_files(config)
    except Exception:
        raise Denied('LEASE_QUIESCENCE_UNPROVEN') from None


def public(error):
    code = str(error)
    return code if isinstance(error, RuntimeError) and re.fullmatch('[A-Z0-9_]{1,80}', code) else 'DOCKER_RUNTIME_OPERATION_UNPROVEN'


def operate(config_path, argv):
    config_path = Path(config_path); config, original = load_configuration(config_path); verify_files(config)
    operation, cid, options = arguments(argv)
    if cid is None:
        return subprocess.run([config['runtimePath'], *argv], stderr=subprocess.DEVNULL, env=ENV, timeout=5).returncode
    require(cid in config['candidates'], 'UNSTAGED_DOCKER_CANDIDATE')
    root = Path(options['--root']).resolve(); parent = Path(config['runtimeStateRoot'])
    require(root.is_relative_to(parent) and root != parent, 'RUNTIME_STATE_ROOT_UNPROVEN')
    base = Path(config['registryRoot'])/cid
    if not os.path.lexists(base): return inactive(config, cid, operation, root, argv)
    private_directory(base); lock = base/'operation.lock'; read(lock)
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Check the opened inode is the sealed, still-linked lock we inspected.
        before = os.fstat(fd); current_lock = lock.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                and all(getattr(before, k) == getattr(current_lock, k) for k in
                ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')), 'OPERATION_LOCK_DRIFT')
        auth, epochs = operation_modules(config)
        record = epochs.current(config['registryRoot'], cid)
        boot = epochs.boot_id()
        if operation in ('state', 'delete') and (record is None or record['state'] in epochs.TERMINAL):
            return inactive(config, cid, operation, root, argv)
        owned = False
        try:
            head = None
            if operation == 'create':
                head = authorization_head(config, original, cid, auth)
                if record and record['state'] not in epochs.TERMINAL:
                    require(record['bootId'] != boot, 'EPOCH_STILL_OPEN')
                    require(record['runtimeRoot'] in (None, str(root)), 'EPOCH_RUNTIME_ROOT_DRIFT')
                    # Old-boot abandonment never performs rollback. Prove that
                    # runc has lost the old /run state before retiring it.
                    inactive(config, cid, 'state', root, ['--root', str(root), 'state', cid])
                    value = {**record, 'state': 'ABANDONED'}
                    publish_epoch(base, record, value, epochs); record = value
                history = epoch_inventory(base, epochs, record)
                now = int(time.time())
                require(sum(v['openedAt'] > now-3600 for v in history) < config['limits']['maxEpochsPerHour'],
                        'EPOCH_RATE_EXCEEDED')
                number = (record['epoch'] if record else 0)+1
                require(number <= epochs.MAX_EPOCH, 'EPOCH_NUMBER_EXHAUSTED')
                quiesce(config)
                require(read(config_path) == original, 'ADAPTER_CONFIGURATION_DRIFT')
                # Revocation/replacement during the child revocation is denied
                # before any epoch is opened.
                require(authorization_head(config, original, cid, auth) == head, 'OPERATION_HEAD_CHANGED')
                require(epochs.current(config['registryRoot'], cid) == record, 'EPOCH_CAS_DRIFT')
                opened_at = int(time.time())
                require(opened_at >= now, 'EPOCH_CLOCK_REGRESSION')
                pointer = pointer_bytes(base)
                folder = base/'epochs'/str(number); folder.mkdir(mode=0o700); private_directory(folder)
                sync_directory(folder.parent)
                record = {'schema': epochs.JOURNAL_SCHEMA, 'containerId': cid, 'epoch': number, 'bootId': boot,
                    'authorizationSha256': head['sha256'], 'configurationHash': sha(original), 'state': 'OPENING',
                    'runtimeRoot': None, 'bundleHash': None, 'driverHash': None, 'generation': None,
                    'openedAt': opened_at, 'failure': None}
                raw = canonical(record); epochs.validate_journal(raw, cid, number)
                exclusive(folder/'adapter.json', raw)
                owned = True
                replace_cas(base/'current', pointer, canonical({'epoch': number, 'journalSha256': sha(raw)}))
            else:
                require(record is not None and record['state'] not in epochs.TERMINAL, 'RUNTIME_PHASE_INACTIVE')
                require(record['bootId'] == boot, 'EPOCH_BOOT_DRIFT')
                require(record['configurationHash'] == sha(original), 'EPOCH_CONFIGURATION_DRIFT')
                require(record['runtimeRoot'] in (None, str(root)), 'EPOCH_RUNTIME_ROOT_DRIFT')
                if operation == 'start':
                    require(record['state'] == 'CREATED', 'OWNED_CREATED_RUNTIME_REQUIRED')
                    owned = True
                    head = authorization_head(config, original, cid, auth)
                    require(record['authorizationSha256'] == head['sha256'], 'EPOCH_AUTHORIZATION_DRIFT')
                elif operation in ('delete', 'state', 'kill'): owned = True
            folder = base/'epochs'/str(record['epoch']); shadow = folder/'bundle'; driver = folder/'driver.json'
            python = [config['pythonPath'], '-I', '-B']; entry = config['candidates'][cid]
            stable = config['admissionConfigurations'][cid]
            admission = [*python, config['admissionPath'], '--configuration', stable['path'], '--container-id', cid,
                '--bundle', str(shadow), '--runtime-root', str(root), '--epoch', str(record['epoch'])]

            def stable_files():
                require(read(config_path) == original, 'ADAPTER_CONFIGURATION_DRIFT'); verify_files(config)

            def broker_phase(mode, state=None):
                stable_files()
                with tempfile.TemporaryFile() as output:
                    result = subprocess.run([*admission, '--mode', mode],
                        **({'stdin': subprocess.DEVNULL} if state is None else {'input': canonical(state)}),
                        stdout=output, stderr=subprocess.DEVNULL, timeout=20, env=ENV)
                require(result.returncode == 0, 'TWO_PHASE_BROKER_DENIED'); stable_files()

            def publish(state, **extra):
                nonlocal record
                value = {**record, 'state': state, **extra}
                publish_epoch(base, record, value, epochs); record = value

            def driver_call(mode, state=None):
                stable_files()
                require(sha(read(driver)) == record['driverHash'], 'SEALED_ADMISSION_DRIVER_DRIFT')
                args = [*python, config['driverPath'], '--configuration', str(driver), '--mode', mode]
                if state is None: capture(args)
                else:
                    result = subprocess.run(args, input=canonical(state), stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=10, env=ENV)
                    require(result.returncode == 0, 'OCI_ADMISSION_GATE_DENIED')
                stable_files()
                require(sha(read(driver)) == record['driverHash'], 'SEALED_ADMISSION_DRIVER_DRIFT')

            if operation == 'create':
                bundle = Path(options.get('--bundle', options.get('-b'))).resolve()
                require(str(bundle.parent) in entry['bundleParents'] and bundle.name == cid, 'OCI_BUNDLE_PARENT_DRIFT')
                oci = parse(read(bundle/'config.json', private=False))
                rootfs = Path(oci['root']['path'])
                require('..' not in rootfs.parts and str(rootfs) not in ('', '.'), 'ROOTFS_PATH_ESCAPE_DENIED')
                if not rootfs.is_absolute():
                    rootfs = (bundle/rootfs).resolve(strict=True)
                    require(rootfs.is_relative_to(bundle), 'ROOTFS_PATH_ESCAPE_DENIED'); oci['root']['path'] = str(rootfs)
                require(not set(oci.get('hooks', {}))-{'prestart', 'createRuntime'}, 'UNSUPPORTED_DOCKER_HOOK_PHASE')
                networks = [v for v in oci['linux']['namespaces'] if v.get('type') == 'network']
                require(len(networks) == 1 and set(networks[0]) in ({'type'}, {'type', 'path'}),
                        'DOCKER_NETWORK_NAMESPACE_REQUIRED')
                if networks[0].get('path'): networks[0]['path'] = str(Path(networks[0]['path']).resolve(strict=True))
                broker_phase('authorize-create', {'id': cid, 'bundleHash': digest(oci)})
                publish('PREPARING', runtimeRoot=str(root), bundleHash=digest(oci))
                shadow.mkdir(mode=0o700); exclusive(shadow/'config.json', canonical(oci)); sync_directory(folder)
                publish('CREATING'); rewritten = list(argv); option = '--bundle' if '--bundle' in options else '-b'
                rewritten[rewritten.index(option)+1] = str(shadow); stable_files()
                result = subprocess.run([config['runtimePath'], *rewritten], env=ENV, timeout=40)
                require(result.returncode == 0, 'RUNTIME_CREATE_DENIED'); stable_files()
                state = parse(capture([config['runtimePath'], '--root', str(root), 'state', cid]))
                require(state['id'] == cid and state['bundle'] == str(shadow) and state['status'] == 'created',
                        'TWO_PHASE_CREATED_STATE_REQUIRED')
                broker_phase('record-created', state); publish('CREATED'); return 0
            if operation == 'start':
                state = parse(capture([config['runtimePath'], '--root', str(root), 'state', cid]))
                broker_phase('cohort-ready', state)
                with admission_schedule(Path(config['registryRoot'])):
                    stable_files(); state = parse(capture([config['runtimePath'], '--root', str(root), 'state', cid]))
                    require(state['bundle'] == str(shadow) and state['id'] == cid and state['status'] == 'created'
                            and type(state['pid']) is int and state['pid'] > 1, 'EXCLUSIVE_OCI_ADMISSION_REQUIRED')
                    publish('PREPARING'); oci = parse(read(shadow/'config.json'))
                    require(digest(oci) == record['bundleHash'], 'OCI_SHADOW_BUNDLE_DRIFT')
                    broker_phase('prepare', state)
                    grant_raw = read(driver); validator, broker_cfg = driver_validator(config, cid)
                    grant = validator.validate(grant_raw)
                    require(grant['operationBinding'] == {'authorizationSha256': record['authorizationSha256'],
                        'epoch': record['epoch'], 'containerId': cid, 'configurationHash': stable['sha256']},
                        'DRIVER_OPERATION_BINDING_DRIFT')
                    require(grant['operation'] == {**config['operation'], 'opensslBinding': config['opensslBinding']}
                            and grant['sourceRoot'] == broker_cfg['sourceRoot']
                            and grant['sourceHashes'] == broker_cfg['sourceHashes'], 'DRIVER_SOURCE_OR_OPERATION_DRIFT')
                    require(grant['profile']['bundlePath'] == str(shadow) and grant['profile']['containerId'] == cid
                            and grant['profile']['bundleHash'] == digest(oci)
                            and grant['runtimeBinding'] == {'path': config['runtimePath'], 'sha256': config['runtimeSha256'],
                                                          'root': str(root)}, 'DRIVER_OCI_BINDING_DRIFT')
                    publish('PREPARING', driverHash=sha(grant_raw)); driver_call('hook', state)
                    publish('ADMITTED'); publish('STARTING'); driver_call('start')
                    started = parse(capture([config['runtimePath'], '--root', str(root), 'state', cid]))
                    require(started['id'] == cid and started['bundle'] == str(shadow) and started['status'] == 'running'
                            and started['pid'] == state['pid'], 'STARTED_PROCESS_GENERATION_UNPROVEN')
                    ticks = epochs.start_ticks(started['pid'])
                    require(type(ticks) is int and ticks > 0, 'STARTED_PROCESS_GENERATION_UNPROVEN')
                    publish('STARTED', generation={'pid': started['pid'], 'startTicks': ticks}); return 0
            stable_files()
            if operation == 'delete': publish('DELETING')
            result = subprocess.run([config['runtimePath'], *argv], stderr=subprocess.DEVNULL, env=ENV, timeout=10)
            if operation == 'delete':
                require(result.returncode == 0, 'RUNTIME_DELETE_DENIED')
                quiesce(config)
                require(record['driverHash'] is not None, 'UNPREPARED_DELETE_REQUIRES_RECOVERY')
                driver_call('rollback'); broker_phase('cleanup'); publish('DELETED')
            else:
                require(result.returncode == 0, 'RUNTIME_STATE_DENIED' if operation == 'state' else 'RUNTIME_KILL_DENIED')
            return result.returncode
        except Exception as error:
            code = public(error)
            if owned:
                try: publish_epoch(base, record, {**record, 'state': 'FAILED', 'failure': code}, epochs)
                except Exception: pass
            raise Denied(code) from None
    finally: os.close(fd)


def main():
    try:
        os.umask(0o077)
        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.dont_write_bytecode)
        require(len(sys.argv) >= 4 and sys.argv[1] == '--configuration')
        return operate(Path(sys.argv[2]), sys.argv[3:])
    except Exception as error:
        reason = public(error)
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
