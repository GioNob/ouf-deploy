"""One bounded private preparation for the actual postboot recovery path.

Reads exact retained metadata and exact current resources. It publishes new
private inputs/source copies only: no authority, grants, services or old journal
changes. A retained preparation directory is a consumed attempt, never retried.
"""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import time
from urllib.parse import urlsplit
import uuid

from .core import require, digest, encoded, hashed, validate_plan
from .caller_configuration import configuration, verify as verify_configuration
from tools.semantic_registry_postboot_owner import contract as owner_contract
from tools.semantic_live_route_diagnostic import reader as transport

SCHEMA = 'ouf.semantic-registry-postboot-preparation-case.v1'
PARENT = '/etc/ouf/deploy-snapshots'
MAX_SECONDS = 90
MAX_BYTES = 167772160
FROZEN_PATH = '/api/internal/v1/onboarding/ingestion-configuration'


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'DUPLICATE_POSTBOOT_PREPARATION_JSON_KEY')
        value[key] = item
    return value


def decode(raw):
    def invalid(_):
        require(False, 'NONFINITE_POSTBOOT_PREPARATION_JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def exact_path(value):
    require(type(value) is str and len(value) <= 4096 and value.startswith('/')
            and str(PurePosixPath(value)) == value and '..' not in PurePosixPath(value).parts,
            'EXACT_PREPARATION_PATH_REQUIRED')
    return Path(value)


def metadata(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def directory_identity(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode]


class Files:
    def __init__(self):
        self.bytes = 0
        self.reads = 0
        self.observed = {}
        self.deadline = time.monotonic() + MAX_SECONDS

    def check(self):
        require(time.monotonic() < self.deadline, 'POSTBOOT_PREPARATION_DEADLINE')

    @contextmanager
    def held_parent(self, path):
        self.check(); path = exact_path(path)
        fds, ancestry = [], []
        try:
            parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); fds.append(parent)
            parts = path.parts[1:]
            require(parts, 'PREPARATION_FILE_PATH_REQUIRED')
            info = os.fstat(parent)
            require(info.st_uid == 0 and not info.st_mode & 0o022, 'PROTECTED_PREPARATION_ROOT_REQUIRED')
            ancestry.append({'path': '/', 'identity': directory_identity(info)})
            names = []
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                fds.append(child); info = os.fstat(child)
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                        'PROTECTED_PREPARATION_ANCESTRY_REQUIRED')
                names.append((parent, part, child, directory_identity(info)))
                ancestry.append({'path': str(Path(ancestry[-1]['path']) / part), 'identity': directory_identity(info)})
                parent = child
            yield parent, parts[-1], ancestry
            require(directory_identity(os.fstat(fds[0])) == ancestry[0]['identity']
                    == directory_identity(os.stat('/', follow_symlinks=False)), 'PREPARATION_ROOT_CHANGED')
            for upper, name, child, pin in names:
                require(directory_identity(os.fstat(child)) == pin
                        == directory_identity(os.stat(name, dir_fd=upper, follow_symlinks=False)),
                        'PREPARATION_ANCESTRY_CHANGED')
        finally:
            for fd in reversed(fds):
                os.close(fd)

    @contextmanager
    def held(self, path):
        with self.held_parent(path) as (parent, name, ancestry):
            leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(leaf)
                require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
                        and before.st_nlink == 1, 'PROTECTED_PREPARATION_FILE_REQUIRED')
                yield leaf, before, ancestry
                require(metadata(before) == metadata(os.fstat(leaf))
                        == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'PREPARATION_FILE_CHANGED')
            finally:
                os.close(leaf)

    def seal(self, path, maximum, expected=None, retain=True):
        with self.held(path) as (fd, info, ancestry):
            require(0 < info.st_size <= maximum and self.reads < 128, 'BOUNDED_PREPARATION_FILE_REQUIRED')
            self.reads += 1; raw = bytearray()
            while len(raw) <= info.st_size:
                self.check(); chunk = os.read(fd, min(65536, info.st_size + 1 - len(raw)))
                if not chunk: break
                raw.extend(chunk)
            self.bytes += len(raw)
            require(len(raw) == info.st_size and self.bytes <= MAX_BYTES, 'PREPARATION_FILE_BYTE_BUDGET')
            sha = hashlib.sha256(raw).hexdigest()
            require(expected is None or sha == expected, 'RETAINED_PREPARATION_HASH_CHANGED')
            profile = {'path': path, 'sha256': sha, 'metadata': metadata(info), 'ancestors': ancestry}
        if retain:
            previous = self.observed.get(path)
            require(previous is None or previous == (profile, maximum), 'PREPARATION_PIN_CHANGED')
            self.observed[path] = (profile, maximum)
        return profile, bytes(raw)

    def json(self, path, expected=None, maximum=8388608):
        profile, raw = self.seal(path, maximum, expected)
        value = decode(raw)
        require(type(value) is dict and encoded(value) == raw, 'CANONICAL_PRIVATE_PREPARATION_JSON_REQUIRED')
        return value, profile

    def stat_private(self, path):
        # Credential custody only; never open or hash credential bytes here.
        with self.held_parent(path) as (parent, name, _):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077
                    and info.st_nlink == 1 and 0 < info.st_size <= 16384,
                    'PRIVATE_EXISTING_CREDENTIAL_CUSTODY_REQUIRED')
            result = metadata(info)
        return result

    def verify(self):
        for path, (profile, maximum) in list(self.observed.items()):
            again, _ = self.seal(path, maximum, profile['sha256'], retain=False)
            require(again == profile, 'PREPARATION_INPUT_CHANGED_DURING_CAPTURE')


def publish(root, name, value):
    require(re.fullmatch('[A-Za-z0-9_.-]{1,160}', name) is not None, 'CLOSED_PREPARATION_ARTIFACT_NAME')
    raw = value if type(value) is bytes else encoded(value)
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        remaining = memoryview(raw)
        while remaining:
            count = os.write(fd, remaining); require(count > 0, 'PREPARATION_ARTIFACT_WRITE_FAILED')
            remaining = remaining[count:]
        os.fsync(fd)
    finally: os.close(fd)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(directory)
    finally: os.close(directory)


def current_pin(actual):
    from tools.ingestion_readiness_patch_execution import runtime_bindings
    require(actual['State']['Running'] is True and actual['State']['Paused'] is False
            and actual['State']['Restarting'] is False and actual['State']['Pid'] > 1,
            'CURRENT_RUNNING_PREPARATION_SERVICE_REQUIRED')
    return {'binding': runtime_bindings.observed(actual, runtime_bindings.SORTED),
            'bindingProfile': runtime_bindings.SORTED, 'restartCount': actual['RestartCount']}


def environment(actual):
    values = {}
    for item in actual['Config']['Env']:
        name, sep, value = item.partition('=')
        require(sep and name not in values, 'UNIQUE_PREPARATION_ENV_REQUIRED')
        values[name] = value
    return values


def mounted_source(actual, target):
    target_path = PurePosixPath(str(exact_path(target)))
    matches = [m for m in actual['Mounts'] if target_path == PurePosixPath(m['Destination'])
               or target_path.is_relative_to(PurePosixPath(m['Destination']))]
    require(len(matches) == 1 and matches[0]['Type'] == 'bind' and matches[0]['RW'] is False,
            'ONE_READONLY_ORIGINAL_SERVICE_TOKEN_BIND_REQUIRED')
    row = matches[0]
    return str(exact_path(row['Source']) / target_path.relative_to(PurePosixPath(row['Destination'])))


def frozen_query(reference):
    require(type(reference) is dict and set(reference) == {'sourceId', 'onboardingVersionId', 'configurationHash'}
            and type(reference['sourceId']) is str and re.fullmatch('[A-Za-z0-9._:-]{1,128}', reference['sourceId'])
            and str(uuid.UUID(reference['onboardingVersionId'])) == reference['onboardingVersionId']
            and reference['configurationHash'].startswith('sha256:')
            and hashed(reference['configurationHash'][7:]), 'EXACT_ORIGINAL_FROZEN_REFERENCE_REQUIRED')
    return copy.deepcopy(reference)


# Separate read-only endpoint, the exact FrozenConfiguration client operation.
# No semantic query, activation, compatibility POST or renewal is performed.
FROZEN_CHILD_SOURCE = r'''import hashlib,http.client,ipaddress,json,os,re,signal,ssl,sys,uuid
from urllib.parse import urlsplit,urlencode
signal.alarm(9)
try:
    raw=sys.stdin.buffer.read(262145)
    if not 0<len(raw)<=262144:raise ValueError()
    v=json.loads(raw)
    if set(v)!={'origin','token','reference','ca','peerCertificateSha256'}:raise ValueError()
    u=urlsplit(v['origin']);r=v['reference'];token=v['token']
    if u.scheme not in ('http','https') or not u.hostname or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:raise ValueError()
    if set(r)!={'sourceId','onboardingVersionId','configurationHash'}:raise ValueError()
    if not re.fullmatch('[A-Za-z0-9._:-]{1,128}',r['sourceId']) or str(uuid.UUID(r['onboardingVersionId']))!=r['onboardingVersionId'] or not re.fullmatch('sha256:[a-f0-9]{64}',r['configurationHash']):raise ValueError()
    if type(token)is not str or not 0<len(token)<=16384 or any(c.isspace()for c in token):raise ValueError()
    if len(sys.argv)!=2 or not sys.argv[1].isdigit():raise ValueError()
    fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
    if u.scheme=='https':
        client=http.client.HTTPSConnection(u.hostname,u.port or 443,context=ssl.create_default_context(cadata=v['ca']),timeout=4)
    else:
        if not ipaddress.ip_address(u.hostname).is_private or v['ca']is not None or v['peerCertificateSha256']is not None:raise ValueError()
        client=http.client.HTTPConnection(u.hostname,u.port or 80,timeout=4)
    client.connect()
    if u.scheme=='https'and hashlib.sha256(client.sock.getpeercert(binary_form=True)).hexdigest()!=v['peerCertificateSha256']:raise ValueError()
    client.request('GET','/api/internal/v1/onboarding/ingestion-configuration?'+urlencode(r),headers={'Authorization':'Bearer '+token,'Accept':'application/json','X-Correlation-ID':str(uuid.uuid4()),'Connection':'close'})
    response=client.getresponse();body=response.read(2097153)
    if response.status!=200 or len(body)>2097152:raise ValueError()
    def unique(pairs):
        result={}
        for k,val in pairs:
            if k in result:raise ValueError()
            result[k]=val
        return result
    result=json.loads(body,object_pairs_hook=unique)
    if type(result)is not dict:raise ValueError()
    output=json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
    if len(output)>2097152:raise ValueError()
    sys.stdout.buffer.write(output);sys.stdout.buffer.flush();client.close()
except BaseException:os._exit(1)
os._exit(0)
'''


def read_frozen(profile, caller, reference):
    from tools.ingestion_readiness_patch_execution import private_file
    pid = caller['State']['Pid']; fds = []; child = None
    ticks = transport.process_ticks(pid)
    identity = lambda s: (s.st_dev, s.st_ino)
    with private_file.opened(profile['tokenSource'], maximum=16384) as host:
        try:
            current = os.open('/proc/' + str(pid) + '/root', os.O_PATH | os.O_DIRECTORY); fds.append(current)
            root_fd = current; root_identity = identity(os.fstat(root_fd))
            parts = PurePosixPath(profile['tokenTarget']).parts[1:]
            mounted_parents = []
            for part in parts[:-1]:
                parent = current
                current = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent); fds.append(current)
                mounted_parents.append((parent, part, current, identity(os.fstat(current))))
            mounted = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current); fds.append(mounted)
            def same_token():
                require(metadata(os.fstat(mounted)) == metadata(os.fstat(host))
                        == metadata(os.stat(parts[-1], dir_fd=current, follow_symlinks=False))
                        == profile['tokenSource']['metadata'], 'ORIGINAL_MOUNTED_SERVICE_TOKEN_CHANGED')
                for parent, name, held, expected in mounted_parents:
                    require(identity(os.fstat(held)) == expected
                            == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                            'ORIGINAL_MOUNTED_SERVICE_TOKEN_ANCESTRY_CHANGED')
            same_token()
            token = os.read(mounted, 16385).decode('ascii').strip()
            require(token and len(token) <= 16384 and not any(c.isspace() for c in token), 'BOUNDED_SERVICE_TOKEN_REQUIRED')
            ca = None if profile['ca'] is None else private_file.read(profile['ca']).decode('ascii')
            ns = '/proc/' + str(pid) + '/ns/net'
            fd = os.open(ns, os.O_RDONLY | os.O_CLOEXEC); fds.append(fd)
            namespace_identity = identity(os.fstat(fd))
            payload = encoded({'origin': profile['origin'], 'token': token, 'reference': reference,
                               'ca': ca, 'peerCertificateSha256': profile['peerCertificateSha256']})
            require(len(payload) <= 262144, 'BOUNDED_PRIVATE_FROZEN_REQUEST_REQUIRED')
            transport.verify_program(profile['pythonExecutable'])
            same_token()
            require(transport.process_ticks(pid) == ticks
                    and identity(os.stat(ns)) == namespace_identity
                    and identity(os.stat('/proc/' + str(pid) + '/root')) == root_identity,
                    'FROZEN_REQUEST_CALLER_CHANGED_BEFORE_GET')
            child = subprocess.Popen([profile['pythonExecutable']['path'], '-I', '-B', '-S', '-c', FROZEN_CHILD_SOURCE, str(fd)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                pass_fds=(fd,), close_fds=True, cwd='/', env={'LC_ALL': 'C'})
            raw, _ = child.communicate(payload, timeout=12)
            require(child.returncode == 0 and 0 < len(raw) <= 2097152, 'CURRENT_FROZEN_CONFIGURATION_GET_UNCONFIRMED')
            same_token()
            require(transport.process_ticks(pid) == ticks
                    and identity(os.fstat(fd)) == namespace_identity == identity(os.stat(ns))
                    and identity(os.fstat(root_fd)) == root_identity
                        == identity(os.stat('/proc/' + str(pid) + '/root')), 'FROZEN_REQUEST_CALLER_CHANGED')
            transport.verify_program(profile['pythonExecutable'])
            same_token()
            return decode(raw)
        finally:
            if child is not None:
                if child.poll() is None: child.kill()
                child.wait(timeout=5)
                for stream in (child.stdin, child.stdout):
                    if stream is not None: stream.close()
            for fd in reversed(fds): os.close(fd)


def frozen_configuration(value, reference):
    require(type(value) is dict and value.get('sourceId') == reference['sourceId']
            and value.get('onboardingVersionId') == reference['onboardingVersionId']
            and value.get('configurationHash') == reference['configurationHash']
            and value.get('state') in ('IN_REVIEW', 'APPROVED') and type(value.get('configuration')) is dict,
            'SAME_FROZEN_CONFIGURATION_REQUIRED')
    configuration = value['configuration']
    calculated = 'sha256:' + hashlib.sha256(json.dumps(configuration, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    require(calculated == reference['configurationHash'], 'FROZEN_CONFIGURATION_CHECKSUM_CHANGED')
    bindings = configuration.get('semanticReferenceBindings')
    require(type(bindings) is list and 1 <= len(bindings) <= 32, 'EXACT_BOUNDED_SEMANTIC_BINDINGS_REQUIRED')
    seen = set()
    for item in bindings:
        require(type(item) is dict and set(item) == {'semanticId', 'semanticVersion', 'revisionId', 'publicationSetId'}
                and all(type(v) is str and 0 < len(v) <= 2048 and not any(ord(c) < 32 for c in v) for v in item.values())
                and all(str(uuid.UUID(item[k])) == item[k] for k in ('revisionId', 'publicationSetId')),
                'EXACT_FROZEN_SEMANTIC_REFERENCE_FIELDS_REQUIRED')
        key = item['semanticId'] + '@' + item['semanticVersion']
        require(key not in seen, 'DISTINCT_FROZEN_SEMANTIC_REFERENCES_REQUIRED'); seen.add(key)
    mapped = configuration.get('semanticMapping', {}).get('semanticRefs')
    require(type(mapped) is list and len(mapped) == len(set(mapped)) and set(mapped) == seen,
            'EXACT_FROZEN_SEMANTIC_REFERENCE_SET_REQUIRED')
    return copy.deepcopy(bindings)


def validate_case(case):
    fields = {'schema', 'privateParent', 'retainedInputs', 'historicalReview', 'patchContext',
        'lineageReceipt', 'predecessorJournalPath', 'frozenReference', 'proposedOwnerBudget', 'originalRequestTls'}
    require(type(case) is dict and set(case) in (fields, fields | {'priorPreparation'})
        and case['schema'] == SCHEMA and case['privateParent'] == PARENT, 'EXACT_POSTBOOT_PREPARATION_CASE_REQUIRED')
    if 'priorPreparation' in case:
        prior = case['priorPreparation']
        require(type(prior) is dict and set(prior) == {'sourceClosureHash', 'caseHash', 'engineAttempts', 'adminAttempts', 'frozenAttempts'}
                and hashed(prior['sourceClosureHash']) and hashed(prior['caseHash'])
                and prior['caseHash'] == digest({k: v for k, v in case.items() if k != 'priorPreparation'})
                and prior['engineAttempts'] == 6 and prior['adminAttempts'] == 1 and prior['frozenAttempts'] == 0,
                'EXACT_RETAINED_FAILED_PREPARATION_RECONCILIATION_REQUIRED')
    for key in ('retainedInputs', 'historicalReview'):
        value = case[key]
        require(type(value) is dict and set(value) == {'path', 'sha256'} and hashed(value['sha256'])
                and exact_path(value['path']).is_relative_to(PARENT), 'EXACT_RETAINED_PREPARATION_REFERENCE_REQUIRED')
    require(exact_path(case['patchContext']).parent == Path(PARENT)
            and exact_path(case['predecessorJournalPath']).is_relative_to(PARENT), 'EXACT_RETAINED_PREPARATION_ROOT_REQUIRED')
    receipt = case['lineageReceipt']; owner_contract.terminal(receipt)
    require(receipt['historicalInputsHash'] == case['retainedInputs']['sha256']
            and receipt['historicalReviewHash'] == case['historicalReview']['sha256'], 'PREPARATION_LINEAGE_ANCHOR_MISMATCH')
    frozen_query(case['frozenReference'])
    budget = case['proposedOwnerBudget']
    require(type(budget) is dict
            and set(budget) == {'maximumGrantAttempts', 'maximumSeconds', 'attemptTimeoutSeconds', 'intervalSeconds'}
            and type(budget['maximumGrantAttempts']) is int and budget['maximumGrantAttempts'] == 1
            and owner_contract.integer(budget['maximumSeconds'], 1, 900)
            and owner_contract.integer(budget['attemptTimeoutSeconds'], 1, min(30, budget['maximumSeconds']))
            and owner_contract.integer(budget['intervalSeconds'], 1, 3600),
            'ONE_EXPLICIT_FINITE_POSTBOOT_ATTEMPT_PROPOSAL_REQUIRED')


def source_files(root, manifest, sources, files):
    selected = owner_contract.SOURCE_FILES
    require(type(manifest) is dict and type(sources) is dict and selected <= set(sources), 'COMPLETE_SEALED_OWNER_SOURCES_REQUIRED')
    source_root = root / 'source'; source_root.mkdir(mode=0o700)
    paths = {}
    for module in sorted(selected):
        raw = sources[module]
        require(type(raw) is bytes and 0 < len(raw) <= 262144
                and hashlib.sha256(raw).hexdigest() == manifest['sourceHashes'][module], 'SEALED_SOURCE_BYTES_CHANGED')
        name = module.replace('.', '_') + '.py'
        publish(source_root, name, raw); paths[module] = str(source_root / name)
    source_root.chmod(0o500)
    return {module: files.seal(path, 262144, manifest['sourceHashes'][module])[0] for module, path in paths.items()}


def authority_inputs(historical, files):
    # These are the installation's already sealed public authority references.
    # Inspect the public policy, never a private signing key or key directory.
    import iam_governance_intake as governance
    from iam_owner_action import stdlib_binding
    public = {}
    for name, reference in (('authorityProfile', governance.PROFILE), ('trustPolicy', governance.POLICY)):
        _, raw = files.seal(reference['path'], 1048576, reference['sha256'])
        public[name] = decode(raw)
    governance.authority_metadata(public['authorityProfile'], public['trustPolicy'], int(time.time()))
    retained_programs = historical['sourceClosure']['executables']
    programs = {}
    for name in ('python', 'docker', 'openssl'):
        retained = retained_programs[name]
        profile, _ = files.seal(retained['path'], 67108864, retained['sha256'])
        require(profile['metadata'][3] == 0 and profile['metadata'][4] & 0o111,
                'ROOT_EXECUTABLE_PREPARATION_CUSTODY_REQUIRED')
        programs[name] = {'path': profile['path'], 'sha256': profile['sha256']}
        require(governance.executable(profile['path']) == programs[name], 'CURRENT_AUTHORITY_EXECUTABLE_CHANGED')
    result = subprocess.run([programs['openssl']['path'], 'version'], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, cwd='/', env={'LC_ALL': 'C'})
    match = re.fullmatch(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?) [^\r\n]{1,200}\r?\n?', result.stdout)
    require(result.returncode == 0 and match is not None, 'CURRENT_OPENSSL_VERSION_UNCONFIRMED')
    programs['openssl']['version'] = match[1].decode('ascii')
    require(programs['openssl'] == retained_programs['openssl'], 'RETAINED_OPENSSL_PROGRAM_VERSION_CHANGED')
    # This existing primitive seals only the interpreter's standard library,
    # excluding site packages: <=4096 files, <=256 MiB, 16 MiB per file.
    library = stdlib_binding(); files.check()
    return {'authorityProfile': copy.deepcopy(governance.PROFILE), 'trustPolicy': copy.deepcopy(governance.POLICY),
        'context': copy.deepcopy(governance.CONTEXT), 'executables': programs,
        'stdlibHash': digest(library), 'stdlibFileCount': len(library['fileHashes'])}


def prepared_root(case, manifest, boot_id=None):
    """One current-boot private path, derived without target discovery or argv."""
    validate_case(case)
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip() if boot_id is None else boot_id
    require(owner_contract.boot(boot_id), 'CURRENT_PREPARATION_BOOT_REQUIRED')
    return Path(PARENT) / ('semantic-registry-postboot-inputs-' + digest({
        'case': case, 'closure': digest(manifest), 'boot': boot_id}))


def reconcile_prior_preparation(case, files, boot):
    """Read exact old claim/markers, retaining conservative attempted counts.

    This never changes or resumes the old preparation. A fresh bounded capture
    has a distinct case and carries prior attempts into its proof and review.
    """
    if 'priorPreparation' not in case:
        return None
    prior = case['priorPreparation']
    original = {k: v for k, v in case.items() if k != 'priorPreparation'}
    root = Path(PARENT) / ('semantic-registry-postboot-inputs-' + digest({
        'case': original, 'closure': prior['sourceClosureHash'], 'boot': boot}))
    expected = {'schema': SCHEMA, 'caseHash': prior['caseHash'],
        'sourceClosureHash': prior['sourceClosureHash'], 'bootId': boot,
        'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
        'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False}
    claim, binding = files.json(str(root / 'claim.json'))
    require(claim == expected, 'EXACT_PRIOR_PREPARATION_CLAIM_REQUIRED')
    markers = []
    for number in range(1, 7):
        marker, profile = files.json(str(root / ('engine-get-' + str(number) + '.json')))
        require(set(marker) == {'requestPathHash', 'attempt'} and marker['attempt'] == number
                and hashed(marker['requestPathHash']), 'EXACT_PRIOR_ENGINE_ATTEMPT_MARKER_REQUIRED')
        markers.append(profile)
    marker, profile = files.json(str(root / 'admin-get.json'))
    require(marker == {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1},
            'EXACT_PRIOR_ADMIN_ATTEMPT_MARKER_REQUIRED')
    markers.append(profile)
    for name in ['engine-get-' + str(n) + '.json' for n in range(7, 13)] + [
            'frozen-get.json', 'source', 'prepared.json', 'review.json']:
        try:
            (root / name).lstat()
        except FileNotFoundError:
            continue
        require(False, 'PRIOR_PREPARATION_ADVANCED_RECONCILE_REQUIRED')
    return {'priorClaim': binding, 'priorMarkers': markers, 'priorAttemptCounts': {
        'engineGets': 6, 'adminGets': 1, 'frozenConfigurationGets': 0},
        'newAttemptCeilings': {'engineGets': 12, 'adminGets': 1, 'frozenConfigurationGets': 1},
        'cumulativeAttemptCeilings': {'engineGets': 18, 'adminGets': 2, 'frozenConfigurationGets': 1},
        'oldPreparationReplayed': False, 'oldPreparationChanged': False, 'budgetReset': False}


def returned(private, profile):
    return {**{key: private[key] for key in ('nativeContext', 'ownerContext', 'preparationProof',
            'registryInputs', 'authorityInputs', 'sourceClosure')}, 'preparedBinding': profile,
        'privatePreparationPath': profile['path'], 'privatePreparationHash': profile['sha256']}


def read_prepared(case, manifest):
    """Read only the exact completed private preparation for this boot/capsule."""
    require(os.geteuid() == os.getegid() == 0, 'ROOT_POSTBOOT_PREPARATION_REQUIRED')
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    root = prepared_root(case, manifest, boot_id)
    files = Files()
    private, profile = files.json(str(root / 'prepared.json'), maximum=16777216)
    require(set(private) == {'schema', 'nativeContext', 'ownerContext', 'registryInputs',
                'authorityInputs', 'sourceClosure', 'preparationProof'}
            and private['schema'] == 'ouf.semantic-registry-postboot-prepared-inputs.v1'
            and stat.S_IMODE(profile['metadata'][4]) == 0o400,
            'EXACT_COMPLETED_PRIVATE_POSTBOOT_PREPARATION_REQUIRED')
    proof = private['preparationProof']
    require(proof['caseHash'] == digest(case) and proof['sourceClosureHash'] == digest(manifest)
            and proof['bootId'] == boot_id and private['sourceClosure'] == manifest
            and private['ownerContext']['lineageReceipt'] == case['lineageReceipt']
            and private['ownerContext']['predecessorJournalPath'] == case['predecessorJournalPath']
            and private['ownerContext']['budget'] == case['proposedOwnerBudget']
            and all(private['nativeContext']['retainedInputs'][key] == value
                    for key, value in case['retainedInputs'].items()),
            'SAME_CASE_SOURCE_BOOT_PRIVATE_PREPARATION_REQUIRED')
    if 'priorPreparation' in case:
        require(proof.get('priorPreparationReconciliation') == reconcile_prior_preparation(case, files, boot_id),
                'RETAINED_PREPARATION_RECONCILIATION_CHANGED')
    owner_contract.compile_scope(private['ownerContext'])
    for name, expected in private['ownerContext']['sourceFiles'].items():
        path = str(root / 'source' / (name.replace('.', '_') + '.py'))
        require(expected['path'] == path, 'EXACT_PREPARED_SOURCE_COPY_PATH_REQUIRED')
        actual, _ = files.seal(path, 262144, manifest['sourceHashes'][name])
        require(actual == expected, 'PREPARED_IMMUTABLE_SOURCE_COPY_CHANGED')
    files.verify()
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot_id,
            'PREPARED_CURRENT_BOOT_CHANGED')
    return returned(private, profile)


def prepare(case, manifest, sources):
    # Interrupt a blocked read as well as checking the cooperative IO budget.
    # Preserve an earlier capsule deadline; preparation cannot extend it.
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    seconds = min(MAX_SECONDS, previous_timer[0]) if previous_timer[0] else MAX_SECONDS
    def expired(_signum, _frame):
        require(False, 'POSTBOOT_PREPARATION_DEADLINE')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return _prepare(case, manifest, sources)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            remaining = max(0.000001, previous_timer[0] - (time.monotonic() - started))
            signal.setitimer(signal.ITIMER_REAL, remaining, previous_timer[1])


def _prepare(case, manifest, sources):
    from .factory import canonical_root, factory_scope, require_historical_parent
    from tools.ingestion_readiness_patch_execution import private_file, runtime_guard
    require(os.geteuid() == os.getegid() == 0, 'ROOT_POSTBOOT_PREPARATION_REQUIRED')
    validate_case(case)
    require(manifest.get('sourceHashes', {}).get(__name__) == globals().get('__qualified_source_sha256__')
            and hashed(globals().get('__qualified_source_sha256__')), 'EXACT_SEALED_PREPARATION_SOURCE_REQUIRED')
    files = Files(); closure_hash = digest(manifest)
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(owner_contract.boot(boot), 'CURRENT_PREPARATION_BOOT_REQUIRED')
    root = prepared_root(case, manifest, boot)
    for parent in [root.parent, *root.parent.parents]:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'PROTECTED_PREPARATION_PARENT_REQUIRED')
    # Durable exclusive path before any Engine/admin/service request. Existing,
    # incomplete or failed preparations are retained and never reinitialized.
    os.mkdir(root, 0o700)
    publish(root, 'claim.json', {'schema': SCHEMA, 'caseHash': digest(case), 'sourceClosureHash': closure_hash,
        'bootId': boot, 'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
        'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False})
    prior_preparation = reconcile_prior_preparation(case, files, boot)
    inputs, input_profile = files.json(case['retainedInputs']['path'], case['retainedInputs']['sha256'])
    historical, _ = files.json(case['historicalReview']['path'], case['historicalReview']['sha256'])
    bundle_ref = historical['scopes']['finiteActionProcess']['bundle']
    require(type(bundle_ref) is dict and hashed(bundle_ref.get('sha256'))
            and exact_path(bundle_ref['path']).is_relative_to(PARENT)
            and bundle_ref['sha256'] == case['lineageReceipt']['historicalBundleHash'], 'EXACT_RETAINED_OWNER_BUNDLE_REQUIRED')
    bundle, _ = files.json(bundle_ref['path'], bundle_ref['sha256'])
    original = bundle['prepared']; registry = inputs['registryInputs']; proposal = inputs['proposal']; plan = inputs['candidateContract']
    validate_plan(plan)
    require(inputs['schema'] == 'ouf.semantic-registry-recovery-private-historical-inputs.v1'
            and inputs['historicalBinding']['historicalDeploymentChainBound'] is True
            and digest(original) == historical['privateInputHashes']['preparedInputs']
            and original['registry'] == registry, 'SAME_RETAINED_PREPARATION_CHAIN_REQUIRED')
    patch = Path(case['patchContext'])
    review, _ = files.json(str(patch / 'review.json'), proposal['retainedPatchReviewHash'])
    journal, _ = files.json(str(patch / 'recovery.json'), proposal['retainedPatchJournalHash'])
    native = review['executionReview']
    require(native['packetBinding']['path'] == str(patch / 'packet.json'), 'EXACT_RETAINED_PATCH_PACKET_REQUIRED')
    packet, _ = files.json(str(patch / 'packet.json'), native['packetBinding']['sha256'])
    require(journal['nextStage'] == len(native['stages']) == len(journal['effects']) == 12
            and all(e['state'] == 'APPLIED' for e in journal['effects']), 'COMPLETED_PATCH_LINEAGE_REQUIRED')
    effects = {e['stage']: e for e in journal['effects']}
    caller_id = effects['ingestion.CREATE_REPLACEMENT']['nativeResource']['containerId']
    require(caller_id == effects['ingestion.START_REPLACEMENT']['nativeResource']['containerId'], 'DURABLE_ORIGINAL_CALLER_REQUIRED')
    rid = proposal['registry']['containerId']; gid = proposal['gatewayBinding']['containerId']
    pgid = registry['readinessScope']['databaseContainerId']
    ids = (rid, gid, pgid, caller_id)
    require(len(set(ids)) == 4 and all(hashed(cid) for cid in ids), 'FOUR_EXACT_PREPARATION_CONTAINERS_REQUIRED')
    request = registry['creationRequest']; endpoints = request['NetworkingConfig']['EndpointsConfig']
    require(len(endpoints) == 1, 'ONE_RETAINED_REGISTRY_NETWORK_REQUIRED')
    nid = next(iter(endpoints.values()))['NetworkID']; require(hashed(nid), 'EXACT_RETAINED_NETWORK_ID_REQUIRED')
    from engine_creation import Engine
    engine_binding = proposal['engineBinding']; engine = Engine(engine_binding['socketPath'], tuple(engine_binding['socketBinding']))
    allowed = {'/v1.44/containers/' + cid + '/json' for cid in ids}
    allowed |= {'/v1.44/networks/' + nid, '/v1.44/images/' + request['Image'] + '/json'}
    calls = 0
    def get(path):
        nonlocal calls
        files.check(); require(path in allowed and calls < 12, 'CLOSED_PREPARATION_ENGINE_GET_BUDGET')
        calls += 1
        publish(root, 'engine-get-' + str(calls) + '.json', {'requestPathHash': digest(path), 'attempt': calls})
        status, value = engine.request('GET', path)
        require(status == 200 and type(value) is dict, 'CURRENT_EXACT_PREPARATION_RESOURCE_UNCONFIRMED')
        return value
    rows = {cid: get('/v1.44/containers/' + cid + '/json') for cid in ids}
    require(all(actual.get('Id') == cid for cid, actual in rows.items()), 'SAME_EXACT_PREPARATION_CONTAINER_IDS_REQUIRED')
    image = get('/v1.44/images/' + request['Image'] + '/json'); network = get('/v1.44/networks/' + nid)
    transport.registry_baseline(rows[rid], proposal['registry'])
    transport.generation(rows[gid], proposal['gatewayBinding'])
    require(image['Id'] == request['Image'], 'SAME_CURRENT_REGISTRY_IMAGE_REQUIRED')
    pgpin, gwpin, callerpin = (current_pin(rows[cid]) for cid in (pgid, gid, caller_id))
    first = effects['ingestion.START_REPLACEMENT']['nativeResource']
    require(rows[caller_id]['State']['Pid'] == first['pid']
            and rows[caller_id]['State']['StartedAt'] == first['startedAt'] and rows[caller_id]['RestartCount'] == 0,
            'ORIGINAL_INGESTION_FIRST_PROCESS_REQUIRED')
    admin = copy.deepcopy(native['gatewayTransportProfile'])
    require({k: admin['config'][k] for k in ('path', 'sha256', 'metadata')} == packet['retainedGatewayConfig'],
            'SAME_RETAINED_ADMIN_CONFIG_REQUIRED')
    require(mounted_source(rows[gid], '/usr/local/apisix/conf/config.yaml') == admin['config']['path'],
            'CURRENT_GATEWAY_ADMIN_CONFIG_MOUNT_REQUIRED')
    publish(root, 'admin-get.json', {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1})
    routes = transport.admin_routes(admin, rows[gid])
    correlation = transport.correlate(routes, packet['routeDraft']['afterRoutes'], request, rows[rid], network, rows[gid])
    require(correlation['completeCurrentRouteMapMatchesRetained'] is True
            and correlation['currentRouteTargetsReviewedRegistryAddressAndPort'] is True
            and correlation['currentTargetEndpointCount'] == 0, 'CURRENT_UNCHANGED_ROUTE_AND_FREE_REGISTRY_ENDPOINT_REQUIRED')
    db_program = native['databaseControlProfile']['dockerExecutable']
    docker, _ = files.seal(db_program['path'], 67108864, db_program['sha256'])
    origin, target, caller_configuration = configuration(rows[caller_id])
    token_path = mounted_source(rows[caller_id], target)
    token_profile, _ = files.seal(token_path, 16384)
    u = urlsplit(origin); tls = case['originalRequestTls']
    if u.scheme == 'http':
        require(tls is None and any(e.get('IPAddress') == u.hostname for e in rows[gid]['NetworkSettings']['Networks'].values()),
                'HTTP_ORIGINAL_CALLER_MUST_TARGET_EXACT_GATEWAY')
        ca, cert = None, None
    else:
        require(u.scheme == 'https' and type(tls) is dict and set(tls) == {'origin', 'ca', 'peerCertificateSha256'}
                and tls['origin'] == origin and hashed(tls['peerCertificateSha256']), 'INDEPENDENT_ORIGINAL_SERVICE_TLS_PROFILE_REQUIRED')
        ca = copy.deepcopy(tls['ca']); private_file.validate(ca)
        observed_ca, _ = files.seal(ca['path'], 1048576, ca['sha256'])
        require(observed_ca == ca, 'CURRENT_ORIGINAL_SERVICE_TLS_CUSTODY_CHANGED')
        cert = tls['peerCertificateSha256']
    original_request = {'caller': callerpin, 'callerConfiguration': caller_configuration,
        'origin': origin, 'tokenTarget': target, 'tokenSource': token_profile,
        'pythonExecutable': copy.deepcopy(admin['pythonExecutable']), 'ca': ca, 'peerCertificateSha256': cert}
    publish(root, 'frozen-get.json', {'method': 'GET', 'path': FROZEN_PATH, 'referenceHash': digest(case['frozenReference']), 'maximumAttempts': 1})
    verify_configuration(rows[caller_id], original_request)
    frozen = read_frozen(original_request, rows[caller_id], case['frozenReference'])
    verify_configuration(rows[caller_id], original_request)
    refs = frozen_configuration(frozen, case['frozenReference'])
    original_request.update(references=refs, frozenConfigurationHash=case['frozenReference']['configurationHash'],
        onboardingVersionId=case['frozenReference']['onboardingVersionId'], frozenConfiguration=frozen)
    # Original owner credential location comes from its already proven three
    # completed root identities, never a guessed client-secret search.
    owner = original['owner']; host = owner['hostInputBinding']
    _, host_raw = files.seal(host['path'], 2097152, host['sha256'])
    from migration_root_custody import completed_roots
    with completed_roots(host_raw, owner['rootEvidenceHash'], owner['rootCreationSourceClosureHash']) as roots:
        credential_path = str(Path(roots['ownerCredential']['path']) / 'client-secret')
        credential_metadata = files.stat_private(credential_path)
    from tools.semantic_policy_token_owner.producer import protected_directory
    binding = owner['binding']
    with protected_directory(binding['output_directory'], gid=binding['output_gid'], mode=0o750) as fd:
        info = os.fstat(fd); output = {'device': info.st_dev, 'inode': info.st_ino}
    recipe = copy.deepcopy(registry['nodeRecipe'])
    require(digest(binding) == case['lineageReceipt']['credentialOutputBindingHash']
            and recipe['renewableToken']['source'] == binding['output_directory']
            and recipe['renewableToken']['ownerBindingHash'] == digest(binding), 'SAME_REGISTRY_CREDENTIAL_OUTPUT_REQUIRED')
    recipe['sourceClosureHash'] = closure_hash
    recipe['renewableToken'].update(directoryDevice=output['device'], directoryInode=output['inode'])
    retained_records = {name: files.json(case['predecessorJournalPath'] + '/' + name, maximum=131072)[0]
                        for name in owner_contract.RECORDS}
    source_profiles = source_files(root, manifest, sources, files)
    authority = authority_inputs(historical, files)
    require(authority['executables']['python'] == original_request['pythonExecutable']
            and authority['executables']['docker'] == {k: docker[k] for k in ('path', 'sha256')},
            'ONE_CURRENT_PREPARATION_EXECUTABLE_SET_REQUIRED')
    owner_context = {'schema': owner_contract.CONTEXT, 'lineageReceipt': copy.deepcopy(case['lineageReceipt']),
        'predecessorJournalPath': case['predecessorJournalPath'], 'retainedRecords': retained_records,
        'ownerInputs': {'binding': copy.deepcopy(binding), 'iamProfile': copy.deepcopy(owner['iamProfile']),
            'tlsTrustHash': owner['tlsTrustSetHash'], 'credentialPath': credential_path,
            'credentialMetadata': credential_metadata, 'outputDirectoryIdentity': output},
        'recovery': {'planHash': digest(plan), 'logicalOperationRef': plan['logicalOperationRef'],
            'registryId': rid, 'bootId': boot}, 'sourceClosureHash': closure_hash,
        'sourceFiles': source_profiles, 'budget': copy.deepcopy(case['proposedOwnerBudget'])}
    owner_contract.compile_scope(owner_context)
    context = {'schema': 'ouf.semantic-registry-recovery-native-context.v1', 'retainedInputs': input_profile,
        'plan': copy.deepcopy(plan), 'engineBinding': copy.deepcopy(engine_binding), 'stoppedSnapshot': rows[rid],
        'nodeRecipe': recipe, 'database': {'readiness': copy.deepcopy(registry['readinessScope']), 'postgres': pgpin, 'program': docker},
        'gateway': {'pin': gwpin, 'profile': admin, 'routes': routes, 'networkId': nid},
        'originalRequest': original_request, 'executionRoot': str(canonical_root(input_profile['path'], plan['logicalOperationRef']))}
    require_historical_parent(registry, context['executionRoot']); factory_scope(context)
    # No old process generation is copied into recovery.newGeneration. Recheck
    # configuration and live caller/DB/Gateway identities before publication.
    for cid in ids:
        current = get('/v1.44/containers/' + cid + '/json')
        if cid == rid:
            transport.registry_baseline(current, proposal['registry'])
            require(transport.stable_fields(current) == transport.stable_fields(rows[cid]), 'STOPPED_REGISTRY_CHANGED_DURING_PREPARATION')
        else:
            runtime_guard.unchanged(current, {pgid: pgpin, gid: gwpin, caller_id: callerpin}[cid])
    require(get('/v1.44/images/' + request['Image'] + '/json') == image
            and get('/v1.44/networks/' + nid) == network, 'PREPARATION_IMAGE_OR_NETWORK_CHANGED')
    verify_configuration(rows[caller_id], original_request)
    require(reconcile_prior_preparation(case, files, boot) == prior_preparation,
            'PRIOR_PREPARATION_CHANGED_DURING_CAPTURE')
    files.verify()
    require(files.stat_private(credential_path) == credential_metadata
            and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot,
            'CURRENT_PREPARATION_BOOT_OR_CREDENTIAL_CUSTODY_CHANGED')
    private = {'schema': 'ouf.semantic-registry-postboot-prepared-inputs.v1', 'nativeContext': context,
        'ownerContext': owner_context, 'registryInputs': copy.deepcopy(registry),
        'authorityInputs': authority, 'sourceClosure': copy.deepcopy(manifest),
        'preparationProof': {'caseHash': digest(case), 'sourceClosureHash': closure_hash,
            'bootId': boot, 'engineGets': calls, 'adminGets': 1, 'frozenConfigurationGets': 1,
            'priorPreparationReconciliation': prior_preparation,
            'originalServiceBearerUsed': True, 'ownerCredentialBytesRead': False, 'databaseCalls': 0, 'oauthRequests': 0,
            'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False, 'budgetReset': False,
            'automaticReplayAllowed': False, 'nativeExecutorQualified': False, 'targetApplyAuthorized': False}}
    publish(root, 'prepared.json', private)
    profile, _ = files.seal(str(root / 'prepared.json'), 16777216, digest(private), retain=False)
    return returned(private, profile)
