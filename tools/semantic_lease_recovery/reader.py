"""Read the consumed R8 cohort and its separate lease prerequisites. No mutation.

The old guard observer requires never-started candidates. This reader does not
invoke it, a boot restorer, broker, supervisor, signer or DNS/provider request.
Native nft structure normalization matches semantic_provider_lease_nft.py.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import traceback

BASE = Path('/etc/ouf/deploy-snapshots')
CONTEXT = BASE/'semantic-provider-v2-approved-context-mf9x0eqd'
OUTPUT = BASE/'semantic-provider-v2-transaction-mf9x0eqd'
GUARD = BASE/'semantic-coordinated-boot-install-v2-e4repg0a'
POINTER = Path('/etc/ouf/coordinated-boot-installation.json')
OWNER_HASH = '656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
APPROVAL = 'OUF_PROVIDER_PREPARED_MOUNTPOINT_APPROVED_20261009T203804_CEST_R8'
TARGETS = {
    'adapter': ('f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67',
                'sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc'),
    'southbound': ('1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916',
                   'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366')}
UNIT_PATHS = {
    'guard.service': Path('/etc/systemd/system/ouf-semantic-boot-guard.service'),
    'docker-drop-in.conf': Path('/etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf')}
FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},'
          '"runtime":{{json .HostConfig.Runtime}},"state":{{json .State}},'
          '"restartCount":{{json .RestartCount}},"networks":{{json .NetworkSettings.Networks}}}')
PHASE = 'READ_CONSUMED_R8_CONTEXT'
SAVED = {}
DIAGNOSIS = {}


class ReadDenied(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise ReadDenied(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ReadDenied('NONFINITE_JSON_VALUE')))


def identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
                                          'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def private(path, expected=None, executable=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'EXPLICIT_SAFE_PATH_REQUIRED')
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'ROOT_OWNED_ANCESTOR_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        limit = 64000000 if executable else 2000000
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and info.st_size <= limit and (bool(info.st_mode & 0o111) and not info.st_mode & 0o022
                if executable else stat.S_IMODE(info.st_mode) == 0o600), 'ROOT_FILE_CUSTODY_UNPROVEN')
        chunks = []
        size = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= limit, 'BOUNDED_FILE_REQUIRED')
        raw = b''.join(chunks)
        require(size == info.st_size and identity(info) == identity(os.fstat(fd)) == identity(path.lstat()),
                'FILE_CHANGED_DURING_READ')
    finally:
        os.close(fd)
    if expected is not None:
        if sha(raw) != expected:
            DIAGNOSIS.update(inputFileName=path.name, expectedSha256=expected, actualSha256=sha(raw))
            raise ReadDenied('EXACT_FILE_HASH_DRIFT')
    return raw


def bound(binding):
    require(type(binding) is dict and set(binding) == {'path', 'sha256'}
            and re.fullmatch('[0-9a-f]{64}', binding['sha256']), 'EXACT_FILE_BINDING_REQUIRED')
    raw = private(binding['path'], binding['sha256'])
    SAVED[binding['path']] = raw
    return raw


def safe_source(root, name):
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == name,
            'SOURCE_PATH_ESCAPE_DENIED')
    return root/path


def structure(value):
    # Same normalization as the already-installed nft backend: preserve handles.
    if isinstance(value, list):
        return [structure(v) for v in value]
    if isinstance(value, dict):
        if isinstance(value.get('set'), dict) and 'name' in value['set']:
            return {'set': structure({k: v for k, v in value['set'].items() if k != 'elem'})}
        return {k: structure(v) for k, v in value.items() if k not in ('packets', 'bytes', 'expires')}
    return value


def lease_projection(owner, journal, tables):
    flows = owner['kernel']['providerFlows']
    require(sha(encoded(structure(tables))) == owner['expectedStructureHash'], 'NFT_STRUCTURE_DRIFT')
    require(set(journal) == {'schema', *owner['binding'], 'state', 'leaseAuthorized', 'startAuthorized', 'leaseAddresses'}
            and journal['schema'] == 'ouf.semantic-lease-coordination.v1'
            and all(journal[k] == v for k, v in owner['binding'].items())
            and journal['state'] in {'LEASE_READY', 'LEASE_UPDATING', 'QUIESCING', 'QUIESCED', 'BLOCKED'}
            and type(journal['leaseAuthorized']) is bool and journal['startAuthorized'] is False,
            'COORDINATION_JOURNAL_BINDING_DRIFT')
    approved = journal['leaseAddresses']
    require(isinstance(approved, list) and len(approved) == len(flows), 'LEASE_RECEIPT_SHAPE_INVALID')
    actual = {}
    for family, table in tables.items():
        for row in table['nftables']:
            value = row.get('set')
            if value is None:
                continue
            require(value['family'] == family and value['table'] == owner['kernel']['tableName']
                    and re.fullmatch('provider_[0-9]+', value['name']) and value.get('flags') == ['timeout'],
                    'LEASE_SET_SCOPE_DRIFT')
            index = int(value['name'].split('_')[1])
            require(index < len(flows) and (family, index) not in actual, 'LEASE_SET_INDEX_INVALID')
            flow = flows[index]
            version = ipaddress.ip_address(flow['source']).version
            require(value['type'] == ('ipv4_addr' if version == 4 else 'ipv6_addr'), 'LEASE_SET_ADDRESS_FAMILY_DRIFT')
            addresses = {}
            for entry in value.get('elem', []):
                element = entry['elem']
                text, ttl = element['val'], element['expires']
                address = ipaddress.ip_address(text)
                require(str(address) == text and address.version == version and text not in addresses
                        and not (address.is_loopback or address.is_link_local or address.is_multicast
                                 or address.is_unspecified or address.is_reserved)
                        and (address.is_global or text in flow['allowedPrivateAddresses'])
                        and type(ttl) is int and 0 < ttl <= flow['leaseSeconds'],
                        'LEASE_ADDRESS_OR_TTL_UNPROVEN')
                addresses[text] = ttl
            require(len(addresses) <= 32, 'LEASE_SET_UNBOUNDED')
            actual[family, index] = addresses
    require(set(actual) == {(f, i) for f in ('inet', 'bridge') for i in range(len(flows))}, 'LEASE_SET_PAIR_INCOMPLETE')
    for index, row in enumerate(approved):
        require(isinstance(row, list) and len(row) <= 32 and all(isinstance(v, str) for v in row)
                and len(set(row)) == len(row), 'LEASE_RECEIPT_ADDRESS_SHAPE_INVALID')
        require(set(actual['inet', index]) == set(actual['bridge', index]), 'LEASE_FAMILY_MEMBERSHIP_DRIFT')
    empty = not any(actual.values())
    consistent = ((journal['state'] == 'QUIESCED' and journal['leaseAuthorized'] is False and empty)
                  or (journal['state'] == 'LEASE_READY' and journal['leaseAuthorized'] is True
                      and all(set(actual['inet', i]).issubset(set(approved[i])) for i in range(len(flows)))))
    return {'journalState': journal['state'], 'leaseAuthorized': journal['leaseAuthorized'],
            'startAuthorized': False, 'journalAndMembershipConsistent': consistent,
            'providerSetsEmpty': empty, 'nativeStructureVerified': True,
            'configurationHash': OWNER_HASH, 'kernelConfigurationHash': sha(encoded(owner['kernel'])),
            'journalHash': sha(encoded(journal)), 'pollSeconds': owner['pollSeconds'],
            'flowCount': len(flows), 'flows': [
                {'index': i, 'endpointHash': sha(flow['endpoint'].encode()),
                 'endpointRefHash': sha(flow['endpointRef'].encode()),
                 'leaseSeconds': flow['leaseSeconds'], 'sourceHash': sha(flow['source'].encode()),
                 'approvedAddressCount': len(approved[i]),
                 'inetAddressCount': len(actual['inet', i]), 'bridgeAddressCount': len(actual['bridge', i]),
                 'minRemainingTtlSeconds': min((*actual['inet', i].values(), *actual['bridge', i].values()), default=None)}
                for i, flow in enumerate(flows)]}


def run(command_bindings, name, args, *, table=None):
    allowed = (
        name == 'nft' and args in [['-j', 'list', 'table', f, table] for f in ('inet', 'bridge')]
        or name == 'docker' and args in [['inspect', '--type', 'container', '--format', FORMAT, cid] for cid, _ in TARGETS.values()]
        or name == 'systemctl' and (args in [['show', u, '--property=' + p, '--value']
            for u, p in [('ouf-semantic-boot-guard.service', 'ExecStart'), ('docker.service', 'ExecStartPre')]]
            or args == ['list-unit-files', '--type=service', '--no-legend', '--no-pager', 'ouf*']))
    require(allowed, 'READ_ONLY_COMMAND_SCOPE_REQUIRED')
    binding = command_bindings[name]
    private(binding['path'], binding['sha256'], executable=True)
    argv = [binding['path'], *args]
    if name == 'docker':
        config_dir = OUTPUT/'activation-docker-cli'
        info = config_dir.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o700 and not os.path.lexists(config_dir/'config.json'),
                'EXISTING_EMPTY_ACTIVATION_CLI_DIRECTORY_REQUIRED')
        argv = [binding['path'], '--config', str(config_dir), *args]
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=15, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                                                 'DOCKER_HOST': 'unix:///var/run/docker.sock'})
    except subprocess.TimeoutExpired:
        DIAGNOSIS.update(commandName=name, budgetSeconds=15)
        raise ReadDenied('READ_ONLY_COMMAND_TIMEOUT') from None
    if result.returncode != 0:
        DIAGNOSIS.update(commandName=name, exitCode=result.returncode, stderrSha256=sha(result.stderr),
                         stderrBytes=len(result.stderr))
        raise ReadDenied('READ_ONLY_COMMAND_FAILED')
    require(len(result.stdout) <= 2000000, 'COMMAND_OUTPUT_UNBOUNDED')
    return result.stdout


def collect():
    global PHASE
    SAVED.clear()
    DIAGNOSIS.clear()
    PHASE = 'READ_CONSUMED_R8_CONTEXT'
    approval = parse(private(CONTEXT/'human-approval-binding.json'))
    require(approval['approvalRef'] == APPROVAL, 'EXACT_CONSUMED_R8_CONTEXT_REQUIRED')
    cfg = parse(bound({'path': str(CONTEXT/'execution-configuration.json'), 'sha256': approval['configurationHash']}))
    require(cfg['outputRoot'] == str(OUTPUT), 'EXACT_R8_OUTPUT_REQUIRED')
    report = {'contextDirectory': str(CONTEXT), 'evidenceDirectory': str(OUTPUT), 'roles': {}}
    historical = parse(private(OUTPUT/'cohort-activation-receipt.json'))
    require(historical['status'] == 'TWO_CANDIDATE_RUNTIME_STARTED', 'SUCCESSFUL_R8_RECEIPT_REQUIRED')
    for role, (cid, image) in TARGETS.items():
        PHASE = 'READ_R8_ROLE_' + role.upper()
        issuance_raw = private(CONTEXT/'role-authority'/role/'role-issuance-receipt.json')
        issuance = parse(issuance_raw)
        journal_raw = private(OUTPUT/'registry'/cid/'adapter.json')
        journal = parse(journal_raw)
        require(issuance['schema'] == 'ouf.semantic-provider-role-authority-issuance.v1'
                and issuance['role'] == role and issuance['status'] == 'ROLE_RECORDS_ISSUED', 'ROLE_ISSUANCE_RECEIPT_DRIFT')
        require(journal['containerId'] == cid, 'R8_JOURNAL_CID_DRIFT')
        value = parse(run(cfg['commandBindings'], 'docker', ['inspect', '--type', 'container', '--format', FORMAT, cid]))
        require(value['id'] == cid and value['image'] == image and value['runtime'] == 'ouf-semantic-admitted-v2',
                'EXACT_CANDIDATE_RUNTIME_DRIFT')
        state = value['state']
        report['roles'][role] = {
            'containerId': cid, 'running': state['Running'], 'pid': state['Pid'],
            'status': state['Status'] if state['Status'] in ('created', 'running', 'paused', 'restarting', 'removing', 'exited', 'dead') else 'UNPROVEN',
            'startedAt': state['StartedAt'], 'restartCount': value['restartCount'], 'exitCode': state['ExitCode'],
            'errorPresent': bool(state.get('Error')), 'adapterState': journal['state'] if journal['state'] in ('STAGED', 'CREATING', 'CREATED', 'PREPARING', 'STARTING', 'STARTED', 'DELETING', 'DELETED') else 'UNPROVEN',
            'adapterJournalHash': sha(journal_raw),
            'matchesSuccessfulR8Journal': sha(journal_raw) == historical['candidates'][cid]['adapterJournalHash'],
            'roleIssuanceReceiptHash': sha(issuance_raw), 'historicalRoleSignaturesIssued': issuance['signaturesIssued']}
        # Keep only network IPs in memory to bind existing governed source addresses.
        report['roles'][role]['_addresses'] = [address for row in value['networks'].values()
                                              for address in (row.get('IPAddress'), row.get('GlobalIPv6Address')) if address]
    PHASE = 'VERIFY_EXISTING_NETWORK_GUARD_CUSTODY'
    pointer = parse(bound(cfg['guardPointerBinding']))
    require(pointer['receiptFile'] == str(GUARD/'installation-receipt.json')
            and pointer['observerFile'] == str(GUARD/'transition-source.py'), 'EXACT_GUARD_POINTER_REQUIRED')
    receipt = parse(bound({'path': pointer['receiptFile'], 'sha256': pointer['receiptHash']}))
    require(receipt['configurationHash'] == OWNER_HASH, 'EXACT_INSTALLED_OWNER_REQUIRED')
    owner = parse(bound({'path': str(GUARD/'coordinated-configuration.json'), 'sha256': OWNER_HASH}))
    boot = parse(bound({'path': str(GUARD/'boot-configuration.json'), 'sha256': receipt['bootConfigurationHash']}))
    profile = parse(bound({'path': str(GUARD/'boot-profile.json'), 'sha256': receipt['bootProfileHash']}))
    require(owner['kernel'] == boot['kernel'] and owner['commonLockFile'] == boot['lockFile']
            and profile['coordinatedConfigurationHash'] == OWNER_HASH
            and profile['bootConfigurationHash'] == receipt['bootConfigurationHash'], 'BOOT_OWNER_BINDING_DRIFT')
    for name, expected in {**owner['sourceHashes'], **profile['sourceHashes']}.items():
        bound({'path': str(safe_source(GUARD/'source', name)), 'sha256': expected})
    require(set(receipt['artifactHashes']) == set(UNIT_PATHS), 'EXACT_BOOT_UNIT_PAIR_REQUIRED')
    for name, expected in receipt['artifactHashes'].items():
        require(name in UNIT_PATHS, 'UNEXPECTED_BOOT_UNIT_ARTIFACT')
        bound({'path': str(UNIT_PATHS[name]), 'sha256': expected})
    for unit, prop in [('ouf-semantic-boot-guard.service', 'ExecStart'), ('docker.service', 'ExecStartPre')]:
        loaded = run(cfg['commandBindings'], 'systemctl', ['show', unit, '--property=' + prop, '--value'])
        require(receipt['guardCommand'].encode() in loaded, 'LOADED_BOOT_COMMAND_DRIFT')
    require(cfg['commandBindings']['nft'] == {'path': owner['nftPath'], 'sha256': owner['nftSha256']},
            'NFT_EXECUTABLE_BINDING_DRIFT')
    PHASE = 'READ_CURRENT_LEASE_JOURNAL_AND_NATIVE_SETS_OPTIMISTICALLY'
    private(owner['commonLockFile'])
    fd = os.open(owner['commonLockFile'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        lock_id = identity(os.fstat(fd))
        require(lock_id == identity(Path(owner['commonLockFile']).lstat()), 'LOCK_IDENTITY_DRIFT')
        journal_raw = private(owner['journalFile'])
        tables = {f: parse(run(cfg['commandBindings'], 'nft', ['-j', 'list', 'table', f, owner['kernel']['tableName']],
                               table=owner['kernel']['tableName'])) for f in ('inet', 'bridge')}
        report['networkLease'] = lease_projection(owner, parse(journal_raw), tables)
        report['networkLease']['journalFileHash'] = sha(journal_raw)
        report['networkLease']['sourceMatchesByRole'] = {
            role: [i for i, flow in enumerate(owner['kernel']['providerFlows']) if flow['source'] in row['_addresses']]
            for role, row in report['roles'].items()}
        require(private(owner['journalFile']) == journal_raw, 'LEASE_JOURNAL_CHANGED_DURING_READ')
        require(lock_id == identity(os.fstat(fd)) == identity(Path(owner['commonLockFile']).lstat()), 'LOCK_IDENTITY_DRIFT')
    finally:
        os.close(fd)
    PHASE = 'READ_DECLARED_OUF_LEASE_SERVICE_NAMES'
    units = run(cfg['commandBindings'], 'systemctl', ['list-unit-files', '--type=service', '--no-legend', '--no-pager', 'ouf*'])
    names = [line.split()[0] for line in units.decode().splitlines() if line.split()]
    report['leaseServiceUnitNames'] = [name for name in names if re.fullmatch(r'ouf[A-Za-z0-9_.@-]*\.service', name)
                                      and ('lease' in name or 'coordinated' in name)]
    for row in report['roles'].values():
        row.pop('_addresses')
    PHASE = 'RECHECK_BOUND_READ_INPUTS'
    for path, raw in SAVED.items():
        require(private(path) == raw, 'BOUND_INPUT_CHANGED_DURING_READ')
    return report


def main():
    base = {'schema': 'ouf.semantic-r8-post-start-read-only.v1', 'containerLifecycleOperations': 0,
            'existingConfigurationWrites': 0, 'privateKeysRead': 0, 'signaturesIssued': 0,
            'providerCalls': 0, 'dnsQueries': 0, 'privateValuesPrinted': False,
            'startAuthorized': False, 'leaseGrantedHere': False, 'notReleaseAcceptance': True}
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv) == 1,
                'ISOLATED_ROOT_NO_ARGUMENT_READER_REQUIRED')
        result = {**base, **collect(), 'status': 'POST_START_FACTS_CAPTURED', 'phase': PHASE}
        code = 0
    except Exception as error:
        result = {**base, 'status': 'READ_FAILED', 'phase': PHASE, 'errorType': type(error).__name__,
                  'reason': str(error) if isinstance(error, ReadDenied) else 'POST_START_READ_UNPROVEN',
                  'contextDirectory': str(CONTEXT), 'evidenceDirectory': str(OUTPUT),
                  'exceptionPoints': [{'file': Path(t.filename).name, 'function': t.name, 'line': t.lineno}
                                      for t in traceback.extract_tb(error.__traceback__)[-4:]]}
        result.update(DIAGNOSIS)
        if isinstance(error, OSError):
            result['errno'] = error.errno
            if error.filename:
                result['inputFileName'] = Path(error.filename).name
        code = 1
    print('OUF_R8_POST_START_READ_ONLY=' + encoded(result).decode())
    return code



"""Read sealed shared ingress, current peer and lease; appended to the R8 reader.

No installed operational code is imported or executed. The only subprocesses
are source-bound Docker/nft reads and root-owned ip/nsenter metadata reads.
"""
import socket
import time

SEMANTIC_ID = '7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147'
SEMANTIC_IMAGE = 'sha256:f6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6'
SEMANTIC_FORMAT = ('{"id":{{json .Id}},"image":{{json .Image}},'
                   '"state":{{json .State}},"networks":{{json .NetworkSettings.Networks}}}')
READ_DEADLINE = None


def guard_footprint(value):
    if isinstance(value, list):
        return [guard_footprint(v) for v in value if not isinstance(v, dict) or 'metainfo' not in v]
    if isinstance(value, dict):
        return {k: guard_footprint(v) for k, v in value.items() if k not in ('handle', 'packets', 'bytes')}
    return value


def generation(pid):
    require(type(pid) is int and 1 < pid < 2147483647, 'LIVE_PID_REQUIRED')
    root = Path('/proc') / str(pid)
    def ticks():
        return int((root / 'stat').read_text().rsplit(')', 1)[1].split()[19])
    first = ticks()
    inode = (root / 'ns/net').stat().st_ino
    require(first == ticks(), 'PROCESS_GENERATION_CHANGED')
    return {'pid': pid, 'startTicks': first, 'namespaceInode': inode}


def native_read(binding, argv, allowed):
    require(argv in allowed, 'CUTOVER_READ_ONLY_COMMAND_SCOPE_REQUIRED')
    shape = (len(argv) == 6 and argv[:4] == ['-j', '-n', 'list', 'table']
             and argv[4] in ('inet', 'bridge') and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}', argv[5]))
    shape = shape or argv == ['inspect', '--type', 'container', '--format', SEMANTIC_FORMAT, SEMANTIC_ID]
    shape = shape or (len(argv) == 5 and argv[:4] == ['-j', 'link', 'show', 'dev']
                      and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,14}', argv[4]))
    shape = shape or (len(argv) == 5 and re.fullmatch('--net=/proc/[1-9][0-9]*/ns/net', argv[0])
                      and argv[1] in ('/usr/sbin/ip', '/usr/bin/ip', '/sbin/ip', '/bin/ip')
                      and argv[2:] == ['-j', 'addr', 'show'])
    require(shape, 'METADATA_ONLY_NATIVE_OPERATION_REQUIRED')
    private(binding['path'], binding['sha256'], executable=True)
    remaining = READ_DEADLINE - time.monotonic()
    require(remaining > 0, 'CUTOVER_READ_BUDGET_EXCEEDED')
    command = [binding['path'], *argv]
    if argv[0] == 'inspect':
        config_dir = OUTPUT / 'activation-docker-cli'
        info = config_dir.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o700 and not os.path.lexists(config_dir / 'config.json'),
                'EXISTING_EMPTY_ACTIVATION_CLI_DIRECTORY_REQUIRED')
        command = [binding['path'], '--config', str(config_dir), *argv]
    result = subprocess.run(command, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(remaining, 10),
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
             'DOCKER_HOST': 'unix:///var/run/docker.sock'})
    require(result.returncode == 0 and len(result.stdout) <= 2000000, 'CUTOVER_NATIVE_READ_FAILED')
    private(binding['path'], binding['sha256'], executable=True)
    return result.stdout


def peer_projection(raw, commands):
    require(raw['id'] == SEMANTIC_ID and raw['image'] == SEMANTIC_IMAGE and raw['state']['Running']
            and raw['state']['Status'] == 'running', 'CURRENT_SEMANTIC_GENERATION_DRIFT')
    gen = generation(raw['state']['Pid'])
    bindings = {}
    for name in ('ip', 'nsenter'):
        path = Path(commands[name])
        require(path.is_absolute() and '..' not in path.parts, 'TRUSTED_METADATA_EXECUTABLE_REQUIRED')
        executable = private(path, executable=True)
        bindings[name] = {'path': str(path), 'sha256': sha(executable)}
    args = ['--net=/proc/' + str(gen['pid']) + '/ns/net', bindings['ip']['path'], '-j', 'addr', 'show']
    children = parse(native_read(bindings['nsenter'], args, [args]))
    children = [v for v in children if v['ifname'] != 'lo']
    require(len(children) == 1, 'EXACT_SEMANTIC_BACKEND_NIC_REQUIRED')
    child = children[0]
    require(child['address'] == 'b2:96:a1:e2:c1:8d'
            and [a['local'] for a in child.get('addr_info', []) if a['family'] == 'inet'] == ['172.18.0.6'],
            'SEMANTIC_NIC_ADDRESS_DRIFT')
    index = child['link_index']
    require(type(index) is int and index == 1377, 'EXISTING_SIGNED_SEMANTIC_PEER_DRIFT')
    host_name = socket.if_indextoname(index)
    args = ['-j', 'link', 'show', 'dev', host_name]
    host = parse(native_read(bindings['ip'], args, [args]))
    require(len(host) == 1 and host[0]['ifindex'] == index
            and host[0]['link_index'] == child['ifindex'] and host[0]['master'] == 'br-113b5f0a3c53',
            'RECIPROCAL_SEMANTIC_BRIDGE_DRIFT')
    require(generation(gen['pid']) == gen, 'SEMANTIC_PROCESS_CHANGED_DURING_READ')
    return {'containerId': SEMANTIC_ID, 'imageId': SEMANTIC_IMAGE, 'generation': gen,
            'binding': {'interface': child['ifname'], 'bridge': host[0]['master'],
                        'mac': child['address'], 'ipv4': '172.18.0.6',
                        'childIfindex': child['ifindex'], 'hostIfindex': index, 'hostInterface': host_name},
            'metadataCommandBindings': bindings}


def collect_cutover():
    global PHASE, READ_DEADLINE
    PHASE = 'READ_ACTIVE_R8_AND_EXISTING_CUSTODY'
    retained = collect()
    READ_DEADLINE = time.monotonic() + 20
    cfg = parse(SAVED[str(CONTEXT / 'execution-configuration.json')])
    owner = parse(SAVED[str(GUARD / 'coordinated-configuration.json')])
    require(retained['networkLease']['journalAndMembershipConsistent'], 'CURRENT_LEASE_STATE_INCONSISTENT')
    nft_binding = cfg['commandBindings']['nft']
    role_data = {}
    PHASE = 'READ_EXACT_SHARED_DRIVERS_AND_JOURNALS'
    private(owner['commonLockFile'])
    fd = os.open(owner['commonLockFile'], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        lock_id = identity(os.fstat(fd))
        lease_raw = private(owner['journalFile'])
        for role, (cid, _) in TARGETS.items():
            root = OUTPUT / 'registry' / cid
            adapter_raw = private(root / 'adapter.json')
            adapter = parse(adapter_raw)
            require(sha(adapter_raw) == retained['roles'][role]['adapterJournalHash'], 'ADAPTER_JOURNAL_DRIFT')
            driver_raw = bound({'path': str(root / 'driver.json'), 'sha256': adapter['driverHash']})
            driver = parse(driver_raw)
            profile = driver['profile']
            require(profile['containerId'] == cid and driver['kernel'] == owner['kernel']
                    and driver['coordinationBinding'] == owner['binding']
                    and driver['coordinationJournal'] == owner['journalFile']
                    and driver['lockFile'] == owner['commonLockFile']
                    and driver['preexecJournal'] == str(root / 'preexec.json'), 'DRIVER_OWNER_CLOSURE_DRIFT')
            # Hash the exact complete OCI in memory; never disclose env or argv.
            bundle_path = Path(profile['bundlePath']) / 'config.json'
            require(bundle_path == root / 'bundle/config.json', 'EXACT_EXISTING_OCI_BUNDLE_REQUIRED')
            bundle_raw = private(bundle_path)
            SAVED[str(bundle_path)] = bundle_raw
            bundle = parse(bundle_raw)
            require(sha(encoded(bundle)) == profile['bundleHash'] == adapter['bundleHash'], 'FULL_OCI_PROFILE_BINDING_DRIFT')
            require(type(driver['sourceHashes']) is dict and 1 <= len(driver['sourceHashes']) <= 64,
                    'BOUNDED_DRIVER_SOURCE_CLOSURE_REQUIRED')
            for name, expected in driver['sourceHashes'].items():
                bound({'path': str(safe_source(Path(driver['sourceRoot']), name)), 'sha256': expected})
            journal_raw = private(root / 'preexec.json')
            journal = parse(journal_raw)
            require(journal['state'] == 'PROTECTED' and journal['configurationHash'] == sha(encoded(profile))
                    and journal['transactionId'] == profile['transactionId'], 'PROTECTED_PREEXEC_JOURNAL_REQUIRED')
            require(journal['containerGeneration'] == generation(retained['roles'][role]['pid']), 'SHARED_GUARD_GENERATION_DRIFT')
            table = profile['policy']['tableName']
            require(type(table) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}', table)
                    and table != owner['kernel']['tableName'], 'DISTINCT_SHARED_GUARD_REQUIRED')
            allowed = [['-j', '-n', 'list', 'table', f, table] for f in ('inet', 'bridge')]
            first = {f: parse(native_read(nft_binding, ['-j', '-n', 'list', 'table', f, table], allowed)) for f in ('inet', 'bridge')}
            second = {f: parse(native_read(nft_binding, ['-j', '-n', 'list', 'table', f, table], allowed)) for f in ('inet', 'bridge')}
            require(sha(encoded(structure(first))) == sha(encoded(structure(second))) == journal['sharedStructureHash']
                    and sha(encoded(guard_footprint(second))) == profile['expectedFootprint'], 'SHARED_NATIVE_STRUCTURE_DRIFT')
            ingress = [v for v in profile['policy']['flows'] if v['purpose'] == 'WORKLOAD_GATEWAY'
                       and v['source'] == '172.18.0.6' and v['destination'] == '172.18.0.14'
                       and v['protocol'] == 'tcp' and v['port'] == 10443]
            require(len(ingress) == (1 if role == 'southbound' else 0), 'EXACT_SEMANTIC_FLOW_SCOPE_REQUIRED')
            if ingress:
                require(ingress[0]['peerIngress'] == {'kind': 'BRIDGE_PORT', 'ifindex': 1377}, 'SIGNED_PEER_SCOPE_DRIFT')
            role_data[role] = {'containerId': cid, 'driverBinding': {'path': str(root / 'driver.json'), 'sha256': sha(driver_raw)},
                'profileHash': sha(encoded(profile)), 'policyHash': sha(encoded(profile['policy'])),
                'journalHash': sha(journal_raw), 'sharedTableName': table,
                'sharedStructureHash': journal['sharedStructureHash'], 'expectedFootprint': profile['expectedFootprint'],
                'fullOciHash': profile['bundleHash'], 'sourceClosureHash': sha(encoded(driver['sourceHashes'])),
                'transportAuthorityHash': sha(encoded(driver.get('authorityScope'))),
                'consumptionBindingHash': sha(encoded(driver.get('consumptionBinding'))),
                'attachmentCount': len(profile['policy']['attachments']), 'flowCount': len(profile['policy']['flows']),
                'semanticIngress': ingress, 'nativeStructureVerified': True}
            if role == 'southbound':
                PHASE = 'READ_CURRENT_SEMANTIC_RECIPROCAL_PEER'
                args = ['inspect', '--type', 'container', '--format', SEMANTIC_FORMAT, SEMANTIC_ID]
                semantic_before = native_read(cfg['commandBindings']['docker'], args, [args])
                semantic_peer = peer_projection(parse(semantic_before), driver['commands'])
                require(native_read(cfg['commandBindings']['docker'], args, [args]) == semantic_before,
                        'SEMANTIC_DOCKER_STATE_CHANGED')
            require(private(root / 'preexec.json') == journal_raw, 'PREEXEC_JOURNAL_CHANGED_DURING_READ')
        require(private(owner['journalFile']) == lease_raw, 'LEASE_JOURNAL_CHANGED_DURING_READ')
        require(lock_id == identity(os.fstat(fd)) == identity(Path(owner['commonLockFile']).lstat()), 'LOCK_IDENTITY_DRIFT')
    finally:
        os.close(fd)
    PHASE = 'RECHECK_READ_ONLY_SOURCE_AND_PROFILE_CUSTODY'
    for path, raw in SAVED.items():
        require(private(path) == raw, 'BOUND_CUTOVER_INPUT_CHANGED')
    return {'roles': role_data, 'currentSemanticPeer': semantic_peer, 'lease': retained['networkLease'],
            'ownerConfigurationHash': OWNER_HASH, 'leaseIngressSeparated': True,
            'missingBeforeApply': ['REPLACEMENT_COMPLETE_OCI_AND_RECIPROCAL_PEER',
                'NEW_HUMAN_TRANSITION_AUTHORITY_AND_SIGNED_TRANSPORT_CLOSURE',
                'MIGRATION_AWARE_APPLICATION_RECOVERY_AND_HOST_READINESS']}


def cutover_main():
    base = {'schema': 'ouf.discovery.cutover-private-input-read.v1', 'containerLifecycleOperations': 0,
            'existingConfigurationWrites': 0, 'firewallWrites': 0, 'privateKeysRead': 0,
            'providerCalls': 0, 'dnsQueries': 0, 'signaturesIssued': 0,
            'privateValuesPrinted': False, 'applyAuthorized': False, 'notReleaseAcceptance': True}
    base['readOnlyRetrySafe'] = True
    base['commonLockAcquired'] = False
    base['readConsistencyMode'] = 'STABLE_REREADS_NOT_ATOMIC_TRANSITION_AUTHORITY'
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv) == 1,
                'ISOLATED_ROOT_READ_ONLY_REQUIRED')
        result = {**base, **collect_cutover(), 'status': 'CUTOVER_INPUT_BINDINGS_CAPTURED', 'phase': PHASE}
        code = 0
    except Exception as error:
        result = {**base, 'status': 'READ_BLOCKED', 'phase': PHASE, 'errorType': type(error).__name__,
            'reason': str(error) if isinstance(error, ReadDenied) else 'CUTOVER_INPUT_UNPROVEN',
            'exceptionPoints': [{'file': Path(t.filename).name, 'function': t.name, 'line': t.lineno}
                                for t in traceback.extract_tb(error.__traceback__)[-5:]]}
        if isinstance(error, OSError):
            result['errno'] = error.errno
            if error.filename: result['inputFileName'] = Path(error.filename).name
        result.update(DIAGNOSIS)
        code = 1
    print('OUF_DISCOVERY_CUTOVER_INPUT_READ=' + encoded(result).decode())
    return code


if __name__ == '__main__':
    raise SystemExit(cutover_main())
