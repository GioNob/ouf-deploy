"""One new source-bound technical recovery of existing flows; never replays R10."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types

APPROVAL_REF = 'OUF_R10_RESILIENT_RECOVERY_OWNER_REQUEST_20261011T144318_CEST'
ISSUED_AT = 1791722598
EXECUTION_EXPIRES_AT = ISSUED_AT + 7200
UNIT = 'ouf-semantic-provider-lease-resilient-r12.service'
PYTHON = '/usr/bin/python3.13'
CLAIM = Path('/etc/ouf/provider-resilient-lease-recovery-r12.claim')
SNAPSHOT_BASE = Path('/etc/ouf/deploy-snapshots')
SNAPSHOT_PREFIX = 'semantic-resilient-lease-recovery-r12-'
PRIOR_ROOT = SNAPSHOT_BASE / 'semantic-finite-lease-recovery-r10-nw9ue4d5'
PRIOR_UNIT = 'ouf-semantic-provider-lease-finite-r10.service'
EXPECTED_PROCESSES = {
    'adapter': {'pid': 1826443, 'startedAt': '2026-10-09T19:10:21.87693854Z',
                'adapterJournalHash': 'd13db4342dc696f0b4c3fce72763de30ca993aa90eaacf38eb5501b392e2b4a7'},
    'southbound': {'pid': 1826422, 'startedAt': '2026-10-09T19:10:21.846292298Z',
                   'adapterJournalHash': '73b1a6e1acaa3f86e1f3e9ccab28455786c41245419d584a5f81961c20ddf772'}}
MODULE_HASHES = {'activation_core.py': '06d14a340db6d35a795115fd921f901e1cd0de74c06174562107270b08fc7c2a', 'reader.py': '589c3bb3faf10ae40d41bd441c201d5599071d55208c01092e0e6c6cf9aca9f9', 'bounded_recovery.py': 'ed126f33b17581ae784c82ce3f0ec8b16c266d5ad78481a1890385736bd61dfd', 'recovery_journal.py': '43a293ab9b4075401cfc139a6531f30fdae7277cbe096f10c0d460cd26ed291d', 'lease_recovery_budget.py': 'c4a70c54823934e8d0ede9a5dff52ec93e896826b36445f21048c9519e2aeedf', 'resilient_lease_adapter.py': 'beb09ee948ac2f5a39777b7a10339d6085bae09a90d94e8d95ec3ef940ac1683', 'adaptive_supervisor.py': '08a354cfbea6a31ed1ea21dd80ddab0d0f983e3a0143a6f656124cf843d5635c', 'nft_seconds_backend.py': '04cd115c756158ce2c04f32608380d7a40f4577d85785dfe46571825876545c1', 'deadline_backend.py': '9918af051a94e1a345a1cb6b73069444e73fdec0918b5494f79b52f8bb2537a2', 'continuous_supervisor.py': '8084748c0ffb5e009e8e59c4c5ecaaf08451fb2cc35540135e2db9a55d12ae0e', 'dns.py': 'f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f', 'readback_margin_compiler.py': '814b5321a5fe5772562f50aa17c34c99c2be741b6e2a9d26110a6b8991bdbf1d', 'target_bindings_r11.json': 'b99440a310d23ede9125936f51a3f8fb75ffcffb9dd2d37390c0b7e28c93e7b4', 'namespace_generation.py': 'f63fa6cac43560714de179f371706debf68a8b6e29dcdc4ce6197b607834fb14'}
LOAD_ORDER = ('bounded_recovery', 'recovery_journal', 'lease_recovery_budget',
              'resilient_lease_adapter', 'adaptive_supervisor', 'nft_seconds_backend',
              'deadline_backend', 'continuous_supervisor', 'dns', 'readback_margin_compiler', 'namespace_generation')
ROOT = None
CORE = None
PHASE = 'REQUIRE_NEW_SCOPED_TECHNICAL_RECOVERY'
R11_ROOT = SNAPSHOT_BASE/'semantic-resilient-lease-recovery-r11-1gpckuir'
R11_UNIT = 'ouf-semantic-provider-lease-resilient-r11.service'
R11_CLAIM = Path('/etc/ouf/provider-resilient-lease-recovery-r11.claim')
R11_ENTRY_HASH = '0cf3275fcd959da58a2b320de49b1059159da3da00fca611236e65c8d7136ad9'
R11_INCIDENT = '34b9533ea3d8931bb9971ef7fa3b2ad9f423d5504350faa63421869f79817a73'


def capture_namespace_bindings(reader, cfg, scope, generations):
    path = Path(__file__).parent/'namespace_generation.py'
    namespace = module('namespace_capture', component(path, MODULE_HASHES['namespace_generation.py']), path)
    result = {}
    for role, (cid, _) in reader.TARGETS.items():
        data = reader.parse(reader.run(cfg['commandBindings'], 'docker',
            ['inspect', '--type', 'container', '--format', reader.FORMAT, cid]))
        result[role] = namespace.capture(data, generations[role], reader.generation)
    reader.READ_DEADLINE = reader.CALL_DEADLINE
    args = ['inspect', '--type', 'container', '--format', reader.SEMANTIC_FORMAT, reader.SEMANTIC_ID]
    data = reader.parse(reader.native_read(cfg['commandBindings']['docker'], args, [args]))
    result['semantic'] = namespace.capture(data, scope['currentSemanticPeer']['generation'], reader.generation)
    return result


def verify_r11(reader, cfg, *, initial):
    reader.private(R11_ROOT/'activate.py', R11_ENTRY_HASH)
    auth = reader.parse(reader.private(R11_ROOT/'authorization.json'))
    require(auth['schema'] == 'ouf.provider-resilient-r11-authorization.v1'
            and auth['contextRef'] == R11_INCIDENT and auth['serviceUnit'] == R11_UNIT
            and auth['ownerConfigurationHash'] == reader.OWNER_HASH,
            'EXACT_CONSUMED_R11_AUTHORITY_REQUIRED')
    body = {k:v for k,v in auth.items() if k != 'contextRef'}
    require(sha(encoded(body)) == R11_INCIDENT, 'EXACT_CONSUMED_R11_CAPSULE_REQUIRED')
    for name, digest in auth['programHashes'].items(): reader.private(R11_ROOT/name, digest)
    require(reader.parse(reader.private(R11_CLAIM)) == auth['activationClaim'], 'EXACT_CONSUMED_R11_CLAIM_REQUIRED')
    props = properties(reader, cfg['commandBindings']['systemctl'], R11_UNIT)
    require(props.get('Restart') == 'no' and props.get('NRestarts') == '0', 'EXACT_CONSUMED_R11_SERVICE_REQUIRED')
    if initial or props.get('LoadState') == 'loaded':
        require(str(R11_ROOT/'activate.py') in props.get('ExecStart', ''), 'EXACT_CONSUMED_R11_SERVICE_REQUIRED')
    else:
        require(props.get('LoadState') == 'not-found', 'CONSUMED_R11_UNIT_STATE_UNPROVEN')
    if initial:
        row = reader.parse(reader.private(R11_ROOT/'retry/recovery.json'))
        status = reader.parse(reader.private(R11_ROOT/'worker-status.json'))
        require(row['state'] == status['state'] == 'BLOCKED'
                and row['contextRef'] == R11_INCIDENT and row['reason'] == 'GENERATION_CHANGED'
                and row['attempts'] == status['attempts'] == row['publicationCount'] == status['refreshCount'] == 0
                and status['setsRevoked'] is True
                and props.get('ActiveState') == 'active' and props.get('MainPID') == str(status['workerPid']),
                'EXACT_ZERO_ATTEMPT_BLOCKED_R11_REQUIRED')
        return row
    require(props.get('MainPID') == '0' and props.get('ActiveState') in {'inactive','failed'},
            'PREDECESSOR_R11_MUST_BE_STOPPED')


def stop_r11(reader, cfg):
    verify_r11(reader, cfg, initial=True)
    checked_command(reader, cfg['commandBindings']['systemctl'], ['stop', R11_UNIT], timeout=55)
    verify_r11(reader, cfg, initial=False)


def preclaim_guard(adapter):
    # Execute the ACTUAL production custody/scope guard under worker capabilities
    # before consuming a claim. No DNS, journal initialization or lease writes.
    import ctypes
    readfd, writefd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(readfd)
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            for number in range(64):
                if number != 12 and libc.prctl(24,number,0,0,0) != 0 and ctypes.get_errno() != 22:
                    raise OSError(ctypes.get_errno(), 'capability bounds')
            require(libc.prctl(38,1,0,0,0) == 0, 'PRECLAIM_NO_NEW_PRIVILEGES_REQUIRED')
            class Header(ctypes.Structure): _fields_ = [('version',ctypes.c_uint32),('pid',ctypes.c_int)]
            class Data(ctypes.Structure): _fields_ = [('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
            header = Header(0x20080522,0); data = (Data*2)()
            data[0].effective = data[0].permitted = 1 << 12
            require(libc.capset(ctypes.byref(header),data) == 0, 'PRECLAIM_CAPABILITY_DROP_REQUIRED')
            adapter.guard()
            result = {'passed':True}
        except Exception as error:
            code = str(error)
            result = {'passed':False,'reason':code if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',code) else 'PRECLAIM_GUARD_UNPROVEN'}
        os.write(writefd, encoded(result)); os._exit(0)
    os.close(writefd)
    import select
    if not select.select([readfd], [], [], 60)[0]:
        os.kill(pid, 9); os.waitpid(pid,0); os.close(readfd)
        raise ValueError('PRECLAIM_GUARD_TIMEOUT_NO_CLAIM_CREATED')
    raw = os.read(readfd, 65536); os.close(readfd)
    _, status = os.waitpid(pid, 0)
    require(status == 0 and raw, 'PRECLAIM_GUARD_PROCESS_UNPROVEN')
    result = json.loads(raw)
    require(result['passed'], result.get('reason', 'PRECLAIM_GUARD_UNPROVEN'))


def require(ok, code):
    if not ok: raise ValueError(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def approval_live(reference, clock=time.time):
    require(reference == APPROVAL_REF and not reference.startswith('PENDING')
            and ISSUED_AT <= clock() < EXECUTION_EXPIRES_AT <= ISSUED_AT + 7200,
            'NEW_SCOPED_TECHNICAL_RECOVERY_WINDOW_REQUIRED')


def component(path, expected):
    with Path(path).open('rb') as stream: raw = stream.read(131073)
    require(len(raw) <= 131072 and sha(raw) == expected, 'EXACT_SEALED_DELIVERY_BYTES_REQUIRED')
    return raw


def module(name, raw, path):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    sys.modules[name] = value
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def readers(directory):
    reader = module('resilient_target_reader',
                    component(directory/'reader.py', MODULE_HASHES['reader.py']),
                    directory/'reader.py')
    core = module('resilient_activation_core',
                  component(directory/'activation_core.py', MODULE_HASHES['activation_core.py']),
                  directory/'activation_core.py')
    return reader, core


def checked_command(reader, binding, args, *, timeout=20):
    reader.private(binding['path'], binding['sha256'], executable=True)
    value = subprocess.run([binding['path'], *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(value.returncode == 0 and len(value.stdout) <= 131072 and len(value.stderr) <= 131072,
            'SCOPED_NATIVE_COMMAND_UNPROVEN')
    reader.private(binding['path'], binding['sha256'], executable=True)
    return value.stdout


def properties(reader, systemctl, unit):
    args = ['show', unit, '--property=LoadState,ActiveState,SubState,MainPID,Restart,NRestarts,ExecStart']
    raw = checked_command(reader, systemctl, args, timeout=reader.transport_timeout(10))
    return dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)


def unit_absent(reader, systemctl):
    for subcommand in ('list-units', 'list-unit-files'):
        raw = checked_command(reader, systemctl,
            [subcommand, '--type=service', '--all', '--no-legend', '--no-pager'])
        require(not any(UNIT.encode() in line.split() for line in raw.splitlines()),
                'NEW_RECOVERY_UNIT_ALREADY_PRESENT')


def configuration(reader):
    human = reader.parse(reader.private(reader.CONTEXT/'human-approval-binding.json'))
    cfg = reader.parse(reader.private(reader.CONTEXT/'execution-configuration.json', human['configurationHash']))
    owner = reader.parse(reader.private(reader.GUARD/'coordinated-configuration.json', reader.OWNER_HASH))
    return cfg, owner


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', value),
            'CURRENT_HOST_BOOT_ID_REQUIRED')
    return value


def validate_current(current, scope, *, quiescent):
    require(current['ownerConfigurationHash'] == scope['ownerConfigurationHash']
            and current['leaseIngressSeparated'] is True
            and current['roles'] == scope['roles']
            and current['currentSemanticPeer'] == scope['currentSemanticPeer'],
            'CURRENT_INTAKE_BOUND_COHORT_OCI_PEER_DRIFT')
    lease = current['lease']
    require(lease['flowCount'] == len(lease['flows']) == 2
            and lease['nativeStructureVerified'] is True
            and lease['journalAndMembershipConsistent'] is True
            and lease['pollSeconds'] == 15
            and lease['sourceMatchesByRole'] == {'adapter': [0], 'southbound': [1]}
            and all(flow['leaseSeconds'] == 30 for flow in lease['flows']),
            'EXACT_CURRENT_TWO_FLOW_LEASE_STRUCTURE_REQUIRED')
    if quiescent:
        require(lease['journalState'] == 'QUIESCED' and lease['leaseAuthorized'] is False
                and lease['startAuthorized'] is False and lease['providerSetsEmpty'] is True
                and lease['journalFileHash'] == scope['quiescentJournalHash'],
                'CURRENT_INTAKE_BOUND_QUIESCENCE_REQUIRED')


def verify_prior(reader, scope):
    for name, expected in scope['retainedArtifactHashes'].items():
        path = Path(name) if name.startswith('/') else PRIOR_ROOT/name
        reader.private(path, expected)
    auth = reader.parse(reader.private(PRIOR_ROOT/'authorization.json',
                         scope['retainedArtifactHashes']['authorization.json']))
    require(auth['ownerConfigurationHash'] == scope['ownerConfigurationHash']
            and auth['serviceUnit'] == PRIOR_UNIT and auth['automaticRestart'] is False
            and auth['enableAtBoot'] is False and auth['containerLifecycleAuthorized'] is False,
            'EXACT_CONSUMED_R10_AUTHORITY_REQUIRED')
    for name, expected in auth['programHashes'].items(): reader.private(PRIOR_ROOT/name, expected)
    return auth


def validate_roles(report):
    require(set(report['roles']) == set(EXPECTED_PROCESSES), 'EXACT_CURRENT_ROLE_SET_REQUIRED')
    for role, expected in EXPECTED_PROCESSES.items():
        value = report['roles'][role]
        require(all(value[k] == v for k, v in expected.items())
                and value['running'] is True and value['status'] == 'running'
                and value['restartCount'] == 0 and value['matchesSuccessfulR8Journal'] is True,
                'CURRENT_ROLE_GENERATION_CHANGED_' + role.upper())


def current_intake(reader, scope):
    reader.CALL_DEADLINE = time.monotonic() + 60
    try:
        current = reader.collect_cutover()
        validate_current(current, scope, quiescent=True)
        validate_roles(reader.collect())
        cfg, owner = configuration(reader)
        verify_prior(reader, scope)
        prior = properties(reader, cfg['commandBindings']['systemctl'], PRIOR_UNIT)
        require(all(prior.get(k) == v for k, v in {
                'ActiveState': 'failed', 'MainPID': '0', 'Restart': 'no', 'NRestarts': '0'}.items()),
                'CONSUMED_R10_WORKER_STATE_CHANGED')
        require(owner['dns'] == {'resolvers': ['46.38.225.230', '46.38.252.230'], 'resolverPort': 53,
            'timeoutSeconds': 2, 'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1},
            'EXACT_EXISTING_DNS_PROFILE_REQUIRED')
        generations = {role: reader.generation(value['pid']) for role, value in EXPECTED_PROCESSES.items()}
        current['workerNamespaceBindings'] = capture_namespace_bindings(reader, cfg, scope, generations)
        return current, cfg, owner, generations
    finally:
        reader.CALL_DEADLINE = None


def load_worker_modules(reader, core, owner, directory, programs):
    modules, retained = core.load_installed(owner, reader.GUARD/'source', reader.private)
    loaded = {}
    for name in LOAD_ORDER:
        path = directory/(name + '.py')
        loaded[name] = module(name, reader.private(path, programs[path.name]), path)
    return modules, loaded, retained


def verify_live_peer(reader, cfg, peer, namespace, namespace_binding):
    # The root intake proved both ends. During supervision, preserve exact
    # process/netns generation, Docker attachment and reciprocal host veth.
    # No nsenter or CAP_SYS_ADMIN is required in the NET_ADMIN-only worker.
    reader.READ_DEADLINE = reader.CALL_DEADLINE
    args = ['inspect', '--type', 'container', '--format', reader.SEMANTIC_FORMAT, reader.SEMANTIC_ID]
    data = reader.parse(reader.native_read(cfg['commandBindings']['docker'], args, [args]))
    state = data['state']
    namespace.verify_metadata(data, namespace_binding)
    require(data['id'] == peer['containerId'] and data['image'] == peer['imageId']
            and state['Running'] is True and state['Status'] == 'running'
            and reader.generation(state['Pid']) == peer['generation'],
            'CURRENT_SEMANTIC_PROCESS_GENERATION_CHANGED')
    attachments = [row for row in data['networks'].values() if row.get('IPAddress')]
    require(len(attachments) == 1 and attachments[0]['IPAddress'] == peer['binding']['ipv4']
            and attachments[0]['MacAddress'] == peer['binding']['mac'],
            'CURRENT_SEMANTIC_NETWORK_ATTACHMENT_CHANGED')
    binding = peer['binding']
    args = ['-j', 'link', 'show', 'dev', binding['hostInterface']]
    host = reader.parse(reader.native_read(peer['metadataCommandBindings']['ip'], args, [args]))
    require(len(host) == 1 and host[0]['ifindex'] == binding['hostIfindex']
            and host[0]['link_index'] == binding['childIfindex'] and host[0]['master'] == binding['bridge']
            and 'UP' in host[0]['flags']
            and reader.generation(state['Pid']) == peer['generation'],
            'CURRENT_RECIPROCAL_HOST_PEER_CHANGED')


def runtime(reader, core, owner, cfg, scope, capsule, *, claimed=True):
    modules, loaded, retained = load_worker_modules(reader, core, owner, ROOT, capsule['programHashes'])
    cls = loaded['deadline_backend'].DeadlineNftBackend
    backend = cls([owner['nftPath']], owner['kernel'], owner['expectedStructureHash'], owner['readBudgetSeconds'])
    coordination = modules['semantic_provider_lease_coordination']
    owner_object = modules['semantic_provider_lease_owner'].LeaseOwner(owner['kernel'], owner['dns'], backend)
    journal = coordination.PrivateJournal(Path(owner['journalFile']))
    coordinator = coordination.Coordinator(owner_object, owner['binding'],
        lambda: coordination.hold_common_lock(Path(owner['commonLockFile'])), journal.read, journal.write)
    snapshot = {name: reader.private(ROOT/name, expected) for name, expected in capsule['programHashes'].items()}
    cfg_hash = sha(encoded(cfg))
    namespace = loaded['namespace_generation']
    ns_bindings = capsule['namespaceBindings']
    by_pid = {v['generation']['pid']: v for v in ns_bindings.values()}
    reader.generation = lambda pid: namespace.generation(by_pid[pid], pid)

    def custody():
        for name, raw in snapshot.items():
            require(reader.private(ROOT/name, capsule['programHashes'][name]) == raw,
                    'NEW_WORKER_PROGRAM_CUSTODY_CHANGED')
        reader.private(reader.GUARD/'coordinated-configuration.json', scope['ownerConfigurationHash'])
        for name, raw in retained.items():
            require(reader.private(reader.GUARD/'source'/name) == raw, 'RETAINED_OWNER_SOURCE_CHANGED')
        reader.private(owner['nftPath'], owner['nftSha256'], executable=True)

    def guard():
        deadline = backend.active_deadline
        reader.CALL_DEADLINE = deadline if deadline is not None else time.monotonic() + 20
        try:
            if os.path.lexists(ROOT/'revoked'):
                raise loaded['bounded_recovery'].Permanent('AUTHORITY_REVOKED')
            require(boot_id() == capsule['hostBootId'], 'HOST_BOOT_GENERATION_CHANGED')
            if claimed:
                require(reader.parse(reader.private(CLAIM)) == capsule['activationClaim'], 'NEW_RECOVERY_CLAIM_DRIFT')
            else:
                require(not os.path.lexists(CLAIM), 'NEW_RECOVERY_ALREADY_CONSUMED_DO_NOT_REPLAY')
            require(sha(encoded(configuration(reader)[0])) == cfg_hash, 'OWNER_COMMAND_CONFIGURATION_DRIFT')
            verify_prior(reader, scope)
            for role, (cid, image) in reader.TARGETS.items():
                data = reader.parse(reader.run(cfg['commandBindings'], 'docker',
                    ['inspect', '--type', 'container', '--format', reader.FORMAT, cid]))
                namespace.verify_metadata(data, ns_bindings[role])
                state = data['state']
                expected = EXPECTED_PROCESSES[role]
                require(data['id'] == cid and data['image'] == image
                        and data['runtime'] == 'ouf-semantic-admitted-v2'
                        and state['Running'] is True and state['Status'] == 'running'
                        and state['Pid'] == expected['pid'] and state['StartedAt'] == expected['startedAt']
                        and data['restartCount'] == 0
                        and reader.generation(state['Pid']) == capsule['roleGenerations'][role],
                        'CURRENT_ROLE_GENERATION_CHANGED')
                expected_role = scope['roles'][role]
                driver = reader.parse(reader.private(expected_role['driverBinding']['path'],
                                                     expected_role['driverBinding']['sha256']))
                profile = driver['profile']
                require(sha(encoded(profile)) == expected_role['profileHash']
                        and sha(encoded(driver['sourceHashes'])) == expected_role['sourceClosureHash'],
                        'CURRENT_SHARED_DRIVER_CHANGED')
                reader.private(Path(expected_role['driverBinding']['path']).parent/'preexec.json',
                               expected_role['journalHash'])
                bundle = reader.parse(reader.private(Path(profile['bundlePath'])/'config.json'))
                require(sha(encoded(bundle)) == expected_role['fullOciHash'], 'CURRENT_COMPLETE_OCI_CHANGED')
                for name, expected_hash in driver['sourceHashes'].items():
                    reader.private(reader.safe_source(Path(driver['sourceRoot']), name), expected_hash)
                table = expected_role['sharedTableName']
                args = [['-j', '-n', 'list', 'table', family, table] for family in ('inet', 'bridge')]
                reader.READ_DEADLINE = reader.CALL_DEADLINE
                tables = {family: reader.parse(reader.native_read(cfg['commandBindings']['nft'], argv, args))
                          for family, argv in zip(('inet', 'bridge'), args)}
                require(sha(encoded(reader.structure(tables))) == expected_role['sharedStructureHash']
                        and sha(encoded(reader.guard_footprint(tables))) == expected_role['expectedFootprint'],
                        'CURRENT_SHARED_NATIVE_GUARD_CHANGED')
            verify_r11(reader, cfg, initial=not claimed)
            peer = scope['currentSemanticPeer']
            verify_live_peer(reader, cfg, peer, namespace, ns_bindings['semantic'])
            prior = properties(reader, cfg['commandBindings']['systemctl'], PRIOR_UNIT)
            require(prior.get('MainPID') == '0' and prior.get('NRestarts') == '0',
                    'CONSUMED_R10_WORKER_RESTARTED')
        except loaded['bounded_recovery'].Permanent:
            raise
        except Exception as error:
            code = str(error)
            if isinstance(error, PermissionError): code = 'PROCESS_METADATA_PERMISSION_DENIED'
            elif not re.fullmatch('[A-Z][A-Z0-9_]{0,120}', code): code = 'LOCAL_SCOPE_UNPROVEN'
            raise loaded['bounded_recovery'].Permanent(code) from None
        finally:
            reader.CALL_DEADLINE = None

    adapter = loaded['continuous_supervisor'].RenewingLeaseAdapter(
        coordinator, loaded['dns'], loaded['readback_margin_compiler'],
        guard, custody, time.monotonic)
    journal = loaded['recovery_journal'].Journal(ROOT/'retry')
    recovery = loaded['lease_recovery_budget'].LeaseRecovery(
        journal, adapter, loaded['bounded_recovery'].Policy(),
        capsule['contextRef'], capsule['generationRef'],
        lambda: (time.time(), time.monotonic()), __import__('secrets').SystemRandom().random)
    return coordinator, loaded, recovery


def validate_capsule(reader, capsule):
    require(capsule['schema'] == 'ouf.provider-resilient-r12-authorization.v1'
            and capsule['approvalRef'] == APPROVAL_REF and capsule['serviceUnit'] == UNIT
            and capsule['ownerConfigurationHash'] == reader.OWNER_HASH
            and capsule['automaticRestart'] is False and capsule['enableAtBoot'] is False
            and capsule['containerLifecycleAuthorized'] is False
            and set(capsule['programHashes']) == {'activate.py', *MODULE_HASHES}
            and all(capsule['programHashes'][name] == expected for name, expected in MODULE_HASHES.items())
            and capsule['issuedAt'] == ISSUED_AT and capsule['executionExpiresAt'] == EXECUTION_EXPIRES_AT,
            'EXACT_NEW_SOURCE_BOUND_CAPSULE_REQUIRED')
    unsigned = {k: v for k, v in capsule.items() if k != 'contextRef'}
    require(sha(encoded(unsigned)) == capsule['contextRef'], 'NEW_RECOVERY_CONTEXT_HASH_UNPROVEN')
    require(capsule['generationRef'] == sha(encoded({
        'bootId': capsule['hostBootId'], 'roles': capsule['roleGenerations'],
        'peer': capsule['targetScope']['currentSemanticPeer']['generation']})),
        'NEW_RECOVERY_GENERATION_HASH_UNPROVEN')


def worker(path, expected_hash):
    global ROOT, CORE, PHASE
    ROOT = Path(path).parent
    require(ROOT.parent == SNAPSHOT_BASE and ROOT.name.startswith(SNAPSHOT_PREFIX),
            'EXACT_NEW_PRIVATE_SNAPSHOT_REQUIRED')
    reader, CORE = readers(ROOT)
    capsule = reader.parse(reader.private(path, expected_hash))
    validate_capsule(reader, capsule)
    approval_live(capsule['approvalRef'])
    for name, expected in capsule['programHashes'].items(): reader.private(ROOT/name, expected)
    scope = reader.parse(reader.private(ROOT/'target_bindings_r11.json', MODULE_HASHES['target_bindings_r11.json']))
    require(scope == capsule['targetScope'], 'NEW_RECOVERY_TARGET_SCOPE_DRIFT')
    require(reader.parse(reader.private(CLAIM)) == capsule['activationClaim'], 'NEW_CLAIM_BINDING_REQUIRED')
    # Exclusive before any lease transition, never recreated by restart.
    CORE.create(ROOT/'worker-invocation-claim.json', {
        'contextRef': capsule['contextRef'], 'pid': os.getpid(), 'hostBootId': boot_id()})
    cfg, owner = configuration(reader)
    coordinator, loaded, recovery = runtime(reader, CORE, owner, cfg, scope, capsule)
    stop = threading.Event()
    CORE.install_signal_handlers(stop)
    supervisor = loaded['continuous_supervisor'].Supervisor(recovery, coordinator, owner['pollSeconds'])
    baseline = {'schema': 'ouf.provider-resilient-worker-status.v1', 'workerPid': os.getpid(),
                'doNotRerunApply': True, 'notReleaseAcceptance': True,
                'startAuthorized': False, 'containerLifecycleOperations': 0,
                'providerCallsIssuedByWorker': 0, 'privateValuesPrinted': False}
    def observe(value):
        row = recovery.journal.read()
        count = row['publicationCount']
        current = {**baseline, **value, 'incidentRef': capsule['incidentRef'], 'status': 'LEASE_ACTIVE' if value['ready'] else 'LEASE_PAUSED',
                   'refreshCount': count, 'recoveryBudgetRemainingSeconds': max(0, recovery.remaining(row))}
        if value['ready']:
            with coordinator.hold_lock():
                lease = coordinator.journal()
                sets = coordinator.sets()
                if lease['state'] == 'LEASE_READY' and not any(sets):
                    raise loaded['bounded_recovery'].Temporary('DNS_WINDOW_TOO_SHORT', no_effect=True)
                require(lease['state'] == 'LEASE_READY' and lease['leaseAuthorized'] and all(sets),
                        'CURRENT_NATIVE_LEASE_READINESS_UNPROVEN')
                current['flowAddressCounts'] = [len(v) for v in sets]
        else:
            try:
                with coordinator.hold_lock():
                    lease = coordinator.journal()
                    current['setsRevoked'] = lease['state'] == 'QUIESCED' and not any(coordinator.sets())
            except Exception:
                current['setsRevoked'] = False
        for number in (1, 2):
            if value['ready'] and count >= number and not (ROOT/('cycle-' + str(number) + '.json')).exists():
                CORE.create(ROOT/('cycle-' + str(number) + '.json'), current)
        CORE.status(ROOT, current)
    PHASE = 'SUPERVISE_NEW_OWNER_WITH_FINITE_DURABLE_RECOVERY'
    try:
        final = supervisor.serve(stop, observe)
        observe({ 'state': final['state'], 'reason': final['reason'], 'attempts': final['attempts'],
                  'renewals': supervisor.renewals, 'incidentRef': recovery.context, 'ready': False, 'live': False })
        return 0
    except Exception as error:
        value = {**baseline, 'status': 'LEASE_WORKER_FAILED', 'phase': PHASE, **CORE.diagnosis(error)}
        CORE.create(ROOT/'worker-denial.json', value)
        CORE.status(ROOT, value)
        return 1


def wait_result(reader, coordinator, systemctl, *, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = reader.parse(reader.private(ROOT/'worker-status.json'))
            props = properties(reader, systemctl, UNIT)
            require(props.get('ActiveState') == 'active' and props.get('SubState') == 'running'
                    and props.get('Restart') == 'no' and props.get('NRestarts') == '0'
                    and props.get('MainPID') == str(value.get('workerPid'))
                    and str(ROOT/'activate.py') in props.get('ExecStart', ''),
                    'CURRENT_NEW_SERVICE_PROCESS_UNPROVEN')
            if value.get('ready') is True and value.get('refreshCount', 0) >= 2:
                with coordinator.hold_lock():
                    lease = coordinator.journal()
                    sets = coordinator.sets()
                    require(lease['state'] == 'LEASE_READY' and lease['leaseAuthorized'] and all(sets),
                            'CURRENT_TWO_FLOW_LEASE_UNPROVEN')
                return value, True
            if value.get('state') in {'BLOCKED', 'RECONCILE_REQUIRED', 'PAUSED_EXHAUSTED'}:
                return value, False
        except FileNotFoundError:
            pass
        if (ROOT/'worker-denial.json').exists():
            raise ValueError('NEW_WORKER_STARTUP_FAILED_READ_RETAINED_DENIAL')
        time.sleep(.1)
    value = reader.parse(reader.private(ROOT/'worker-status.json'))
    require(value.get('state') == 'RETRY_WAIT' and value.get('setsRevoked') is True,
            'NEW_WORKER_PAUSE_READBACK_UNPROVEN')
    return value, False


def apply(reference):
    global ROOT, CORE, PHASE
    approval_live(reference)
    require(not os.path.lexists(CLAIM), 'NEW_RECOVERY_ALREADY_CONSUMED_DO_NOT_REPLAY')
    source = Path(__file__).absolute()
    raw = globals().get('__verified_source_bytes__')
    require(type(raw) is bytes and len(raw) <= 131072, 'VERIFIED_IN_MEMORY_ENTRYPOINT_REQUIRED')
    delivery = {name: component(source.parent/name, expected) for name, expected in MODULE_HASHES.items()}
    reader, CORE = readers(source.parent)
    scope = reader.parse(delivery['target_bindings_r11.json'])
    PHASE = 'RECHECK_CURRENT_INTAKE_WITHOUT_LEASE_AUTHORITY'
    current, cfg, owner, generations = current_intake(reader, scope)
    unit_absent(reader, cfg['commandBindings']['systemctl'])
    native = {name: {'path': path, 'sha256': sha(reader.private(path, executable=True))}
              for name, path in [('systemd-run', '/usr/bin/systemd-run'), ('python', PYTHON)]}
    checked_command(reader, native['systemd-run'], ['--version'])
    # Fresh intake twice; no claim is created after an unproven/drifting read.
    predecessor = verify_r11(reader, cfg, initial=True)
    second, _, second_owner, second_generations = current_intake(reader, scope)
    require(second == current and second_owner == owner and second_generations == generations,
            'CURRENT_BINDINGS_CHANGED_BEFORE_NEW_CLAIM')
    approval_live(reference)
    ROOT = Path(tempfile.mkdtemp(prefix=SNAPSHOT_PREFIX, dir=SNAPSHOT_BASE))
    ROOT.chmod(0o700)
    claim = {'schema': 'ouf.provider-resilient-r12-activation-claim.v1', 'approvalRef': reference,
             'directory': str(ROOT), 'startAuthorized': False}
    programs = {'activate.py': raw, **delivery}
    for name, data in programs.items(): CORE.create(ROOT/name, data)
    capsule = {'schema': 'ouf.provider-resilient-r12-authorization.v1', 'approvalRef': reference,
        'serviceUnit': UNIT, 'ownerConfigurationHash': reader.OWNER_HASH, 'targetScope': scope,
        'programHashes': {name: sha(data) for name, data in programs.items()},
        'namespaceBindings': current['workerNamespaceBindings'], 'incidentRef': R11_INCIDENT,
        'predecessorRecovery': predecessor, 'activationClaim': claim, 'issuedAt': ISSUED_AT, 'executionExpiresAt': EXECUTION_EXPIRES_AT,
        'hostBootId': boot_id(), 'roleGenerations': generations, 'automaticRestart': False,
        'enableAtBoot': False, 'containerLifecycleAuthorized': False, 'notReleaseAcceptance': True,
        'authorityLifetime': 'CURRENT_BOUND_ROLE_PEER_AND_HOST_GENERATIONS_UNTIL_STOP_OR_REVOCATION',
        'nativeBindings': native}
    capsule['generationRef'] = sha(encoded({'bootId': capsule['hostBootId'], 'roles': generations,
        'peer': scope['currentSemanticPeer']['generation']}))
    capsule['contextRef'] = sha(encoded(capsule))
    CORE.create(ROOT/'authorization.json', capsule)
    CORE.create(ROOT/'before.json', current)
    retry_root = ROOT/'retry'; retry_root.mkdir(mode=0o700)
    PHASE = 'VERIFY_ACTUAL_GUARD_NET_ADMIN_ONLY_BEFORE_CLAIM'
    _, _, preflight = runtime(reader, CORE, owner, cfg, scope, capsule, claimed=False)
    preclaim_guard(preflight.adapter)
    CORE.create(ROOT/'preclaim-guard.json', {'actualProductionGuardPassed': True,
        'netAdminOnly': True, 'noNewPrivileges': True, 'claimCreatedBeforeProbe': False})
    CORE.create(CLAIM, claim)
    stop_r11(reader, cfg)
    coordinator, loaded, recovery = runtime(reader, CORE, owner, cfg, scope, capsule)
    initial = recovery.initial()
    for key in ('startedWall', 'startedMonotonic', 'attempts', 'healthyWallSeconds', 'healthyMonotonicSeconds'):
        initial[key] = predecessor[key]
    recovery.journal.initialize(initial)
    with coordinator.hold_lock():
        require(sha(encoded(coordinator.journal())) == scope['quiescentJournalHash']
                and not any(coordinator.sets()), 'CURRENT_QUIESCENCE_CHANGED_BEFORE_START')
    PHASE = 'SUBMIT_NEW_SCOPED_WORKER_ONCE'
    argv = CORE.service_command(ROOT, sha(encoded(capsule)), unit=UNIT, python=native['python']['path'])
    CORE.create(ROOT/'service-command.json', {'argv': argv, 'nativeBindings': native})
    for binding in native.values(): reader.private(binding['path'], binding['sha256'], executable=True)
    submitted = False
    try:
        submitted = True
        checked_command(reader, native['systemd-run'], argv[1:])
        PHASE = 'OBSERVE_NEW_WORKER_AND_NATIVE_LEASES'
        status, ready = wait_result(reader, coordinator, cfg['commandBindings']['systemctl'])
        result = {'schema': 'ouf.provider-resilient-r12-activation.v1',
            'status': 'TWO_FLOW_RESILIENT_LEASE_ACTIVE_AND_RENEWED' if ready else 'RESILIENT_WORKER_PARKED_REQUIRES_ATTENTION',
            'evidenceDirectory': str(ROOT), 'serviceUnit': UNIT, 'workerState': status['state'],
            'refreshCount': status['refreshCount'], 'recoveryAttempts': status['attempts'], 'workerReason': status['reason'],
            'incidentRef': status['incidentRef'], 'r11ConsumedClaimPreserved': True, 'ownerConfigurationHash': reader.OWNER_HASH,
            'flowAddressCounts': status.get('flowAddressCounts', [0, 0]),
            'externalTrafficNowPermittedForApprovedFlows': ready, 'doNotRerunApply': True,
            'r10ConsumedClaimPreserved': True, 'containerLifecycleOperations': 0,
            'automaticRestart': False, 'bootEnablement': False, 'privateKeysRead': 0,
            'signaturesIssued': 0, 'providerCallsIssuedByWorker': 0, 'applicationHealthProven': False,
            'notReleaseAcceptance': True, 'privateValuesPrinted': False}
        CORE.create(ROOT/'activation-receipt.json', result)
        return result
    except Exception:
        if submitted:
            try:
                props = properties(reader, cfg['commandBindings']['systemctl'], UNIT)
                require(str(ROOT/'activate.py') in props.get('ExecStart', ''), 'FOREIGN_SERVICE_PRESERVED')
                checked_command(reader, cfg['commandBindings']['systemctl'], ['stop', UNIT], timeout=55)
            except Exception as error:
                CORE.create(ROOT/'cleanup-denial.json', CORE.diagnosis(error))
        raise


def main():
    os.umask(0o077)
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_REQUIRED')
        if len(sys.argv) == 4 and sys.argv[1] == '--supervise':
            return worker(sys.argv[2], sys.argv[3])
        require(len(sys.argv) == 3 and sys.argv[1] == '--apply', 'EXACT_NEW_RECOVERY_ACTION_REQUIRED')
        result = apply(sys.argv[2])
        print('OUF_RESILIENT_R12_ACTIVATION=' + json.dumps(result, sort_keys=True))
        return 0 if result['externalTrafficNowPermittedForApprovedFlows'] else 2
    except Exception as error:
        reason = str(error)
        value = {'schema': 'ouf.provider-resilient-r12-activation.v1', 'status': 'NEW_RESILIENT_RECOVERY_DENIED',
                 'phase': PHASE, 'reason': reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}', reason) else 'RECOVERY_UNPROVEN',
                 'errorType': type(error).__name__, 'evidenceDirectory': str(ROOT) if ROOT else None,
                 'doNotRerunApply': os.path.lexists(CLAIM), 'r10Touched': False,
                 'containerLifecycleOperations': 0, 'privateValuesPrinted': False, 'notReleaseAcceptance': True}
        if CORE: value.update(CORE.diagnosis(error))
        if ROOT and CORE:
            try: CORE.create(ROOT/'operator-denial.json', value)
            except Exception: pass
        print('OUF_RESILIENT_R12_ACTIVATION=' + json.dumps(value, sort_keys=True))
        return 1


if __name__ == '__main__': sys.exit(main())
