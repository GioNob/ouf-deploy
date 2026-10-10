"""Distinct finite-lease R10 recovery; inert until a NEW scoped human decision is bound."""
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

APPROVAL_REF = 'OUF_FINITE_LEASE_R10_DELEGATED_RECOVERY_20261010T204700_CEST'
ISSUED_AT = 1791658020
EXECUTION_EXPIRES_AT = 1791665220
READER_HASH = '4ddfda694150771fc8059ce22080a44c1d42db80c4f85b6b42f85c46442536d2'
NFT_HASH = 'b088f4e2338991ac92e0abf879360dc3e6bbf52214f7d8e42dc3732ed25fe3a6'
SUPERVISOR_HASH = '08a354cfbea6a31ed1ea21dd80ddab0d0f983e3a0143a6f656124cf843d5635c'
OLD_NFT_HASH = '7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93'
OLD_SUPERVISOR_HASH = '25a952c9f6d1385ce7759ef61666d25c7ec24a5735d3d0d27c36ade8e1614dad'
NFT_BINARY_HASH = '57bdb96c8a48844ddd6dd469c267cda951b9a466be93d254c928891ed8c3b7f0'
CORE_HASH = 'a56abdae8737274c93b1e59315cfa7cb1f68e6459e0da8bcecba3ebf279a12b1'
COMPILER_HASH = 'c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079'
OLD_COMPILER_HASH = '1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084'
EXISTING_READER = Path(__file__).absolute().parent/'reader.py'
DNS_HASH = 'f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f'
OLD_DNS_HASH = 'c466172113d1ffe850bf2c69762113b55fbc65d9091c96dca98a74548fddf930'
SNAPSHOT_BASE = Path('/etc/ouf/deploy-snapshots')
OLD_UNIT = 'ouf-semantic-provider-lease-dns-r9.service'
OLD_APPROVAL = 'OUF_DNS_WINDOW_RECOVERY_R9_APPROVED_20261010T075611_CEST'
PRIOR_CLAIM_HASH = 'a251c0d9b17636267dbf7d966d4717df4c168b2884c30bcfc80afd2471595b6d'
PRIOR_STATUS_HASH = 'd3613b21946b8181a9abbe6fe7d89214669e658bba0e66b9bc53d8d9346d631f'
CLAIM = Path('/etc/ouf/provider-finite-lease-recovery-r10.claim')
PRIOR_CLAIM = Path('/etc/ouf/provider-dns-window-recovery-r9.claim')
PRIOR_ROOT = Path('/etc/ouf/deploy-snapshots/semantic-dns-recovery-r9-hkv5exgo')
PRIOR_AUTH_HASH = '400d4e2bd7c0e638960eb144dad69a3ab4a35f6e1c6d39e114033a371c30d3a9'
PRIOR_RECEIPT_HASH = '12473d3e30ee6f143bd742abf10359682ac3eeb563587dff55ade920de9f3d23'
UNIT = 'ouf-semantic-provider-lease-finite-r10.service'
JOURNAL_HASH = 'a58f0cb6e011879fc22723356d19926adf8945c38dcdbf2d21ab3fa34dd6f7f1'
EXPECTED = {
    'adapter': {'pid': 1826443, 'startedAt': '2026-10-09T19:10:21.87693854Z',
                'adapterJournalHash': 'd13db4342dc696f0b4c3fce72763de30ca993aa90eaacf38eb5501b392e2b4a7'},
    'southbound': {'pid': 1826422, 'startedAt': '2026-10-09T19:10:21.846292298Z',
                   'adapterJournalHash': '73b1a6e1acaa3f86e1f3e9ccab28455786c41245419d584a5f81961c20ddf772'}}
FLOW_HASHES = [
    {'endpointHash': '7eb565c4d0399ecb90a080007a8a9dc4bf21eaf0c6a09ffa9bf12b00bd60d5fc',
     'endpointRefHash': '5569bba62cf88f212353d19b2dfc6a2628febcc414258bdd1e081771f1ce04ff',
     'sourceHash': 'baab4746ca334ea17bc7c52ab0cb00c2f8c1f6195d25ff7fa96c733d9a45fab3'},
    {'endpointHash': '4859b6573326119ae26658c8fefeb8cfc05841601a68a37e32ad863c06d2cbed',
     'endpointRefHash': 'bb46dea65bf5662fda3e1b2339065e3ef2bfe67d67ee64dd076dc26e916fdcae',
     'sourceHash': 'c41d7c528e74fcd055b095d7166eaf67738ffe9e8701376e30315a269f097445'}]
PHASE = 'REQUIRE_EXPLICIT_LEASE_APPROVAL'
ROOT = None
CORE = None


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def component_bytes(path, expected):
    with Path(path).open('rb') as stream:
        raw = stream.read(131073)
    require(len(raw) <= 131072 and sha(raw) == expected, 'EXACT_DELIVERY_COMPONENT_HASH_REQUIRED')
    return raw


def load_component(name, path, expected):
    raw = component_bytes(path, expected)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, raw


def approval_live(reference, clock=time.time):
    require(not APPROVAL_REF.startswith('PENDING') and reference == APPROVAL_REF
            and type(ISSUED_AT) is int and type(EXECUTION_EXPIRES_AT) is int
            and 0 < ISSUED_AT <= clock() < EXECUTION_EXPIRES_AT <= ISSUED_AT + 7200,
            'EXPLICIT_NEW_FINITE_LEASE_R10_APPROVAL_REQUIRED')


def validate_report(report):
    require(set(report['roles']) == set(EXPECTED), 'EXACT_TWO_R8_ROLES_REQUIRED')
    for role, expected in EXPECTED.items():
        row = report['roles'][role]
        require(all(row[k] == v for k, v in expected.items()) and row['running'] is True
                and row['status'] == 'running' and row['restartCount'] == 0 and row['exitCode'] == 0
                and row['errorPresent'] is False and row['matchesSuccessfulR8Journal'] is True,
                'REVIEWED_R8_PROCESS_GENERATION_DRIFT_' + role.upper())
    lease = report['networkLease']
    require(lease['journalFileHash'] == JOURNAL_HASH and lease['journalState'] == 'QUIESCED'
            and lease['leaseAuthorized'] is False and lease['providerSetsEmpty'] is True
            and lease['journalAndMembershipConsistent'] is True and lease['pollSeconds'] == 15
            and lease['sourceMatchesByRole'] == {'adapter': [0], 'southbound': [1]},
            'REVIEWED_QUIESCENT_OWNER_GENERATION_REQUIRED')
    require(lease['flowCount'] == len(lease['flows']) == 2, 'EXACT_TWO_FLOW_SCOPE_REQUIRED')
    for row, expected in zip(lease['flows'], FLOW_HASHES):
        require(all(row[k] == v for k, v in expected.items()) and row['leaseSeconds'] == 30,
                'REVIEWED_TWO_FLOW_SCOPE_DRIFT')
    require(set(report['leaseServiceUnitNames']) <= {OLD_UNIT, 'ouf-semantic-provider-lease-r8.service'}, 'EXISTING_LEASE_SERVICE_REQUIRES_RECONCILIATION')


def command(argv, timeout=20):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(len(result.stdout) <= 131072 and len(result.stderr) <= 131072, 'NATIVE_OUTPUT_UNBOUNDED')
    if result.returncode:
        error = ValueError('NATIVE_SERVICE_COMMAND_FAILED')
        error.native_diagnosis = {'commandName': Path(argv[0]).name, 'subcommand': argv[1] if len(argv) > 1 else None,
                                  'exitCode': result.returncode, 'stdoutSha256': sha(result.stdout), 'stdoutBytes': len(result.stdout),
                                  'stderrSha256': sha(result.stderr), 'stderrBytes': len(result.stderr)}
        raise error
    return result.stdout


def require_unit_absent(unit):
    # With an exact nonmatching pattern, list-unit-files may return exit 1
    # with no stderr. Enumerate both inventories without a name pattern and
    # check exact membership ourselves; genuine command errors remain fatal.
    for subcommand in ('list-units', 'list-unit-files'):
        names = command(['/usr/bin/systemctl', subcommand, '--type=service',
                         '--all', '--no-legend', '--no-pager'])
        require(not any(unit.encode() in line.split() for line in names.splitlines()),
                'LEASE_UNIT_NAME_ALREADY_OWNED')


def native_program(reader, path):
    raw = reader.private(path, executable=True)
    return {'path': str(path), 'sha256': sha(raw)}


def configuration(reader):
    human = reader.parse(reader.private(reader.CONTEXT/'human-approval-binding.json'))
    cfg = reader.parse(reader.private(reader.CONTEXT/'execution-configuration.json', human['configurationHash']))
    owner = reader.parse(reader.private(reader.GUARD/'coordinated-configuration.json', reader.OWNER_HASH))
    return cfg, owner


def service_read(reader, binding, args):
    # The cutover reader's native_read accepts only network metadata and has
    # its own cutover deadline. Keep service probes in a separate exact scope.
    allowed = [
        ['show', OLD_UNIT, '--property=LoadState,ActiveState,SubState,MainPID,Restart,NRestarts,InvocationID,ExecStart'],
        ['list-units', '--type=service', '--all', '--no-legend', '--no-pager']]
    require(args in allowed and binding['path'] == '/usr/bin/systemctl',
            'EXACT_READ_ONLY_SERVICE_PROBE_REQUIRED')
    reader.private(binding['path'], binding['sha256'], executable=True)
    raw = command([binding['path'], *args])
    reader.private(binding['path'], binding['sha256'], executable=True)
    return raw


def validate_prior(reader):
    """Preserve the consumed R9 claim, authorization and failure unchanged."""
    claim_raw = reader.private(PRIOR_CLAIM, PRIOR_CLAIM_HASH)
    require(reader.parse(claim_raw) == {'schema': 'ouf.provider-dns-recovery-activation-claim.v1',
        'approvalRef': OLD_APPROVAL, 'directory': str(PRIOR_ROOT), 'startAuthorized': False},
        'EXACT_CONSUMED_R9_CLAIM_REQUIRED')
    auth_raw = reader.private(PRIOR_ROOT/'authorization.json', PRIOR_AUTH_HASH)
    auth = reader.parse(auth_raw)
    require(auth['approvalRef'] == OLD_APPROVAL and auth['serviceUnit'] == OLD_UNIT
            and auth['ownerConfigurationHash'] == reader.OWNER_HASH and auth['automaticRestart'] is False
            and auth['enableAtBoot'] is False and auth['containerLifecycleAuthorized'] is False,
            'EXACT_CONSUMED_R9_AUTHORITY_REQUIRED')
    require(set(auth['programHashes']) == {'activate.py','activation_core.py','reader.py',
            'materialize_southbound_lease_refresh.py','dns.py'}, 'EXACT_RETAINED_R9_CLOSURE_REQUIRED')
    for name, expected in auth['programHashes'].items(): reader.private(PRIOR_ROOT/name, expected)
    receipt_raw = reader.private(PRIOR_ROOT/'activation-receipt.json', PRIOR_RECEIPT_HASH)
    receipt = reader.parse(receipt_raw)
    require(receipt['status'] == 'TWO_FLOW_LEASE_ACTIVE_AND_RENEWED' and receipt['doNotRerunApply'] is True
            and receipt['serviceUnit'] == OLD_UNIT, 'RETAINED_R9_ACTIVATION_REQUIRED')
    status_raw = reader.private(PRIOR_ROOT/'worker-status.json', PRIOR_STATUS_HASH)
    status = reader.parse(status_raw)
    require(status['status'] == 'LEASE_WORKER_FAILED' and status['refreshCount'] == 795
            and [row['reason'] for row in status['exceptionChain']] == ['NFT_SET_TTL_UNPROVEN'],
            'EXACT_RETAINED_R9_TTL_FAILURE_REQUIRED')
    cfg, owner = configuration(reader)
    require(owner['nftSha256'] == NFT_BINARY_HASH
            and owner['sourceHashes']['tools/semantic_provider_lease_nft.py'] == OLD_NFT_HASH
            and owner['sourceHashes']['tools/semantic_provider_coordinated_supervisor.py'] == OLD_SUPERVISOR_HASH,
            'TARGET_QUALIFIED_SECONDS_BACKEND_DELTA_REQUIRED')
    args = ['show', OLD_UNIT, '--property=LoadState,ActiveState,SubState,MainPID,Restart,NRestarts,InvocationID,ExecStart']
    raw = service_read(reader, cfg['commandBindings']['systemctl'], args)
    old = dict(line.split('=',1) for line in raw.decode().splitlines() if '=' in line)
    require(all(old.get(k) == v for k,v in {'LoadState':'loaded','ActiveState':'failed',
        'SubState':'failed','MainPID':'0','Restart':'no','NRestarts':'0',
        'InvocationID':'ba95ba7239664789ac68430107ac6dc8'}.items())
        and str(PRIOR_ROOT/'activate.py') in old.get('ExecStart',''), 'CONSUMED_R9_WORKER_QUIESCENCE_DRIFT')
    raw = service_read(reader, cfg['commandBindings']['systemctl'],
                       ['list-units','--type=service','--all','--no-legend','--no-pager'])
    names = {line.split()[0] for line in raw.decode().splitlines() if line.split()}
    require({n for n in names if n.startswith('ouf') and 'lease' in n}
            <= {OLD_UNIT,'ouf-semantic-provider-lease-r8.service'}, 'OTHER_LOADED_LEASE_WORKER_REQUIRES_RECONCILIATION')
    for path, expected, retained in ((PRIOR_CLAIM,PRIOR_CLAIM_HASH,claim_raw),
        (PRIOR_ROOT/'authorization.json',PRIOR_AUTH_HASH,auth_raw),
        (PRIOR_ROOT/'activation-receipt.json',PRIOR_RECEIPT_HASH,receipt_raw),
        (PRIOR_ROOT/'worker-status.json',PRIOR_STATUS_HASH,status_raw)):
        require(reader.private(path,expected) == retained,'CONSUMED_R9_EVIDENCE_CHANGED')
    return claim_raw

def plan():
    """Stable read-only preflight, without executing installed operational code."""
    global PHASE
    PHASE = 'READ_NEW_DNS_RECOVERY_PRECONDITIONS_WITHOUT_LOCK_OR_AUTHORITY'
    source = Path(__file__).absolute()
    self_raw = globals().get('__verified_source_bytes__')
    require(isinstance(self_raw, bytes), 'VERIFIED_IN_MEMORY_ENTRYPOINT_REQUIRED')
    reader, reader_raw = load_component('dns_recovery_reader', source.parent/'reader.py', READER_HASH)
    delivery = {'activate.py': sha(self_raw), 'reader.py': sha(reader_raw)}
    for delivered, retained, expected in (
            ('activation_core.py', 'activation_core.py', CORE_HASH),
            ('dns.py', 'dns.py', DNS_HASH),
            ('materialize_southbound_lease_refresh.py', 'materialize_southbound_lease_refresh.py', COMPILER_HASH),
            ('nft.py', 'nft.py', NFT_HASH), ('supervisor.py', 'supervisor.py', SUPERVISOR_HASH)):
        delivery[retained] = sha(component_bytes(source.parent/delivered, expected))
    require(not os.path.lexists(CLAIM), 'LEASE_ACTIVATION_ALREADY_CLAIMED_DO_NOT_REPLAY')
    report = reader.collect()
    validate_report(report)
    validate_prior(reader)
    cfg, owner = configuration(reader)
    require(owner['sourceHashes']['tools/semantic_provider_dns.py'] == OLD_DNS_HASH
            and owner['sourceHashes']['tools/materialize_southbound_lease_refresh.py'] == OLD_COMPILER_HASH,
            'EXACT_ORIGINAL_SOURCE_DELTA_REQUIRED')
    require(owner['dns'] == {'resolvers': ['46.38.225.230', '46.38.252.230'], 'resolverPort': 53,
            'timeoutSeconds': 2, 'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1}, 'EXISTING_BOUNDED_DNS_PROFILE_REQUIRED')
    require_unit_absent(UNIT)
    validate_report(reader.collect())
    validate_prior(reader)
    return {'schema': 'ouf.provider-finite-lease-recovery-plan.v1', 'status': 'FINITE_LEASE_R10_PRECONDITIONS_CAPTURED',
        'programHashes': delivery, 'ownerConfigurationHash': reader.OWNER_HASH,
        'expectedJournalHash': JOURNAL_HASH, 'proposedClaimPath': str(CLAIM), 'proposedServiceUnit': UNIT,
        'applyAuthorized': False, 'newHumanDecisionRequired': True, 'readOnlyRetrySafe': True,
        'commonLockAcquired': False, 'existingConfigurationWrites': 0, 'firewallWrites': 0,
        'dnsQueries': 0, 'providerCalls': 0, 'privateKeysRead': 0, 'signaturesIssued': 0,
        'containerLifecycleOperations': 0, 'notReleaseAcceptance': True,
        'readConsistencyMode': 'STABLE_REREADS_NOT_ATOMIC_TRANSITION_AUTHORITY'}


def runtime(reader, core, cfg, owner, capsule):
    override = capsule['leaseCompilerBinding'] if capsule else None
    modules, source_bytes = core.load_installed(owner, reader.GUARD/'source', reader.private, override,
                                                capsule['dnsBinding'] if capsule else None,
        capsule['nftBinding'] if capsule else None, capsule['supervisorBinding'] if capsule else None)
    nft = modules['semantic_provider_lease_nft']
    coordination = modules['semantic_provider_lease_coordination']
    backend = nft.NftBackend([owner['nftPath']], owner['kernel'], owner['expectedStructureHash'], owner['readBudgetSeconds'])
    worker = modules['semantic_provider_lease_owner'].LeaseOwner(owner['kernel'], owner['dns'], backend)
    journal = coordination.PrivateJournal(Path(owner['journalFile']))
    coordinator = coordination.Coordinator(worker, owner['binding'],
        lambda: coordination.hold_common_lock(Path(owner['commonLockFile'])), journal.read, journal.write)
    coordinator.configuration_poll_seconds = owner['pollSeconds']

    def check():
        reader.private(reader.GUARD/'coordinated-configuration.json', reader.OWNER_HASH)
        for name, raw in source_bytes.items():
            require(reader.private(reader.GUARD/'source'/name) == raw, 'INSTALLED_OWNER_SOURCE_CHANGED')
        reader.private(owner['nftPath'], owner['nftSha256'], executable=True)
        for role, (cid, image) in reader.TARGETS.items():
            value = reader.parse(reader.run(cfg['commandBindings'], 'docker',
                ['inspect', '--type', 'container', '--format', reader.FORMAT, cid]))
            state = value['state']
            require(value['id'] == cid and value['image'] == image and value['runtime'] == 'ouf-semantic-admitted-v2'
                    and state['Running'] is True and state['Status'] == 'running' and state['Pid'] == EXPECTED[role]['pid']
                    and state['StartedAt'] == EXPECTED[role]['startedAt'] and value['restartCount'] == 0,
                    'RUNNING_APPROVED_GENERATION_CHANGED_' + role.upper())
            addresses = {row.get('IPAddress') for row in value['networks'].values()}
            index = 0 if role == 'adapter' else 1
            require(owner['kernel']['providerFlows'][index]['source'] in addresses, 'GOVERNED_SOURCE_ATTACHMENT_CHANGED')
        if capsule is not None:
            for name, expected in capsule['programHashes'].items():
                reader.private(ROOT/name, expected)
    return coordinator, modules['semantic_provider_coordinated_supervisor'].supervise, check


def wait_for_second_cycle(reader, root, timeout=90):
    # O_EXCL makes a receipt name visible before its contents are durable.
    # Wait through only known publication states; custody failures stay fatal.
    deadline = time.monotonic() + timeout
    last_publication_error = None
    while time.monotonic() < deadline:
        if (root/'worker-denial.json').exists():
            raise ValueError('LEASE_WORKER_FAILED_READ_RETAINED_CAUSE')
        try:
            if (root/'cycle-2.json').exists():
                raw = reader.private(root/'cycle-2.json')
                return raw, reader.parse(raw)
        except (json.JSONDecodeError, FileNotFoundError) as error:
            last_publication_error = error
        except reader.ReadDenied as error:
            if str(error) != 'FILE_CHANGED_DURING_READ':
                raise
            last_publication_error = error
        time.sleep(.05)
    raise ValueError('SECOND_FRESH_LEASE_CYCLE_NOT_OBSERVED') from last_publication_error


def compare(cycle, unit, root):
    pid = unit.get('MainPID', '')
    checks = {
        'secondCycleActive': cycle.get('status') == 'LEASE_ACTIVE',
        'secondCycleCount': type(cycle.get('refreshCount')) is int and cycle['refreshCount'] >= 2,
        'serviceActive': unit.get('ActiveState') == 'active',
        'serviceRunning': unit.get('SubState') == 'running',
        'automaticRestartDisabled': unit.get('Restart') == 'no',
        'sameWorkerPid': isinstance(pid, str) and pid.isdecimal() and int(pid) == cycle.get('workerPid'),
        'exactWorkerProgram': str(root / 'activate.py') in unit.get('ExecStart', '')}
    if not all(checks.values()):
        error = ValueError('EXACT_ACTIVE_LEASE_WORKER_UNPROVEN')
        error.readback_checks = checks
        raise error
    return checks


def properties():
    raw = command(['/usr/bin/systemctl', 'show', UNIT, '--property=LoadState,ActiveState,SubState,MainPID,Restart,ExecStart'])
    return dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)


def worker(capsule_path, expected_hash):
    global ROOT, CORE, PHASE
    ROOT = Path(capsule_path).parent
    require(ROOT.parent == SNAPSHOT_BASE and ROOT.name.startswith('semantic-finite-lease-recovery-r10-'),
            'EXACT_PRIVATE_LEASE_SNAPSHOT_REQUIRED')
    reader, _ = load_component('r8_post_reader', ROOT/'reader.py', READER_HASH)
    CORE, _ = load_component('r8_lease_core', ROOT/'activation_core.py', CORE_HASH)
    capsule = reader.parse(reader.private(capsule_path, expected_hash))
    require(capsule['schema'] == 'ouf.provider-finite-lease-recovery-authorization.v1'
            and capsule['approvalRef'] == APPROVAL_REF and capsule['ownerConfigurationHash'] == reader.OWNER_HASH
            and capsule['expectedProcessGenerations'] == EXPECTED and capsule['flowHashes'] == FLOW_HASHES
            and capsule['expectedJournalHash'] == JOURNAL_HASH and capsule['serviceUnit'] == UNIT,
            'EXACT_APPROVED_LEASE_CAPSULE_REQUIRED')
    approval_live(capsule['approvalRef'])
    require(capsule['leaseCompilerBinding'] == {'path': str(ROOT/'materialize_southbound_lease_refresh.py'),
            'sha256': COMPILER_HASH, 'originalSha256': OLD_COMPILER_HASH}, 'EXACT_REVIEWED_COMPILER_DELTA_REQUIRED')
    require(capsule['dnsBinding'] == {'path': str(ROOT/'dns.py'), 'sha256': DNS_HASH,
            'originalSha256': OLD_DNS_HASH}, 'EXACT_REVIEWED_DNS_DELTA_REQUIRED')
    require(set(capsule['programHashes']) == {'activate.py', 'activation_core.py', 'reader.py',
            'materialize_southbound_lease_refresh.py', 'dns.py', 'nft.py', 'supervisor.py'}, 'EXACT_PROGRAM_CLOSURE_REQUIRED')
    require(capsule['nftBinding'] == {'path':str(ROOT/'nft.py'),'sha256':NFT_HASH,'originalSha256':OLD_NFT_HASH}
            and capsule['supervisorBinding'] == {'path':str(ROOT/'supervisor.py'),'sha256':SUPERVISOR_HASH,
            'originalSha256':OLD_SUPERVISOR_HASH}, 'EXACT_REVIEWED_FINITE_LEASE_DELTAS_REQUIRED')
    for name, expected in capsule['programHashes'].items():
        reader.private(ROOT/name, expected)
    cfg, owner = configuration(reader)
    coord, supervisor, check = runtime(reader, CORE, cfg, owner, capsule)
    stop = threading.Event()
    CORE.install_signal_handlers(stop)
    PHASE = 'RUN_ONE_APPROVED_TRANSIENT_LEASE_OWNER'
    return CORE.supervise_claimed(ROOT, coord, supervisor, capsule, JOURNAL_HASH, check, stop)


def apply(reference):
    global ROOT, CORE, PHASE
    approval_live(reference)
    require(not os.path.lexists(CLAIM), 'LEASE_ACTIVATION_ALREADY_CLAIMED_DO_NOT_REPLAY')
    source = Path(__file__).absolute()
    # The root bootstrap executes hash-verified memory bytes. Never reread and
    # promote a user-writable downloaded file after that verification.
    self_raw = globals().get('__verified_source_bytes__')
    require(isinstance(self_raw, bytes) and len(self_raw) <= 131072,
            'VERIFIED_IN_MEMORY_ENTRYPOINT_REQUIRED')
    CORE, core_raw = load_component('r8_lease_core', source.parent/'activation_core.py', CORE_HASH)
    compiler_raw = component_bytes(source.parent/'materialize_southbound_lease_refresh.py', COMPILER_HASH)
    reader, reader_raw = load_component('dns_recovery_reader', EXISTING_READER, READER_HASH)
    dns_raw = component_bytes(source.parent/'dns.py', DNS_HASH)
    nft_raw = component_bytes(source.parent/'nft.py', NFT_HASH)
    supervisor_raw = component_bytes(source.parent/'supervisor.py', SUPERVISOR_HASH)
    PHASE = 'RECHECK_REVIEWED_RUNNING_COHORT_AND_QUIESCENT_TWO_FLOW_OWNER'
    report = reader.collect()
    validate_report(report)
    prior_claim_raw = validate_prior(reader)
    cfg, owner = configuration(reader)
    require(owner['dns'] == {'resolvers': ['46.38.225.230', '46.38.252.230'], 'resolverPort': 53,
            'timeoutSeconds': 2, 'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1}, 'EXISTING_BOUNDED_DNS_PROFILE_REQUIRED')
    for name in ('docker', 'nft', 'systemctl'):
        reader.private(cfg['commandBindings'][name]['path'], cfg['commandBindings'][name]['sha256'], executable=True)
    native = {name: native_program(reader, path) for name, path in (
        ('systemd-run', Path('/usr/bin/systemd-run')), ('python', Path('/usr/bin/python3.13')))}
    require_unit_absent(UNIT)
    # Compatibility is queried before any grant; no package installation.
    version = command(['/usr/bin/systemd-run', '--version'])
    require(re.search(rb'^systemd [0-9]+', version), 'SYSTEMD_RUN_VERSION_UNPROVEN')
    coord, _, check = runtime(reader, CORE, cfg, owner, None)
    check()
    with coord.hold_lock():
        require(sha(CORE.encoded(coord.journal())) == JOURNAL_HASH and not any(coord.sets()),
                'QUIESCENT_JOURNAL_CHANGED_BEFORE_CLAIM')
    approval_live(reference)
    PHASE = 'RESERVE_NEW_LEASE_AUTHORIZATION_AND_TRANSIENT_SERVICE'
    ROOT = Path(tempfile.mkdtemp(prefix='semantic-finite-lease-recovery-r10-', dir=reader.BASE))
    ROOT.chmod(0o700)
    CORE.create(CLAIM, {'schema': 'ouf.provider-finite-lease-recovery-activation-claim.v1', 'approvalRef': reference,
                       'directory': str(ROOT), 'startAuthorized': False})
    for name, raw in (('activate.py', self_raw), ('activation_core.py', core_raw), ('reader.py', reader_raw),
                      ('materialize_southbound_lease_refresh.py', compiler_raw), ('dns.py', dns_raw),
                      ('nft.py', nft_raw), ('supervisor.py', supervisor_raw)):
        CORE.create(ROOT/name, raw)
    capsule = {'schema': 'ouf.provider-finite-lease-recovery-authorization.v1', 'approvalRef': reference,
        'ownerConfigurationHash': reader.OWNER_HASH, 'expectedProcessGenerations': EXPECTED,
        'flowHashes': FLOW_HASHES, 'expectedJournalHash': JOURNAL_HASH, 'serviceUnit': UNIT,
        'programHashes': {name: sha(reader.private(ROOT/name)) for name in ('activate.py', 'activation_core.py', 'reader.py',
                         'materialize_southbound_lease_refresh.py', 'dns.py', 'nft.py', 'supervisor.py')},
        'leaseCompilerBinding': {'path': str(ROOT/'materialize_southbound_lease_refresh.py'),
                                'sha256': COMPILER_HASH, 'originalSha256': OLD_COMPILER_HASH},
        'dnsBinding': {'path': str(ROOT/'dns.py'), 'sha256': DNS_HASH, 'originalSha256': OLD_DNS_HASH},
        'nftBinding': {'path':str(ROOT/'nft.py'),'sha256':NFT_HASH,'originalSha256':OLD_NFT_HASH},
        'supervisorBinding': {'path':str(ROOT/'supervisor.py'),'sha256':SUPERVISOR_HASH,'originalSha256':OLD_SUPERVISOR_HASH},
        'issuedAt': ISSUED_AT, 'executionExpiresAt': EXECUTION_EXPIRES_AT,
        'authorityLifetime': 'CURRENT_R8_PROCESS_GENERATIONS_UNTIL_STOP_FAILURE_OR_REBOOT',
        'automaticRestart': False, 'enableAtBoot': False, 'containerLifecycleAuthorized': False,
        'providerRequestIssuedByWorker': False, 'notReleaseAcceptance': True}
    CORE.create(ROOT/'authorization.json', capsule)
    CORE.create(ROOT/'before.json', report)
    CORE.create(ROOT/'prior-consumed-lease-evidence.json', {'directory': str(PRIOR_ROOT),
        'authorizationHash': PRIOR_AUTH_HASH, 'activationReceiptHash': PRIOR_RECEIPT_HASH,
        'claimHash': sha(prior_claim_raw), 'oldClaimPreserved': True})
    coord, _, check = runtime(reader, CORE, cfg, owner, capsule)
    launched = False
    try:
        PHASE = 'START_EXACT_TRANSIENT_LEASE_WORKER_WITHOUT_DOCKER_LIFECYCLE'
        for binding in native.values():
            reader.private(binding['path'], binding['sha256'], executable=True)
        argv = CORE.service_command(ROOT, sha(CORE.encoded(capsule)), unit=UNIT)
        CORE.create(ROOT/'service-command.json', {'argv': argv, 'nativeBindings': native})
        launched = True  # Unknown result is still a potentially submitted start.
        command(argv)
        PHASE = 'VERIFY_TWO_FRESH_DNS_CYCLES_AND_CURRENT_NATIVE_MEMBERSHIP'
        cycle_raw, current = wait_for_second_cycle(reader, ROOT)
        unit = properties()
        readback = {'cycleReceiptSha256': sha(cycle_raw),
                    'cycleReceipt': {k: current[k] for k in ('status', 'refreshCount', 'workerPid', 'flowAddressCounts')},
                    'service': {k: unit.get(k) for k in ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'Restart')},
                    'execStartMatchesSnapshot': str(ROOT/'activate.py') in unit.get('ExecStart', '')}
        try:
            readback['checks'] = compare(current, unit, ROOT)
        except Exception as error:
            readback['checks'] = getattr(error, 'readback_checks', {})
            CORE.create(ROOT/'final-worker-readback.json', readback)
            error.native_diagnosis = {'finalWorkerReadback': readback}
            raise
        CORE.create(ROOT/'final-worker-readback.json', readback)
        check()
        with coord.hold_lock():
            value = coord.journal()
            sets = coord.sets()
            require(value['state'] == 'LEASE_READY' and value['leaseAuthorized'] and all(sets),
                    'CURRENT_TWO_FLOW_NATIVE_MEMBERSHIP_UNPROVEN')
        result = {'schema': 'ouf.provider-finite-lease-recovery-activation.v1', 'status': 'TWO_FLOW_LEASE_ACTIVE_AND_RENEWED',
            'evidenceDirectory': str(ROOT), 'serviceUnit': UNIT, 'refreshCount': current['refreshCount'],
            'flowAddressCounts': [len(v) for v in sets], 'ownerConfigurationHash': reader.OWNER_HASH,
            'containerLifecycleOperations': 0, 'daemonRestarted': False, 'automaticRestart': False,
            'bootEnablement': False, 'privateKeysRead': 0, 'signaturesIssued': 0,
            'providerCallsIssuedByWorker': 0, 'externalTrafficNowPermittedForApprovedFlows': True,
            'applicationHealthProven': False, 'notReleaseAcceptance': True, 'doNotRerunApply': True}
        CORE.create(ROOT/'activation-receipt.json', result)
        return result
    except Exception as error:
        cleanup = 'SERVICE_NOT_SUBMITTED'
        if launched:
            try:
                unit = properties()
                require(str(ROOT/'activate.py') in unit.get('ExecStart', ''), 'FOREIGN_SERVICE_PRESERVED')
                command(['/usr/bin/systemctl', 'stop', UNIT], timeout=55)
                with coord.hold_lock():
                    value = coord.journal()
                    require(value['state'] == 'QUIESCED' and not value['leaseAuthorized'] and not any(coord.sets()),
                            'FAILED_ACTIVATION_REVOCATION_UNPROVEN')
                cleanup = 'EXACT_WORKER_STOPPED_AND_LEASES_REVOKED'
            except Exception as recovery:
                cleanup = 'REVOCATION_UNPROVEN_FINITE_TTLS_REMAIN'
                CORE.create(ROOT/'cleanup-denial.json', CORE.diagnosis(recovery))
        error.cleanup = cleanup
        raise


def main():
    os.umask(0o077)
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_REQUIRED')
        if len(sys.argv) == 4 and sys.argv[1] == '--supervise':
            return worker(sys.argv[2], sys.argv[3])
        if len(sys.argv) == 2 and sys.argv[1] == '--plan':
            print('OUF_FINITE_LEASE_R10_PLAN=' + json.dumps(plan(), sort_keys=True))
            return 0
        require(len(sys.argv) == 3 and sys.argv[1] == '--apply', 'EXACT_EXPLICIT_LEASE_ACTION_REQUIRED')
        result = apply(sys.argv[2])
        print('OUF_FINITE_LEASE_R10_ACTIVATION=' + json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        result = {'schema': 'ouf.provider-finite-lease-recovery-activation.v1', 'status': 'LEASE_ACTIVATION_DENIED',
            'phase': PHASE, 'reason': str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,120}', str(error)) else 'LEASE_ACTIVATION_UNPROVEN',
            'errorType': type(error).__name__, 'evidenceDirectory': str(ROOT) if ROOT else None,
            'doNotRerunApply': os.path.lexists(CLAIM), 'containerLifecycleOperations': 0,
            'privateKeysRead': 0, 'signaturesIssued': 0, 'privateValuesPrinted': False,
            'notReleaseAcceptance': True, 'cleanup': getattr(error, 'cleanup', 'NO_SERVICE_START_IN_THIS_PHASE')}
        if CORE:
            result.update(CORE.diagnosis(error))
        result.update(getattr(error, 'native_diagnosis', {}))
        if ROOT and CORE:
            try:
                if (ROOT/'worker-denial.json').exists():
                    result['retainedWorkerDenial'] = json.loads((ROOT/'worker-denial.json').read_bytes())
                CORE.create(ROOT/'operator-denial.json', result)
            except Exception:
                result['diagnosisSaved'] = False
        print('OUF_FINITE_LEASE_R10_ACTIVATION=' + json.dumps(result, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())


