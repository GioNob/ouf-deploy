"""Prepared R8 lease activation. Inert until the exact human approval is bound."""
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

APPROVAL_REF = 'PENDING_EXPLICIT_R8_TWO_FLOW_LEASE_APPROVAL'
ISSUED_AT = 0
EXECUTION_EXPIRES_AT = 0
READER_HASH = 'ab61835ef55396ddacf4513acc0f21adbaab1b50ac32ad2fdc4c80a23d1835c8'
CORE_HASH = '62eb52a7ed0833b9d1fa418851ca1c4a027bf17a9032e97bb083ff13c00e9854'
EXISTING_READER = Path('/home/oufadmin/ouf-r8-post-read.Tl08rnjI/read.py')
CLAIM = Path('/etc/ouf/provider-r8-network-lease.claim')
UNIT = 'ouf-semantic-provider-lease-r8.service'
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


def load_component(name, path, expected):
    with Path(path).open('rb') as stream:
        raw = stream.read(131073)
    require(len(raw) <= 131072 and sha(raw) == expected, 'EXACT_DELIVERY_COMPONENT_HASH_REQUIRED')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, raw


def approval_live(reference, clock=time.time):
    require(not APPROVAL_REF.startswith('PENDING') and reference == APPROVAL_REF
            and type(ISSUED_AT) is int and type(EXECUTION_EXPIRES_AT) is int
            and 0 < ISSUED_AT <= clock() < EXECUTION_EXPIRES_AT <= ISSUED_AT + 7200,
            'EXPLICIT_NEW_LEASE_APPROVAL_REQUIRED')


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
    require(report['leaseServiceUnitNames'] == [], 'EXISTING_LEASE_SERVICE_REQUIRES_RECONCILIATION')


def command(argv, timeout=20):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(len(result.stdout) <= 131072 and len(result.stderr) <= 131072, 'NATIVE_OUTPUT_UNBOUNDED')
    if result.returncode:
        error = ValueError('NATIVE_SERVICE_COMMAND_FAILED')
        error.native_diagnosis = {'commandName': Path(argv[0]).name, 'exitCode': result.returncode,
                                  'stderrSha256': sha(result.stderr), 'stderrBytes': len(result.stderr)}
        raise error
    return result.stdout


def native_program(reader, path):
    raw = reader.private(path, executable=True)
    return {'path': str(path), 'sha256': sha(raw)}


def configuration(reader):
    human = reader.parse(reader.private(reader.CONTEXT/'human-approval-binding.json'))
    cfg = reader.parse(reader.private(reader.CONTEXT/'execution-configuration.json', human['configurationHash']))
    owner = reader.parse(reader.private(reader.GUARD/'coordinated-configuration.json', reader.OWNER_HASH))
    return cfg, owner


def runtime(reader, core, cfg, owner, capsule):
    modules, source_bytes = core.load_installed(owner, reader.GUARD/'source', reader.private)
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


def properties():
    raw = command(['/usr/bin/systemctl', 'show', UNIT, '--property=LoadState,ActiveState,SubState,MainPID,Restart,ExecStart'])
    return dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)


def worker(capsule_path, expected_hash):
    global ROOT, CORE, PHASE
    ROOT = Path(capsule_path).parent
    require(ROOT.parent == Path('/etc/ouf/deploy-snapshots') and ROOT.name.startswith('semantic-r8-lease-'),
            'EXACT_PRIVATE_LEASE_SNAPSHOT_REQUIRED')
    reader, _ = load_component('r8_post_reader', ROOT/'reader.py', READER_HASH)
    CORE, _ = load_component('r8_lease_core', ROOT/'activation_core.py', CORE_HASH)
    capsule = reader.parse(reader.private(capsule_path, expected_hash))
    require(capsule['schema'] == 'ouf.provider-r8-lease-authorization.v1'
            and capsule['approvalRef'] == APPROVAL_REF and capsule['ownerConfigurationHash'] == reader.OWNER_HASH
            and capsule['expectedProcessGenerations'] == EXPECTED and capsule['flowHashes'] == FLOW_HASHES
            and capsule['expectedJournalHash'] == JOURNAL_HASH and capsule['serviceUnit'] == UNIT,
            'EXACT_APPROVED_LEASE_CAPSULE_REQUIRED')
    approval_live(capsule['approvalRef'])
    require(set(capsule['programHashes']) == {'activate.py', 'activation_core.py', 'reader.py'}, 'EXACT_PROGRAM_CLOSURE_REQUIRED')
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
    CORE, core_raw = load_component('r8_lease_core', source.parent/'activation_core.py', CORE_HASH)
    reader, reader_raw = load_component('r8_post_reader', EXISTING_READER, READER_HASH)
    PHASE = 'RECHECK_REVIEWED_RUNNING_COHORT_AND_QUIESCENT_TWO_FLOW_OWNER'
    report = reader.collect()
    validate_report(report)
    cfg, owner = configuration(reader)
    require(owner['dns'] == {'resolvers': ['46.38.225.230', '46.38.252.230'], 'resolverPort': 53,
            'timeoutSeconds': 2, 'maxLeaseSeconds': 30, 'applyBudgetSeconds': 1}, 'EXISTING_BOUNDED_DNS_PROFILE_REQUIRED')
    for name in ('docker', 'nft', 'systemctl'):
        reader.private(cfg['commandBindings'][name]['path'], cfg['commandBindings'][name]['sha256'], executable=True)
    native = {name: native_program(reader, path) for name, path in (
        ('systemd-run', Path('/usr/bin/systemd-run')), ('python', Path('/usr/bin/python3.13')))}
    for subcommand in ('list-units', 'list-unit-files'):
        names = command(['/usr/bin/systemctl', subcommand, '--all', '--no-legend', '--no-pager', UNIT])
        require(not any(line.split() and line.split()[0].decode() == UNIT for line in names.splitlines()),
                'LEASE_UNIT_NAME_ALREADY_OWNED')
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
    ROOT = Path(tempfile.mkdtemp(prefix='semantic-r8-lease-', dir=reader.BASE))
    ROOT.chmod(0o700)
    CORE.create(CLAIM, {'schema': 'ouf.provider-r8-lease-activation-claim.v1', 'approvalRef': reference,
                       'directory': str(ROOT), 'startAuthorized': False})
    for name, raw in (('activate.py', source.read_bytes()), ('activation_core.py', core_raw), ('reader.py', reader_raw)):
        CORE.create(ROOT/name, raw)
    capsule = {'schema': 'ouf.provider-r8-lease-authorization.v1', 'approvalRef': reference,
        'ownerConfigurationHash': reader.OWNER_HASH, 'expectedProcessGenerations': EXPECTED,
        'flowHashes': FLOW_HASHES, 'expectedJournalHash': JOURNAL_HASH, 'serviceUnit': UNIT,
        'programHashes': {name: sha(reader.private(ROOT/name)) for name in ('activate.py', 'activation_core.py', 'reader.py')},
        'issuedAt': ISSUED_AT, 'executionExpiresAt': EXECUTION_EXPIRES_AT,
        'authorityLifetime': 'CURRENT_R8_PROCESS_GENERATIONS_UNTIL_STOP_FAILURE_OR_REBOOT',
        'automaticRestart': False, 'enableAtBoot': False, 'containerLifecycleAuthorized': False,
        'providerRequestIssuedByWorker': False, 'notReleaseAcceptance': True}
    CORE.create(ROOT/'authorization.json', capsule)
    CORE.create(ROOT/'before.json', report)
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
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if (ROOT/'worker-denial.json').exists():
                raise ValueError('LEASE_WORKER_FAILED_READ_RETAINED_CAUSE')
            if (ROOT/'cycle-2.json').exists():
                break
            time.sleep(.25)
        require((ROOT/'cycle-2.json').exists(), 'SECOND_FRESH_LEASE_CYCLE_NOT_OBSERVED')
        current = reader.parse(reader.private(ROOT/'worker-status.json'))
        unit = properties()
        require(current['status'] == 'LEASE_ACTIVE' and current['refreshCount'] >= 2
                and unit['ActiveState'] == 'active' and unit['SubState'] == 'running'
                and unit['Restart'] == 'no' and int(unit['MainPID']) == current['workerPid']
                and str(ROOT/'activate.py') in unit['ExecStart'], 'EXACT_ACTIVE_LEASE_WORKER_UNPROVEN')
        check()
        with coord.hold_lock():
            value = coord.journal()
            sets = coord.sets()
            require(value['state'] == 'LEASE_READY' and value['leaseAuthorized'] and all(sets),
                    'CURRENT_TWO_FLOW_NATIVE_MEMBERSHIP_UNPROVEN')
        result = {'schema': 'ouf.provider-r8-lease-activation.v1', 'status': 'TWO_FLOW_LEASE_ACTIVE_AND_RENEWED',
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
        require(len(sys.argv) == 3 and sys.argv[1] == '--apply', 'EXACT_EXPLICIT_LEASE_ACTION_REQUIRED')
        result = apply(sys.argv[2])
        print('OUF_R8_LEASE_ACTIVATION=' + json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        result = {'schema': 'ouf.provider-r8-lease-activation.v1', 'status': 'LEASE_ACTIVATION_DENIED',
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
        print('OUF_R8_LEASE_ACTIVATION=' + json.dumps(result, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
