"""One-use root lease activation around the existing installed coordinator.

No image/start authority. Configuration and process generations are supplied by
the separately pinned target entrypoint, never inferred from CI or DNS values.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import sys
import threading
import traceback
import types


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sync_parent(path):
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path, value):
    raw = value if isinstance(value, bytes) else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    sync_parent(path)


def status(root, value):
    # One writer: the claimed service process. Never overwrite historical files.
    target = root/'worker-status.json'
    temporary = root/('.worker-status-' + str(os.getpid()))
    create(temporary, value)
    os.replace(temporary, target)
    sync_parent(target)


def diagnosis(error):
    chain = []
    seen = set()
    while error is not None and id(error) not in seen and len(chain) < 6:
        seen.add(id(error))
        text = str(error)
        row = {'errorType': type(error).__name__,
               'reason': text if re.fullmatch('[A-Z][A-Z0-9_]{0,120}', text) else 'LEASE_OPERATION_UNPROVEN',
               'exceptionPoints': [{'file': Path(t.filename).name, 'function': t.name, 'line': t.lineno}
                                   for t in traceback.extract_tb(error.__traceback__)[-6:]]}
        if isinstance(error, OSError):
            row['errno'] = error.errno
            if error.filename:
                row['inputFileName'] = Path(error.filename).name
        window = getattr(error, 'observation_window', None)
        attempts = getattr(error, 'fresh_observation_attempts', None)
        if (type(window) is dict and set(window) == {'minimumObservedTtlSeconds', 'elapsedSeconds', 'ttlNoncacheable'}
                and type(window['minimumObservedTtlSeconds']) is int and 0 <= window['minimumObservedTtlSeconds'] < 2**31
                and type(window['elapsedSeconds']) in (int, float) and math.isfinite(window['elapsedSeconds'])
                and 0 <= window['elapsedSeconds'] <= 30
                and type(window['ttlNoncacheable']) is bool
                and window['ttlNoncacheable'] == (window['minimumObservedTtlSeconds'] == 0)
                and type(attempts) is int and 1 <= attempts <= 3):
            row['dnsObservationWindow'] = {**window, 'freshObservationAttempts': attempts}
        nft = getattr(error, 'nft_readback', None)
        if (type(nft) is dict and set(nft) == {'family','flowIndex','expiresType','expiresValue',
                'duplicateAddress','configuredLeaseSeconds'} and nft['family'] in ('inet','bridge')
                and type(nft['flowIndex']) is int and 0 <= nft['flowIndex'] <= 31
                and type(nft['expiresType']) is str and re.fullmatch('[A-Za-z_]{1,32}',nft['expiresType'])
                and (nft['expiresValue'] is None or type(nft['expiresValue']) is int and 0 <= nft['expiresValue'] < 2**31)
                and type(nft['duplicateAddress']) is bool and type(nft['configuredLeaseSeconds']) is int
                and 1 <= nft['configuredLeaseSeconds'] <= 3600):
            row['nftReadback'] = nft
        chain.append(row)
        error = error.__cause__ or error.__context__
    return {'exceptionChain': chain, 'privateValuesPrinted': False}


def load_installed(owner, source_root, read, compiler_override=None, dns_override=None, nft_override=None, supervisor_override=None):
    """Execute only memory bytes sealed by the fixed owner configuration hash."""
    saved = {name: read(source_root/name, expected) for name, expected in owner['sourceHashes'].items()}
    order = ('materialize_southbound_kernel', 'semantic_provider_dns', 'materialize_southbound_lease_refresh',
             'semantic_provider_lease_nft', 'semantic_provider_lease_owner',
             'semantic_provider_lease_coordination', 'semantic_provider_coordinated_supervisor')
    require(set(saved) == {'scripts/run_semantic_coordinated_lease_owner.py',
                           *('tools/' + n + '.py' for n in order)}, 'EXACT_INSTALLED_OWNER_CLOSURE_REQUIRED')
    execution = dict(saved)
    if compiler_override is not None:
        key = 'tools/materialize_southbound_lease_refresh.py'
        require(set(compiler_override) == {'path', 'sha256', 'originalSha256'}
                and compiler_override['originalSha256'] == digest(saved[key]),
                'EXPLICIT_REVIEWED_COMPILER_DELTA_REQUIRED')
        execution[key] = read(Path(compiler_override['path']), compiler_override['sha256'])
    if dns_override is not None:
        key = 'tools/semantic_provider_dns.py'
        require(set(dns_override) == {'path', 'sha256', 'originalSha256'}
                and dns_override['originalSha256'] == digest(saved[key]),
                'EXPLICIT_REVIEWED_DNS_DELTA_REQUIRED')
        execution[key] = read(Path(dns_override['path']), dns_override['sha256'])
    for name, override in (('semantic_provider_lease_nft', nft_override),
                           ('semantic_provider_coordinated_supervisor', supervisor_override)):
        if override is not None:
            key = 'tools/' + name + '.py'
            require(set(override) == {'path', 'sha256', 'originalSha256'}
                    and override['originalSha256'] == digest(saved[key]),
                    'EXPLICIT_REVIEWED_FINITE_LEASE_DELTA_REQUIRED')
            execution[key] = read(Path(override['path']), override['sha256'])
    package = types.ModuleType('tools')
    package.__path__ = []
    sys.modules['tools'] = package
    modules = {}
    for name in order:
        key = 'tools/' + name + '.py'
        module = types.ModuleType('tools.' + name)
        module.__file__ = str(source_root/key)
        module.__package__ = 'tools'
        sys.modules[module.__name__] = module
        setattr(package, name, module)
        exec(compile(execution[key], module.__file__, 'exec'), module.__dict__)
        modules[name] = module
    return modules, saved


def authorize_once(root, coordinator, approval, expected_journal_hash, check):
    """The entrypoint has already matched a real, explicit human approval.

    Preserve the old journal; exclusive claim precedes the first state change.
    This function cannot renew/replay a consumed service authorization.
    """
    check()
    with coordinator.hold_lock():
        old = coordinator.journal()
        require(digest(encoded(old)) == expected_journal_hash and old['state'] == 'QUIESCED'
                and old['leaseAuthorized'] is False and not any(coordinator.sets()),
                'REVIEWED_QUIESCENT_LEASE_GENERATION_REQUIRED')
        create(root/'prior-coordination-journal.json', old)
        create(root/'worker-activation-claim.json', {'schema': 'ouf.provider-lease-worker-claim.v1',
               'approvalHash': digest(encoded(approval)), 'previousJournalHash': expected_journal_hash,
               'pid': os.getpid(), 'startAuthorized': False})
        try:
            coordinator.publish(old, {**old, 'state': 'LEASE_READY', 'leaseAuthorized': True})
        except Exception:
            # Still under the original lock. Do not recursively acquire it.
            if coordinator.journal() == {**old, 'state': 'LEASE_READY', 'leaseAuthorized': True}:
                coordinator.publish(coordinator.journal(), old)
            raise


def supervise_claimed(root, coordinator, supervisor, approval, expected_journal_hash, check, stop=None):
    """Run existing DNS/expiry/lock logic; retain startup, refresh and failure facts."""
    stop = threading.Event() if stop is None else stop
    refresh_count = 0
    phase = 'AUTHORIZE_REVIEWED_QUIESCENT_GENERATION_ONCE'
    baseline = {'schema': 'ouf.provider-lease-worker-status.v1', 'containerLifecycleOperations': 0,
                'providerCallsIssuedByWorker': 0, 'notReleaseAcceptance': True, 'startAuthorized': False}
    try:
        authorize_once(root, coordinator, approval, expected_journal_hash, check)
        phase = 'SUPERVISE_EXISTING_OWNER_FRESH_DNS_AND_FINITE_LEASES'

        def record(message, **_):
            nonlocal refresh_count
            if message.startswith(('SEMANTIC_COORDINATED_START=PASS', 'SEMANTIC_COORDINATED_CYCLE=PASS')):
                with coordinator.hold_lock():
                    current = coordinator.journal()
                    sets = coordinator.sets()
                    require(current['state'] == 'LEASE_READY' and current['leaseAuthorized']
                            and len(sets) == 2 and all(sets), 'TWO_ACTIVE_FLOW_LEASES_REQUIRED')
                refresh_count += 1
                value = {**baseline, 'status': 'LEASE_ACTIVE', 'refreshCount': refresh_count,
                         'journalHash': digest(encoded(current)), 'flowAddressCounts': [len(v) for v in sets],
                         'workerPid': os.getpid(), 'freshDnsObserved': True}
                if refresh_count <= 2:
                    create(root/('cycle-' + str(refresh_count) + '.json'), value)
                status(root, value)
            elif message.startswith('SEMANTIC_COORDINATED_STOP=PASS'):
                status(root, {**baseline, 'status': 'QUIESCED', 'refreshCount': refresh_count,
                              'leaseAuthorized': False, 'setsRevoked': True, 'workerPid': os.getpid()})

        supervisor(coordinator, check, coordinator.configuration_poll_seconds, stop, log=record)
        return 0
    except Exception as error:
        # The existing supervisor performs ownership-checked revocation in its
        # finally. Never clean up somebody else's previously consumed claim.
        value = {**baseline, 'status': 'LEASE_WORKER_FAILED', 'phase': phase,
                 'refreshCount': refresh_count, 'doNotRerunApply': True, **diagnosis(error)}
        create(root/'worker-denial.json', value)
        status(root, value)
        return 1


def install_signal_handlers(stop):
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())


def service_command(root, capsule_hash, *, unit, python='/usr/bin/python3.13'):
    """Transient, not enabled at boot; Restart=no cannot re-arm a consumed claim."""
    return ['/usr/bin/systemd-run', '--unit=' + unit, '--service-type=exec', '--no-block',
            '--property=Restart=no', '--property=User=root', '--property=Group=root',
            '--property=UMask=0077', '--property=KillSignal=SIGTERM', '--property=KillMode=control-group',
            '--property=TimeoutStopSec=45', '--property=BindsTo=docker.service', '--property=After=docker.service',
            '--property=NoNewPrivileges=yes', '--property=CapabilityBoundingSet=CAP_NET_ADMIN',
            '--property=AmbientCapabilities=CAP_NET_ADMIN', '--property=StandardInput=null',
            '--property=StandardOutput=journal', '--property=StandardError=journal',
            python, '-I', '-B', str(root/'activate.py'), '--supervise', str(root/'authorization.json'), capsule_hash]
