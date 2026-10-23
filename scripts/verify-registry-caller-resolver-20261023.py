#!/usr/bin/env python3
"""One bounded corrected resolver-view observation; never replay recovery.

The retained probe used host resolver files in the caller network namespace.
This probe privately binds copies of the caller's three libc lookup files in
an unshared, recursively private mount namespace. Nothing is mounted in the
host or workload namespace. No HTTP, token, OAuth or target runtime write.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys

PREVIOUS = '/home/oufadmin/ouf-tls-diagnostic.mQbAvB1l/read.py'
PREVIOUS_HASH = 'b27a7c6474054700312bf39aa5f4fb28d02da40c29102fa6d67e3907fe7e31c2'
OBSERVATION = '/etc/ouf/deploy-snapshots/semantic-registry-tls-diagnostic-292e9b913ed9970bac171fc1911631be37038eb7fb0bd681215ffe97c98c3742/observation.json'
OBSERVATION_HASH = 'c53550e75b92ed916b78c26ec8f5457f102d5fef45326d02118393e961a66454'
SCHEMA = 'ouf.semantic-registry-caller-resolver-result.v1'
STAGE = 'VERIFY_LAUNCH'
VIEWS = ('resolv.conf', 'hosts', 'nsswitch.conf')


class Stop(RuntimeError): pass


def require(ok, code):
    if not ok: raise Stop(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value): return hashlib.sha256(encoded(value)).hexdigest()


def metadata(s):
    return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def previous(path=PREVIOUS):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == 30341,
                'EXACT_RETAINED_DIAGNOSTIC_REQUIRED')
        raw = os.read(fd, 30342)
        require(len(raw) == 30341 and hashlib.sha256(raw).hexdigest() == PREVIOUS_HASH
                and metadata(before) == metadata(os.fstat(fd)) == metadata(os.stat(path, follow_symlinks=False)),
                'RETAINED_DIAGNOSTIC_CHANGED')
    finally: os.close(fd)
    namespace = {'__name__': 'retained_diagnostic'}
    exec(compile(raw, '<verified-retained-diagnostic>', 'exec'), namespace)
    return namespace


def validate_views(views):
    require(type(views) is dict and set(views) == set(VIEWS)
            and all(type(v) is str and 0 < len(v.encode('ascii')) <= 16384 and '\0' not in v for v in views.values()),
            'BOUNDED_PUBLIC_CALLER_LOOKUP_FILES_REQUIRED')
    hosts = [line.split('#', 1)[0].split(':', 1)[1].split()
             for line in views['nsswitch.conf'].splitlines()
             if line.split('#', 1)[0].strip().startswith('hosts:')]
    # Do not allow a caller-controlled nsswitch to load additional host modules
    # or contact nscd, systemd-resolved, mDNS or another implicit side channel.
    require(hosts == [['files', 'dns']], 'CALLER_FILES_DNS_NSS_POLICY_REQUIRED')


def caller_views(pid, ticks, process_ticks):
    require(process_ticks(pid) == ticks, 'SAME_CALLER_LOOKUP_GENERATION_REQUIRED')
    fds = []; values = {}; profiles = {}
    ident = lambda s: [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode]
    try:
        root = os.open('/proc/' + str(pid) + '/root', os.O_PATH | os.O_DIRECTORY); fds.append(root)
        parent = os.open('etc', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root); fds.append(parent)
        parent_pin = ident(os.fstat(parent))
        require(parent_pin[2] == 0 and not parent_pin[4] & 0o022, 'PROTECTED_CALLER_ETC_REQUIRED')
        for name in VIEWS:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent); fds.append(fd)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                    and before.st_mode & 0o004 and not before.st_mode & 0o022 and 0 < before.st_size <= 16384,
                    'PUBLIC_CUSTODIED_CALLER_LOOKUP_FILE_REQUIRED')
            raw = os.read(fd, 16385)
            require(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
                    == metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'CALLER_LOOKUP_FILE_CHANGED')
            values[name] = raw.decode('ascii')
            profiles[name] = {'metadata': metadata(before), 'sha256': hashlib.sha256(raw).hexdigest()}
        require(parent_pin == ident(os.fstat(parent)) == ident(os.stat('etc', dir_fd=root, follow_symlinks=False))
                and process_ticks(pid) == ticks, 'CALLER_LOOKUP_DIRECTORY_OR_GENERATION_CHANGED')
        validate_views(values)
        return values, profiles
    finally:
        for fd in reversed(fds): os.close(fd)


# Injected only into the exact hash-verified prior child. All mounts are private
# and use files on a private read-only tmpfs, not caller files or caller binaries. The host libc,
# CA and Python remain in use. No dynamic code from the container is loaded.
PRIVATE_VIEW = r'''
result['phase']='PRIVATE_LOOKUP_VIEW'
import ctypes
if type(v['views'])is not dict or set(v['views'])!={'resolv.conf','hosts','nsswitch.conf'}:raise ValueError()
if not all(type(x)is str and 0<len(x.encode('ascii'))<=16384 and '\0'not in x for x in v['views'].values()):raise ValueError()
nss=[s.split('#',1)[0].split(':',1)[1].split()for s in v['views']['nsswitch.conf'].splitlines()if s.split('#',1)[0].strip().startswith('hosts:')]
if nss!=[['files','dns']]:raise ValueError()
mount_before=os.stat('/proc/self/ns/mnt').st_ino
os.unshare(os.CLONE_NEWNS)
if os.stat('/proc/self/ns/mnt').st_ino==mount_before:raise ValueError()
libc=ctypes.CDLL(None,use_errno=True)
libc.mount.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_char_p]
libc.mount.restype=ctypes.c_int
def mount(source,target,flags,kind=None,data=None):
 if libc.mount(source,target,kind,flags,data)!=0:raise OSError(ctypes.get_errno(),'')
mount(None,b'/',(1<<14)|(1<<18)) # MS_REC | MS_PRIVATE, before any bind
mount(b'tmpfs',b'/tmp',2|4|8,b'tmpfs',b'size=64k,mode=0700')
for name in ('resolv.conf','hosts','nsswitch.conf'):
 data=v['views'][name].encode('ascii')
 fd_copy=os.open('/tmp/ouf-view-'+name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
 try:
  if os.write(fd_copy,data)!=len(data):raise ValueError()
 finally:os.close(fd_copy)
mount(None,b'/tmp',32|1|2|4|8) # private tmpfs now read-only
for name in ('resolv.conf','hosts','nsswitch.conf'):
 target=('/etc/'+name).encode('ascii')
 mount(('/tmp/ouf-view-'+name).encode('ascii'),target,4096) # MS_BIND
 mount(None,target,4096|32|1|2|4|8) # bind remount, RO/nosuid/nodev/noexec
 with open(target,'rb')as check:
  if check.read(16385)!=v['views'][name].encode('ascii'):raise ValueError()
# Prevent libc nscd from providing answers outside the copied lookup view.
# nscd is not expected on this strictly bounded host transport; fail closed.
if os.path.exists('/var/run/nscd/socket')or os.path.exists('/run/nscd/socket'):raise ValueError()
result['privateLookupViewInstalled']=True
'''


def child_source(old):
    require(old.count("set(v)!={'mode','origin','ca'}") == 1 and old.count(' context=None') == 1,
            'EXACT_RETAINED_CHILD_SHAPE_REQUIRED')
    code = old.replace("set(v)!={'mode','origin','ca'}", "set(v)!={'mode','origin','ca','views'}")
    code = code.replace("'peerCertificateSha256':None}", "'peerCertificateSha256':None,'privateLookupViewInstalled':False}")
    # The original child is in one try block. Preserve the structured error
    # result while adding the isolated mount setup after entering the netns.
    return code.replace(' context=None', '\n' + '\n'.join(' ' + line for line in PRIVATE_VIEW.splitlines()) + '\n context=None')


def check_result(value, old):
    require(type(value) is dict and type(value.get('privateLookupViewInstalled')) is bool,
            'PRIVATE_VIEW_RESULT_REQUIRED')
    installed = value['privateLookupViewInstalled']; base = dict(value); del base['privateLookupViewInstalled']
    phase = base.get('phase')
    if phase == 'PRIVATE_LOOKUP_VIEW':
        require(not installed and base.get('status') == 'REJECTED' and not base.get('resolverSucceeded')
                and not base.get('tcpConnectAttempted') and not base.get('tlsHandshakeAttempted'),
                'FAILED_VIEW_MUST_NOT_RESOLVE_OR_CONNECT')
        base['phase'] = 'ENTER_CALLER_NETNS'
    old['check_child'](base)
    require(not base['resolverSucceeded'] or installed, 'RESOLUTION_REQUIRES_PRIVATE_CALLER_VIEW')
    require(base['status'] != 'OBSERVED' or installed and base['certificateChainVerified'],
            'OBSERVATION_REQUIRES_CALLER_VIEW_AND_TLS')
    return value


def run_child(old, origin, ca, views, program, netfd):
    validate_views(views)
    payload = encoded({'mode': 'CALLER_DNS_TLS', 'origin': origin, 'ca': ca.decode('ascii'), 'views': views})
    require(len(payload) <= 2097152, 'BOUNDED_CALLER_VIEW_CHILD_REQUIRED')
    child = subprocess.Popen([program['path'], '-I', '-B', '-S', '-c', child_source(old['CHILD']), str(netfd)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=(netfd,),
        close_fds=True, cwd='/', env={'LC_ALL': 'C'})
    try:
        raw, _ = child.communicate(payload, timeout=12)
        require(child.returncode == 0 and 0 < len(raw) <= 4096, 'CALLER_VIEW_CHILD_OUTCOME_UNPROVEN')
        return check_result(json.loads(raw), old)
    finally:
        if child.poll() is None: child.kill()
        child.wait(timeout=5)
        for stream in (child.stdin, child.stdout):
            if stream is not None: stream.close()


def observation_root(parent, claim, boot):
    return Path(parent) / ('semantic-registry-caller-resolver-' + digest({
        'retainedDiagnosticClaimHash': digest(claim), 'boot': boot, 'purpose': 'PRIVATE_CALLER_LOOKUP_VIEW_V1'}))


def diagnose():
    global STAGE
    require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv) == 1 and re.fullmatch('[0-9a-f]{64}', globals().get('__verified_diagnostic_sha256__', '')),
            'VERIFIED_ISOLATED_ROOT_RESOLVER_PROBE_REQUIRED')
    STAGE = 'VERIFY_RETAINED_SOURCE'
    old = previous(); case, manifest, loader, sources = old['unpack'](old['read_capsule']())
    ns = {}; exec(compile(loader, '<verified-retained-loader>', 'exec'), ns)
    _, actual = ns['load_entry'](manifest['sourceCommit'], sources, loader, old['CLOSURE_HASH'], manifest['sourcePins'])
    require(actual == manifest, 'SAME_RETAINED_SOURCE_PRELOAD_REQUIRED')
    from tools.semantic_registry_recovery_execution import postboot_prepare as p, original_tls, caller_configuration
    from tools.semantic_live_route_diagnostic import reader as transport
    from tools.ingestion_readiness_patch_execution import runtime_guard
    from engine_creation import Engine
    files = p.Files(); boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    STAGE = 'RECONCILE_COMPLETED_DIAGNOSTIC'
    observed, _ = files.json(OBSERVATION, OBSERVATION_HASH)
    oldroot = Path(OBSERVATION).parent; claim, _ = files.json(str(oldroot / 'claim.json'))
    require(claim == {'schema': old['SCHEMA'], 'retainedClaimHash': observed['oldClaim']['sha256'], 'bootId': boot,
        'diagnosticScriptSha256': PREVIOUS_HASH, 'maximumEngineGets': 2, 'maximumResolverCalls': 2,
        'maximumNewTlsHandshakes': 1, 'retainedTlsAttemptMarkers': 1, 'cumulativeTlsAttemptCeiling': 2,
        'automaticReplayAllowed': False, 'budgetReset': False}, 'EXACT_RETAINED_DIAGNOSTIC_CLAIM_REQUIRED')
    for number in (1, 2):
        marker, _ = files.json(str(oldroot / ('engine-get-' + str(number) + '.json')))
        require(set(marker) == {'pathHash', 'attempt'} and marker['attempt'] == number,
                'BOTH_COMPLETED_DIAGNOSTIC_ENGINE_MARKERS_REQUIRED')
    for name, expected in [('host-dns-attempt.json', {'maximumResolverCalls': 1, 'httpRequests': 0, 'tlsHandshakes': 0}),
        ('caller-probe-attempt.json', {'maximumResolverCalls': 1, 'maximumTlsHandshakes': 1, 'httpRequests': 0, 'bearersSent': 0})]:
        require(files.json(str(oldroot / name))[0] == expected, 'EXACT_RETAINED_NETWORK_ATTEMPTS_REQUIRED')
    require(old['finding'](observed['host'], observed['caller']) == 'CALLER_DNS_FAILED_HOST_RESOLVES'
            and observed['caller']['phase'] == 'DNS_RESOLUTION' and observed['caller']['gaiCode'] == -3
            and not observed['caller']['tcpConnectAttempted'] and not observed['caller']['tlsHandshakeAttempted'],
            'EXACT_RETAINED_PRECONNECTION_DNS_FAILURE_REQUIRED')
    preparation = case['preparation']; prior = p.reconcile_prior_preparation(preparation, files, boot)
    require(prior['priorAttemptCounts'] == {'engineGets': 12, 'adminGets': 2, 'frozenConfigurationGets': 0},
            'BOTH_EARLIER_CLAIMS_RETAINED_REQUIRED')
    original_claim, profile = files.json(observed['oldClaim']['path'], observed['oldClaim']['sha256'])
    require(profile == observed['oldClaim'] and digest(original_claim) == claim['retainedClaimHash']
            and original_claim['bootId'] == boot, 'SAME_CONSUMED_PREPARATION_REQUIRED')
    prep_root = Path(profile['path']).parent
    for number in range(1, 7): files.json(str(prep_root / ('engine-get-' + str(number) + '.json')))
    files.json(str(prep_root / 'admin-get.json')); tls_marker, _ = files.json(str(prep_root / 'tls-handshake.json'))
    def not_advanced():
        for name in ['engine-get-' + str(n) + '.json' for n in range(7, 13)] + ['frozen-get.json', 'source', 'prepared.json', 'review.json']:
            try: (prep_root / name).lstat()
            except FileNotFoundError: continue
            require(False, 'ORIGINAL_PREPARATION_ADVANCED')
    not_advanced()
    inputs, _ = files.json(preparation['retainedInputs']['path'], preparation['retainedInputs']['sha256'])
    proposal = inputs['proposal']; review, _ = files.json(str(Path(preparation['patchContext']) / 'review.json'), proposal['retainedPatchReviewHash'])
    program = review['executionReview']['gatewayTransportProfile']['pythonExecutable']
    transport.verify_program(program)
    root = observation_root(p.PARENT, claim, boot)
    STAGE = 'CLAIM_CORRECTED_VIEW_OBSERVATION'
    # A stable purpose/incident/boot root survives source corrections.
    for parent in (root.parent, *root.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'PROTECTED_OBSERVATION_PARENT_REQUIRED')
    try: os.mkdir(root, 0o700)
    except FileExistsError: require(False, 'CALLER_VIEW_ALREADY_CLAIMED_DO_NOT_REPLAY')
    p.publish(root, 'claim.json', {'schema': SCHEMA, 'retainedObservationHash': OBSERVATION_HASH,
        'retainedDiagnosticClaimHash': digest(claim), 'bootId': boot,
        'scriptSha256': globals()['__verified_diagnostic_sha256__'], 'maximumEngineGets': 2,
        'maximumResolverCalls': 1, 'maximumTlsHandshakes': 1,
        'priorEngineAttempts': 20, 'priorResolverAttempts': 2, 'priorTlsIntentMarkers': 2,
        'cumulativeEngineGetCeiling': 22, 'cumulativeResolverCallCeiling': 3, 'cumulativeTlsIntentCeiling': 3,
        'automaticReplayAllowed': False, 'budgetReset': False})
    engine = Engine(proposal['engineBinding']['socketPath'], tuple(proposal['engineBinding']['socketBinding']))
    cid = observed['callerPin']['binding']['containerId']; count = 0
    path = '/v1.44/containers/' + cid + '/json'
    def get():
        nonlocal count
        require(count < 2, 'TWO_CURRENT_CALLER_GETS_ONLY'); count += 1
        p.publish(root, 'engine-get-' + str(count) + '.json', {'pathHash': digest(path), 'attempt': count})
        status, value = engine.request('GET', path)
        require(status == 200 and value.get('Id') == cid, 'SAME_CURRENT_CALLER_REQUIRED')
        runtime_guard.unchanged(value, observed['callerPin']); return value
    STAGE = 'READ_CURRENT_CALLER_VIEW'
    caller = get(); pid = caller['State']['Pid']; ticks = transport.process_ticks(pid)
    origin, _, configuration = caller_configuration.configuration(caller)
    ca, ca_source = original_tls.system_ca(files)
    require(origin == observed['origin'] and ca == observed['ca'] and ca_source == observed['caSource']
            and digest(origin) == tls_marker['originHash'] and digest(ca) == tls_marker['caProfileHash'],
            'SAME_CONFIGURED_ORIGIN_AND_CA_REQUIRED')
    _, ca_raw = files.seal(ca['path'], 1048576, ca['sha256'])
    views, view_profile = caller_views(pid, ticks, transport.process_ticks)
    servers, shape = old['resolver_shape'](views['resolv.conf'].encode())
    require(bool(servers), 'CONFIGURED_CALLER_RESOLVER_REQUIRED')
    host_profile = old['host_resolver'](files)[1]
    for name in ('hosts', 'nsswitch.conf'): old['read_public_resolver']('/etc/' + name)
    netfd = os.open('/proc/' + str(pid) + '/ns/net', os.O_RDONLY | os.O_CLOEXEC)
    ident = lambda s: (s.st_dev, s.st_ino)
    net_pin = ident(os.fstat(netfd)); host_mount_pin = ident(os.stat('/proc/self/ns/mnt'))
    try:
        require(net_pin == ident(os.stat('/proc/' + str(pid) + '/ns/net')) and transport.process_ticks(pid) == ticks,
                'SAME_CALLER_BEFORE_VIEW_PROBE_REQUIRED')
        p.publish(root, 'network-attempt.json', {'maximumResolverCalls': 1, 'maximumTlsHandshakes': 1,
            'httpRequests': 0, 'bearersSent': 0, 'resolverSource': 'COPIED_CALLER_FILES', 'privateMountNamespace': True})
        STAGE = 'PROBE_CORRECT_CALLER_RESOLVER_VIEW'
        result = run_child(old, origin, ca_raw, views, program, netfd)
        require(net_pin == ident(os.fstat(netfd)) == ident(os.stat('/proc/' + str(pid) + '/ns/net'))
                and host_mount_pin == ident(os.stat('/proc/self/ns/mnt')) and transport.process_ticks(pid) == ticks,
                'CALLER_OR_HOST_NAMESPACE_CHANGED')
    finally: os.close(netfd)
    STAGE = 'VERIFY_UNCHANGED_CONTEXT'
    get(); require(caller_configuration.configuration(caller, configuration)[0] == origin
        and caller_views(pid, ticks, transport.process_ticks)[1] == view_profile
        and old['host_resolver'](files)[1] == host_profile and original_tls.resolve_system_ca() == ca_source,
        'RESOLVER_OBSERVATION_INPUT_CHANGED')
    transport.verify_program(program); not_advanced(); files.verify()
    require(p.reconcile_prior_preparation(preparation, files, boot) == prior
            and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'CLAIMS_OR_BOOT_CHANGED')
    private = {'result': result, 'callerViews': view_profile, 'originHash': digest(origin),
        'caProfileHash': digest(ca), 'retainedObservationHash': OBSERVATION_HASH}
    p.publish(root, 'observation.json', private)
    finding = 'CORRECTED_CALLER_VIEW_TLS_VERIFIED' if result['certificateChainVerified'] else (
        'PRIVATE_LOOKUP_VIEW_UNPROVEN' if result['phase'] == 'PRIVATE_LOOKUP_VIEW' else
        old['finding']({'resolverSucceeded': True}, result))
    return {'schema': SCHEMA, 'status': 'CALLER_RESOLVER_OBSERVED', 'complete': True, 'finding': finding,
        'callerDnsTls': old['public_child'](result), 'callerResolverShape': shape,
        'privateObservationPath': str(root / 'observation.json'), 'privateObservationHash': digest(private),
        'engineGets': count, 'maximumResolverCalls': 1, 'maximumTlsHandshakes': 1,
        'cumulativeEngineGetCeiling': 22, 'cumulativeResolverCallCeiling': 3, 'cumulativeTlsIntentCeiling': 3,
        'retainedDiagnosticObservationHash': OBSERVATION_HASH, 'oldClaimsRetained': True,
        'hostMountNamespaceUnchanged': True, 'resolverSource': 'COPIED_CALLER_FILES',
        'applicationEntryInvoked': False, 'httpRequests': 0, 'bearersSent': 0, 'tokenFilesOpened': 0,
        'oauthRequests': 0, 'databaseCalls': 0, 'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False,
        'addressesPrinted': False, 'rawErrorsPrinted': False, 'readOnlyRuntime': True,
        'rootCauseEstablished': False, 'serviceReadinessEstablished': False, 'releaseAcceptance': False,
        'automaticReplayAllowed': False, 'budgetReset': False}


if __name__ == '__main__':
    def expired(*_): require(False, 'CALLER_VIEW_DEADLINE')
    signal.signal(signal.SIGALRM, expired); signal.alarm(45)
    try: result = diagnose()
    except (Exception, KeyboardInterrupt) as error:
        code = str(error) if isinstance(error, Stop) else ''
        result = {'schema': SCHEMA, 'status': 'STOP_RECONCILE', 'complete': False,
            'reasonCode': code if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', code) else 'CALLER_VIEW_INPUT_OR_OUTCOME_UNPROVEN',
            'stage': STAGE, 'exceptionClass': type(error).__name__ if type(error).__name__ in (
                'Stop', 'RecoveryDenied', 'Denied', 'OSError', 'PermissionError', 'FileNotFoundError', 'TimeoutError',
                'KeyError', 'TypeError', 'ValueError', 'RuntimeError', 'JSONDecodeError') else 'OTHER',
            'errno': error.errno if isinstance(error, OSError) and type(error.errno) is int else None,
            'contextsAndClaimsRetained': True, 'automaticReplayAllowed': False, 'budgetReset': False,
            'httpRequests': 0, 'bearersSent': 0, 'oauthRequests': 0, 'databaseCalls': 0,
            'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False, 'releaseAcceptance': False}
    signal.alarm(0); print(encoded(result).decode(), flush=True)
    raise SystemExit(0 if result['complete'] else 2)
