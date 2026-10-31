#!/usr/bin/env python3
"""One separately claimed DNS/TLS diagnosis of the exact retained TLS stop.

No application entry, bearer, HTTP, OAuth, database or recovery dispatch.
Earlier claims remain untouched. The erased original exception is not recovered.
"""
import ast
import base64
import gzip
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
from urllib.parse import urlsplit

CAPSULE = '/home/oufadmin/ouf-registry-postboot-review.f4mzcZVO/capsule.py'
CAPSULE_HASH = '138240bc01ad9688374ed7f991a545ec779165b25c822c323fe791a8295b0fe8'
DECLARATION_HASH = '11058cbff799386e1e5a6a4fb84851a3bd21c25cb00866fb41cfad8ecafeb008'
CLOSURE_HASH = 'eac09fe98cfcbbbb4bf0c25d8976f0c359f4ed93a9314f3541df25096a524a41'
SCHEMA = 'ouf.semantic-registry-tls-diagnostic-result.v1'
STAGE = 'VERIFY_LAUNCH'

CHILD = r'''import hashlib,json,os,signal,socket,ssl,sys
from urllib.parse import urlsplit
result={'status':'UNPROVEN','phase':'INPUT','resolverSucceeded':False,'tcpConnectAttempted':False,
 'tlsHandshakeAttempted':False,'certificateChainVerified':False,'hostnameVerified':False,
 'errorClass':None,'errno':None,'gaiCode':None,'verifyCode':None,'addressSetHash':None,'peerCertificateSha256':None}
def expired(*_):raise TimeoutError()
signal.signal(signal.SIGALRM,expired);signal.alarm(8)
sock=None
try:
 raw=sys.stdin.buffer.read(2097153)
 if not 0<len(raw)<=2097152:raise ValueError()
 v=json.loads(raw)
 if type(v)is not dict or set(v)!={'mode','origin','ca'} or v['mode']not in('HOST_DNS','CALLER_DNS_TLS'):raise ValueError()
 if len(sys.argv)!=2 or not sys.argv[1].isdigit():raise ValueError()
 u=urlsplit(v['origin'])
 if u.scheme!='https' or not u.hostname or u.username or u.password or u.path not in('','/')or u.query or u.fragment:raise ValueError()
 if v['mode']=='HOST_DNS'and v['ca']is not None:raise ValueError()
 fd=int(sys.argv[1])
 result['phase']='ENTER_CALLER_NETNS'
 if v['mode']=='CALLER_DNS_TLS':os.setns(fd,0)
 os.close(fd)
 context=None
 if v['mode']=='CALLER_DNS_TLS':
  result['phase']='LOAD_CA'
  if type(v['ca'])is not str or not 0<len(v['ca'].encode())<=1048576:raise ValueError()
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.minimum_version=ssl.TLSVersion.TLSv1_2
  context.load_verify_locations(cadata=v['ca'])
  if not context.check_hostname or context.verify_mode!=ssl.CERT_REQUIRED:raise ValueError()
 result['phase']='DNS_RESOLUTION'
 answers=socket.getaddrinfo(u.hostname,u.port or 443,type=socket.SOCK_STREAM)
 answers=[a for a in answers if a[0]in(socket.AF_INET,socket.AF_INET6)and a[1]==socket.SOCK_STREAM]
 if not 1<=len(answers)<=64:raise ValueError()
 result['resolverSucceeded']=True
 result['addressSetHash']=hashlib.sha256(json.dumps(sorted({a[4][0]for a in answers}),separators=(',',':')).encode()).hexdigest()
 if v['mode']=='CALLER_DNS_TLS':
  # Reuse these exact resolved answers; do not resolve again or retry another
  # address after an ambiguous connection/handshake. Prefer the IPv4 family
  # used by the retained Docker topology, then a single IPv6 endpoint.
  chosen=next((a for a in answers if a[0]==socket.AF_INET),answers[0])
  result['phase']='TCP_CONNECT';result['tcpConnectAttempted']=True
  sock=socket.socket(chosen[0],chosen[1],chosen[2]);sock.settimeout(4);sock.connect(chosen[4])
  result['phase']='TLS_HANDSHAKE';result['tlsHandshakeAttempted']=True
  sock=context.wrap_socket(sock,server_hostname=u.hostname)
  leaf=sock.getpeercert(binary_form=True)
  if not leaf:raise ValueError()
  result['peerCertificateSha256']=hashlib.sha256(leaf).hexdigest()
  result['certificateChainVerified']=result['hostnameVerified']=True
 result['phase']='COMPLETE';result['status']='OBSERVED'
except BaseException as error:
 if isinstance(error,ssl.SSLCertVerificationError):
  result['errorClass']='SSLCertVerificationError'
  code=getattr(error,'verify_code',None)
  if type(code)is int and 0<=code<=65535:result['verifyCode']=code
 elif isinstance(error,socket.gaierror):
  result['errorClass']='gaierror'
  if type(error.errno)is int and -4096<=error.errno<=4096:result['gaiCode']=error.errno
 elif isinstance(error,TimeoutError):result['errorClass']='TimeoutError'
 elif isinstance(error,PermissionError):result['errorClass']='PermissionError'
 elif isinstance(error,ssl.SSLError):result['errorClass']='SSLError'
 elif isinstance(error,OSError):result['errorClass']='OSError'
 else:result['errorClass']='INPUT_OR_PROTOCOL_REJECTED'
 if isinstance(error,OSError)and type(error.errno)is int and -4096<=error.errno<=4096:result['errno']=error.errno
 result['status']='REJECTED'
finally:
 signal.alarm(0)
 if sock is not None:
  try:sock.close()
  except OSError:pass
 try:
  sys.stdout.buffer.write(json.dumps(result,sort_keys=True,separators=(',',':')).encode());sys.stdout.buffer.flush()
 except BaseException:os._exit(2)
os._exit(0)
'''


class Stop(RuntimeError): pass

def require(ok, code):
    if not ok: raise Stop(code)

def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def digest(value): return hashlib.sha256(encoded(value)).hexdigest()
def metadata(s): return [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read_capsule(path=CAPSULE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 3145728,
                'BOUNDED_RETAINED_TLS_CAPSULE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as stream: raw = stream.read(3145729)
        require(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
                == metadata(os.stat(path, follow_symlinks=False)) and hashlib.sha256(raw).hexdigest() == CAPSULE_HASH,
                'EXACT_RETAINED_TLS_CAPSULE_REQUIRED')
        return raw
    finally: os.close(fd)


def unpack(raw):
    require(hashlib.sha256(raw).hexdigest() == CAPSULE_HASH, 'EXACT_RETAINED_TLS_CAPSULE_REQUIRED')
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign):
            require(len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id not in values, 'UNIQUE_RETAINED_CAPSULE_ASSIGNMENTS_REQUIRED')
            values[node.targets[0].id] = ast.literal_eval(node.value)
    require(set(values) == {'CASE', 'DELIVERY', 'DELIVERY_HASH', 'PACKED', 'BOOTSTRAP'}, 'EXACT_RETAINED_CAPSULE_FIELDS_REQUIRED')
    declaration = values['DELIVERY']; manifest = declaration['nativeDeclaration']
    require(digest(declaration) == values['DELIVERY_HASH'] == DECLARATION_HASH and digest(manifest) == CLOSURE_HASH
            and digest(values['CASE']) == declaration['caseHash'], 'RETAINED_TLS_DECLARATION_CHANGED')
    with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(values['PACKED'], validate=True))) as stream:
        packed = stream.read(12582913)
    require(0 < len(packed) <= 12582912, 'BOUNDED_RETAINED_SOURCE_PAYLOAD_REQUIRED')
    payload = json.loads(packed); loader = payload['loader'].encode()
    sources = {name: text.encode() for name, text in payload['sources'].items()}
    require(hashlib.sha256(loader).hexdigest() == manifest['loaderHash'] and len(sources) == 132
            and set(sources) == set(manifest['sourceHashes']) and all(
                hashlib.sha256(v).hexdigest() == manifest['sourceHashes'][k] for k, v in sources.items()),
            'RETAINED_TLS_SOURCES_CHANGED')
    return values['CASE'], manifest, loader, sources


def resolver_shape(raw):
    require(0 < len(raw) <= 16384 and b'\0' not in raw, 'BOUNDED_RESOLVER_CONFIGURATION_REQUIRED')
    servers = []
    for line in raw.decode('ascii').splitlines():
        fields = line.split('#', 1)[0].split(';', 1)[0].split()
        if fields and fields[0] == 'nameserver':
            require(len(fields) == 2 and len(servers) < 8, 'CLOSED_RESOLVER_NAMESERVER_LIST_REQUIRED')
            try: servers.append(str(ipaddress.ip_address(fields[1])))
            except ValueError: require(False, 'NUMERIC_RESOLVER_ADDRESS_REQUIRED')
    require(servers, 'EXPLICIT_RESOLVER_NAMESERVERS_REQUIRED')
    return servers, {'nameserverCount': len(servers), 'dockerEmbeddedPresent': '127.0.0.11' in servers,
        'loopbackOtherThanDockerPresent': any(ipaddress.ip_address(v).is_loopback and v != '127.0.0.11' for v in servers),
        'nonLoopbackPresent': any(not ipaddress.ip_address(v).is_loopback for v in servers)}


def read_public_resolver(path):
    """Observe public OS DNS data, never adopt it as a trust/credential source.

    systemd-resolved may own this regular public file and its runtime directory.
    Do not apply the private root-only CA/token custody rule to such data.
    Held no-follow descriptors, public readonly mode, bounds and identity still
    prevent following daemon-controlled links into private root files.
    """
    target = Path(path); fds = []; parents = []
    require(target.is_absolute() and '..' not in target.parts, 'EXACT_PUBLIC_RESOLVER_PATH_REQUIRED')
    identity = lambda info: [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode]
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); fds.append(parent)
        for part in target.parts[1:-1]:
            held = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent); fds.append(held)
            info = os.fstat(held)
            require(not info.st_mode & 0o022, 'PUBLIC_RESOLVER_ANCESTRY_WRITABLE')
            parents.append((parent, part, held, identity(info))); parent = held
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent); fds.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_mode & 0o004
                and not before.st_mode & 0o022 and 0 < before.st_size <= 16384, 'BOUNDED_PUBLIC_RESOLVER_FILE_REQUIRED')
        raw = b''
        while len(raw) <= 16384:
            part = os.read(fd, min(4096, 16385 - len(raw)))
            if not part: break
            raw += part
        require(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
                == metadata(os.stat(target.name, dir_fd=parent, follow_symlinks=False))
                and all(identity(os.fstat(held)) == expected
                        == identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
                        for directory, name, held, expected in parents), 'PUBLIC_RESOLVER_VIEW_CHANGED')
        return raw, {'path': str(target), 'metadata': metadata(before), 'sha256': hashlib.sha256(raw).hexdigest(),
                     'ancestors': [expected for _, _, _, expected in parents]}
    finally:
        for fd in reversed(fds): os.close(fd)


def host_resolver(files):
    pending = Path('/etc/resolv.conf'); links = []
    for _ in range(16):
        prefix = Path('/')
        for index, part in enumerate(pending.parts[1:], 1):
            prefix /= part; info = prefix.lstat()
            if stat.S_ISLNK(info.st_mode):
                require(info.st_uid == 0, 'ROOT_CONTROLLED_HOST_RESOLVER_SELECTOR_REQUIRED')
                target = os.readlink(prefix); require(metadata(prefix.lstat()) == metadata(info), 'HOST_RESOLVER_LINK_CHANGED')
                links.append((str(prefix), target, metadata(info)))
                base = Path(target) if target.startswith('/') else prefix.parent / target
                pending = Path(os.path.normpath(str(base.joinpath(*pending.parts[index + 1:])))); break
            require(not info.st_mode & 0o022, 'ROOT_CONTROLLED_HOST_RESOLVER_REQUIRED')
        else:
            raw, profile = read_public_resolver(str(pending))
            return resolver_shape(raw), (profile, links)
    require(False, 'HOST_RESOLVER_LINK_DEPTH_EXCEEDED')


def caller_resolver(pid, ticks, process_ticks):
    require(process_ticks(pid) == ticks, 'SAME_CALLER_FOR_RESOLVER_VIEW_REQUIRED'); fds = []
    try:
        root = os.open('/proc/' + str(pid) + '/root', os.O_PATH | os.O_DIRECTORY); fds.append(root)
        parent = os.open('etc', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root); fds.append(parent)
        fd = os.open('resolv.conf', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent); fds.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                and not before.st_mode & 0o022 and 0 < before.st_size <= 16384, 'CUSTODIED_CALLER_RESOLVER_REQUIRED')
        raw = b''
        while len(raw) <= 16384:
            part = os.read(fd, min(4096, 16385 - len(raw)))
            if not part: break
            raw += part
        require(len(raw) == before.st_size and metadata(before) == metadata(os.fstat(fd))
                == metadata(os.stat('resolv.conf', dir_fd=parent, follow_symlinks=False))
                and process_ticks(pid) == ticks, 'CALLER_RESOLVER_CHANGED')
        return resolver_shape(raw), {'metadata': metadata(before), 'sha256': hashlib.sha256(raw).hexdigest()}
    finally:
        for fd in reversed(fds): os.close(fd)


def check_child(value):
    fields = {'status', 'phase', 'resolverSucceeded', 'tcpConnectAttempted', 'tlsHandshakeAttempted',
        'certificateChainVerified', 'hostnameVerified', 'errorClass', 'errno', 'gaiCode', 'verifyCode',
        'addressSetHash', 'peerCertificateSha256'}
    require(type(value) is dict and set(value) == fields and value['status'] in ('OBSERVED', 'REJECTED')
            and value['phase'] in ('INPUT', 'ENTER_CALLER_NETNS', 'LOAD_CA', 'DNS_RESOLUTION', 'TCP_CONNECT', 'TLS_HANDSHAKE', 'COMPLETE')
            and value['errorClass'] in (None, 'SSLCertVerificationError', 'gaierror', 'TimeoutError', 'PermissionError', 'SSLError', 'OSError', 'INPUT_OR_PROTOCOL_REJECTED'),
            'CLOSED_DIAGNOSTIC_CHILD_RESULT_REQUIRED')
    require(all(type(value[k]) is bool for k in ('resolverSucceeded', 'tcpConnectAttempted', 'tlsHandshakeAttempted', 'certificateChainVerified', 'hostnameVerified'))
            and all(value[k] is None or type(value[k]) is int and -4096 <= value[k] <= 65535 for k in ('errno', 'gaiCode', 'verifyCode'))
            and all(value[k] is None or type(value[k]) is str and re.fullmatch('[0-9a-f]{64}', value[k]) for k in ('addressSetHash', 'peerCertificateSha256')),
            'TYPED_DIAGNOSTIC_CHILD_RESULT_REQUIRED')
    require((value['status'] == 'OBSERVED' and value['phase'] == 'COMPLETE' and value['resolverSucceeded'] and value['errorClass'] is None)
            or (value['status'] == 'REJECTED' and value['phase'] != 'COMPLETE' and value['errorClass'] is not None),
            'CONSISTENT_DIAGNOSTIC_COMPLETION_REQUIRED')
    require(value['certificateChainVerified'] == value['hostnameVerified'], 'CONSISTENT_CERTIFICATE_AND_NAME_RESULT_REQUIRED')
    require(not value['certificateChainVerified'] or (value['hostnameVerified'] and value['tlsHandshakeAttempted']
            and value['resolverSucceeded'] and value['status'] == 'OBSERVED' and value['peerCertificateSha256'] is not None),
            'CONSISTENT_DIAGNOSTIC_TLS_RESULT_REQUIRED')
    return value


def run_child(mode, origin, ca_raw, program, namespace_fd):
    payload = encoded({'mode': mode, 'origin': origin, 'ca': None if mode == 'HOST_DNS' else ca_raw.decode('ascii')})
    require(len(payload) <= 2097152, 'BOUNDED_DIAGNOSTIC_TLS_INPUT_REQUIRED')
    child = subprocess.Popen([program['path'], '-I', '-B', '-S', '-c', CHILD, str(namespace_fd)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=(namespace_fd,),
        close_fds=True, cwd='/', env={'LC_ALL': 'C'})
    try:
        raw, _ = child.communicate(payload, timeout=12)
        require(child.returncode == 0 and 0 < len(raw) <= 4096, 'DIAGNOSTIC_CHILD_OUTCOME_UNPROVEN')
        result = check_child(json.loads(raw))
        require(mode != 'HOST_DNS' or (not result['tcpConnectAttempted'] and not result['tlsHandshakeAttempted']
                and not result['certificateChainVerified'] and result['peerCertificateSha256'] is None),
                'HOST_RESOLUTION_MUST_NOT_CONNECT')
        require(mode != 'CALLER_DNS_TLS' or result['status'] != 'OBSERVED' or result['certificateChainVerified'],
                'CALLER_COMPLETION_REQUIRES_VERIFIED_TLS')
        return result
    finally:
        if child.poll() is None: child.kill()
        child.wait(timeout=5)
        for stream in (child.stdin, child.stdout):
            if stream is not None: stream.close()


def public_child(value):
    return {key: value[key] for key in value if key not in ('addressSetHash', 'peerCertificateSha256')}


def finding(host, caller):
    if caller['phase'] == 'INPUT': return 'DIAGNOSTIC_INPUT_REJECTED'
    if caller['phase'] == 'ENTER_CALLER_NETNS': return 'CALLER_NAMESPACE_UNPROVEN'
    if caller['phase'] == 'LOAD_CA': return 'CALLER_CA_CONTEXT_REJECTED'
    if not caller['resolverSucceeded']:
        return 'CALLER_DNS_FAILED_HOST_RESOLVES' if host['resolverSucceeded'] else 'HOST_AND_CALLER_DNS_UNPROVEN'
    if caller['phase'] == 'TCP_CONNECT': return 'CALLER_TCP_CONNECTION_FAILED'
    if caller['errorClass'] == 'SSLCertVerificationError': return 'CALLER_TLS_CERTIFICATE_REJECTED'
    if caller['certificateChainVerified']: return 'TLS_VERIFIED_IN_DIAGNOSTIC_ONLY'
    return 'CALLER_TLS_STAGE_UNPROVEN'


LEGACY_DIAGNOSTIC_DIGESTS = (
    'f98b1f0a9f87a73dfdaae10e2564775a751fa9f38c36e572efd369a3d659e629',
    '7ea06981258606c3c21cb107a50675c9b26f33b87b5691744d4c30ee272362ef',
    '5f6d59d1bae6f1755070166d1f498a0867b33baae485a79bd4f21e2344eaba02')


def diagnostic_roots(parent, claim_profile, claim, boot):
    # One incident/boot claim across future source versions. Publishing a code
    # correction must not silently allocate another observation allowance.
    root = Path(parent) / ('semantic-registry-tls-diagnostic-' + digest({
        'retainedClaimHash': digest(claim), 'boot': boot}))
    legacy = [Path(parent) / ('semantic-registry-tls-diagnostic-' + digest({
        'claim': claim_profile, 'script': source, 'boot': boot})) for source in LEGACY_DIAGNOSTIC_DIGESTS]
    return root, legacy


def require_unused_diagnostic(root, legacy):
    for path in [root, *legacy]:
        try: path.lstat()
        except FileNotFoundError: continue
        require(False, 'TLS_DIAGNOSTIC_ALREADY_CLAIMED_DO_NOT_REPLAY')


def diagnose():
    global STAGE
    require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and len(sys.argv) == 1 and re.fullmatch('[0-9a-f]{64}', globals().get('__verified_diagnostic_sha256__', '')),
            'ISOLATED_VERIFIED_ROOT_TLS_DIAGNOSTIC_REQUIRED')
    STAGE = 'VERIFY_RETAINED_CAPSULE'
    case, manifest, loader, sources = unpack(read_capsule())
    STAGE = 'PRELOAD_RETAINED_SOURCES'
    namespace = {}; exec(compile(loader, '<verified-postboot-loader>', 'exec'), namespace)
    entry, actual_manifest = namespace['load_entry'](manifest['sourceCommit'], sources, loader, CLOSURE_HASH, manifest['sourcePins'])
    require(actual_manifest == manifest, 'SAME_RETAINED_SOURCE_PRELOAD_REQUIRED')
    from tools.semantic_registry_recovery_execution import postboot_prepare as p, original_tls, caller_configuration
    from tools.semantic_live_route_diagnostic import reader as transport
    from tools.ingestion_readiness_patch_execution import runtime_guard
    from engine_creation import Engine
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip(); files = p.Files(); preparation = case['preparation']
    STAGE = 'RECONCILE_OLD_CLAIMS'
    old_root = p.prepared_root(preparation, manifest, boot)
    prior = p.reconcile_prior_preparation(preparation, files, boot)
    require(prior['priorAttemptCounts'] == {'engineGets': 12, 'adminGets': 2, 'frozenConfigurationGets': 0}, 'BOTH_EARLIER_PREPARATIONS_REQUIRED')
    expected_claim = {'schema': p.SCHEMA, 'caseHash': digest(preparation), 'sourceClosureHash': CLOSURE_HASH,
        'bootId': boot, 'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
        'maximumTlsHandshakes': 1, 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False}
    claim, claim_profile = files.json(str(old_root / 'claim.json'))
    require(claim == expected_claim, 'EXACT_CONSUMED_TLS_PREPARATION_CLAIM_REQUIRED')
    for number in range(1, 7):
        marker, _ = files.json(str(old_root / ('engine-get-' + str(number) + '.json')))
        require(set(marker) == {'requestPathHash', 'attempt'} and marker['attempt'] == number
                and re.fullmatch('[0-9a-f]{64}', marker['requestPathHash']), 'EXACT_TLS_PREPARATION_ENGINE_MARKERS_REQUIRED')
    admin_marker, _ = files.json(str(old_root / 'admin-get.json'))
    require(admin_marker == {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1}, 'EXACT_TLS_PREPARATION_ADMIN_MARKER_REQUIRED')
    tls_marker, _ = files.json(str(old_root / 'tls-handshake.json'))
    require(set(tls_marker) == {'originHash', 'caProfileHash', 'maximumAttempts', 'httpRequests', 'bearersSent'}
            and tls_marker['maximumAttempts'] == 1 and tls_marker['httpRequests'] == tls_marker['bearersSent'] == 0,
            'EXACT_CONSUMED_TLS_ATTEMPT_REQUIRED')
    absent = ['engine-get-' + str(n) + '.json' for n in range(7, 13)] + ['frozen-get.json', 'source', 'prepared.json', 'review.json']
    def check_absent():
        for name in absent:
            try: (old_root / name).lstat()
            except FileNotFoundError: continue
            require(False, 'STOPPED_TLS_PREPARATION_ADVANCED')
    check_absent()
    STAGE = 'READ_RETAINED_INPUTS'
    inputs, _ = files.json(preparation['retainedInputs']['path'], preparation['retainedInputs']['sha256'])
    proposal = inputs['proposal']; patch = Path(preparation['patchContext'])
    review, _ = files.json(str(patch / 'review.json'), proposal['retainedPatchReviewHash'])
    journal, _ = files.json(str(patch / 'recovery.json'), proposal['retainedPatchJournalHash'])
    native = review['executionReview']; effects = {e['stage']: e for e in journal['effects']}
    require(journal['nextStage'] == len(native['stages']) == len(journal['effects']) == 12
            and all(e['state'] == 'APPLIED' for e in journal['effects']), 'SAME_COMPLETED_PATCH_REQUIRED')
    cid = effects['ingestion.CREATE_REPLACEMENT']['nativeResource']['containerId']
    first = effects['ingestion.START_REPLACEMENT']['nativeResource']
    require(re.fullmatch('[0-9a-f]{64}', cid) and first['containerId'] == cid, 'EXACT_ORIGINAL_CALLER_REQUIRED')
    root, legacy_roots = diagnostic_roots(p.PARENT, claim_profile, claim, boot)
    for parent in (root.parent, *root.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'PROTECTED_DIAGNOSTIC_PARENT_REQUIRED')
    STAGE = 'CLAIM_DIAGNOSTIC'
    require_unused_diagnostic(root, legacy_roots)
    try: os.mkdir(root, 0o700)
    except FileExistsError: require(False, 'TLS_DIAGNOSTIC_ALREADY_CLAIMED_DO_NOT_REPLAY')
    p.publish(root, 'claim.json', {'schema': SCHEMA, 'retainedClaimHash': digest(claim), 'bootId': boot,
        'diagnosticScriptSha256': globals()['__verified_diagnostic_sha256__'],
        'maximumEngineGets': 2, 'maximumResolverCalls': 2, 'maximumNewTlsHandshakes': 1,
        'retainedTlsAttemptMarkers': 1, 'cumulativeTlsAttemptCeiling': 2, 'automaticReplayAllowed': False, 'budgetReset': False})
    binding = proposal['engineBinding']; engine = Engine(binding['socketPath'], tuple(binding['socketBinding']))
    path = '/v1.44/containers/' + cid + '/json'; engine_calls = 0
    def get():
        nonlocal engine_calls
        require(engine_calls < 2, 'TWO_DIAGNOSTIC_ENGINE_GETS_ONLY'); engine_calls += 1
        p.publish(root, 'engine-get-' + str(engine_calls) + '.json', {'pathHash': digest(path), 'attempt': engine_calls})
        status, value = engine.request('GET', path)
        require(status == 200 and value.get('Id') == cid, 'CURRENT_EXACT_CALLER_UNPROVEN')
        return value
    STAGE = 'GET_CURRENT_CALLER'
    caller = get(); pin = p.current_pin(caller)
    require(caller['State']['Pid'] == first['pid'] and caller['State']['StartedAt'] == first['startedAt']
            and caller['RestartCount'] == 0, 'SAME_ORIGINAL_CALLER_GENERATION_REQUIRED')
    STAGE = 'SEAL_CURRENT_CONFIGURATION_CA'
    origin, _, config = caller_configuration.configuration(caller)
    ca, ca_source = original_tls.system_ca(files)
    require(digest(origin) == tls_marker['originHash'] and digest(ca) == tls_marker['caProfileHash'], 'SAME_ORIGINAL_TLS_ORIGIN_AND_CA_REQUIRED')
    u = urlsplit(origin); require(u.scheme == 'https', 'ORIGINAL_HTTPS_ORIGIN_REQUIRED')
    program = native['gatewayTransportProfile']['pythonExecutable']; transport.verify_program(program)
    _, ca_raw = files.seal(ca['path'], 1048576, ca['sha256'])
    STAGE = 'READ_RESOLVER_VIEWS'
    (host_servers, host_shape), host_profile = host_resolver(files)
    pid = caller['State']['Pid']; ticks = transport.process_ticks(pid)
    (caller_servers, caller_shape), resolver_profile = caller_resolver(pid, ticks, transport.process_ticks)
    namespace_fd = os.open('/proc/' + str(pid) + '/ns/net', os.O_RDONLY | os.O_CLOEXEC)
    identity = lambda info: (info.st_dev, info.st_ino)
    ns_pin = identity(os.fstat(namespace_fd))
    try:
        p.publish(root, 'host-dns-attempt.json', {'maximumResolverCalls': 1, 'httpRequests': 0, 'tlsHandshakes': 0})
        STAGE = 'RUN_HOST_DNS'
        host = run_child('HOST_DNS', origin, ca_raw, program, namespace_fd)
        p.publish(root, 'caller-probe-attempt.json', {'maximumResolverCalls': 1, 'maximumTlsHandshakes': 1, 'httpRequests': 0, 'bearersSent': 0})
        STAGE = 'RUN_CALLER_DNS_TLS'
        caller_result = run_child('CALLER_DNS_TLS', origin, ca_raw, program, namespace_fd)
        require(transport.process_ticks(pid) == ticks and ns_pin == identity(os.fstat(namespace_fd))
                == identity(os.stat('/proc/' + str(pid) + '/ns/net')), 'CALLER_NAMESPACE_CHANGED_DURING_DIAGNOSTIC')
        caller_ns_is_host = ns_pin == identity(os.stat('/proc/self/ns/net'))
    finally: os.close(namespace_fd)
    STAGE = 'VERIFY_SAME_CONTEXT'
    runtime_guard.unchanged(get(), pin)
    require(caller_configuration.configuration(caller, config)[0] == origin
            and caller_resolver(pid, ticks, transport.process_ticks)[1] == resolver_profile
            and host_resolver(files)[1] == host_profile and original_tls.resolve_system_ca() == ca_source,
            'TLS_DIAGNOSTIC_INPUTS_CHANGED')
    transport.verify_program(program); files.verify(); check_absent()
    require(p.reconcile_prior_preparation(preparation, files, boot) == prior
            and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'RETAINED_CLAIMS_OR_BOOT_CHANGED')
    private = {'origin': origin, 'ca': ca, 'caSource': ca_source, 'callerPin': pin,
        'host': host, 'caller': caller_result, 'oldClaim': claim_profile}
    STAGE = 'PUBLISH_PRIVATE_OBSERVATION'
    p.publish(root, 'observation.json', private)
    return {'schema': SCHEMA, 'status': 'TLS_DIAGNOSTIC_OBSERVED', 'complete': True, 'finding': finding(host, caller_result),
        'privateObservationPath': str(root / 'observation.json'), 'privateObservationHash': digest(private),
        'hostDns': public_child(host), 'callerDnsTls': public_child(caller_result),
        'hostResolverShape': host_shape, 'callerResolverShape': caller_shape,
        'sameNameserverList': host_servers == caller_servers, 'callerNetworkNamespaceIsHost': caller_ns_is_host,
        'sameResolvedAddressSet': host['addressSetHash'] is not None and host['addressSetHash'] == caller_result['addressSetHash'],
        'engineGets': engine_calls, 'adminGets': 0, 'maximumResolverCalls': 2,
        'retainedPreparationAttemptCounts': {'engineGets': 18, 'adminGets': 3, 'frozenConfigurationGets': 0, 'tlsAttemptMarkers': 1},
        'cumulativeEngineGetCeiling': 20, 'cumulativeTlsAttemptCeiling': 2,
        'maximumNewTlsHandshakes': 1, 'newTlsHandshakeAttempted': caller_result['tlsHandshakeAttempted'],
        'originalFailureReproduced': False, 'originalExceptionRecovered': False,
        'applicationEntryInvoked': False, 'httpRequests': 0, 'bearersSent': 0, 'tokenFilesOpened': 0,
        'oauthRequests': 0, 'databaseCalls': 0, 'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False,
        'addressesPrinted': False, 'rawErrorsPrinted': False, 'readOnlyRuntime': True,
        'rootCauseEstablished': False, 'serviceReadinessEstablished': False, 'releaseAcceptance': False,
        'automaticReplayAllowed': False, 'budgetReset': False}


if __name__ == '__main__':
    def expired(*_): require(False, 'TLS_DIAGNOSTIC_DEADLINE')
    signal.signal(signal.SIGALRM, expired); signal.alarm(45)
    try:
        result = diagnose()
    except (Exception, KeyboardInterrupt) as error:
        code = str(error) if isinstance(error, Stop) else ''
        result = {'schema': SCHEMA, 'status': 'STOP_RECONCILE', 'complete': False,
            'reasonCode': code if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', code) else 'TLS_DIAGNOSTIC_INPUT_OR_OUTCOME_UNPROVEN',
            'stage': STAGE, 'exceptionClass': type(error).__name__ if type(error).__name__ in (
                'Stop', 'RecoveryDenied', 'Denied', 'OSError', 'PermissionError', 'FileNotFoundError', 'TimeoutError',
                'KeyError', 'TypeError', 'ValueError', 'RuntimeError', 'JSONDecodeError') else 'OTHER',
            'errno': error.errno if isinstance(error, OSError) and type(error.errno) is int and -4096 <= error.errno <= 4096 else None,
            'contextsAndClaimsRetained': True, 'originalExceptionRecovered': False, 'httpRequests': 0, 'bearersSent': 0,
            'oauthRequests': 0, 'databaseCalls': 0, 'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}
    signal.alarm(0); print(encoded(result).decode(), flush=True)
    raise SystemExit(0 if result['complete'] else 2)
