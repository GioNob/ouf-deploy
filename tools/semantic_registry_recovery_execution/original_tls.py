"""Authenticate the original HTTPS origin before any SERVICE bearer is sent.

Trust comes from the root-controlled compiled OpenSSL CA file, not a certificate
fetched without verification. One TLS-only handshake in the caller's namespace
verifies the chain and hostname and seals its leaf for subsequent pinned GETs.
"""
import os
from pathlib import Path
import ssl
import stat
import subprocess
from urllib.parse import urlsplit

from .core import require, encoded, hashed, digest
from . import caller_lookup
from tools.semantic_live_route_diagnostic.reader import process_ticks, verify_program

POLICY = {'mode': 'SYSTEM_PKI_PINNED', 'trustSource': 'COMPILED_OPENSSL_CA_FILE', 'maximumTlsHandshakes': 1}
MAX_PAYLOAD = 2097152

TLS_CHILD_SOURCE = r'''import hashlib,http.client,json,os,signal,ssl,sys
from urllib.parse import urlsplit
signal.alarm(8)
try:
    raw=sys.stdin.buffer.read(2097153)
    if not 0<len(raw)<=2097152:raise ValueError()
    v=json.loads(raw)
    if type(v)is not dict or set(v)!={'origin','ca'}:raise ValueError()
    u=urlsplit(v['origin'])
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:raise ValueError()
    if type(v['ca'])is not str or not 0<len(v['ca'].encode())<=1048576:raise ValueError()
    if len(sys.argv)!=2 or not sys.argv[1].isdigit():raise ValueError()
    fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=v['ca'])
    if not context.check_hostname or context.verify_mode!=ssl.CERT_REQUIRED:raise ValueError()
    client=http.client.HTTPSConnection(u.hostname,u.port or 443,context=context,timeout=4)
    client.connect()
    leaf=client.sock.getpeercert(binary_form=True)
    if not leaf:raise ValueError()
    result={'peerCertificateSha256':hashlib.sha256(leaf).hexdigest(),'certificateChainVerified':True,'hostnameVerified':True}
    client.close()
    sys.stdout.buffer.write(json.dumps(result,sort_keys=True,separators=(',',':')).encode());sys.stdout.buffer.flush()
except BaseException:os._exit(1)
os._exit(0)
'''

TLS_CHILD_SOURCE = caller_lookup.child(TLS_CHILD_SOURCE, "{'origin','ca'}")


def metadata(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def resolve_system_ca():
    # openssl_cafile is compiled in; cafile may instead be overridden through
    # SSL_CERT_FILE. Never use that environment-selected alternative here.
    selected = ssl.get_default_verify_paths().openssl_cafile
    require(type(selected) is str and selected.startswith('/') and len(selected) <= 4096,
            'COMPILED_SYSTEM_CA_FILE_REQUIRED')
    pending = Path(selected); links = []
    for _ in range(16):
        require('..' not in pending.parts and len(str(pending)) <= 4096, 'EXACT_COMPILED_CA_PATH_REQUIRED')
        parts = pending.parts; prefix = Path('/')
        root = prefix.lstat()
        require(root.st_uid == 0 and not root.st_mode & 0o022, 'ROOT_CONTROLLED_CA_ANCESTRY_REQUIRED')
        for index, name in enumerate(parts[1:], 1):
            prefix = prefix / name; info = prefix.lstat()
            require(info.st_uid == 0, 'ROOT_CONTROLLED_SYSTEM_CA_PATH_REQUIRED')
            if stat.S_ISLNK(info.st_mode):
                require(info.st_nlink == 1, 'SINGLE_SYSTEM_CA_LINK_REQUIRED')
                target = os.readlink(prefix)
                require(metadata(prefix.lstat()) == metadata(info), 'COMPILED_CA_LINK_CHANGED')
                links.append({'path': str(prefix), 'target': target, 'metadata': metadata(info)})
                base = Path(target) if target.startswith('/') else prefix.parent / target
                pending = Path(os.path.normpath(str(base.joinpath(*parts[index + 1:]))))
                break
            require(not info.st_mode & 0o022, 'ROOT_CONTROLLED_CA_ANCESTRY_REQUIRED')
            require(stat.S_ISREG(info.st_mode) if index == len(parts) - 1 else stat.S_ISDIR(info.st_mode),
                    'REGULAR_COMPILED_CA_FILE_REQUIRED')
        else:
            return {'compiledPath': selected, 'resolvedPath': str(pending), 'links': links}
    require(False, 'COMPILED_CA_LINK_DEPTH_EXCEEDED')


def system_ca(files):
    source = resolve_system_ca()
    profile, raw = files.seal(source['resolvedPath'], 1048576)
    require(resolve_system_ca() == source, 'COMPILED_CA_SELECTION_CHANGED')
    require(b'PRIVATE KEY' not in raw and b'-----BEGIN CERTIFICATE-----' in raw,
            'PUBLIC_SYSTEM_CA_CERTIFICATES_ONLY')
    return profile, source


def observe(origin, ca, program, caller, lookup_profile=None):
    from tools.ingestion_readiness_patch_execution import private_file
    u = urlsplit(origin)
    require(u.scheme == 'https' and u.hostname and not u.username and not u.password
            and u.path in ('', '/') and not u.query and not u.fragment and len(origin) <= 4096,
            'EXACT_ORIGINAL_HTTPS_ORIGIN_REQUIRED')
    verify_program(program); private_file.validate(ca)
    pid = caller['State']['Pid']; ticks = process_ticks(pid)
    ns = '/proc/' + str(pid) + '/ns/net'; fds = []; child = None
    identity = lambda info: (info.st_dev, info.st_ino)
    try:
        fd = os.open(ns, os.O_RDONLY | os.O_CLOEXEC); fds.append(fd)
        pin = identity(os.fstat(fd))
        payload = encoded({'origin': origin, 'ca': private_file.read(ca).decode('ascii'),
                           **caller_lookup.payload(caller, lookup_profile)})
        require(len(payload) <= MAX_PAYLOAD and process_ticks(pid) == ticks
                and pin == identity(os.stat(ns)), 'BOUNDED_CURRENT_CALLER_TLS_INPUT_REQUIRED')
        child = subprocess.Popen([program['path'], '-I', '-B', '-S', '-c', TLS_CHILD_SOURCE, str(fd)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            pass_fds=(fd,), close_fds=True, cwd='/', env={'LC_ALL': 'C'})
        raw, _ = child.communicate(payload, timeout=12)
        require(child.returncode == 0 and 0 < len(raw) <= 1024,
                'AUTHENTICATED_ORIGINAL_SERVICE_TLS_HANDSHAKE_UNCONFIRMED')
        import json
        result = json.loads(raw)
        require(type(result) is dict and set(result) == {'peerCertificateSha256', 'certificateChainVerified', 'hostnameVerified'}
                and hashed(result['peerCertificateSha256']) and result['certificateChainVerified'] is True
                and result['hostnameVerified'] is True, 'VERIFIED_ORIGINAL_SERVICE_TLS_IDENTITY_REQUIRED')
        require(process_ticks(pid) == ticks and pin == identity(os.fstat(fd)) == identity(os.stat(ns)),
                'CALLER_CHANGED_DURING_TLS_IDENTITY_OBSERVATION')
        private_file.read(ca); verify_program(program); caller_lookup.payload(caller, lookup_profile)
        return {**result, 'originHash': digest(origin), 'caProfileHash': digest(ca),
                'httpRequests': 0, 'bearersSent': 0, 'tlsHandshakes': 1}
    finally:
        if child is not None:
            if child.poll() is None: child.kill()
            child.wait(timeout=5)
            for stream in (child.stdin, child.stdout):
                if stream is not None: stream.close()
        for fd in reversed(fds): os.close(fd)
