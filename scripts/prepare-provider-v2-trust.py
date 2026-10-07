"""Prepare fresh role-bound private TLS inputs only. No runtime or authority activation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess

ACCOUNT_SOURCE_HASH = 'd3fe5e78d84e021c4a9afdade8ad01add681e1037d26238eb972e03fb9c472fb'
AUTHORITY = Path('/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json')
AUTHORITY_HASH = '7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18'
OPENSSL = Path('/usr/bin/openssl')
OPENSSL_HASH = 'acc10176d038aeb7b2a77d9ec972ac2985857a7191f7aecb7c54ef0e2c7e9549'
HOSTS = {'adapter': 'ouf-semantic-provider-v2', 'southbound': 'ouf-semantic-southbound-v2'}
IDS = {'adapter': (10006, 10006), 'southbound': (636, 636)}
STAGE = 'ARGUMENT_VALIDATION'

def require(ok):
    if not ok:
        raise ValueError('PROVIDER_V2_TRUST_UNPROVEN')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()

def ancestors(directory):
    for item in (directory, *directory.parents):
        s = item.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022)

def read(filename, uid=0, gid=0, private=True, limit=1048576):
    ancestors(filename.parent)
    fd = os.open(filename, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == uid and before.st_gid == gid and before.st_size <= limit and not before.st_mode & (0o077 if private else 0o022))
        raw = os.read(fd, limit+1); require(len(raw) <= limit)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(tuple(getattr(before, k) for k in fields) == tuple(getattr(os.fstat(fd), k) for k in fields) == tuple(getattr(filename.lstat(), k) for k in fields))
        return raw
    finally:
        os.close(fd)

def write(filename, raw, uid=0, gid=0, mode=0o600):
    fd = os.open(filename, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode); os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally:
        os.close(fd)
    d = os.open(filename.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        os.fsync(d)
    finally:
        os.close(d)

def command(executable, *args, expected_success=True):
    r = subprocess.run([str(executable), *map(str, args)], capture_output=True, timeout=30)
    require((r.returncode == 0) is expected_success)

def verified_executable(filename, expected_hash):
    actual = digest(read(filename, private=False, limit=16777216))
    require(actual == expected_hash and os.access(filename, os.X_OK))
    return {'path': str(filename), 'sha256': actual}

def make_trust(root, roles, public_ca, executable):
    require(set(HOSTS) == {r['role'] for r in roles} and len(roles) == 2)
    for row in roles:
        require((row['uid'], row['gid']) == IDS[row['role']] and row['layerBytesVerified'] is True)
    require(b'PRIVATE KEY' not in public_ca)
    ssl.create_default_context(cadata=public_ca.decode('ascii'))
    for name in ('ca.key', 'ca.crt', 'trust-bundle.pem', 'adapter', 'southbound', 'trust-receipt.json'):
        require(not os.path.lexists(root/name))
    old_mask = os.umask(0o077)
    try:
        command(executable, 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', root/'ca.key', '-x509', '-sha256', '-days', '365', '-subj', '/CN=OUF-provider-v2-private-CA', '-out', root/'ca.crt', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        for name in ('ca.key', 'ca.crt'):
            os.chmod(root/name, 0o600); read(root/name)
        receipt_key = secrets.token_hex(32).encode()
        for row in roles:
            role = row['role']; host = HOSTS[role]; directory = root/role
            directory.mkdir(mode=0o700)
            command(executable, 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', directory/'server.key', '-out', directory/'server.csr', '-subj', '/CN='+host)
            write(directory/'extensions.cnf', ('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+host+'\n').encode())
            command(executable, 'x509', '-req', '-in', directory/'server.csr', '-CA', root/'ca.crt', '-CAkey', root/'ca.key', '-set_serial', secrets.randbits(128)+1, '-sha256', '-days', '90', '-extfile', directory/'extensions.cnf', '-out', directory/'server.crt')
            for name in ('server.key', 'server.crt'):
                os.chmod(directory/name, 0o600); os.chown(directory/name, row['uid'], row['gid'])
                read(directory/name, row['uid'], row['gid'])
            write(directory/'provider-receipt.key', receipt_key, row['uid'], row['gid'])
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(directory/'server.crt', directory/'server.key')
            command(executable, 'verify', '-CAfile', root/'ca.crt', '-purpose', 'sslserver', '-verify_hostname', host, directory/'server.crt')
            command(executable, 'verify', '-CAfile', root/'ca.crt', '-purpose', 'sslserver', '-verify_hostname', 'wrong-host.invalid', directory/'server.crt', expected_success=False)
        write(root/'trust-bundle.pem', public_ca.rstrip()+b'\n'+read(root/'ca.crt'), mode=0o644)
    finally:
        os.umask(old_mask)
    hashes = {'ca.key': digest(read(root/'ca.key')), 'ca.crt': digest(read(root/'ca.crt')), 'trust-bundle.pem': digest(read(root/'trust-bundle.pem', private=False))}
    for row in roles:
        for name in ('server.key', 'server.crt', 'provider-receipt.key'):
            filename = row['role']+'/'+name
            hashes[filename] = digest(read(root/filename, row['uid'], row['gid']))
    return hashes

def prepare(root):
    global STAGE
    STAGE = 'ROOT_AND_SOURCE_BINDING'
    require(os.geteuid() == os.getegid() == 0)
    require(root.parent == Path('/etc/ouf/deploy-snapshots') and re.fullmatch(r'semantic-provider-v2-trust-[A-Za-z0-9]+', root.name))
    ancestors(root); require(stat.S_IMODE(root.lstat().st_mode) == 0o700)
    source = read(root/'prepare-provider-v2-trust.py')
    account_raw = read(root/'provider-role-accounts.py'); require(digest(account_raw) == ACCOUNT_SOURCE_HASH)
    STAGE = 'AUTHORITY_PROFILE_BINDING'
    authority_raw = read(AUTHORITY); require(digest(authority_raw) == AUTHORITY_HASH)
    authority = json.loads(authority_raw)
    require(authority['schema'] == 'ouf.semantic-existing-installation-authority-bindings.v1' and authority['authorities']['installationRef'] == 'ouf-lab-netcup-01' and authority['authorities']['entityRef'] == 'ouf-lab')
    STAGE = 'OPENSSL_EXECUTABLE_BINDING'
    openssl_binding = verified_executable(OPENSSL, OPENSSL_HASH)
    STAGE = 'SYSTEM_PUBLIC_CA_BINDING'
    ca_path = Path('/etc/ssl/certs/ca-certificates.crt')
    public_ca = read(ca_path, private=False)
    STAGE = 'IMAGE_ROLE_LAYER_BINDING'
    namespace = {'__name__': 'ouf_provider_role_accounts', '__file__': str(root/'provider-role-accounts.py')}
    exec(compile(account_raw, str(root/'provider-role-accounts.py'), 'exec'), namespace)
    roles = [namespace['inspect'](role) for role in HOSTS]
    require(all((row['uid'], row['gid']) == IDS[row['role']] for row in roles))
    claim = {'schema': 'ouf.semantic-provider-v2-trust-claim.v1', 'state': 'PREPARING_PRIVATE_TRUST', 'sourceHash': digest(source), 'accountSourceHash': digest(account_raw), 'authorityProfileHash': AUTHORITY_HASH, 'roles': roles, 'startAuthorized': False}
    STAGE = 'CLAIM_PUBLICATION'
    write(root/'preparation-claim.json', encoded(claim))
    STAGE = 'PRIVATE_TLS_PREPARATION'
    hashes = make_trust(root, roles, public_ca, OPENSSL)
    STAGE = 'INPUT_STABILITY_READBACK'
    require(read(AUTHORITY) == authority_raw and read(root/'prepare-provider-v2-trust.py') == source and read(root/'provider-role-accounts.py') == account_raw and read(ca_path, private=False) == public_ca and verified_executable(OPENSSL, OPENSSL_HASH) == openssl_binding)
    report = {'schema': 'ouf.semantic-provider-v2-private-trust.v1', 'status': 'PRIVATE_TRUST_PREPARED', 'directory': str(root), 'sourceHash': digest(source), 'accountSourceHash': digest(account_raw), 'authorityProfileHash': AUTHORITY_HASH, 'roles': [{**r, 'hostname': HOSTS[r['role']]} for r in roles], 'artifactHashes': hashes, 'publicCaHash': digest(public_ca), 'tlsCertificatesIssued': 3, 'tlsKeysGenerated': 3, 'providerReceiptKeyGenerated': True, 'installationAuthorityKeysRead': 0, 'deploymentSignaturesIssued': 0, 'containerLifecycleOperations': 0, 'imageImportPerformed': False, 'mountsInstalled': False, 'rulesChanged': False, 'serviceChanges': 0, 'providerCalls': 0, 'publisherTrustAccepted': False, 'acceptanceGranted': False, 'startAuthorized': False, 'notReleaseAcceptance': True, 'generalSudoGranted': False}
    report['opensslBinding'] = openssl_binding
    STAGE = 'RECEIPT_PUBLICATION'
    write(root/'trust-receipt.json', encoded(report))
    require(read(root/'trust-receipt.json') == encoded(report))
    return report

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--package-root', type=Path, required=True)
    parser.add_argument('--prepare-private-trust-only', action='store_true')
    args = parser.parse_args()
    try:
        require(args.prepare_private_trust_only); report = prepare(args.package_root)
        print('OUF_PROVIDER_V2_TRUST='+json.dumps(report, sort_keys=True)); return 0
    except Exception as error:
        kind = type(error).__name__
        allowed = {'ValueError', 'OSError', 'PermissionError', 'FileNotFoundError', 'SSLError', 'KeyError', 'TypeError', 'TimeoutExpired'}
        print('OUF_PROVIDER_V2_TRUST=BLOCKED STAGE='+STAGE+' ERROR_CLASS='+(kind if kind in allowed else 'OTHER')+' PARTIAL_EVIDENCE_RETAINED=true DO_NOT_RERUN_APPLY=true NO_RAW_OUTPUT=true'); return 1

if __name__ == '__main__':
    raise SystemExit(main())
