"""Read-only diagnosis of one failed private trust snapshot. Never rerun prepare."""
import hashlib
import json
import os
from pathlib import Path
import stat
import ssl

ROOT = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-trust-dlz2t6B6')
SOURCE_HASH = 'cc068fd31923027f24c60c6efb1b89300aa5d6e5809dcb7060cb95951661b420'
ACCOUNT_HASH = 'd3fe5e78d84e021c4a9afdade8ad01add681e1037d26238eb972e03fb9c472fb'

def sealed(filename, sha):
    fd = os.open(filename, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        assert stat.S_ISREG(s.st_mode) and s.st_uid == s.st_gid == 0 and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= 1048576
        raw = os.read(fd, 1048577)
        assert hashlib.sha256(raw).hexdigest() == sha
        return raw
    finally:
        os.close(fd)

def metadata(filename):
    try:
        s = filename.lstat()
        return {'present': True, 'regularFile': stat.S_ISREG(s.st_mode), 'symlink': stat.S_ISLNK(s.st_mode), 'uid': s.st_uid, 'gid': s.st_gid, 'mode': oct(stat.S_IMODE(s.st_mode)), 'bytes': s.st_size}
    except FileNotFoundError:
        return {'present': False}

def check(name, function, results):
    try:
        result = function()
        facts = result if type(result) is dict else {}
        valid = all(facts.get(key, True) is True for key in ('hashMatchesExpected', 'identityMatchesExpected', 'executable'))
        results[name] = {'status': 'PASS' if valid else 'BLOCKED', **facts}
    except Exception as error:
        trace = error.__traceback__; line = 0
        while trace:
            if trace.tb_frame.f_code.co_filename in (str(ROOT/'prepare-provider-v2-trust.py'), str(ROOT/'provider-role-accounts.py')):
                line = trace.tb_lineno
            trace = trace.tb_next
        kind = type(error).__name__
        results[name] = {'status': 'BLOCKED', 'errorClass': kind if kind in {'AssertionError', 'ValueError', 'OSError', 'PermissionError', 'FileNotFoundError', 'SSLError', 'KeyError', 'TypeError'} else 'OTHER', 'sourceLine': line}

def diagnose():
    assert os.geteuid() == os.getegid() == 0
    raw = sealed(ROOT/'prepare-provider-v2-trust.py', SOURCE_HASH)
    account_raw = sealed(ROOT/'provider-role-accounts.py', ACCOUNT_HASH)
    ns = {'__name__': 'ouf_read_only_trust_diagnosis', '__file__': str(ROOT/'prepare-provider-v2-trust.py')}
    exec(compile(raw, ns['__file__'], 'exec'), ns)
    # Only declarations were loaded. prepare(), make_trust(), write() and main()
    # are never called. Existing private key files are never opened.
    checks = {}
    check('ROOT_ANCESTORS', lambda: ns['ancestors'](ROOT), checks)
    def profile():
        value = ns['read'](ns['AUTHORITY'])
        sha = hashlib.sha256(value).hexdigest()
        return {'hashMatchesExpected': sha == ns['AUTHORITY_HASH'], 'actualSha256': sha}
    check('AUTHORITY_PROFILE', profile, checks)
    def executable():
        value = ns['read'](ns['OPENSSL'], private=False, limit=16777216)
        sha = hashlib.sha256(value).hexdigest()
        return {'hashMatchesExpected': sha == ns['OPENSSL_HASH'], 'actualSha256': sha, 'executable': os.access(ns['OPENSSL'], os.X_OK)}
    check('OPENSSL_BINDING', executable, checks)
    def public_ca():
        value = ns['read'](Path('/etc/ssl/certs/ca-certificates.crt'), private=False)
        assert b'PRIVATE KEY' not in value
        ssl.create_default_context(cadata=value.decode('ascii'))
        return {'publicTrustParses': True}
    check('SYSTEM_PUBLIC_CA', public_ca, checks)
    account_ns = {'__name__': 'ouf_read_only_role_diagnosis', '__file__': str(ROOT/'provider-role-accounts.py')}
    exec(compile(account_raw, account_ns['__file__'], 'exec'), account_ns)
    def accounts(role):
        row = account_ns['inspect'](role)
        return {'uid': row['uid'], 'gid': row['gid'], 'identityMatchesExpected': (row['uid'], row['gid']) == ns['IDS'][role], 'layerBytesVerified': row['layerBytesVerified']}
    for role in ns['HOSTS']:
        check('ROLE_'+role.upper(), lambda role=role: accounts(role), checks)
    paths = ['preparation-claim.json', 'trust-receipt.json', 'ca.key', 'ca.crt', 'trust-bundle.pem']
    paths += [role+'/'+filename for role in ns['HOSTS'] for filename in ('server.key', 'server.crt', 'server.csr', 'extensions.cnf', 'provider-receipt.key')]
    files = {name: metadata(ROOT/name) for name in paths}
    checks['SNAPSHOT_ROOT'] = metadata(ROOT)
    return {'schema': 'ouf.semantic-provider-v2-trust-read-only-diagnosis.v1', 'snapshotDirectory': str(ROOT), 'sourceBytesVerified': True, 'checks': checks, 'fileMetadata': files, 'configurationWrites': 0, 'containerLifecycleOperations': 0, 'privateKeysRead': 0, 'secretValuesPrinted': False, 'prepareInvoked': False, 'startAuthorized': False}

def main():
    try:
        print('OUF_PROVIDER_V2_TRUST_DIAGNOSIS='+json.dumps(diagnose(), sort_keys=True))
        return 0
    except Exception:
        print('OUF_PROVIDER_V2_TRUST_DIAGNOSIS=BLOCKED STAGE=SEALED_DIAGNOSTIC_INPUT NO_RAW_OUTPUT=true')
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
