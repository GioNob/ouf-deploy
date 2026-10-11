"""Bounded root-owned R10 status projection; no locks, changes or private values."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import types

ROOT = Path('/etc/ouf/deploy-snapshots/semantic-finite-lease-recovery-r10-nw9ue4d5')
UNIT = 'ouf-semantic-provider-lease-finite-r10.service'

def code(value):
    return value if type(value) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,120}', value) else 'UNPROJECTED'

def project(value, depth=0):
    result = {k: code(value[k]) for k in ('status', 'phase', 'reason') if k in value}
    for k in ('refreshCount', 'workerPid', 'errno'):
        if type(value.get(k)) is int and 0 <= value[k] <= 2**63-1:
            result[k] = value[k]
    for k in ('setsRevoked', 'leaseAuthorized', 'doNotRerunApply'):
        if type(value.get(k)) is bool:
            result[k] = value[k]
    nft = value.get('nftReadback')
    if (type(nft) is dict and set(nft) == {'family', 'flowIndex', 'expiresType', 'expiresValue', 'duplicateAddress', 'configuredLeaseSeconds'}
            and nft['family'] in ('inet', 'bridge') and type(nft['flowIndex']) is int and 0 <= nft['flowIndex'] <= 31
            and nft['expiresType'] in ('int', 'float', 'str', 'NoneType', 'bool', 'list', 'dict')
            and (nft['expiresValue'] is None or type(nft['expiresValue']) is int and 0 <= nft['expiresValue'] < 2**31)
            and type(nft['duplicateAddress']) is bool and type(nft['configuredLeaseSeconds']) is int
            and 1 <= nft['configuredLeaseSeconds'] <= 3600):
        result['nftReadback'] = dict(nft)
    if depth < 6 and type(value.get('exceptionChain')) is list:
        result['exceptionChain'] = [project(v, depth + 1) for v in value['exceptionChain'][:6] if type(v) is dict]
    return result

def raw_file(name):
    for parent in [ROOT, *ROOT.parents]:
        s = parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('ROOT_ANCESTRY_UNPROVEN')
    try:
        fd = os.open(ROOT / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 65536:
            raise ValueError('PRIVATE_STATUS_CUSTODY_UNPROVEN')
        raw = os.read(fd, 65537)
        after = os.fstat(fd)
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns) or len(raw) != before.st_size:
            raise ValueError('STATUS_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)

def read(name):
    raw = raw_file(name)
    if raw is None:
        return {'present': False}
    value = json.loads(raw)
    if type(value) is not dict:
        raise ValueError('STATUS_OBJECT_REQUIRED')
    return {'present': True, 'sha256': hashlib.sha256(raw).hexdigest(), **project(value)}

def lease_observation():
    raw = raw_file('reader.py')
    if raw is None or hashlib.sha256(raw).hexdigest() != '4ddfda694150771fc8059ce22080a44c1d42db80c4f85b6b42f85c46442536d2':
        raise ValueError('INSTALLED_R10_READER_HASH_UNPROVEN')
    reader = types.ModuleType('qualified_installed_r10_reader')
    reader.__file__ = str(ROOT / 'reader.py')
    exec(compile(raw, reader.__file__, 'exec'), reader.__dict__)
    value = reader.collect()
    # collect is source-bound read-only and returns this reviewed public lease projection.
    return value['networkLease']

def main():
    result = {'schema': 'ouf.provider-r10-read-only-diagnosis.v1', 'r10Touched': False,
              'commonLockAcquired': False, 'privateValuesPrinted': False, 'notReleaseAcceptance': True}
    for name in ('worker-status.json', 'worker-denial.json'):
        try:
            result[name] = read(name)
        except Exception as error:
            result[name] = {'readProven': False, 'reason': code(str(error))}
    props = ['LoadState', 'ActiveState', 'SubState', 'MainPID', 'Restart', 'NRestarts', 'Result', 'ExecMainCode', 'ExecMainStatus']
    p = subprocess.run(['/usr/bin/systemctl', 'show', UNIT, '--no-pager', '--property=' + ','.join(props)],
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=15,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    service = {}
    if p.returncode == 0 and len(p.stdout) <= 8192:
        for line in p.stdout.decode().splitlines():
            key, sep, value = line.partition('=')
            if sep and key in props and re.fullmatch('[A-Za-z0-9_-]{1,64}', value):
                service[key] = value
    result['service'] = service
    try:
        result['currentNativeLease'] = lease_observation()
    except Exception as error:
        result['currentNativeLease'] = {'readProven': False, 'reason': code(str(error))}
    print('OUF_R10_READ_ONLY_DIAGNOSIS=' + json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    main()
