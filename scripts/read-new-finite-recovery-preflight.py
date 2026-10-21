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


import sys
PROGRAMS = {
    'activate.py': '40822d277af67ec7145fb811cc2076e7845072418f1c25e306e1c0c9e14499e7',
    'activation_core.py': '06d14a340db6d35a795115fd921f901e1cd0de74c06174562107270b08fc7c2a',
    'reader.py': '4ddfda694150771fc8059ce22080a44c1d42db80c4f85b6b42f85c46442536d2',
    'dns.py': 'f1491cca148c488bbee8089dabcada0361781962d7b2858ad2fc4549cea3696f',
    'materialize_southbound_lease_refresh.py': 'c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079',
    'nft.py': '04cd115c756158ce2c04f32608380d7a40f4577d85785dfe46571825876545c1',
    'supervisor.py': '08a354cfbea6a31ed1ea21dd80ddab0d0f983e3a0143a6f656124cf843d5635c'}
OWNER_HASH = '656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'
DENIAL_HASH = '96f10ca10c9f9409bb6fff310cc58886b58421b9bd2292ddaf3142fb61a9b05a'
JOURNAL_HASH = 'a58f0cb6e011879fc22723356d19926adf8945c38dcdbf2d21ab3fa34dd6f7f1'

def require(ok, reason):
    if not ok: raise ValueError(reason)

def validate_artifacts(auth, claim, receipt, denial):
    require(auth.get('schema') == 'ouf.provider-finite-lease-recovery-authorization.v1'
            and auth.get('ownerConfigurationHash') == OWNER_HASH and auth.get('serviceUnit') == UNIT
            and auth.get('programHashes') == PROGRAMS and auth.get('automaticRestart') is False
            and auth.get('enableAtBoot') is False and auth.get('containerLifecycleAuthorized') is False,
            'EXACT_CONSUMED_R10_AUTHORIZATION_REQUIRED')
    require(claim.get('directory') == str(ROOT) and claim.get('approvalRef') == auth.get('approvalRef')
            and type(auth.get('approvalRef')) is str and claim.get('startAuthorized') is False,
            'CONSUMED_R10_CLAIM_BINDING_DRIFT')
    require(receipt.get('status') == 'TWO_FLOW_LEASE_ACTIVE_AND_RENEWED' and receipt.get('doNotRerunApply') is True
            and receipt.get('ownerConfigurationHash') == OWNER_HASH and receipt.get('serviceUnit') == UNIT,
            'EXACT_HISTORICAL_R10_ACTIVATION_RECEIPT_REQUIRED')
    require(denial.get('status') == 'LEASE_WORKER_FAILED' and type(denial.get('refreshCount')) is int
            and denial['refreshCount'] == 250 and denial.get('doNotRerunApply') is True,
            'EXACT_RETAINED_R10_FAILURE_REQUIRED')

def main():
    report = {'schema': 'ouf.provider-new-recovery-read-only-preflight.v1', 'commonLockAcquired': False,
              'r10Touched': False, 'privateValuesPrinted': False, 'productionApplyReady': False,
              'newClaimCreated': False, 'newStartAuthorized': False, 'notReleaseAcceptance': True}
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_READER_REQUIRED')
        paths = ['authorization.json', 'activation-receipt.json', 'worker-denial.json', '/etc/ouf/provider-finite-lease-recovery-r10.claim']
        saved = {p: raw_file(p) for p in paths}
        require(all(type(v) is bytes for v in saved.values()), 'RETAINED_R10_ARTIFACTS_REQUIRED')
        auth, receipt, denial, claim = [json.loads(saved[p]) for p in paths]
        validate_artifacts(auth, claim, receipt, denial)
        require(hashlib.sha256(saved['worker-denial.json']).hexdigest() == DENIAL_HASH, 'RETAINED_R10_DENIAL_HASH_DRIFT')
        for name, expected in PROGRAMS.items():
            raw = raw_file(name)
            require(raw is not None and hashlib.sha256(raw).hexdigest() == expected, 'INSTALLED_R10_PROGRAM_HASH_DRIFT')
        raw = raw_file('reader.py')
        reader = types.ModuleType('qualified_recovery_preflight_reader')
        reader.__file__ = str(ROOT / 'reader.py')
        exec(compile(raw, reader.__file__, 'exec'), reader.__dict__)
        current = reader.collect_cutover()
        lease = current['lease']
        require(lease['journalState'] == 'QUIESCED' and lease['leaseAuthorized'] is False
                and lease['providerSetsEmpty'] is True and lease['journalAndMembershipConsistent'] is True
                and lease['journalFileHash'] == JOURNAL_HASH, 'EXACT_CURRENT_QUIESCENCE_REQUIRED')
        p = subprocess.run(['/usr/bin/systemctl', 'show', UNIT, '--no-pager', '--property=ActiveState,MainPID,Restart,NRestarts'],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=15,
                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        require(p.returncode == 0 and len(p.stdout) <= 8192, 'BOUNDED_SERVICE_READ_REQUIRED')
        service = dict(line.split('=', 1) for line in p.stdout.decode().splitlines() if '=' in line)
        require(service == {'ActiveState': 'failed', 'MainPID': '0', 'Restart': 'no', 'NRestarts': '0'}, 'CONSUMED_R10_SERVICE_STATE_DRIFT')
        require(all(raw_file(p) == raw for p, raw in saved.items()), 'RETAINED_R10_ARTIFACT_CHANGED')
        report.update(status='NEW_RECOVERY_INPUT_BINDINGS_CAPTURED_NOT_APPLY_AUTHORITY',
                      retainedArtifactHashes={p: hashlib.sha256(raw).hexdigest() for p, raw in saved.items()},
                      currentBindings=current, failedRefreshCount=250, doNotRerunR10=True,
                      missingBeforeApply=['COMPLETE_NEW_WORKER_QUALIFICATION', 'NEW_ONE_USE_SOURCE_BOUND_TECHNICAL_DECISION_AND_CLAIM'])
    except Exception as error:
        report.update(status='NEW_RECOVERY_PREFLIGHT_BLOCKED', reason=code(str(error)))
    print('OUF_NEW_RECOVERY_PREFLIGHT=' + json.dumps(report, sort_keys=True))

if __name__ == '__main__': main()
