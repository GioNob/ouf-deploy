"""Read only selected public authority receipts; no keys or runtime operations."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path('/etc/ouf/deploy-snapshots')
COHORTS = {
    'semantic-authority-provisioning-20261004-164654': ('key-custody-receipt.json', 'authority-draft.json'),
    'semantic-trust-policy-preparation-20261004-172336': ('policy-preparation-receipt.json', 'trust-policy.json'),
}
FIELDS = ('schema', 'state', 'sourceCommit', 'sourceSha256', 'helperSha256',
          'authSourceSha256', 'protocolSourceSha256', 'opensslSha256',
          'custodyReceiptHash', 'draftHash', 'policyHash', 'originalNotBefore',
          'originalExpiresAt', 'createdAt', 'roleSigningAuthorized',
          'trustPolicyProvisioned', 'trustPolicyInstalled', 'policyConsumerLinked',
          'startAuthorized')

def read(path):
    for p in (path.parent, *path.parent.parents):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError('UNSAFE_ANCESTOR')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1 or s.st_size > 131072:
            raise ValueError('UNSAFE_RECEIPT')
        raw = os.read(fd, 131073)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(raw) != s.st_size or any(getattr(s, k) != getattr(after, k) for k in fields):
            raise ValueError('RECEIPT_DRIFT')
        def unique(pairs):
            d = {}
            for k, v in pairs:
                if k in d: raise ValueError('DUPLICATE_KEY')
                d[k] = v
            return d
        value = json.loads(raw, object_pairs_hook=unique)
        if type(value) is not dict: raise ValueError('INVALID_RECEIPT')
        return raw, value
    finally:
        os.close(fd)

def project(value):
    result = {k: value[k] for k in FIELDS if type(value.get(k)) in (str, int, bool)}
    # Explicit identity names only; never copy arbitrary configuration or keys.
    names = ('installationRef', 'entityRef', 'installerIssuerRef', 'attestorIssuerRef', 'installerKeyRef', 'attestorKeyRef')
    bindings = value.get('bindings', {})
    if type(bindings) is dict:
        result['bindings'] = {k: bindings[k] for k in names if type(bindings.get(k)) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', bindings[k])}
    hashes = value.get('inventoryHashes', {})
    if type(hashes) is dict:
        result['inventoryHashes'] = {k: v for k, v in hashes.items() if k in ('dossier.json', 'authority-plan.json', 'source-package-receipt.json') and type(v) is str and re.fullmatch('[0-9a-f]{64}', v)}
    return result

def collect():
    rows = []
    for cohort, names in COHORTS.items():
        for name in names:
            for parent in (ROOT / cohort, ROOT / cohort / 'prepared'):
                path = parent / name
                try:
                    raw, value = read(path)
                    rows.append({'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'metadata': project(value)})
                except FileNotFoundError:
                    continue
    return rows

def main():
    try:
        if os.geteuid() != 0 or not sys.flags.isolated or not sys.dont_write_bytecode:
            raise ValueError('ROOT_ISOLATED_REQUIRED')
        first, second = collect(), collect()
        if first != second: raise ValueError('READBACK_DRIFT')
        print('OUF_PROVIDER_AUTHORITY_INPUTS=' + json.dumps({'status': 'READ_ONLY', 'receipts': second, 'privateKeysRead': 0, 'configurationWrites': 0, 'containerLifecycleOperations': 0, 'startAuthorized': False}, sort_keys=True))
        return 0
    except Exception:
        print('OUF_PROVIDER_AUTHORITY_INPUTS=BLOCKED NO_RAW_OUTPUT=true')
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
