"""Prove JSON expiry units in a NEW disposable netns; never touch host rules.

Only the installation's hash-bound nft binary is used. No hooks, network traffic,
DNS, lease grant, Docker, services, keys or persistent configuration are involved.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

OWNER = Path('/etc/ouf/deploy-snapshots/semantic-coordinated-boot-install-v2-e4repg0a/coordinated-configuration.json')
OWNER_HASH = '656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8'


def require(ok, reason):
    if not ok: raise RuntimeError(reason)


def private(path, digest=None, *, executable=False):
    path = Path(path)
    require(path.is_absolute(), 'ABSOLUTE_BOUND_SOURCE_REQUIRED')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'ROOT_OWNED_SOURCE_ANCESTOR_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022 and info.st_size <= 8388608
                and (bool(info.st_mode & 0o111) if executable else stat.S_IMODE(info.st_mode) == 0o600),
                'EXACT_ROOT_OWNED_SOURCE_REQUIRED')
        raw = os.read(fd, 8388609)
        def stable(value):
            return tuple(getattr(value, key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid',
                         'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        require(stable(info) == stable(os.fstat(fd)) == stable(path.lstat()) and len(raw) == info.st_size,
                'SOURCE_CHANGED_DURING_READ')
    finally: os.close(fd)
    require(digest is None or hashlib.sha256(raw).hexdigest() == digest, 'BOUND_SOURCE_HASH_MISMATCH')
    return raw


def expiry(data, family, table):
    values = [row['set'] for row in data['nftables'] if 'set' in row]
    require(len(values) == 1, 'ONE_ISOLATED_TEST_SET_REQUIRED')
    value = values[0]
    require(value.get('family') == family and value.get('table') == table and value.get('name') == 'unit_probe'
            and value.get('type') == 'ipv4_addr' and value.get('flags') == ['timeout'], 'ISOLATED_TEST_SET_BINDING_REQUIRED')
    entries = value.get('elem', [])
    require(len(entries) == 1, 'ONE_ISOLATED_TEST_ELEMENT_REQUIRED')
    element = entries[0]['elem']
    require(element.get('val') == '198.51.100.1' and type(element.get('timeout')) is int
            and element['timeout'] == 30 and type(element.get('expires')) is int
            and 25 <= element['expires'] <= 30, 'NFT_JSON_SECONDS_FORMAT_UNPROVEN')
    return element['expires']


def prove(binary, expected_hash):
    before = Path('/proc/self/ns/net').stat().st_ino
    library = ctypes.CDLL(None, use_errno=True)
    require(library.unshare(0x40000000) == 0, 'NEW_NETWORK_NAMESPACE_REQUIRED')
    after = Path('/proc/self/ns/net').stat().st_ino
    require(before != after, 'NETWORK_NAMESPACE_ISOLATION_UNPROVEN')
    raw = private(binary, expected_hash, executable=True)
    def run(args, text=None):
        value = subprocess.run([binary, *args], input=text, text=True, capture_output=True, timeout=5,
                               env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
        require(value.returncode == 0 and len(value.stdout) <= 65536 and len(value.stderr) <= 65536,
                'BOUNDED_ISOLATED_NFT_OPERATION_REQUIRED')
        require(private(binary, expected_hash, executable=True) == raw, 'NFT_BINARY_CHANGED_DURING_PROBE')
        return value.stdout
    require(not any('table' in row for row in json.loads(run(['-j','list','tables']))['nftables']),
            'NEW_NAMESPACE_MUST_HAVE_NO_TABLES')
    table = 'ouf_json_seconds_probe'
    rule = ''.join('add table '+family+' '+table+'\nadd set '+family+' '+table+
                   ' unit_probe { type ipv4_addr; flags timeout; }\nadd element '+family+' '+table+
                   ' unit_probe { 198.51.100.1 timeout 30s }\n' for family in ('inet','bridge'))
    created = False
    try:
        run(['-f','-'], rule); created = True
        first = {f:expiry(json.loads(run(['-j','list','table',f,table])),f,table) for f in ('inet','bridge')}
        time.sleep(1.2)
        second = {f:expiry(json.loads(run(['-j','list','table',f,table])),f,table) for f in ('inet','bridge')}
        require(all(1 <= first[f]-second[f] <= 3 for f in first), 'NFT_JSON_SECONDS_DECREMENT_UNPROVEN')
    finally:
        if created: run(['-f','-'], ''.join('delete table '+f+' '+table+'\n' for f in ('inet','bridge')))
    require(not any('table' in row for row in json.loads(run(['-j','list','tables']))['nftables']),
            'ISOLATED_TEST_TABLE_CLEANUP_UNPROVEN')
    return {'nftBinaryHash':expected_hash, 'jsonExpiryUnit':'SECONDS', 'configuredTestTimeoutSeconds':30,
            'firstExpiresByFamily':first, 'secondExpiresByFamily':second,
            'newNetworkNamespaceProven':True, 'isolatedTestTablesCleaned':True,
            'isolatedNftMutationBatches':2, 'hostFirewallWrites':0, 'nftVersionOutputHash':hashlib.sha256(run(['--version']).encode()).hexdigest()}


def main():
    result = {'schema':'ouf.lease.nft-json-unit-probe.v1','applicationCutoverAuthorized':False,
              'existingConfigurationWrites':0,'containerLifecycleOperations':0,'serviceRestarts':0,
              'privateKeysRead':0,'credentialFilesOpened':0,'dnsQueries':0,'providerCalls':0,
              'r9Touched':False,'leaseAuthorityGranted':False,'notReleaseAcceptance':True}
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv) == 1,
                'ISOLATED_ROOT_PROBE_REQUIRED')
        owner_raw = private(OWNER, OWNER_HASH); owner = json.loads(owner_raw)
        require(type(owner['nftPath']) is str and re.fullmatch('[0-9a-f]{64}',owner['nftSha256']), 'SEALED_NFT_BINDING_REQUIRED')
        result.update(prove(owner['nftPath'], owner['nftSha256']))
        require(private(OWNER, OWNER_HASH) == owner_raw, 'OWNER_CHANGED_DURING_PROBE')
        result['status'] = 'INSTALLED_NFT_JSON_SECONDS_PROVEN_IN_ISOLATED_NAMESPACE'; code = 0
    except Exception as error:
        text = str(error)
        result.update(status='UNIT_PROBE_DENIED',errorType=type(error).__name__,
                      reason=text if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',text) else 'ISOLATED_UNIT_PROBE_UNPROVEN')
        code = 1
    print('OUF_NFT_JSON_UNIT_PROBE='+json.dumps(result,sort_keys=True)); return code


if __name__ == '__main__': raise SystemExit(main())
