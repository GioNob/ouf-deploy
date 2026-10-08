"""Fixed read of private expected OCI and existing authority metadata.

Emit hashes and public identity/resource facts only. No key files, signatures,
configuration writes, Docker calls, acceptance or application start.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ROOT = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-frame-policies-5m18tpzh')
PROFILE = Path('/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22/installation-authority-profile.json')
PROFILE_SHA = '7fb7880d58e43ab40f9f53dac07a5dbad462d12e3a96f3b1287c6763b1d7ce18'
STAGE = 'INITIALIZE'
HASHES = {
 'adapter': {'policy': 'e8047e92e8b3938abe67dc8e57f385fced9de1218db348b4723eb3c6d34867fd', 'context': 'ede2f4ee4de3b869d11e125cad094cbc5bad900bdb365a10d5d365d3104853ca', 'template': 'bf536f60c1d511f4cdbeb8546e84f46d426f693019938a0a9b4dbf76b3308e01'},
 'southbound': {'policy': 'f49155fa412bb76d529713cb4ac2c253105884e9e72f7d2d74dfc5ccf9c5c822', 'context': 'e515366dbe8412bf261711ea98bcaac3e6d9e9d8bc3f77109829613ec166f4eb', 'template': '0ef8aa503bfb6a5c789000cd73de6e987d1a55688894475e555f4d566581ad05'}}
def require(ok, code):
    if not ok: raise ValueError(code)
def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def digest(raw): return hashlib.sha256(raw).hexdigest()
def read(path, sha):
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'PRIVATE_ANCESTOR_DRIFT')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= 262144, 'PRIVATE_FILE_CUSTODY_DRIFT')
        raw = os.read(fd, 262145); after = os.fstat(fd)
        require((s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'PRIVATE_FILE_CHANGED')
        require(digest(raw) == sha, 'PRIVATE_FILE_HASH_DRIFT'); return raw
    finally: os.close(fd)
def summary(policy):
    require(set(policy) == {'schema', 'expectedOci', 'manifest', 'startup', 'approvedHooks', 'sources'} and
        policy['schema'] == 'ouf.semantic-configured-creation-frame-policy.v1', 'POLICY_SCHEMA_DRIFT')
    oci = policy['expectedOci']; process = oci['process']; resources = oci['linux']['resources']
    require(type(oci['root'].get('readonly', False)) is bool, 'ROOT_MODE_SCHEMA_DRIFT')
    require(type(process['user']['uid']) is int and type(process['user']['gid']) is int, 'PROCESS_IDENTITY_DRIFT')
    return {'expectedApplicationHash': digest(encoded(oci)), 'expectedRootfsPath': oci['root']['path'],
        'uid': process['user']['uid'], 'gid': process['user']['gid'], 'readOnlyRoot': oci['root'].get('readonly', False),
        'memory': resources.get('memory'), 'pids': resources.get('pids'),
        'mountCount': len(oci['mounts']), 'sealedSourceCount': len(policy['sources']),
        'manifestHash': digest(encoded(policy['manifest'])), 'startupHash': digest(encoded(policy['startup'])),
        'approvedHooksHash': digest(encoded(policy['approvedHooks'])), 'completeTemplateApprovalProven': False}
def main():
    global STAGE
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    saved = {}; roles = {}
    for role, hashes in HASHES.items():
        values = {}
        for kind, sha in hashes.items():
            STAGE = 'READ_' + role.upper() + '_' + kind.upper()
            path = ROOT / (role + '.' + kind + '.json'); raw = read(path, sha); saved[path] = (sha, raw)
            values[kind] = json.loads(raw)
        STAGE = 'SUMMARIZE_' + role.upper()
        roles[role] = {'artifactHash': hashes['policy'], 'contextHash': hashes['context'], 'templateHash': hashes['template'],
            **summary(values['policy']), 'containerId': values['context']['containerId']}
    STAGE = 'READ_AUTHORITY_PROFILE'
    raw = read(PROFILE, PROFILE_SHA); saved[PROFILE] = (PROFILE_SHA, raw); profile = json.loads(raw)
    require(profile['schema'] == 'ouf.semantic-existing-installation-authority-bindings.v1', 'AUTHORITY_PROFILE_DRIFT')
    STAGE = 'VERIFY_STABLE_SNAPSHOT'
    for path, (sha, prior) in saved.items(): require(read(path, sha) == prior, 'PRIVATE_SNAPSHOT_CHANGED')
    report = {'schema': 'ouf.semantic-provider-v2-admission-input-manifest.v1', 'status': 'HASH_BOUND_PRIVATE_INPUTS_READ',
        'roles': roles, 'authorities': profile['authorities'], 'keyRefs': profile['keyRefs'],
        'keyBindings': profile['keyBindings'], 'policyBinding': profile['policyBinding'],
        'authorityProfileHash': PROFILE_SHA, 'privateApplicationPolicyRead': True, 'privateKeyFilesRead': 0,
        'configurationWrites': 0, 'containerLifecycleOperations': 0, 'signaturesIssued': 0,
        'contextAuthenticated': False, 'rootfsAcceptanceProven': False, 'transactionConfigured': False,
        'acceptanceGranted': False, 'startAuthorized': False, 'secretValuesPrinted': False}
    print('OUF_PROVIDER_V2_ADMISSION_MANIFEST=' + encoded(report).decode())
if __name__ == '__main__':
    try: main()
    except Exception as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch('[A-Z_]+', str(error)) else 'BOUNDED_PRIVATE_MANIFEST_READ_FAILED'
        print('OUF_PROVIDER_V2_ADMISSION_MANIFEST=BLOCKED REASON=' + reason + ' STAGE=' + STAGE + ' ERROR_CLASS=' + type(error).__name__ + ' NO_RAW_OUTPUT=true'); raise SystemExit(1)
