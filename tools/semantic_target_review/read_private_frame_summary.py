"""Read the already prepared two-CID frames without exposing private values.

No preparation, signing, Docker, package install, mutation, or acceptance.
Fixed paths and previously reported SHA256 bindings only. Operator root read.
"""
import hashlib
import json
import os
from pathlib import Path
import stat

FRAME = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-frame-policies-5m18tpzh')
LAUNCH = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-launch-inputs-7g1du3a6')
HASHES = {
    'adapter': {'launch': '061e2bd245d45d7e435ff86e07a6897413ae6c164d2d2c9ade2d455d80846943',
        'template': 'bf536f60c1d511f4cdbeb8546e84f46d426f693019938a0a9b4dbf76b3308e01',
        'context': 'ede2f4ee4de3b869d11e125cad094cbc5bad900bdb365a10d5d365d3104853ca',
        'policy': 'e8047e92e8b3938abe67dc8e57f385fced9de1218db348b4723eb3c6d34867fd'},
    'southbound': {'launch': 'cbc1f30c200a6a27e92b8055aa5542df30f7d124d08004d6f3bfe7dfb9ed2a39',
        'template': '0ef8aa503bfb6a5c789000cd73de6e987d1a55688894475e555f4d566581ad05',
        'context': 'e515366dbe8412bf261711ea98bcaac3e6d9e9d8bc3f77109829613ec166f4eb',
        'policy': 'f49155fa412bb76d529713cb4ac2c253105884e9e72f7d2d74dfc5ccf9c5c822'}}

def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def read(path, expected):
    if path.resolve(strict=True) != path:
        raise ValueError('INPUT_PATH_ALIAS_DENIED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > 131072:
            raise ValueError('PRIVATE_INPUT_CUSTODY_DRIFT')
        raw = os.read(fd, 131073)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, key) != getattr(after, key) for key in fields) or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('FROZEN_PRIVATE_INPUT_HASH_DRIFT')
        return json.loads(raw)
    finally:
        os.close(fd)

def main():
    if os.geteuid() != 0:
        raise ValueError('OPERATOR_ROOT_READ_REQUIRED')
    roles = {}
    for role, hashes in HASHES.items():
        documents = {name: read((LAUNCH if name == 'launch' else FRAME) / (role + '.' + name + '.json'), sha)
                     for name, sha in hashes.items()}
        oci = documents['policy']['expectedOci']
        process = oci['process']
        roles[role] = {'inputHashes': hashes, 'containerId': documents['context']['containerId'],
            'user': process['user'], 'readOnlyRoot': oci['root']['readonly'],
            'processHash': hashed(process), 'environmentCount': len(process['env']),
            'argumentCount': len(process['args']), 'noNewPrivileges': process['noNewPrivileges'],
            'resources': oci['linux'].get('resources'),
            'mountCount': len(oci['mounts']), 'mountsHash': hashed(oci['mounts']),
            'namespacesHash': hashed(oci['linux']['namespaces']),
            'freshPrivateNetworkNamespace': documents['context']['networkNamespaceName'] is None,
            'sourceCount': len(documents['launch']['sources']),
            'sourceDescriptorsHash': hashed(documents['launch']['sources']),
            'contextHash': hashed(documents['context'])}
    print('OUF_PRIVATE_FRAME_REVIEW=' + json.dumps({'schema': 'ouf.semantic-private-frame-review-summary.v1',
        'status': 'FROZEN_INPUT_SUMMARY_CAPTURED', 'roles': roles,
        'independentlyCompiledHere': False, 'privateValuesPrinted': False,
        'privateKeysRead': 0, 'configurationWrites': 0, 'containerLifecycleOperations': 0,
        'acceptanceGranted': False, 'startAuthorized': False, 'notReleaseAcceptance': True}, sort_keys=True))

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        reason = str(error) if type(error) is ValueError and str(error).isupper() else type(error).__name__
        print('OUF_PRIVATE_FRAME_REVIEW=' + json.dumps({'status': 'BLOCKED',
            'phase': 'READ_EXISTING_FROZEN_FRAME_INPUTS', 'reason': reason,
            'privateValuesPrinted': False, 'privateKeysRead': 0,
            'configurationWrites': 0, 'containerLifecycleOperations': 0, 'startAuthorized': False}))
        raise SystemExit(1)
