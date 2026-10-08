"""Freeze private frame-policy drafts without signing or starting candidates.

The CI baseline is independently fixed but remains unapproved for the target.
Compilation records that distinction; later signed admission must not infer
acceptance from this receipt. No observed target OCI or authority key is read.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from build_role_frame_template import build_role_template
from compile_creation_frame_policy import canonical, compile_policy, require

LAUNCH_ROOT = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-launch-inputs-7g1du3a6')
LAUNCH_HASHES = {'adapter': '061e2bd245d45d7e435ff86e07a6897413ae6c164d2d2c9ade2d455d80846943',
                 'southbound': 'cbc1f30c200a6a27e92b8055aa5542df30f7d124d08004d6f3bfe7dfb9ed2a39'}
BASELINE_HASHES = {'adapter': '6dc554812c9298baffeb1ef7314eb2f43d7d4e5e41aea791f506a723f527b41e',
                   'southbound': 'ea86df348ace963d41d3a24ab3b9bea693c3b3ba36e181a1aaec5f7e97333b63'}
CIDS = {'adapter': 'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67',
        'southbound': '1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'}
IMAGES = {'adapter': 'sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc',
          'southbound': 'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366'}
DOCKER = Path('/usr/bin/docker')
DOCKER_HASH = '7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40'
REG = Path('/etc/ouf/deploy-snapshots/semantic-v2-runtime-registration-krSL786w/adapter-configuration.json')
REG_HASH = 'c3da65ad911e27836af7b0802ff464043d2354847ff21bbab0a1a3476134bf16'
STAGE = 'INITIAL_READ'


def hashed(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def sealed_read(path, uid=0, gid=0, mode=0o600, bound=131072, executable=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'ABSOLUTE_PRIVATE_PATH_REQUIRED')
    for parent in path.parents:
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'ROOT_SOURCE_ANCESTOR_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_gid == gid
                and before.st_nlink == 1 and 0 <= before.st_size <= bound
                and (not before.st_mode & 0o022 and before.st_mode & 0o111 if executable
                     else stat.S_IMODE(before.st_mode) == mode), 'SEALED_FILE_REQUIRED')
        parts = []; size = 0
        while True:
            chunk = os.read(fd, min(65536, bound + 1 - size))
            if not chunk: break
            parts.append(chunk); size += len(chunk)
            require(size <= bound, 'SEALED_FILE_UNBOUNDED')
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(size == before.st_size and all(getattr(before, k) == getattr(after, k) for k in keys),
                'SEALED_FILE_CHANGED')
        return b''.join(parts)
    finally:
        os.close(fd)


def compile_role(role, baseline, launch, info):
    require(role in CIDS and type(baseline) is dict
            and baseline.get('schema') == 'ouf.semantic-ci-engine-frame-baseline.v1'
            and baseline.get('role') == role and baseline.get('syntheticFixture') is True
            and baseline.get('targetTemplateApproved') is False
            and baseline.get('acceptanceGranted') is False and baseline.get('startAuthorized') is False,
            'UNAPPROVED_FIXED_BASELINE_REQUIRED')
    require(info == {'serverVersion': '29.8.1', 'storageDriver': 'overlayfs',
                     'cgroupDriver': 'systemd', 'dataRoot': '/var/lib/docker'}, 'EXACT_ENGINE_PROFILE_REQUIRED')
    engine = baseline['engine']
    require(engine == {'serverVersion': '29.8.1', 'storageDriver': 'overlayfs',
                       'cgroupDriver': 'systemd', 'backend': 'containerd-overlayfs'}
            and baseline.get('mountOrdering') == 'depth-path', 'CI_ENGINE_PROFILE_DRIFT')
    uid = 10006 if role == 'adapter' else 636
    require(launch['startup']['uid'] == launch['startup']['gid'] == uid
            and launch['manifest']['readOnlyRoot'] is (role == 'adapter'), 'ROLE_IDENTITY_DRIFT')
    template = build_role_template(baseline['template'], baseline['launch'], launch,
                                   baseline['approvedUser'], mount_ordering=baseline['mountOrdering'])
    # This path layout was exercised with the pinned 29.8.1 snapshotter. It is
    # a draft target context, not proof of the live target mount or namespace.
    context = {'schema': 'ouf.semantic-docker-frame-context.v1', 'containerId': CIDS[role],
               'bundleParent': '/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby',
               'metadataParent': '/var/lib/docker/containers', 'networkNamespaceParent': '/run/docker/netns',
               'networkNamespaceName': None, 'cgroupDriver': 'systemd',
               'rootfsPath': '/var/lib/docker/rootfs/overlayfs/' + CIDS[role], 'storageParent': '/var/lib/docker'}
    return {'template': template, 'context': context, 'policy': compile_policy(template, launch, context)}


def query(config, *args):
    require(hashed(sealed_read(DOCKER, bound=64000000, executable=True)) == DOCKER_HASH, 'DOCKER_BYTE_DRIFT')
    r = subprocess.run([str(DOCKER), '--config', str(config), '--host', 'unix:///var/run/docker.sock', *args],
                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=15, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(r.returncode == 0 and 0 < len(r.stdout) <= 131072, 'BOUNDED_DOCKER_READ_FAILED')
    return parse(r.stdout)


def publish(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)


def main():
    global STAGE
    require(os.geteuid() == 0, 'ROOT_REQUIRED'); os.umask(0o077)
    source = Path(__file__).resolve().parent
    STAGE = 'VERIFY_FROZEN_INPUTS'
    saved = {}
    for role in CIDS:
        for p, expected in ((LAUNCH_ROOT / (role + '.launch.json'), LAUNCH_HASHES[role]),
                            (source / ('containerd-overlayfs-' + role + '.json'), BASELINE_HASHES[role])):
            raw = sealed_read(p); require(hashed(raw) == expected, 'FROZEN_INPUT_HASH_DRIFT'); saved[p] = raw
    raw = sealed_read(REG); require(hashed(raw) == REG_HASH, 'EMPTY_RUNTIME_CONFIGURATION_DRIFT'); saved[REG] = raw
    require(parse(raw)['candidates'] == {} and parse(raw)['runtimeStateRoot'] == '/run/docker',
            'EMPTY_RUNTIME_REQUIRED')
    STAGE = 'VERIFY_STOPPED_TARGET_AND_SOURCES'
    outputs = {}
    with tempfile.TemporaryDirectory(prefix='ouf-empty-policy-docker-') as config:
        info = query(config, 'info', '--format',
             '{"serverVersion":{{json .ServerVersion}},"storageDriver":{{json .Driver}},"cgroupDriver":{{json .CgroupDriver}},"dataRoot":{{json .DockerRootDir}}}')
        for role, cid in CIDS.items():
            value = query(config, 'inspect', '--type', 'container', '--format',
                '{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},"runtime":{{json .HostConfig.Runtime}}}', cid)
            state = value['state']
            require(value['id'] == cid and value['image'] == IMAGES[role] and value['runtime'] == 'ouf-semantic-admitted-v2'
                    and state['Status'] == 'created' and state['Running'] is False and state['Restarting'] is False
                    and state['Pid'] == 0 and state['StartedAt'].startswith('0001-01-01T'), 'STOPPED_CANDIDATE_DRIFT')
            launch = parse(saved[LAUNCH_ROOT / (role + '.launch.json')])
            for item in launch['sources']:
                content = sealed_read(item['source'], item['uid'], item['gid'], item['mode'], item['maxBytes'])
                require(hashed(content) == item['sha256'], 'SEALED_MOUNT_SOURCE_DRIFT')
            baseline = parse(saved[source / ('containerd-overlayfs-' + role + '.json')])
            outputs[role] = compile_role(role, baseline, launch, info)
            for item in launch['sources']:
                require(hashed(sealed_read(item['source'], item['uid'], item['gid'], item['mode'], item['maxBytes']))
                        == item['sha256'], 'SEALED_MOUNT_SOURCE_CHANGED')
        require(query(config, 'info', '--format',
             '{"serverVersion":{{json .ServerVersion}},"storageDriver":{{json .Driver}},"cgroupDriver":{{json .CgroupDriver}},"dataRoot":{{json .DockerRootDir}}}') == info,
                'ENGINE_PROFILE_CHANGED')
    require(all(sealed_read(p) == raw for p, raw in saved.items()), 'FROZEN_INPUT_CHANGED')
    STAGE = 'PUBLISH_PRIVATE_DRAFT_POLICIES'
    root = Path(tempfile.mkdtemp(prefix='semantic-provider-v2-frame-policies-', dir='/etc/ouf/deploy-snapshots'))
    hashes = {}
    for role, values in outputs.items():
        hashes[role] = {}
        for name, value in values.items():
            raw = canonical(value); publish(root / (role + '.' + name + '.json'), raw)
            hashes[role][name] = hashed(raw)
    receipt = {'schema': 'ouf.semantic-provider-v2-private-frame-policies.v1', 'status': 'PRIVATE_DRAFT_POLICIES_PREPARED',
               'directory': str(root), 'hashes': hashes, 'engine': info, 'candidateCount': 2, 'candidatesNeverStarted': True,
               'targetTemplateApproved': False, 'contextAuthenticated': False, 'observedTargetOciUsed': False,
               'signedTransactionConfigured': False, 'runtimeAllowlistChanged': False,
               'containerLifecycleOperations': 0, 'rulesChanged': False, 'installationAuthorityKeysRead': 0,
               'signaturesIssued': 0, 'providerCalls': 0, 'secretValuesPrinted': False,
               'privateLaunchAndMountFilesRead': True, 'acceptanceGranted': False, 'startAuthorized': False}
    publish(root / 'frame-policy-receipt.json', canonical(receipt))
    print('OUF_PROVIDER_V2_FRAME_POLICIES=' + canonical(receipt).decode())


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('OUF_PROVIDER_V2_FRAME_POLICIES=' + canonical({'status': 'BLOCKED', 'stage': STAGE,
              'secretValuesPrinted': False, 'startAuthorized': False,
              'doNotRerunApply': STAGE == 'PUBLISH_PRIVATE_DRAFT_POLICIES'}).decode())
        raise SystemExit(1)
