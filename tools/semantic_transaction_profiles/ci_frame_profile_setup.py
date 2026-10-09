"""CI-only assembly against two preapproved synthetic runc frames.

No target authority. Keys, filesystems and topology belong to disposable CI.
The exact full OCI and rootfs seal are fixed before either task is created.
"""
import copy
import json
import os
from pathlib import Path
import shutil

from assemble_provider_profiles import assemble_profiles, digest, encoded
from tools.semantic_provider_node_observation import rootfs_seal
from tools.semantic_provider_deployment_authentication import VerificationBudget


def private(path, value):
    path.write_bytes(encoded(value)); path.chmod(0o600)


def frame(root, rootfs, cid, index, namespace):
    baseline = json.loads(Path(__file__).with_name('containerd-overlayfs-adapter.json').read_bytes())
    spec = copy.deepcopy(baseline['template']['expectedOci'])
    spec['root']['path'] = str(rootfs)
    spec['hostname'] = cid[:12]
    spec['linux']['cgroupsPath'] = '/ouf_frame_' + cid[:12]
    # This is an independently authored runc CI frame, not a Docker target
    # template. Its already-created named namespace is fixed before create.
    for item in spec['linux']['namespaces']:
        if item['type'] == 'network': item['path'] = str(Path('/run/netns') / namespace)
    spec['process'].pop('apparmorProfile', None)
    spec['process'].update(args=['/bin/busybox', 'sh', '-c',
        'echo APP > /dev/shm/started; /bin/busybox sleep 60'], cwd='/',
        env=['PATH=/bin', 'HOSTNAME=' + cid[:12]])
    source = root / ('approved-source-' + str(index))
    source.write_bytes(b'CI_APPROVED_READ_ONLY_SOURCE'); source.chmod(0o600); os.chown(source, 10006, 10006)
    engine_sources = {}
    for name, token in [('hosts', '$OUF_HOSTS'), ('hostname', '$OUF_HOSTNAME_FILE'), ('resolv.conf', '$OUF_RESOLV')]:
        path = root / (name + '-' + str(index))
        path.write_bytes(b'CI_METADATA'); path.chmod(0o644)
        engine_sources[token] = str(path)
    for mount in spec['mounts']:
        if mount['destination'] == '/approved-source': mount['source'] = str(source)
        elif mount['source'] in engine_sources: mount['source'] = engine_sources[mount['source']]
        mount['options'] = ['ro' if x == 'rro' else x for x in mount.get('options', [])]
    for directory in ('bin', 'etc', 'proc', 'dev', 'dev/pts', 'dev/shm', 'dev/mqueue', 'sys', 'sys/fs/cgroup'):
        (rootfs / directory).mkdir(parents=True, exist_ok=True)
    for name in ('etc/hosts', 'etc/hostname', 'etc/resolv.conf', 'approved-source'):
        (rootfs / name).touch(mode=0o644)
    mount = {'source': str(source), 'target': '/approved-source', 'readOnly': True}
    startup = {k: spec['process'][k] for k in ('args', 'cwd', 'env')}
    startup.update(uid=10006, gid=10006, umask=None)
    policy = {'schema': 'ouf.semantic-configured-creation-frame-policy.v1', 'expectedOci': spec,
              'manifest': {'user': '10006:10006', 'readOnlyRoot': True, 'memoryBytes': 268435456,
                           'pidsLimit': 128, 'mounts': [mount]},
              'startup': startup, 'approvedHooks': {},
              'sources': [{**mount, 'uid': 10006, 'gid': 10006, 'mode': 0o600,
                           'maxBytes': 131072, 'sha256': digest(source.read_bytes())}]}
    return spec, policy


def assemble(directory, source, python, crypto, intent, policies, policy, node, registry, *, independently_expected_rootfs=None):
    policy_path = directory / 'frame-policy.json'; private(policy_path, policy)
    limits = {'maxEntries': 10000, 'maxBytes': 268435456, 'maxDepth': 32}
    seal = (rootfs_seal(Path(policy['expectedOci']['root']['path']), limits, VerificationBudget(12))
            if independently_expected_rootfs is None else independently_expected_rootfs)
    # Signing input below is CI-only explicit acceptance. It uses the prepared
    # complete frame/hash, never copies a field from the candidate's observed OCI.
    private(directory / 'ci-preapproved-frame.json', {'policyHash': digest(encoded(policy)),
        'applicationHash': digest(encoded(policy['expectedOci'])), 'rootfsSeal': seal})
    observer = directory / 'frame-observer.py'
    observer.write_bytes(Path(__file__).with_name('frame-observer.py').read_bytes()); observer.chmod(0o600)
    producer = directory / 'ci-frame-broker.py'
    producer.write_bytes(Path(__file__).with_name('ci_frame_profile_broker.py').read_bytes()); producer.chmod(0o600)
    sources = {str(p.relative_to(source)): p.read_bytes() for p in source.rglob('*.py')}
    paths = crypto['privateKeys']
    authority = {'authorities': policies['authorities'],
                 'keyBindings': {role: {'path': paths[ref], 'sha256': digest(Path(paths[ref]).read_bytes())}
                                 for role, ref in [('installer', 'installer-key'), ('attestor', 'verifier-key')]},
                 'keyRefs': {'installer': 'installer-key', 'attestor': 'verifier-key'}}
    binding = lambda path: {'path': str(path), 'sha256': digest(Path(path).read_bytes())}
    files = assemble_profiles(str(directory), str(source), sources, authority, binding(python),
        {k: crypto[k] for k in ('policyBinding', 'signatureDirectory', 'opensslBinding')},
        binding(directory / 'intent.json'), intent, json.loads((directory / 'preparer-template.json').read_bytes()),
        binding(directory / 'ci-final-mandate.json'),
        {'python': binding(python), 'source': binding(observer), 'configuration': binding(policy_path)},
        ['/run'], [str(registry)], limits)
    for name, value in files.items(): private(directory / name, value)
    return files['broker.json'], producer

