"""Prepare private compiler launch inputs; never authorize or execute candidates.

Reuse only the hash-bound existing stopped-creation reader. Read frozen image
configuration, sealed startup inputs and the two exact stopped candidates.
No lifecycle command, signing command or authority-key file is accessed.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import types

READER = Path('/etc/ouf/deploy-snapshots/semantic-v2-recovery-source-WrmSZaY0/resume-provider-v2-stopped.py')
READER_HASH = '2a9fc3d2861faa2e15370c70979b171cb63b2e09a2dfef1e2895ca27fa663861'
CREATED = Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-stopped-resume-k5mmsudx')
TARGETS = {
    'adapter': ('f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67',
                'sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc'),
    'southbound': ('1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916',
                   'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366')}
MAX_SOURCE_BYTES = 1048576
OBSERVER_HASH = '122a1a44705892ba577d2e83467f39870627ffc16685f886757828611063b3fc'
OBSERVER_COMMIT = '72310a0f4b0d649854d3abc010509d6724617e4e'
STAGE = 'INITIAL_READ'
SAFE_REASONS = {'ROOT_REQUIRED'}


class Denied(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise Denied(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def add_public_reasons(raw):
    SAFE_REASONS.update(v.value for v in ast.walk(ast.parse(raw)) if isinstance(v, ast.Constant)
                        and type(v.value) is str and re.fullmatch('[A-Z_]{1,96}', v.value))


def public_failure(error):
    reason = error.args[0] if type(error).__name__ == 'Denied' and len(error.args) == 1 else None
    return reason if type(reason) is str and reason in SAFE_REASONS else 'REDACTED_ERROR'


def observer_binding(ns):
    path = Path(__file__).resolve().with_name('frame-observer.py')
    require(digest(ns.read(path)) == OBSERVER_HASH, 'UPDATED_OBSERVER_SOURCE_REQUIRED')
    return {'path': str(path), 'sha256': OBSERVER_HASH, 'sourceCommit': OBSERVER_COMMIT,
            'installedInRuntime': False}


def load_reader():
    for parent in (READER.parent, *READER.parent.parents):
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'ROOT_SOURCE_ANCESTOR_REQUIRED')
    fd = os.open(READER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_size <= 131072, 'SEALED_READER_REQUIRED')
        raw = os.read(fd, 131073)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and digest(raw) == READER_HASH
                and all(getattr(before, k) == getattr(after, k) for k in
                        ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')),
                'READER_SOURCE_DRIFT')
    finally:
        os.close(fd)
    module = types.ModuleType('_ouf_verified_stopped_reader')
    module.__file__ = str(READER)
    exec(compile(raw, str(READER), 'exec'), module.__dict__)
    return module


def launch_from_spec(spec, image_config, independent_environment):
    """Image config is from the verified frozen archive, never container Config."""
    require(spec['role'] in TARGETS and spec['user'] == f"{spec['uid']}:{spec['gid']}",
            'ROLE_USER_DRIFT')
    require(spec['uid'] > 0 and spec['gid'] > 0 and image_config.get('WorkingDir', '').startswith('/'),
            'NONROOT_ABSOLUTE_LAUNCH_REQUIRED')
    args = (image_config.get('Entrypoint') or []) + (spec['command'] or image_config.get('Cmd') or [])
    require(args and all(type(x) is str and x and '\x00' not in x for x in args), 'LAUNCH_ARGUMENTS_REQUIRED')
    require(type(independent_environment) is dict and 'HOSTNAME' not in independent_environment,
            'IMAGE_HOSTNAME_OVERRIDE_UNSUPPORTED')
    require(all(type(k) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', k)
                and type(v) is str and '\x00' not in v for k, v in independent_environment.items()),
            'BOUNDED_ENVIRONMENT_REQUIRED')
    # Docker Linux non-TTY defaults, then independently sealed image/env-file
    # overrides. Full-template review still establishes OCI ordering/equality.
    environment = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                   'HOSTNAME': '$OUF_HOSTNAME', **independent_environment}
    sources = []
    for m in spec['mounts']:
        require(m['mode'] in (0o600, 0o644) and re.fullmatch('[0-9a-f]{64}', m['sha256']),
                'SEALED_MOUNT_REQUIRED')
        sources.append({**{k: m[k] for k in ('source', 'target', 'uid', 'gid', 'mode', 'sha256')},
                        'readOnly': True, 'maxBytes': MAX_SOURCE_BYTES})
    result = {'schema': 'ouf.semantic-creation-frame-launch.v1',
              'manifest': {'user': spec['user'], 'readOnlyRoot': spec['readOnlyRoot'],
                           'memoryBytes': spec['memoryBytes'], 'pidsLimit': spec['pidsLimit'],
                           'mounts': [{k: s[k] for k in ('source', 'target', 'readOnly')} for s in sources]},
              'startup': {'uid': spec['uid'], 'gid': spec['gid'], 'umask': None,
                          'cwd': image_config['WorkingDir'], 'args': args,
                          'env': [k + '=' + v for k, v in environment.items()]},
              'sources': sources}
    require(len(encoded(result)) <= 131072, 'LAUNCH_INPUT_UNBOUNDED')
    return result


def collect(reader, ns):
    before = reader.snapshot(ns)
    created_raw = reader.private(CREATED / 'creation-receipt.json')
    created = ns.parse(created_raw)
    require(created['status'] == 'CREATED_STOPPED_AND_READBACK_VERIFIED'
            and created['sourceHash'] == READER_HASH and created['startAuthorized'] is False
            and {r['role']: (r['containerId'], r['imageId']) for r in created['candidates']} == TARGETS,
            'STOPPED_CREATION_RECEIPT_REQUIRED')
    specs, preserved = reader.prepare(ns)
    accounts = reader.namespace(reader.TRUST / 'provider-role-accounts.py', reader.ACCOUNT_HASH)
    proofs = reader.verify_retained(accounts)
    output = {}
    for spec in specs:
        role = spec['role']; cid, image_id = TARGETS[role]
        resolved = reader.resolved_image(ns, spec, proofs[role])
        require(resolved['imageId'] == image_id, 'EXACT_TARGET_IMAGE_REQUIRED')
        image = reader.image(ns, image_id)
        reader.verify_container(ns, resolved, cid, image, CREATED.name)
        # prepare() already rehashes these private TLS/MAC/config files; report
        # those reads explicitly. Never claim that no private material is read.
        for source in resolved['mounts']:
            require(len(reader.private(source['source'], source['uid'], source['gid'], source['mode'])) <= MAX_SOURCE_BYTES,
                    'OBSERVER_SOURCE_BOUND_EXCEEDED')
        output[role] = launch_from_spec(resolved, proofs[role]['configuration']['config'],
                                       reader.environment(resolved, image))
    require(set(output) == set(TARGETS), 'EXACT_ROLE_SET_REQUIRED')
    require(reader.snapshot(ns) == before, 'CONTAINER_STATE_CHANGED')
    require(reader.private(CREATED / 'creation-receipt.json') == created_raw, 'CREATION_RECEIPT_CHANGED')
    for spec in specs:
        for source in spec['mounts']:
            require(digest(reader.private(source['source'], source['uid'], source['gid'], source['mode']))
                    == source['sha256'], 'MOUNT_SOURCE_CHANGED')
    for path, raw in preserved.items():
        uid, gid = ((10006, 10006) if path.name == 'adapter.json' else
                    (636, 636) if path.name in ('config.yaml', 'apisix.yaml') else (0, 0))
        require(reader.private(path, uid, gid) == raw, 'PRIVATE_INPUT_CHANGED')
    return output


def main():
    global STAGE
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    os.umask(0o077)
    STAGE = 'LOAD_EXISTING_READER'
    reader = load_reader()
    add_public_reasons(reader.private(READER))
    STAGE = 'LOAD_RUNTIME_READER'
    ns = reader.namespace(reader.REG / 'register-provider-v2-runtime.py', reader.REG_SOURCE_HASH)
    add_public_reasons(reader.private(reader.REG / 'register-provider-v2-runtime.py'))
    own = ns.read(Path(__file__).resolve())
    add_public_reasons(own)
    STAGE = 'VERIFY_UPDATED_OBSERVER'
    observer = observer_binding(ns)
    STAGE = 'VERIFY_COMMAND_BINDINGS'
    for path, expected in ns.BINDS.values():
        require(digest(ns.read(Path(path), True)) == expected, 'COMMAND_BINDING_DRIFT')
    STAGE = 'COLLECT_PRIVATE_INPUTS'
    output = collect(reader, ns)
    require(ns.read(Path(__file__).resolve()) == own, 'PREPARER_SOURCE_CHANGED')
    STAGE = 'PUBLISH_PRIVATE_INPUTS'
    root = Path(tempfile.mkdtemp(prefix='semantic-provider-v2-launch-inputs-', dir='/etc/ouf/deploy-snapshots'))
    hashes = {}
    for role, launch in output.items():
        raw = encoded(launch); ns.publish(root / (role + '.launch.json'), raw)
        hashes[role] = digest(raw)
    receipt = {'schema': 'ouf.semantic-provider-v2-private-launch-inputs.v1',
               'status': 'PRIVATE_LAUNCH_INPUTS_PREPARED', 'directory': str(root), 'launchHashes': hashes,
               'readerSourceHash': READER_HASH, 'candidateCount': 2, 'candidatesNeverStarted': True,
               'preparerSourceHash': digest(own),
               'maxSourceBytes': MAX_SOURCE_BYTES,
               'frameObserverBinding': observer,
               'privateTlsAndReceiptFilesRead': True, 'privateEnvironmentRead': True,
               'installationAuthorityKeysRead': 0, 'secretValuesPrinted': False,
               'containerLifecycleOperations': 0, 'providerCalls': 0, 'rulesChanged': False,
               'runtimeAllowlistChanged': False, 'completeOciTemplateApproved': False,
               'signaturesIssued': 0, 'acceptanceGranted': False, 'startAuthorized': False}
    ns.publish(root / 'launch-input-receipt.json', encoded(receipt))
    print('OUF_PROVIDER_V2_LAUNCH_INPUTS=' + encoded(receipt).decode().strip())


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('OUF_PROVIDER_V2_LAUNCH_INPUTS=' + json.dumps({'status': 'BLOCKED', 'stage': STAGE,
              'reason': public_failure(error), 'secretValuesPrinted': False, 'startAuthorized': False}))
        raise SystemExit(1)
