#!/usr/bin/env python3
"""Prepare private B1 recipes. Docker GET only; no acceptance or start."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePath, PurePosixPath
import re
import stat
import sys
import types

SCHEMA = 'ouf.semantic-provider-b1-recipes.v1'
ROOT = Path(__file__).resolve().parents[1]
ROLES = ('adapter', 'southbound')
PARTS = ('template', 'launch', 'context', 'policy')
PINS = {
    'scripts/recreate-southbound-successor-20261113.py': '13fe99b68e6e81af7976cf3b8a4c2e3b1d3ccfc0cb3896be0fd8665cf6390bcb',
    'tools/semantic_frame_compiler/compile_creation_frame_policy.py': '36ee627e524415002a98fede8d7e61ad22ae95b6fec6b6686c1e01d878be570d',
    'tools/semantic_frame_compiler/build_role_frame_template.py': '64f71f1c1414a87fda7e98a4402bef2b12ff8c5a917766810412825cca54f00c',
    'tools/semantic_successor_recipes/build_role_frame_template_tmpfs.py': '63a04a56ac483b36e304db6694723dd5114372dc85011da5e1a5ae6b1aae3a15',
    'tools/semantic_successor_recipes/creation_launch.py': '1a81298dce02b95d5209f26e309129576dd3b41b90f366dcd977121009b96bfd',
    'tools/semantic_frame_compiler/containerd-overlayfs-adapter.json': '6dc554812c9298baffeb1ef7314eb2f43d7d4e5e41aea791f506a723f527b41e',
    'tools/semantic_successor_recipes/containerd-overlayfs-southbound-tmpfs.json': '326d0b88276db8dde1729dfe0fabed9ca9d8ff9e8f6b87e6fcba7fa8f1741080',
}
BASELINES = {
    'adapter': 'tools/semantic_frame_compiler/containerd-overlayfs-adapter.json',
    'southbound': 'tools/semantic_successor_recipes/containerd-overlayfs-southbound-tmpfs.json',
}
A2_FRAME_FIELDS = ('Id', 'Name', 'Image', 'State', 'RestartCount', 'Config', 'HostConfig', 'Mounts', 'NetworkSettings')


class Held(RuntimeError):
    pass


def require(ok, code):
    if not ok:
        raise Held(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def encoded(value):
    return canonical(value) + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), 'DUPLICATE_JSON_FIELD')
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'NONFINITE_JSON_VALUE'))


def absolute(value):
    require(type(value) is str and value.startswith('/') and '\x00' not in value
            and '..' not in value.split('/') and str(PurePosixPath(value)) == value,
            'ABSOLUTE_NORMALIZED_PATH_REQUIRED')
    return Path(value)


def identity(entry):
    return tuple(getattr(entry, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
                 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def private_read(path, expected=None, *, modes=(0o600,)):
    """Read non-secret controller inputs under root custody, without symlinks."""
    path = absolute(str(path))
    for parent in path.parents:
        entry = parent.lstat()
        require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == 0
                and not entry.st_mode & 0o022, 'INPUT_PARENT_CUSTODY_REQUIRED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and (before.st_uid, before.st_gid) == (0, 0)
                and stat.S_IMODE(before.st_mode) in modes and 0 <= before.st_size <= 1048576,
                'INPUT_FILE_CUSTODY_REQUIRED')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(1048577)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                and identity(before) == identity(path.lstat()), 'INPUT_CHANGED_DURING_READ')
        require(expected is None or sha(raw) == expected, 'INPUT_SHA256_MISMATCH')
        return raw
    finally:
        os.close(fd)


def helpers():
    # Authenticate the entire closure before executing any module. __name__ is
    # never __main__; the recreation controller's main/run are never invoked.
    raw = {name: private_read(ROOT / name, digest, modes=(0o600, 0o644)) for name, digest in PINS.items()}
    modules, previous, old_path = {}, dict(sys.modules), list(sys.path)
    try:
        for alias, filename in (
            ('compile_creation_frame_policy', 'tools/semantic_frame_compiler/compile_creation_frame_policy.py'),
            ('build_role_frame_template', 'tools/semantic_frame_compiler/build_role_frame_template.py'),
            ('_b1_tmpfs', 'tools/semantic_successor_recipes/build_role_frame_template_tmpfs.py'),
            ('_b1_launch', 'tools/semantic_successor_recipes/creation_launch.py'),
            ('_b1_recreation', 'scripts/recreate-southbound-successor-20261113.py')):
            module = types.ModuleType(alias)
            module.__file__ = str(ROOT / filename)
            sys.modules[alias] = module
            exec(compile(raw[filename], module.__file__, 'exec'), module.__dict__)
            modules[alias] = module
    finally:
        sys.path[:] = old_path
        for alias in ('compile_creation_frame_policy', 'build_role_frame_template', '_b1_tmpfs', '_b1_launch', '_b1_recreation'):
            if alias in previous:
                sys.modules[alias] = previous[alias]
            else:
                sys.modules.pop(alias, None)
    return types.SimpleNamespace(compiler=modules['compile_creation_frame_policy'],
        adapter=modules['build_role_frame_template'], southbound=modules['_b1_tmpfs'],
        launch=modules['_b1_launch'], recreation=modules['_b1_recreation'],
        baselines={role: decode(raw[name]) for role, name in BASELINES.items()})


def receipt_a2(args, inputs):
    root = args.a2_root
    def read(name, expected=None):
        path = root / name
        raw = private_read(path, expected)
        inputs['a2/' + name] = sha(raw)
        return decode(raw)
    result, manifest = read('result.json'), read('manifest.json')
    require(result['status'] == 'SEMANTIC_PROVIDER_PREPARATION_A_STAGED'
            and result['planSha256'] == manifest['planSha256'] == args.a2_plan_sha256
            and result['manifest'] == manifest['manifest'] and result['replayAllowed'] is False,
            'A2_RECEIPT_UNPROVEN')
    body = result['manifest']
    require(body['directory']['path'] == str(root)
            and body['schema'] == 'ouf.semantic-provider-preparation-a.manifest.v1', 'A2_SCOPE_CHANGED')
    pins = {row['path']: row.get('sha256') for row in body['filesCreated']}
    for name, field in (('semantic-peer.json', 'semanticPeer'), ('successors.json', 'successors')):
        pin = pins[str(root / name)]
        require(type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin), 'A2_FILE_PIN_REQUIRED')
        doc = read(name, pin)
        require(doc == body[field], 'A2_ARTIFACT_CHANGED')
    require(inputs['a2/successors.json'] == args.a2_successors_sha256, 'A2_SUCCESSORS_HASH_MISMATCH')
    successors = body['successors']
    expected = {args.adapter_id: args.adapter_transaction, args.southbound_id: args.southbound_transaction}
    require(len(successors['containers']) == 2 and successors['transactions'] == expected
            and {row['containerId']: row['transaction'] for row in successors['containers']} == expected,
            'A2_SUCCESSOR_ID_OR_TRANSACTION_MISMATCH')
    return successors


def requests_from_receipt(args, recreation, inputs):
    raw = private_read(args.recreation_receipt, args.recreation_receipt_sha256)
    inputs['recreation/result.json'] = sha(raw)
    receipt = decode(raw)
    require(receipt['schema'] == 'ouf.semantic-southbound-successor-recreation.v1'
            and receipt['status'] == 'SOUTHBOUND_RECREATED_STOPPED'
            and receipt['newCid'] == args.southbound_id
            and receipt['newTransaction'] == args.southbound_transaction, 'RECREATION_RECEIPT_MISMATCH')
    plan = receipt['plan']
    require(recreation.sha(recreation.canonical(plan)) == receipt['planSha256'], 'RECREATION_PLAN_DIGEST_MISMATCH')
    southbound = plan['newSouthboundRequest']
    labeled = southbound | {'Labels': {recreation.OWNER_LABEL: args.southbound_transaction}}
    require(recreation.sha(recreation.canonical(labeled)) == receipt['newRequestSha256'],
            'SOUTHBOUND_REQUEST_DIGEST_MISMATCH')
    adapter = recreation.build_request({recreation.ADAPTER: args.historical_adapter_id,
                                       recreation.SOUTHBOUND: args.historical_southbound_id}, recreation.ADAPTER, True)
    require(recreation.sha(recreation.canonical(adapter)) == plan['reconstructedRequestDigests'][recreation.ADAPTER],
            'ADAPTER_REQUEST_DIGEST_MISMATCH')
    # Preserve the independently bound original creation digest as lineage.
    require(re.fullmatch('[0-9a-f]{64}', plan['reconstructedRequestsSha256']) is not None,
            'ORIGINAL_CREATION_DIGEST_REQUIRED')
    inputs['creation/original'] = plan['reconstructedRequestsSha256']
    inputs['request/adapter'] = recreation.sha(recreation.canonical(adapter))
    inputs['request/southbound'] = recreation.sha(recreation.canonical(southbound))
    return {'adapter': adapter, 'southbound': southbound}, receipt


def context(args, cid):
    return {'schema': 'ouf.semantic-docker-frame-context.v1', 'containerId': cid,
            'bundleParent': args.bundle_parent, 'metadataParent': args.metadata_parent,
            'networkNamespaceParent': args.network_namespace_parent, 'networkNamespaceName': None,
            'cgroupDriver': args.cgroup_driver, 'storageParent': args.storage_parent,
            'rootfsPath': args.rootfs_parent + '/' + cid}


def compile_roles(args, deps, requests):
    output = {}
    for role in ROLES:
        baseline = deps.baselines[role]
        launch = deps.launch.creation_launch(requests[role], role,
                    baseline['launch']['manifest'].get('tmpfs'))
        template = getattr(deps, role).build_role_template(baseline['template'], baseline['launch'],
                    launch, baseline['approvedUser'], mount_ordering=baseline['mountOrdering'])
        ctx = context(args, getattr(args, role + '_id'))
        output[role] = dict(template=template, launch=launch, context=ctx,
                           policy=deps.compiler.compile_policy(template, launch, ctx))
    return output


def observe(args, deps):
    inputs = {'controller': sha(private_read(Path(__file__).resolve(), modes=(0o600, 0o644)))}
    successors = receipt_a2(args, inputs)
    requests, receipt = requests_from_receipt(args, deps.recreation, inputs)
    lineage = successors['lineage']['recreation']
    require(lineage['path'] == str(args.recreation_receipt)
            and lineage['sha256'] == args.recreation_receipt_sha256
            and lineage['planSha256'] == receipt['planSha256']
            and lineage['newCid'] == args.southbound_id, 'A2_RECREATION_BINDING_MISMATCH')
    observed = {}
    for role in ROLES:
        cid, transaction = getattr(args, role + '_id'), getattr(args, role + '_transaction')
        name = deps.recreation.ADAPTER if role == 'adapter' else deps.recreation.SOUTHBOUND
        doc = deps.recreation.inspect_created(cid, name, requests[role], transaction, args.expected_runtime)
        selected = next(row for row in successors['containers'] if row['containerId'] == cid)
        require(selected['dockerFrameSha256'] == sha(canonical({k: doc[k] for k in A2_FRAME_FIELDS}))
                and selected['name'] == doc['Name'] and selected['image'] == doc['Image'], 'SUCCESSOR_FRAME_DIFFERS_FROM_A2')
        observed[role] = deps.recreation.frame_digest(doc)
    mounts = requests['southbound']['HostConfig']['Mounts']
    require(sum(m['Source'] == str(deps.recreation.HMAC_SOURCE)
                for request in requests.values() for m in request['HostConfig']['Mounts']) == 1
            and sum(m['Source'] == str(deps.recreation.HMAC_SOURCE)
                and m['Target'] == deps.recreation.HMAC_TARGET for m in mounts) == 1,
            'EXACT_SOUTHBOUND_HMAC_BIND_REQUIRED')
    deps.recreation.protected_file(deps.recreation.HMAC_SOURCE, (636, 636, 0o600))
    routes = {m['Target']: Path(m['Source']) for m in mounts}
    deps.recreation.verify_routes(routes[deps.recreation.ROUTES_SOURCE], routes['/usr/local/apisix/conf/config.yaml'])
    artifacts = compile_roles(args, deps, requests)
    plan = {'schema': 'ouf.semantic-provider-b1-recipes-plan.v1',
        'inputs': {k: str(v) if isinstance(v, PurePath) else v for k, v in vars(args).items()
                   if k not in {'plan', 'apply', 'plan_sha256'}},
        'inputHashes': inputs, 'softwareHashes': dict(PINS),
        'baselineHashes': {role: PINS[name] for role, name in BASELINES.items()},
        'observedFrameHashes': observed,
        'roles': {role: {part: sha(encoded(artifacts[role][part])) for part in PARTS} for role in ROLES},
        'secretBytesHashed': 1, 'secretValuesPrinted': False,
        'startAuthorized': False, 'acceptanceGranted': False}
    return plan, artifacts


def output_parent(args, deps):
    fd = deps.launch.parent_fd(args.output_root / args.output_name)
    try:
        try:
            os.stat(args.output_name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return fd
        raise Held('OUTPUT_ALREADY_EXISTS')
    except BaseException:
        os.close(fd)
        raise


def write_file(directory_fd, name, value):
    raw = encoded(value)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        entry = os.fstat(fd)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            readback = stream.read(len(raw) + 1)
        require((entry.st_uid, entry.st_gid, stat.S_IMODE(entry.st_mode), entry.st_nlink) == (0, 0, 0o600, 1)
                and sha(readback) == sha(raw), 'OUTPUT_READBACK_MISMATCH')
    finally:
        os.close(fd)
    os.fsync(directory_fd)
    return sha(raw)


def publish(args, plan, artifacts, plan_sha, parent):
    # mkdir is the exclusive directory creation primitive (O_EXCL applies to files).
    os.mkdir(args.output_name, 0o700, dir_fd=parent)
    os.fsync(parent)
    directory = os.open(args.output_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    root = args.output_root / args.output_name
    try:
        os.fchown(directory, 0, 0)
        os.fchmod(directory, 0o700)
        result = {'schema': SCHEMA, 'status': 'SEMANTIC_PROVIDER_B1_RECIPES_PREPARED',
            'planSha256': plan_sha, 'roles': {},
            'preparationA': {'root': str(args.a2_root), 'planSha256': args.a2_plan_sha256,
                'files': {field: {'path': str(args.a2_root / name), 'sha256': plan['inputHashes']['a2/' + name]}
                    for field, name in (('manifest', 'manifest.json'), ('result', 'result.json'),
                                        ('semanticPeer', 'semantic-peer.json'), ('successors', 'successors.json'))}},
            'recreation': {'path': str(args.recreation_receipt), 'sha256': args.recreation_receipt_sha256},
            'baselineHashes': plan['baselineHashes'], 'inputHashes': plan['inputHashes'],
            'softwareHashes': plan['softwareHashes'], 'secretBytesHashed': 1, 'secretValuesPrinted': False,
            'startAuthorized': False, 'acceptanceGranted': False}
        for role in ROLES:
            os.mkdir(role, 0o700, dir_fd=directory)
            role_fd = os.open(role, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                os.fchown(role_fd, 0, 0)
                os.fchmod(role_fd, 0o700)
                recipe = {}
                for part in PARTS:
                    digest = write_file(role_fd, part + '.json', artifacts[role][part])
                    require(digest == plan['roles'][role][part], 'OUTPUT_PLAN_HASH_MISMATCH')
                    recipe[part] = {'path': str(root / role / (part + '.json')), 'sha256': digest}
                result['roles'][role] = {'containerId': getattr(args, role + '_id'),
                    'transaction': getattr(args, role + '_transaction'), 'recipe': recipe}
            finally:
                os.close(role_fd)
        write_file(directory, 'result.json', result)
        return result
    finally:
        os.close(directory)


def run(args, deps=None):
    created = False
    parent = None
    try:
        deps = helpers() if deps is None else deps
        recreation = deps.recreation
        recreation.DOCKER_SOCKET = str(args.docker_socket)
        original_engine = recreation.engine
        def get_only(method, resource, payload=None):
            require(method == 'GET' and payload is None, 'DOCKER_GET_ONLY')
            return original_engine(method, resource)
        recreation.engine = get_only
        try:
            parent = output_parent(args, deps)
            plan, artifacts = observe(args, deps)
            repeated_plan, repeated_artifacts = observe(args, deps)
            require(encoded(plan) == encoded(repeated_plan)
                    and encoded(artifacts) == encoded(repeated_artifacts), 'RECIPE_NOT_DETERMINISTIC_OR_INPUT_CHANGED')
            # Reauthenticate source modules/baselines before publication as well.
            for name, digest in PINS.items():
                private_read(ROOT / name, digest, modes=(0o600, 0o644))
            plan_sha = sha(canonical(plan))
            if args.plan:
                return {'schema': SCHEMA, 'status': 'PLAN_READY', 'plan': plan, 'planSha256': plan_sha,
                        'secretValuesPrinted': False, 'startAuthorized': False, 'acceptanceGranted': False}
            require(plan_sha == args.plan_sha256, 'PLAN_DIGEST_MISMATCH')
            # The only writes are inside publish, strictly after every check.
            created = True
            return publish(args, plan, artifacts, plan_sha, parent)
        finally:
            recreation.engine = original_engine
    except (Exception, KeyboardInterrupt) as error:
        # Never echo arbitrary exception text (JSON values, paths or env).
        reason = (error.args[0] if type(error).__name__ in {'Held', 'Denied'} and len(error.args) == 1 else '')
        if type(reason) is not str or not re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason):
            reason = 'REDACTED_INPUT_OR_IO_FAILURE'
        return {'schema': SCHEMA, 'status': 'PARTIAL' if created else 'HELD', 'reason': reason,
                'preserveOutput': created, 'secretValuesPrinted': False,
                'startAuthorized': False, 'acceptanceGranted': False}
    finally:
        if parent is not None:
            os.close(parent)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--plan', action='store_true')
    modes.add_argument('--apply', action='store_true')
    paths = {'a2-root', 'recreation-receipt', 'output-root', 'docker-socket'}
    for name in ('a2-root', 'a2-plan-sha256', 'a2-successors-sha256', 'recreation-receipt',
                 'recreation-receipt-sha256', 'historical-adapter-id', 'historical-southbound-id',
                 'adapter-id', 'southbound-id', 'adapter-transaction', 'southbound-transaction',
                 'expected-runtime', 'bundle-parent', 'metadata-parent', 'network-namespace-parent',
                 'cgroup-driver', 'storage-parent', 'rootfs-parent', 'output-root', 'output-name', 'docker-socket'):
        parser.add_argument('--' + name, required=True, type=Path if name in paths else str)
    parser.add_argument('--plan-sha256')
    args = parser.parse_args(argv)
    for key, value in vars(args).items():
        length = 64 if key.endswith(('_id', '_sha256')) else 32 if key.endswith('_transaction') else None
        if length and (value is not None or key != 'plan_sha256') and not re.fullmatch('[0-9a-f]{%d}' % length, value):
            parser.error('invalid --' + key.replace('_', '-'))
    ids = (args.historical_adapter_id, args.historical_southbound_id, args.adapter_id, args.southbound_id)
    if len(set(ids)) != 4:
        parser.error('four distinct container IDs required')
    for key in paths | {'bundle-parent', 'metadata-parent', 'network-namespace-parent', 'storage-parent', 'rootfs-parent'}:
        try:
            absolute(str(getattr(args, key.replace('-', '_'))))
        except Held:
            parser.error('invalid --' + key)
    if args.cgroup_driver not in {'systemd', 'cgroupfs'} or not re.fullmatch('[a-z0-9][a-z0-9-]{0,79}', args.output_name):
        parser.error('invalid cgroup driver or output name')
    if args.expected_runtime in {'runc', 'io.containerd.runc.v2'} or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', args.expected_runtime):
        parser.error('governed runtime required')
    if args.apply != (args.plan_sha256 is not None):
        parser.error('--plan-sha256 is required only with --apply')
    return args


def main():
    os.umask(0o077)
    if not hasattr(os, 'geteuid') or os.geteuid() != 0 or os.getegid() != 0:
        report = {'schema': SCHEMA, 'status': 'HELD', 'reason': 'ROOT_REQUIRED', 'secretValuesPrinted': False}
    elif not sys.flags.isolated or not sys.dont_write_bytecode:
        report = {'schema': SCHEMA, 'status': 'HELD', 'reason': 'PYTHON_ISOLATED_NO_BYTECODE_REQUIRED', 'secretValuesPrinted': False}
    else:
        report = run(arguments())
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] in {'PLAN_READY', 'SEMANTIC_PROVIDER_B1_RECIPES_PREPARED'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
