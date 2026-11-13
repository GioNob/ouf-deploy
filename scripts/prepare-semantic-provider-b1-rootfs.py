#!/usr/bin/env python3
"""Prepare fresh B1 rootfs evidence for two never-started candidates.

Only apply writes. The historical libraries are imported unchanged, either
beside this controller (delivery) or from this repository (tests).
"""

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
if (HERE / 'prepare_provider_image_rootfs.py').is_file():
    sys.path.insert(0, str(HERE))
else:
    sys.path[:0] = [str(HERE.parent / 'tools/semantic_image_rootfs'),
                    str(HERE.parent / 'tools/semantic_stopped_rootfs')]

from prepare_provider_image_rootfs import (Budget, Denied, ancestors, attributes,
    canonical, decode, load_sealer, private, program, require, sha, write_once,
    prepare, apply_docker_init)
from stopped_rootfs_comparison import expected_overlay, stopped_export_view
from rootfs_difference_report import entries, classify
from rootfs_image_equivalence import expected_root_mode, compare_image_entries

ROLES = ('adapter', 'southbound')
LIFECYCLE = ('Status', 'Running', 'Paused', 'Restarting', 'OOMKilled', 'Dead',
             'Pid', 'ExitCode', 'Error', 'StartedAt', 'FinishedAt')
# This is a constraint of the unchanged apply_docker_init library, not a CLI default.
SUPPORTED_INIT_COMMIT = '464cd50c3d9e92877d56940ea160de6fca7bea23'


def matching(pattern):
    def parse(value):
        if not re.fullmatch(pattern, value):
            raise argparse.ArgumentTypeError('invalid argument syntax')
        return value
    return parse


def absolute(value):
    path = Path(value)
    if (not value.startswith('/') or value.startswith('//') or str(path) != value or '..' in path.parts
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(c in value for c in ',:\\')):
        raise argparse.ArgumentTypeError('canonical absolute POSIX path required')
    return path


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    parser.add_argument('--plan-sha256', type=matching('[0-9a-f]{64}'))
    for name in ('a-successors', 'umoci', 'docker-init-tool', 'docker', 'mount',
                 'umount', 'source', 'docker-root', 'output-root'):
        parser.add_argument('--' + name, type=absolute, required=True)
    for name in ('a-successors-sha256', 'umoci-sha256', 'docker-init-sha256',
                 'docker-sha256', 'mount-sha256', 'umount-sha256', 'source-manifest-sha256'):
        parser.add_argument('--' + name, type=matching('[0-9a-f]{64}'), required=True)
    for role in ROLES:
        for name, kind in (('container-id', matching('[0-9a-f]{64}')),
                           ('image-id', matching('sha256:[0-9a-f]{64}')),
                           ('archive', absolute), ('archive-sha256', matching('[0-9a-f]{64}')),
                           ('config-digest', matching('sha256:[0-9a-f]{64}'))):
            parser.add_argument('--' + role + '-' + name, type=kind, required=True)
    parser.add_argument('--engine-version', type=matching('[0-9]+[.][0-9]+[.][0-9]+'), required=True)
    parser.add_argument('--engine-commit', type=matching('[0-9a-f]{40}'), required=True)
    parser.add_argument('--docker-socket', type=matching('unix:///[^\\s]+'), required=True)
    parser.add_argument('--output-name', type=matching('[a-z0-9][a-z0-9_-]{0,79}'), required=True)
    args = parser.parse_args(argv)
    if args.apply != bool(args.plan_sha256):
        parser.error('--plan-sha256 is required only with --apply')
    if args.adapter_container_id == args.southbound_container_id:
        parser.error('distinct candidate container IDs required')
    try:
        absolute(args.docker_socket[len('unix://'):])
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    return args


def spec(args, role):
    return {key: getattr(args, role + '_' + key) for key in
            ('container_id', 'image_id', 'archive', 'archive_sha256', 'config_digest')}


def binary_bindings(args):
    return {'umoci': (args.umoci, args.umoci_sha256),
            'dockerInit': (args.docker_init_tool, args.docker_init_sha256),
            'docker': (args.docker, args.docker_sha256),
            'mount': (args.mount, args.mount_sha256),
            'umount': (args.umount, args.umount_sha256)}


def frozen_archive(path, expected):
    """Stream a bounded archive without unpacking, spooling or writing."""
    ancestors(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                and 0 < before.st_size <= 536870912, 'PRIVATE_FROZEN_IMAGE_REQUIRED')
        h = hashlib.sha256()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            remaining = before.st_size
            while remaining:
                raw = stream.read(min(65536, remaining))
                require(bool(raw), 'FROZEN_ARCHIVE_CHANGED')
                h.update(raw)
                remaining -= len(raw)
            require(not stream.read(1), 'FROZEN_ARCHIVE_CHANGED')
        require(attributes(before) == attributes(os.fstat(fd)) == attributes(path.lstat()),
                'FROZEN_ARCHIVE_CHANGED')
        require(h.hexdigest() == expected, 'FROZEN_IMAGE_HASH_DRIFT')
    finally:
        os.close(fd)


class Docker:
    """Read commands use bounded pipes, including in plan: no temporary files.

    The private config path is deliberately absent during plan. Read commands
    do not create it, and cannot consult an operator's Docker config/plugins.
    """
    def __init__(self, args):
        self.binding = (args.docker, args.docker_sha256)
        self.socket = args.docker_socket
        self.config = args.output_root / args.output_name / 'docker-config'

    def read(self, *args, bound=4194304):
        require(args[0] in ('info', 'version', 'inspect', 'ps'), 'DOCKER_READ_ONLY_COMMAND_REQUIRED')
        program(*self.binding)
        command = [str(self.binding[0]), '--host', self.socket, '--config', str(self.config), *args]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        try:
            parts = []; total = 0; deadline = time.monotonic() + 30
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    require(time.monotonic() < deadline, 'BOUNDED_DOCKER_READ_FAILED')
                    if not selector.select(.1):
                        continue
                    raw = os.read(process.stdout.fileno(), min(65536, bound + 1 - total))
                    if not raw:
                        break
                    total += len(raw)
                    require(total <= bound, 'BOUNDED_DOCKER_READ_FAILED')
                    parts.append(raw)
            require(process.wait(timeout=max(.001, deadline - time.monotonic())) == 0,
                    'BOUNDED_DOCKER_READ_FAILED')
            program(*self.binding)
            return b''.join(parts)
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)

    def selected(self, role_spec):
        rows = decode(self.read('inspect', role_spec['container_id']))
        require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
                'NEVER_STARTED_EXACT_CANDIDATE_REQUIRED')
        item = rows[0]; state = item.get('State')
        require(type(state) is dict, 'NEVER_STARTED_EXACT_CANDIDATE_REQUIRED')
        require(item.get('Id') == role_spec['container_id'] and item.get('Image') == role_spec['image_id']
                and state.get('Status') == 'created' and type(state.get('Pid')) is int
                and state['Pid'] == 0 and state.get('Running') is False
                and type(state.get('StartedAt')) is str
                and re.fullmatch(r'0001-01-01T00:00:00(?:[.]0+)?Z', state['StartedAt']),
                'NEVER_STARTED_EXACT_CANDIDATE_REQUIRED')
        # Preserve all fields, including Config.MacAddress and each endpoint;
        # no normalization of absent/null/empty legacy MAC values.
        return item

    def states(self):
        ids = self.read('ps', '-aq', '--no-trunc', bound=65536).decode('ascii').splitlines()
        require(len(ids) <= 256 and len(ids) == len(set(ids))
                and all(re.fullmatch('[0-9a-f]{64}', cid) for cid in ids), 'CONTAINER_INVENTORY_UNBOUNDED')
        if not ids:
            return {}
        raw = self.read('inspect', '--format', '{{.Id}} {{json .State}}', *ids, bound=1048576)
        result = {}
        for line in raw.splitlines():
            cid, body = line.split(b' ', 1); cid = cid.decode('ascii'); state = decode(body)
            require(cid not in result, 'STATE_INVENTORY_UNPROVEN')
            result[cid] = {key: state[key] for key in LIFECYCLE}
        require(set(result) == set(ids), 'STATE_INVENTORY_UNPROVEN')
        return result


def observe(args, docker):
    output = args.output_root / args.output_name
    ancestors(output)
    root = args.output_root.lstat()
    require(stat.S_ISDIR(root.st_mode) and root.st_uid == root.st_gid == 0 and not root.st_mode & 0o022,
            'TRUSTED_OUTPUT_ROOT_REQUIRED')
    require(not os.path.lexists(output), 'NEW_OUTPUT_DIRECTORY_REQUIRED')
    for binding in binary_bindings(args).values():
        program(*binding)
    load_sealer(args.source, args.source_manifest_sha256)
    for role in ROLES:
        row = spec(args, role)
        frozen_archive(row['archive'], row['archive_sha256'])
    raw = private(args.a_successors)
    require(sha(raw) == args.a_successors_sha256, 'A_SUCCESSORS_HASH_DRIFT')
    a = decode(raw)
    # A's writer emits containers in cutover.SUCCESSORS order: adapter, southbound.
    rows = a.get('containers') if type(a) is dict else None
    require(type(rows) is list and len(rows) == 2, 'A_SUCCESSOR_BINDING_MISMATCH')
    for role, row in zip(ROLES, rows):
        selected = spec(args, role)
        require(type(row) is dict and row.get('containerId') == selected['container_id']
                and row.get('image') == selected['image_id'], 'A_SUCCESSOR_BINDING_MISMATCH')
    info = decode(docker.read('info', '--format', '{{json .}}'))
    version = decode(docker.read('version', '--format', '{{json .Server}}'))
    require(info.get('ServerVersion') == args.engine_version and info.get('Driver') == 'overlayfs'
            and info.get('DockerRootDir') == str(args.docker_root)
            and version.get('Version') == args.engine_version
            and version.get('GitCommit') == args.engine_commit[:7], 'ENGINE_BINDING_DRIFT')
    require(args.engine_commit == SUPPORTED_INIT_COMMIT, 'EXACT_OBSERVED_ENGINE_SOURCE_REQUIRED')
    states = docker.states()
    candidates = {role: docker.selected(spec(args, role)) for role in ROLES}
    require(all(spec(args, r)['container_id'] in states for r in ROLES), 'STATE_INVENTORY_UNPROVEN')
    engine = {'version': args.engine_version, 'commit': args.engine_commit,
              'serverGitCommit': version['GitCommit'], 'storageDriver': info['Driver'],
              'dockerRoot': str(args.docker_root), 'dockerSocket': args.docker_socket}
    plan = {'schema': 'ouf.semantic-provider-b1-rootfs-plan.v1',
            'aSuccessors': {'path': str(args.a_successors), 'sha256': sha(raw)},
            'source': {'path': str(args.source), 'manifestSha256': args.source_manifest_sha256},
            'engine': engine,
            'binaries': {k: {'path': str(p), 'sha256': h} for k, (p, h) in binary_bindings(args).items()},
            'roles': {role: {'containerId': spec(args, role)['container_id'],
                             'imageId': spec(args, role)['image_id'],
                             'archive': {'path': str(spec(args, role)['archive']),
                                         'sha256': spec(args, role)['archive_sha256']},
                             'configDigest': spec(args, role)['config_digest'],
                             'candidateSha256': sha(canonical(candidates[role]))} for role in ROLES},
            'containerStatesSha256': sha(canonical(states)), 'output': str(output),
            'plannedWrites': ['docker-config/', *[r + '/offline/{layout,bundle,expected-rootfs.json,'
                'docker-init-claim.json,expected-docker-rootfs.json}' for r in ROLES],
                *[r + '/strict/{view,upper,work}' for r in ROLES],
                *[r + '-comparison.json' for r in ROLES], 'result.json'],
            'operations': {'offlinePreparations': 2, 'offlineDockerInitApplications': 2,
                           'temporaryExpectedOverlayMounts': 2, 'stoppedContainerExports': 2,
                           'containerLifecycleOperations': 0, 'dockerStartRequests': 0}}
    return plan, candidates, states


def file_binding(path):
    return {'path': str(path), 'sha256': sha(private(path))}


def effective_seal(actual):
    require(type(actual) is dict and set(actual) == {'schema', 'sha256', 'entries', 'bytes'}
            and actual['schema'] == 'ouf.semantic-rootfs-seal.v1'
            and re.fullmatch('[0-9a-f]{64}', actual['sha256'])
            and type(actual['entries']) is int and actual['entries'] >= 1
            and type(actual['bytes']) is int and actual['bytes'] >= 0, 'EXACT_EFFECTIVE_SEAL_REQUIRED')
    return dict(actual)


def unchanged_candidate(docker, row, baseline):
    try:
        current = docker.selected(row)
    except Denied:
        raise Denied('STOPPED_CANDIDATE_CONFIGURATION_CHANGED') from None
    require(current == baseline, 'STOPPED_CANDIDATE_CONFIGURATION_CHANGED')


@contextmanager
def checked_export(args, docker, role, baselines):
    row = spec(args, role)
    for candidate in ROLES:
        unchanged_candidate(docker, spec(args, candidate), baselines[candidate])
    try:
        with stopped_export_view((args.docker, args.docker_sha256), args.docker_socket,
                                 docker.config, row['container_id'],
                                 args.docker_root / 'rootfs/overlayfs' / row['container_id']) as mounted:
            yield mounted
    finally:
        for candidate in ROLES:
            unchanged_candidate(docker, spec(args, candidate), baselines[candidate])


def compare_role(args, docker, role, directory, receipt, baselines):
    row = spec(args, role); lower = directory / 'offline/bundle/rootfs'
    limits = receipt['rootfsLimits']; sealer = load_sealer(args.source, args.source_manifest_sha256)
    require(sealer(lower, limits, Budget()) == receipt['rootfsSeal'], 'OFFLINE_EXPECTATION_CHANGED')
    expected_v1, image_entries = entries(sealer, lower, limits)
    require(expected_v1 == receipt['rootfsSeal'], 'OFFLINE_EXPECTATION_CHANGED')
    policy = expected_root_mode(directory / 'offline/layout', row['image_id'])
    strict = directory / 'strict'; strict.mkdir(mode=0o700)
    # Both comparisons share one held Docker export; exactly one export per CID.
    with expected_overlay(lower, strict, (args.mount, args.mount_sha256),
                          (args.umount, args.umount_sha256)) as view:
        expected, strict_entries = entries(sealer, view, limits)
        with checked_export(args, docker, role, baselines) as mounted:
            actual, actual_entries = entries(sealer, mounted, limits)
            equivalence = compare_image_entries(image_entries, actual_entries, policy)
            differences = classify(strict_entries, actual_entries)
    require(sealer(lower, limits, Budget()) == receipt['rootfsSeal'], 'OFFLINE_EXPECTATION_CHANGED')
    effective_seal(actual)
    return {'role': role, 'containerId': row['container_id'],
            'offlineReceiptSha256': file_binding(directory / 'offline/expected-docker-rootfs.json')['sha256'],
            'originalOfflineSeal': receipt['rootfsSeal'], 'expectedOverlaySeal': expected,
            'expectedV1Seal': expected_v1, 'actualSeal': actual, 'strictSealsMatch': actual == expected,
            'imageEquivalence': equivalence, 'differences': differences, 'targetRootfsCompared': True,
            'neverStarted': True, 'exportMountReleased': True, 'privateMountContentsRead': False,
            'dockerInitLayerAccepted': False, 'acceptanceGranted': False, 'startAuthorized': False}


def apply_plan(args, docker, plan, candidates, original_states, progress):
    output = Path(plan['output'])
    progress['phase'] = 'CREATE_OUTPUT'
    output.mkdir(mode=0o700)  # Exclusive; no exist_ok, overwrite or automatic rollback.
    progress['created'] = True
    roles = {}
    try:
        (output / 'docker-config').mkdir(mode=0o700)
        progress['phase'] = 'CREATE_ROLE_DIRECTORIES'
        for role in ROLES:
            (output / role).mkdir(mode=0o700)
            (output / role / 'offline').mkdir(mode=0o700)
        for role in ROLES:
            progress['phase'] = role + ':PREPARE_IMAGE'
            row = spec(args, role); directory = output / role
            offline = directory / 'offline'
            prepare(row['archive'], row['archive_sha256'], row['image_id'], row['config_digest'],
                    args.umoci, args.umoci_sha256, args.source, args.source_manifest_sha256, offline)
            progress['phase'] = role + ':APPLY_DOCKER_INIT'
            receipt = apply_docker_init(offline, args.docker_init_tool, args.docker_init_sha256,
                                       args.engine_commit, args.source, args.source_manifest_sha256)
            progress['phase'] = role + ':COMPARE'
            record = compare_role(args, docker, role, directory, receipt, candidates)
            comparison = output / (role + '-comparison.json')
            write_once(comparison, canonical(record))
            require(record['imageEquivalence']['equivalent'] is True,
                    'TARGET_ROOTFS_DIFFERS_FROM_INDEPENDENT_EXPECTATION')
            roles[role] = {'containerId': row['container_id'], 'imageId': row['image_id'],
                           'offlineImageReceipt': file_binding(offline / 'expected-rootfs.json'),
                           'offlineDockerReceipt': file_binding(offline / 'expected-docker-rootfs.json'),
                           'comparison': file_binding(comparison), 'effectiveSeal': effective_seal(record['actualSeal'])}
        progress['phase'] = 'FINAL_REVALIDATION'
        for role in ROLES:
            unchanged_candidate(docker, spec(args, role), candidates[role])
        load_sealer(args.source, args.source_manifest_sha256)
        for binding in binary_bindings(args).values():
            program(*binding)
    finally:
        # Includes failure paths; retain partial evidence and never start/stop anything.
        require(docker.states() == original_states, 'EXISTING_CONTAINER_STATES_CHANGED')
    result = {'schema': 'ouf.semantic-provider-b1-rootfs-evidence.v1',
              'planSha256': sha(canonical(plan)), 'aSuccessors': plan['aSuccessors'],
              'sourceManifestSha256': args.source_manifest_sha256, 'engine': plan['engine'], 'roles': roles,
              'containerLifecycleOperations': 0, 'dockerStartRequests': 0, 'stoppedContainerExports': 2,
              'privateKeysRead': 0, 'signaturesIssued': 0, 'startAuthorized': False, 'acceptanceGranted': False,
              'status': 'SEMANTIC_PROVIDER_B1_ROOTFS_EVIDENCE_PREPARED'}
    progress['phase'] = 'WRITE_RESULT'
    write_once(output / 'result.json', canonical(result))
    progress['phase'] = 'COMPLETE'
    return result


def written_files(output):
    # Do not recurse into unpacked rootfs (possible image links/mounts). These
    # directories are retained wholesale; only controller receipts are listed.
    names = ['result.json', *[r + '-comparison.json' for r in ROLES],
             *[r + '/offline/' + f for r in ROLES for f in
               ('expected-rootfs.json', 'docker-init-claim.json', 'expected-docker-rootfs.json')]]
    return [str(output / name) for name in names if os.path.lexists(output / name)]


def retained_directories(output):
    names = ['docker-config', *[r + suffix for r in ROLES for suffix in
                              ('', '/offline', '/offline/layout', '/offline/bundle', '/strict')]]
    return [str(output / name) for name in names if os.path.lexists(output / name)]


def main(argv=None):
    args = arguments(argv)
    progress = {'phase': 'PREFLIGHT', 'created': False}
    output = args.output_root / args.output_name
    try:
        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.dont_write_bytecode,
                'ISOLATED_ROOT_REQUIRED')
        os.umask(0o077)
        docker = Docker(args)
        plan, candidates, states = observe(args, docker)
        digest = sha(canonical(plan))
        if args.plan:
            result = {'status': 'SEMANTIC_PROVIDER_B1_ROOTFS_PLAN', 'plan': plan, 'planSha256': digest}
        else:
            require(args.plan_sha256 == digest, 'PLAN_DIGEST_CHANGED')
            result = apply_plan(args, docker, plan, candidates, states, progress)
        print(canonical(result).decode(), flush=True)
        return 0
    except Exception as error:
        reason = str(error) if isinstance(error, Denied) and re.fullmatch('[A-Z0-9_]{1,80}', str(error)) else 'B1_ROOTFS_EVIDENCE_UNPROVEN'
        print(canonical({'status': 'HELD', 'reason': reason, 'phase': progress['phase'],
                         'outputDirectory': str(output), 'outputCreated': progress['created'],
                         'writtenFiles': written_files(output) if progress['created'] else [],
                         'retainedDirectories': retained_directories(output) if progress['created'] else [],
                         'partialDirectoriesRetained': progress['created'], 'automaticRollback': False}).decode(), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
