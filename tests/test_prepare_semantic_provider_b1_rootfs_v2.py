"""Portable D-040 tests and opt-in real overlay/Docker/runc qualification.

OUF_B1_ROOTFS_V2_NATIVE=1 requires Linux root and python -I -B; missing
prerequisites fail. The native child has its own mount namespace and daemon.
"""
from contextlib import contextmanager, ExitStack, redirect_stderr
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
import test_semantic_provider_b1_acceptance_issuance as legacy
from tools.semantic_b1_acceptance import acceptance as B
from tools.semantic_b1b2_authority import authority as A


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


C = module('rootfs_v2', 'scripts/prepare-semantic-provider-b1-rootfs-v2.py')
ISSUER = module('issuer_v51_reseal_test', 'scripts/issue-semantic-provider-acceptance-v51.py')
NATIVE = os.environ.get('OUF_B1_ROOTFS_V2_NATIVE') == '1'
if NATIVE and (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0
               or not sys.flags.isolated or not sys.dont_write_bytecode):
    raise RuntimeError('OUF_B1_ROOTFS_V2_NATIVE requires Linux root:root and python -I -B')


def entry(path, kind='directory', mode=None, links=2, content=b''):
    value = dict(path=path, kind=kind, mode=mode if mode is not None else (0o600 if kind == 'file' else 0o700),
                 uid=0, gid=0, links=1 if kind == 'file' else links, xattrs={})
    if kind == 'file':
        value.update(size=len(content), sha256=C.sha(content))
    return value


def trees():
    image = {'': entry('', mode=0o755, links=3), 'run': entry('run', mode=0o755),
             'payload': entry('payload', 'file', content=b'image fixture')}
    upper = {'': entry('', mode=0o755, links=3), 'run': entry('run', mode=0o755, links=3),
             'run/provider': entry('run/provider', links=3),
             'run/provider/key': entry('run/provider/key', 'file'),
             'run/provider/tmp': entry('run/provider/tmp')}
    actual = {**copy.deepcopy(image), **copy.deepcopy(upper)}
    actual['']['links'] = actual['run']['links'] = 1
    mounts = [{'destination': '/run/provider/key', 'type': 'bind', 'source': '/private/key'},
              {'destination': '/run/provider/tmp', 'type': 'tmpfs', 'source': 'tmpfs'}]
    return image, actual, upper, mounts


def seal(records):
    # Portable fixture only. Native qualification uses unchanged load_sealer.
    return {'schema': 'ouf.semantic-rootfs-seal.v1', 'sha256': C.sha(C.canonical(records)),
            'entries': len(records), 'bytes': sum(r.get('size', 0) for r in records.values())}


class DifferenceTests(unittest.TestCase):
    def setUp(self):
        self.image, self.actual, self.upper, self.mounts = trees()

    def compare(self):
        return C.compare_entries(self.image, self.actual, self.upper, self.mounts, lambda _: 'file')

    def denied(self, code):
        with self.assertRaisesRegex(C.Denied, '^' + code + '$'):
            self.compare()

    def test_only_declared_empty_mountpoints_yield_a_new_seal_and_all_deltas(self):
        result = self.compare()
        self.assertNotEqual(seal(self.image), seal(self.actual))
        self.assertEqual([d['path'] for d in result], ['', 'run', 'run/provider', 'run/provider/key', 'run/provider/tmp'])
        self.assertEqual(result[-2]['change'], 'mountpoint')
        self.assertEqual(result[-3]['change'], 'ancestor')

    def test_nonempty_file(self):
        self.actual['run/provider/key']['size'] = 1
        self.denied('POST_CREATE_NONEMPTY_FILE')

    def test_owner_permissions_and_hardlinks(self):
        for key, value, reason in [('uid', 1, 'OWNER'), ('gid', 1, 'OWNER'), ('mode', 0o644, 'MODE'),
                                   ('links', 2, 'HARDLINK')]:
            with self.subTest(key=key):
                self.setUp(); self.actual['run/provider/key'][key] = value
                self.denied('POST_CREATE_' + reason + '_DENIED')

    def test_undeclared_and_missing_paths(self):
        self.actual['extra'] = entry('extra', 'file')
        self.denied('POST_CREATE_UNDECLARED_PATH')
        self.setUp(); del self.actual['payload']
        self.denied('POST_CREATE_IMAGE_ENTRY_MISSING')

    def test_copyup_mode_owner_and_content_change(self):
        for path, key, value in [('run', 'mode', 0o700), ('run', 'uid', 2), ('payload', 'sha256', 'a' * 64)]:
            with self.subTest(path=path, key=key):
                self.setUp(); self.actual[path][key] = value
                self.denied('POST_CREATE_IMAGE_METADATA_OR_CONTENT_DRIFT')
        self.setUp(); self.upper['run']['mode'] = 0o700
        self.denied('POST_CREATE_COPYUP_METADATA_DRIFT')

    def test_xattrs_on_new_and_copied_up_entries(self):
        self.actual['run/provider/key']['xattrs'] = {'user.unapproved': '01'}
        self.denied('POST_CREATE_XATTR_DENIED')
        self.setUp(); self.upper['run']['xattrs'] = {'trusted.overlay.opaque': '79'}
        self.denied('POST_CREATE_XATTR_DENIED')

    def test_symlink_special_and_wrong_source_kind(self):
        for kind in ('symlink', 'fifo', 'socket', 'character', 'block', 'directory'):
            with self.subTest(kind=kind):
                self.setUp(); self.actual['run/provider/key']['kind'] = kind
                self.denied('POST_CREATE_ENTRY_TYPE_DENIED')
        self.setUp()
        with self.assertRaisesRegex(C.Denied, 'OCI_BIND_SOURCE_TYPE_DENIED'):
            C.compare_entries(self.image, self.actual, self.upper, self.mounts, lambda _: 'symlink')

    def test_hidden_identical_file_copyup_and_whiteout_denied(self):
        self.upper['payload'] = self.image['payload']
        self.denied('POST_CREATE_UPPER_UNDECLARED_PATH')
        self.setUp(); self.upper['.wh.hidden'] = entry('.wh.hidden', 'character')
        self.denied('POST_CREATE_UPPER_UNDECLARED_PATH')

    def test_directory_link_counts_are_not_globally_ignored(self):
        self.actual['run']['links'] = 99
        self.denied('POST_CREATE_DIRECTORY_LINKS_DENIED')
        self.setUp(); self.upper['run']['links'] = 99
        self.denied('POST_CREATE_UPPER_DIRECTORY_LINKS_DENIED')

    def test_existing_destinations_remain_exact_and_symlink_ancestors_are_denied(self):
        self.mounts.append({'destination': '/payload', 'type': 'bind', 'source': '/unused'})
        self.compare()
        self.image['run']['kind'] = 'symlink'
        self.denied('OCI_MOUNT_ANCESTOR_NOT_DIRECTORY')

    def test_directory_bind_and_nested_mounts(self):
        self.mounts[0]['source'] = '/private/directory'
        self.actual['run/provider/key'] = self.upper['run/provider/key'] = entry('run/provider/key')
        self.actual['run/provider']['links'] = self.upper['run/provider']['links'] = 4
        C.compare_entries(self.image, self.actual, self.upper, self.mounts, lambda _: 'directory')

    def test_mount_paths_types_and_duplicates(self):
        for dest in ('relative', '/run/../escape', '//run/key', '/run//key', '/', '/run/key/'):
            with self.subTest(dest=dest), self.assertRaises(C.Denied):
                C.mount_targets([dict(self.mounts[0], destination=dest)], self.image, lambda _: 'file')
        with self.assertRaisesRegex(C.Denied, 'DUPLICATE_OCI_MOUNT_DESTINATION'):
            C.mount_targets(self.mounts * 2, self.image, lambda _: 'file')
        with self.assertRaisesRegex(C.Denied, 'ABSENT_OCI_MOUNT_TYPE_UNSUPPORTED'):
            C.mount_targets([dict(self.mounts[0], type='proc')], self.image, lambda _: 'file')


class Fixture:
    """In-memory image/snapshot, frozen receipts and two independent OCI inputs."""
    def __init__(self):
        self.files = {}; self.image, self.actual, self.upper, self.mounts = trees()
        self.parent = PurePosixPath('/var/lib/ouf-storage-migration')
        self.args = types.SimpleNamespace(date='20261115', plan=True, apply=False, plan_sha256=None,
            docker_root=PurePosixPath('/var/lib/docker'), source=PurePosixPath('/sealed/source'),
            source_manifest_sha256='a' * 64)
        for n in ('docker', 'mount', 'umount'):
            setattr(self.args, n, PurePosixPath('/usr/bin/' + n)); setattr(self.args, n + '_sha256', 'b' * 64)
        self.previous = dict(schema=C.SCHEMA, status=C.PREPARED, sourceManifestSha256='a' * 64,
            engine=dict(version='29.8.1', commit=C.V1.SUPPORTED_INIT_COMMIT, serverGitCommit='464cd50',
                        dockerRoot='/var/lib/docker', storageDriver='overlayfs', dockerSocket='unix:///var/run/docker.sock'), roles={})
        self.baselines = {}; self.snapshots = {}; self.oci = {}
        successors = {'containers': []}
        for i, r in enumerate(C.ROLES, 1):
            cid = str(i) * 64; image = 'sha256:' + str(i + 2) * 64
            successors['containers'].append(dict(containerId=cid, image=image))
            offline = PurePosixPath('/sealed/old/' + r + '/offline')
            limits = dict(maxEntries=100000, maxBytes=8589934592, maxDepth=64)
            im = self.put(offline / 'expected-rootfs.json', dict(schema='ouf.semantic-offline-image-rootfs.v1',
                rootfsSeal=seal(self.image), rootfsLimits=limits, manifestDigest=image))
            docker_receipt = dict(schema='ouf.semantic-offline-docker-rootfs.v1', imageReceiptSha256=im['sha256'],
                imageRootfsSeal=seal(self.image), rootfsSeal=seal(self.image), rootfsLimits=limits,
                manifestDigest=image, sourceManifestSha256='a' * 64, engineCommit=C.V1.SUPPORTED_INIT_COMMIT)
            self.previous['roles'][r] = dict(containerId=cid, imageId=image, offlineImageReceipt=im,
                offlineDockerReceipt=self.put(offline / 'expected-docker-rootfs.json', docker_receipt),
                comparison=self.put(PurePosixPath('/sealed/old/' + r + '-comparison.json'), {}), effectiveSeal=seal(self.image))
            root = self.args.docker_root / 'rootfs/overlayfs' / cid
            self.oci[r] = dict(root={'path': str(root)}, mounts=self.mounts)
            for name, value in [('frame_policy', {'expectedOci': self.oci[r]}), ('oci_config', self.oci[r])]:
                b = self.put(PurePosixPath('/sealed/frames/' + r + '-' + name + '.json'), value)
                setattr(self.args, r + '_' + name, PurePosixPath(b['path']))
                setattr(self.args, r + '_' + name + '_sha256', b['sha256'])
            for name in ('image_view', 'container_view'):
                setattr(self.args, r + '_' + name, PurePosixPath('/var/lib/reseal-views/' + r + '-' + name))
            self.snapshots[str(root)] = {'root': str(root), 'upper': '/snapshots/' + r + '/fs',
                'lowers': ['/snapshots/lower/fs'], 'work': '/snapshots/' + r + '/work', 'type': 'overlay', 'options': []}
            self.baselines[r] = dict(Id=cid, Image=image, Config={'MacAddress': '02:00:00:00:00:01'})
        b = self.put(PurePosixPath('/sealed/successors.json'), successors)
        self.args.a_successors = PurePosixPath(b['path']); self.args.a_successors_sha256 = b['sha256']
        self.previous['aSuccessors'] = b
        self.refresh_previous()
        f = self
        class Docker:
            def read(self, command, *args):
                return C.canonical(dict(ServerVersion='29.8.1', Driver='overlayfs', DockerRootDir='/var/lib/docker')
                    if command == 'info' else dict(Version='29.8.1', GitCommit='464cd50'))
            def states(self): return {v['Id']: {'Status': 'created'} for v in f.baselines.values()}
            def selected(self, row): return next(v for v in f.baselines.values() if v['Id'] == row['container_id'])
        self.docker = Docker()

    def put(self, path, value):
        self.files[str(path)] = C.canonical(value)
        return dict(path=str(path), sha256=C.sha(self.files[str(path)]))

    def refresh_previous(self):
        b = self.put(PurePosixPath('/sealed/old/result.json'), self.previous)
        self.args.previous_result = PurePosixPath(b['path']); self.args.previous_result_sha256 = b['sha256']

    def records(self, path):
        path = str(path)
        if path.startswith('/snapshots/'):
            return self.upper
        if path.endswith('container_view') or '/rootfs/overlayfs/' in path:
            return self.actual
        return self.image

    @contextmanager
    def portable(self):
        @contextmanager
        def view(args, source, target, image=False): yield target
        @contextmanager
        def export(args, docker, role, baselines):
            yield args.docker_root / 'rootfs/overlayfs' / self.previous['roles'][role]['containerId']
        with ExitStack() as s:
            for target, name, value in [
                (C, 'private', lambda p: self.files[str(p)]), (C, 'ancestors', lambda p: None),
                (C, 'program', lambda *a: None), (C, 'empty_mountpoint', lambda p: None),
                (C, 'load_sealer', lambda *a: lambda p, *a: seal(self.records(p))),
                (C, 'entries', lambda sealer, p, limits: (seal(self.records(p)), copy.deepcopy(self.records(p)))),
                (C, 'readonly_view', view), (C, 'overlay_binding', lambda p, d: self.snapshots[str(p)]),
                (C, 'source_kind', lambda _: 'file'), (C.V1, 'checked_export', export),
                (C, 'verified_root_mode', lambda *a: ({'mode': 0o755}, [])),
                (C.V1, 'absolute', lambda p: PurePosixPath(p)), (C, 'OUTPUT_PARENT', self.parent),
                (C, 'Path', PurePosixPath), (C.os.path, 'lexists', lambda p: False)]:
                s.enter_context(patch.object(target, name, value))
            yield

    def plan(self):
        return C.observe(self.args, self.docker)


class PlanApplyTests(unittest.TestCase):
    def test_plan_is_deterministic_readonly_and_binds_every_input(self):
        f = Fixture()
        with f.portable(), patch.object(os, 'open', side_effect=AssertionError('plan write/open')), \
             patch.object(C, 'write_once', side_effect=AssertionError('plan write')):
            first = f.plan(); second = f.plan()
        self.assertEqual(first, second)
        self.assertEqual(first['roles']['adapter']['comparison']['effectiveSeal'], seal(f.actual))
        self.assertEqual(first['roles']['adapter']['comparison']['oldSeal'], seal(f.image))
        self.assertEqual(set(first['inputs']), set(f.files))
        self.assertEqual(first['containerLifecycleOperations'], 0)

    def test_input_tamper_and_wrong_oci_root_denied(self):
        f = Fixture(); f.files[str(f.args.adapter_oci_config)] += b' '
        with f.portable(), self.assertRaisesRegex(C.Denied, 'INPUT_HASH_DRIFT'):
            f.plan()
        f = Fixture(); changed = dict(f.oci['adapter'], root={'path': '/different'})
        for field, value in [('oci_config', changed), ('frame_policy', {'expectedOci': changed})]:
            b = f.put(getattr(f.args, 'adapter_' + field), value)
            setattr(f.args, 'adapter_' + field + '_sha256', b['sha256'])
        with f.portable(), self.assertRaisesRegex(C.Denied, 'OCI_ROOT_PATH_NOT_DOCKER_CONTAINERD'):
            f.plan()

    def test_node_view_mismatch_stops_before_any_write(self):
        f = Fixture(); original = f.records
        def changed(path):
            if '/rootfs/overlayfs/' in str(path):
                value = copy.deepcopy(f.actual); value['payload']['sha256'] = 'd' * 64
                return value
            return original(path)
        f.records = changed
        with f.portable(), self.assertRaisesRegex(C.Denied, 'NODE_ROOTFS_VIEW_MISMATCH'):
            f.plan()

    def test_full_config_mac_is_not_normalized(self):
        f = Fixture()
        with f.portable():
            first = f.plan()
            del f.baselines['adapter']['Config']['MacAddress']
            self.assertNotEqual(first, f.plan())

    def test_apply_exclusive_digest_drift_and_retained_partial(self):
        f = Fixture()
        with f.portable(): plan = f.plan()
        with tempfile.TemporaryDirectory() as tmp, patch.object(C.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True):
            plan['output'] = str(Path(tmp) / 'post-create')
            f.args.plan_sha256 = C.sha(C.canonical(plan)); progress = {'created': False}
            with patch.object(C, 'observe', return_value=plan):
                result = C.apply_plan(f.args, f.docker, plan, progress)
            self.assertTrue(progress['created']); self.assertTrue(result['doNotRerunApply'])
            self.assertEqual(result['status'], C.PREPARED)
            self.assertEqual(json.loads((Path(plan['output']) / 'result.json').read_bytes()), result)
            self.assertEqual(result['roles']['adapter']['offlineImageReceipt'], f.previous['roles']['adapter']['offlineImageReceipt'])
            with self.assertRaises(FileExistsError):
                C.apply_plan(f.args, f.docker, plan, {})
            plan['output'] += '-changed'; f.args.plan_sha256 = C.sha(C.canonical(plan)); progress = {}
            with patch.object(C, 'observe', return_value={**plan, 'candidateSha256': {}}), self.assertRaisesRegex(C.Denied, 'PLAN_CHANGED_BEFORE_WRITE'):
                C.apply_plan(f.args, f.docker, plan, progress)
            self.assertTrue(Path(plan['output']).is_dir())
            self.assertFalse((Path(plan['output']) / 'result.json').exists())
            plan['output'] += '-no-create'; f.args.plan_sha256 = '0' * 64
            with self.assertRaisesRegex(C.Denied, 'PLAN_DIGEST_CHANGED'):
                C.apply_plan(f.args, f.docker, plan, {})
            self.assertFalse(Path(plan['output']).exists())

    def test_write_once_never_overwrites(self):
        # O_NOFOLLOW is unavailable on Windows; O_EXCL is the tested primitive.
        with tempfile.TemporaryDirectory() as tmp, patch.object(C.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True):
            path = Path(tmp) / 'evidence.json'; C.write_once(path, b'first')
            with self.assertRaises(FileExistsError): C.write_once(path, b'second')
            self.assertEqual(path.read_bytes(), b'first')

    def test_cli_modes_and_hash_are_mandatory(self):
        args = ['--date', '20261115']
        for name in ('previous-result', 'a-successors', 'source', 'docker', 'mount', 'umount'):
            args += ['--' + name, '/input/' + name, '--' + name + ('-manifest-sha256' if name == 'source' else '-sha256'), 'a' * 64]
        for role in C.ROLES:
            for name in ('frame-policy', 'oci-config'):
                args += ['--' + role + '-' + name, '/input/' + role + '-' + name,
                         '--' + role + '-' + name + '-sha256', 'a' * 64]
            for name in ('image-view', 'container-view'):
                args += ['--' + role + '-' + name, '/views/' + role + '-' + name]
        with patch.object(C.V1, 'Path', PurePosixPath), redirect_stderr(io.StringIO()):
            self.assertTrue(C.arguments(['--plan', *args]).plan)
            self.assertTrue(C.arguments(['--apply', '--plan-sha256', 'a' * 64, *args]).apply)
            for prefix in (['--apply'], ['--plan', '--plan-sha256', 'a' * 64], ['--plan', '--apply']):
                with self.assertRaises(SystemExit): C.arguments([*prefix, *args])
            with self.assertRaises(SystemExit): C.arguments(['--plan', *args, '--date', '20260230'])

    def test_readonly_bind_mount_verified_and_unmounted_after_denial(self):
        args = types.SimpleNamespace()
        commands = []
        with patch.object(C, 'empty_mountpoint'), patch.object(C, 'run_mount', side_effect=lambda a, cmd, **kw: commands.append((cmd, kw))), \
             patch.object(C, 'mount_rows', return_value=[{'target': '/view', 'options': ['ro']}]), patch.object(C.os.path, 'ismount', return_value=False):
            with C.readonly_view(args, PurePosixPath('/oci/root'), PurePosixPath('/view')):
                pass
        self.assertEqual(commands[0][0], ['-n', '--bind', '/oci/root', '/view'])
        self.assertEqual(commands[1][0], ['-n', '-o', 'remount,bind,ro', '/view'])
        self.assertEqual(commands[-1], (['-n', '/view'], {'unmount': True}))
        commands.clear()
        with patch.object(C, 'empty_mountpoint'), patch.object(C, 'run_mount', side_effect=lambda a, cmd, **kw: commands.append((cmd, kw))), \
             patch.object(C, 'mount_rows', return_value=[{'target': '/view', 'options': ['rw']}]), patch.object(C.os.path, 'ismount', return_value=False):
            with self.assertRaisesRegex(C.Denied, 'READONLY_VIEW_UNPROVEN'):
                with C.readonly_view(args, PurePosixPath('/oci/root'), PurePosixPath('/view')): pass
        self.assertTrue(commands[-1][1]['unmount'])

    def test_embedded_native_runtime_program_compiles(self):
        tree = ast.parse(Path(__file__).read_bytes())
        native = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'native_child')
        wrapper = next(n.value.value for n in ast.walk(native) if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'wrapper' for t in n.targets))
        compile(wrapper, '<real-runc-capture>', 'exec')

    def test_retained_root_mode_layer_bytes_are_authenticated(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = Path(tmp); blobs = layout / 'blobs/sha256'; blobs.mkdir(parents=True)
            layer = b'fake image layer bytes'; digest = C.sha(layer)
            (blobs / digest).write_bytes(layer)
            manifest = C.canonical({'layers': [{'digest': 'sha256:' + digest}]})
            image = 'sha256:' + C.sha(manifest); (blobs / image[7:]).write_bytes(manifest)
            def frozen(path, expected):
                C.require(C.sha(path.read_bytes()) == expected, 'FROZEN_IMAGE_HASH_DRIFT')
            with patch.object(C, 'private', side_effect=lambda p: p.read_bytes()), \
                 patch.object(C.V1, 'frozen_archive', side_effect=frozen), \
                 patch.object(C.V1, 'expected_root_mode', return_value={'mode': 0o755}) as reader:
                policy, bindings = C.verified_root_mode(layout, image)
                self.assertEqual(policy, {'mode': 0o755}); self.assertEqual(len(bindings), 2)
                reader.assert_called_once()
                (blobs / digest).write_bytes(b'tampered layer header')
                with self.assertRaisesRegex(C.Denied, 'FROZEN_IMAGE_HASH_DRIFT'):
                    C.verified_root_mode(layout, image)
                reader.assert_called_once()  # Drift is refused before interpreting headers.

    def test_mountinfo_binds_the_actual_upper_and_ordered_image_layers(self):
        with tempfile.TemporaryDirectory() as tmp:
            docker_root = Path(tmp) / 'docker'
            base = docker_root / 'containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots'
            for name in ('3/fs', '3/work', '2/fs', '1/fs'):
                (base / name).mkdir(parents=True)
            root = docker_root / 'rootfs/overlayfs/cid'
            row = {'target': str(root), 'type': 'overlay', 'options': ['rw'], 'super':
                   ['rw', 'upperdir=/snapshots/3/fs', 'workdir=/snapshots/3/work',
                    'lowerdir=/snapshots/2/fs:/snapshots/1/fs']}
            # Map POSIX mountinfo paths to the fake native snapshot directories.
            def path(value):
                return base / value[len('/snapshots/'):]
            with patch.object(C, 'mount_rows', return_value=[row]), patch.object(C, 'ancestors'), patch.object(C.V1, 'absolute', side_effect=path):
                observed = C.overlay_binding(root, docker_root)
                self.assertEqual(observed['upper'], '/snapshots/3/fs')
                self.assertEqual(observed['lowers'], row['super'][-1][len('lowerdir='):].split(':'))
                row['super'].append('upperdir=' + str(base / '1/fs'))
                with self.assertRaisesRegex(C.Denied, 'OVERLAY_OPTION_DUPLICATE'):
                    C.overlay_binding(root, docker_root)
            with patch.object(C, 'mount_rows', return_value=[row, {'target': str(root) + '/private'}]):
                with self.assertRaisesRegex(C.Denied, 'OCI_ROOT_SUBMOUNT_DENIED'):
                    C.overlay_binding(root, docker_root)


class AcceptanceTests(unittest.TestCase):
    def test_unmodified_r3_composes_version_five_with_resealed_inputs_and_rejects_mismatch(self):
        import test_semantic_provider_r3_compose as r3
        f = Fixture()
        with f.portable(): plan = f.plan()
        inputs = r3.fixture()
        previous = r3.C.compose(inputs, 4, sequence=4, supersedes='a' * 64)
        accepted = B.decode_manifest(inputs['files']['acceptance'])
        plan['aSuccessors'] = accepted['preparationA']['files']['successors']
        comparisons = {}
        for role in C.ROLES:
            row = accepted['roles'][role]
            plan['roles'][role].update(containerId=row['containerId'], imageId=row['imageId'])
            for key in ('offlineImageReceipt', 'offlineDockerReceipt'):
                plan['roles'][role][key] = row['rootfs'][key]
            comparisons[role] = {'path': '/var/lib/resealed/' + role + '.json',
                                 'sha256': C.sha(C.canonical(plan['roles'][role]['comparison']))}
        result = C.make_result(plan, comparisons)
        accepted['generation'] = 4
        for role in C.ROLES:
            accepted['roles'][role]['rootfs'] = {k: result['roles'][role][k] for k in
                ('effectiveSeal', 'comparison', 'offlineImageReceipt', 'offlineDockerReceipt')}
        inputs['files']['rootfs'] = C.canonical(result)
        inputs['files']['acceptance'] = B.build_acceptance(**accepted)
        composed = r3.C.compose(inputs, 5, sequence=5, supersedes=r3.A.sha(previous['authorization']))
        for role in C.ROLES:
            sealed = json.loads(composed['documents']['versions/5/documents/' + role + '/rootfs-seal.json'])
            self.assertEqual(sealed, result['roles'][role]['effectiveSeal'])
            self.assertEqual(composed['audit'][role]['rootfsResultSha256'], C.sha(inputs['files']['rootfs']))
        result['roles']['adapter']['effectiveSeal'] = seal(f.image)
        inputs['files']['rootfs'] = C.canonical(result)
        with self.assertRaisesRegex(r3.A.OperationDenied, 'A2_ACCEPTANCE_ROLE_DRIFT'):
            r3.C.compose(inputs, 5, sequence=5, supersedes=r3.A.sha(previous['authorization']))

    def test_unmodified_v51_issuer_plans_generation_four_from_actual_v2_result(self):
        f = Fixture()
        with f.portable(): plan = f.plan()
        old = legacy.Fixture()
        # Keep all A2/authority/recipe inputs from the existing issuer fixture.
        plan['aSuccessors'] = old.preparation['files']['successors']
        comparisons = {}
        for role in C.ROLES:
            plan['roles'][role].update(containerId=old.cid[role], imageId=old.image[role])
            for key in ('offlineImageReceipt', 'offlineDockerReceipt'):
                plan['roles'][role][key] = old.rootfs['roles'][role][key]
            comparisons[role] = old.put(old.root / ('post-create-' + role + '.json'), plan['roles'][role]['comparison'])
        result = C.make_result(plan, comparisons)
        old.update('rootfs_result', result)
        old.args.generation = 4; old.args.mandate_root = '/synthetic-mandates'
        old.args.closure_file = []
        for name in sorted(ISSUER.CLOSURE):
            b = old.put(old.delivery / name, (ROOT / name).read_bytes())
            old.args.closure_file.append(name + '=' + b['sha256'])
        class Reader(ISSUER.Reader):
            def read(self, path, expected=None, limit=8388608):
                if str(path) == str(old.key): raise AssertionError('private key read')
                raw = old.files[str(path)]
                A.require(expected is None or C.sha(raw) == expected, 'INPUT_SHA256_MISMATCH')
                self.hashes[str(path)] = C.sha(raw)
                return raw
        class Ledger:
            def __init__(self, *args): pass
            def refresh(self, *args): pass
            def at(self, *args): return dict(old.mandate, generation=0)
            def current(self, *args): return self.at()
            def ever_revoked(self, *args): return False
            def snapshot(self): return {'generations': 0}
        mandates = ISSUER.V.load_mandates((ROOT / ISSUER.MANDATES).read_bytes(),
                    C.sha((ROOT / ISSUER.MANDATES).read_bytes()), ROOT / ISSUER.MANDATES)
        with old.portable(), patch.object(ISSUER, 'ROOT', old.delivery), patch.object(ISSUER, 'Reader', Reader), \
             patch.object(ISSUER.V, 'load_mandates', return_value=mandates), \
             patch.object(mandates, 'MandateLedger', Ledger), patch.object(mandates, 'MandateAuthenticator'), \
             patch.object(ISSUER, 'check_openssl'):
            observed, raw, expected, *_ = ISSUER.observe(old.args)
        accepted = B.decode_manifest(raw)
        self.assertEqual(accepted['generation'], 4)
        self.assertEqual(observed['privateKeysRead'], 0)
        for role in C.ROLES:
            self.assertEqual(accepted['roles'][role]['rootfs'], {k: result['roles'][role][k] for k in
                ('effectiveSeal', 'comparison', 'offlineImageReceipt', 'offlineDockerReceipt')})


@unittest.skipUnless(NATIVE, 'set OUF_B1_ROOTFS_V2_NATIVE=1 on native Linux root')
class NativeTests(unittest.TestCase):
    def test_real_docker_create_overlay_and_node_observation_in_private_namespace(self):
        for name in ('docker', 'dockerd', 'runc', 'mount', 'umount', 'unshare', 'ip', 'nsenter', 'sleep', 'ldd'):
            self.assertIsNotNone(shutil.which(name), name)
        result = subprocess.run(['unshare', '--mount', '--fork', sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--native-child'],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=150)
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))
        self.assertIn(b'NODE_OBSERVE_POST_CREATE_EQUAL', result.stdout)
        print(result.stdout.decode(), flush=True)


def native_child():
    """Private Docker29 fixture: runc create, Node.observe, delete, then export.

    Lifecycle operations belong only to this disposable test. The tool itself
    never invokes create/start/delete. No downloads or application credentials.
    """
    os.umask(0o077)
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    with tempfile.TemporaryDirectory(prefix='ouf-rootfs-v2-', dir='/var/lib') as tmp:
        root = Path(tmp); root.chmod(0o700)
        source = root / 'source'
        shutil.copytree(ROOT / 'tools/semantic_cohort_admission/cohort-draft', source)
        for p in [source, *source.rglob('*')]: p.chmod(0o700 if p.is_dir() else 0o600)
        source_hash = C.sha((source / 'sources.json').read_bytes())
        config = root / 'docker-config'; config.mkdir(mode=0o700)
        runtime = root / 'capture-runtime'; capture = root / 'node.json'
        runc = str(Path(shutil.which('runc')).resolve())
        # Run NodeObservation.observe while the real runc task is CREATED.
        # Only unrelated signed transport/live-profile checks are synthetic.
        wrapper = '''
import hashlib,importlib.util,json,os,pathlib,subprocess,sys
from unittest.mock import patch
args=sys.argv[1:]
if 'create' not in args: raise SystemExit(subprocess.run([RUNC,*args]).returncode)
created=False
try:
    subprocess.run([RUNC,*args],check=True);created=True
    runtime_root=args[args.index('--root')+1];cid=args[-1]
    state=json.loads(subprocess.check_output([RUNC,'--root',runtime_root,'state',cid]))
    spec=importlib.util.spec_from_file_location('controller',CONTROLLER)
    c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
    c.load_sealer(pathlib.Path(SOURCE),SOURCE_HASH)
    node=sys.modules['tools.semantic_provider_node_observation']
    bundle=pathlib.Path(state['bundle']);raw=(bundle/'config.json').read_bytes();oci=json.loads(raw)
    assert pathlib.Path(oci['root']['path']).is_absolute()
    assert '/rootfs/overlayfs/'+cid == oci['root']['path'][-(len('/rootfs/overlayfs/')+len(cid)):]
    generation=node.NativeBackend.generation(None,state['pid'])
    app=node.application_hash(oci)
    class Budget(c.Budget):
        def remaining(self,*args): return super().remaining()
    binding={'path':RUNC,'sha256':hashlib.sha256(pathlib.Path(RUNC).read_bytes()).hexdigest()}
    def program(name):
        import shutil
        p=str(pathlib.Path(shutil.which(name)).resolve())
        return {'path':p,'sha256':hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()}
    cfg={'runtimeRootParents':[str(pathlib.Path(runtime_root).parent)],'bundleParents':[str(bundle.parent)],
         'runtimeBinding':binding,'rootfsLimits':{'maxEntries':100000,'maxBytes':8589934592,'maxDepth':64},
         'commands':{'ip':program('ip'),'nsenter':program('nsenter')},
         'candidate':{'networkBindings':[],'transport':{}}}
    request={'containerId':cid,'generation':generation,'applicationHash':app,'transportHash':'fixture','transactionId':'fixture'}
    with patch.object(node,'transport_hash',return_value='fixture'),patch.object(node,'declarations',return_value=[]),patch.object(node,'live_profile'):
        observed=node.NodeObservation(cfg,Budget()).observe(request,{'runtimeRoot':runtime_root,'bundleHash':app},lambda p:p.read_bytes())
    pathlib.Path(CAPTURE).write_text(json.dumps({'oci':oci,'seal':observed['rootfsSeal']}))
finally:
    if created: subprocess.run([RUNC,'--root',runtime_root,'delete','--force',cid],check=True)
raise SystemExit(1)
'''
        assignments = dict(RUNC=runc, CONTROLLER=str(ROOT / 'scripts/prepare-semantic-provider-b1-rootfs-v2.py'),
                           SOURCE=str(source), SOURCE_HASH=source_hash, CAPTURE=str(capture))
        runtime.write_text('#!' + sys.executable + '\n' + '\n'.join(k + '=' + repr(v) for k, v in assignments.items()) + '\n' + wrapper)
        runtime.chmod(0o700)
        socket = 'unix://' + str(root / 'docker.sock'); data = root / 'docker-data'
        daemon_config = root / 'daemon.json'
        daemon_config.write_text('{"features":{"containerd-snapshotter":true}}')
        with (root / 'daemon.log').open('wb') as log:
            daemon = subprocess.Popen(['dockerd', '--config-file=' + str(daemon_config), '--host=' + socket,
                '--data-root=' + str(data), '--exec-root=' + str(root / 'exec'), '--pidfile=' + str(root / 'daemon.pid'),
                '--bridge=none', '--iptables=false', '--ip6tables=false', '--ip-forward=false', '--ip-masq=false',
                '--add-runtime=reseal-fixture=' + str(runtime)], stdout=log, stderr=log)
            cid = None
            def docker(*args, check=True):
                return subprocess.run(['docker', '--host', socket, '--config', str(config), *args],
                    check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
            try:
                end = time.monotonic() + 40
                while docker('info', check=False).returncode:
                    assert daemon.poll() is None and time.monotonic() < end, (root / 'daemon.log').read_text()
                    time.sleep(.1)
                info = json.loads(docker('info', '--format', '{{json .}}').stdout)
                assert info['ServerVersion'] == '29.8.1' and info['Driver'] == 'overlayfs', info
                image = root / 'image'; image.mkdir(mode=0o755)
                for d in ('run', 'etc', 'dev', 'dev/pts', 'dev/shm', 'dev/mqueue', 'proc', 'sys', 'sys/fs', 'sys/fs/cgroup'):
                    (image / d).mkdir(mode=0o755)
                archive = root / 'image.tar'
                with tarfile.open(archive, 'w') as tar:
                    for p in image.iterdir(): tar.add(p, arcname=p.name)
                    sleep = Path(shutil.which('sleep')).resolve()
                    tar.add(sleep, arcname='sleep')
                    linked = subprocess.check_output(['ldd', str(sleep)]).decode()
                    for path in sorted(set(re.findall(r'(/[A-Za-z0-9_./+-]+)', linked))):
                        raw = Path(path).read_bytes(); info = tarfile.TarInfo(path.lstrip('/'))
                        info.size, info.mode = len(raw), 0o755
                        tar.addfile(info, io.BytesIO(raw))
                image_id = docker('import', str(archive)).stdout.decode().strip()
                key = root / 'synthetic-key'; key.write_bytes(b'fixture secret, never read by resealer'); key.chmod(0o600)
                cid = docker('create', '--network=none', '--runtime=reseal-fixture', '--mount',
                    'type=bind,src=' + str(key) + ',dst=/run/provider/key,readonly',
                    '--tmpfs', '/run/provider/tmp:mode=700', image_id, '/sleep', '60').stdout.decode().strip()
                assert docker('start', cid, check=False).returncode != 0
                assert capture.exists(), (root / 'daemon.log').read_text()
                observed = json.loads(capture.read_bytes())
                assert observed['oci']['root']['path'] == str(data / 'rootfs/overlayfs' / cid)
                # Node has been observed on the actual Docker bundle/root.path.
                sealer = C.load_sealer(source, source_hash)
                limits = dict(maxEntries=100000, maxBytes=8589934592, maxDepth=64)
                args = types.SimpleNamespace()
                for n in ('docker', 'mount', 'umount'):
                    p = Path(shutil.which(n)).resolve(); setattr(args, n, p); setattr(args, n + '_sha256', C.sha(p.read_bytes()))
                image_view = root / 'image-view'; view = root / 'container-view'
                image_view.mkdir(mode=0o700); view.mkdir(mode=0o700)
                with C.V1.stopped_export_view((args.docker, args.docker_sha256), socket, config, cid,
                                              Path(observed['oci']['root']['path'])) as original:
                    snapshot = C.overlay_binding(original, data)
                    C.run_mount(args, ['-n', '-t', 'overlay', 'overlay', '-o', 'ro,lowerdir=' + ':'.join(snapshot['lowers']), str(image_view)])
                    try:
                        _, expected = C.entries(sealer, image_view, limits)
                        _, upper = C.entries(sealer, Path(snapshot['upper']), limits)
                        with C.readonly_view(args, original, view) as ro:
                            actual_seal, actual = C.entries(sealer, ro, limits)
                            differences = C.compare_entries(expected, actual, upper, observed['oci']['mounts'], C.source_kind)
                            assert actual_seal == observed['seal'] == sealer(original, limits, C.Budget())
                            assert any(d['path'] == 'run/provider/key' for d in differences)
                            print('NODE_OBSERVE_POST_CREATE_EQUAL ' + json.dumps(actual_seal), flush=True)
                    finally:
                        C.run_mount(args, ['-n', str(image_view)], unmount=True)
            finally:
                if cid is not None: docker('rm', '-f', cid, check=False)
                daemon.terminate()
                try: daemon.wait(timeout=20)
                except subprocess.TimeoutExpired: daemon.kill(); daemon.wait(timeout=5)


if __name__ == '__main__':
    if sys.argv[1:] == ['--native-child']: native_child()
    else: unittest.main()
