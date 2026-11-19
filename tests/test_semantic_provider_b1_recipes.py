"""Synthetic GET-only requests; real builders/baselines and publication bytes.

Linux root CI exercises native modes, links, ownership, no-follow and fsync.
Windows adapts descriptor-relative directory IO only; it is not POSIX proof.
"""
import copy
from contextlib import ExitStack, contextmanager, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools/semantic_frame_compiler'))

from tools.semantic_successor_recipes import creation_launch as L
from tools.semantic_successor_recipes import build_role_frame_template_tmpfs as T
import compile_creation_frame_policy as C
import build_role_frame_template as B
from prepare_provider_v2_launch_inputs import launch_from_spec
from tools.semantic_b1_acceptance import acceptance as ACCEPT


def load(filename):
    spec = importlib.util.spec_from_file_location('test_' + Path(filename).stem.replace('-', '_'), ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('scripts/prepare-semantic-provider-b1-recipes.py')
r = load('scripts/recreate-southbound-successor-20261113.py')
r.HMAC_SOURCE = PurePosixPath(r.HMAC_SOURCE.as_posix())
baseline = {role: json.loads((ROOT / name).read_bytes()) for role, name in m.BASELINES.items()}
SENTINEL = b'HMAC_SENTINEL_NEVER_PRINT_OR_COPY_9c812fa0'
CID = {'adapter': 'a' * 64, 'southbound': 'b' * 64}
TX = {'adapter': '1' * 32, 'southbound': '2' * 32}


def st_with(entry, **overrides):
    fields = {key: getattr(entry, key) for key in dir(entry) if key.startswith('st_')}
    return types.SimpleNamespace(**(fields | overrides))


@contextmanager
def portable_stage():
    """On Linux no adapters: real dir_fd, no-follow, permissions and fsync."""
    if os.name != 'nt':
        yield
        return
    original_open, original_close, original_sync = os.open, os.close, os.fsync
    original_stat, original_mkdir = os.fstat, os.mkdir
    directories, files, modes = {}, {}, {}

    def open_fd(path, flags, mode=0o777, *, dir_fd=None):
        path = Path(path) if dir_fd is None else directories[dir_fd] / path
        if path.is_dir():
            fd = -100 - len(directories)
            directories[fd] = path
            return fd
        fd = original_open(path, flags | os.O_BINARY, mode)
        files[fd] = path
        if flags & os.O_CREAT:
            modes[path] = mode
        return fd

    def fstat(fd):
        if fd in directories:
            return st_with(directories[fd].stat(), st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o700)
        result = original_stat(fd)
        return st_with(result, st_uid=0, st_gid=0,
                       st_mode=stat.S_IFREG | modes.get(files.get(fd), 0o600))

    with ExitStack() as stack:
        for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK'):
            stack.enter_context(patch.object(os, name, 0, create=True))
        stack.enter_context(patch.object(os, 'open', side_effect=open_fd))
        stack.enter_context(patch.object(os, 'mkdir', side_effect=lambda path, mode=0o777, *, dir_fd=None:
            original_mkdir(path if dir_fd is None else directories[dir_fd] / path, mode)))
        stack.enter_context(patch.object(os, 'close', side_effect=lambda fd: None if fd in directories else original_close(fd)))
        stack.enter_context(patch.object(os, 'fsync', side_effect=lambda fd: None if fd in directories else original_sync(fd)))
        stack.enter_context(patch.object(os, 'fchmod', side_effect=lambda fd, mode:
            modes.update({files[fd]: mode}) if fd in files else None, create=True))
        stack.enter_context(patch.object(os, 'fchown', create=True))
        stack.enter_context(patch.object(os, 'fstat', side_effect=fstat))
        yield


def synthetic_request(role):
    launch = baseline[role]['launch']
    uid, gid = launch['startup']['uid'], launch['startup']['gid']
    mounts = [{'Type': 'bind', 'Source': '/sealed/' + role + '/config.json',
               'Target': '/usr/local/etc/ouf/config.json', 'ReadOnly': True}]
    if role == 'southbound':
        mounts += [{'Type': 'bind', 'Source': str(r.HMAC_SOURCE),
                    'Target': r.HMAC_TARGET, 'ReadOnly': True},
                   {'Type': 'bind', 'Source': '/sealed/southbound/apisix.yaml',
                    'Target': r.ROUTES_SOURCE, 'ReadOnly': True},
                   {'Type': 'bind', 'Source': '/sealed/southbound/config.yaml',
                    'Target': '/usr/local/apisix/conf/config.yaml', 'ReadOnly': True}]
    return {'Image': 'sha256:' + ('c' if role == 'adapter' else 'd') * 64,
        'User': f'{uid}:{gid}', 'WorkingDir': '/app' if role == 'adapter' else '/',
        'Entrypoint': ['python3', '-B', '-m', 'tools.semantic_provider_adapter'] if role == 'adapter' else ['/bin/sh', '-c'],
        'Cmd': ['--configuration', '/usr/local/etc/ouf/config.json'] if role == 'adapter' else [r.SOUTHBOUND_STARTUP],
        'Env': ['LANG=C.UTF-8', 'PATH=/image/bin'], 'Healthcheck': {'Test': ['NONE']},
        'HostConfig': {'ReadonlyRootfs': launch['manifest']['readOnlyRoot'],
            'Memory': launch['manifest']['memoryBytes'], 'MemorySwap': launch['manifest']['memoryBytes'],
            'PidsLimit': launch['manifest']['pidsLimit'], 'Mounts': mounts, 'Binds': None,
            'Tmpfs': copy.deepcopy(launch['manifest'].get('tmpfs', {})),
            'OomKillDisable': None, 'RestartPolicy': {'Name': 'no'}, 'Runtime': 'governed-test'},
        'NetworkingConfig': {'EndpointsConfig': {}}}


def synthetic_inspect(role, request):
    name = r.ADAPTER if role == 'adapter' else r.SOUTHBOUND
    host = copy.deepcopy(request['HostConfig'])
    host['OomKillDisable'] = False  # The sole admitted real Engine normalization.
    return {'Id': CID[role], 'Name': '/' + name + '-successor', 'Image': request['Image'],
        'Config': {key: copy.deepcopy(request[key]) for key in ('User', 'WorkingDir', 'Entrypoint', 'Cmd', 'Env', 'Healthcheck')}
                  | {'Labels': {r.OWNER_LABEL: TX[role]}},
        'HostConfig': host, 'RestartCount': 0,
        'State': {'Status': 'created', 'Running': False, 'Restarting': False, 'Paused': False,
                  'Pid': 0, 'StartedAt': '0001-01-01T00:00:00Z'},
        'Mounts': [{'Source': mt['Source'], 'Destination': mt['Target'], 'Type': 'bind', 'RW': False,
                    'Propagation': 'rprivate'} for mt in host['Mounts']],
        'NetworkSettings': {'Networks': {network: {'IPAMConfig': {'IPv4Address': ip}, 'Aliases': [name],
            'EndpointID': '', 'IPAddress': '', 'GlobalIPv6Address': '', 'MacAddress': mac}
            for network, (ip, mac) in r.ENDPOINTS[name].items()}}}


def fake_source(mount, uid, gid):
    raw = SENTINEL if mount['Source'] == str(r.HMAC_SOURCE) else b'public synthetic configuration'
    return {'source': mount['Source'], 'target': mount['Target'], 'readOnly': True,
            'uid': uid, 'gid': gid, 'mode': 0o600, 'sha256': m.sha(raw), 'maxBytes': L.MAX_BYTES}


class LaunchTests(unittest.TestCase):
    def launch(self, role, request=None):
        return L.creation_launch(synthetic_request(role) if request is None else request, role,
                                baseline[role]['launch']['manifest'].get('tmpfs'), hash_source=fake_source)

    def test_adapter_parity_with_historical_independent_spec(self):
        request = synthetic_request('adapter')
        actual = self.launch('adapter', request)
        spec = {'role': 'adapter', 'uid': actual['startup']['uid'], 'gid': actual['startup']['gid'],
            'user': request['User'], 'command': request['Cmd'],
            **{key: actual['manifest'][key] for key in ('readOnlyRoot', 'memoryBytes', 'pidsLimit')},
            'mounts': actual['sources']}
        image = {key: request[key] for key in ('Entrypoint', 'Cmd', 'WorkingDir')}
        self.assertEqual(actual, launch_from_spec(spec, image, dict(row.split('=', 1) for row in request['Env'])))

    def test_southbound_entrypoint_and_tmpfs_and_env_order(self):
        launch = self.launch('southbound')
        self.assertEqual(launch['startup']['args'], ['/bin/sh', '-c', r.SOUTHBOUND_STARTUP])
        self.assertEqual(launch['manifest']['tmpfs'], baseline['southbound']['launch']['manifest']['tmpfs'])
        self.assertEqual(launch['startup']['env'], ['PATH=/image/bin', 'HOSTNAME=$OUF_HOSTNAME', 'LANG=C.UTF-8'])
        self.assertEqual(launch['startup']['umask'], None)

    def test_tmpfs_drift_and_invalid_requests(self):
        for value in ({}, {'/wrong': 'rw'}, None):
            request = synthetic_request('southbound')
            request['HostConfig']['Tmpfs'] = value
            with self.assertRaisesRegex(L.Held, '^SOUTHBOUND_TMPFS_BASELINE_MISMATCH$'):
                self.launch('southbound', request)
        for field, value in (('User', '0:636'), ('Env', ['HOSTNAME=override']), ('Env', ['A=1', 'A=2'])):
            request = synthetic_request('adapter')
            request[field] = value
            with self.assertRaises(L.Held):
                self.launch('adapter', request)
        request = synthetic_request('adapter')
        request['HostConfig']['MemorySwap'] = -1
        with self.assertRaisesRegex(L.Held, 'LAUNCH_RESOURCES_REQUIRED'):
            self.launch('adapter', request)
        request = synthetic_request('adapter')
        request['HostConfig']['Mounts'][0]['ReadOnly'] = False
        with self.assertRaisesRegex(L.Held, 'READONLY_REQUEST_BINDS_REQUIRED'):
            self.launch('adapter', request)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        # On POSIX CI this must be root; never silently skip custody checks.
        if os.name != 'nt':
            self.assertEqual(os.geteuid(), 0, 'Run this suite with sudo for native custody tests')
        self.temp = tempfile.TemporaryDirectory(dir=Path.home() if os.name != 'nt' else None)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'provider-receipt.key'
        self.path.write_bytes(SENTINEL)
        self.path.chmod(0o600)
        if os.name != 'nt':
            os.chown(self.path, 636, 636)

    def binding(self, **metadata):
        if os.name != 'nt' and not metadata:
            return L.source_binding({'Source': str(self.path), 'Target': '/run/key'}, 636, 636)
        # Metadata fault injection uses real readinto; Windows has no POSIX uid.
        real_stat, real_open = os.fstat, os.open
        parent = real_open(self.path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)) if os.name != 'nt' else 123456
        try:
            with ExitStack() as stack:
                for flag in ('O_NOFOLLOW', 'O_NONBLOCK'):
                    if not hasattr(os, flag):
                        stack.enter_context(patch.object(os, flag, 0, create=True))
                stack.enter_context(patch.object(L, 'absolute', side_effect=Path))
                stack.enter_context(patch.object(L, 'parent_fd', return_value=parent))
                if os.name == 'nt':
                    original_close = os.close
                    stack.enter_context(patch.object(os, 'open', side_effect=lambda name, flags, **kw:
                        real_open(self.path, flags | os.O_BINARY)))
                    stack.enter_context(patch.object(os, 'close', side_effect=lambda fd:
                        None if fd == parent else original_close(fd)))
                def entry(fd):
                    return st_with(real_stat(fd), **({'st_uid': 636, 'st_gid': 636,
                        'st_mode': stat.S_IFREG | 0o600, 'st_nlink': 1,
                        'st_dev': 0, 'st_ino': 0, 'st_mtime_ns': 0, 'st_ctime_ns': 0} | metadata))
                stack.enter_context(patch.object(os, 'fstat', side_effect=entry))
                original_stat = os.stat
                stack.enter_context(patch.object(os, 'stat', side_effect=lambda path, **kw:
                    st_with(original_stat(self.path), **({'st_uid': 636, 'st_gid': 636,
                        'st_mode': stat.S_IFREG | 0o600, 'st_nlink': 1,
                        'st_dev': 0, 'st_ino': 0, 'st_mtime_ns': 0, 'st_ctime_ns': 0} | metadata)) if kw.get('dir_fd') == parent
                    else original_stat(path, **kw)))
                # source_binding owns parent after parent_fd returns.
                return L.source_binding({'Source': str(self.path), 'Target': '/run/key'}, 636, 636)
        finally:
            pass

    def test_hmac_returns_only_hash(self):
        result = self.binding()
        self.assertEqual(result['sha256'], m.sha(SENTINEL))
        self.assertNotIn(SENTINEL.decode(), json.dumps(result))
        self.assertEqual(set(result), {'source', 'target', 'uid', 'gid', 'mode', 'sha256', 'readOnly', 'maxBytes'})

    def test_mode_owner_and_link_faults_are_held(self):
        for metadata in ({'st_uid': 999}, {'st_gid': 999}, {'st_mode': stat.S_IFREG | 0o644},
                         {'st_mode': stat.S_IFREG | 0o666}, {'st_nlink': 2}, {'st_size': L.MAX_BYTES + 1}):
            with self.subTest(metadata=metadata), self.assertRaisesRegex(L.Held, '^SOURCE_FILE_CUSTODY_REQUIRED$'):
                self.binding(**metadata)

    def test_parent_open_failure_has_constant_code(self):
        with patch.object(L, 'absolute', return_value=self.path), \
                patch.object(L, 'parent_fd', side_effect=OSError('private path must not escape')), \
                self.assertRaisesRegex(L.Held, '^SOURCE_CUSTODY_IO_FAILED$'):
            L.source_binding({'Source': str(self.path), 'Target': '/run/key'}, 636, 636)

    def test_native_symlink_hardlink_and_parent_custody(self):
        if os.name == 'nt':
            # Equivalent metadata denial above; symlink privilege is not present.
            with self.assertRaises(L.Held):
                self.binding(st_mode=stat.S_IFLNK | 0o777)
            return
        linked = self.path.with_name('linked')
        os.link(self.path, linked)
        with self.assertRaisesRegex(L.Held, 'SOURCE_FILE_CUSTODY_REQUIRED'):
            self.binding()
        linked.unlink()
        link = self.path.with_name('symlink')
        link.symlink_to(self.path)
        with self.assertRaises(L.Held):
            L.source_binding({'Source': str(link), 'Target': '/run/key'}, 636, 636)
        self.path.parent.chmod(0o770)
        with self.assertRaisesRegex(L.Held, 'SOURCE_PARENT_CUSTODY_REQUIRED'):
            self.binding()
        self.path.parent.chmod(0o700)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home() if os.name != 'nt' else None)
        self.addCleanup(self.temp.cleanup)
        self.physical = Path(self.temp.name)
        self.args = types.SimpleNamespace(plan=True, apply=False, plan_sha256=None,
            a2_root=PurePosixPath('/private/a2'), a2_plan_sha256='e' * 64, a2_successors_sha256=None,
            recreation_receipt=PurePosixPath('/private/recreation/result.json'), recreation_receipt_sha256=None,
            historical_adapter_id='8' * 64, historical_southbound_id='9' * 64,
            adapter_id=CID['adapter'], southbound_id=CID['southbound'],
            adapter_transaction=TX['adapter'], southbound_transaction=TX['southbound'],
            expected_runtime='governed-test', bundle_parent='/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby',
            metadata_parent='/var/lib/docker/containers', network_namespace_parent='/run/docker/netns',
            cgroup_driver='systemd', storage_parent='/var/lib/docker', rootfs_parent='/var/lib/docker/rootfs/overlayfs',
            output_root=PurePosixPath('/private/recipes'), output_name='new', docker_socket=PurePosixPath('/var/run/docker.sock'))
        self.requests = {role: synthetic_request(role) for role in m.ROLES}
        self.docs = {CID[role]: synthetic_inspect(role, self.requests[role]) for role in m.ROLES}
        self.files = {}
        self.recreation = {'schema': 'ouf.semantic-southbound-successor-recreation.v1',
            'status': 'SOUTHBOUND_RECREATED_STOPPED', 'newCid': CID['southbound'], 'newTransaction': TX['southbound'],
            'plan': {'newSouthboundRequest': self.requests['southbound'],
                'reconstructedRequestDigests': {r.ADAPTER: m.sha(r.canonical(self.requests['adapter']))},
                'reconstructedRequestsSha256': 'f' * 64}}
        self.update_recreation()
        self.successors = {'transactions': {CID[role]: TX[role] for role in m.ROLES},
            'lineage': {'recreation': {'path': str(self.args.recreation_receipt),
                'sha256': self.args.recreation_receipt_sha256, 'planSha256': self.recreation['planSha256'],
                'newCid': CID['southbound']}},
            'containers': [{'containerId': CID[role], 'transaction': TX[role], 'name': self.docs[CID[role]]['Name'],
                'image': self.requests[role]['Image'],
                'dockerFrameSha256': m.sha(m.canonical({k: self.docs[CID[role]][k] for k in m.A2_FRAME_FIELDS}))}
                for role in m.ROLES]}
        self.update_a2()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(portable_stage())
        self.stack.enter_context(patch.object(m, 'private_read', side_effect=self.read))
        self.stack.enter_context(patch.object(m, 'output_parent', side_effect=lambda *args:
            os.open(self.physical, os.O_RDONLY | os.O_DIRECTORY)))
        self.engine = self.stack.enter_context(patch.object(r, 'engine', side_effect=self.get))
        self.build = self.stack.enter_context(patch.object(r, 'build_request', side_effect=lambda historical, name, noswap:
            copy.deepcopy(self.requests['adapter'])))
        self.stack.enter_context(patch.object(r, 'verify_routes'))
        self.stack.enter_context(patch.object(r, 'protected_file'))
        # Real generator and real compiler/builders; synthetic source hashes.
        self.hasher = Mock(side_effect=fake_source)
        self.launcher = types.SimpleNamespace(creation_launch=lambda req, role, tmpfs:
            L.creation_launch(req, role, tmpfs, hash_source=self.hasher))
        self.deps = types.SimpleNamespace(launch=self.launcher, recreation=r, adapter=B,
                                          southbound=T, compiler=C, baselines=copy.deepcopy(baseline))

    def read(self, path, expected=None, **kwargs):
        name = str(path)
        if name in self.files:
            raw = self.files[name]
        else:
            # LF-only synthetic delivery bytes for Windows checkout tests.
            raw = Path(path).read_bytes().replace(b'\r\n', b'\n')
        m.require(expected is None or m.sha(raw) == expected, 'INPUT_SHA256_MISMATCH')
        return raw

    def update_recreation(self):
        self.recreation['planSha256'] = m.sha(r.canonical(self.recreation['plan']))
        self.recreation['newRequestSha256'] = m.sha(r.canonical(self.requests['southbound'] |
            {'Labels': {r.OWNER_LABEL: self.args.southbound_transaction}}))
        raw = m.encoded(self.recreation)
        self.files[str(self.args.recreation_receipt)] = raw
        self.args.recreation_receipt_sha256 = m.sha(raw)

    def update_a2(self):
        peer = {'synthetic': True}
        self.files[str(self.args.a2_root / 'semantic-peer.json')] = m.encoded(peer)
        self.files[str(self.args.a2_root / 'successors.json')] = m.encoded(self.successors)
        self.args.a2_successors_sha256 = m.sha(self.files[str(self.args.a2_root / 'successors.json')])
        body = {'schema': 'ouf.semantic-provider-preparation-a.manifest.v1',
            'directory': {'path': str(self.args.a2_root)}, 'semanticPeer': peer, 'successors': self.successors,
            'filesCreated': [{'path': str(self.args.a2_root / name), 'sha256': m.sha(self.files[str(self.args.a2_root / name)])}
                             for name in ('semantic-peer.json', 'successors.json')]}
        self.files[str(self.args.a2_root / 'result.json')] = m.encoded({'status': 'SEMANTIC_PROVIDER_PREPARATION_A_STAGED',
            'planSha256': self.args.a2_plan_sha256, 'manifest': body, 'replayAllowed': False})
        self.files[str(self.args.a2_root / 'manifest.json')] = m.encoded({'planSha256': self.args.a2_plan_sha256, 'manifest': body})

    def get(self, method, path, payload=None):
        self.assertEqual(method, 'GET')
        self.assertIsNone(payload)
        return copy.deepcopy(self.docs[path.split('/')[2]])

    def run_controller(self):
        return m.run(self.args, self.deps)

    def assert_held(self, code):
        result = self.run_controller()
        self.assertEqual((result['status'], result.get('reason')), ('HELD', code))
        self.assertEqual(list(self.physical.iterdir()), [])

    def test_plan_no_writes_real_baselines_determinism_hashes_only(self):
        result = self.run_controller()
        self.assertEqual(result['status'], 'PLAN_READY', result)
        self.assertEqual(list(self.physical.iterdir()), [])
        again = self.run_controller()
        self.assertEqual(result, again)
        self.assertEqual(result['plan']['secretBytesHashed'], 1)
        self.assertFalse(result['plan']['secretValuesPrinted'])
        self.assertNotIn('/image/bin', json.dumps(result))
        self.assertNotIn(SENTINEL.decode(), json.dumps(result))
        plan, artifacts = m.observe(self.args, self.deps)
        for role in m.ROLES:
            for part in m.PARTS:
                self.assertEqual(plan['roles'][role][part], m.sha(m.encoded(artifacts[role][part])))
            self.assertEqual(artifacts[role]['policy'], C.compile_policy(
                artifacts[role]['template'], artifacts[role]['launch'], artifacts[role]['context']))
        self.assertEqual(self.build.call_args.args[1:], (r.ADAPTER, True))

    def test_apply_publishes_private_files_and_task15_recipe_shape(self):
        plan = self.run_controller()
        self.assertEqual(plan['status'], 'PLAN_READY', plan)
        self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, plan['planSha256']
        result = self.run_controller()
        self.assertEqual(result['status'], 'SEMANTIC_PROVIDER_B1_RECIPES_PREPARED', result)
        on_disk = json.loads((self.physical / 'new/result.json').read_bytes())
        self.assertEqual(on_disk, result)
        acceptance_fixture = load('tests/test_semantic_b1_acceptance.py').fixture()
        for role in m.ROLES:
            recipe = result['roles'][role]['recipe']
            self.assertEqual(set(recipe), set(ACCEPT.RECIPE_PARTS))
            acceptance_fixture['roles'][role]['recipe'] = recipe
            for part, binding in recipe.items():
                ACCEPT.binding(binding)
                path = self.physical / 'new' / role / (part + '.json')
                self.assertEqual(binding['sha256'], m.sha(path.read_bytes()))
                self.assertEqual(path.read_bytes(), m.encoded(json.loads(path.read_bytes())))
                if os.name != 'nt':
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        ACCEPT.validate_acceptance(acceptance_fixture)
        for path in (self.physical / 'new').rglob('*'):
            if path.is_file():
                self.assertNotIn(SENTINEL, path.read_bytes())
            elif os.name != 'nt':
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        self.assertFalse(result['startAuthorized'])
        self.assertFalse(result['acceptanceGranted'])
        before = {str(p): p.read_bytes() for p in (self.physical / 'new').rglob('*.json')}
        # A second apply cannot truncate or replace any retained output.
        parent = os.open(self.physical, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(FileExistsError):
                m.publish(self.args, plan['plan'], {}, plan['planSha256'], parent)
        finally:
            os.close(parent)
        self.assertEqual(before, {str(p): p.read_bytes() for p in (self.physical / 'new').rglob('*.json')})

    def test_apply_changed_digest_without_writes(self):
        plan = self.run_controller()
        self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, plan['planSha256']
        self.args.rootfs_parent += '/changed'
        self.assert_held('PLAN_DIGEST_MISMATCH')

    def test_request_digest_mismatches_adapter_and_labelled_southbound(self):
        self.requests['adapter']['WorkingDir'] = '/changed'
        self.assert_held('ADAPTER_REQUEST_DIGEST_MISMATCH')
        self.requests['adapter']['WorkingDir'] = '/app'
        doc = json.loads(self.files[str(self.args.recreation_receipt)])
        doc['newRequestSha256'] = m.sha(r.canonical(doc['plan']['newSouthboundRequest']))
        raw = m.encoded(doc)
        self.files[str(self.args.recreation_receipt)] = raw
        self.args.recreation_receipt_sha256 = m.sha(raw)
        self.assert_held('SOUTHBOUND_REQUEST_DIGEST_MISMATCH')

    def test_inspect_hostconfig_and_process_and_mac_fail_closed(self):
        original = copy.deepcopy(self.docs[CID['southbound']])
        for area, key, value, code in (
            ('Config', 'Entrypoint', ['/docker-entrypoint.sh'], 'CANDIDATE_PROCESS_CONFIGURATION_CHANGED'),
            ('HostConfig', 'MemorySwap', -1, 'CANDIDATE_FULL_HOSTCONFIG_CHANGED'),
            ('Config', 'MacAddress', None, 'CONFIG_LEGACY_MAC_PROFILE_UNPROVEN'),
            ('HostConfig', 'OomKillDisable', None, 'CANDIDATE_FULL_HOSTCONFIG_CHANGED')):
            self.docs[CID['southbound']] = copy.deepcopy(original)
            self.docs[CID['southbound']][area][key] = value
            self.assert_held(code)

    def test_a2_pins_transactions_and_receipt_root_binding(self):
        self.args.a2_successors_sha256 = '0' * 64
        self.assert_held('A2_SUCCESSORS_HASH_MISMATCH')
        self.update_a2()
        self.successors['transactions'][CID['southbound']] = '3' * 32
        self.update_a2()
        self.assert_held('A2_SUCCESSOR_ID_OR_TRANSACTION_MISMATCH')

    def test_recreation_transaction_and_tmpfs_drift(self):
        self.args.southbound_transaction = '3' * 32
        self.successors['transactions'][CID['southbound']] = '3' * 32
        self.successors['containers'][1]['transaction'] = '3' * 32
        self.update_a2()
        self.assert_held('RECREATION_RECEIPT_MISMATCH')
        self.args.southbound_transaction = TX['southbound']
        self.successors['transactions'][CID['southbound']] = TX['southbound']
        self.successors['containers'][1]['transaction'] = TX['southbound']
        self.deps.baselines['southbound']['launch']['manifest']['tmpfs'] = {'/changed': 'rw'}
        self.update_a2()
        self.assert_held('SOUTHBOUND_TMPFS_BASELINE_MISMATCH')

    def test_second_compile_drift_without_writes_and_redacted_errors(self):
        original = m.compile_roles
        calls = []
        def drift(*args):
            value = original(*args)
            calls.append(1)
            if len(calls) == 2:
                value['adapter']['policy']['startup']['cwd'] = '/changed'
            return value
        with patch.object(m, 'compile_roles', side_effect=drift):
            self.assert_held('RECIPE_NOT_DETERMINISTIC_OR_INPUT_CHANGED')
        with patch.object(m, 'observe', side_effect=ValueError(SENTINEL.decode())):
            self.assert_held('REDACTED_INPUT_OR_IO_FAILURE')

    def test_hmac_sentinel_absent_from_stdout_plan_and_every_file(self):
        # Exercise the actual mutable-buffer source hasher on synthetic bytes.
        original_hasher = self.hasher.side_effect
        custody = CustodyTests(methodName='test_hmac_returns_only_hash')
        custody.setUp()
        self.addCleanup(custody.doCleanups)
        def source(mount, uid, gid):
            if mount['Source'] != str(r.HMAC_SOURCE):
                return original_hasher(mount, uid, gid)
            result = custody.binding()
            return result | {'source': mount['Source'], 'target': mount['Target']}
        self.hasher.side_effect = source
        captured = io.StringIO()
        with redirect_stdout(captured), patch.object(m, 'arguments', return_value=self.args), \
                patch.object(m, 'helpers', return_value=self.deps), \
                patch.object(os, 'geteuid', return_value=0, create=True), \
                patch.object(os, 'getegid', return_value=0, create=True):
            self.assertEqual(m.main(), 0)
            plan = json.loads(captured.getvalue())
            self.args.plan, self.args.apply, self.args.plan_sha256 = False, True, plan['planSha256']
            self.assertEqual(m.main(), 0)
        self.assertNotIn(SENTINEL.decode(), captured.getvalue())
        self.assertEqual(json.loads((self.physical / 'new/result.json').read_bytes())['status'],
                         'SEMANTIC_PROVIDER_B1_RECIPES_PREPARED')
        for path in (self.physical / 'new').rglob('*.json'):
            self.assertNotIn(SENTINEL, path.read_bytes())

    def test_pinned_modules_load_without_main_and_reject_changed_hash(self):
        deps = m.helpers()
        self.assertEqual(deps.recreation.OWNER_LABEL, r.OWNER_LABEL)
        self.assertEqual(deps.baselines, baseline)
        name = 'scripts/recreate-southbound-successor-20261113.py'
        with patch.dict(m.PINS, {name: '0' * 64}):
            with self.assertRaisesRegex(m.Held, '^INPUT_SHA256_MISMATCH$'):
                m.helpers()

    def test_cli_requires_every_binding_and_context_and_apply_digest(self):
        argv = ['--plan']
        for key, value in vars(self.args).items():
            if key not in {'plan', 'apply', 'plan_sha256'}:
                argv.extend(['--' + key.replace('_', '-'), str(value)])
        def parse(values):
            with patch.object(m, 'Path', PurePosixPath):
                return m.arguments(values)
        parsed = parse(argv)
        self.assertEqual(parsed.adapter_id, self.args.adapter_id)
        for missing in ('--adapter-id', '--a2-plan-sha256', '--bundle-parent', '--docker-socket'):
            index = argv.index(missing)
            with redirect_stdout(io.StringIO()), patch.object(sys, 'stderr', io.StringIO()), self.assertRaises(SystemExit):
                parse(argv[:index] + argv[index + 2:])
        with patch.object(sys, 'stderr', io.StringIO()), self.assertRaises(SystemExit):
            parse(['--apply'] + argv[1:])


if __name__ == '__main__':
    unittest.main()
