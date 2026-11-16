"""D-042 portable proofs and opt-in Docker29/overlay/runc/uid qualification.

OUF_B1_ROOTFS_V3_NATIVE=1 requires native Linux root and python -I -B.
"""
from contextlib import contextmanager, redirect_stderr
import ast
import copy
import errno
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
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
import test_prepare_semantic_provider_b1_rootfs_v2 as V2
from tools.semantic_b1_acceptance import acceptance as B
from tools.semantic_b1b2_authority import authority as A
C = V2.module('rootfs_v3', 'scripts/prepare-semantic-provider-b1-rootfs-v3.py')
NATIVE = os.environ.get('OUF_B1_ROOTFS_V3_NATIVE') == '1'
if NATIVE and (sys.platform != 'linux' or os.geteuid() != 0 or os.getegid() != 0
               or not sys.flags.isolated or not sys.dont_write_bytecode):
    raise RuntimeError('OUF_B1_ROOTFS_V3_NATIVE requires Linux root:root and python -I -B')


class Fixture(V2.Fixture):
    def __init__(self):
        with patch.object(V2, 'C', C):
            super().__init__()
        self.args.date = '20261116'
        self.docker.states = lambda: {v['Id']: dict(Status='exited', Pid=0, Running=False,
            Paused=False, Restarting=False, Dead=False) for v in self.baselines.values()}

    @contextmanager
    def portable(self):
        def projected(sealer, path, limits, rows):
            records = copy.deepcopy(self.records(path))
            for row in rows:
                records[row['path']]['mode'] = row['expectedMode']
            return V2.seal(records)
        with patch.object(V2, 'C', C), super().portable(), patch.object(C, 'projected_entries', projected):
            yield

    def plan(self):
        return C.observe(self.args, self.docker)


class DifferenceTests(unittest.TestCase):
    def setUp(self):
        self.image, self.actual, self.upper, self.mounts = V2.trees()

    def correction(self):
        return C.correction(self.image, self.actual, self.upper, self.mounts, lambda _: 'file')

    def test_0700_projects_only_ancestor_to_0711_and_0711_is_idempotent(self):
        rows, differences = self.correction()
        self.assertEqual(rows, [dict(path='run/provider', currentMode=0o700, expectedMode=0o711)])
        after = {d['path']: d['after'] for d in differences}
        self.assertEqual(after['run/provider']['mode'], 0o711)
        self.assertEqual(after['run/provider/key']['mode'], 0o600)
        self.assertEqual(after['run/provider/tmp']['mode'], 0o700)
        self.assertEqual(after['run']['mode'], 0o755)
        self.actual['run/provider']['mode'] = self.upper['run/provider']['mode'] = 0o711
        again, final = self.correction()
        self.assertEqual(again[0]['currentMode'], 0o711)
        self.assertEqual(differences, final)
        self.assertEqual(final, C.compare_entries(self.image, self.actual, self.upper, self.mounts, lambda _: 'file'))

    def test_other_mode_owner_gid_xattrs_and_symlink_denied(self):
        for key, value, reason in [('mode', 0o755, 'MODE'), ('uid', 10006, 'OWNER'),
                ('gid', 636, 'OWNER'), ('xattrs', {'trusted.overlay.opaque': '79'}, 'XATTR'),
                ('kind', 'symlink', 'DIRECTORY_REQUIRED')]:
            with self.subTest(key=key):
                self.setUp()
                self.actual['run/provider'][key] = self.upper['run/provider'][key] = value
                code = 'ANCESTOR_' + reason + ('_DENIED' if reason != 'DIRECTORY_REQUIRED' else '')
                with self.assertRaisesRegex(C.Denied, code): self.correction()

    def test_undeclared_child_and_target_directory_0711_denied(self):
        self.actual['run/provider/extra'] = self.upper['run/provider/extra'] = V2.entry('run/provider/extra', 'file')
        with self.assertRaisesRegex(C.Denied, 'POST_CREATE_UNDECLARED_PATH'): self.correction()
        self.setUp()
        self.actual['run/provider/tmp']['mode'] = self.upper['run/provider/tmp']['mode'] = 0o711
        with self.assertRaisesRegex(C.Denied, 'POST_CREATE_MODE_DENIED'): self.correction()

    def test_historical_v2_still_requires_0700(self):
        V2.C.compare_entries(self.image, self.actual, self.upper, self.mounts, lambda _: 'file')
        self.actual['run/provider']['mode'] = self.upper['run/provider']['mode'] = 0o711
        with self.assertRaisesRegex(V2.C.Denied, 'POST_CREATE_MODE_DENIED'):
            V2.C.compare_entries(self.image, self.actual, self.upper, self.mounts, lambda _: 'file')


class PlanApplyTests(unittest.TestCase):
    def test_plan_deterministic_readonly_current_expected_seals_and_rule(self):
        f = Fixture()
        with f.portable(), patch.object(C.os, 'open', side_effect=AssertionError('plan write/open')), \
             patch.object(C.os, 'chmod', side_effect=AssertionError('plan chmod')), \
             patch.object(C, 'write_once', side_effect=AssertionError('plan write')):
            plan = f.plan()
            self.assertEqual(plan, f.plan())
        c = plan['roles']['adapter']['comparison']
        self.assertEqual(c['currentSeal'], V2.seal(f.actual))
        self.assertNotEqual(c['currentSeal'], c['expectedSeal'])
        self.assertEqual(c['effectiveSeal'], c['expectedSeal'])
        self.assertEqual(plan['rule'], 'D-042')
        self.assertTrue(plan['output'].endswith('20261116-mountpoint-0711'))
        self.assertEqual(set(plan['inputs']), set(f.files))
        self.assertTrue(plan['doNotRerunApply'])

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

    def test_projection_uses_private_encoder_and_leaves_historical_sealer_unchanged(self):
        original = C.canonical
        scope = {'encoded': original}
        exec("def sealer(path, limits, budget):\n return encoded({'path':'run/provider','mode':448})", scope)
        sealer = scope['sealer']
        rows = [dict(path='run/provider', currentMode=0o700, expectedMode=0o711)]
        actual = sealer(None, None, None)
        projected = C.projected_entries(sealer, None, None, rows)
        self.assertEqual(json.loads(projected)['mode'], 0o711)
        self.assertEqual(json.loads(actual)['mode'], 0o700)
        self.assertIs(sealer.__globals__['encoded'], original)
        self.assertEqual(sealer(None, None, None), actual)

    def test_plan_denial_is_before_writes_for_either_role(self):
        f = Fixture(); f.actual['run/provider/extra'] = f.upper['run/provider/extra'] = V2.entry('run/provider/extra', 'file')
        with f.portable(), patch.object(C, 'write_once') as write, \
             patch.object(C.os, 'fchmod', create=True) as chmod, \
             self.assertRaisesRegex(C.Denied, 'POST_CREATE_UNDECLARED_PATH'):
            f.plan()
        write.assert_not_called(); chmod.assert_not_called()

    def test_running_container_denied_before_correction(self):
        f = Fixture(); states = f.docker.states()
        states[f.baselines['southbound']['Id']].update(Status='running', Running=True, Pid=42)
        f.docker.states = lambda: states
        with f.portable(), self.assertRaisesRegex(C.Denied, 'STOPPED_EXACT_CANDIDATE_REQUIRED'):
            f.plan()

    def test_stopped_selector_accepts_exited_and_preserves_full_frame(self):
        args = types.SimpleNamespace(docker_socket='unix:///fixture', docker='/docker', docker_sha256='a'*64,
            output_root=PurePosixPath('/fixture'), output_name='out')
        docker = C.Docker(args)
        row = dict(Id='1'*64, Image='sha256:'+'2'*64, Config={'MacAddress':'02:00:00:00:00:01'},
            State=dict(Status='exited', Pid=0, Running=False, Paused=False, Restarting=False, Dead=False))
        spec = dict(container_id=row['Id'], image_id=row['Image'])
        with patch.object(docker, 'read', return_value=C.canonical([row])):
            self.assertEqual(docker.selected(spec), row)
        for change in [dict(Pid=1), dict(Running=True), dict(Paused=True), dict(Status='restarting'), dict(Dead=True)]:
            bad = copy.deepcopy(row); bad['State'].update(change)
            with patch.object(docker, 'read', return_value=C.canonical([bad])), \
                 self.assertRaisesRegex(C.Denied, 'STOPPED_EXACT_CANDIDATE_REQUIRED'):
                docker.selected(spec)

    def apply_fixture(self, initial=0o700, drift=False):
        f = Fixture()
        f.actual['run/provider']['mode'] = f.upper['run/provider']['mode'] = initial
        with f.portable(): plan = f.plan()
        @contextmanager
        def held(plan):
            yield [(role, row, role, None) for role in C.ROLES
                   for row in plan['roles'][role]['comparison']['ancestors']]
        calls = []
        def chmod(fd, mode):
            calls.append((fd, mode))
            f.actual['run/provider']['mode'] = f.upper['run/provider']['mode'] = mode
        real_observe = C.observe
        def observe(*a, **kw):
            with f.portable():
                final = real_observe(f.args, f.docker, allow_output=True)
            final['output'] = plan['output']
            if drift and calls: final['candidateSha256'] = {}
            return final
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(C.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
             patch.object(C.os, 'fchmod', side_effect=chmod, create=True), \
             patch.object(C.os, 'fstat', return_value=types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o711)), \
             patch.object(C, 'correction_fds', held), patch.object(C, 'observe', side_effect=observe):
            plan['output'] = str(Path(tmp) / 'mountpoint-0711')
            f.args.plan_sha256 = C.sha(C.canonical(plan)); progress = {'created':False}
            if drift:
                with self.assertRaisesRegex(C.Denied, 'POST_CHMOD_PLAN_MISMATCH'):
                    C.apply_plan(f.args, f.docker, plan, progress)
                self.assertFalse((Path(plan['output']) / 'result.json').exists())
                self.assertTrue((Path(plan['output']) / 'chmod-001.json').exists())
                return
            result = C.apply_plan(f.args, f.docker, plan, progress)
            self.assertEqual(result['rule'], 'D-042')
            self.assertEqual(len(result['chmods']), 2 if initial == 0o700 else 0)
            self.assertEqual(len(calls), len(result['chmods']))
            self.assertTrue(result['doNotRerunApply'])
            self.assertEqual(result['status'], C.PREPARED)
            self.assertEqual(json.loads((Path(plan['output']) / 'result.json').read_bytes()), result)
            for role in C.ROLES:
                c = json.loads((Path(plan['output']) / (role+'-comparison.json')).read_bytes())
                self.assertEqual(c['currentSeal'], c['expectedSeal'])
                self.assertEqual(c['nodeRootfsSeal'], result['roles'][role]['effectiveSeal'])
            with self.assertRaises(FileExistsError): C.apply_plan(f.args, f.docker, plan, {})
            f.args.plan_sha256 = '0'*64
            with self.assertRaisesRegex(C.Denied, 'PLAN_DIGEST_CHANGED'): C.apply_plan(f.args, f.docker, plan, {})

    def test_apply_chmod_seal_and_exclusive_evidence(self): self.apply_fixture()
    def test_apply_already_0711_does_not_chmod(self): self.apply_fixture(0o711)
    def test_after_chmod_drift_retains_partial_without_result(self): self.apply_fixture(drift=True)

    def test_embedded_runtime_and_uid_probe_compile(self):
        tree = ast.parse(Path(__file__).read_bytes())
        native = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'native_child')
        wrapper = next(n.value.value for n in ast.walk(native) if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'wrapper' for t in n.targets))
        runtime = ast.parse(wrapper)
        probe = next(n.value.value for n in ast.walk(runtime) if isinstance(n, ast.Assign)
                     and any(isinstance(t, ast.Name) and t.id == 'probe' for t in n.targets))
        compile(runtime, '<real-runc-capture>', 'exec')
        compile(probe, '<nonroot-open-probe>', 'exec')

    def test_fd_preflight_all_roles_before_first_chmod(self):
        f = Fixture()
        with f.portable(): plan = f.plan()
        @contextmanager
        def descriptor(path): yield str(path)
        seen = []
        def check(fd, row, differences):
            seen.append(fd)
            if 'southbound' in fd: raise C.Denied('ANCESTOR_OWNER_DENIED')
            return 1
        with patch.object(C, 'directory_fd', descriptor), patch.object(C, 'check_ancestor_fd', check), \
             patch.object(C.os, 'fchmod', create=True) as chmod:
            with self.assertRaisesRegex(C.Denied, 'ANCESTOR_OWNER_DENIED'):
                with C.correction_fds(plan): self.fail('not all roles validated')
        self.assertEqual(len(seen), 2); chmod.assert_not_called()

    def test_held_descriptors_accept_stable_paths_and_deny_replacement(self):
        f = Fixture()
        with f.portable(): plan = f.plan()
        for replaced in (False, True):
            seen = {}; stats = {}; serial = []
            @contextmanager
            def descriptor(path):
                path = str(path); seen[path] = seen.get(path, 0) + 1
                fd = len(serial); serial.append(fd)
                inode = 100 + ('southbound' in path)
                if replaced and seen[path] > 1: inode += 50
                stats[fd] = types.SimpleNamespace(st_dev=1, st_ino=inode, st_uid=0, st_gid=0,
                    st_mode=stat.S_IFDIR|0o700, st_nlink=3, st_size=4096, st_mtime_ns=1, st_ctime_ns=1)
                yield fd
            with patch.object(C, 'directory_fd', descriptor), patch.object(C.os, 'fstat', side_effect=stats.__getitem__), \
                 patch.object(C.os, 'listxattr', return_value=[], create=True), \
                 patch.object(C.os, 'listdir', return_value=['key','tmp']):
                if replaced:
                    with self.assertRaisesRegex(C.Denied, 'ANCESTOR_CHANGED_BEFORE_CHMOD'):
                        with C.correction_fds(plan): self.fail('replaced inode admitted')
                else:
                    with C.correction_fds(plan) as held:
                        self.assertEqual([r for r, *_ in held], list(C.ROLES))
                    self.assertEqual(len(serial), 4)

    def test_fd_open_rejects_symlink_and_never_follows(self):
        flags = 0x10000 | 0x20000
        with patch.object(C, 'Path', PurePosixPath), \
             patch.object(C.os, 'O_DIRECTORY', 0x10000, create=True), \
             patch.object(C.os, 'O_NOFOLLOW', 0x20000, create=True), \
             patch.object(C.os, 'open', side_effect=[10, 11, OSError(errno.ELOOP, 'symlink')]) as opened, \
             patch.object(C.os, 'close') as closed:
            with self.assertRaisesRegex(C.Denied, 'ANCESTOR_NOFOLLOW_DIRECTORY_REQUIRED'):
                with C.directory_fd(PurePosixPath('/upper/link')): self.fail('followed symlink')
            self.assertTrue(all(call.args[1] & flags == flags for call in opened.call_args_list))
            self.assertEqual(closed.call_args_list, [unittest.mock.call(10), unittest.mock.call(11)])

    def test_fd_metadata_children_and_xattrs_checked(self):
        row = dict(path='run/provider', currentMode=0o700, expectedMode=0o711)
        differences = [dict(path='run/provider/key')]
        good = dict(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
        for info, attrs, names, reason in [
                (dict(good, st_uid=1), [], ['key'], 'OWNER'),
                (dict(good, st_gid=1), [], ['key'], 'OWNER'),
                (dict(good, st_mode=stat.S_IFDIR | 0o755), [], ['key'], 'MODE'),
                (good, ['user.x'], ['key'], 'XATTR'),
                (good, [], ['key','extra'], 'UNDECLARED_CHILD')]:
            with patch.object(C.os, 'fstat', return_value=types.SimpleNamespace(**info)), \
                 patch.object(C.os, 'listxattr', return_value=attrs, create=True), \
                 patch.object(C.os, 'listdir', return_value=names), \
                 self.assertRaisesRegex(C.Denied, 'ANCESTOR_'+reason):
                C.check_ancestor_fd(10, row, differences)


class AcceptanceTests(unittest.TestCase):
    def test_unmodified_v51_issuer_plans_generation_five_from_actual_v3_result(self):
        f = Fixture()
        with f.portable(): plan = f.plan()
        old = V2.legacy.Fixture()
        # Keep all A2/authority/recipe inputs from the existing issuer fixture.
        plan['aSuccessors'] = old.preparation['files']['successors']
        comparisons = {}
        for role in C.ROLES:
            plan['roles'][role].update(containerId=old.cid[role], imageId=old.image[role])
            for key in ('offlineImageReceipt', 'offlineDockerReceipt'):
                plan['roles'][role][key] = old.rootfs['roles'][role][key]
            comparisons[role] = old.put(old.root / ('post-create-' + role + '.json'), plan['roles'][role]['comparison'])
        result = C.make_result(plan, comparisons, [])
        old.update('rootfs_result', result)
        old.args.generation = 5; old.args.mandate_root = '/synthetic-mandates'
        old.args.closure_file = []
        for name in sorted(V2.ISSUER.CLOSURE):
            b = old.put(old.delivery / name, (ROOT / name).read_bytes())
            old.args.closure_file.append(name + '=' + b['sha256'])
        class Reader(V2.ISSUER.Reader):
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
        mandates = V2.ISSUER.V.load_mandates((ROOT / V2.ISSUER.MANDATES).read_bytes(),
                    C.sha((ROOT / V2.ISSUER.MANDATES).read_bytes()), ROOT / V2.ISSUER.MANDATES)
        with old.portable(), patch.object(V2.ISSUER, 'ROOT', old.delivery), patch.object(V2.ISSUER, 'Reader', Reader), \
             patch.object(V2.ISSUER.V, 'load_mandates', return_value=mandates), \
             patch.object(mandates, 'MandateLedger', Ledger), patch.object(mandates, 'MandateAuthenticator'), \
             patch.object(V2.ISSUER, 'check_openssl'):
            observed, raw, expected, *_ = V2.ISSUER.observe(old.args)
        accepted = B.decode_manifest(raw)
        self.assertEqual(accepted['generation'], 5)
        self.assertEqual(observed['privateKeysRead'], 0)
        for role in C.ROLES:
            self.assertEqual(accepted['roles'][role]['rootfs'], {k: result['roles'][role][k] for k in
                ('effectiveSeal', 'comparison', 'offlineImageReceipt', 'offlineDockerReceipt')})


class CompositionTests(unittest.TestCase):
    def test_v10_uses_v3_result_and_generation_five_with_unchanged_composer(self):
        import test_semantic_provider_r3_compose as r3
        f = Fixture()
        with f.portable(): plan = f.plan()
        inputs = r3.fixture(10)
        previous = r3.C.compose(inputs, 9, sequence=9, supersedes='a'*64)
        accepted = B.decode_manifest(inputs['files']['acceptance'])
        plan['aSuccessors'] = accepted['preparationA']['files']['successors']
        comparisons = {}
        for role in C.ROLES:
            row = accepted['roles'][role]
            plan['roles'][role].update(containerId=row['containerId'], imageId=row['imageId'])
            for key in ('offlineImageReceipt', 'offlineDockerReceipt'):
                plan['roles'][role][key] = row['rootfs'][key]
            comparisons[role] = row['rootfs']['comparison']
            row['rootfs']['effectiveSeal'] = plan['roles'][role]['comparison']['expectedSeal']
        result = C.make_result(plan, comparisons, [])
        accepted['generation'] = 5
        inputs['files']['rootfs'] = C.canonical(result)
        inputs['files']['acceptance'] = B.build_acceptance(**accepted)
        composed = r3.C.compose(inputs, 10, sequence=10, supersedes=r3.A.sha(previous['authorization']))
        for role in C.ROLES:
            path = 'versions/10/documents/'+role+'/rootfs-seal.json'
            self.assertEqual(json.loads(composed['documents'][path]), result['roles'][role]['effectiveSeal'])
            self.assertEqual(composed['audit'][role]['rootfsResultSha256'], C.sha(inputs['files']['rootfs']))
        result['roles']['adapter']['effectiveSeal'] = V2.seal(f.image)
        inputs['files']['rootfs'] = C.canonical(result)
        with self.assertRaisesRegex(r3.A.OperationDenied, 'A2_ACCEPTANCE_ROLE_DRIFT'):
            r3.C.compose(inputs, 10, sequence=10, supersedes=r3.A.sha(previous['authorization']))


class RunbookTests(unittest.TestCase):
    def test_b1_zero_pin_and_delivery_hashes_match_lf_source(self):
        text = (ROOT / 'ops/vps/b1-rootfs-v3.sh').read_text()
        # Zero before review (D-001), then the reviewed commit that serves these blobs.
        self.assertRegex(text, r'(?m)^C=[0-9a-f]{40}$')
        deliveries = re.findall(r'^  fetch (\S+) ([0-9a-f]{64})$', text, re.M)
        self.assertEqual(len(deliveries), 6)
        for path, digest in deliveries:
            self.assertEqual(C.sha((ROOT/path).read_bytes().replace(b'\r\n',b'\n')), digest, path)
        self.assertIn('--date 20261116', text)
        self.assertIn('PREV_SHA=6f42e319a8c9ba3fe1385b6b2ea814aa40df77ce814b3b4ae60c6afb430905f9', text)
        self.assertNotIn('prepare-semantic-provider-b1-rootfs-v2.py', text)

    def test_g5_changes_only_rootfs_generation_and_delivery_names(self):
        text = (ROOT / 'ops/vps/acceptance-v51-g5.sh').read_text()
        self.assertIn('--generation 5', text)
        self.assertIn('semantic-provider-b1-rootfs-20261116-mountpoint-0711/result.json', text)
        self.assertIn('$rootfs_sha != 6f42e319a8c9ba3fe1385b6b2ea814aa40df77ce814b3b4ae60c6afb430905f9', text)
        old = (ROOT / 'ops/vps/acceptance-v51-g4.sh').read_text()
        # Operational bindings and authority remain the same.
        self.assertEqual(re.findall(r'^([A-Z][A-Z0-9_]*=[0-9a-f]+)$', text, re.M),
                         re.findall(r'^([A-Z][A-Z0-9_]*=[0-9a-f]+)$', old, re.M))


@unittest.skipUnless(NATIVE, 'set OUF_B1_ROOTFS_V3_NATIVE=1 on native Linux root')
class NativeTests(unittest.TestCase):
    def test_real_docker_create_overlay_and_node_observation_in_private_namespace(self):
        for name in ('docker', 'dockerd', 'runc', 'mount', 'umount', 'unshare', 'ip', 'nsenter', 'sleep', 'ldd'):
            self.assertIsNotNone(shutil.which(name), name)
        # Like the VPS and the R3 cohort fixture: host mount/net/PID views and the
        # host containerd, so shims and runtime see the daemon's rootfs mounts.
        result = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--native-child'],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))
        self.assertIn(b'NODE_OBSERVE_POST_CREATE_EQUAL', result.stdout)
        self.assertIn(b'UID_EACCES', result.stdout)
        self.assertIn(b'UID_READ_OK', result.stdout)
        print(result.stdout.decode(), flush=True)


def native_child():
    """Private Docker29 fixture: runc create, Node.observe, delete, then export.

    Lifecycle operations belong only to this disposable test. The tool itself
    never invokes create/start/delete. No downloads or application credentials.
    """
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='ouf-rootfs-v3-', dir='/var/lib') as tmp:
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
        wrapper = r'''
import hashlib,importlib.util,json,os,pathlib,subprocess,sys
from unittest.mock import patch
os.umask(0o077)  # like runtime v5.2 main(): runc creates mountpoints 0600/0700
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
    probe = "import errno,os,sys\nroot=os.open('/proc/'+sys.argv[1]+'/root',os.O_RDONLY|os.O_DIRECTORY)\nns=os.open('/proc/'+sys.argv[1]+'/ns/mnt',os.O_RDONLY)\nos.setns(ns,0);os.close(ns);os.fchdir(root);os.chroot('.');os.close(root);os.chdir('/')\nos.setgroups([]);os.setgid(10006);os.setuid(10006)\ntry:\n data=open('/run/provider/key','rb').read()\n assert data==b'synthetic mount payload'\n print('UID_READ_OK',flush=True)\nexcept PermissionError as error:\n assert error.errno==errno.EACCES\n print('UID_EACCES',flush=True)"
    read=subprocess.check_output([sys.executable,'-I','-B','-c',probe,str(state['pid'])]).decode().strip()
    pathlib.Path(CAPTURE).write_text(json.dumps({'oci':oci,'seal':observed['rootfsSeal'],'read':read}))
finally:
    if created: subprocess.run([RUNC,'--root',runtime_root,'delete','--force',cid],check=True)
raise SystemExit(1)
'''
        assignments = dict(RUNC=runc, CONTROLLER=str(ROOT / 'scripts/prepare-semantic-provider-b1-rootfs-v3.py'),
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
                    (image / d).chmod(0o755)  # image modes independent of runtime umask 077
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
                key = root / 'synthetic-key'; key.write_bytes(b'synthetic mount payload'); key.chmod(0o600); os.chown(key, 10006, 10006)
                cid = docker('create', '--network=none', '--runtime=reseal-fixture', '--mount',
                    'type=bind,src=' + str(key) + ',dst=/run/provider/key,readonly',
                    '--tmpfs', '/run/provider/tmp:mode=700', image_id, '/sleep', '60').stdout.decode().strip()
                assert docker('start', cid, check=False).returncode != 0
                assert capture.exists(), (root / 'daemon.log').read_text()
                observed = json.loads(capture.read_bytes())
                assert observed['oci']['root']['path'] == str(data / 'rootfs/overlayfs' / cid)
                assert observed['read'] == 'UID_EACCES', observed
                print('UID_EACCES', flush=True)
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
                            rows, differences = C.correction(expected, actual, upper, observed['oci']['mounts'], C.source_kind)
                            assert rows == [dict(path='run/provider', currentMode=0o700, expectedMode=0o711)]
                            predicted = C.projected_entries(sealer, ro, limits, rows)
                            assert actual_seal == observed['seal'] == sealer(original, limits, C.Budget())
                    finally:
                        C.run_mount(args, ['-n', str(image_view)], unmount=True)
                # As in apply_plan, change upper only after export/overlay unmount.
                state = json.loads(docker('inspect', '--format', '{{json .State}}', cid).stdout)
                C.stopped(state)
                evidence = root / 'evidence'; evidence.mkdir(mode=0o700)
                chmods = []
                with C.directory_fd(Path(snapshot['upper']) / rows[0]['path']) as fd:
                    C.check_ancestor_fd(fd, rows[0], differences)
                    C.chmod_ancestor(fd, rows[0], 'adapter', evidence, {}, chmods)
                assert len(chmods) == 1
                with C.V1.stopped_export_view((args.docker, args.docker_sha256), socket, config, cid,
                                              Path(observed['oci']['root']['path'])) as original:
                    final_seal, final = C.entries(sealer, original, limits)
                    _, final_upper = C.entries(sealer, Path(snapshot['upper']), limits)
                    C.compare_entries(expected, final, final_upper, observed['oci']['mounts'], C.source_kind)
                    assert predicted == final_seal == sealer(original, limits, C.Budget())
                    final_seal_expected = final_seal
                    done, _ = C.correction(expected, final, final_upper, observed['oci']['mounts'], C.source_kind)
                # A second application to the ancestor performs no chmod.
                with C.directory_fd(Path(snapshot['upper']) / done[0]['path']) as fd:
                    C.check_ancestor_fd(fd, done[0], differences)
                    C.chmod_ancestor(fd, done[0], 'adapter', evidence, {}, chmods)
                assert len(chmods) == 1
                # Export has unmounted; real runc create reuses persistent 0711.
                assert docker('start', cid, check=False).returncode != 0
                positive = json.loads(capture.read_bytes())
                assert positive['read'] == 'UID_READ_OK', positive
                assert positive['seal'] == final_seal_expected
                print('UID_READ_OK', flush=True)
                print('NODE_OBSERVE_POST_CREATE_EQUAL ' + json.dumps(positive['seal']), flush=True)
            finally:
                if cid is not None: docker('rm', '-f', cid, check=False)
                daemon.terminate()
                try: daemon.wait(timeout=20)
                except subprocess.TimeoutExpired: daemon.kill(); daemon.wait(timeout=5)


if __name__ == '__main__':
    if sys.argv[1:] == ['--native-child']: native_child()
    else: unittest.main()
