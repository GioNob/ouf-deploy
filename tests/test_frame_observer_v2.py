"""Portable sealed-module review; the real PID/mount subprocess runs in R3 CI."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMPILER = ROOT / 'tools/semantic_frame_compiler'


def closure(filename):
    tree = ast.parse((COMPILER / filename).read_bytes())
    return {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
            if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
            and n.targets[0].id in ('SOURCES', 'SOURCE_HASHES', 'SCHEMA_BYTES')}


def reviewer(filename='frame-observer-v2.py'):
    embedded = closure(filename)
    module = types.ModuleType('isolated_test_oci_reviewer')
    exec(compile(embedded['SOURCES']['review_semantic_oci_policy'], '<sealed-reviewer>', 'exec'), module.__dict__)
    return module, module.schema_from_source_closure(embedded['SCHEMA_BYTES'])


def policy(role='southbound'):
    relative = ('tools/semantic_successor_recipes/containerd-overlayfs-southbound-tmpfs.json'
                if role == 'southbound' else 'tools/semantic_frame_compiler/containerd-overlayfs-adapter.json')
    fixture = json.loads((ROOT / relative).read_bytes())
    spec = importlib.util.spec_from_file_location('observer_v2_policy_compiler', COMPILER / 'compile_creation_frame_policy.py')
    compiler = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    cid = 'a' * 64
    context = dict(schema='ouf.semantic-docker-frame-context.v1', containerId=cid,
        bundleParent='/run/containerd/io.containerd.runtime.v2.task/moby',
        metadataParent='/var/lib/docker/containers', networkNamespaceParent='/var/run/docker/netns',
        networkNamespaceName=None, cgroupDriver='systemd', rootfsPath='/var/lib/docker/rootfs/overlayfs/' + cid,
        storageParent='/var/lib/docker')
    return compiler.compile_policy(fixture['template'], fixture['launch'], context)


class ObserverV2Tests(unittest.TestCase):
    def setUp(self):
        self.module, self.schema = reviewer()
        self.policy = policy()
        self.oci = self.policy['expectedOci']
        self.spec = self.policy['manifest']
        self.target, self.options = next(iter(self.spec['tmpfs'].items()))

    def review(self, actual=None):
        return self.module.configured_profile(self.oci if actual is None else actual, self.oci, self.spec,
                                             self.policy['startup'], self.policy['approvedHooks'], self.schema)

    def mount(self):
        return next(m for m in self.oci['mounts'] if m['destination'] == self.target)

    def deny(self, suffix):
        with self.assertRaisesRegex(self.module.Denied, '^OCI_' + suffix + '$'):
            self.review()

    def test_realistic_docker_29_southbound_order_and_no_authority(self):
        self.assertEqual(self.mount()['options'], ['rprivate'] + self.options.split(','))
        result = self.review()
        self.assertTrue(result['configuredPolicyConforms'])
        for key in ('acceptanceGranted', 'startAuthorized', 'kernelEnforcementObserved', 'rootfsSealProven'):
            self.assertIs(result[key], False)

    def test_adapter_absent_or_empty_tmpfs_is_identical_to_v1(self):
        old, schema = reviewer('frame-observer.py')
        p = policy('adapter')
        for extra in ({}, {'tmpfs': {}}):
            manifest = {**p['manifest'], **extra}
            args = (p['expectedOci'], p['expectedOci'], manifest, p['startup'], p['approvedHooks'], schema)
            self.assertEqual(self.module.configured_profile(*args), old.configured_profile(*args))

    def test_undeclared_tmpfs_is_still_denied(self):
        del self.spec['tmpfs']
        self.deny('UNDECLARED_MOUNT_DENIED')

    def test_missing_or_duplicate_declared_tmpfs_is_drift(self):
        original = copy.deepcopy(self.oci['mounts'])
        mount = copy.deepcopy(self.mount())
        for mounts in ([m for m in original if m['destination'] != self.target], original + [mount]):
            with self.subTest(mountCount=len(mounts)):
                self.oci['mounts'] = mounts
                self.deny('DECLARED_TMPFS_DRIFT')

    def test_type_source_mappings_options_and_size_drift(self):
        original = copy.deepcopy(self.mount())
        for change in ({'type': 'bind'}, {'source': 'other'}, {'uidMappings': []}, {'gidMappings': []},
                       {'uidMappings': [{'containerID': 1, 'hostID': 1, 'size': 1}]},
                       {'options': ['rprivate'] + self.options.replace('size=1m', 'size=2m').split(',')},
                       {'options': ['rprivate'] + self.options.replace('rw,', 'ro,').split(',')},
                       {'options': ['rprivate'] + list(reversed(self.options.split(',')))},
                       {'options': original['options'] + ['rw']}):
            with self.subTest(change=change):
                mount = self.mount()
                mount.clear(); mount.update(copy.deepcopy(original)); mount.update(change)
                self.deny('DECLARED_TMPFS_DRIFT')

    def test_hardening_on_both_declared_and_actual_options(self):
        variants = [self.options + ',' + v for v in ('exec', 'suid', 'dev', 'shared', 'rshared', 'slave', 'rslave')]
        variants += [self.options.replace(v + ',', '') for v in ('noexec', 'nosuid', 'nodev')]
        variants += [self.options.replace(old, new) for old, new in (
            ('uid=636', 'uid=0'), ('gid=636', 'gid=0'), ('mode=0700', 'mode=0750'),
            ('mode=0700', 'mode=0701'), ('mode=0700', 'mode=4700'), ('size=1m', 'size=65m'),
            ('size=1m', 'size=67108865'), ('size=1m', 'size=0'), ('size=1m', 'size=50%'),
            ('uid=636,', ''), ('size=1m', 'size=bad'), ('gid=636', 'gid=4294967296'),
            ('size=1m', 'size=' + '9' * 5000), ('uid=636', 'uid=' + '9' * 5000))]
        for options in variants:
            for change_declaration, change_actual in ((False, True), (True, True), (True, False)):
                with self.subTest(options=options, declaration=change_declaration, actual=change_actual):
                    self.spec['tmpfs'][self.target] = options if change_declaration else self.options
                    self.mount()['options'] = ['rprivate'] + (options if change_actual else self.options).split(',')
                    self.deny('DECLARED_TMPFS_HARDENING_REQUIRED')

    def test_size_bound_is_bytes_with_binary_suffix(self):
        for size in ('67108864', '65536k', '64m', '64M'):
            self.spec['tmpfs'][self.target] = self.options.replace('size=1m', 'size=' + size)
            self.mount()['options'] = ['rprivate'] + self.spec['tmpfs'][self.target].split(',')
            self.assertTrue(self.review()['configuredPolicyConforms'])

    def test_bind_and_kernel_overlap_in_both_directions(self):
        bind = self.spec['mounts'][0]['target']
        for target in (bind, bind + '/child', str(Path(bind).as_posix()).rsplit('/', 1)[0] or '/',
                       '/proc', '/proc/child', '/sys/fs/cgroup/child', '/etc', '/'):
            with self.subTest(target=target):
                self.spec['tmpfs'] = {target: self.options}
                self.deny('DECLARED_TMPFS_OVERLAP')

    def test_prefix_without_path_overlap_is_allowed(self):
        self.spec['tmpfs'] = {'/proc-scratch': self.options}
        self.mount()['destination'] = '/proc-scratch'
        self.assertTrue(self.review()['configuredPolicyConforms'])

    def test_exact_signed_oci_check_still_precedes_tmpfs_review(self):
        actual = copy.deepcopy(self.oci)
        actual['mounts'][-1]['options'] = ['rw']
        with self.assertRaisesRegex(self.module.Denied, '^OCI_EXACT_POLICY_DRIFT$'):
            self.review(actual)

    def test_source_hashes_schema_other_modules_and_wrapper_are_retained(self):
        old, new = closure('frame-observer.py'), closure('frame-observer-v2.py')
        self.assertEqual(set(old['SOURCES']), set(new['SOURCES']))
        for name, source in new['SOURCES'].items():
            self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), new['SOURCE_HASHES'][name])
            if name != 'review_semantic_oci_policy':
                self.assertEqual(source.encode(), old['SOURCES'][name].encode())
        self.assertNotEqual(old['SOURCES']['review_semantic_oci_policy'], new['SOURCES']['review_semantic_oci_policy'])
        self.assertEqual(new['SCHEMA_BYTES'], old['SCHEMA_BYTES'])
        self.assertEqual(hashlib.sha256(new['SCHEMA_BYTES']).hexdigest(), new['SOURCE_HASHES']['semantic_oci_shape_schema.json'])
        def wrapper(filename):
            tree = ast.parse((COMPILER / filename).read_bytes())
            tree.body = [n for n in tree.body if not (isinstance(n, ast.Assign)
                and isinstance(n.targets[0], ast.Name) and n.targets[0].id in ('SOURCES', 'SOURCE_HASHES'))]
            return ast.dump(tree)
        self.assertEqual(wrapper('frame-observer.py'), wrapper('frame-observer-v2.py'))
        result = subprocess.run([sys.executable, '-I', '-B', str(COMPILER / 'build_frame_observer_v2.py'), '--check'],
                                capture_output=True, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_real_subprocess_closed_redacted_denial_matches_v1(self):
        # No synthetic /proc or mocked custody. Positive real-PID coverage is
        # gated by OUF_R3_COHORT_NATIVE, including Linux root -I -B invocation.
        results = [subprocess.run([sys.executable, '-I', '-B', str(COMPILER / name),
                                  '--configuration', '/nonexistent/PRIVATE_SENTINEL'],
                                 input=b'{}', capture_output=True, timeout=10)
                   for name in ('frame-observer.py', 'frame-observer-v2.py')]
        for result in results:
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr.strip(), b'SEMANTIC_CREATION_FRAME=DENIED NO_SECRETS_PRINTED=true')


if __name__ == '__main__':
    unittest.main()
