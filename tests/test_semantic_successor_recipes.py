"""Pure builder contract tests; these synthetic edits are not a CI baseline."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.semantic_successor_recipes.build_role_frame_template_tmpfs import build_role_template
from build_role_frame_template import build_role_template as build_historical
from compile_creation_frame_policy import Denied, compile_policy

TARGET = '/run/ouf-southbound-runtime'
OPTIONS = 'rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m'


class SouthboundTmpfsBuilderTests(unittest.TestCase):
    def setUp(self):
        # Reuse a real existing Engine shape, adding a deliberately synthetic
        # role tmpfs solely for pure ordering/validation tests. No export here.
        baseline = json.loads((ROOT / 'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes())
        self.template = baseline['template']
        self.launch = baseline['launch']
        self.user = baseline['approvedUser']
        self.launch['manifest']['tmpfs'] = {TARGET: OPTIONS}
        self.tmpfs = {'destination': TARGET, 'type': 'tmpfs', 'source': 'tmpfs',
                      'options': OPTIONS.split(',')}
        oci = self.template['expectedOci']
        defaults = [m for m in oci['mounts'] if m['type'] != 'bind']
        ordered = [m for m in oci['mounts'] if m['type'] == 'bind'] + [copy.deepcopy(self.tmpfs)]
        ordered.sort(key=lambda m: (m['destination'].count('/'), m['destination']))
        oci['mounts'] = defaults + ordered
        self.context = {'schema': 'ouf.semantic-docker-frame-context.v1', 'containerId': 'a' * 64,
                        'bundleParent': '/run/owned/bundles', 'metadataParent': '/var/lib/owned/containers',
                        'networkNamespaceParent': '/run/owned/netns', 'networkNamespaceName': None,
                        'cgroupDriver': 'systemd', 'storageParent': '/var/lib/owned',
                        'rootfsPath': '/var/lib/owned/rootfs'}

    def build(self, launch=None):
        return build_role_template(self.template, self.launch, self.launch if launch is None else launch,
                                   self.user, mount_ordering='depth-path')

    def test_only_mount_order_differs_from_historical_builder_and_inputs_are_immutable(self):
        original = copy.deepcopy((self.template, self.launch, self.user))
        result = self.build()
        self.assertEqual(result, self.template)
        for ordering in ('depth-path', 'depth-stable-user-first'):
            historical = build_historical(self.template, self.launch, self.launch, self.user,
                                          mount_ordering=ordering)
            self.assertNotEqual(historical['expectedOci']['mounts'], result['expectedOci']['mounts'])
            historical['expectedOci']['mounts'] = copy.deepcopy(result['expectedOci']['mounts'])
            self.assertEqual(historical, result)
        self.assertEqual((self.template, self.launch, self.user), original)

    def test_second_launch_multiple_binds_compiles_and_preserves_complete_tmpfs_and_defaults(self):
        launch = copy.deepcopy(self.launch)
        launch['startup']['args'] = ['/bin/sh', '-c', 'printf second']
        launch['manifest'].update(memoryBytes=536870912, pidsLimit=128)
        one = {**launch['sources'][0], 'source': '/owned/second-config', 'target': '/usr/local/etc/ouf/config.json'}
        two = {**one, 'source': '/owned/second-hmac', 'target': '/run/ouf-southbound-hmac.key', 'sha256': 'd' * 64}
        launch['sources'] = [one, two]
        launch['manifest']['mounts'] = [{k: s[k] for k in ('source', 'target', 'readOnly')} for s in launch['sources']]
        original = copy.deepcopy(launch)
        result = self.build(launch)
        policy = compile_policy(result, launch, self.context)
        self.assertEqual(policy['expectedOci']['process']['args'], launch['startup']['args'])
        mounts = policy['expectedOci']['mounts']
        self.assertEqual(next(m for m in mounts if m['destination'] == TARGET), self.tmpfs)
        self.assertEqual([m for m in mounts if m['type'] != 'bind' and m['destination'] != TARGET],
                         [m for m in self.template['expectedOci']['mounts'] if m['type'] != 'bind' and m['destination'] != TARGET])
        self.assertEqual([m['destination'] for m in mounts if m['type'] == 'bind' or m['destination'] == TARGET],
                         ['/etc/hostname', '/etc/hosts', '/etc/resolv.conf',
                          '/run/ouf-southbound-hmac.key', TARGET, '/usr/local/etc/ouf/config.json'])
        self.assertEqual(launch, original)

    def test_changed_or_missing_tmpfs_declarations_are_rejected_with_specific_code(self):
        for declaration in (None, {}, {'/foreign': OPTIONS}, {TARGET: OPTIONS + ',noswap'},
                            {TARGET: OPTIONS + ',ro'}, {TARGET: OPTIONS, '/extra': OPTIONS}):
            with self.subTest(declaration=declaration):
                launch = copy.deepcopy(self.launch)
                launch['manifest']['tmpfs'] = declaration
                with self.assertRaisesRegex(Denied, '^TMPFS_LAUNCH_DRIFT$'):
                    self.build(launch)

    def test_missing_baseline_declaration_is_rejected(self):
        del self.launch['manifest']['tmpfs']
        with self.assertRaisesRegex(Denied, '^TMPFS_BASELINE_DECLARATION_REQUIRED$'):
            self.build()

    def test_missing_duplicate_or_changed_baseline_tmpfs_kind_is_rejected(self):
        for change in ('missing', 'duplicate', 'type', 'source'):
            with self.subTest(change=change):
                original = copy.deepcopy(self.template)
                mounts = self.template['expectedOci']['mounts']
                mount = next(m for m in mounts if m['destination'] == TARGET)
                if change == 'missing':
                    mounts.remove(mount)
                elif change == 'duplicate':
                    mounts.append(copy.deepcopy(mount))
                else:
                    mount[change] = 'bind'
                with self.assertRaisesRegex(Denied, '^TMPFS_BASELINE_MOUNT_REQUIRED$'):
                    self.build()
                self.template = original

    def test_baseline_oci_options_are_never_reconstructed_from_request_string(self):
        mount = next(m for m in self.template['expectedOci']['mounts'] if m['destination'] == TARGET)
        mount['options'] = ['size=1024k', 'mode=700', 'uid=636', 'gid=636', 'nodev', 'nosuid', 'noexec']
        self.assertEqual(next(m for m in self.build()['expectedOci']['mounts'] if m['destination'] == TARGET), mount)

    def test_bind_cannot_shadow_role_tmpfs(self):
        for target in (TARGET, TARGET + '/child', '/run'):
            with self.subTest(target=target):
                launch = copy.deepcopy(self.launch)
                launch['sources'][0]['target'] = launch['manifest']['mounts'][0]['target'] = target
                with self.assertRaisesRegex(Denied, '^SOURCE_MOUNT_SHADOWING_DENIED$'):
                    self.build(launch)

    def test_other_mount_orderings_are_not_silently_admitted(self):
        with self.assertRaisesRegex(Denied, '^TMPFS_DEPTH_PATH_ORDER_REQUIRED$'):
            build_role_template(self.template, self.launch, self.launch, self.user,
                                mount_ordering='depth-stable-user-first')

    def test_historical_root_user_and_readonly_bind_guards_remain_enforced(self):
        for change in ('root', 'user', 'bind'):
            with self.subTest(change=change):
                launch = copy.deepcopy(self.launch)
                if change == 'root':
                    launch['manifest']['readOnlyRoot'] = True
                elif change == 'user':
                    launch['startup']['uid'] = 637
                else:
                    launch['manifest']['mounts'][0]['readOnly'] = False
                with self.assertRaises(Denied):
                    self.build(launch)


if __name__ == '__main__':
    unittest.main()
