import copy
import unittest

from build_role_frame_template import build_role_template
from compile_creation_frame_policy import Denied, compile_policy
from test_compile_creation_frame_policy import CompilerTests


class RoleTemplateTests(unittest.TestCase):
    def setUp(self):
        fixture = CompilerTests(); fixture.setUp()
        self.template, self.launch, self.context = fixture.template, fixture.launch, fixture.context

    def test_role_uses_sealed_startup_resources_and_multi_mounts_without_changing_engine_fields(self):
        launch = copy.deepcopy(self.launch)
        launch['startup'].update(args=['/app/worker', '--configuration', '/run/deep/config.json'], cwd='/app/worker',
                                 env=['HOSTNAME=$OUF_HOSTNAME', 'PATH=/bin', 'PRIVATE=SEALED'])
        launch['manifest'].update(memoryBytes=536870912, pidsLimit=64)
        source = copy.deepcopy(launch['sources'][0])
        source.update(source='/approved/trust.pem', target='/run/deep/trust.pem', uid=0, gid=0, mode=0o644)
        launch['sources'].append(source)
        launch['manifest']['mounts'].append({k: source[k] for k in ('source', 'target', 'readOnly')})
        original = copy.deepcopy((self.template, self.launch, launch))
        result = build_role_template(self.template, self.launch, launch, {'uid': 10006, 'gid': 10006})
        self.assertEqual((self.template, self.launch, launch), original)
        policy = compile_policy(result, launch, self.context)
        self.assertEqual(policy['expectedOci']['process']['args'], launch['startup']['args'])
        self.assertEqual(result['expectedOci']['linux']['seccomp'], self.template['expectedOci']['linux']['seccomp'])
        self.assertEqual(result['expectedOci']['process']['capabilities'], self.template['expectedOci']['process']['capabilities'])
        self.assertEqual([m['destination'] for m in result['expectedOci']['mounts']],
                         ['/run/provider.json', '/etc/hosts', '/etc/hostname', '/etc/resolv.conf', '/run/deep/trust.pem'])

    def test_distinct_root_mode_requires_separate_reviewed_baseline(self):
        launch = copy.deepcopy(self.launch); launch['manifest']['readOnlyRoot'] = False
        with self.assertRaises(Denied): build_role_template(self.template, self.launch, launch, {'uid': 10006, 'gid': 10006})

    def test_unapproved_group_or_user_binding_rejected(self):
        for user in ({'uid': 636, 'gid': 636}, {'uid': 10006, 'gid': 10006, 'additionalGids': [0, 0]},
                     {'uid': 10006, 'gid': 10006, 'unreviewed': True}):
            with self.subTest(user=user), self.assertRaises(Denied):
                build_role_template(self.template, self.launch, self.launch, user)

    def test_source_cannot_shadow_engine_or_other_source_mount(self):
        for target in ('/etc', '/etc/hosts', '/run/provider.json/subfile'):
            launch = copy.deepcopy(self.launch)
            launch['manifest']['mounts'][0]['target'] = launch['sources'][0]['target'] = target
            if target.endswith('subfile'):
                old = copy.deepcopy(self.launch['sources'][0]); launch['sources'].append(old)
                launch['manifest']['mounts'].append({k: old[k] for k in ('source', 'target', 'readOnly')})
            with self.subTest(target=target), self.assertRaises(Denied):
                build_role_template(self.template, self.launch, launch, {'uid': 10006, 'gid': 10006})

    def test_changed_sealed_source_hash_still_verified_by_observer_not_builder(self):
        launch = copy.deepcopy(self.launch); launch['sources'][0]['sha256'] = 'e' * 64
        result = build_role_template(self.template, self.launch, launch, {'uid': 10006, 'gid': 10006})
        self.assertEqual(compile_policy(result, launch, self.context)['sources'][0]['sha256'], 'e' * 64)


if __name__ == '__main__': unittest.main()
