import copy
import json
from pathlib import Path
import unittest

from compile_creation_frame_policy import Denied, compile_policy, compilation_receipt
from review_semantic_oci_policy import configured_profile, schema_from_source_closure


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.context = {'schema': 'ouf.semantic-docker-frame-context.v1', 'containerId': 'a' * 64,
                        'bundleParent': '/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby',
                        'metadataParent': '/var/lib/docker/containers', 'networkNamespaceParent': '/run/docker/netns',
                        'networkNamespaceName': 'b' * 12, 'cgroupDriver': 'systemd'}
        mount = {'source': '/approved/adapter.json', 'target': '/run/provider.json', 'readOnly': True}
        self.launch = {'schema': 'ouf.semantic-creation-frame-launch.v1',
                       'manifest': {'user': '10006:10006', 'readOnlyRoot': True, 'memoryBytes': 268435456,
                                    'pidsLimit': 128, 'mounts': [mount]},
                       'startup': {'uid': 10006, 'gid': 10006, 'umask': None, 'cwd': '/app',
                                   'args': ['python3', '-B', '-m', 'tools.semantic_provider_adapter'],
                                   'env': ['PATH=/usr/local/bin:/usr/bin:/bin', 'HOSTNAME=$OUF_HOSTNAME',
                                           'PRIVATE_VALUE=CI_SECRET_NOT_FOR_LOGS']},
                       'sources': [{**mount, 'uid': 10006, 'gid': 10006, 'mode': 0o600,
                                    'maxBytes': 131072, 'sha256': 'c' * 64}]}
        oci = {'ociVersion': '1.3.0', 'hostname': '$OUF_HOSTNAME',
               'root': {'path': '$OUF_ROOTFS', 'readonly': True},
               'process': {'terminal': False, 'noNewPrivileges': True, 'user': {'uid': 10006, 'gid': 10006},
                           'args': self.launch['startup']['args'], 'cwd': '/app', 'env': self.launch['startup']['env'],
                           'capabilities': {k: [] for k in ('bounding', 'effective', 'inheritable', 'permitted', 'ambient')}},
               'mounts': [{'type': 'bind', 'destination': '/run/provider.json', 'source': '/approved/adapter.json',
                           'options': ['rbind', 'rprivate', 'ro']},
                          *[{'type': 'bind', 'destination': target, 'source': source, 'options': ['rbind', 'rprivate', 'ro']}
                            for target, source in (('/etc/hosts', '$OUF_HOSTS'), ('/etc/hostname', '$OUF_HOSTNAME_FILE'),
                                                   ('/etc/resolv.conf', '$OUF_RESOLV'))]],
               'linux': {'cgroupsPath': '$OUF_CGROUPS', 'namespaces': [{'type': k} for k in ('mount', 'pid', 'ipc', 'uts', 'cgroup')]
                         + [{'type': 'network', 'path': '$OUF_NETWORK_NAMESPACE'}],
                         'maskedPaths': ['/proc/kcore'], 'readonlyPaths': ['/proc/sys'],
                         'resources': {'memory': {'limit': 268435456, 'swap': 268435456}, 'pids': {'limit': 128}},
                         'seccomp': {'defaultAction': 'SCMP_ACT_ERRNO', 'defaultErrnoRet': 1,
                                     'architectures': ['SCMP_ARCH_X86_64'], 'syscalls': []}}}
        self.template = {'schema': 'ouf.semantic-creation-frame-template.v1', 'expectedOci': oci, 'approvedHooks': {}}
        self.schema = schema_from_source_closure(Path(__file__).with_name('semantic_oci_shape_schema.json').read_bytes())

    def compile(self):
        return compile_policy(self.template, self.launch, self.context)

    def review(self, actual, policy):
        return configured_profile(actual, policy['expectedOci'], policy['manifest'], policy['startup'],
                                  policy['approvedHooks'], self.schema)

    def test_compiles_exact_policy_accepted_by_pinned_owner_reviewer_without_authority(self):
        original = copy.deepcopy((self.template, self.launch, self.context))
        policy = self.compile()
        self.assertEqual(original, (self.template, self.launch, self.context))
        result = self.review(copy.deepcopy(policy['expectedOci']), policy)
        self.assertTrue(result['configuredPolicyConforms'])
        self.assertFalse(result['acceptanceGranted'])
        self.assertFalse(result['startAuthorized'])
        self.assertEqual(policy['expectedOci']['root']['path'], self.context['bundleParent'] + '/' + 'a' * 64 + '/rootfs')
        self.assertEqual(policy['expectedOci']['linux']['cgroupsPath'], 'system.slice:docker:' + 'a' * 64)

    def test_cross_container_namespace_mount_and_seccomp_drift_denied_by_owner(self):
        policy = self.compile()
        changes = [lambda o: o['process'].update(args=['/bin/sh']),
                   lambda o: o['root'].update(path='/foreign/rootfs'),
                   lambda o: o['linux']['namespaces'][-1].update(path='/run/docker/netns/foreign'),
                   lambda o: o['mounts'][0].update(source='/foreign/adapter.json'),
                   lambda o: o['linux']['seccomp'].update(defaultAction='SCMP_ACT_ALLOW'),
                   lambda o: o['process']['capabilities'].update(effective=['CAP_SYS_ADMIN']),
                   lambda o: o['linux']['resources']['memory'].update(limit=536870912),
                   lambda o: o.update(unreviewedExtension=True)]
        for index, mutate in enumerate(changes):
            with self.subTest(index=index):
                actual = copy.deepcopy(policy['expectedOci']); mutate(actual)
                with self.assertRaises(ValueError):
                    self.review(actual, policy)

    def test_context_cannot_change_commands_or_add_arbitrary_substitution(self):
        self.context['command'] = ['/bin/sh']
        with self.assertRaises(Denied): self.compile()
        del self.context['command']
        self.template['expectedOci']['process']['args'] = ['$OUF_COMMAND']
        with self.assertRaises(Denied): self.compile()

    def test_launch_compiled_from_different_image_does_not_match_template(self):
        self.launch['startup']['args'] = ['/bin/sh']
        with self.assertRaises(Denied): self.compile()

    def test_namespace_path_traversal_and_invalid_container_identity_denied(self):
        for field, value in (('networkNamespaceName', '../escape'), ('containerId', 'g' * 64),
                             ('bundleParent', '/run/docker/../escape'), ('cgroupDriver', 'other')):
            with self.subTest(field=field):
                context = copy.deepcopy(self.context); context[field] = value
                with self.assertRaises(Denied): compile_policy(self.template, self.launch, context)

    def test_different_container_and_namespace_produce_different_exact_policy(self):
        first = self.compile()
        context = copy.deepcopy(self.context); context.update(containerId='d' * 64, networkNamespaceName='e' * 12)
        second = compile_policy(self.template, self.launch, context)
        with self.assertRaises(ValueError): self.review(first['expectedOci'], second)

    def test_duplicate_or_unsealed_mount_source_denied(self):
        self.launch['sources'].append(copy.deepcopy(self.launch['sources'][0]))
        with self.assertRaises(Denied): self.compile()
        self.launch['sources'].pop(); self.launch['sources'][0]['sha256'] = ''
        with self.assertRaises(Denied): self.compile()

    def test_template_cannot_extend_allowed_placeholders(self):
        self.template['expectedOci']['annotations'] = {'other': '$OUF_HOSTNAME'}
        with self.assertRaises(Denied): self.compile()

    def test_receipt_contains_no_private_values_and_grants_no_acceptance(self):
        receipt = compilation_receipt(self.template, self.launch, self.context, self.compile())
        raw = json.dumps(receipt)
        self.assertNotIn('CI_SECRET_NOT_FOR_LOGS', raw)
        self.assertNotIn('/approved/', raw)
        for key in ('inputsAuthenticated', 'templateApproved', 'kernelEnforcementObserved', 'acceptanceGranted', 'startAuthorized'):
            self.assertFalse(receipt[key])
        self.assertEqual(receipt['signaturesIssued'], 0)

    def test_cgroupfs_context_does_not_change_static_policy(self):
        context = copy.deepcopy(self.context); context['cgroupDriver'] = 'cgroupfs'
        policy = compile_policy(self.template, self.launch, context)
        self.assertEqual(policy['expectedOci']['linux']['cgroupsPath'], '/docker/' + 'a' * 64)
        self.assertTrue(self.review(policy['expectedOci'], policy)['configuredPolicyConforms'])

    def test_fresh_private_network_namespace_remains_unaccepted_and_has_no_join_path(self):
        context = copy.deepcopy(self.context); context['networkNamespaceName'] = None
        policy = compile_policy(self.template, self.launch, context)
        network = next(v for v in policy['expectedOci']['linux']['namespaces'] if v['type'] == 'network')
        self.assertEqual(network, {'type': 'network'})
        self.assertTrue(self.review(policy['expectedOci'], policy)['configuredPolicyConforms'])
        self.assertFalse(compilation_receipt(self.template, self.launch, context, policy)['kernelEnforcementObserved'])
        joined = copy.deepcopy(policy['expectedOci']); joined['linux']['namespaces'][-1]['path'] = '/foreign/netns'
        with self.assertRaises(ValueError): self.review(joined, policy)


if __name__ == '__main__':
    unittest.main()
