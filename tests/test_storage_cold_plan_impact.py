import copy
import importlib.util
from pathlib import Path
import unittest


def module(name, filename):
    path = Path(__file__).resolve().parents[1] / 'scripts' / filename
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


b = module('cold', 'storage-cold-backup.py')
r = module('impact', 'read-storage-cold-plan-impact-20261106.py')


class ImpactTests(unittest.TestCase):
    def setUp(self):
        self.host, roles = {}, {}
        for i, role in enumerate(sorted(b.ROLES | {'etcd'})):
            cid = '%064x' % (i + 1)
            d = {'Id': cid, 'Image': 'sha256:' + 'a' * 64, 'Config': {'Env': ['SECRET=never-print']},
                 'Mounts': [], 'HostConfig': {'RestartPolicy': {'Name': 'always'}},
                 'State': {'Running': True, 'StartedAt': 'generation', 'Pid': 10}}
            self.host[cid] = d
            roles[role] = {'containerId': cid, 'fingerprint': b.fingerprint(d), 'wasRunning': True,
                           'originalRestartPolicy': copy.deepcopy(d['HostConfig']['RestartPolicy'])}
        for i in range(103):
            cid = '%064x' % (i + 1000)
            self.host[cid] = {'Id': cid, 'Mounts': [{'Source': '/retained/source0', 'RW': True}],
                'HostConfig': {'RestartPolicy': {'Name': 'no' if i < 100 else 'always'}},
                'State': {'Running': False, 'Pid': 0, 'StartedAt': 'old', 'Status': 'exited'}}
        sources = ['/retained/source' + str(i) for i in range(34)]
        self.plan = {'roles': roles, 'sources': sources, 'runtimeSources': {str(i): {'entryCount': 2, 'fileBytes': 64} for i in range(5)},
            'stoppedSharingContainers': b.shared_outside_bindings(self.host, {x['containerId'] for x in roles.values()}, sources),
            'createdEpoch': 1, 'validUntilEpoch': 100, 'maximumSeconds': 3600, 'maximumProducedBytes': 64 << 30,
            'includesWholeSharedPostgresCluster': True}

    def test_exact_counts_and_redaction(self):
        result = r.project(self.plan, self.host, vars(b), 50)
        self.assertEqual(result['sharingContainerPolicyChangesRequiredByCapture'], 3)
        self.assertEqual(result['runtimeFileBytesBound'], 320)
        self.assertNotIn('SECRET', str(result))
        self.assertFalse(result['runtimeAuthorityIssued'])

    def test_expiry_is_reported_without_renewal(self):
        result = r.project(self.plan, self.host, vars(b), 101)
        self.assertFalse(result['planUnexpiredAtRead'])
        self.assertEqual(self.plan['validUntilEpoch'], 100)

    def test_retained_role_policy_drift_rejected(self):
        cid = next(iter(self.host))
        self.host[cid]['HostConfig']['RestartPolicy']['Name'] = 'no'
        with self.assertRaises(b.Held):
            r.project(self.plan, self.host, vars(b), 50)

    def test_sharing_generation_change_rejected(self):
        cid = '%064x' % 1000
        self.host[cid]['State']['StartedAt'] = 'different'
        with self.assertRaises(b.Held):
            r.project(self.plan, self.host, vars(b), 50)


if __name__ == '__main__':
    unittest.main()
