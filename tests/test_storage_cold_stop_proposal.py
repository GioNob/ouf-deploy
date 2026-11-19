import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


b = load('backup_stop_fixture', 'scripts/storage-cold-backup.py')
p = load('stop_proposal', 'tools/storage_planning/cold_stop_proposal.py')


class ProposalTests(unittest.TestCase):
    def setUp(self):
        self.host, roles = {}, {}
        for i, role in enumerate(sorted(b.ROLES | {'etcd'})):
            cid = '%064x' % (i + 1)
            doc = {'Id': cid, 'Image': 'sha256:' + 'a' * 64,
                'Config': {'Env': ['SECRET=not-in-proposal'], 'StopSignal': 'SIGINT' if role == 'postgres' else ''},
                'Mounts': [], 'HostConfig': {'RestartPolicy': {'Name': 'no' if role == 'semantic' else 'unless-stopped', 'MaximumRetryCount': 0}},
                'State': {'Running': True, 'StartedAt': 'generation', 'Pid': 10}}
            self.host[cid] = doc
            roles[role] = {'containerId': cid, 'fingerprint': b.fingerprint(doc),
                'wasRunning': True, 'originalRestartPolicy': copy.deepcopy(doc['HostConfig']['RestartPolicy'])}
        for i in range(131):
            cid = '%064x' % (i + 1000)
            self.host[cid] = {'Id': cid,
                'Mounts': [{'Source': '/source', 'RW': True}] if i < 103 else [],
                'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped' if i < 22 else 'no', 'MaximumRetryCount': 0}},
                'State': {'Running': False, 'Pid': 0, 'StartedAt': 'old', 'Status': 'exited'}}
        self.plan = {'roles': roles, 'sources': ['/source'],
            'stoppedSharingContainers': b.shared_outside_bindings(self.host, {r['containerId'] for r in roles.values()}, ['/source']),
            'createdEpoch': 1, 'validUntilEpoch': 100, 'maximumSeconds': 3600, 'maximumProducedBytes': 64 << 30}

    def compile(self, now=50, sha=None):
        return p.compile_proposal(self.plan, self.host, vars(b),
            sha or b.digest(b.canonical(self.plan)), now)

    def test_exact_scope_and_order_without_mutation_or_authority(self):
        before = copy.deepcopy((self.plan, self.host))
        result = self.compile()
        self.assertEqual((result['selectedPolicyChanges'], result['sharingPolicyChanges']), (13, 22))
        self.assertEqual(result['maximumStopSignals'], 14)
        self.assertFalse(result['targetCommandAuthorized'])
        self.assertEqual(len(result['remainingRequiredEvidence']), 9)
        self.assertEqual(before, (self.plan, self.host))
        self.assertNotIn('SECRET', str(result))
        commands = [a for g in result['stopGroups'] for a in g['signals']]
        self.assertEqual(next(x for x in commands if x['role'] == 'postgres')['proposedArgv'][-2], '--signal=SIGINT')
        self.assertEqual(result['stopGroups'][-1]['signals'][0]['role'], 'etcd')

    def test_expiry_and_bad_digest(self):
        for kwargs in ({'now': 101}, {'now': 0}, {'sha': '0' * 64}):
            with self.subTest(kwargs=kwargs), self.assertRaises(b.Held):
                self.compile(**kwargs)

    def test_policy_or_process_generation_drift(self):
        cid = self.plan['roles']['onboarding']['containerId']
        for part, key, value in [('State', 'StartedAt', 'new'), ('HostConfig', 'RestartPolicy', {'Name': 'no'})]:
            original = copy.deepcopy(self.host[cid][part][key])
            self.host[cid][part][key] = value
            with self.subTest(part=part), self.assertRaises(b.Held): self.compile()
            self.host[cid][part][key] = original

    def test_new_running_outside_even_without_shared_mounts(self):
        self.host['%064x' % 1130]['State']['Running'] = True
        with self.assertRaises(b.Held): self.compile()

    def test_shared_generation_drift(self):
        self.host['%064x' % 1000]['State']['StartedAt'] = 'new'
        with self.assertRaises(b.Held): self.compile()

    def test_force_signal_rejected_even_if_fingerprint_matches(self):
        row = self.plan['roles']['postgres']
        self.host[row['containerId']]['Config']['StopSignal'] = 'SIGKILL'
        row['fingerprint'] = b.fingerprint(self.host[row['containerId']])
        with self.assertRaises(b.Held): self.compile()

    def test_unknown_role_or_injected_container_id(self):
        self.plan['roles']['unexpected'] = self.plan['roles'].pop('etcd')
        with self.assertRaises(b.Held): self.compile()

    def test_removed_or_new_shared_container(self):
        del self.host['%064x' % 1000]
        with self.assertRaises(b.Held): self.compile()


if __name__ == '__main__':
    unittest.main()
