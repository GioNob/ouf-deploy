import copy
import importlib.util
from pathlib import Path
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load('mount_fixture', 'tests/test_storage_cold_stop_proposal.py')
v4 = load('v4', 'scripts/storage-cold-backup-v4.py')
b = types.SimpleNamespace(**v4.definitions((ROOT / 'scripts/storage-cold-backup.py').read_bytes()))
d = load('stop_v4', 'scripts/storage-test-cold-stop.py')


class MountIdentityTests(unittest.TestCase):
    def setUp(self):
        f = fixture.ProposalTests()
        f.setUp()
        self.host, self.plan = f.host, f.plan
        self.ids = {r['containerId'] for r in self.plan['roles'].values()}
        self.plan['programSha256'] = v4.LEGACY_SHA
        for doc in self.host.values():
            doc['Mounts'] = [{'Source': '/source', 'Destination': '/a', 'RW': True},
                             {'Source': '/other', 'Destination': '/b', 'RW': False}]
        for row in self.plan['roles'].values():
            row['fingerprint'] = fixture.b.fingerprint(self.host[row['containerId']])
        self.plan['stoppedSharingContainers'] = fixture.b.shared_outside_bindings(self.host, self.ids, ['/source'])
        self.v4plan = b.derive_legacy_plan(self.plan, self.host, 'b' * 64)

    def test_permutation_accepted_for_selected_and_sharing(self):
        current = copy.deepcopy(self.host)
        for doc in current.values(): doc['Mounts'].reverse()
        for row in self.v4plan['roles'].values():
            self.assertEqual(b.fingerprint(current[row['containerId']]), row['fingerprint'])
        self.assertEqual(b.shared_outside_bindings(current, self.ids, ['/source']), self.v4plan['stoppedSharingContainers'])
        d.check_host(vars(b), self.v4plan, self.host, current, set(), set(), set())

    def test_actual_mount_values_or_duplicates_remain_bound(self):
        row = self.v4plan['roles']['onboarding']
        for field, value in [('Source', '/new'), ('Destination', '/new'), ('RW', False), ('Driver', 'new')]:
            current = copy.deepcopy(self.host)
            current[row['containerId']]['Mounts'][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(b.Held, 'ROLE_GENERATION_CHANGED'):
                d.check_host(vars(b), self.v4plan, self.host, current, set(), set(), set())
        current = copy.deepcopy(self.host)
        current[row['containerId']]['Mounts'].append(current[row['containerId']]['Mounts'][0])
        self.assertNotEqual(b.fingerprint(current[row['containerId']]), row['fingerprint'])
        outside = next(cid for cid in self.host if cid not in self.ids)
        current = copy.deepcopy(self.host)
        current[outside]['Mounts'][0]['RW'] = False
        with self.assertRaisesRegex(b.Held, 'SHARED_GENERATION_CHANGED'):
            d.check_host(vars(b), self.v4plan, self.host, current, set(), set(), set())

    def test_derivation_never_renews_or_mutates_legacy_plan(self):
        old = copy.deepcopy(self.plan)
        result = b.derive_legacy_plan(self.plan, self.host, 'b' * 64)
        self.assertEqual(self.plan, old)
        self.assertEqual(result, self.v4plan)
        for k in set(old) - {'roles', 'programSha256', 'stoppedSharingContainers'}:
            self.assertEqual(result[k], old[k])
        self.assertEqual(result['mountIdentityCorrection']['derivedFromPlanSha256'], b.digest(b.canonical(old)))
        self.assertFalse(result['mountIdentityCorrection']['attemptsReset'])
        self.assertFalse(result['mountIdentityCorrection']['expiryRenewed'])

    def test_old_binding_change_blocks_derivation(self):
        self.host[self.plan['roles']['onboarding']['containerId']]['Mounts'][0]['RW'] = False
        with self.assertRaisesRegex(b.Held, 'LEGACY_ROLE_BINDING'):
            b.derive_legacy_plan(self.plan, self.host, 'b' * 64)

    def test_exact_dependency_and_driver_pin(self):
        self.assertEqual(d.WRAPPER_SHA, b.digest((ROOT / 'scripts/storage-cold-backup-v4.py').read_bytes()))
        with self.assertRaisesRegex(ValueError, 'LEGACY_PROGRAM_DIGEST'):
            v4.definitions((ROOT / 'scripts/storage-cold-backup.py').read_bytes() + b'\n')


if __name__ == '__main__': unittest.main()
