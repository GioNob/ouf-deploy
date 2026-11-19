import copy
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


b = module('cold', 'scripts/storage-cold-backup.py')
r = module('readback', 'scripts/read-storage-cold-preparation-20261106.py')


class RetainedReviewTests(unittest.TestCase):
    def setUp(self):
        self.base = {'roles': {role: {'containerId': '%064x' % (i + 1), 'nativeImage': 'sha256:' + 'a' * 64}
                               for i, role in enumerate(sorted(b.ROLES))}}
        self.docs = [{'Id': v['containerId'], 'Image': v['nativeImage'], 'Mounts': [],
                      'Config': {'Env': ['PASSWORD=do-not-export']}, 'State': {'Running': True}}
                     for v in self.base['roles'].values()]
        self.docs.append({'Id': b.ETCD_ID, 'Image': b.ETCD_IMAGE, 'Mounts': [], 'State': {'Running': True}})
        self.docs[0]['Mounts'] = [{'Type': 'bind', 'Source': '/proc/123/root/run/secrets/private-name',
                                  'Destination': '/run/secrets/private-name', 'RW': False}]
        self.ids = [d['Id'] for d in self.docs]

    def check(self, others=None):
        return r.review(self.base, self.docs, others or [], self.ids, vars(b))

    def test_process_view_and_secrets_redacted(self):
        result = self.check()
        m = result['mounts'][0]
        self.assertEqual(m['sourceCategory'], 'PROCESS_ROOT_VIEW')
        self.assertIn('EPHEMERAL_OR_DEVICE_MOUNT_REQUIRES_REVIEW', m['blockersFromRetainedMetadata'])
        text = json.dumps(result)
        for private in ('private-name', 'do-not-export', '/proc/123', self.ids[0]):
            self.assertNotIn(private, text)

    def test_all_mounts_and_stopped_sharing_reported(self):
        self.docs[1]['Mounts'] = [{'Type': 'bind', 'Source': '/run/docker.sock',
                                  'Destination': '/var/run/docker.sock', 'RW': True}]
        other = {'Id': 'f' * 64, 'Mounts': copy.deepcopy(self.docs[0]['Mounts']), 'State': {'Running': False}}
        self.ids.append(other['Id'])
        result = self.check([other])
        self.assertEqual(len(result['mounts']), 2)
        self.assertEqual(result['mounts'][0]['sharingNonRosterContainers'], 1)
        self.assertEqual(result['mounts'][0]['sharingNonRosterRunning'], 0)
        self.assertTrue(result['mounts'][1]['dockerSocketDestination'])

    def test_missing_inventory_rejected(self):
        self.ids.append('f' * 64)
        with self.assertRaises(b.Held):
            self.check()

    def test_image_drift_rejected(self):
        self.docs[0]['Image'] = 'sha256:' + 'b' * 64
        with self.assertRaises(b.Held):
            self.check()

    def test_duplicate_selection_rejected(self):
        self.docs[-1] = self.docs[0]
        with self.assertRaises(b.Held):
            self.check()

    def test_tmpfs_and_remote_driver_not_omitted(self):
        self.docs[0]['Mounts'] = [
            {'Type': 'tmpfs', 'Destination': '/tmp', 'RW': True},
            {'Type': 'tmpfs', 'Destination': '/important', 'RW': True},
            {'Type': 'volume', 'Driver': 'remote', 'Source': '/data/remote', 'Destination': '/data', 'RW': True}]
        mounts = self.check()['mounts']
        self.assertEqual(mounts[0]['blockersFromRetainedMetadata'], [])
        self.assertEqual(mounts[1]['blockersFromRetainedMetadata'], ['NON_SCRATCH_TMPFS'])
        self.assertEqual(mounts[2]['blockersFromRetainedMetadata'], ['UNSUPPORTED_DRIVER'])


if __name__ == '__main__':
    unittest.main()
