import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('metadata', Path(__file__).resolve().parents[1] / 'scripts/read-storage-cold-v2-metadata-20261106.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_directory_is_reported_without_reading_entries(self):
        (self.root / 'private-name').write_text('private-content')
        result = m.inspect_metadata(self.root, 1024)
        self.assertEqual(result['type'], 'DIRECTORY')
        self.assertIn('regularFile', result['failedRegularInputChecks'])
        self.assertNotIn('private-name', json.dumps(result))
        self.assertNotIn('private-content', json.dumps(result))

    def test_all_failed_predicates_reported_together(self):
        p = self.root / 'file'
        p.touch(mode=0o600)
        p.chmod(0o666)
        os.link(p, self.root / 'link')
        result = m.inspect_metadata(p, 1024)
        self.assertTrue({'singleLink', 'notGroupOrOtherWritable', 'nonemptyWithinLimit'} <= set(result['failedRegularInputChecks']))

    def test_symlink_leaf_not_followed(self):
        p = self.root / 'link'
        p.symlink_to('/not-present-private-target')
        self.assertEqual(m.inspect_metadata(p, 1024)['type'], 'SYMLINK')

    def test_symlink_ancestor_not_followed(self):
        p = self.root / 'link'
        p.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(m.inspect_metadata(p / 'leaf', 1024)['status'], 'METADATA_UNAVAILABLE')

    def test_fifo_is_metadata_only_without_open_block(self):
        p = self.root / 'fifo'
        os.mkfifo(p)
        self.assertEqual(m.inspect_metadata(p, 1024)['type'], 'FIFO')

    def test_private_mode_and_size_reported_without_content(self):
        p = self.root / 'file'
        p.write_text('do-not-export')
        p.chmod(0o640)
        result = m.inspect_metadata(p, 4, private=True)
        self.assertFalse(result['privateModeSatisfied'])
        self.assertIn('nonemptyWithinLimit', result['failedRegularInputChecks'])
        self.assertNotIn('do-not-export', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
