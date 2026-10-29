import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('scope_probe',ROOT/'tools/semantic_policy_token_owner/protected_scope_probe.py')
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)

class ScopeProbeTest(unittest.TestCase):
    def test_metadata_preserves_private_member_content_and_inode(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as value:
            directory=Path(value);directory.chmod(0o700);secret=directory/'private';secret.write_text('NEVER_READ_THIS');secret.chmod(0o400)
            before=secret.stat();result=probe.observe(str(directory))
            self.assertEqual(result['state'],'PRESENT');self.assertFalse(result['custodyAccepted'])
            self.assertEqual(secret.stat().st_ino,before.st_ino);self.assertNotIn('NEVER_READ_THIS',str(result));self.assertNotIn('private',str(result))
    def test_missing_root_is_observed_without_creation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as value:
            path=Path(value)/'absent';self.assertEqual(probe.observe(str(path))['state'],'ABSENT');self.assertFalse(path.exists())
    def test_symlink_and_non_directory_are_never_followed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as value:
            path=Path(value);(path/'file').write_text('PRIVATE');(path/'link').symlink_to('/')
            for name in ('file','link'):self.assertEqual(probe.observe(str(path/name))['state'],'NON_DIRECTORY_OR_SYMLINK')

if __name__=='__main__':unittest.main()
