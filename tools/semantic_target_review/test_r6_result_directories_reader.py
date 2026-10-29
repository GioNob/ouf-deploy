"""Read-only directory facts never follow symlinks or print names."""
import importlib.util,tempfile,unittest
from pathlib import Path
s=importlib.util.spec_from_file_location('reader',Path(__file__).with_name('read_r6_result_directories.py'))
reader=importlib.util.module_from_spec(s);s.loader.exec_module(reader)
class DirectoryReaderTests(unittest.TestCase):
    def test_missing_empty_used_nonprivate_and_symlink(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as t:
            path=Path(t)/'result'
            self.assertEqual(reader.result_directory_summary(path),{'present':False})
            path.mkdir(mode=0o700)
            self.assertTrue(reader.result_directory_summary(path)['empty'])
            (path/'private-name').write_bytes(b'preserve')
            self.assertFalse(reader.result_directory_summary(path)['empty'])
            path.chmod(0o755)
            self.assertIsNone(reader.result_directory_summary(path)['empty'])
            alias=Path(t)/'alias';alias.symlink_to(path)
            self.assertFalse(reader.result_directory_summary(alias)['isDirectory'])
            self.assertEqual((path/'private-name').read_bytes(),b'preserve')
if __name__=='__main__':unittest.main()
