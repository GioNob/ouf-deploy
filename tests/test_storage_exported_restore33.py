import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('exported33',ROOT/'scripts/run-storage-exported-restore33.py')
restore=importlib.util.module_from_spec(spec);spec.loader.exec_module(restore)

def archive(entries):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w:gz') as tar:
        for name,data,kind in entries:
            member=tarfile.TarInfo(name);member.type=kind
            if kind==tarfile.REGTYPE:member.size=len(data)
            else:member.linkname='outside'
            tar.addfile(member,io.BytesIO(data))
    return out.getvalue()

class ExportedRestoreTests(unittest.TestCase):
    def test_roundtrip_preserves_exact_binary_files(self):
        raw=archive([('a/b',b'\x00\xff',tarfile.REGTYPE),('c',b'',tarfile.REGTYPE)])
        index=restore.reader.tar_inventory(raw)
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/'extracted';restore.extract_export(raw,index,dest)
            self.assertEqual((dest/'a/b').read_bytes(),b'\x00\xff')
            self.assertEqual(restore.tree_inventory(dest),index)

    def test_invalid_member_leaves_no_extraction(self):
        for name in ('../escape','/absolute','a/../../escape','a\\b','a:b','a/./b'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                raw=archive([('valid',b'ok',tarfile.REGTYPE),(name,b'bad',tarfile.REGTYPE)])
                dest=Path(tmp)/'extracted'
                with self.assertRaises((ValueError,RuntimeError)):restore.extract_export(raw,{},dest)
                self.assertFalse(dest.exists())

    def test_link_and_device_members_rejected(self):
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.CHRTYPE,tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):restore.reader.tar_inventory(archive([('link',b'',kind)]))

    def test_duplicate_names_rejected(self):
        with self.assertRaises(ValueError):
            restore.reader.tar_inventory(archive([('a',b'one',tarfile.REGTYPE),('a',b'two',tarfile.REGTYPE)]))

    def test_file_parent_collision_rejected_before_write(self):
        raw=archive([('a',b'one',tarfile.REGTYPE),('a/b',b'two',tarfile.REGTYPE)])
        index=restore.reader.tar_inventory(raw)
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/'extracted'
            with self.assertRaisesRegex(RuntimeError,'NO_FILE_DIRECTORY_COLLISION'):restore.extract_export(raw,index,dest)
            self.assertFalse(dest.exists())

    def test_wrong_bytes_or_missing_file_rejected(self):
        raw=archive([('a',b'original',tarfile.REGTYPE)])
        index=restore.reader.tar_inventory(raw)
        for expected in ({},{'a':{'bytes':8,'sha256':'0'*64}}):
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(RuntimeError,'EXACT_EXPORTED_COMPONENT'):restore.validate_export(raw,expected)

    def test_existing_destination_never_overwritten(self):
        raw=archive([('a',b'original',tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp);(dest/'a').write_bytes(b'keep')
            with self.assertRaisesRegex(RuntimeError,'FRESH_EXTRACTION_ROOT'):
                restore.extract_export(raw,restore.reader.tar_inventory(raw),dest)
            self.assertEqual((dest/'a').read_bytes(),b'keep')

    def test_directory_reconstruction_creates_no_state_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in restore.PG_DIRECTORIES:restore.private_directories(root,name)
            self.assertEqual(restore.tree_inventory(root),{})
            self.assertTrue((root/'pg_wal/archive_status').is_dir())
            self.assertTrue((root/'pg_tblspc').is_dir())

    def test_uncompressed_member_budget(self):
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w:gz') as tar:
            member=tarfile.TarInfo('huge');member.size=32*1024*1024+1;tar.addfile(member)
        with self.assertRaisesRegex(ValueError,'SAFE_REGULAR_TAR_MEMBER'):restore.reader.tar_inventory(raw.getvalue())

if __name__=='__main__':unittest.main()
