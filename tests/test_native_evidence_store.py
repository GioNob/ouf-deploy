import sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/semantic_application_cutover'))
from native_evidence_store import NativeEvidenceStore,digest

class Evidence(unittest.TestCase):
    def fixture(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);root.chmod(0o700)
        return NativeEvidenceStore(root)
    def test_exact_repeat_preserves_file_and_foreign_payload_is_denied(self):
        s=self.fixture();v={'fixturePrivate':True};s.publish('CREATE_REPLACEMENT',v);p=s.path('CREATE_REPLACEMENT');before=p.stat()
        self.assertEqual(s.publish('CREATE_REPLACEMENT',v),v);self.assertEqual(before.st_ino,p.stat().st_ino)
        with self.assertRaises(ValueError):s.publish('CREATE_REPLACEMENT',{'foreign':True})
        self.assertEqual(s.read('CREATE_REPLACEMENT',digest(v)),v)
    def test_partial_and_link_receipts_are_retained_and_denied(self):
        for content in (b'',b'{'):
            s=self.fixture();p=s.path('CREATE_REPLACEMENT');p.write_bytes(content);p.chmod(0o600)
            with self.assertRaises(ValueError):s.publish('CREATE_REPLACEMENT',{'fixture':True})
            self.assertEqual(p.read_bytes(),content)
        s=self.fixture();s.path('CREATE_REPLACEMENT').symlink_to('/dev/null')
        with self.assertRaises(OSError):s.publish('CREATE_REPLACEMENT',{})
    def test_hash_mode_and_phase_are_checked(self):
        s=self.fixture();s.publish('CREATE_REPLACEMENT',{'fixture':True})
        with self.assertRaises(ValueError):s.read('CREATE_REPLACEMENT','f'*64)
        s.path('CREATE_REPLACEMENT').chmod(0o644)
        with self.assertRaises(ValueError):s.read('CREATE_REPLACEMENT',digest({'fixture':True}))
        with self.assertRaises(ValueError):s.path('../foreign')


class Baseline(unittest.TestCase):
    fixture=Evidence.fixture
    def test_scoped_baseline_rejects_foreign_context_and_symlink_before_content_read(self):
        s=self.fixture();v={'transitionContextHash':'a'*64,'intentHash':'b'*64,'fixturePrivate':True};s.publish('START_REPLACEMENT',v)
        self.assertEqual(s.read_baseline('START_REPLACEMENT','a'*64,'b'*64),v)
        with self.assertRaises(ValueError):s.read_baseline('START_REPLACEMENT','c'*64,'b'*64)
        p=s.path('START_REPLACEMENT');p.unlink();p.symlink_to('/dev/null')
        with self.assertRaises(OSError):s.read_baseline('START_REPLACEMENT','a'*64,'b'*64)

if __name__=='__main__':unittest.main()
