"""Verify unchanged sealer capture and frozen input rejection without Docker."""
import copy,hashlib,importlib.util,os,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rootfs_baseline',ROOT/'scripts/diagnose-chatbot-rootfs-baseline.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class RootfsBaseline(unittest.TestCase):
    def test_exact_original_stream_replays_without_normalizing_any_field(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            root=Path(d);root.chmod(0o700);image=root/'image';image.mkdir(mode=0o755)
            (image/'nested').mkdir();(image/'nested/file').write_bytes(b'frozen-fixture')
            (image/'link').symlink_to('nested/file')
            observe,records=m.sealer(ROOT);seal=observe(image,m.LIMITS,m.Budget())
            self.assertEqual(seal,m.replay(records));self.assertEqual(seal['entries'],4)
            self.assertEqual(seal['bytes'],len(b'frozen-fixture'))
            clone=copy.deepcopy(records);clone['nested/file']['links']+=1
            self.assertNotEqual(m.replay(clone),seal)
            clone=copy.deepcopy(records);clone['']['mode']^=0o100
            self.assertNotEqual(m.replay(clone),seal)
    def test_second_scan_uses_independent_records_and_detects_file_drift(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            root=Path(d);root.chmod(0o700);(root/'file').write_bytes(b'before')
            observe,records=m.sealer(ROOT);first=observe(root,m.LIMITS,m.Budget())
            other,other_records=m.sealer(ROOT);self.assertEqual(other(root,m.LIMITS,m.Budget()),first)
            self.assertEqual(records,other_records);(root/'file').write_bytes(b'after')
            changed,changed_records=m.sealer(ROOT);self.assertNotEqual(changed(root,m.LIMITS,m.Budget()),first)
    def test_unrelated_artifact_is_refused_before_extraction_or_output_creation(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            root=Path(d);bad=root/'wrong.zip';bad.write_bytes(b'not the retained archive')
            with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_SEMANTIC_ARTIFACT_REQUIRED'):m.unpack(bad,root/'output')
            self.assertFalse((root/'output').exists())
    def test_changed_original_sealer_source_is_refused_before_execution(self):
        with tempfile.TemporaryDirectory(dir=ROOT)as d:
            root=Path(d);source=root/'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_node_observation.py'
            source.parent.mkdir(parents=True);source.write_text('raise RuntimeError("MUST_NOT_EXECUTE")')
            with self.assertRaisesRegex(ValueError,'FROZEN_SEALER_SOURCE_REQUIRED'):m.sealer(root)

if __name__=='__main__':unittest.main()
