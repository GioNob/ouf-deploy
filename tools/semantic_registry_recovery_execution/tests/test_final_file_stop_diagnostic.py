import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('file_stop_diagnostic',ROOT/'scripts/inspect-registry-final-file-stop-20261023.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

class MetadataOnly(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'source';self.path.write_bytes(b'private-test-credential');self.path.chmod(0o600)
    def binding(self):
        parts=self.path.parts
        parents=['/']+['/'+'/'.join(parts[1:i])for i in range(2,len(parts))]
        return {'path':str(self.path),'sha256':'0'*64,'metadata':list(d.identity(self.path.stat())),
                'ancestors':[{'path':p,'identity':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]}
                             for p in parents for s in[Path(p).stat()]]}
    def test_matching_metadata_uses_no_source_data_reads(self):
        b=self.binding();old=d.os.read
        d.os.read=lambda *a:(_ for _ in()).throw(AssertionError('Source bytes forbidden'))
        try:self.assertEqual(d.binding_metadata(b),{'status':'METADATA_MATCHES','changedFields':[]})
        finally:d.os.read=old
    def test_replaced_credential_reports_identity_without_content_or_path(self):
        b=self.binding();new=self.path.with_name('replacement');new.write_bytes(b'other-private-content');os.replace(new,self.path)
        r=d.binding_metadata(b);self.assertEqual(r['status'],'METADATA_CHANGED');self.assertIn('inode',r['changedFields'])
        self.assertNotIn(str(self.path),str(r));self.assertNotIn('private-content',str(r))
    def test_symlink_is_metadata_difference_not_followed(self):
        b=self.binding();self.path.unlink();self.path.symlink_to('/unavailable-private-source')
        r=d.binding_metadata(b);self.assertEqual(r['status'],'METADATA_CHANGED');self.assertIn('mode',r['changedFields'])
    def test_directory_replacement_is_distinct_from_leaf_rotation(self):
        b=self.binding();b['ancestors'][-1]['identity'][1]+=1
        self.assertEqual(d.binding_metadata(b),{'status':'ANCESTRY_CHANGED'})
    def test_missing_source_is_bounded_observation(self):
        b=self.binding();self.path.unlink();self.assertEqual(d.binding_metadata(b),{'status':'MISSING_AT_OBSERVATION'})
    def test_bound_file_selection_deduplicates_and_uses_fixed_public_roles(self):
        b=self.binding();p={'nativeContext':{'originalRequest':{'tokenSource':b,'ca':None},'other':b},'ownerContext':{},'authorityInputs':{}}
        self.assertEqual(d.candidates(p),[('ORIGINAL_CALLER_TOKEN_SOURCE',b)])
    def test_unbounded_review_shape_refused(self):
        b=self.binding();v={};root=v
        for _ in range(50):v['nested']={};v=v['nested']
        p={'nativeContext':{'originalRequest':{'tokenSource':b,'ca':None},'bad':root},'ownerContext':{},'authorityInputs':{}}
        with self.assertRaisesRegex(ValueError,'BOUNDED_REVIEW_SHAPE_REQUIRED'):d.candidates(p)

if __name__=='__main__':unittest.main()
