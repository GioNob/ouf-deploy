import io
import tempfile
import tarfile
import unittest
from pathlib import Path
from rootfs_image_equivalence import compare_image_entries,layer_root_mode

class ImageEquivalenceTest(unittest.TestCase):
    def records(self):
        return {'':{'path':'','kind':'directory','mode':0o700,'uid':0,'gid':0,'links':7,'xattrs':{}},
            'file':{'path':'file','kind':'file','mode':0o640,'uid':10006,'gid':10006,'links':2,'size':4,'sha256':'a'*64,'xattrs':{}}}
    def test_backend_directory_count_and_unpack_umask_do_not_change_image(self):
        expected=self.records();actual=self.records();actual['']['mode']=0o755;actual['']['links']=1
        result=compare_image_entries(expected,actual,{'mode':0o755})
        self.assertTrue(result['equivalent']);self.assertEqual(result['directoryLinkCounterDifferences'],1)
        self.assertEqual(expected['']['mode'],0o700)
    def test_file_or_security_metadata_drift_is_never_normalized(self):
        for key,value in [('links',1),('sha256','b'*64),('mode',0o666),('uid',0),('xattrs',{'user.x':'bad'})]:
            with self.subTest(key=key):
                expected=self.records();actual=self.records();actual['file'][key]=value
                self.assertFalse(compare_image_entries(expected,actual,{'mode':0o700})['equivalent'])
    def test_wrong_root_mode_is_denied(self):
        self.assertFalse(compare_image_entries(self.records(),self.records(),{'mode':0o755})['equivalent'])
    def test_last_explicit_layer_root_mode_wins_and_absent_root_defaults(self):
        with tempfile.TemporaryDirectory() as temp:
            files=[]
            for i,mode in enumerate((None,0o710,0o750)):
                path=Path(temp)/str(i);files.append(path)
                with tarfile.open(path,'w') as tar:
                    if mode is not None:
                        item=tarfile.TarInfo('.');item.type=tarfile.DIRTYPE;item.mode=mode;tar.addfile(item)
                    item=tarfile.TarInfo('file');item.size=1;tar.addfile(item,io.BytesIO(b'x'))
            self.assertEqual(layer_root_mode(files[:1])['mode'],0o755)
            self.assertEqual(layer_root_mode(files)['mode'],0o750)

if __name__=='__main__':unittest.main()
