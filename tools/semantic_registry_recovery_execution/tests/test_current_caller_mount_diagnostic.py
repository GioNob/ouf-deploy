import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('caller_mount_diagnostic',ROOT/'scripts/inspect-registry-current-caller-mount-20261023.py')
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

class MountDiagnostic(unittest.TestCase):
    def profile(self):return {'tokenTarget':'/run/auth/token','tokenSource':{'path':'/protected/auth/token'}}
    def test_file_bind_detected_without_printing_source(self):
        v={'Mounts':[{'Destination':'/run/auth/token','Source':'/protected/auth/token','RW':False}]}
        r=d.mount_shape(v,self.profile());self.assertTrue(r['exactFileMount']);self.assertFalse(r['parentDirectoryMount'])
        self.assertNotIn('/protected',str(r))
    def test_directory_bind_detected_and_source_resolved(self):
        v={'Mounts':[{'Destination':'/run/auth','Source':'/protected/auth','RW':False}]}
        r=d.mount_shape(v,self.profile());self.assertTrue(r['parentDirectoryMount']);self.assertTrue(r['sourcePathMatchesReviewed'])
    def test_shadowing_mount_must_be_selected(self):
        v={'Mounts':[{'Destination':'/run/auth','Source':'/protected/auth','RW':False},
                     {'Destination':'/run/auth/token','Source':'/wrong/token','RW':True}]}
        r=d.mount_shape(v,self.profile());self.assertFalse(r['sourcePathMatchesReviewed']);self.assertFalse(r['readOnlyMount'])
    def test_engine_only_four_allowlisted_container_gets(self):
        class Stub:
            def __init__(self):self.calls=[]
            def request(self,m,p):self.calls.append((m,p));return 200,{'Id':p.split('/')[-2]}
        stub=Stub();a,b='a'*64,'b'*64;e=d.DiagnosticEngine(stub,(a,b))
        for cid in(a,b,a,b):e.get(cid)
        with self.assertRaisesRegex(ValueError,'FOUR_EXACT'):e.get(a)
        with self.assertRaisesRegex(ValueError,'FOUR_EXACT'):e.get('c'*64)
        self.assertEqual(len(stub.calls),4);self.assertEqual({m for m,p in stub.calls},{'GET'})
    def test_failed_read_is_consumed_not_retried(self):
        class Stub:
            def request(self,m,p):raise TimeoutError()
        e=d.DiagnosticEngine(Stub(),('a'*64,'b'*64))
        with self.assertRaises(TimeoutError):e.get('a'*64)
        self.assertEqual(e.attempts,1)
    def test_bad_container_id_refused_before_engine(self):
        with self.assertRaisesRegex(ValueError,'TWO_EXACT'):d.DiagnosticEngine(None,('../escape','b'*64))
    def test_mounted_metadata_does_not_read_source_bytes(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);(root/'run/auth').mkdir(parents=True);token=root/'run/auth/token';token.write_bytes(b'fixture-private-value')
            original=d.os.open;read=d.os.read
            def redirected(path,*a,**kw):return original(root if path=='/proc/123/root'else path,*a,**kw)
            d.os.open=redirected;d.os.read=lambda *a:(_ for _ in()).throw(AssertionError('No data reads'))
            try:self.assertEqual(d.mounted_metadata(123,'/run/auth/token'),list(d.identity(token.stat())))
            finally:d.os.open=original;d.os.read=read

if __name__=='__main__':unittest.main()
