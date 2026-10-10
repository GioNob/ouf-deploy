"""Immutable delivery and root-side hash checks precede source execution."""
import importlib.util, subprocess, sys, tempfile, unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('delivery',HERE/'try_current_r9_transition.py')
delivery=importlib.util.module_from_spec(spec);spec.loader.exec_module(delivery)
class Delivery(unittest.TestCase):
    def test_tampered_entrypoint_cannot_execute(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);marker=root/'marker';p=root/'read.py';r=root/'reader.py'
            p.write_text('from pathlib import Path;Path('+repr(str(marker))+').write_text("executed")');r.write_bytes(b'bad reader')
            result=subprocess.run([sys.executable,'-I','-B','-c',delivery.BOOTSTRAP,str(p),str(r)],capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertIn(b'OUF_R9_READ_DELIVERY_HASH_MISMATCH',result.stderr);self.assertFalse(marker.exists())
    def test_tampered_original_reader_cannot_reach_root_collect(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);p=root/'read.py';r=root/'reader.py';p.write_bytes((HERE/'read_current_r9_transition.py').read_bytes());r.write_bytes(b'bad original source')
            result=subprocess.run([sys.executable,'-I','-B','-c',delivery.BOOTSTRAP,str(p),str(r)],capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertIn(b'OUF_R9_READ_DELIVERY_HASH_MISMATCH',result.stderr);self.assertNotIn(b'OUF_CURRENT_R9_TRANSITION_READ=',result.stdout)
    def test_launcher_binds_commit_both_hashes_and_verified_memory(self):
        path=HERE.parents[1]/'releases/current-r9-transition-read-20261010.sh'
        if not path.exists():path=Path('current-r9-transition-read-20261010.sh')
        text=path.read_text();subprocess.run(['bash','-n',str(path)],check=True)
        self.assertIn('ref=f44dae25b77d7e7ff1df59550cc5d3e5fd37d8fe',text)
        self.assertIn(delivery.READ_HASH,text);self.assertIn(delivery.READER_HASH,text);self.assertIn(delivery.BOOTSTRAP,text)
        self.assertIn('sudo /usr/bin/python3 -I -B -c',text);self.assertNotIn('--apply',text);self.assertNotIn('systemctl restart',text)
if __name__=='__main__':unittest.main()
