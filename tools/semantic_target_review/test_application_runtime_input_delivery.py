"""Both immutable source hashes must verify before any root input preparation."""
import subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
LAUNCH=HERE.parents[1]/'releases/application-runtime-input-preparation-20261010.sh'
if not LAUNCH.exists():LAUNCH=Path('application-runtime-input-preparation-20261010.sh')
TEXT=LAUNCH.read_text()
BOOTSTRAP=TEXT.split("sudo /usr/bin/python3 -I -B -c '",1)[1].split("\n' \"$OUF_INPUT_DIR",1)[0]
class Delivery(unittest.TestCase):
    def test_entrypoint_tamper_denied_before_execution(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);marker=d/'marker';p=d/'prepare.py';r=d/'reader.py'
            p.write_text('from pathlib import Path;Path('+repr(str(marker))+').touch()');r.write_text('bad source')
            result=subprocess.run([sys.executable,'-I','-B','-c',BOOTSTRAP,str(p),str(r)],capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertIn(b'OUF_APPLICATION_INPUT_DELIVERY_HASH_MISMATCH',result.stderr);self.assertFalse(marker.exists())
    def test_helper_tamper_denied_before_preparation(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);p=d/'prepare.py';r=d/'reader.py';p.write_bytes((HERE/'prepare_application_runtime_inputs.py').read_bytes());r.write_bytes(b'bad original reader')
            result=subprocess.run([sys.executable,'-I','-B','-c',BOOTSTRAP,str(p),str(r)],capture_output=True)
            self.assertNotEqual(result.returncode,0);self.assertIn(b'OUF_APPLICATION_INPUT_DELIVERY_HASH_MISMATCH',result.stderr);self.assertNotIn(b'OUF_APPLICATION_RUNTIME_INPUTS=',result.stdout)
    def test_launcher_is_pinned_and_not_a_cutover(self):
        subprocess.run(['bash','-n',str(LAUNCH)],check=True)
        self.assertIn('ref=f75a0a101bf675b1e009e7a6eef0f961575ff851',TEXT)
        self.assertIn('106b55746b26b2c3f2151bfc41f6496165f239f7d3735b8050b3fe3040da7fcc',TEXT)
        self.assertIn('b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf',TEXT)
        self.assertNotIn('systemctl',TEXT);self.assertNotIn('docker run',TEXT);self.assertNotIn('--apply',TEXT)
if __name__=='__main__':unittest.main()
