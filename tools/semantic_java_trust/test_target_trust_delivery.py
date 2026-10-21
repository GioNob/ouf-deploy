import hashlib,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
LAUNCH=HERE.parents[1]/'releases/application-java-trust-preparation-20261010.sh'
if not LAUNCH.exists():LAUNCH=Path('application-java-trust-preparation-20261010.sh')
TEXT=LAUNCH.read_text();BOOTSTRAP=TEXT.split("sudo /usr/bin/python3 -I -B -c '\n",1)[1].split("\n' ",1)[0]
FILES=[HERE/'prepare_target_trust.py',HERE.parent/'semantic_target_review/prepare_application_runtime_inputs.py',HERE.parent/'semantic_target_review/read_cutover_inputs.py',HERE/'merge_public_roots.py']
if not FILES[2].exists():FILES[2]=Path('read_cutover_inputs.py')
class Delivery(unittest.TestCase):
    def test_every_tampered_source_is_rejected_before_root_preparation(self):
        for index in range(4):
            with self.subTest(index=index),tempfile.TemporaryDirectory() as d:
                paths=[]
                for i,source in enumerate(FILES):
                    p=Path(d)/str(i);p.write_bytes(b'tampered' if i==index else source.read_bytes());paths.append(str(p))
                result=subprocess.run([sys.executable,'-I','-B','-c',BOOTSTRAP,*paths],capture_output=True)
                self.assertNotEqual(result.returncode,0);self.assertIn(b'OUF_JAVA_TRUST_SOURCE_HASH_MISMATCH',result.stderr);self.assertNotIn(b'OUF_APPLICATION_JAVA_TRUST=',result.stdout)
    def test_exact_source_count_and_shell_delivery(self):
        result=subprocess.run([sys.executable,'-I','-B','-c',BOOTSTRAP],capture_output=True)
        self.assertIn(b'OUF_JAVA_TRUST_EXACT_SOURCE_SET_REQUIRED',result.stderr)
        subprocess.run(['bash','-n',str(LAUNCH)],check=True)
        self.assertIn('ref=f25e205b5fe812780cd421a9a742e592268d32b9',TEXT)
        for source in FILES:self.assertIn(hashlib.sha256(source.read_bytes()).hexdigest(),TEXT)
        self.assertNotIn('systemctl restart',TEXT);self.assertNotIn('docker load',TEXT)
if __name__=='__main__':unittest.main()
