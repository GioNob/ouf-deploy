import importlib.util, json, os, shutil, subprocess, tempfile, unittest
from pathlib import Path
MODULE=Path(__file__).resolve().parents[1]/"scripts/privileged-discovery-preflight.py"
spec=importlib.util.spec_from_file_location("preflight",MODULE)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(tempfile.mkdtemp(prefix="ouf-preflight-ci-",dir="/run"))
        self.root.chmod(0o700)
    def tearDown(self):shutil.rmtree(self.root)
    def receipt(self):
        p=self.root/"stage-receipt.json"
        p.write_text(json.dumps({"startAuthorized":False,"notReleaseAcceptance":True,"clientSecret":"FIXTURE_CANARY_MUST_NOT_APPEAR"}))
        p.chmod(0o600);return p
    def test_redacts_other_fields(self):
        result=m.read_receipt(self.receipt())
        self.assertEqual(result["flags"],{"startAuthorized":False,"notReleaseAcceptance":True})
        self.assertNotIn("CANARY",json.dumps(result))
    def test_rejects_symlink(self):
        p=self.receipt();link=self.root/"linked.json";link.symlink_to(p)
        with self.assertRaises(OSError):m.read_receipt(link)
    def test_rejects_open_permissions(self):
        p=self.receipt();p.chmod(0o644)
        with self.assertRaises(ValueError):m.read_receipt(p)
    def test_rejects_unsafe_ancestor(self):
        p=self.receipt();self.root.chmod(0o770)
        with self.assertRaises(ValueError):m.read_receipt(p)
    def test_no_arguments_contract(self):
        result=subprocess.run(["/usr/bin/python3","-I","-B",str(MODULE),"unexpected"],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("ROOT_AND_NO_ARGUMENTS_REQUIRED",result.stdout)
    def test_bounded_sudo_rule_parses(self):
        p=self.root/"sudo-rule"
        p.write_text('oufadmin ALL=(root) NOPASSWD: /usr/local/sbin/ouf-discovery-preflight ""\n');p.chmod(0o440)
        result=subprocess.run(["/usr/sbin/visudo","--check","--file",str(p)],capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr.decode())
if __name__=="__main__":unittest.main()
