import ast, importlib.util, json, os, shutil, stat, subprocess, tempfile, unittest
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
    def publisher(self):
        text=(MODULE.parent/"bootstrap-discovery-preflight.sh").read_text()
        body=text.split("<<'OUF_INSTALL'\n",1)[1].split("\nOUF_INSTALL",1)[0]
        nodes=[n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef) and n.name in ("ancestors","publish")]
        env=dict(os=os,stat=stat,Path=Path,tempfile=tempfile)
        exec(compile(ast.Module(body=nodes,type_ignores=[]),"bounded-installer","exec"),env)
        return env["publish"]
    def test_installer_publishes_complete_private_policy(self):
        path=self.root/"policy"
        raw=b"complete-policy-fixture"
        self.publisher()(path,raw,0o440)
        self.assertEqual(path.read_bytes(),raw)
        self.assertEqual(path.stat().st_mode & 0o777,0o440)
        self.assertEqual(path.stat().st_nlink,1)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),["policy"])
    def test_installer_preserves_existing_foreign_policy(self):
        path=self.root/"policy";path.write_bytes(b"existing-policy");path.chmod(0o440)
        with self.assertRaises(SystemExit):self.publisher()(path,b"changed-policy",0o440)
        self.assertEqual(path.read_bytes(),b"existing-policy")
if __name__=="__main__":unittest.main()
