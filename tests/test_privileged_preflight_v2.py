import ast, hashlib, importlib.util, json, os, shutil, stat, subprocess, tempfile, unittest
from pathlib import Path
MODULE=Path(__file__).resolve().parents[1]/"scripts/privileged-discovery-preflight-v2.py"
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
        text=(MODULE.parent/"upgrade-discovery-preflight-v2.sh").read_text()
        body=text.split("<<'OUF_INSTALL'\n",1)[1].split("\nOUF_INSTALL",1)[0]
        nodes=[n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef) and n.name in ("ancestors","publish")]
        env=dict(os=os,stat=stat,Path=Path,tempfile=tempfile,hashlib=hashlib)
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

    def test_installer_replaces_only_known_previous_hash(self):
        path=self.root/"helper";old=b"reviewed-old-helper";new=b"reviewed-new-helper"
        path.write_bytes(old);path.chmod(0o755)
        self.publisher()(path,new,0o755,previous_hash=hashlib.sha256(old).hexdigest())
        self.assertEqual(path.read_bytes(),new)
        self.assertEqual(path.stat().st_mode & 0o777,0o755)
        self.assertEqual(path.stat().st_nlink,1)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),["helper"])
    def test_installer_preserves_foreign_upgrade_and_hardlinks(self):
        path=self.root/"helper";path.write_bytes(b"foreign");path.chmod(0o755)
        with self.assertRaises(SystemExit):self.publisher()(path,b"new",0o755,previous_hash="a"*64)
        self.assertEqual(path.read_bytes(),b"foreign")
        alias=self.root/"alias";os.link(path,alias)
        with self.assertRaises(SystemExit):self.publisher()(path,b"new",0o755,previous_hash=hashlib.sha256(b"foreign").hexdigest())
        self.assertEqual(path.read_bytes(),b"foreign")
    def test_runtime_receipt_drift_denies_before_loading_any_installer(self):
        from unittest.mock import patch
        with patch.object(m,"private_receipt_data",return_value=(b"changed",{})),patch.object(m,"runtime_installer") as load:
            with self.assertRaises(ValueError):m.selected_runtime_readiness()
            load.assert_not_called()
    def test_native_inventory_matches_reviewed_owner_functions(self):
        owner=Path(__file__).resolve().parents[1]/"gateway-source/scripts/inventory_semantic_runtime_readiness.py"
        expected=ast.parse(owner.read_text())
        actual=ast.parse(MODULE.read_text())
        for native,bounded in (("installer","runtime_installer"),("collect","runtime_collect")):
            a=next(n for n in expected.body if isinstance(n,ast.FunctionDef) and n.name==native)
            b=next(n for n in actual.body if isinstance(n,ast.FunctionDef) and n.name==bounded)
            b.name=native
            self.assertEqual(ast.dump(a,include_attributes=False),ast.dump(b,include_attributes=False))

if __name__=="__main__":unittest.main()

