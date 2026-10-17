"""Delivery bytes and shell checks only; never invokes target bootstrap or sudo."""
import ast,hashlib,importlib.util,json,os,re,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Delivery(unittest.TestCase):
 def setUp(self):
  self.script=(ROOT/'scripts/launch-resolution-comparison-update-20261017.sh').read_text()
  self.package=json.loads((ROOT/'releases/resolution-comparison-update-code-package-20261017.json').read_bytes())
 def test_every_download_and_shell_checksum_matches_pinned_manifest(self):
  subprocess.run(['bash','-n',str(ROOT/'scripts/launch-resolution-comparison-update-20261017.sh')],check=True)
  rows=re.findall(r'contents/([^?\x27]+)\?ref=([0-9a-f]{40})\x27 --jq .content \| base64 --decode > "\$ouf_stage/([A-Za-z0-9_.-]+)"',self.script)
  self.assertEqual(len(rows),52);self.assertEqual(len({r[2]for r in rows}),52)
  with tempfile.TemporaryDirectory()as d:
   for path,ref,name in rows:
    if name!='package.json':self.assertEqual(ref,self.package['sourceCommit'])
    shutil.copyfile(ROOT/path,Path(d)/name)
   begin=self.script.index("printf '%s  %s\\n' \\");end=self.script.index('ouf_cache=',begin)
   command=self.script[begin:end];env={**os.environ,'ouf_stage':d}
   good=subprocess.run(['bash','-euo','pipefail','-c',command],env=env,capture_output=True);self.assertEqual(good.returncode,0,good.stderr.decode())
   (Path(d)/'comparison_entry.py').write_bytes(b'changed delivery bytes')
   bad=subprocess.run(['bash','-euo','pipefail','-c',command],env=env,capture_output=True);self.assertNotEqual(bad.returncode,0)
 def test_root_copy_uses_exact_executor_manifest_and_archive_argument(self):
  body=self.script.split("<<'ROOTPY'",1)[1].split('\n',1)[1].rsplit('\nROOTPY',1)[0];tree=ast.parse(body)
  assignments=[node for node in tree.body if isinstance(node,ast.Assign)and any(isinstance(t,ast.Attribute)and isinstance(t.value,ast.Name)and t.value.id=='sys'and t.attr=='argv'for t in node.targets)]
  self.assertEqual(len(assignments),1);argv=assignments[0].value;self.assertEqual(len(argv.elts),5)
  self.assertEqual(argv.elts[2].value,self.package['sourceCommit'])
  self.assertEqual(argv.elts[3].value,hashlib.sha256((ROOT/'releases/resolution-comparison-update-code-package-20261017.json').read_bytes()).hexdigest())
  self.assertIsInstance(argv.elts[4],ast.Call);self.assertEqual(argv.elts[4].args[0].id,'archive')
  self.assertIn('source=Path(sys.argv[1]);archive=Path(sys.argv[2])',body)
 def test_candidate_download_precedes_root_and_login_is_not_launched_by_shell(self):
  self.assertIn('9c6e549ea643fa20f76c0d61c9a2353219ccec23eff784f320db1ec68b617afb',self.script)
  self.assertLess(self.script.index('actions/artifacts/12105197726/zip'),self.script.index('sudo /usr/bin/python3'))
  self.assertNotIn('grant_type=',self.script);self.assertIn('command -v gh || true',self.script)
if __name__=='__main__':unittest.main()
