"""The delivered shell must select exactly the qualified executable closure."""
import hashlib,json,re,runpy,subprocess,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Delivery(unittest.TestCase):
 def test_manifest_and_all_downloads_match_checked_in_source(self):
  manifest=ROOT/'releases/linked-property-update-code-20261017.json'
  raw=manifest.read_bytes();package=json.loads(raw)
  shell=(ROOT/'scripts/launch-linked-property-update-20261017.sh').read_text()
  embedded=shell.split("<<'PACKAGE'\n",1)[1].split('\nPACKAGE\n',1)[0]+'\n'
  self.assertEqual(embedded.encode(),raw)
  sha=hashlib.sha256(raw).hexdigest()
  self.assertIn("manifest_raw=read('package.json','"+sha+"')",shell)
  metadata=runpy.run_path(str(ROOT/'scripts/execute-linked-property-update-20261017.py'),run_name='metadata')
  downloads=re.findall(r"contents/([^?']+)\?ref=([0-9a-f]{40})' --jq \.content \| base64 --decode > \"\$ouf_stage/([^\"]+)\"",shell)
  expected={'execute.py':('scripts/execute-linked-property-update-20261017.py',package['executorSha256']),
   'runtime.py':('tools/linked_property_rollout/runtime.py',package['loaderSha256']),
   'case.json':('releases/linked-property-update-selection-20261017.json',package['caseSha256'])}
  self.assertEqual(set(metadata['OVERLAYS']),set(package['sourceHashes']))
  for module,(name,path)in metadata['OVERLAYS'].items():expected[name]=(path,package['sourceHashes'][module])
  self.assertEqual(len(downloads),len(expected));self.assertEqual({n for _,_,n in downloads},set(expected))
  for path,commit,name in downloads:
   self.assertEqual(commit,package['sourceCommit']);self.assertEqual(path,expected[name][0])
   actual=hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
   self.assertEqual(actual,expected[name][1],path)
   self.assertIn("'"+actual+"' \"$ouf_stage/"+name+'"',shell)
 def test_operator_shell_and_privileged_stage_compile(self):
  path=ROOT/'scripts/launch-linked-property-update-20261017.sh'
  subprocess.run(['bash','-n',str(path)],check=True,capture_output=True)
  stage=path.read_text().split("<<'ROOTPY' 2>&1 | tee \"$ouf_stage/run.log\"\n",1)[1].rsplit('\nROOTPY',1)[0]
  compile(stage,'<root-custody-stage>','exec')
