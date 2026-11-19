import hashlib,json,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Delivery(unittest.TestCase):
 def test_manifest_and_preparer_match_qualified_source_commit(self):
  files={'prepare.py':'scripts/prepare-source-revision-governed-continuation.py','authorization.py':'tools/source_revision_update/governed_authorization.py','entry.py':'tools/source_revision_update/governed_entry.py','login.py':'tools/source_revision_update/governed_login.py'}
  manifest={'schema':'ouf.source-revision-governed-code.v1','sourceCommit':'0dff945d5798856a67f3fa742662a9f2fde37a3c','files':{k:hashlib.sha256((ROOT/v).read_bytes()).hexdigest()for k,v in files.items()}}
  self.assertEqual(hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'2c106bf3456a42de6024980379af2f9ebc0e3d8f56cf94e928f471e72b1a7ac4')
  launcher=(ROOT/'scripts/launch-source-revision-governed-20261019.sh').read_text();self.assertIn(manifest['files']['prepare.py'],launcher)
  self.assertIn('ouf-source-revision-governed-code-39203223055',launcher)
 def exercise(self,tamper):
  text=(ROOT/'scripts/launch-source-revision-governed-20261019.sh').read_text();payload=text.split("<<'OUF_GOVERNED_CONTINUATION' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_GOVERNED_CONTINUATION',1)[0]
  with tempfile.TemporaryDirectory()as temp:
   stage=Path(temp);(stage/'prepare.py').write_bytes(b'print("PRIVATE_CANARY")'if tamper else(ROOT/'scripts/prepare-source-revision-governed-continuation.py').read_bytes())
   harness='''import os,sys,json
payload,stage=sys.argv[1:];original=os.open;reads=[]
def checked(path,*args,**kwargs):
 if str(path).endswith('/manifest.json'):
  reads.append(str(path));raise RuntimeError('PRIVATE_CANARY')
 return original(path,*args,**kwargs)
os.open=checked;sys.argv=['delivery',stage,'2c106bf3456a42de6024980379af2f9ebc0e3d8f56cf94e928f471e72b1a7ac4']
try:exec(compile(payload,'<exact-root-shim>','exec'),{'__name__':'__main__'})
except SystemExit as error:print(json.dumps({'fixtureExit':error.code,'stageReads':len(reads)}))
'''
   result=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,payload,str(stage)],capture_output=True,timeout=20);self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stderr,b'');self.assertNotIn(b'PRIVATE_CANARY',result.stdout);rows=[json.loads(line)for line in result.stdout.splitlines()];self.assertEqual(rows[-1]['stageReads'],0 if tamper else 1)
   if not tamper:self.assertFalse(rows[0]['complete']);self.assertTrue(rows[0]['reconciliationRequired']);self.assertEqual(rows[-1]['fixtureExit'],2)
 def test_tampered_delivery_stops_before_any_manifest_or_private_read(self):self.exercise(True)
 def test_exact_root_shim_reaches_first_stage_check_only(self):self.exercise(False)
if __name__=='__main__':unittest.main()
