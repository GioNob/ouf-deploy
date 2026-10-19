import hashlib,json,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Delivery(unittest.TestCase):
 def test_manifest_and_preparer_match_qualified_source_commit(self):
  files={'prepare.py':'scripts/prepare-ingestion-read-authorization.py','bootstrap.py':'scripts/execute-ingestion-read-authorization.py','reader.py':'scripts/read-source-revision-completed-20261019.py','selection.json':'releases/ingestion-read-administrative-installation-20261019.json'}
  files.update({name+'.py':'tools/ingestion_read_authorization/'+name+'.py' for name in ('entry','authority','authorization','login','iam','runtime')})
  manifest={'schema':'ouf.ingestion-read-administrative-code.v1','sourceCommit':'a47e3edef6bba579d0df05859cc9eb7d8f8ca17d','installationSpecific':True,'runtimeAuthorityIssued':False,'privateInputsRead':False,'files':{k:hashlib.sha256((ROOT/v).read_bytes()).hexdigest()for k,v in files.items()}}
  self.assertEqual(hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'6462f6f506dee6904123fcc94975b16727476d482969f5020f03d43ddb69e09c')
  launcher=(ROOT/'scripts/launch-ingestion-human-administration-20261019.sh').read_text();self.assertIn(manifest['files']['prepare.py'],launcher)
  self.assertIn('ouf-ingestion-read-administrative-code-39221983431',launcher)
 def exercise(self,tamper):
  text=(ROOT/'scripts/launch-ingestion-human-administration-20261019.sh').read_text();payload=text.split("<<'OUF_INGESTION_ADMIN' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_INGESTION_ADMIN',1)[0]
  with tempfile.TemporaryDirectory()as temp:
   stage=Path(temp);(stage/'prepare.py').write_bytes(b'print("PRIVATE_CANARY")'if tamper else(ROOT/'scripts/prepare-ingestion-read-authorization.py').read_bytes())
   harness='''import os,sys,json
payload,stage=sys.argv[1:];original=os.open;reads=[]
def checked(path,*args,**kwargs):
 if str(path).endswith('/manifest.json'):
  reads.append(str(path));raise RuntimeError('PRIVATE_CANARY')
 return original(path,*args,**kwargs)
os.open=checked;sys.argv=['delivery',stage,'6462f6f506dee6904123fcc94975b16727476d482969f5020f03d43ddb69e09c']
try:exec(compile(payload,'<exact-root-shim>','exec'),{'__name__':'__main__'})
except SystemExit as error:print(json.dumps({'fixtureExit':error.code,'stageReads':len(reads)}))
'''
   result=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,payload,str(stage)],capture_output=True,timeout=20);self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stderr,b'');self.assertNotIn(b'PRIVATE_CANARY',result.stdout);rows=[json.loads(line)for line in result.stdout.splitlines()];self.assertEqual(rows[-1]['stageReads'],0 if tamper else 1)
   if not tamper:self.assertEqual(rows[0]['status'],'STOP_RECONCILE');self.assertFalse(rows[0]['automaticReplayAllowed']);self.assertEqual(rows[-1]['fixtureExit'],2)
 def test_tampered_delivery_stops_before_any_manifest_or_private_read(self):self.exercise(True)
 def test_exact_root_shim_reaches_first_stage_check_only(self):self.exercise(False)
if __name__=='__main__':unittest.main()

