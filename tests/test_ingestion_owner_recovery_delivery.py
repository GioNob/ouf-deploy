import ast,base64,hashlib,json,subprocess,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
BUNDLE=HERE/'delivery-bundle.json'
if not BUNDLE.exists():BUNDLE=ROOT/'releases/ingestion-owner-recovery-bundle-20261019.json'
LAUNCH=HERE/'launch.sh'
if not LAUNCH.exists():LAUNCH=ROOT/'scripts/launch-ingestion-owner-recovery-20261019.sh'
class Delivery(unittest.TestCase):
 def setUp(self):self.raw=BUNDLE.read_bytes();self.value=json.loads(self.raw)
 def test_every_delivery_member_matches_qualified_repository_source_exactly(self):
  self.assertEqual(self.value['schema'],'ouf.ingestion-owner-recovery-delivery.v1');self.assertEqual(self.value['sourceCommit'],'948242095f031673df01338a3c1eb313fd3c64e6')
  names={'entry','authority','owner','native','login','reconcile','runtime','bootstrap','confirmation_patch','human_extension','prepare'}
  self.assertEqual(set(self.value['files']),names)
  for name,row in self.value['files'].items():
   raw=base64.b64decode(row['base64'],validate=True);self.assertEqual(hashlib.sha256(raw).hexdigest(),row['sha256']);compile(raw,'<qualified-'+name+'>','exec')
   local=HERE/(name+'.py')
   if local.exists():expected=local.read_bytes()
   else:
    path={'prepare':ROOT/'scripts/prepare-ingestion-owner-recovery.py','bootstrap':ROOT/'scripts/execute-ingestion-owner-recovery.py'}.get(name,ROOT/'tools/ingestion_owner_recovery'/(name+'.py'))
    expected=path.read_bytes()
   self.assertEqual(raw,expected,name)
  tree=ast.parse(base64.b64decode(self.value['files']['prepare']['base64']))
  declaration=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='NAMES'for t in n.targets))
  self.assertEqual(set(ast.literal_eval(declaration.value)),names)
 def test_launcher_checks_exact_blob_and_sha_before_sudo_and_compiles_root_wrapper(self):
  text=LAUNCH.read_text();subprocess.run(['bash','-n',str(LAUNCH)],check=True,capture_output=True)
  self.assertIn(hashlib.sha256(self.raw).hexdigest(),text)
  blob=hashlib.sha1(b'blob '+str(len(self.raw)).encode()+b'\0'+self.raw).hexdigest();self.assertIn('/git/blobs/'+blob,text)
  self.assertLess(text.index('ouf-gh-2.102.0'),text.index('command -v gh'));self.assertLess(text.index('sha256sum -c -'),text.index('sudo /usr/bin/python3'))
  marker="<<'OUF_OWNER_REFERENCE'";code=text.split(marker,1)[1].split('\n',1)[1].rsplit('\nOUF_OWNER_REFERENCE',1)[0]
  compile(code,'<authenticated-owner-reference-root-wrapper>','exec')
  self.assertIn("namespace['main'](delivery,'"+self.value['sourceCommit']+"')",code)
 def test_no_completed_or_runtime_rollout_entrypoint_in_delivery(self):
  text=LAUNCH.read_text()
  for forbidden in('launch-installation-route-reconcile','launch-ingestion-read-owner-draft','docker restart','docker run','systemctl','APPROVO BUDGET264'):
   self.assertNotIn(forbidden,text)
  self.assertIn('APPROVO BUDGET288',text);self.assertIn('LOGIN COMPLETATO',text)
if __name__=='__main__':unittest.main()
