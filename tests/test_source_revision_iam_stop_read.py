import copy,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('history',ROOT/'scripts/read-source-revision-iam-stop-20261019.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Files(unittest.TestCase):
 def temporary(self):return tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent)))
 def put(self,path,value):
  path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(value if type(value)is bytes else m.encoded(value));path.chmod(0o600)
 def execution(self,root):
  prepared=root/'prepared';stopped=root/'stopped';case={'preparedPlanBinding':{'path':'/fixed/private','sha256':'a'*64}}
  for base in (prepared,stopped):
   base.mkdir(mode=0o700)
   for i in range(7):self.put(base/'gateway-compiler'/('file'+str(i)+'.py'),b'pass\n')
  review={'schema':'ouf.source-revision-candidate-review.v1','preparedPlanBinding':case['preparedPlanBinding'],'runtimeAuthorityIssued':False,'readyForExecution':False};self.put(stopped/'candidate-review.json',review)
  plan={'schema':'ouf.source-revision-native-update-plan.v1','authorityDirectory':str(stopped),'privateReviewBinding':{'path':str(stopped/'candidate-review.json'),'sha256':m.digest(review)},**{k:False for k in('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed')}};self.put(stopped/'prepared-plan.json',plan)
  return prepared,stopped,case
 def test_exact_nine_execution_files_and_refusal_of_unknown_authority_or_sources(self):
  for change in (None,'authority','compiler','emptydir','link','planbinding','reviewbinding','permission'):
   with self.subTest(change=change),self.temporary()as temp:
    prepared,stopped,case=self.execution(Path(temp))
    if change=='authority':self.put(stopped/'authority.json',{})
    if change=='compiler':self.put(stopped/'gateway-compiler/file0.py',b'changed')
    if change=='emptydir':(stopped/'gateway-compiler/unknown').mkdir(mode=0o700)
    if change=='link':(stopped/'gateway-compiler/file0.py').unlink();(stopped/'gateway-compiler/file0.py').symlink_to(stopped/'gateway-compiler/file1.py')
    if change=='permission':(stopped/'candidate-review.json').chmod(0o644)
    if change=='planbinding':
     row=json.loads((stopped/'prepared-plan.json').read_bytes());row['privateReviewBinding']['sha256']='0'*64;self.put(stopped/'prepared-plan.json',row)
    if change=='reviewbinding':
     row=json.loads((stopped/'candidate-review.json').read_bytes());row['preparedPlanBinding']['sha256']='0'*64;self.put(stopped/'candidate-review.json',row)
    if change:
     with self.assertRaises(ValueError):m.reconcile_execution(stopped,prepared,{},case)
    else:
     before={str(p):p.read_bytes()for p in Path(temp).rglob('*')if p.is_file()}
     result=m.reconcile_execution(stopped,prepared,{},case);self.assertEqual(result['contextFiles'],9);self.assertTrue(result['authorityAndLoginArtifactsAbsent'])
     self.assertEqual(before,{str(p):p.read_bytes()for p in Path(temp).rglob('*')if p.is_file()})
 def test_no_auth_or_mutation_imports_and_exact_target_pins(self):
  import ast
  tree=ast.parse((ROOT/'scripts/read-source-revision-iam-stop-20261019.py').read_bytes())
  imports={name.name for node in tree.body if isinstance(node,ast.Import) for name in node.names}
  self.assertEqual(imports,{'hashlib','json','os','signal','stat'})
  self.assertEqual(m.STOPPED.name,'source-revision-execution-tvc2ilnv');self.assertEqual(m.PREPARED.name,'source-revision-postboot-prepared-kfy691gh')
  self.assertEqual(m.RESULT,'90559c21350b737c591342163140477bcf42c7f4aa21f4819563c92b7e5ffed6')

if __name__=='__main__':unittest.main()
