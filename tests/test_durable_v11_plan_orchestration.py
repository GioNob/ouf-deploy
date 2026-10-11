import contextlib,copy,io,json,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
from test_durable_v11_rebind import r,entry,fixture

class PlanOrchestration(unittest.TestCase):
 def run_plan(self,fault=None):
  with tempfile.TemporaryDirectory() as folder:
   base=Path(folder);d,c=fixture();raw=json.dumps(d).encode();calls={}
   def count(k):
    calls[k]=calls.get(k,0)+1;return calls[k]
   def observe(*args):
    n=count("observe")
    if fault=="ttl" and n==2:raise ValueError("CURRENT_FLOW_TTL_TOO_SHORT")
    result=dict(workerGenerationHash="g",authorizationHash="a",currentSemanticFrameHash=r.digest({"Id":"fixture"}),declarationHash=r.digest(d),refreshCount=100+n,workerPid=123,flows=[{"minRemainingTtlSeconds":15}])
    if n==2 and fault in ("workerGenerationHash","authorizationHash","currentSemanticFrameHash","declarationHash"):result[fault]="changed"
    return result
   native=b'SEMANTIC_ID="fixture"\nCONTEXT=__import__("pathlib").Path("/fixture")\nparse=__import__("json").loads\ndef private(path,*args):\n return b\'{ "configurationHash":"h", "commandBindings":{"docker":"fixture"} }\'\n'
   def file_bytes(path,*args,**kwargs):
    if str(path).endswith("reader.py"):return native
    n=count("declaration")
    return raw+b" " if fault=="declarationBytes" and n==2 else raw
   def config(*args,**kwargs):
    value=copy.deepcopy(c)
    if count("package")==2 and fault=="package":value["Env"].append("LANG=changed")
    return value
   def secret(*args):
    if count("secret")==2 and fault=="secret":raise ValueError("SECRET_CUSTODY_DRIFT")
   def compile_creation(d,*args):
    n=count("compile")
    return ({"Image":d["candidateImageId"],"fixture":False if fault=="request" and n==2 else True},{"status":"PLAN_ONLY"})
   def create(path,data):
    if count("write")==2 and fault=="write":raise OSError("fixture write failure")
    path.write_bytes(data)
   current={"Id":"fixture"}
   m=dict(reader=types.SimpleNamespace(observe=observe),
     planner=types.SimpleNamespace(DECLARATION=base/"old.json",DECLARATION_HASH=r.digest(d),verify_secret_custody=secret,current_host=lambda *args:{}),
     prepare=types.SimpleNamespace(R10=base,PROGRAMS={"reader.py":"h"},BASE=base,frame=lambda x:x,native=lambda *args:json.dumps([current])),
     custody=types.SimpleNamespace(file_bytes=file_bytes,create=create),
     creation=types.SimpleNamespace(digest=r.digest,encoded=lambda x:json.dumps(x).encode(),compile_creation=compile_creation),
     package=types.SimpleNamespace(package_config=config),rebind=r)
   output=io.StringIO()
   with patch.object(entry,"modules",return_value=m),patch.object(entry.os,"geteuid",return_value=0),patch.object(entry,"sys",types.SimpleNamespace(flags=types.SimpleNamespace(isolated=True),dont_write_bytecode=True,argv=["fixture"])),contextlib.redirect_stdout(output):
    code=entry.main()
   receipt=json.loads(output.getvalue().split("=",1)[1])
   files=list(base.glob("semantic-durable-v11-plan-*/*"))
   return code,receipt,[p.name for p in files],calls
 def test_success_publishes_four_new_private_drafts_with_no_apply_authority(self):
  code,receipt,files,calls=self.run_plan()
  self.assertEqual(code,0);self.assertEqual(receipt["protectedFileWrites"],4)
  self.assertEqual(set(files),{"private-runtime-declaration.json","creation-request.private.json","observation.private.json","receipt.json"})
  for key in ("productionApplyReady","applicationCutoverAuthorized","newClaimCreated","budgetReset","r12Touched"):self.assertFalse(receipt[key])
  for key in ("imageImports","containerLifecycleOperations","databaseWrites","providerCalls"):self.assertEqual(receipt[key],0)
 def test_all_final_drift_boundaries_publish_nothing(self):
  for fault in ("ttl","workerGenerationHash","authorizationHash","currentSemanticFrameHash","declarationHash","declarationBytes","package","secret","request"):
   with self.subTest(fault=fault):
    code,receipt,files,calls=self.run_plan(fault)
    self.assertEqual(code,1);self.assertEqual(receipt["protectedFileWrites"],0);self.assertEqual(files,[])
    self.assertNotIn("write",calls)
 def test_partial_new_draft_failure_retains_evidence_without_authority(self):
  code,receipt,files,calls=self.run_plan("write")
  self.assertEqual(code,1);self.assertEqual(receipt["protectedFileWrites"],1)
  self.assertEqual(files,["private-runtime-declaration.json"])
  self.assertEqual(receipt["phase"],"NEW_PRIVATE_DRAFT_PUBLICATION_NO_APPLY")
  self.assertFalse(receipt["productionApplyReady"]);self.assertFalse(receipt["newClaimCreated"])
if __name__=="__main__":unittest.main()
