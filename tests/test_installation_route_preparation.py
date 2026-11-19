import gzip,io,tarfile,zipfile
import ast,base64,hashlib,importlib.util,json,os,subprocess,time,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;PACKAGE=HERE
if not(PACKAGE/'prepare.py').exists():PACKAGE=ROOT/'tools/installation_route_reconcile'
PREPARE=HERE/'prepare.py'
if not PREPARE.exists():PREPARE=ROOT/'scripts/prepare-installation-route-reconcile.py'
try:import test_installation_binding_custody_stop as fixture
except ModuleNotFoundError:
 spec=importlib.util.spec_from_file_location('custody_fixture',ROOT/'installation_binding_apply/custody_stop/test_read.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
LEGACY=ROOT/'tools/installation_binding_apply/runtime.py'
if not LEGACY.exists():LEGACY=ROOT/'installation_binding_apply/runtime.py'
spec=importlib.util.spec_from_file_location('legacy219',LEGACY);legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
BUDGET_FIXTURES=HERE/'fixtures'
if not(BUDGET_FIXTURES/'human_source.py').exists():BUDGET_FIXTURES=ROOT/'tests/fixtures/installation-route-budget264'
class Preparation(fixture.Read):
 def setup_package(self):
  hb={'sessionDirectory':str(self.root/'semantic-token-execution-fixture'/'human-installation-binding-reauth251-c0f7490ebe641e8a015e09799f6812eb1caf870388f1776a140a34a189cb11c1'),
   'expiresAt':1792436155,'createdAt':1792428955,'scopes':['scope'+str(i)for i in range(11)],'retryProfile':{'maximumAttempts':256}}
  hd=Path(hb['sessionDirectory']);hd.parent.mkdir(mode=0o700);hd.mkdir(mode=0o700);hb['tokenPath']=str(hd/'human-access.jwt')
  review={'schema':'ouf.human-explicit-test-continuation-review.v3','priorOAuthAttempts':251,'maximumCumulativeOAuthAttempts':256,'budgetReset':False}
  self.hreview=fixture.m.digest(review);decision={'reviewHash':self.hreview,'approvedAt':1792428955,'expiresAt':1792436155}
  boot_path=Path('/proc/sys/kernel/random/boot_id');boot=boot_path.read_text().strip()if boot_path.exists()else'fixture-boot'
  self.hpath=hd/'recovery.json';self.write(self.hpath,{'schema':'ouf.chatbot-human-session.private.v1','binding':hb,'attempts':255,'budgetReset':False,'bootId':boot,
   'state':'READY','lastObservedAt':1792429999.,'monotonicDeadline':time.monotonic()+7200,'accessExpiresAt':1792429331,'refreshToken':'NEVER_READ_OR_REPLAY',
   'governedWindowRenewal':{'review':review,'decision':decision}})
  self.p1['humanBinding']=hb;self.p2['humanBinding']=hb;self.p1['logicalRef']=fixture.m.digest(str(self.first));self.p2['logicalRef']=fixture.m.digest(str(self.second))
  sources={name:b'raise RuntimeError("RETAINED_MAIN_MUST_NOT_RUN")\n'for name in legacy.MODULES}
  gateway=self.gateway
  if not self.native_uid:gateway=gateway.replace(': (1000, 1000, 0o750)',': (0, 0, 0o750)')
  sources['tools.chatbot_file_cohort.gateway']=gateway.encode()
  tree=ast.parse((BUDGET_FIXTURES/'human_source.py').read_bytes());frozen=next(n for n in ast.walk(ast.parse((BUDGET_FIXTURES/'frozen_guard_fixture.py').read_bytes()))if isinstance(n,ast.FunctionDef)and n.name=='_check_identity_and_budget')
  human=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='HumanSession');human.body=[frozen if isinstance(n,ast.FunctionDef)and n.name=='_check_identity_and_budget'else n for n in human.body]
  sources['tools.chatbot_file_cohort.human_session']=ast.unparse(ast.fix_missing_locations(tree)).encode()
  closure={'declaration':{'moduleCount':219,'entryModule':'tools.installation_binding_apply.entry','sourceHashes':{k:fixture.m.sha(v)for k,v in sources.items()}}};self.closure=fixture.m.digest(closure)
  source_raw=fixture.m.encoded({k:base64.b64encode(v).decode()for k,v in sources.items()})
  original=self.root/'original.json';self.write(original,{'authorization':{'plan':{'selection':{'fixture':'retained'}}}})
  case={'originalBinding':{'path':str(original),'sha256':fixture.m.sha(original.read_bytes())}}
  members={'case.json':fixture.m.encoded(case),'bootstrap.py':b'raise RuntimeError("OLD_BOOTSTRAP_MUST_NOT_RUN")\n','runtime.py':LEGACY.read_bytes(),
   'reader.py':b'raise RuntimeError("OLD_READER_MUST_NOT_RUN")\n','sources.json':source_raw}
  for name,raw in members.items():self.raw(self.first/name,raw)
  package={'schema':'ouf.mcp-ingestion-read-transport-package.v1','sourceCommit':fixture.m.SOURCE,'closure':closure,'declarationHash':fixture.m.digest(closure['declaration']),
   'sourcePins':{'ouf-deploy':fixture.m.SOURCE,'ouf-onboarding':'b0f5e3dacbe59ebf87e22dd6af2575e41249f51d','ouf-mcp-server':'1f2c28d7abadae78680b040ba7b58be62ef85ee9'},
   'fileHashes':{n:fixture.m.sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
  self.package=fixture.m.digest(package);self.write(self.first/'package.json',package);self.write(self.first/'runtime.claim.json',{'packageHash':self.package,'automaticReplayAllowed':False})
  self.r1=self.scope(self.first,self.p1,6,False);self.r2=self.scope(self.second,self.p2,1,True)
  self.actual_custody={'parents':{str(self.ouf):(1000 if self.native_uid else 0,1000 if self.native_uid else 0,0o750),str(self.directory):(0,0,0o700)},'file':(0,0,0o600)}
 def child(self):
  values={'FIRST':str(self.first),'PACKAGE':self.package,'CLOSURE':self.closure,'OWNER_REVIEW':self.r1,'ROUTE_REVIEW':self.r2,'EXPORT':self.export,'ACTIVE_PATH':str(self.profile),'APPROVED_CUSTODY':self.actual_custody,'HUMAN_REVIEW':self.hreview}
  code='''import ast,json,sys\nfrom pathlib import Path\np={"__name__":"qualified_route_preparer"};exec(compile(Path(sys.argv[1]).read_bytes(),sys.argv[1],"exec"),p)\nroot=Path(sys.argv[2]);vals=json.loads(sys.argv[3]);vals["APPROVED_CUSTODY"]={"parents":{k:tuple(v)for k,v in vals["APPROVED_CUSTODY"]["parents"].items()},"file":tuple(vals["APPROVED_CUSTODY"]["file"])};delivery={n:(root/(n+".py")).read_bytes()for n in p["NAMES"]}\ntree=ast.parse(delivery["reconcile"]);targets=set(vals)\nfor n in tree.body:\n if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id in targets:\n  k=n.targets[0].id;n.value=ast.parse("Path("+repr(vals[k])+")"if k=="FIRST"else repr(vals[k]),mode="eval").body\nraw=ast.unparse(ast.fix_missing_locations(tree))\nif not Path("/proc/sys/kernel/random/boot_id").exists():raw=raw.replace("Path('/proc/sys/kernel/random/boot_id').read_text().strip()",repr("fixture-boot"))\ndelivery["reconcile"]=raw.encode()\np["FROZEN_HUMAN_SOURCE_HASH"]=p["sha"](__import__("base64").b64decode(json.loads((Path(vals["FIRST"])/"sources.json").read_bytes())["tools.chatbot_file_cohort.human_session"]))\np["time"].time=lambda:1792430000.\ndef dispatched(*args):print("NEW_ROUTE_BOOTSTRAP_DISPATCH_REACHED",flush=True);raise SystemExit(0)\np["os"].execv=dispatched\np["main"](delivery,"a"*40)\n'''
  # Only fixture paths/package pins and the synthetic full-source hash are substituted.
  # The retained public method includes the exact target MCP compatibility branch.
  # Script paths are staged under their module aliases solely inside the isolated fixture.
  delivery=self.root/'delivery';delivery.mkdir(exist_ok=True,mode=0o700)
  for name in('entry','authority','owner','native','baseline','login','reconcile','runtime','human_extension'):(delivery/(name+'.py')).write_bytes((PACKAGE/(name+'.py')).read_bytes())
  (delivery/'prepare.py').write_bytes(PREPARE.read_bytes())
  bootstrap=HERE/'bootstrap.py'
  if not bootstrap.exists():bootstrap=ROOT/'scripts/execute-installation-route-reconcile.py'
  (delivery/'bootstrap.py').write_bytes(bootstrap.read_bytes())
  return subprocess.run(['/usr/bin/python3','-I','-B','-S','-',str(PREPARE),str(delivery),json.dumps(values)],input=code.encode(),capture_output=True,timeout=60)
 def test_actual_isolated226_preparation_preserves_history_and_denies_second_claim(self):
  self.setup_package();before={p:p.read_bytes()for d in(self.first,self.second)for p in d.iterdir()if not p.is_symlink()};human=self.hpath.read_bytes();result=self.child()
  self.assertEqual(result.returncode,0,(result.stdout+result.stderr).decode());self.assertIn(b'NEW_ROUTE_BOOTSTRAP_DISPATCH_REACHED',result.stdout);self.assertNotIn(b'NEVER_',result.stdout)
  self.assertTrue(all(p.read_bytes()==v for p,v in before.items()));self.assertEqual(self.hpath.read_bytes(),human)
  claims=list(self.root.glob('installation-route-reconcile-preparation-*.claim.json'));self.assertEqual(len(claims),1);context=Path(json.loads(claims[0].read_bytes())['context'])
  report=json.loads((context/'preparation-result.json').read_bytes());self.assertEqual(report['sourceModuleCount'],226);self.assertFalse(report['budgetChangeAuthorized']);self.assertEqual(report['oauthRequests'],0)
  self.assertFalse((context/'authority.json').exists());self.assertFalse((context/'runtime.claim.json').exists());self.assertFalse((self.hpath.parent/'successor-window.claim.json').exists())
  second=self.child();self.assertNotEqual(second.returncode,0);self.assertIn(b'ALREADY_PREPARED_NO_REPLAY',second.stderr)
 def test_changed_current_counter_blocks_before_preparation_claim(self):
  self.setup_package();row=json.loads(self.hpath.read_bytes());row['attempts']=256;self.write(self.hpath,row);result=self.child()
  self.assertNotEqual(result.returncode,0);self.assertEqual(list(self.root.glob('installation-route-reconcile-preparation-*.claim.json')),[])
 def test_full_source_pin_preserves_exact_prefix_and_rejects_any_byte_drift(self):
  ns={'__name__':'qualified_preparation_guard'};exec(compile(PREPARE.read_bytes(),str(PREPARE),'exec'),ns)
  self.assertEqual(ns['FROZEN_HUMAN_SOURCE_HASH'],'305c7804b084b02f0bf7d6c1521c3c5a4f8e7f4e2fb0a15e27f5886a2a685dcc')
  raw=(BUDGET_FIXTURES/'frozen_guard_fixture.py').read_bytes();self.assertIn(b'ouf.mcp-read-transport-human-reauthentication-review.v1',raw)
  ns['FROZEN_HUMAN_SOURCE_HASH']=ns['sha'](raw) # Synthetic fixture full-source pin only.
  extension=(PACKAGE/'human_extension.py').read_bytes()
  result=ns['extend_human'](raw,extension);self.assertEqual(result,raw+b'\n'+extension)
  for changed in(raw+b'\n# byte drift',raw.replace(b'== 217',b'== 218'),result):
   with self.subTest(changed=ns['sha'](changed)),self.assertRaisesRegex(ValueError,'EXACT_FROZEN256_PREDECESSOR_GUARD_REQUIRED'):ns['extend_human'](changed,extension)
def load_tests(loader,tests,pattern):return unittest.TestSuite(Preparation(n)for n in('test_actual_isolated226_preparation_preserves_history_and_denies_second_claim','test_changed_current_counter_blocks_before_preparation_claim','test_full_source_pin_preserves_exact_prefix_and_rejects_any_byte_drift'))
if __name__=='__main__':unittest.main()
