"""Actual archive/JAR custody and isolated213 preparation with one real Engine GET."""
import base64,copy,hashlib,importlib.util,io,json,os,socket,stat,subprocess,sys,tarfile,tempfile,threading,time,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from tools.installation_binding_plan import runtime as prior_loader
SCRIPT=ROOT/'scripts/prepare-installation-owner-update.py'
spec=importlib.util.spec_from_file_location('owner_preparation',SCRIPT);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
SQL=b'create table governed_fixture (id bigint);\n'
MIG={'src/main/resources/db/migration/V1__fixture.sql':hashlib.sha1(b'blob '+str(len(SQL)).encode()+b'\0'+SQL).hexdigest()}
def jar(sql=SQL):
 stream=io.BytesIO()
 with zipfile.ZipFile(stream,'w')as archive:archive.writestr(zipfile.ZipInfo('BOOT-INF/classes/db/migration/V1__fixture.sql',(2026,10,19,0,0,0)),sql)
 return stream.getvalue()
def layer(jar_bytes,link=False,whiteout=False):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w')as archive:
  directory=tarfile.TarInfo('app');directory.type=tarfile.DIRTYPE;archive.addfile(directory)
  info=tarfile.TarInfo('app/application.jar')
  if link:info.type=tarfile.SYMTYPE;info.linkname='/outside/application.jar';archive.addfile(info)
  else:info.size=len(jar_bytes);archive.addfile(info,io.BytesIO(jar_bytes))
  if whiteout:info=tarfile.TarInfo('app/.wh.application.jar');archive.addfile(info,io.BytesIO())
 return out.getvalue()
def image(jar_bytes):
 content=layer(jar_bytes);config=p.encoded({'architecture':'amd64','os':'linux','config':{'Labels':{'org.opencontainers.image.revision':p.SOURCE},'User':'10003:10003','Entrypoint':['java','-jar','/app/application.jar']},'rootfs':{'type':'layers','diff_ids':['sha256:'+p.sha(content)]}})
 manifest=p.encoded([{'Config':'config.json','Layers':['layer.tar'],'RepoTags':['fixture:one']}]);output=io.BytesIO()
 with tarfile.open(fileobj=output,mode='w')as archive:
  for name,raw in(('manifest.json',manifest),('config.json',config),('layer.tar',content)):
   item=tarfile.TarInfo(name);item.size=len(raw);archive.addfile(item,io.BytesIO(raw))
 return output.getvalue(),'sha256:'+p.sha(config)
class MigrationCustody(unittest.TestCase):
 def test_actual_zip_migrations_match_installed_git_blob_bytes_and_image_jar_hash(self):
  raw=jar()
  with patch.object(p,'MIGRATIONS',MIG):
   result=p.migration_proof(raw,{'truncated':False,'tree':[{'path':k,'sha':v}for k,v in MIG.items()]},p.sha(raw))
   self.assertTrue(result['migrationFilesUnchanged']);self.assertTrue(result['imageJarBound']);self.assertEqual(result['migrationFileCount'],1)
 def test_changed_migration_truncated_tree_or_other_image_jar_denied(self):
  with patch.object(p,'MIGRATIONS',MIG):
   for raw,inventory,wanted in((jar(b'changed'),{'truncated':False,'tree':[{'path':k,'sha':v}for k,v in MIG.items()]},p.sha(jar(b'changed'))),
       (jar(),{'truncated':True,'tree':[]},p.sha(jar())),(jar(),{'truncated':False,'tree':[]},'0'*64)):
    with self.subTest(wanted=wanted),self.assertRaises(Exception):p.migration_proof(raw,inventory,wanted)
 def test_jar_layer_symlink_or_later_whiteout_cannot_prove_runtime_bytes(self):
  with tempfile.TemporaryDirectory()as directory:
   for link,whiteout in((False,False),(True,False),(False,True)):
    path=Path(directory)/'image.tar';payload=layer(jar(),link,whiteout)
    with tarfile.open(path,mode='w')as archive:
     item=tarfile.TarInfo('layer.tar');item.size=len(payload);archive.addfile(item,io.BytesIO(payload))
    if not link and not whiteout:self.assertEqual(p.image_jar_hash(path,{'layerMembers':['layer.tar']}),p.sha(jar()))
    else:
     with self.assertRaises(Exception):p.image_jar_hash(path,{'layerMembers':['layer.tar']})

class IsolatedPreparation(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)));self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.completed=self.root/'completed209';self.completed.mkdir(mode=0o700);self.human=self.root/'human';self.human.mkdir(mode=0o700);self.stage=self.root/'stage';self.stage.mkdir(mode=0o700)
  self.binding={'sessionDirectory':str(self.human),'expiresAt':1792425259,'scopes':['fixture']}
  self.row={'binding':self.binding,'state':'READY','attempts':243,'budgetReset':False,'lastObservedAt':1792418999};self.write(self.human/'recovery.json',self.row)
  # Only the standalone retained Engine and image custody modules execute during preparation.
  sources={n:b'pass\n'for n in prior_loader.MODULES}
  for name in('engine_creation','image_custody'):sources[name]=(ROOT/'tools/semantic_application_cutover'/(name+'.py')).read_bytes()
  self.server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket=self.root/'e.sock';self.server.bind(str(self.socket));self.socket.chmod(0o600);self.server.listen(1);self.server.settimeout(15);self.addCleanup(self.server.close)
  info=self.socket.stat();socket_binding=[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]
  old={'engine':{'socketPath':str(self.socket),'socketBinding':socket_binding},'replacements':{'onboarding':{'imageAudit':{}}}}
  old_path=self.root/'old.json';self.write(old_path,old)
  self.case={'installedPlanBinding':{'path':str(old_path),'sha256':p.digest(old)}}
  old_runtime=(ROOT/'tools/installation_binding_plan/runtime.py').read_bytes()
  members={'case.json':p.encoded(self.case),'sources.json':p.encoded({n:base64.b64encode(raw).decode()for n,raw in sources.items()}),'runtime.py':old_runtime,'bootstrap.py':b'raise RuntimeError("NO_OLD_BOOTSTRAP")\n','reader.py':b'raise RuntimeError("NO_OLD_READER")\n'}
  closure={'declaration':{'moduleCount':209,'entryModule':'tools.installation_binding_plan.entry','sourceHashes':{n:p.sha(raw)for n,raw in sources.items()},'loaderHash':p.sha(old_runtime)},'executables':{},'stdlibHash':'b'*64,'stdlibFileCount':0}
  package={'schema':'ouf.mcp-ingestion-read-transport-package.v1','sourceCommit':'7e0eddca54df18b3b01f5059b19feea50b7b645b','closure':closure,'declarationHash':p.digest(closure['declaration']),
   'sourcePins':{'ouf-deploy':'7e0eddca54df18b3b01f5059b19feea50b7b645b','ouf-onboarding':p.OLD_SOURCE,'ouf-mcp-server':'1f2c28d7abadae78680b040ba7b58be62ef85ee9'},'fileHashes':{n:p.sha(raw)for n,raw in members.items()}}
  self.plan={'bindings':{'sourceClosureHash':p.digest(closure),'humanBinding':self.binding},'ownerApplyAuthorized':False,'installationActivationAllowed':False,'gatewayWritesAllowed':False,'atomicOwnerActivePreconditionSupportProven':False};self.plan_hash=p.digest(self.plan)
  report={'schema':'ouf.installation-ingestion-binding-planning-result.v1','complete':True,'planHash':self.plan_hash,'contextPath':str(self.completed),'expectedActiveRevision':5,
   'sourcePayloadChecksum':'e9bea44bf977b17c94d9a9d1a1f2f2ddfff188360df3dbe11d20ee31460298b4','candidatePayloadChecksum':'ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98',
   'oauthAttemptsAfter':243,'ownerApplyAuthorized':False,'ownerMutationRequests':0,'activeProjectionWrites':0,'projectionExports':0,'gatewayWrites':0,'budgetReset':False,'automaticReplayAllowed':False}
  login={'schema':'ouf.installation-binding-scope-login-receipt.v1','reviewHash':'2f973bf92defd736e313861b0efafbb0a0d0fb6a7c17bd536f4b71d97d256c71','directory':str(self.human),'expiresAt':1792425259,'oauthAttemptsAfter':243,'priorOAuthAttempts':236,'maximumCumulativeOAuthAttempts':256,'requestedInstallationScopeCount':4,'oldRefreshReplayed':False,'budgetReset':False}
  for name,raw in members.items():(self.completed/name).write_bytes(raw);(self.completed/name).chmod(0o600)
  for name,value in{'installation-plan.json':self.plan,'package.json':package,'runtime.claim.json':{'packageHash':p.digest(package),'automaticReplayAllowed':False},'planning-result.json':report,'login-window-receipt.json':login}.items():self.write(self.completed/name,value)
  raw,image_id=image(jar());self.image_id=image_id
  candidate={'sourceCommit':p.SOURCE,'module':'onboarding','imageId':image_id,'scanGate':'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'}
  files={'image.docker.tar':raw,'application.jar':jar(),'source-inventory.json':p.encoded({'truncated':False,'tree':[{'path':k,'sha':v}for k,v in MIG.items()]}),'candidate-manifest.json':p.encoded(candidate),**{n:b'{}'for n in('package-record.json','trivy-image.json','Dockerfile.resolved','SHA256SUMS')}}
  for name,raw in files.items():(self.stage/name).write_bytes(raw)
  self.manifest={'schema':'ouf.installation-owner-staged-package.v1','sourceCommit':p.SOURCE,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'candidateManifest':candidate,'files':{n:p.sha(raw)for n,raw in files.items()}}
  self.write(self.stage/'qualified-package.json',self.manifest)
  self.requests=[]
 def write(self,path,value):path.write_bytes(p.encoded(value));path.chmod(0o600)
 def serve(self):
  client,_=self.server.accept()
  with client:
   data=b''
   while b'\r\n\r\n'not in data:data+=client.recv(4096)
   self.requests.append(data.split(b'\r\n',1)[0]);body=b'{"DriverStatus":[]}'
   client.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
 def child(self):
  paths={n:str(ROOT/path)for n,path in{'prepare':'scripts/prepare-installation-owner-update.py','bootstrap':'scripts/execute-installation-owner-update.py',**{n:'tools/installation_owner_update/'+n+'.py'for n in('entry','owner','native','authority','runtime')}}.items()}
  code='''import importlib.util,json,os,sys\nfrom pathlib import Path\nspec=importlib.util.spec_from_file_location('exact_preparer',sys.argv[1]);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)\nconfig=json.loads(sys.argv[2]);p.COMPLETED=Path(config['completed']);p.PLAN_HASH=config['planHash'];p.STAGE=Path(config['stage']);p.MANIFEST=config['manifestHash'];p.IMAGE=config['image'];p.MIGRATIONS=config['migrations'];p.time.time=lambda:1792419000\ndef done(*args):\n print('PREPARATION_EXEC_REACHED',flush=True);raise SystemExit(0)\np.os.execv=done\np.main({k:Path(v).read_bytes()for k,v in config['paths'].items()},'e'*40)\n'''
  config={'completed':str(self.completed),'planHash':self.plan_hash,'stage':str(self.stage),'manifestHash':p.digest(self.manifest),'image':self.image_id,'migrations':MIG,'paths':paths}
  return subprocess.run(['/usr/bin/python3','-I','-B','-S','-',str(SCRIPT),json.dumps(config)],input=code.encode(),capture_output=True,timeout=45)
 def test_real_frozen_engine_get_full_image_audit_capsule213_and_no_old_replay(self):
  before={path:path.read_bytes()for path in self.completed.iterdir()};human_before=(self.human/'recovery.json').read_bytes()
  thread=threading.Thread(target=self.serve,daemon=True);thread.start();result=self.child();thread.join(5)
  self.assertEqual(result.returncode,0,(result.stdout+result.stderr).decode());self.assertIn(b'PREPARATION_EXEC_REACHED',result.stdout)
  self.assertEqual(self.requests,[b'GET /v1.44/info HTTP/1.1']);self.assertTrue(all(path.read_bytes()==raw for path,raw in before.items()));self.assertEqual((self.human/'recovery.json').read_bytes(),human_before)
  claims=list(self.root.glob('installation-owner-preparation-*.claim.json'));self.assertEqual(len(claims),1)
  context=Path(json.loads(claims[0].read_bytes())['context']);report=json.loads((context/'preparation-result.json').read_bytes())
  self.assertEqual(report['sourceModuleCount'],213);self.assertEqual(report['priorOAuthAttempts'],243);self.assertFalse(report['runtimeAuthorityIssued']);self.assertFalse((context/'authority.json').exists())
  again=self.child();self.assertNotEqual(again.returncode,0);self.assertIn(b'OWNER_UPDATE_ALREADY_PREPARED_NO_REPLAY',again.stderr);self.assertEqual(len(self.requests),1)
 def test_bad_cumulative_budget_or_completed_plan_denies_before_engine_and_claim(self):
  self.write(self.human/'recovery.json',{**self.row,'attempts':256});result=self.child()
  self.assertNotEqual(result.returncode,0);self.assertEqual(self.requests,[]);self.assertEqual(list(self.root.glob('installation-owner-preparation-*')),[])
if __name__=='__main__':unittest.main()
