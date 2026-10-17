"""Real Docker lifecycle, native image custody and namespace Admin HTTP fixture.

The fixture is independent from the VPS. Application health and APISIX Admin
contracts are synthetic; production application/route tests run in their repos.
"""
import copy,hashlib,http.client,importlib.util,json,os,shutil,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as crypto
from engine_creation import Engine
import image_custody
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,MOUNT_SET_BINDING
from tools.ingestion_readiness_update.plan import compile_plan
from tools.udp_resolution_update.owner import ReadinessUpdate,scope,digest,UpdatePaused,STAGES
from tools.udp_resolution_update.native import NativePorts,runtime
APP="""import http.server,json
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  raw=b'{"status":"UP"}';self.send_response(200);self.end_headers();self.wfile.write(raw)
 def log_message(self,*a):pass
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
"""
ADMIN="""import http.server,json
routes={'retained-route':{'id':'retained-route','uri':'/preserved','methods':['GET']}}
class H(http.server.BaseHTTPRequestHandler):
 def reply(self,status,body):
  raw=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def do_GET(self):
  if self.headers.get('X-API-KEY')!='EXISTING_FIXTURE_ADMIN_KEY_123456':return self.reply(403,{})
  if self.path=='/apisix/admin/routes':return self.reply(200,{'total':len(routes),'list':[{'value':v}for v in routes.values()]})
  return self.reply(404,{})
 def do_PUT(self):
  if self.headers.get('X-API-KEY')!='EXISTING_FIXTURE_ADMIN_KEY_123456':return self.reply(403,{})
  rid=self.path.rsplit('/',1)[-1]
  if rid in routes:return self.reply(409,{})
  routes[rid]=json.loads(self.rfile.read(int(self.headers['Content-Length'])));return self.reply(201,{'value':routes[rid]})
 def log_message(self,*a):pass
http.server.HTTPServer(('0.0.0.0',9180),H).serve_forever()
"""
@unittest.skipUnless(os.geteuid()==0,'private input custody requires root')
class NativeInputReadback(unittest.TestCase):
 def test_reconciliation_cannot_accept_changed_image_or_changed_route_inventory(self):
  with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT)))as d:
   image=Path(d)/'candidate.tar';image.write_bytes(b'original reviewed bytes');image.chmod(0o600)
   before={'retained':{'id':'retained','uri':'/preserved'}}
   ports=NativePorts.__new__(NativePorts)
   ports.plan={'privateReviewBinding':{'sha256':'a'*64},'gateway':{'beforeRoutes':before},
    'replacements':{'onboarding':{'imageArchive':{'path':str(image),'sha256':hashlib.sha256(image.read_bytes()).hexdigest()},'retiredName':'retired'}}}
   ports.gateway=SimpleNamespace(routes=lambda:copy.deepcopy(before));ports.inspect=lambda *a:None
   self.assertEqual(ports.observe('VERIFY_INPUTS')[0],'APPLIED')
   image.write_bytes(b'changed bytes after review')
   with self.assertRaisesRegex(Exception,'PRIVATE_FILE_BYTES_CHANGED'):ports.observe('VERIFY_INPUTS')
   ports.gateway=SimpleNamespace(routes=lambda:{'foreign':{'id':'foreign'}})
   with self.assertRaisesRegex(Exception,'COMPLETE_GATEWAY_ROUTE_MAP_CHANGED'):ports.observe('VERIFY_INPUTS')
@unittest.skipUnless(os.environ.get('OUF_READINESS_DOCKER_NATIVE')=='1','explicit real-Docker qualification only')
class NativeEndToEnd(unittest.TestCase):
 def cli(self,*args):
  r=subprocess.run(['docker',*args],capture_output=True,timeout=180)
  self.assertEqual(r.returncode,0,r.stderr.decode()[-2000:]);return r.stdout.decode().strip()
 def test_signed_udp_replacement_retains_peer_gateway_and_no_replay(self):
  self.assertEqual(os.geteuid(),0);self.assertTrue(hasattr(os,'setns'))
  base=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT','/root'));self.addCleanup(base.cleanup);root=Path(base.name);root.chmod(0o700)
  c=crypto.SignedCutover()
  with patch.object(crypto,'ROOT',root):c.setUp()
  self.addCleanup(c.doCleanups)
  image='readiness-native-fixture:'+str(os.getpid())
  self.addCleanup(lambda:subprocess.run(['docker','image','rm',image],capture_output=True,timeout=30))
  net='readiness-fixture-'+str(os.getpid());self.cli('network','create','--subnet','172.30.88.0/24',net)
  self.addCleanup(lambda:self.cli('network','rm',net));created=[]
  self.addCleanup(lambda:[self.cli('rm','-f',cid)for cid in reversed(created)])
  self.cli('pull','python:3.13-alpine')
  pinned=self.cli('image','inspect','python:3.13-alpine','--format','{{index .RepoDigests 0}}')
  build=root/'build';build.mkdir(mode=0o700);(build/'Dockerfile').write_text('FROM '+pinned+'\nLABEL org.opencontainers.image.revision="'+'c'*40+'"\nUSER 0:0\nWORKDIR /\n')
  self.cli('build','--quiet','--tag',image,str(build))
  image_id=self.cli('image','inspect',image,'--format','{{.Id}}');archive=root/'image.tar';self.cli('save','-o',str(archive),image);archive.chmod(0o600)
  archive_hash=hashlib.sha256(archive.read_bytes()).hexdigest()
  with archive.open('rb')as f:audit=image_custody.archive(f,archive_hash,image_id,'c'*40)
  # Qualify the actual storage driver without changing Docker configuration.
  info=json.loads(self.cli('info','--format','{{json .}}'));containerd=dict(info.get('DriverStatus')or[]).get('driver-type')=='io.containerd.snapshotter.v1'
  tagged=root/'tagless.tar'
  with archive.open('rb')as f,tagged.open('w+b')as dest:derived=image_custody.tagless_archive(f,dest,audit,containerd=containerd)
  tagged.chmod(0o600)
  with tagged.open('rb')as f:audit=image_custody.archive(f,derived['derivedArchiveSha256'],image_id,'c'*40)
  if containerd:audit['nativeIdentity']=image_custody.native_identity(audit)
  inspected=json.loads(self.cli('image','inspect',image_id))[0]
  self.assertEqual({k:inspected['Config'].get(k)for k in image_custody.FIELDS},{k:audit['imageConfig'].get(k)for k in image_custody.FIELDS})
  sock=Path('/var/run/docker.sock').resolve();s=sock.stat();engine=Engine(str(sock),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777))
  def create(name,ip,program,binds=None):
   request={'Image':image_id,'User':'0:0','Entrypoint':None,'Cmd':['python3','-B','-u','-c',program],
    'Env':['FIXTURE_SECRET=synthetic-only'],'WorkingDir':'/','Labels':{'org.opencontainers.image.revision':'a'*40},
    'HostConfig':{'NetworkMode':net,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'ReadonlyRootfs':True,'Binds':binds or[]},
    'NetworkingConfig':{'EndpointsConfig':{net:{'IPAMConfig':{'IPv4Address':ip},'Aliases':[name]}}}}
   status,value=engine.request('POST','/v1.44/containers/create?name='+name,request);self.assertEqual(status,201);created.append(value['Id'])
   self.assertEqual(engine.request('POST','/v1.44/containers/'+value['Id']+'/start')[0],204)
   status,actual=engine.request('GET','/v1.44/containers/'+value['Id']+'/json');self.assertEqual(status,200);return request,actual
  config=root/'apisix-config.yaml';config.write_text('deployment:\n  admin:\n    admin_key:\n      - name: existing\n        key: EXISTING_FIXTURE_ADMIN_KEY_123456\n        role: admin\n');config.chmod(0o600)
  _,gw=create('ouf-apisix','172.30.88.13',ADMIN,[str(config)+':/usr/local/apisix/conf/config.yaml:ro'])
  transport=NamespaceAdmin.observe(engine,str(config),MOUNT_SET_BINDING);admin=NamespaceAdmin(engine,transport)
  until=time.monotonic()+20
  while True:
   try:routes=admin.routes();break
   except Exception:
    if time.monotonic()>until:raise
    time.sleep(.2)
  images={};actuals={}
  shared=root/'shared';shared.write_text('synthetic mount');shared.chmod(0o400)
  for i,name in enumerate(('onboarding','ingestion')):
   request,actual=create('fixture-'+name,'172.30.88.'+str(11+i),APP,[str(shared)+':/run/fixture:ro']);actuals[name]=actual
   images[name]={'oldNativeConfig':actual['Config'],'oldNativeHostConfig':actual['HostConfig'],'oldNativeMounts':actual['Mounts'],
    'oldNativeNetworks':actual['NetworkSettings']['Networks'],'oldRuntimeBinding':runtime(actual),'retainedCreationRequest':request,
    'nativeImageId':image_custody.runtime_image_id(audit),'imageAudit':audit,'imageArchive':{'path':str(tagged),'sha256':derived['derivedArchiveSha256']}}
  _,peer=create('fixture-peer','172.30.88.14',APP,[str(shared)+':/run/fixture:ro'])
  projection=root/'projection.json';projection.write_text('{}');projection.chmod(0o600)
  from tools.chatbot_file_cohort.gateway import private_config
  _,projection_binding=private_config(str(projection))
  review={'schema':'ouf.ingestion-readiness-update-private-review.v1','readyForExecution':False,'runtimeAuthorityIssued':False,
   'databaseMigrationsAllowed':False,'grantChangesAllowed':False,'semanticDispatchAllowed':False,
   'engine':{'socketPath':str(sock),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777]},
   'images':images,'candidateModules':{n:{'sourceCommit':'c'*40}for n in images},
   'gateway':{'proposedRoute':{'id':'fixture-new-read','uri':'/new-service-read','methods':['GET']},'targetProjectionBinding':projection_binding}}
  private=c.root/'private-review.json';c.write(private,json.dumps(review,sort_keys=True,separators=(',',':')).encode())
  binding={'path':str(private),'sha256':digest(review)};context=c.root/'native-update';context.mkdir(mode=0o700)
  selection={n:{'readinessPort':8080,'readinessPath':'/actuator/health/readiness'}for n in images}
  plan=compile_plan(review,binding,context,actuals,transport,routes,selection)
  docker=Path(shutil.which('docker')).resolve();plan['programs']={'docker':{'path':str(docker),'sha256':hashlib.sha256(docker.read_bytes()).hexdigest()}}
  # The already-installed read route is preserved, never republished by this owner.
  route=review['gateway']['proposedRoute'];status,_=admin.request('PUT','/apisix/admin/routes/'+route['id'],route);self.assertEqual(status,201)
  plan['gateway']['beforeRoutes']={**routes,route['id']:route}
  plan['schema']='ouf.udp-resolution-get-native-update-plan.v1';plan['maximumGatewayWrites']=0
  plan['unchangedApplications']={'onboarding':runtime(actuals['ingestion']),'ingestion':runtime(peer)};plan['humanBinding']={'fixture':'human'};plan['identityDecisionsAllowed']=False
  del plan['replacements']['ingestion'];plan['replacements']['udp']=plan['replacements'].pop('onboarding')
  plan['logicalUpdateRef']=digest({'retiredContainerIds':[actuals['onboarding']['Id']],'routeId':route['id']})
  c.authority=crypto.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in c.expected.items()if k!='intakeHash'},
   'issuedAt':c.now,'expiresAt':c.now+480,'udpResolutionUpdate':scope(plan)})
  c.approval['expiresAt']=c.now+500;c.approval['executionAuthorityHash']=crypto.sha(c.authority);c.write(c.mandate,crypto.encoded(c.approval));c.approved=crypto.sha(c.mandate.read_bytes())
  for role in c.grant['roles']:c.sign(role)
  action=AggregateAction(c.gate(),c.authority,c.expected['sourceClosureHash']);ports=NativePorts(action,engine,plan,SimpleNamespace(current=lambda:plan['humanBinding']))
  update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
  try:
   while True:
    try:result=update.run();break
    except UpdatePaused as paused:
     self.assertEqual(str(paused),'READINESS_RETRY_WAIT');time.sleep(.5)
   self.assertTrue(result['applicationReady']);self.assertFalse(result['sourceActivationProven'])
   self.assertEqual(admin.routes(),{**routes,'fixture-new-read':review['gateway']['proposedRoute']})
   for name,row in plan['replacements'].items():
    live=ports.candidate(name,True);created.append(live['Id'])
    old=ports.inspect('containers',row['oldRuntimeBinding']['containerId']);self.assertFalse(old['State']['Running'])
    self.assertEqual(old['Name'],'/'+row['retiredName']);self.assertEqual(live['Config']['Cmd'],actuals['onboarding']['Config']['Cmd'])
   self.assertEqual(runtime(ports.inspect('containers',actuals['ingestion']['Id'])),runtime(actuals['ingestion']))
   self.assertEqual(runtime(ports.inspect('containers',peer['Id'])),runtime(peer))
   before=update.record();update.run();self.assertEqual(update.record(),before)
   with self.assertRaises(Exception):ports.claim_logical_scope()
  finally:
   for row in plan['replacements'].values():
    live=ports.inspect('containers',row['name'])
    if live is not None and live['Id']not in created:created.append(live['Id'])
if __name__=='__main__':unittest.main()
