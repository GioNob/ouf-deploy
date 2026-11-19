"""Real same-image Docker replacement and three-route namespace Admin fixture.

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
from tools.resolution_ths_configuration.plan import replacement
from test_resolution_routes_plan import templates
from tools.resolution_ths_update.plan import compile_routes
from tools.resolution_ths_update.native import NativePorts as RoutePorts
from tools.resolution_ths_configuration.owner import ReadinessUpdate,scope,digest,UpdatePaused,STAGES
from tools.resolution_ths_configuration.native import NativePorts,runtime
APP="""import http.server,json
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  raw=b'{"status":"UP"}';self.send_response(200);self.end_headers();self.wfile.write(raw)
 def log_message(self,*a):pass
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
"""
ADMIN="""import http.server,json
routes=INITIAL
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
@unittest.skipUnless(os.environ.get('OUF_READINESS_DOCKER_NATIVE')=='1','explicit real-Docker qualification only')
class NativeEndToEnd(unittest.TestCase):
 def cli(self,*args):
  r=subprocess.run(['docker',*args],capture_output=True,timeout=180)
  self.assertEqual(r.returncode,0,r.stderr.decode()[-2000:]);return r.stdout.decode().strip()
 def test_same_image_configuration_replacement_three_routes_and_no_replay(self):
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
  self.cli('load','--input',str(tagged));image_id=image_custody.runtime_image_id(audit)
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
  _,gw=create('ouf-apisix','172.30.88.13',ADMIN.replace('INITIAL',repr(templates())),[str(config)+':/usr/local/apisix/conf/config.yaml:ro'])
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
  old_plan=plan
  new_env=list(actuals['onboarding']['Config']['Env'])+['SPRING_APPLICATION_JSON={"ouf.authorization.ths.enabled":true,"spring.security.oauth2.client.registration.ouf-ths.scope":["openid","resolution.issue.read","resolution.match.approve"]}']
  row=replacement(old_plan,actuals['onboarding'],new_env,'d'*64)
  plan={'schema':'ouf.resolution-ths-configuration-plan.v1','authorityDirectory':str(context),'privateReviewBinding':binding,
   'engine':review['engine'],'replacements':{'onboarding':row},'unchangedIngestionRuntimeBinding':runtime(actuals['ingestion']),
   'gateway':{'transport':transport,'projectionBinding':projection_binding},'configuration':{'fileBinding':projection_binding},
   'beforeRoutes':routes,'routes':compile_routes(routes),'humanBinding':{'fixtureHuman':'same'},'reviewedOrigin':'https://fixture.invalid',
   'sameImageOnly':True,'containerLifecycleAllowed':True,'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':3,
   **{k:False for k in('automaticReplayAllowed','databaseMigrationsAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed')}}
  plan['logicalUpdateRef']=digest({'beforeRoutes':digest(routes),'routes':plan['routes'],'replacement':row})
  c.authority=crypto.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in c.expected.items()if k!='intakeHash'},
   'issuedAt':c.now,'expiresAt':c.now+480,'resolutionConfigurationUpdate':scope(plan)})
  c.approval['expiresAt']=c.now+500;c.approval['executionAuthorityHash']=crypto.sha(c.authority);c.write(c.mandate,crypto.encoded(c.approval));c.approved=crypto.sha(c.mandate.read_bytes())
  for role in c.grant['roles']:c.sign(role)
  action=AggregateAction(c.gate(),c.authority,c.expected['sourceClosureHash']);ports=NativePorts(action,engine,plan,SimpleNamespace(current=lambda:plan['humanBinding']))
  effects=[];real_request=engine.request
  def tracking(method,path,body=None):
   if method!='GET':effects.append((method,path))
   return real_request(method,path,body)
  engine.request=tracking
  probe=patch.object(RoutePorts,'anonymous_probes',return_value={'page':302,'owner':401});probe.start();self.addCleanup(probe.stop)
  update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
  try:
   while True:
    try:result=update.run();break
    except UpdatePaused as paused:
     self.assertEqual(str(paused),'READINESS_RETRY_WAIT');time.sleep(.5)
   self.assertTrue(result['applicationReady']);self.assertFalse(result['sourceActivationProven'])
   self.assertEqual(admin.routes(),{**routes,**plan['routes']})
   self.assertFalse(any('images/load'in path for _,path in effects))
   self.assertEqual(ports.candidate('onboarding',True)['Image'],actuals['onboarding']['Image'])
   self.assertEqual(dict(v.split('=',1)for v in ports.candidate('onboarding',True)['Config']['Env'])['SPRING_APPLICATION_JSON'],new_env[-1].split('=',1)[1])
   for name,row in plan['replacements'].items():
    live=ports.candidate(name,True);created.append(live['Id'])
    old=ports.inspect('containers',row['oldRuntimeBinding']['containerId']);self.assertFalse(old['State']['Running'])
    self.assertEqual(old['Name'],'/'+row['retiredName']);self.assertEqual(live['Config']['Cmd'],actuals[name]['Config']['Cmd'])
   self.assertEqual(runtime(ports.inspect('containers',actuals['ingestion']['Id'])),runtime(actuals['ingestion']))
   before=update.record();update.run();self.assertEqual(update.record(),before)
   with self.assertRaises(Exception):ports.claim_logical_scope()
  finally:
   for row in plan['replacements'].values():
    live=ports.inspect('containers',row['name'])
    if live is not None and live['Id']not in created:created.append(live['Id'])
if __name__=='__main__':unittest.main()
