#!/usr/bin/env python3
"""Real Docker reproduction of the exact credential STOP, then retained-snapshot continuation.
Historical scopes/model MinIO role are synthetic; kernel/Docker/S3 are real.
"""
import hashlib,json,os,shutil,socket,stat,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
from tools.storage_migration import target_inventory_credentials as stage
m=stage.base
pid=int(sys.argv[1]);binary=Path(sys.argv[2]);data=Path(sys.argv[3]);out=Path(sys.argv[4])
results=[]
for case in ['defaults-absent','files']:
 temporary=Path(tempfile.mkdtemp(prefix='ouf-credential-case-',dir='/root'));containers=[];image='ouf-storage-credentials-'+temporary.name
 try:
  assert hashlib.sha256(binary.read_bytes()).hexdigest()==m.BACKEND_SHA,'EXACT_PREVIOUSLY_INSTALLED_READER_REQUIRED'
  backend=temporary/'inventory';shutil.copyfile(binary,backend);backend.chmod(0o500);m.BACKEND=backend
  origin=temporary/'origin';origin.mkdir(mode=0o700)
  old_result={'fixture':'synthetic-result'};old_private={'roles':{'minio':{'nativeImageId':'sha256:'+'a'*64}}}
  for name,record in [('result.json',old_result),('runtime-origin.private.json',old_private)]:
   p=origin/name;p.write_bytes(m.encoded(record));p.chmod(0o600)
  m.origins.OUTPUT=origin;m.ORIGIN_RESULT=m.digest(old_result);m.ORIGIN_PRIVATE=m.digest(old_private);m.origins.history=lambda control:({},None,None)
  predecessor=temporary/'failed';predecessor.mkdir(mode=0o700)
  for name,value in [('capture.claim.json',{'schema':'ouf.m2-discovery-custody-capture-claim.v1','automaticReplayAllowed':False}),('storage-baseline.claim.json',{'profile':m.FAILED_PROFILE,'automaticReplayAllowed':False}),('result.json',m.FAILED_RESULT)]:
   p=predecessor/name;p.write_bytes(m.encoded(value));p.chmod(0o600)
  m.PREDECESSOR=predecessor;before={p.name:p.read_bytes() for p in predecessor.iterdir()}
  context=temporary/'image';context.mkdir();shutil.copyfile(ROOT/'sw-readback/waiter',context/'waiter');(context/'waiter').chmod(0o500)
  (context/'Dockerfile').write_text('FROM scratch\nCOPY waiter /waiter\nENTRYPOINT ["/waiter"]\n')
  subprocess.run(['docker','build','-t',image,str(context)],check=True,stdout=subprocess.DEVNULL)
  observations={};pins={};roster={}
  from tools.m2_discovery_installation_profile.retained_mount_role_correction import stable_binding,ROLES
  for index,role in enumerate(sorted(ROLES)):
   args=['docker','run','-d','--network','host','--name','storage_'+role.replace('-','_')+'_'+temporary.name]
   if role=='minio':
    args+=['--mount','type=bind,source='+str(data)+',target=/data','-e','MINIO_ROOT_USER='+('wrong-env-user' if case=='files' else 'lab-admin'),'-e','MINIO_ROOT_PASSWORD='+('wrong-env-password' if case=='files' else 'lab-admin-secret-not-production')]
    for key,value in [('MINIO_ACCESS_KEY_FILE','access_key'),('MINIO_SECRET_KEY_FILE','secret_key'),('MINIO_ROOT_USER_FILE','access_key'),('MINIO_ROOT_PASSWORD_FILE','secret_key'),('MINIO_CONFIG_ENV_FILE','config.env')]:args+=['-e',key+'='+value]
    if case=='files':
     for filename,value in [('access_key','lab-admin'),('secret_key','lab-admin-secret-not-production')]:
      secret=temporary/filename;secret.write_text(value+'\n');secret.chmod(0o600);args+=['--mount','type=bind,source='+str(secret)+',target=/run/secrets/'+filename+',readonly']
   cid=subprocess.check_output(args+[image],text=True).strip();containers.append(cid)
   doc=json.loads(subprocess.check_output(['docker','inspect',cid],text=True,env={**os.environ,'DOCKER_API_VERSION':'1.44'}))[0];pin=m.process_pin(doc['State']['Pid'])
   assert not doc['Name'].startswith('/ouf-') and doc['State']['Running'] and not doc['State']['Paused']
   alias='opaque-alias-'+str(index);observations[alias]=doc;pins[alias]=pin;roster[role]={'containerId':cid,'nativeBindingHash':m.digest(stable_binding(doc)),'generation':pin}
  sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.connect('/run/docker.sock');peer=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)));sock.close()
  sock_info=Path('/run/docker.sock').lstat()
  seed={'schema':'ouf.m2-discovery-current-private-bindings.v1','observations':observations,'processPins':pins,'rootProcessPins':{'engine':m.process_pin(peer[0])},'engineBinding':{'socketPath':'/run/docker.sock','socketBinding':[sock_info.st_dev,sock_info.st_ino,sock_info.st_uid,sock_info.st_gid,stat.S_IMODE(sock_info.st_mode)],'peerCredentials':peer},'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'historicalAuthorityReused':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
  m.ROSTER=roster;m.SEED=temporary/'seed.json';m.SEED.write_bytes(m.encoded(seed));m.SEED.chmod(0o600);m.SEED_HASH=m.digest(seed)
  old_private={'roles':{'minio':{'nativeImageId':observations['opaque-alias-'+str(sorted(ROLES).index('minio'))]['Image']}}}
  (origin/'runtime-origin.private.json').write_bytes(m.encoded(old_private));m.ORIGIN_PRIVATE=m.digest(old_private)
  previous=m.Capture(temporary/'control14');previous.until=time.monotonic()+600;previous.put('storage-baseline.claim.json',{'profile':m.PROFILE,'automaticReplayAllowed':False});old_engine=m.Engine(previous)
  try:m.capture(previous,old_engine)
  except m.Stop as error:assert str(error)=='CANONICAL_PRIVATE_CREDENTIAL_REFERENCE_REQUIRED'
  else:raise AssertionError('OLD_GUARD_DID_NOT_REPRODUCE_TARGET_STOP')
  assert old_engine.gets==13;previous.put('result.json',stage.FAILED);stage.PREVIOUS=previous.scope
  before={p.name:p.read_bytes() for p in previous.scope.iterdir()}
  class ProviderOrderEngine(stage.Engine):
   def get(self,path):
    doc=super().get(path)
    if case=='files':doc['Mounts']=sorted(doc['Mounts'],key=lambda r:r['Destination'],reverse=self.gets==2)
    return doc
  control=stage.Capture(temporary/'control15');control.until=time.monotonic()+600;control.put('storage-baseline.claim.json',{'profile':stage.PROFILE,'automaticReplayAllowed':False});engine=ProviderOrderEngine(control)
  try:report=stage.capture(control,engine)
  except Exception:
   if (control.scope/'postcheck.private.json').is_file():print('SYNTHETIC_POSTCHECK_DIFFERENCE '+(control.scope/'postcheck.private.json').read_text())
   raise
  assert report['s3Complete'] and report['records']==1010 and report['directEngineGets']==2 and report['cumulativeControlAttempts']==15 and report['cumulativeDirectEngineGets']==51 and report['allFourteenPriorScopesPreserved'] and not report['thirteenInspectScanReplayed']
  assert before=={p.name:p.read_bytes() for p in previous.scope.iterdir()}
  expected='DECLARED_SECRET_FILE' if case=='files' else 'EXPLICIT_ENV';assert report['credentialSources']['selectedSources']==[expected,expected]
  if case=='files':assert report['credentialSources']['secretFilesOpened']==2
  else:assert report['credentialSources']['secretFilesOpened']==0
  (previous.scope/'result.json').write_bytes(m.encoded({**stage.FAILED,'directEngineGets':12}))
  denied=stage.Capture(temporary/'denied');denied_engine=stage.Engine(denied)
  try:stage.capture(denied,denied_engine)
  except m.Stop as error:assert str(error)=='EXACT_CONSUMED_CREDENTIAL_REFERENCE_STOP_REQUIRED'
  else:raise AssertionError('CHANGED_CONTROL14_STOP_ACCEPTED')
  assert denied_engine.gets==0
  results.append({'case':case,'status':'PASS','reproducedOldStopAfter13RealGets':True,'freshMinioInspects':2,'records':1010,'retainedSnapshotBytesPreserved':True,'secretFilesOpened':report['credentialSources']['secretFilesOpened'],'selectedSources':report['credentialSources']['selectedSources'],'capacityAndMemoryFromControl':report['capacityAndMemoryObservedAtControl'],'providerMountOrderVariationInjected':case=='files','tamperedPreviousStopDeniedBeforeEngineAndS3':True})
 finally:
  for cid in reversed(containers):subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  shutil.rmtree(temporary)
value={'status':'PASS','cases':results,'realDockerEngineQualified':True,'historicalScopeChecks':'MODELLED','minioRoleProcessInFixture':'SYNTHETIC_STATIC_WAITER_HOST_NETWORK_WITH_SEPARATE_REAL_S3_SERVER','exactOriginalSdkReused':True,'oldFourteenScopesPreserved':True,'thirteenInspectScanReplayed':False,'targetOperations':0,'runtimeAuthorityIssued':False}
out.write_text(json.dumps(value,indent=2)+'\n');out.chmod(0o644)
