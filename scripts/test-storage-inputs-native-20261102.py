#!/usr/bin/env python3
"""Real Docker reproduction of the exact credential STOP, then retained-snapshot continuation.
Historical scopes/model MinIO role are synthetic; kernel/Docker/S3 are real.
"""
import hashlib,json,os,shutil,socket,stat,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
from tools.storage_migration import target_inventory_inputs as stage
m=stage.base;prior=stage.prior
pid=int(sys.argv[1]);binary=Path(sys.argv[2]);data=Path(sys.argv[3]);out=Path(sys.argv[4])
results=[]
for case in ['mode0644','owner10001','hardlink','oversize']:
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
    args+=['--mount','type=bind,source='+str(data)+',target=/data','-e','MINIO_ROOT_USER='+'wrong-env-user','-e','MINIO_ROOT_PASSWORD='+'wrong-env-password']
    for key,value in [('MINIO_ACCESS_KEY_FILE','access_key'),('MINIO_SECRET_KEY_FILE','secret_key'),('MINIO_ROOT_USER_FILE','live-user'),('MINIO_ROOT_PASSWORD_FILE','live-password'),('MINIO_CONFIG_ENV_FILE','config.env')]:args+=['-e',key+'='+value]
    for filename,value in [('live-user','lab-admin'),('live-password','lab-admin-secret-not-production')]:
     secret=temporary/filename;secret.write_text(('x'*4097 if case=='oversize' and filename=='live-user' else value+'\n'));secret.chmod(0o644 if case=='mode0644' else 0o600)
     if case=='owner10001' and filename=='live-user':os.chown(secret,10001,10001)
     if case=='hardlink' and filename=='live-user':os.link(secret,temporary/'extra-alias')
     args+=['--mount','type=bind,source='+str(secret)+',target=/'+filename+',readonly']
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
  assert old_engine.gets==13;previous.put('result.json',prior.FAILED);prior.PREVIOUS=previous.scope
  before={p.name:p.read_bytes() for p in previous.scope.iterdir()}
  old15=prior.Capture(temporary/'control15');old15.until=time.monotonic()+600;old15.put('storage-baseline.claim.json',{'profile':prior.PROFILE,'automaticReplayAllowed':False});old15_engine=prior.Engine(old15)
  try:prior.capture(old15,old15_engine)
  except m.Stop as error:assert str(error)=='PRIVATE_BOUNDED_REGULAR_CREDENTIAL_SOURCE_REQUIRED'
  else:raise AssertionError('CONTROL15_COMBINED_GUARD_NOT_REPRODUCED')
  assert old15_engine.gets==1 and old15.credentialStatus=={'filesOpened':0,'sourceBytesRead':0,'metadataCandidates':5,'rawValuesSpooled':False}
  old15.put('result.json',stage.FAILED);stage.PREVIOUS=old15.scope;before15={p.name:p.read_bytes() for p in old15.scope.iterdir()}
  class ProviderOrderEngine(stage.Engine):
   def get(self,path):
    doc=super().get(path);doc['Mounts']=sorted(doc['Mounts'],key=lambda r:r['Destination'],reverse=self.gets==2);return doc
  control=stage.Capture(temporary/'control16');control.until=time.monotonic()+600;control.put('storage-baseline.claim.json',{'profile':stage.PROFILE,'automaticReplayAllowed':False});engine=ProviderOrderEngine(control)
  if case=='oversize':
   try:stage.capture(control,engine)
   except m.Stop as error:assert str(error)=='CREDENTIAL_INPUT_METADATA_REVIEW_REQUIRED'
   else:raise AssertionError('OVERSIZED_INPUT_READ')
   assert engine.gets==1 and control.inputMetadata['metadataComplete'] and control.inputMetadata['policyBlocked'] and control.credentialStatus['filesOpened']==control.credentialStatus['sourceBytesRead']==0
   result={'case':case,'status':'PASS','unsupportedInputMetadataComplete':True,'contentReads':0,'s3Requests':0,'freshMinioInspects':1}
  else:
   report=stage.capture(control,engine)
   assert report['s3Complete'] and report['records']==1010 and report['directEngineGets']==2 and report['cumulativeControlAttempts']==16 and report['cumulativeDirectEngineGets']==52 and report['allFifteenPriorScopesPreserved'] and not report['thirteenInspectScanReplayed'] and report['credentialSourceCustodyAdmitted'] is False
   assert report['credentialSources']['selectedSources']==['DECLARED_SECRET_FILE','DECLARED_SECRET_FILE']
   result={'case':case,'status':'PASS','records':1010,'freshMinioInspects':2,'inputMetadataComplete':report['credentialInputMetadata']['metadataComplete'],'inputPermissionsAndOwnerUnmodified':True,'sourceCustodyAdmitted':False}
  assert before15=={p.name:p.read_bytes() for p in old15.scope.iterdir()} and before=={p.name:p.read_bytes() for p in previous.scope.iterdir()}
  (old15.scope/'result.json').write_bytes(m.encoded({**stage.FAILED,'directEngineGets':0}))
  denied=stage.Capture(temporary/'denied');denied_engine=stage.Engine(denied)
  try:stage.capture(denied,denied_engine)
  except m.Stop as error:assert str(error)=='EXACT_CONSUMED_CONTROL15_PREFLIGHT_STOP_REQUIRED'
  else:raise AssertionError('CHANGED_CONTROL15_ACCEPTED')
  assert denied_engine.gets==0
  result.update(reproducedExactControl15Stop=True,retainedSnapshotBytesPreserved=True,tamperedPreviousStopDeniedBeforeEngineAndS3=True);results.append(result)
 finally:
  for cid in reversed(containers):subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  shutil.rmtree(temporary)
value={'status':'PASS','cases':results,'realDockerEngineQualified':True,'historicalScopeChecks':'MODELLED','minioRoleProcessInFixture':'SYNTHETIC_STATIC_WAITER_HOST_NETWORK_WITH_SEPARATE_REAL_S3_SERVER','exactOriginalSdkReused':True,'oldFifteenScopesPreserved':True,'thirteenInspectScanReplayed':False,'targetOperations':0,'runtimeAuthorityIssued':False}
out.write_text(json.dumps(value,indent=2)+'\n');out.chmod(0o644)
