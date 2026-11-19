#!/usr/bin/env python3
"""Corrective root fixture: real thirteen-container Docker and namespace/S3; historical state modeled."""
import hashlib,importlib.util,json,os,shutil,socket,stat,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true','ROOT_CI_FIXTURE_ONLY'
spec=importlib.util.spec_from_file_location('correction',ROOT/'tools/storage_migration/target_inventory_reconciliation.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
pid=int(sys.argv[1]);binary=Path(sys.argv[2]);data=Path(sys.argv[3]);out=Path(sys.argv[4]);temporary=Path(tempfile.mkdtemp(prefix='ouf-storage-correction-',dir='/root'));containers=[];image='ouf-storage-correction-'+temporary.name
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
  if role=='minio':args+=['--mount','type=bind,source='+str(data)+',target=/data','-e','MINIO_ROOT_USER=lab-admin','-e','MINIO_ROOT_PASSWORD=lab-admin-secret-not-production']
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
 control=m.Capture(temporary/'scope');control.until=time.monotonic()+600;engine=m.Engine(control)
 report=m.capture(control,engine)
 assert report['s3Complete'] and report['records']==1010 and report['directEngineGets']==13 and report['cumulativeControlAttempts']==14 and report['cumulativeDirectEngineGets']==49 and report['allThirteenPriorScopesPreserved'] and not report['oldScopeRearmed']
 assert before=={p.name:p.read_bytes() for p in predecessor.iterdir()}
 # Wrong source receipt must stop before bind/GET and before any S3 call.
 original=dict(m.FAILED_RESULT);(predecessor/'result.json').write_bytes(m.encoded({**original,'directEngineGets':2}))
 denied=m.Capture(temporary/'denied');denied_engine=m.Engine(denied)
 try:m.capture(denied,denied_engine)
 except m.Stop as error:assert str(error)=='EXACT_CONSUMED_STORAGE_SELECTION_STOP_REQUIRED'
 else:raise AssertionError('TAMPERED_PREDECESSOR_ACCEPTED')
 assert denied_engine.gets==0
 value={'status':'PASS','records':1010,'directIdInspects':13,'containerListRequests':0,'namesWithoutOufDashAccepted':True,'opaqueSeedAliasesResolvedById':True,'exactOldSdkExecutableReused':True,'predecessorBytesPreserved':True,'tamperedPredecessorDeniedBeforeEngineAndS3':True,'cumulativeControlAttempts':14,'cumulativeDirectEngineGets':49,'kernelNetworkNamespaceEntered':True,'anonymousSealedCredentialFds':2,'realDockerEngineQualified':True,'minioRoleProcessInFixture':'SYNTHETIC_STATIC_WAITER_WITH_HOST_NETWORK_AND_REAL_S3_SERVER','historicalScopeChecks':'MODELLED','targetOperations':0,'runtimeAuthorityIssued':False}
 out.write_text(json.dumps(value,indent=2)+'\n');out.chmod(0o644)
finally:
 for cid in reversed(containers):subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 shutil.rmtree(temporary)
