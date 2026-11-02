"""Fresh bounded private storage baseline. NOT a migration or runtime grant.

Packed with the unchanged historical readers; never invokes their main/reconcile
functions. Target delivery is not ready until backend and capsule are qualified.
"""
import fcntl,hashlib,http.client,json,os,re,socket,stat,subprocess,sys,time
from pathlib import Path,PurePosixPath
from tools.m2_discovery_installation_profile.custody_capture import Capture,Stop,attrs,decode,digest,encoded,process_pin,require
from tools.m2_discovery_installation_profile import retained_runtime_origins as origins

SCOPE=Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-20261102-v1')
BACKEND=Path('/usr/local/lib/ouf-storage-inventory-20261102/inventory')
BACKEND_SHA='__QUALIFIED_BACKEND_SHA256__'
ORIGIN_RESULT='ca16c7e3799d916517cba7e0c0d0456c57bd949184bd103d3fa3204110768a09'
ORIGIN_PRIVATE='8cf9a9ba0eaaf1f485515f893fee738c526622e2df97ec3687ca01843f0cd067'
PROFILE={'schema':'ouf.storage-baseline-read-control.v1','maximumAttempts':1,'maximumSeconds':600,
 'maximumEngineGets':65,'maximumContainers':64,'maximumEngineResponseBytes':2097152,
 'maximumCredentialSources':2,'maximumCredentialBytesEach':4096,'maximumS3Requests':10000,
 'maximumS3Records':25000,'maximumS3Seconds':300,'backendGoMemoryLimit':'256MiB','backendGoMaxProcs':1,'objectBodiesRead':0,'sqlRequests':0,
 'containerLifecycleOperations':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,
 'previousControlAttempts':12,'previousEngineGets':35,'migrationAuthorized':False}

class UnixConnection(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5);self.sock.connect('/run/docker.sock')

class Engine:
 def __init__(self,control):
  self.control=control;self.gets=0
  info=Path('/run/docker.sock').lstat();require(stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and not info.st_mode&0o007 and info.st_nlink==1,'ROOT_PRIVATE_ENGINE_SOCKET_REQUIRED');self.socketFrame=attrs(info)
 def get(self,path):
  self.control.check();require(self.gets<PROFILE['maximumEngineGets'] and (path=='/containers/json?all=1' or re.fullmatch('/containers/[a-f0-9]{64}/json',path)),'EXACT_BOUNDED_READ_ONLY_ENGINE_PATH_REQUIRED')
  self.gets+=1;connection=UnixConnection('localhost',timeout=5)
  try:
   connection.request('GET',path,headers={'Accept':'application/json'});response=connection.getresponse();raw=response.read(PROFILE['maximumEngineResponseBytes']+1)
   require(response.status==200 and 0<len(raw)<=PROFILE['maximumEngineResponseBytes'],'BOUNDED_SUCCESSFUL_ENGINE_READ_REQUIRED');return decode(raw)
  finally:
   connection.close();require(attrs(Path('/run/docker.sock').lstat())==self.socketFrame,'ENGINE_SOCKET_CHANGED')

def select_containers(rows):
 require(type(rows) is list and len(rows)<=256,'BOUNDED_CONTAINER_LIST_REQUIRED')
 selected=[];seen=set()
 for row in rows:
  require(type(row) is dict and type(row.get('Names')) is list,'TYPED_CONTAINER_SUMMARY_REQUIRED')
  if not any(type(n) is str and n.startswith('/ouf-') for n in row['Names']):continue
  identifier=row.get('Id');require(type(identifier) is str and re.fullmatch('[a-f0-9]{64}',identifier) and identifier not in seen,'UNIQUE_OUF_CONTAINER_REQUIRED')
  seen.add(identifier);selected.append(identifier)
 require(0<len(selected)<=PROFILE['maximumContainers'],'BOUNDED_NONEMPTY_OUF_CONTAINER_SET_REQUIRED');return selected

def environment(doc):
 result={}
 for entry in doc.get('Config',{}).get('Env') or []:
  require(type(entry) is str and '=' in entry,'TYPED_ENVIRONMENT_ENTRY_REQUIRED');key,value=entry.split('=',1)
  require(key not in result,'DUPLICATE_ENVIRONMENT_KEY');result[key]=value
 return result

def minio_admission(doc,expected_native):
 require(doc.get('Name')=='/ouf-minio' and doc.get('Image')==expected_native,'EXACT_RETAINED_MINIO_NATIVE_IMAGE_REQUIRED')
 state=doc.get('State',{});require(state.get('Running') is True and state.get('Paused') is False and type(state.get('Pid')) is int and state['Pid']>1,'LIVE_UNPAUSED_MINIO_REQUIRED')
 args=doc.get('Args') or [];require(type(args) is list and all(type(v) is str for v in args),'TYPED_MINIO_ARGUMENTS_REQUIRED')
 env=environment(doc);address=env.get('MINIO_ADDRESS',':9000')
 for i,a in enumerate(args):
  if a=='--address':require(i+1<len(args),'MINIO_ADDRESS_VALUE_REQUIRED');address=args[i+1]
  elif a.startswith('--address='):address=a.split('=',1)[1]
 require(address in (':9000','0.0.0.0:9000','127.0.0.1:9000'),'EXACT_DEFAULT_MINIO_S3_LISTENER_REQUIRED')
 return state['Pid'],env

def credential(pid,env,name):
 path=env.get(name+'_FILE')
 if path:
  p=PurePosixPath(path);require(p.is_absolute() and str(p)==path and '..' not in p.parts,'CANONICAL_PRIVATE_CREDENTIAL_REFERENCE_REQUIRED')
  root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY);opened=[root]
  try:
   current=root
   for part in p.parts[1:-1]:current=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current);opened.append(current)
   fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=current);opened.append(fd);info=os.fstat(fd)
   require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o007 and info.st_nlink==1 and 0<info.st_size<=4096,'PRIVATE_ROOT_CREDENTIAL_METADATA_REQUIRED')
   raw=os.read(fd,4097);require(len(raw)==info.st_size and attrs(info)==attrs(os.fstat(fd)),'STABLE_BOUNDED_CREDENTIAL_REQUIRED')
  finally:
   for fd in reversed(opened):os.close(fd)
 else:
  require(name in env,'EXPLICIT_ROOT_CREDENTIAL_SOURCE_REQUIRED');raw=env[name].encode()
 value=raw.strip();require(0<len(value)<=4096 and b'\n' not in value and b'\r' not in value,'SINGLE_BOUNDED_CREDENTIAL_VALUE_REQUIRED');return value

def file_sha(stream):
 h=hashlib.sha256()
 while raw:=stream.read(1048576):h.update(raw)
 return h.hexdigest()

def sealed_descriptor(raw):
 require(os.uname().sysname=='Linux','LINUX_SEALED_CREDENTIALS_REQUIRED')
 fd=os.memfd_create('ouf-storage-credential',os.MFD_ALLOW_SEALING)
 try:
  os.fchmod(fd,0o600);require(os.write(fd,raw)==len(raw),'COMPLETE_SEALED_CREDENTIAL_WRITE');os.lseek(fd,0,os.SEEK_SET)
  # Stable Linux uapi: F_ADD_SEALS=1033, all SEAL/SHRINK/GROW/WRITE bits=15.
  fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),15);return fd
 except Exception:
  os.close(fd);raise

def filtered_binding(doc):
 allowed={'OUF_ONBOARDING_STAGING_ENDPOINT','OUF_ONBOARDING_STAGING_BUCKET','OUF_UDP_S3_ENDPOINT','OUF_UDP_S3_BUCKET','OUF_UDP_LAKE_S3_ENDPOINT','OUF_UDP_LAKE_S3_BUCKET','OUF_ONBOARDING_OBJECT_STORE_GATEWAY_BASE_URL','OUF_ONBOARDING_OBJECT_STORE_READ_PATH','AWS_REGION','AWS_DEFAULT_REGION'}
 env=environment(doc);state=doc.get('State') or {}
 return {'id':doc['Id'],'name':doc.get('Name'),'nativeImage':doc.get('Image'),'running':state.get('Running'),'paused':state.get('Paused'),
 'storageBindingValues':{k:v for k,v in env.items() if k in allowed},'environmentNames':sorted(env),
 'mounts':[{k:m.get(k) for k in ['Type','Name','Source','Destination','RW']} for m in doc.get('Mounts') or []]}

def capture(control,engine):
 frames,_,_=origins.history(control)
 result=decode(control.read(origins.OUTPUT/'result.json',0,0,0o600,65536,'metadataReads'))
 private=decode(control.read(origins.OUTPUT/'runtime-origin.private.json',0,0,0o600,2097152,'metadataReads'))
 require(digest(result)==ORIGIN_RESULT and digest(private)==ORIGIN_PRIVATE,'EXACT_CONSUMED_ORIGIN_CHECKPOINT_REQUIRED')
 for p in [origins.OUTPUT,origins.OUTPUT/'result.json',origins.OUTPUT/'runtime-origin.private.json']:frames[str(p)]=attrs(p.lstat())
 def stable():
  control.check();require(all(attrs(Path(p).lstat())==v for p,v in frames.items()),'PRIOR_SCOPES_CHANGED')
 stable();ids=select_containers(engine.get('/containers/json?all=1'));bindings=[];minio=None
 for identifier in ids:
  stable();doc=engine.get('/containers/'+identifier+'/json');require(doc.get('Id')==identifier,'EXACT_CONTAINER_ID_RESPONSE_REQUIRED');bindings.append(filtered_binding(doc))
  if doc.get('Name')=='/ouf-minio':require(minio is None,'UNIQUE_MINIO_REQUIRED');minio=doc
 require(minio is not None,'RETAINED_MINIO_CONTAINER_REQUIRED')
 pid,env=minio_admission(minio,private['roles']['minio']['nativeImageId']);pin=process_pin(pid)
 root=Path('/proc/'+str(pid)+'/root');memory=Path('/proc/meminfo').read_text();require(len(memory)<=32768,'BOUNDED_MEMORY_METADATA_REQUIRED')
 capacity=[]
 for m in minio.get('Mounts') or []:
  if m.get('Destination')=='/data':
   filesystem=os.statvfs(m['Source']);capacity.append({'destination':'/data','freeBytes':filesystem.f_bavail*filesystem.f_frsize,'totalBytes':filesystem.f_blocks*filesystem.f_frsize})
 require(len(capacity)==1,'ONE_MINIO_DATA_MOUNT_REQUIRED')
 host={'bindings':bindings,'minioProcessPin':pin,'capacity':capacity,'memoryInfo':memory,'pointInTimeSnapshotProven':False,'externalConsumersProvenAbsent':False};control.put('host-baseline.private.json',host)
 Capture.ancestors(BACKEND);metadata=BACKEND.lstat();require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid==metadata.st_gid==0 and stat.S_IMODE(metadata.st_mode)==0o500 and metadata.st_nlink==1 and 0<metadata.st_size<=33554432,'ROOT_PINNED_INVENTORY_BACKEND_REQUIRED')
 with BACKEND.open('rb') as f:require(file_sha(f)==BACKEND_SHA,'EXACT_QUALIFIED_INVENTORY_BACKEND_REQUIRED')
 stable();descriptors=[]
 try:
  for name in ['MINIO_ROOT_USER','MINIO_ROOT_PASSWORD']:descriptors.append(sealed_descriptor(credential(pid,env,name)))
  require(process_pin(pid)==pin,'MINIO_NAMESPACE_PIN_CHANGED');stable()
  config={'endpoint':'http://127.0.0.1:9000','region':env.get('MINIO_REGION_NAME') or env.get('MINIO_REGION') or 'us-east-1','allowLoopbackHttp':True,'accessKeyFd':descriptors[0],'secretKeyFd':descriptors[1]}
  control.put('inventory-config.private.json',config)
  timeout=min(320,int(control.until-time.monotonic()));require(timeout>=10,'INVENTORY_CONTROL_DEADLINE')
  completed=subprocess.run(['/usr/bin/nsenter','--net=/proc/'+str(pid)+'/ns/net','--',str(BACKEND),str(control.scope/'inventory-config.private.json'),str(control.scope/'s3')],pass_fds=descriptors,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','GOMEMLIMIT':'256MiB','GOMAXPROCS':'1'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
  require(len(completed.stdout)<=4096 and len(completed.stderr)<=4096,'MINIMIZED_BACKEND_OUTPUT_REQUIRED')
  require(process_pin(pid)==pin,'MINIO_NAMESPACE_PIN_CHANGED');stable()
  report=decode(completed.stdout);require(completed.returncode==0 and report.get('complete') is True and report.get('objectBodiesRead')==report.get('targetWrites')==0,'PRIVATE_INVENTORY_INCOMPLETE')
  fd=os.open(control.scope/'s3/inventory.private.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  with os.fdopen(fd,'rb') as stream:
   info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and 0<info.st_size<=67108864,'BOUNDED_ROOT_PRIVATE_INVENTORY_REQUIRED')
   private_hash=file_sha(stream);require(attrs(info)==attrs(os.fstat(stream.fileno())),'PRIVATE_INVENTORY_CHANGED')
  stable()
  return {'status':'PRIVATE_STORAGE_BASELINE_CAPTURED_NOT_ADMITTED','privateInventorySha256':private_hash,'hostBaselineHash':digest(host),'profileHash':digest(PROFILE),'parentOriginResultHash':ORIGIN_RESULT,'s3Complete':True,'storageDataFreeBytes':capacity[0]['freeBytes'],'storageDataTotalBytes':capacity[0]['totalBytes'],'inventorySummary':report['summary'],'records':report['records'],'s3Requests':report['requests'],'containersObserved':len(bindings),'directEngineGets':engine.gets,'cumulativeDirectEngineGets':35+engine.gets,'cumulativeControlAttempts':13,'credentialSourcesOpened':2,'credentialBytesSpooled':0,'allTwelvePriorScopesPreserved':True,'pointInTimeSnapshotProven':False,'externalConsumersProvenAbsent':False,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'releaseAcceptance':False}
 finally:
  for fd in descriptors:os.close(fd)

def main():
 control=None;engine=None
 try:
  require(sys.argv[1:]==[] and os.geteuid()==os.getegid()==0,'ROOT_ISOLATED_NO_ARGUMENT_ENTRY_REQUIRED');require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_STDLIB_ENTRY_REQUIRED')
  os.umask(0o077);control=Capture(SCOPE);control.until=time.monotonic()+PROFILE['maximumSeconds'];control.put('storage-baseline.claim.json',{'profile':PROFILE,'automaticReplayAllowed':False});engine=Engine(control)
  report=capture(control,engine);control.put('result.json',report);code=0
 except Exception as error:
  reason=str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}',str(error)) else 'STORAGE_BASELINE_UNPROVEN'
  report={'status':'STOP_RECONCILE','reasonCode':reason,'scopeConsumed':os.path.lexists(SCOPE),'directEngineGets':engine.gets if engine else 0,'cumulativeControlAttempts':13 if control else 12,'cumulativeDirectEngineGets':35+(engine.gets if engine else 0),'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
  if control:
   try:control.put('result.json',report)
   except Exception:pass
  code=1
 print(json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
