#!/usr/bin/env python3
"""Installation-specific candidate staging and private review. No runtime effects."""
import ast,copy,fcntl,hashlib,http.client,importlib.util,io,json,os,re,signal,socket,stat,sys,tarfile,tempfile,time,zipfile
from pathlib import Path,PurePosixPath
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_SHA='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CASE_SHA='18ff5a8436d2058c6e9c6820cf8b017facb58e42ce718eee4bf0c1591781ae40'
CUSTODY_SHA='9391a7d497943bd0412d96405d51359cd11a2b0db7106d30f272d28e8f0fc6b2'
GATEWAY_CUSTODY_SHA='5e7182d899a25a299b103d63f6bf81822280f09e58b963c38f735aa2a4fee72f'
LIMIT=1200000000
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def safe_reason(error):
 known=isinstance(error,ValueError)or type(error).__name__ in ('ReadDenied','PlanDenied')
 return str(error)if known and re.fullmatch('[A-Z_]{1,160}',str(error))else type(error).__name__
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def emit(check,**v):
 print(json.dumps(dict(schema='ouf.ingestion-readiness-private-review.v1',check=check,newPrivateReviewOnly=True,readOnly=False,automaticRetry=False,
  existingConfigurationWrites=0,engineWrites=0,serviceMutations=0,gatewayWrites=0,databaseCalls=0,
  grantRequests=0,credentialFilesRead=0,privateKeysRead=0,humanSessionStateRead=False,budgetReset=False,
  runtimeAuthorityIssued=False,completedTechnicalPhases=8,functionalMilestonesProven=1,**v),sort_keys=True),flush=True)
def input_bytes(path,expected,maximum,protected=False):
 p=Path(path);require(p.is_absolute()and str(p)==str(path)and '..'not in p.parts,'EXACT_INPUT_PATH_REQUIRED')
 fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY)]
 try:
  for part in p.parts[1:-1]:
   fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
   if protected:
    s=os.fstat(fds[-1]);require(s.st_uid==0 and not s.st_mode&0o022,'ROOT_INPUT_ANCESTRY_REQUIRED')
  fds.append(os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1]))
  before=os.fstat(fds[-1]);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum,'BOUNDED_INPUT_REQUIRED')
  if protected:require(before.st_uid==0 and not before.st_mode&0o022,'ROOT_INPUT_CUSTODY_REQUIRED')
  raw=os.read(fds[-1],maximum+1)
  require(len(raw)==before.st_size and pin(before)==pin(os.fstat(fds[-1]))and hashlib.sha256(raw).hexdigest()==expected,'INPUT_BYTE_DRIFT')
  return raw
 finally:
  for fd in reversed(fds):os.close(fd)
def module(raw,name):
 spec=importlib.util.spec_from_loader(name,loader=None);m=importlib.util.module_from_spec(spec)
 exec(compile(raw,'<verified-private-preparation:'+name+'>','exec'),m.__dict__);return m
def projection_reader(raw):
 # Reuse only the qualified custody reader; never import the Gateway publisher.
 require(hashlib.sha256(raw).hexdigest()==GATEWAY_CUSTODY_SHA,'GATEWAY_CUSTODY_SOURCE_DRIFT')
 names={'EXTERNAL_ADMIN_KEY','_EXISTING_CONFIG_CUSTODY','selected_directory_custody','selected_file_custody','private_config'}
 nodes=[];seen=set()
 for node in ast.parse(raw).body:
  name=node.name if isinstance(node,ast.FunctionDef)else node.targets[0].id if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)else None
  if name in names:nodes.append(node);seen.add(name)
 require(seen==names,'GATEWAY_CUSTODY_READER_REQUIRED')
 ns={'os':os,'stat':stat,'Path':Path,'hashlib':hashlib,'require':require}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<qualified-gateway-custody-reader>','exec'),ns)
 def read(binding):
  require(binding.get('path')=='/opt/ouf/installation/active-projection.json','EXACT_SELECTED_PROJECTION_REQUIRED')
  return json.loads(ns['private_config'](binding['path'],binding)[0])
 return read
def write_new(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
def copy_artifact(path,target,expected):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=LIMIT,'BOUNDED_ARTIFACT_REQUIRED')
  out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=hashlib.sha256();size=0
  try:
   with os.fdopen(os.dup(out),'wb')as f:
    while True:
     block=os.read(fd,1048576)
     if not block:break
     size+=len(block);require(size<=LIMIT,'ARTIFACT_LIMIT');h.update(block);f.write(block)
    f.flush();os.fsync(f.fileno())
  finally:os.close(out)
  require(size==s.st_size and pin(s)==pin(os.fstat(fd))and h.hexdigest()==expected,'ARTIFACT_COPY_DRIFT')
 finally:os.close(fd)
def zip_index(z):
 rows=z.infolist();require(0<len(rows)<=4096,'BOUNDED_ZIP_INDEX_REQUIRED');result={}
 for row in rows:
  p=PurePosixPath(row.filename);mode=row.external_attr>>16
  require(str(p)==row.filename.rstrip('/')and not p.is_absolute()and '..'not in p.parts
   and row.filename not in result and not row.flag_bits&1 and stat.S_IFMT(mode)in(0,stat.S_IFREG,stat.S_IFDIR)
   and row.compress_type in(zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED)and 0<=row.file_size<=LIMIT,'SAFE_ZIP_MEMBER_REQUIRED')
  if not row.is_dir():result[row.filename]=row
 require(sum(r.file_size for r in result.values())<=LIMIT,'ZIP_EXPANSION_BOUND')
 return result
def sums(raw):
 result={}
 for line in raw.decode('ascii').splitlines():
  m=re.fullmatch(r'([0-9a-f]{64})  (.+)',line);require(m is not None,'HASH_LIST_SHAPE')
  p=PurePosixPath(m[2]);require(str(p)==m[2]and not p.is_absolute()and '..'not in p.parts and m[2]not in result,'SAFE_HASH_LIST')
  result[m[2]]=m[1]
 return result
def member(z,index,name,maximum):
 require(name in index and 0<index[name].file_size<=maximum,'BOUNDED_PACKAGE_MEMBER_REQUIRED')
 return z.read(name)
def verified_zip(z,index):
 mapping=sums(member(z,index,'SHA256SUMS',1048576))
 require(set(mapping)==set(index)-{'SHA256SUMS','SHA256SUMS.sigstore.json'}
  and 'SHA256SUMS.sigstore.json'in index,'COMPLETE_AGGREGATE_HASH_LIST_REQUIRED')
 for name,expected in mapping.items():
  with z.open(name)as f:
   h=hashlib.sha256()
   while True:
    block=f.read(1048576)
    if not block:break
    h.update(block)
   require(h.hexdigest()==expected,'AGGREGATE_MEMBER_HASH_DRIFT')
 return mapping
def extract_member(z,index,name,target,maximum):
 require(name in index and 0<index[name].file_size<=maximum,'BOUNDED_EXTRACT_MEMBER_REQUIRED')
 fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with z.open(name)as source,os.fdopen(os.dup(fd),'wb')as dest:
   total=0
   while True:
    block=source.read(1048576)
    if not block:break
    total+=len(block);require(total<=maximum,'EXTRACT_BOUND');dest.write(block)
   dest.flush();os.fsync(dest.fileno())
 finally:os.close(fd)
def engine_info(ns,engine):
 path=engine['socketPath']
 def guard():
  s=os.stat(path,follow_symlinks=False);require(stat.S_ISSOCK(s.st_mode)and
   (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==tuple(engine['socketBinding']),'ENGINE_SOCKET_DRIFT')
 class Local(http.client.HTTPConnection):
  def connect(self):
   self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(10);self.sock.connect(path)
 guard();c=Local('localhost',timeout=10)
 try:
  c.request('GET','/v1.44/info');response=c.getresponse();raw=response.read(2097153)
  require(response.status==200 and len(raw)<=2097152,'ENGINE_INFO_UNAVAILABLE');guard()
  value=json.loads(raw);status=dict(value.get('DriverStatus')or[])
  if value.get('Driver')=='overlayfs'and status.get('driver-type')=='io.containerd.snapshotter.v1':return True
  require(value.get('Driver')=='overlay2'and status.get('driver-type')!='io.containerd.snapshotter.v1','NATIVE_IMAGE_STORE_UNQUALIFIED')
  return False
 finally:c.close()
def check_worker(ns,case):
 w=case['worker'];root=Path(w['contextPath']);review=ns['read'](root/'review.json',8388608,w['reviewSha256'])
 authority=ns['read'](root/'authority.json',131072,w['authoritySha256']);journal=Path(w['journalPath'])
 require(journal.resolve()==journal,'EXACT_WORKER_JOURNAL_REQUIRED')
 for p in(journal,*journal.parents):
  s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'WORKER_ANCESTRY_DRIFT')
 fd=os.open(journal/'invocation.lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size==0 and s.st_nlink==1,'WORKER_LOCK_CUSTODY')
  fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
  records={name:ns['read'](journal/name,131072,sha)for name,sha in w['recordHashes'].items()}
  old=records['recovery.json'];session=records['owner-session.json'];last=records['owner-status.json']
  require(authority.get('policyTokenFiniteWorkerSession')==review['scopes']['policyTokenFiniteWorkerSession']==session
   and old.get('workerSessionHash')==digest(session)and old.get('state')==last.get('state')=='CANCELLED'
   and old.get('reason')==last.get('reason')=='CANCELLED_BY_OWNER'and old.get('attempts')==last.get('attempts')==60
   and old.get('controlledPredecessorGrantAttempts')==128 and old.get('controlledCumulativeGrantAttempts')==188
   and session.get('maximumCumulativeGrantAttempts')==197 and time.time()>=authority['expiresAt']
   and records['owner-admission.json'].get('state')=='BLOCKED','RETAINED_WORKER_CHANGED')
  return dict(**w,records=records,authorityExpired=True,invocationLockUnheldAtRead=True)
 finally:os.close(fd)
def tar_sources(z,index,prefix,wanted):
 name=prefix+'source.tar';raw=member(z,index,name,67108864);result={}
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as tar:
  rows=tar.getmembers();require(len(rows)<=4096,'BOUNDED_SOURCE_ARCHIVE_REQUIRED')
  for row in rows:
   if row.name in wanted:
    require(row.isfile()and 0<row.size<=1048576 and row.name not in result,'EXACT_SOURCE_HELPER_REQUIRED')
    result[row.name]=tar.extractfile(row).read(1048577)
 require(set(result)==set(wanted),'PACKAGE_HELPER_MISSING')
 return result
def prepare(archive_path,case_path,custody_path,gateway_custody_path):
 case=json.loads(input_bytes(case_path,CASE_SHA,1048576))
 ns={'__name__':'preparation_read_only'};exec(compile(input_bytes(BOOT,BOOT_SHA,131072,True),'<verified-retained-helper>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);b=old['scopes']['finiteActionProcess']['bundle']
 prepared=ns['read'](b['path'],8388608,b['sha256'])['prepared'];engine=prepared['engine']
 projection=prepared['gatewayPlan']['projectionBinding']
 read_projection=projection_reader(input_bytes(gateway_custody_path,GATEWAY_CUSTODY_SHA,131072))
 profile=read_projection(projection)
 emit('SELECTED_PROJECTION_CUSTODY',exactRetainedBindingMatched=True,configurationValuesPrinted=False)
 actual={name:ns['engine_get'](engine,'containers',name)for name in case['expectedRuntimeBindings']}
 require(all(v and v['State']['Running']and ns['runtime_pin'](v)==case['expectedRuntimeBindings'][name]for name,v in actual.items()),'CURRENT_REVIEWED_GENERATION_CHANGED')
 worker=check_worker(ns,case);containerd=engine_info(ns,engine)
 custody=module(input_bytes(custody_path,CUSTODY_SHA,1048576),'image_custody')
 parent=Path('/etc/ouf/deploy-snapshots');require(parent.resolve()==parent,'PRIVATE_PARENT_REQUIRED')
 for p in(parent,*parent.parents):
  st=p.lstat();require(stat.S_ISDIR(st.st_mode)and st.st_uid==0 and not st.st_mode&0o022,'PRIVATE_PARENT_CUSTODY')
 require(os.statvfs(parent).f_bavail*os.statvfs(parent).f_frsize>=3500000000,'PRIVATE_PACKAGE_SPACE_REQUIRED')
 output=Path(tempfile.mkdtemp(prefix='ingestion-readiness-update-review-',dir=parent));output.chmod(0o700)
 emit('PACKAGE_CUSTODY',maximumPackageBytes=LIMIT)
 copy_artifact(archive_path,output/'candidate.zip',case['artifact']['zipSha256'])
 images={};metas={};route=None
 with zipfile.ZipFile(output/'candidate.zip')as z:
  index=zip_index(z);mapping=verified_zip(z,index)
  lock=member(z,index,'source-lock.json',1048576)
  require(hashlib.sha256(lock).hexdigest()==case['artifact']['sourceLockSha256'],'SOURCE_LOCK_CHANGED')
  for selected in case['modules']:
   name=selected['module'];prefix='parts/ingestion-readiness-part-'+name+'-'+str(case['artifact']['runId'])+'/'
   meta=json.loads(member(z,index,prefix+'candidate-manifest.json',1048576))
   require(meta.get('sourceCommit')==selected['sourceCommit']and meta.get('module')==name
    and meta.get('imageId')==selected['imageId']and meta.get('sourceLockSha256')==case['artifact']['sourceLockSha256']
    and meta.get('scanGate')=='PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
    and meta.get('runtimeAuthorityIssued')is False and meta.get('targetApplyAuthorized')is False,'CANDIDATE_SCOPE_DRIFT')
   metas[name]=meta
   inventory=json.loads(member(z,index,prefix+'source-inventory.json',8388608))
   require(inventory.get('truncated')is False,'COMPLETE_SOURCE_INVENTORY_REQUIRED')
   if name!='gateway':
    migrated=[r for r in inventory['tree']if r['path'].startswith('src/main/resources/db/migration/')and r['path'].endswith('.sql')]
    require(migrated==case['expectedMigrationTrees'][name],'MIGRATION_SOURCE_CHANGED')
    emit('IMAGE_BYTE_CUSTODY',module=name)
    original=output/(name+'.original.tar');candidate=output/(name+'.candidate.tar')
    extract_member(z,index,prefix+'image.docker.tar',original,LIMIT)
    with original.open('rb')as f:
     audit=custody.archive(f,mapping[prefix+'image.docker.tar'],selected['imageId'],selected['sourceCommit'])
     with candidate.open('x+b')as dest:
      os.chmod(candidate,0o600);derived=custody.tagless_archive(f,dest,audit,containerd=containerd);dest.flush();os.fsync(dest.fileno())
    with candidate.open('rb')as f:audit=custody.archive(f,derived['derivedArchiveSha256'],selected['imageId'],selected['sourceCommit'])
    require(not audit['repositoryTags'],'TAGLESS_IMAGE_REQUIRED')
    if containerd:audit['nativeIdentity']=custody.native_identity(audit)
    current=actual[selected['runtimeName']];config=audit['imageConfig']
    require(current['Config']['User']==config['User']and current['Config']['Entrypoint']==config['Entrypoint']
     and current['Config']['WorkingDir']==config.get('WorkingDir',''),'RETAINED_APPLICATION_LAUNCH_CHANGED')
    original.unlink()
    previous=next(r for r in prepared['cohortPlan']['replacements']if r['module']==name)
    images[name]={'imageAudit':audit,'imageArchive':{'path':str(candidate),'sha256':derived['derivedArchiveSha256']},
     'nativeImageId':custody.runtime_image_id(audit),'oldRuntimeBinding':case['expectedRuntimeBindings'][selected['runtimeName']],
     'oldNativeConfig':current['Config'],'oldNativeHostConfig':current['HostConfig'],'oldNativeMounts':current['Mounts'],
     'oldNativeNetworks':current['NetworkSettings']['Networks'],'retainedCreationRequest':previous['creationRequest'],
     'migrationFilesUnchanged':True,'expectedMigrationTree':migrated}
   else:
    wanted=['tools/apply_installation_projection.py','tools/materialize_apisix_internal_m2m_routes.py']
    source=tar_sources(z,index,prefix,wanted)
    for key,raw in source.items():
     entry=next(r for r in inventory['tree']if r['path']==key)
     require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==entry['sha'],'SOURCE_HELPER_IDENTITY_DRIFT')
    projector=module(source[wanted[0]],'projector');materializer=module(source[wanted[1]],'materializer')
    compiled=json.loads(member(z,index,prefix+'compiled-route-declarations.json',8388608))
    runtime=projector.apply_projection(compiled,profile)
    old_route=prepared['gatewayPlan']['proposedRoutes']['trusted-human-onboarding-lifecycle-get']
    secret_ref=old_route['plugins']['openid-connect']['client_secret']
    packet=materializer.materialize(runtime,['r4a-onboarding-ingestion-configuration-read'],secret_ref)
    require(len(packet['routes'])==1 and packet['routes'][0]['methods']==['GET'],'ONE_READ_ROUTE_REQUIRED')
    route={'proposedRoute':packet['routes'][0],'targetProjectionBinding':projection,'targetRuntimeHash':digest(runtime),
     'currentGatewayRuntimeBinding':case['expectedRuntimeBindings']['ouf-apisix'],'previousQualifiedRouteMapHash':prepared['gatewayPlan']['proposedRuntimeHash'],
     'maximumPutAttempts':1,'deleteAllowed':False,'existingRouteOverwriteAllowed':False,'liveRouteAbsenceProven':False}
 for name,expected in case['expectedRuntimeBindings'].items():
  require(ns['runtime_pin'](ns['engine_get'](engine,'containers',name))==expected,'RUNTIME_CHANGED_DURING_PREPARATION')
 check_worker(ns,case)
 require(read_projection(projection)==profile,'SELECTED_PROJECTION_CHANGED_DURING_PREPARATION')
 finite=case['finiteTestProfile'];require(finite['maximumNewTokenGrantAttempts']==128 and finite['maximumSeconds']==3600,'EXACT_TEST_PROFILE_REQUIRED')
 review={'schema':'ouf.ingestion-readiness-update-private-review.v1','authorityDirectory':str(output),
  'engine':engine,'candidateArtifact':case['artifact'],'candidateModules':metas,'images':images,'gateway':route,
  'retainedWorker':worker,'finiteTestProfile':finite,'proposedWorkerBudget':{'priorControlledGrantAttempts':188,
   'maximumNewTokenGrantAttempts':128,'maximumCumulativeGrantAttempts':316,'maximumSeconds':3600,
   'historicalSessionCeiling':197,'historicalRecordsChanged':False,'freshHumanDecisionRequired':True},
  'source':case['source'],'humanSelection':{k:prepared['authorization']['plan']['selection'][k]for k in('issuer','tenant','subject')},
  'maximumApplicationReplacementAttempts':{'onboarding':1,'ingestion':1},
  'imageImportAttemptsPerImage':1,'databaseMigrationsAllowed':False,'grantChangesAllowed':False,
  'semanticDispatchAllowed':False,'approvalReplayAllowed':False,'automaticRollbackAllowed':False,'budgetReset':False,
  'maximumExecutionSeconds':900,'readyForExecution':False,'runtimeAuthorityIssued':False,'humanApprovalGranted':False,
  'pendingGates':['NATIVE_SCOPED_EXECUTOR_QUALIFICATION','FRESH_GATEWAY_ROUTE_ABSENCE_AND_RUNTIME_CHECK',
   'FRESH_AUTHENTICATED_EXACT_ROLLOUT_REVIEW','EXISTING_ROLE_SIGNATURES','SEPARATE_EXPLICIT_TEST_WORKER_SESSION',
   'CURRENT_OWNER_POLICY_AND_HUMAN_THS_RESUME'],
  'completedTechnicalPhases':8,'functionalMilestonesProven':1}
 write_new(output/'review.json',encoded(review))
 emit('END',complete=True,reviewPath=str(output/'review.json'),reviewSha256=digest(review),readyForExecution=False,
  candidateNativeImageIds={k:v['nativeImageId']for k,v in images.items()},routeCount=1,migrationFilesUnchanged=True,
  controlledCumulativeGrantAttempts=188,proposedNewWorkerAttempts=128,proposedMaximumCumulativeGrantAttempts=316,
  newWorkerSessionStarted=False)
def main():
 require(os.geteuid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(len(sys.argv)==5,'EXACT_PREPARATION_ARGUMENTS_REQUIRED');os.umask(0o077)
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(ValueError('PREPARATION_DEADLINE')));signal.alarm(300)
 emit('BEGIN',maximumSeconds=300,maximumEngineReads=7,newPrivateFilesOnly=True)
 prepare(*sys.argv[1:])
if __name__=='__main__':
 try:main()
 except Exception as error:
  emit('STOP',reason=safe_reason(error),exceptionMessagePrinted=False)
  raise SystemExit(2)

