"""Retained-host MCP-only preparation. No old execution or completed read replay."""
import base64,hashlib,json,os,re,signal,stat,sys,tempfile,time
from pathlib import Path
STAGE=Path('/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-ingestion-read-transport-39232718756')
MANIFEST='c685d0c26e7fcdf4936c5d86341a79f23310b09e40b02441b870ff89333a0ce6'
SOURCE='1f2c28d7abadae78680b040ba7b58be62ef85ee9'
IMAGE='sha256:bf40c534c96221e5cc989871a13465565942e86556751410ba6812a977e40631'
DIAGNOSTIC='661726c94b71aeb2b820ecf945ea5b15e7fdd9bca4b6f08f55275528f556da1b'
INSTALLED=Path('/etc/ouf/deploy-snapshots/source-revision-execution-uow4n8lp')
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def stage_bytes(path,expected,maximum=8388608):
 path=Path(path);require(path.resolve()==path and path.is_absolute(),'EXACT_STAGE_MEMBER_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  first=os.fstat(fd);require(stat.S_ISREG(first.st_mode)and first.st_nlink==1 and 0<first.st_size<=maximum,'BOUNDED_STAGE_MEMBER_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  require(len(raw)==first.st_size and sha(raw)==expected,'STAGED_MEMBER_CHANGED')
  return raw
 finally:os.close(fd)

def copy_archive(source,target,expected):
 fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1
   and 0<before.st_size<=1200000000,'BOUNDED_CANDIDATE_ARCHIVE_REQUIRED')
  out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  h=hashlib.sha256();count=0
  try:
   with os.fdopen(os.dup(fd),'rb')as inp,os.fdopen(os.dup(out),'wb')as stream:
    while True:
     raw=inp.read(1048576)
     if not raw:break
     count+=len(raw);require(count<=1200000000,'ARCHIVE_COPY_BOUND_EXHAUSTED');h.update(raw);stream.write(raw)
    stream.flush();os.fsync(stream.fileno())
  finally:os.close(out)
  fields=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  require(count==before.st_size and fields(before)==fields(os.fstat(fd))==fields(Path(source).lstat())
   and h.hexdigest()==expected,'CANDIDATE_ARCHIVE_CHANGED_DURING_COPY')
 finally:os.close(fd)

def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)=={'prepare','entry','authority','owner','native','runtime','bootstrap','diagnostic'}
  and re.fullmatch('[0-9a-f]{40}',commit)and sha(delivery['diagnostic'])==DIAGNOSTIC,'EXACT_QUALIFIED_MCP_UPDATE_DELIVERY_REQUIRED')
 os.umask(0o077)
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_MCP_PREPARATION_DEADLINE_EXHAUSTED')))
 signal.alarm(300)
 ns={'__name__':'qualified_existing_custody_helpers'}
 exec(compile(delivery['diagnostic'],'<qualified-existing-custody-helpers>','exec'),ns)
 read,raw_read,write_new=ns['read'],ns['raw_read'],ns['write_new']
 print('OUF_MCP_INGESTION_PREPARATION_PHASE=VERIFY_RETAINED_CUSTODY',flush=True)
 entry,sources,old_case,original,base_package,base_receipt,_=ns['load_capsule']()
 selection=original['authorization']['plan']['selection']
 human,row=ns['existing_human'](entry,old_case,selection,base_package['closure'])
 require(216<=row['attempts']<=256 and human.expires_at==1792405963
  and human.expires_at-time.time()>=900,'EXISTING_HUMAN_WINDOW_OR_CUMULATIVE_BUDGET_UNAVAILABLE')
 print('OUF_MCP_INGESTION_PREPARATION_PHASE=VERIFY_COMPLETED_HISTORY_AS_FILES',flush=True)
 # Exact private history; no readback main, database, old effect or login runs.
 reader={'__name__':'qualified_completed_file_history'}
 reader_raw=raw_read(ns['CONTEXT']/'reader.py',expected=base_package['fileHashes']['reader.py'])
 exec(compile(reader_raw,'<qualified-completed-file-history>','exec'),reader)
 previous,_=reader['frozen_preparation']()
 require(digest(previous)=='3eb2fd4fff1048accdb954322faa58979bb490250c8535c1dd8512253e603587','EXACT_COMPLETED_PREPARATION_REQUIRED')
 old_review=read(INSTALLED/'review.json');old_plan=read(INSTALLED/'execution-plan.json');history=read(INSTALLED/'recovery.json')
 old_authority=raw_read(INSTALLED/'authority.json')
 reader['completed_history'](history,old_plan,old_review,old_authority)
 require(old_review['scopes']['sourceRevisionUpdate']['planHash']==digest(old_plan)
  and history['effects'][-1]['stage']=='VERIFY_FINAL'and all(e['state']=='APPLIED'for e in history['effects']),
  'COMPLETED_INSTALLATION_HISTORY_REQUIRED')
 manifest=json.loads(stage_bytes(STAGE/'qualified-package.json',MANIFEST))
 require(manifest['schema']=='ouf.ingestion-read-transport-staged-package.v1'and manifest['sourceCommit']==SOURCE
  and manifest['targetApplyAuthorized']is False and manifest['runtimeAuthorityIssued']is False,'EXACT_STAGED_CANDIDATE_REQUIRED')
 candidate=json.loads(stage_bytes(STAGE/'candidate-manifest.json',manifest['files']['candidate-manifest.json']))
 require(candidate==manifest['candidateManifest']and candidate['sourceCommit']==SOURCE and candidate['imageId']==IMAGE
  and candidate['module']=='mcp'and candidate['scanGate']=='PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
  and candidate['executableSha256']=='7643d98d90bfe75958c3debee51348bd96803bfc3afb82446a383cd34434e8b1',
  'EXACT_SCANNED_MCP_CANDIDATE_REQUIRED')
 for name in ('source-inventory.json','package-record.json','trivy-image.json','Dockerfile.resolved','SHA256SUMS'):
  stage_bytes(STAGE/name,manifest['files'][name])
 for name in ('entry','authority','owner','native'):sources['tools.ingestion_read_transport_update.'+name]=delivery[name]
 loader=delivery['runtime'];memory={'__name__':'qualified_mcp_update_closed_loader'}
 exec(compile(loader,'<qualified-mcp-update-closed-loader>','exec'),memory);memory['compile_sources'](sources)
 root=ns['ROOT'];context=Path(tempfile.mkdtemp(prefix='mcp-ingestion-read-transport-execution-',dir=root))
 claim='mcp-ingestion-read-transport-preparation-'+digest({'oldContainerId':'c6fc3a462f4e1faf1e8121fee13ca445f7a3f7f1f39df65d738ea9cc1d4185f4',
  'candidateSourceCommit':SOURCE})+'.claim.json'
 write_new(root,claim,encoded({'context':str(context),'candidateSourceCommit':SOURCE,'sourceCommit':commit,
  'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False}))
 print('OUF_MCP_INGESTION_PREPARATION_PHASE=COPY_AUTHENTICATED_CANDIDATE',flush=True)
 copy_archive(STAGE/'image.docker.tar',context/'original-image.docker.tar',manifest['files']['image.docker.tar'])
 print('OUF_MCP_INGESTION_PREPARATION_PHASE=AUDIT_EXACT_IMAGE_BYTES',flush=True)
 import image_custody
 from engine_creation import Engine
 engine=Engine(old_plan['engine']['socketPath'],tuple(old_plan['engine']['socketBinding']))
 status,info=engine.request('GET','/v1.44/info');require(status==200,'RETAINED_ENGINE_INFO_REQUIRED')
 containerd=any(k=='driver-type'and v=='io.containerd.snapshotter.v1'for k,v in(info.get('DriverStatus')or[]))
 require(containerd==('nativeIdentity'in old_plan['replacements']['mcp']['imageAudit']),'RETAINED_IMAGE_STORE_PROFILE_CHANGED')
 with(context/'original-image.docker.tar').open('rb')as f:
  audit=image_custody.archive(f,manifest['files']['image.docker.tar'],IMAGE,SOURCE)
 with(context/'original-image.docker.tar').open('rb')as inp:
  fd=os.open(context/'candidate-image.docker.tar',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'w+b')as output:derived=image_custody.tagless_archive(inp,output,audit,containerd=containerd);os.fsync(output.fileno())
 with(context/'candidate-image.docker.tar').open('rb')as f:
  audited=image_custody.archive(f,derived['derivedArchiveSha256'],IMAGE,SOURCE)
 if containerd:audited['nativeIdentity']=image_custody.native_identity(audited)
 image={'imageAudit':audited,'imageArchive':{'path':str(context/'candidate-image.docker.tar'),'sha256':derived['derivedArchiveSha256']}}
 write_new(context,'image-custody.json',encoded(image));write_new(context,'candidate-provenance.json',encoded({'manifest':manifest,'derivedArchive':derived}))
 print('OUF_MCP_INGESTION_PREPARATION_PHASE=SEAL_NEW_MCP_ONLY_CAPSULE',flush=True)
 case={'schema':'ouf.mcp-ingestion-read-transport-case.v1','sourceId':'teatri-csv-6609b245',
  'originalBinding':old_case['originalBinding'],'humanBinding':row['binding'],'priorOAuthAttempts':row['attempts'],
  'installedPlanBinding':{'path':str(INSTALLED/'execution-plan.json'),'sha256':digest(old_plan)},
  'installedJournalBinding':{'path':str(INSTALLED/'recovery.json'),'sha256':digest(history)},
  'imageBinding':{'path':str(context/'image-custody.json'),'sha256':digest(image)},
  'preparationClaimBinding':{'path':str(root/claim),'sha256':sha(raw_read(root/claim))}}
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':loader,'reader.py':reader_raw,
  'sources.json':encoded({n:base64.b64encode(v).decode('ascii')for n,v in sorted(sources.items())})}
 for name,raw in members.items():write_new(context,name,raw)
 pins={**base_package['sourcePins'],'ouf-deploy':commit,'ouf-mcp-server':SOURCE}
 execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'MCP_READ_TRANSPORT_UPDATE'}
 declaration=memory['declaration'](commit,sources,loader,pins,execution)
 closure={**base_package['closure'],'declaration':declaration}
 package={'schema':'ouf.mcp-ingestion-read-transport-package.v1','sourceCommit':commit,'sourcePins':pins,
  'executionPins':execution,'closure':closure,'declarationHash':digest(declaration),
  'fileHashes':{n:sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
 write_new(context,'package.json',encoded(package))
 report={'schema':'ouf.mcp-ingestion-read-transport-preparation.v1','contextPath':str(context),'sourceCommit':commit,
  'candidateSourceCommit':SOURCE,'packageHash':digest(package),'sourceClosureHash':digest(closure),
  'candidateImageId':image_custody.runtime_image_id(audited),'priorOAuthAttempts':row['attempts'],
  'maximumCumulativeOAuthAttempts':256,'runtimeAuthorityIssued':False,'budgetReset':False,'automaticReplayAllowed':False,
  'completedInstallationReadbackReplayed':False,'imageRebuilt':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(context,'preparation-result.json',encoded(report));print('OUF_MCP_INGESTION_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0)
 os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(context/'bootstrap.py'),str(context),digest(package)])
