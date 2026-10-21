"""Distinct reauthentication capsule preparation. No login or runtime effects."""
import base64,hashlib,json,os,re,signal,stat,sys,tempfile,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-mbbleugm')
PACKAGE='f4552fa8894c2050e67f025df9d6c14eb02b04a7c6d18d4a9019994d8bda1de9'
CLOSURE='6e2a0e4ec523c7de9c337ce71f18e3b1983205738a2aaccecf2c97319bb313ee'
SOURCE='f57728d2aa68dc9cf58b86a7f3fad04b45df82dc'
ARTIFACTS=('candidate-review.json','execution-plan.json','review.json','decision.json','human.json','authority.json','issuance.claim.json','recovery.json','update-result.json')
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  row=parent.lstat();require(stat.S_ISDIR(row.st_mode)and row.st_uid==0 and not row.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  row=os.fstat(fd);require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0
   and stat.S_IMODE(row.st_mode)==0o600 and row.st_nlink==1 and 0<row.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==row.st_size and pin(row)==pin(os.fstat(fd))==pin(path.lstat())
   and(expected is None or sha(raw)==expected),'PRIVATE_BYTES_CHANGED');return raw
 finally:os.close(fd)
def parsed(path,expected=None,maximum=8388608):return json.loads(read(path,expected,maximum))
def write_new(directory,name,raw):
 require(Path(name).name==name,'SAFE_PRIVATE_MEMBER_REQUIRED')
 fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)=={'prepare','entry','authority','login','runtime','bootstrap'}
  and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_REAUTHENTICATION_DELIVERY_REQUIRED')
 os.umask(0o077)
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('REAUTHENTICATION_PREPARATION_DEADLINE')));signal.alarm(120)
 print('OUF_MCP_REAUTH_PREPARATION_PHASE=RECONCILE_STOPPED_CAPSULE',flush=True)
 package=parsed(CONTEXT/'package.json',PACKAGE)
 require(package['sourceCommit']==SOURCE and digest(package['closure'])==CLOSURE
  and package['closure']['declaration']['moduleCount']==185 and package['runtimeAuthorityIssued']is False,
  'EXACT_STOPPED185_PACKAGE_REQUIRED')
 require(parsed(CONTEXT/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False},'EXACT_CONSUMED_RUNTIME_CLAIM_REQUIRED')
 require(not any(os.path.lexists(CONTEXT/n)for n in ARTIFACTS),'STOPPED_ACTION_HAS_LATER_AUTHORITY_OR_EFFECTS')
 old_case=parsed(CONTEXT/'case.json',package['fileHashes']['case.json']);case=dict(old_case)
 old_binding=old_case['humanBinding'];directory=Path(old_binding['sessionDirectory'])
 require(directory.is_absolute()and directory.resolve()==directory and CONTEXT.parent in directory.parents
  and old_binding['tokenPath']==str(directory/'human-access.jwt'),'EXACT_BLOCKED_HUMAN_DIRECTORY_REQUIRED')
 row=parsed(directory/'recovery.json',maximum=65536)
 require(row['binding']==old_binding and row['state']=='BLOCKED'and row['operation']=='REFRESH'
  and row['reason']=='HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN'and row['attempts']==217
  and row['budgetReset']is False and not os.path.lexists(directory/'successor-window.claim.json'),
  'EXACT_UNCLAIMED_BLOCKED217_REQUIRED')
 image=parsed(old_case['imageBinding']['path'],old_case['imageBinding']['sha256'])
 audit=image['imageAudit'];native=audit.get('nativeIdentity',{}).get('nativeImageId')
 require(audit['sourceCommit']=='1f2c28d7abadae78680b040ba7b58be62ef85ee9'
  and native=='sha256:a0a6f9562ba0b28ba3fef2b3a78bf46e90d9e14c99448d413bacf5d5cb75f182',
  'EXACT_PREPARED_CANDIDATE_IMAGE_REQUIRED')
 # No repeated byte audit/import: the same private archive remains bound and
 # the native update rechecks its exact hash before the first image effect.
 logical=digest({'oldContainerId':'c6fc3a462f4e1faf1e8121fee13ca445f7a3f7f1f39df65d738ea9cc1d4185f4',
  'candidateSourceCommit':audit['sourceCommit'],'candidateImageId':native,'profile':'ouf.mcp-ingestion-read-transport-update.v1'})
 require(not os.path.lexists(CONTEXT.parent/('mcp-ingestion-read-transport-'+logical+'.claim.json')),
  'MCP_LOGICAL_UPDATE_ALREADY_CLAIMED_RECONCILE')
 sources={n:base64.b64decode(v,validate=True)for n,v in parsed(CONTEXT/'sources.json',package['fileHashes']['sources.json']).items()}
 require(set(sources)==set(package['closure']['declaration']['sourceHashes'])
  and all(sha(raw)==package['closure']['declaration']['sourceHashes'][name]for name,raw in sources.items()),'EXACT_STOPPED_SOURCE_BYTES_REQUIRED')
 for name in('entry','authority','login'):sources['tools.mcp_read_transport_reauthentication.'+name]=delivery[name]
 memory={'__name__':'qualified_distinct_human_reauthentication_loader'}
 exec(compile(delivery['runtime'],'<qualified-reauthentication-loader>','exec'),memory);memory['compile_sources'](sources)
 require(len(sources)==188,'EXACT188_REAUTHENTICATION_CLOSURE_REQUIRED')
 destination=Path(tempfile.mkdtemp(prefix='mcp-ingestion-read-transport-execution-',dir=CONTEXT.parent))
 claim_name='mcp-ingestion-read-transport-reauth-preparation-'+digest({'stoppedPackageHash':PACKAGE,'imageId':native})+'.claim.json'
 claim={'context':str(destination),'candidateSourceCommit':audit['sourceCommit'],'priorOAuthAttempts':217,
  'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False,
  'newLoginRequiresNativeConsent':True,'stoppedPackageHash':PACKAGE}
 write_new(CONTEXT.parent,claim_name,encoded(claim))
 case['preparationClaimBinding']={'path':str(CONTEXT.parent/claim_name),'sha256':digest(claim)}
 case['priorOAuthAttempts']=217
 case['reauthentication']={'schema':'ouf.mcp-read-transport-blocked217-reauthentication.v1','stoppedContext':str(CONTEXT),
  'stoppedPackageHash':PACKAGE,'priorOAuthAttempts':217,'maximumCumulativeOAuthAttempts':256,
  'newWindowSeconds':7200,'newLoginRequiresNativeConsent':True,'failedRefreshReplayAllowed':False,
  'oldCredentialsReusable':False,'automaticRenewalAllowed':False,'budgetReset':False}
 reader_raw=read(CONTEXT/'reader.py',package['fileHashes']['reader.py'])
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],
  'reader.py':reader_raw,'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit}
 execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'MCP_READ_TRANSPORT_UPDATE'}
 declaration=memory['declaration'](commit,sources,delivery['runtime'],pins,execution)
 closure={**package['closure'],'declaration':declaration}
 fresh={'schema':'ouf.mcp-ingestion-read-transport-package.v1','sourceCommit':commit,'sourcePins':pins,
  'executionPins':execution,'closure':closure,'declarationHash':digest(declaration),
  'fileHashes':{n:sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
 for name,raw in members.items():write_new(destination,name,raw)
 write_new(destination,'package.json',encoded(fresh))
 report={'schema':'ouf.mcp-read-transport-reauthentication-preparation.v1','contextPath':str(destination),
  'stoppedContext':str(CONTEXT),'sourceCommit':commit,'packageHash':digest(fresh),'sourceClosureHash':digest(closure),
  'sourceModuleCount':188,'priorOAuthAttempts':217,'maximumCumulativeOAuthAttempts':256,
  'maximumRemainingOAuthAttempts':39,'runtimeAuthorityIssued':False,'newLoginOpened':False,
  'newLoginRequiresNativeConsent':True,'proposedNewWindowSeconds':7200,'failedRefreshReplayed':False,
  'imageRebuilt':False,'preparedImageReusedWithoutImport':True,'completedInstallationReadbackReplayed':False,
  'automaticReplayAllowed':False,'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination,'preparation-result.json',encoded(report))
 print('OUF_MCP_REAUTH_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0)
 os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
