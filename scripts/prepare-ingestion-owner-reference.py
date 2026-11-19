"""Seal new owner-only capsule from completed draft; no login or old runtime dispatch."""
import ast,base64,hashlib,json,os,re,signal,stat,sys,tempfile
from pathlib import Path
NAMES=('entry','authority','owner','native','baseline','login','runtime','bootstrap','human_extension','predecessor_extension','prepare')
FIRST=Path('/etc/ouf/deploy-snapshots/installation-binding-apply-execution-w8nfc1ko')
DRAFT=Path('/etc/ouf/deploy-snapshots/ingestion-read-owner-draft-71atrj6k')
PACKAGE='4b21a5733ccd6212432e3aa69dc08b8ad0f4f402d50044fa8c442da585130f82'
CLOSURE='1191c3817a2c152b4070ec9c946fae29746b6f2b155e54d9dba504e3803bd965'
DRAFT_HASH='2b2e04e379209e365c8fcf2da8ac52141afed9d2034dc5534722c32cdfbb32ec'
FROZEN256='305c7804b084b02f0bf7d6c1521c3c5a4f8e7f4e2fb0a15e27f5886a2a685dcc'
V5='b6205968783149a9f9e5bfa4b1586c08bddd0d14f7cf287618f7d04b58fa8618'
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==s.st_size and pin(s)==pin(os.fstat(fd))==pin(path.lstat())and(expected is None or sha(raw)==expected),'PRIVATE_BYTES_CHANGED');return raw
 finally:os.close(fd)
def parsed(path,expected=None):return json.loads(read(path,expected))
def write_new(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 fd=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def extend_human(raw,v5,v6):
 require(sha(v5)==V5 and raw.endswith(b'\n'+v5)and sha(raw[:-len(v5)-1])==FROZEN256
  and b'_explicit_272_identity'not in raw and 0<len(v6)<=32768,'EXACT_FROZEN264_PREFIX_AND_V5_EXTENSION_REQUIRED')
 result=raw+b'\n'+v6;compile(result,'<explicit-budget272-human-v6>','exec');return result

def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)==set(NAMES)and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_OWNER_REFERENCE_DELIVERY_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('OWNER_REFERENCE_PREPARATION_DEADLINE')));signal.alarm(120)
 package=parsed(FIRST/'package.json',PACKAGE);require(digest(package['closure'])==CLOSURE and package['closure']['declaration']['moduleCount']==226,'EXACT_COMPLETED226_PACKAGE_REQUIRED')
 require(parsed(FIRST/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False},'EXACT_CONSUMED_PREDECESSOR_NO_REPLAY_REQUIRED')
 raw={n:read(FIRST/n,h)for n,h in package['fileHashes'].items()};sources={n:base64.b64decode(v,validate=True)for n,v in json.loads(raw['sources.json']).items()}
 hashes=package['closure']['declaration']['sourceHashes'];require(len(sources)==226 and set(sources)==set(hashes)and all(sha(v)==hashes[n]for n,v in sources.items()),'EXACT226_SOURCE_HASHES_REQUIRED')
 draft=parsed(DRAFT/'draft-plan.json',DRAFT_HASH);receipt=parsed(DRAFT/'preparation-result.json')
 require(receipt['complete']is True and receipt['draftPlanHash']==DRAFT_HASH and receipt['runtimeAuthorityIssued']is False
  and receipt['installedSqlResourceEqualityProven']is True and receipt['candidateRootfsByteCustodyProven']is True,'EXACT_COMPLETED_DRAFT_REQUIRED')
 for name in('entry','authority','owner','native','baseline','login'):sources['tools.ingestion_read_owner_reference.'+name]=delivery[name]
 h='tools.chatbot_file_cohort.human_session';sources[h]=extend_human(sources[h],delivery['predecessor_extension'],delivery['human_extension'])
 memory={'__name__':'qualified_owner_reference_loader'};exec(compile(delivery['runtime'],'<owner-reference-loader>','exec'),memory)
 memory['compile_sources'](sources);require(len(sources)==232,'EXACT232_SOURCE_CLOSURE_REQUIRED')
 prior=parsed(FIRST/'execution-plan.json');old_case=json.loads(raw['case.json']);logical=digest({'draftPlanHash':DRAFT_HASH,'profile':'ouf.ingestion-read-owner-reference.v1','predecessorPackageHash':PACKAGE})
 root=FIRST.parent;claim_path=root/('ingestion-owner-reference-preparation-'+logical+'.claim.json');require(not os.path.lexists(claim_path),'OWNER_REFERENCE_ALREADY_PREPARED_NO_REPLAY')
 destination=Path(tempfile.mkdtemp(prefix='ingestion-owner-reference-execution-',dir=root));os.chmod(destination,0o700)
 print('OUF_INGESTION_OWNER_REFERENCE_CONTEXT='+str(destination),flush=True)
 claim={'context':str(destination),'draftPlanHash':DRAFT_HASH,'priorOAuthAttempts':259,'maximumCumulativeOAuthAttemptsProposed':272,
  'newWindowSecondsProposed':7200,'predecessorWindowExpiresAt':1792436155,'budgetChangeAuthorized':False,'budgetReset':False,'automaticReplayAllowed':False}
 write_new(claim_path,encoded(claim))
 case={'originalBinding':old_case['originalBinding'],'humanBinding':prior['humanBinding'],'logicalRef':logical,
  'draftBinding':{'path':str(DRAFT/'draft-plan.json'),'sha256':DRAFT_HASH},'preparationClaimBinding':{'path':str(claim_path),'sha256':digest(claim)}}
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],'reader.py':raw['reader.py'],
  'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit};execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'INGESTION_OWNER_REFERENCE_APPLY'}
 declaration=memory['declaration'](commit,sources,delivery['runtime'],pins,execution);closure={**package['closure'],'declaration':declaration}
 fresh={**package,'sourceCommit':commit,'sourcePins':pins,'executionPins':execution,'closure':closure,'declarationHash':digest(declaration),
  'fileHashes':{n:sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
 for n,v in members.items():write_new(destination/n,v)
 write_new(destination/'package.json',encoded(fresh))
 report={'schema':'ouf.ingestion-owner-reference-preparation.v1','contextPath':str(destination),'sourceCommit':commit,'packageHash':digest(fresh),
  'sourceClosureHash':digest(closure),'sourceModuleCount':232,'draftPlanHash':DRAFT_HASH,'priorOAuthAttempts':259,
  'maximumCumulativeOAuthAttemptsProposed':272,'newWindowSecondsProposed':7200,'budgetChangeAuthorized':False,'runtimeAuthorityIssued':False,
  'humanCredentialJournalsRead':0,'oauthRequests':0,'secretValuesGenerated':0,'ownerRequests':0,'gatewayWrites':0,'activeProjectionWrites':0,
  'containerLifecycleOperations':0,'directDatabaseCalls':0,'completedDraftPreparationReplayed':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination/'preparation-result.json',encoded(report));print('OUF_INGESTION_OWNER_REFERENCE_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0);os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
