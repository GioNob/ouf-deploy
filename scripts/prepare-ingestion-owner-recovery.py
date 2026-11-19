"""Distinct recovery preparation. Never run any retained main; no OAuth or owner requests."""
import ast,base64,hashlib,json,os,re,signal,stat,sys,tempfile
from pathlib import Path
FIRST=Path('/etc/ouf/deploy-snapshots/ingestion-owner-reference-execution-tr33g8bg')
PACKAGE='afff187c6c97fe697ab448b6d88bdd24092c1fd00b0aef01f268e9982e96b5a5'
CLOSURE='0493b8737f3421cd2c3d03eb11e1fb12b34c165c258a064e0905faf666ce7244'
DRAFT_HASH='2b2e04e379209e365c8fcf2da8ac52141afed9d2034dc5534722c32cdfbb32ec'
NAMES=('entry','authority','owner','native','login','reconcile','runtime','bootstrap','confirmation_patch','human_extension','prepare')
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

def extend_human(raw,expected,patch,extension):
 require(sha(raw)==expected and b'_explicit_272_identity'in raw and b'_explicit_288_identity'not in raw,
  'EXACT_APPROVED272_SOURCE_PREFIX_REQUIRED')
 result=raw+b'\n'+patch+b'\n'+extension;compile(result,'<confirmed288-successor>','exec');return result

def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)==set(NAMES)and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_RECOVERY_DELIVERY_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('RECOVERY_PREPARATION_DEADLINE')));signal.alarm(120)
 package=parsed(FIRST/'package.json',PACKAGE)
 require(digest(package['closure'])==CLOSURE and package['closure']['declaration']['moduleCount']==232,'EXACT_STOPPED232_PACKAGE_REQUIRED')
 raw={n:read(FIRST/n,h)for n,h in package['fileHashes'].items()};old_case=json.loads(raw['case.json'])
 sources={n:base64.b64decode(v,validate=True)for n,v in json.loads(raw['sources.json']).items()};hashes=package['closure']['declaration']['sourceHashes']
 require(len(sources)==232 and set(sources)==set(hashes)and all(sha(v)==hashes[n]for n,v in sources.items()),'EXACT232_SOURCE_HASHES_REQUIRED')
 require(parsed(FIRST/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False},'EXACT_CONSUMED_PREDECESSOR_NO_REPLAY_REQUIRED')
 logical=digest({'predecessorPackageHash':PACKAGE,'draftPlanHash':DRAFT_HASH,'profile':'ouf.human.ingestion-owner-recovery288.v7'})
 root=FIRST.parent;claim_path=root/('ingestion-owner-recovery-preparation-'+logical+'.claim.json')
 require(not os.path.lexists(claim_path),'OWNER_RECOVERY_ALREADY_PREPARED_NO_REPLAY')
 safe={'__name__':'pure_read_reconciliation'};exec(compile(delivery['reconcile'],'<pure-stop-reader>','exec'),safe)
 binding=safe['predecessor_binding']()
 require(binding['retryProfile']['maximumAttempts']==272 and binding['expiresAt']==1792446208,'EXACT_STOPPED272_PUBLIC_BINDING_REQUIRED')
 for name in('entry','authority','owner','native','login','reconcile'):sources['tools.ingestion_owner_recovery.'+name]=delivery[name]
 h='tools.chatbot_file_cohort.human_session';sources[h]=extend_human(sources[h],hashes[h],delivery['confirmation_patch'],delivery['human_extension'])
 memory={'__name__':'qualified_recovery_loader'};exec(compile(delivery['runtime'],'<recovery-loader>','exec'),memory)
 memory['compile_sources'](sources);require(len(sources)==238,'EXACT238_SOURCE_CLOSURE_REQUIRED')
 destination=Path(tempfile.mkdtemp(prefix='ingestion-owner-recovery-execution-',dir=root));os.chmod(destination,0o700)
 print('OUF_INGESTION_OWNER_RECOVERY_CONTEXT='+str(destination),flush=True)
 claim={'context':str(destination),'predecessorContext':str(FIRST),'predecessorPackageHash':PACKAGE,'draftPlanHash':DRAFT_HASH,
  'priorOAuthAttempts':272,'maximumCumulativeOAuthAttemptsProposed':288,'newWindowSecondsProposed':7200,
  'budgetChangeAuthorized':False,'budgetReset':False,'automaticReplayAllowed':False}
 write_new(claim_path,encoded(claim))
 case={'originalBinding':old_case['originalBinding'],'humanBinding':binding,'logicalRef':logical,
  'preparationClaimBinding':{'path':str(claim_path),'sha256':digest(claim)}}
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],
  'reader.py':raw['reader.py'],'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit};execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'INGESTION_OWNER_REFERENCE_RECOVERY_APPLY'}
 declaration=memory['declaration'](commit,sources,delivery['runtime'],pins,execution);closure={**package['closure'],'declaration':declaration}
 fresh={**package,'sourceCommit':commit,'sourcePins':pins,'executionPins':execution,'closure':closure,'declarationHash':digest(declaration),
  'fileHashes':{n:sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
 for name,value in members.items():write_new(destination/name,value)
 write_new(destination/'package.json',encoded(fresh))
 report={'schema':'ouf.ingestion-owner-recovery-preparation.v1','contextPath':str(destination),'sourceCommit':commit,
  'packageHash':digest(fresh),'sourceClosureHash':digest(closure),'sourceModuleCount':238,'priorOAuthAttempts':272,
  'maximumCumulativeOAuthAttemptsProposed':288,'newWindowSecondsProposed':7200,'budgetChangeAuthorized':False,
  'runtimeAuthorityIssued':False,'credentialJournalReadOperations':3,'credentialValuesPrinted':False,'credentialHashesPrinted':False,
  'oauthRequests':0,'ownerRequests':0,'gatewayWrites':0,'activeProjectionWrites':0,'containerLifecycleOperations':0,'databaseCalls':0,
  'secretValuesGenerated':0,'completedWorkReplayed':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination/'preparation-result.json',encoded(report));print('OUF_INGESTION_OWNER_RECOVERY_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0);os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
