"""Seal244 modules from completed owner7; no retained execution or HUMAN credential reads."""
import base64,hashlib,json,os,re,signal,stat,sys,tempfile
from pathlib import Path
NAMES=('entry','authority','owner','native','history','session','runtime','bootstrap','prepare')
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


def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)==set(NAMES)and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_PROJECTION_DELIVERY_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('PROJECTION_PREPARATION_DEADLINE')));signal.alarm(120)
 safe={'__name__':'pure_completed_owner_history'};exec(compile(delivery['history'],'<pure-owner7-history>','exec'),safe)
 completed=safe['verified']();source=completed['package'];root=safe['CONTEXT'].parent
 logical=digest({'ownerResultHash':safe['RESULT'],'oldProjectionHash':completed['plan']['projectionBinding']['sha256'],'newProjectionHash':safe['EXPORT']})
 claim_path=root/('ingestion-active-projection-preparation-'+logical+'.claim.json')
 require(not os.path.lexists(claim_path),'PROJECTION_ALREADY_PREPARED_NO_REPLAY')
 sources=completed['sources'].copy()
 for name in('entry','authority','owner','native','history','session'):sources['tools.ingestion_profile_publication.'+name]=delivery[name]
 memory={'__name__':'new_projection_loader'};exec(compile(delivery['runtime'],'<projection-loader>','exec'),memory)
 memory['compile_sources'](sources);require(len(sources)==244,'EXACT244_SOURCE_CLOSURE_REQUIRED')
 destination=Path(tempfile.mkdtemp(prefix='ingestion-profile-publication-execution-',dir=root));os.chmod(destination,0o700)
 print('OUF_INGESTION_PROFILE_CONTEXT='+str(destination),flush=True)
 claim={'context':str(destination),'ownerResultHash':safe['RESULT'],'ownerContextPath':str(safe['CONTEXT']),
  'maximumActiveProjectionWrites':1,'newLoginAllowed':False,'maximumCumulativeOAuthAttempts':288,
  'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
 write_new(claim_path,encoded(claim))
 case={'originalBinding':completed['case']['originalBinding'],'humanBinding':completed['plan']['humanBinding'],
  'logicalRef':logical,'preparationClaimBinding':{'path':str(claim_path),'sha256':digest(claim)}}
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],
  'reader.py':completed['raw']['reader.py'],'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**source['sourcePins'],'ouf-deploy':commit};execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'INGESTION_PROFILE_PUBLICATION_APPLY'}
 declaration=memory['declaration'](commit,sources,delivery['runtime'],pins,execution);closure={**source['closure'],'declaration':declaration}
 package={**source,'sourceCommit':commit,'sourcePins':pins,'executionPins':execution,'closure':closure,'declarationHash':digest(declaration),
  'fileHashes':{n:sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
 for name,value in members.items():write_new(destination/name,value)
 write_new(destination/'package.json',encoded(package))
 report={'schema':'ouf.ingestion-active-projection-preparation.v1','complete':True,'contextPath':str(destination),'sourceCommit':commit,
  'packageHash':digest(package),'sourceClosureHash':digest(closure),'sourceModuleCount':244,'completedOwnerReadbackProvenAsFiles':True,
  'completedOwnerActionReplayed':False,'humanCredentialJournalsRead':0,'humanSourceChanged':False,'oauthRequests':0,'ownerRequests':0,
  'activeProjectionWrites':0,'gatewayWrites':0,'containerLifecycleOperations':0,'databaseCalls':0,'newLoginAllowed':False,
  'maximumCumulativeOAuthAttempts':288,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination/'preparation-result.json',encoded(report));print('OUF_INGESTION_PROFILE_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0);os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(package)])
