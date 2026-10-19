"""Prepare one finite existing-window compatibility capsule. No issuer or native effects."""
import base64,hashlib,json,os,re,signal,stat,sys,tempfile,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-s_qwngj5')
PACKAGE='a925da0d4a1a695f22690ac24d351f7dd34ba46b620465fa0198e13feedf0a16'
CLOSURE='898db65bfb84e361d957e8288b189c0c453b3c7e63e9546b9b9d7801f83b7182'
SOURCE='bab8a2d3d7965b9d2de60f13de475e7afad44b8e'
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
PLAN='a316deb877fc9d2506ee41da98915fd43c582ec9f9fc2b7188af90452f19c617'
REVIEW='f1222de6ac5ab736120fb9cd159443992e4089186296891c8cc61cb2ab50dbd3'
EXPIRES=1792413359
BEFORE='9b022a247a5777347cd7794733507bb90a9142ffd62c6497ae3e3c1cbd66fcd2'
PROFILE='ouf.ingestion-read-gateway-custody-correction.v1'
def reconcile():
 package=parsed(CONTEXT/'package.json',PACKAGE)
 require(package['sourceCommit']==SOURCE and digest(package['closure'])==CLOSURE and package['closure']['declaration']['moduleCount']==195,'EXACT_STOPPED195_PACKAGE_REQUIRED')
 require(parsed(CONTEXT/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False},'EXACT_CONSUMED195_RUNTIME_CLAIM_REQUIRED')
 require(not os.path.lexists(CONTEXT/'update-result.json'),'PREDECESSOR_COMPLETED_RESULT_REQUIRES_RECONCILIATION')
 case=parsed(CONTEXT/'case.json',package['fileHashes']['case.json'])
 plan=parsed(CONTEXT/'execution-plan.json',PLAN);review=parsed(CONTEXT/'review.json',REVIEW);decision=parsed(CONTEXT/'decision.json')
 journal_raw=read(CONTEXT/'recovery.json');journal=json.loads(journal_raw)
 scope=review['scopes']['ingestionReadGatewayUpdate']
 require(journal['schema']=='ouf.ingestion-read-gateway-journal.v1'and journal['version']==0 and journal['nextStage']==0
  and journal['effects']==[]and journal['budgetReset']is False and journal['scopeHash']==digest(scope)
  and scope['planHash']==PLAN and scope['maximumGatewayWrites']==2 and digest(plan['gateway']['beforeRoutes'])==BEFORE
  and review['sourceClosureHash']==CLOSURE and decision['reviewHash']==REVIEW and decision['sourceClosureHash']==CLOSURE
  and decision['expiresAt']==EXPIRES and journal['expiresAt']==EXPIRES,'EXACT_APPROVED_ZERO_EFFECT195_HISTORY_REQUIRED')
 require(time.time()>EXPIRES,'PREDECESSOR_AUTHORITY_STILL_LIVE_NO_REPLACEMENT')
 old_logical=digest({'profile':'ouf.ingestion-read-gateway-publication.v1','beforeRouteMapHash':BEFORE,'capabilities':['ouf.ingestion.status','ouf.ingestion.history']})
 require(plan['logicalUpdateRef']==old_logical,'EXACT_ORIGINAL_LOGICAL_ACTION_REQUIRED')
 logical_path=CONTEXT.parent/('ingestion-read-gateway-'+old_logical+'.claim.json');claim=parsed(logical_path)
 require(claim['context']==str(CONTEXT)and claim['planHash']==PLAN and claim['authorityHash']==journal['authorityHash']
  and claim['automaticReplayAllowed']is False,'ORIGINAL_LOGICAL_FENCE_CHANGED')
 require(read(CONTEXT/'recovery.json')==journal_raw,'ZERO_EFFECT_HISTORY_CHANGED_DURING_RECONCILIATION')
 predecessor={'originContext':str(CONTEXT),'originPackageHash':PACKAGE,'originPlanHash':PLAN,'originReviewHash':REVIEW,
  'originalAuthorityExpiresAt':EXPIRES,'bindings':{key:{'path':str(path),'sha256':sha(read(path))}for key,path in{
   'plan':CONTEXT/'execution-plan.json','review':CONTEXT/'review.json','journal':CONTEXT/'recovery.json',
   'runtimeClaim':CONTEXT/'runtime.claim.json','logicalClaim':logical_path}.items()}}
 return package,case,predecessor

def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)=={'prepare','entry','authority','owner','runtime','bootstrap'}and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_CUSTODY_CORRECTION_DELIVERY_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_CUSTODY_PREPARATION_DEADLINE')));signal.alarm(120)
 print('OUF_GATEWAY_CUSTODY_PREPARATION_PHASE=VERIFY_EXPIRED_ZERO_EFFECT195',flush=True)
 package,case,predecessor=reconcile()
 row=parsed(Path(case['humanBinding']['sessionDirectory'])/'recovery.json',maximum=65536)
 require(row['binding']==case['humanBinding']and row['state']=='READY'and type(row['attempts'])is int and 227<=row['attempts']<256
  and row['budgetReset']is False and row['binding']['expiresAt']==1792415703
  and time.time()+1200<1792415703 and time.monotonic()+1200<row['monotonicDeadline'],
  'EXISTING_READY227_WINDOW_OR_BUDGET_UNAVAILABLE_NO_NEW_LOGIN')
 sources=parsed(CONTEXT/'sources.json',package['fileHashes']['sources.json']);sources={n:base64.b64decode(v,validate=True)for n,v in sources.items()}
 require(len(sources)==195 and set(sources)==set(package['closure']['declaration']['sourceHashes'])
  and all(sha(raw)==package['closure']['declaration']['sourceHashes'][n]for n,raw in sources.items())
  and sha(sources['tools.semantic_mcp_update.native'])=='7ecc130876b88fead82f371b29f797751d6bf78530891c89ff1526504cf5034a',
  'EXACT_RETAINED195_AND_UNCHANGED_PRIVATE0600_GUARD_REQUIRED')
 for name in('entry','authority','owner'):sources['tools.ingestion_read_gateway_custody.'+name]=delivery[name]
 memory={'__name__':'qualified_custody_correction_closed_loader'}
 exec(compile(delivery['runtime'],'<qualified-custody-correction-loader>','exec'),memory);memory['compile_sources'](sources)
 require(len(sources)==198,'EXACT198_SOURCE_CLOSURE_REQUIRED')
 logical=digest({'profile':PROFILE,'beforeRouteMapHash':BEFORE,'originPackageHash':PACKAGE,'capabilities':['ouf.ingestion.status','ouf.ingestion.history']})
 require(not os.path.lexists(CONTEXT.parent/('ingestion-read-gateway-custody-'+logical+'.claim.json')),'CUSTODY_CORRECTION_LOGICAL_ACTION_ALREADY_CLAIMED')
 destination=Path(tempfile.mkdtemp(prefix='mcp-ingestion-read-transport-execution-',dir=CONTEXT.parent))
 claim_name='ingestion-read-gateway-custody-preparation-'+logical+'.claim.json'
 claim={'context':str(destination),'profile':PROFILE,'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,
  'existingWindowExpiresAt':1792415703,'predecessorPackageHash':PACKAGE,'automaticReplayAllowed':False,'budgetReset':False}
 write_new(CONTEXT.parent,claim_name,encoded(claim))
 case['custodyPredecessor']=predecessor;case['priorOAuthAttempts']=row['attempts']
 case['preparationClaimBinding']={'path':str(CONTEXT.parent/claim_name),'sha256':digest(claim)}
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],
  'reader.py':read(CONTEXT/'reader.py',package['fileHashes']['reader.py']),
  'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit};execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'MCP_READ_TRANSPORT_UPDATE'}
 declaration=memory['declaration'](commit,sources,delivery['runtime'],pins,execution);closure={**package['closure'],'declaration':declaration}
 fresh={'schema':'ouf.mcp-ingestion-read-transport-package.v1','sourceCommit':commit,'sourcePins':pins,'executionPins':execution,
  'closure':closure,'declarationHash':digest(declaration),'fileHashes':{n:sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
 for name,raw in members.items():write_new(destination,name,raw)
 write_new(destination,'package.json',encoded(fresh))
 report={'schema':'ouf.ingestion-read-gateway-custody-preparation.v1','contextPath':str(destination),'sourceCommit':commit,
  'packageHash':digest(fresh),'sourceClosureHash':digest(closure),'sourceModuleCount':198,'predecessorAuthorityExpired':True,
  'predecessorZeroEffectsProven':True,'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,
  'existingWindowExpiresAt':1792415703,'runtimeAuthorityIssued':False,'newLoginWindowOpened':False,'automaticReplayAllowed':False,
  'budgetReset':False,'containerLifecycleOperations':0,'oauthRequests':0,'maximumGatewayWritesAfterNewApproval':2,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination,'preparation-result.json',encoded(report));print('OUF_INGESTION_READ_GATEWAY_CUSTODY_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0);os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
