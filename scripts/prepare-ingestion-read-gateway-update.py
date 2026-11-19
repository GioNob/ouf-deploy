"""Prepare one finite existing-window compatibility capsule. No issuer or native effects."""
import base64,hashlib,json,os,re,signal,stat,sys,tempfile,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-zzp9gqcs')
PACKAGE='c131f941202667fb52e639fd6a59f8084dbae2a2ebe9015c3fb86bdc57e394b4'
CLOSURE='02d07d681c6a407e666027f7c97206f79c2235e95254e7b44140ca137bb5e206'
SOURCE='f0ecc3ec7db6a97c5bd331a2a0bd07b5752c976e'
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
 require(set(delivery)=={'prepare','entry','authority','owner','compiler','runtime','bootstrap','gateway-data'}
  and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_GATEWAY_ONLY_DELIVERY_REQUIRED')
 os.umask(0o077)
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_GATEWAY_PREPARATION_DEADLINE')));signal.alarm(120)
 print('OUF_GATEWAY_READ_PREPARATION_PHASE=RECONCILE_STOPPED191_NO_REPLAY',flush=True)
 package=parsed(CONTEXT/'package.json',PACKAGE)
 require(package['sourceCommit']==SOURCE and digest(package['closure'])==CLOSURE and package['closure']['declaration']['moduleCount']==191,'EXACT_STOPPED191_PACKAGE_REQUIRED')
 require(parsed(CONTEXT/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False},'EXACT_CONSUMED191_CLAIM_REQUIRED')
 require(not any(os.path.lexists(CONTEXT/n)for n in ARTIFACTS),'PRIOR_GATEWAY_OR_MCP_EFFECT_REQUIRES_RECONCILIATION')
 case=parsed(CONTEXT/'case.json',package['fileHashes']['case.json'])
 receipt=parsed(CONTEXT/'login-window-receipt.json')
 require(receipt['compatibilityReviewHash']=='71ed7ce4faa930e84d7582ced9aaec56f07abf7fc1d9886e447f6fca39353c3e'
  and receipt['reviewHash']=='43b0caf6165b43df25e6fba7a37ccce39a1dc56597d47cffe7b6b8a8fed0b301'
  and receipt['oauthAttemptsAfter']==225 and receipt['expiresAt']==1792415703 and receipt['newLoginWindowOpened']is False
  and receipt['budgetReset']is False and receipt['runtimeAuthorityIssued']is False,'EXACT_LOGIN225_RECEIPT_REQUIRED')
 row=parsed(Path(case['humanBinding']['sessionDirectory'])/'recovery.json',maximum=65536)
 require(row['binding']==case['humanBinding']and row['state']=='READY'and type(row['attempts'])is int
  and 225<=row['attempts']<256 and row['budgetReset']is False and time.time()+1200<1792415703
  and time.monotonic()+1200<row['monotonicDeadline'],'EXISTING_READY_SESSION_OR_WINDOW_UNAVAILABLE_NO_LOGIN_ALLOWED')
 case['priorOAuthAttempts']=row['attempts']
 sources=parsed(CONTEXT/'sources.json',package['fileHashes']['sources.json'])
 sources={n:base64.b64decode(v,validate=True)for n,v in sources.items()}
 require(len(sources)==191 and set(sources)==set(package['closure']['declaration']['sourceHashes'])
  and all(sha(v)==package['closure']['declaration']['sourceHashes'][n]for n,v in sources.items()),'EXACT_RETAINED191_SOURCE_BYTES_REQUIRED')
 for name in('entry','authority','owner','compiler'):sources['tools.ingestion_read_gateway_update.'+name]=delivery[name]
 loader={'__name__':'qualified_gateway_read_closed_loader'}
 exec(compile(delivery['runtime'],'<qualified-gateway-read-loader>','exec'),loader);loader['compile_sources'](sources)
 require(len(sources)==195,'EXACT195_SOURCE_CLOSURE_REQUIRED')
 bundle=json.loads(delivery['gateway-data'])
 require(bundle['schema']=='ouf.ingestion-read-gateway-compiler-sources.v1'and bundle['sourceCommit']=='2dfa53fcf3792e8ed68df4e14303c3b085cdbd43','EXACT_GATEWAY_SOURCE_COMMIT_REQUIRED')
 logical=digest({'profile':'ouf.ingestion-read-gateway-publication.v1','beforeRouteMapHash':'9b022a247a5777347cd7794733507bb90a9142ffd62c6497ae3e3c1cbd66fcd2','capabilities':['ouf.ingestion.status','ouf.ingestion.history']})
 require(not os.path.lexists(CONTEXT.parent/('ingestion-read-gateway-'+logical+'.claim.json')),'GATEWAY_LOGICAL_ACTION_ALREADY_CLAIMED_RECONCILE')
 destination=Path(tempfile.mkdtemp(prefix='mcp-ingestion-read-transport-execution-',dir=CONTEXT.parent))
 claim_name='ingestion-read-gateway-preparation-'+logical+'.claim.json'
 claim={'context':str(destination),'profile':'ouf.ingestion-read-gateway-publication.v1','priorOAuthAttempts':row['attempts'],
  'maximumCumulativeOAuthAttempts':256,'existingWindowExpiresAt':1792415703,'automaticReplayAllowed':False,'budgetReset':False}
 write_new(CONTEXT.parent,claim_name,encoded(claim))
 case['preparationClaimBinding']={'path':str(CONTEXT.parent/claim_name),'sha256':digest(claim)}
 write_new(destination,'gateway-compiler-source.json',delivery['gateway-data'])
 case['gatewayCompilerBinding']={'path':str(destination/'gateway-compiler-source.json'),'sha256':sha(delivery['gateway-data'])}
 case['gatewayPredecessor']={'context':str(CONTEXT),'packageHash':PACKAGE,'sourceClosureHash':CLOSURE,'loginReceiptHash':digest(receipt)}
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],
  'reader.py':read(CONTEXT/'reader.py',package['fileHashes']['reader.py']),
  'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit}
 execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'MCP_READ_TRANSPORT_UPDATE'}
 declaration=loader['declaration'](commit,sources,delivery['runtime'],pins,execution)
 closure={**package['closure'],'declaration':declaration}
 fresh={'schema':'ouf.mcp-ingestion-read-transport-package.v1','sourceCommit':commit,'sourcePins':pins,'executionPins':execution,
  'closure':closure,'declarationHash':digest(declaration),'fileHashes':{n:sha(v)for n,v in members.items()},'runtimeAuthorityIssued':False}
 for name,raw in members.items():write_new(destination,name,raw)
 write_new(destination,'package.json',encoded(fresh))
 report={'schema':'ouf.ingestion-read-gateway-preparation.v1','contextPath':str(destination),'sourceCommit':commit,
  'gatewaySourceCommit':bundle['sourceCommit'],'sourceClosureHash':digest(closure),'packageHash':digest(fresh),'sourceModuleCount':195,
  'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'existingWindowExpiresAt':1792415703,
  'newLoginWindowOpened':False,'containerLifecycleOperations':0,'oauthRequests':0,'maximumGatewayWritesAfterSeparateApproval':2,
  'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination,'preparation-result.json',encoded(report));print('OUF_INGESTION_READ_GATEWAY_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0)
 os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
