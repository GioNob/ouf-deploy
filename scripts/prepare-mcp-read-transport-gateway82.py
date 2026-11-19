"""Prepare one finite existing-window compatibility capsule. No issuer or native effects."""
import base64,hashlib,json,os,re,signal,stat,sys,tempfile,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-azxw328z')
SOURCE='77033cd6125b633d5d188541f2ddac8366e07db2'
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
PINS={'tools.ingestion_read_gateway_custody.entry': '421b16519961747e364eecabd855749db2066d96bccee1caf272bb2681388116', 'tools.ingestion_read_gateway_custody.authority': 'c7789dd31d576373fb559657bd8c6abd947924338ac61aad1d804eca130f341b', 'tools.ingestion_read_gateway_custody.owner': '94fae0b16c6fedeca6c2094ebe25bdf8db44d2ea25e33d00fbe324b27e09b54c'}
BEFORE='9b022a247a5777347cd7794733507bb90a9142ffd62c6497ae3e3c1cbd66fcd2'
AFTER='d5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927'
PROFILE='ouf.mcp-read-transport-gateway82-preparation.v1'
def reconcile():
 logical=digest({'profile':'ouf.ingestion-read-gateway-publication.v1','beforeRouteMapHash':BEFORE,'capabilities':['ouf.ingestion.status','ouf.ingestion.history']})
 fence=parsed(CONTEXT.parent/('ingestion-read-gateway-custody-preparation-'+logical+'.claim.json'))
 require(fence['context']==str(CONTEXT)and fence['priorOAuthAttempts']==227 and fence['maximumCumulativeOAuthAttempts']==256
  and fence['budgetReset']is False and fence['automaticReplayAllowed']is False,'EXACT_COMPLETED198_PREPARATION_FENCE_REQUIRED')
 package_raw=read(CONTEXT/'package.json');package=json.loads(package_raw)
 require(package['sourceCommit']==SOURCE and package['closure']['declaration']['moduleCount']==198
  and package['closure']['declaration']['entryModule']=='tools.ingestion_read_gateway_custody.entry',
  'EXACT_COMPLETED198_PACKAGE_REQUIRED')
 require(parsed(CONTEXT/'runtime.claim.json')=={'packageHash':sha(package_raw),'automaticReplayAllowed':False},'EXACT_CONSUMED198_RUNTIME_CLAIM_REQUIRED')
 case=parsed(CONTEXT/'case.json',package['fileHashes']['case.json'])
 prep=parsed(CONTEXT/'preparation-result.json')
 require(prep['packageHash']==sha(package_raw)and prep['sourceClosureHash']==digest(package['closure'])
  and prep['contextPath']==str(CONTEXT),'EXACT_COMPLETED198_PACKAGE_RECEIPT_REQUIRED')
 bindings={k:{'path':str(CONTEXT/n),'sha256':sha(read(CONTEXT/n))}for k,n in
  {'plan':'execution-plan.json','journal':'recovery.json','result':'update-result.json'}.items()}
 p,j,r=[parsed(bindings[k]['path'],bindings[k]['sha256'])for k in('plan','journal','result')]
 review=parsed(CONTEXT/'review.json');decision=parsed(CONTEXT/'decision.json')
 require(review['sourceClosureHash']==digest(package['closure'])and decision['reviewHash']==digest(review)
  and review['scopes']['ingestionReadGatewayCustodyUpdate']['planHash']==digest(p)
  and j['scopeHash']==digest(review['scopes']['ingestionReadGatewayCustodyUpdate'])
  and j['nextStage']==4 and len(j['effects'])==4 and all(x['state']=='APPLIED'for x in j['effects'])
  and j['incidentState']=='RECOVERED'and j['budgetReset']is False
  and r['schema']=='ouf.ingestion-read-gateway-result.v1'and r['complete']is True
  and r['gatewayWrites']==2 and r['humanAttemptsAfter']==229 and r['approvedPublicMetadata0440Preserved']is True
  and r['routeCount']==82 and r['routeMapHash']==AFTER and r['sourceActivated']is False
  and r['containerLifecycleOperations']==0 and digest(p['gateway']['afterRoutes'])==AFTER,
  'EXACT_COMPLETED_GATEWAY82_RESULT_REQUIRED')
 return package,case,bindings

def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)=={'prepare','entry','authority','owner','native','runtime','bootstrap'}and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_MCP82_DELIVERY_REQUIRED')
 os.umask(0o077);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_MCP82_PREPARATION_DEADLINE')));signal.alarm(120)
 print('OUF_MCP82_PREPARATION_PHASE=VERIFY_COMPLETED_GATEWAY_HISTORY_AS_FILES',flush=True)
 package,case,bindings=reconcile()
 row=parsed(Path(case['humanBinding']['sessionDirectory'])/'recovery.json',maximum=65536)
 require(row['binding']==case['humanBinding']and row['state']=='READY'and type(row['attempts'])is int and 229<=row['attempts']<256
  and row['budgetReset']is False and row['binding']['expiresAt']==1792415703
  and time.time()+1200<1792415703 and time.monotonic()+1200<row['monotonicDeadline'],
  'EXISTING_READY229_WINDOW_OR_BUDGET_UNAVAILABLE_NO_NEW_LOGIN')
 sources=parsed(CONTEXT/'sources.json',package['fileHashes']['sources.json']);sources={n:base64.b64decode(v,validate=True)for n,v in sources.items()}
 require(len(sources)==198 and set(sources)==set(package['closure']['declaration']['sourceHashes'])
  and all(sha(raw)==package['closure']['declaration']['sourceHashes'][n]for n,raw in sources.items())
  and all(sha(sources[n])==pin for n,pin in PINS.items()),'EXACT_RETAINED198_SOURCE_CLOSURE_REQUIRED')
 image=parsed(case['imageBinding']['path'],case['imageBinding']['sha256'])
 require(image['imageAudit']['sourceCommit']=='1f2c28d7abadae78680b040ba7b58be62ef85ee9','EXACT_RETAINED_MCP_CANDIDATE_REQUIRED')
 # Preserve original logical MCP operation identity and one-use fence.
 logical=digest({'oldContainerId':'c6fc3a462f4e1faf1e8121fee13ca445f7a3f7f1f39df65d738ea9cc1d4185f4',
  'candidateSourceCommit':'1f2c28d7abadae78680b040ba7b58be62ef85ee9',
  'candidateImageId':'sha256:a0a6f9562ba0b28ba3fef2b3a78bf46e90d9e14c99448d413bacf5d5cb75f182',
  'profile':'ouf.mcp-ingestion-read-transport-update.v1'})
 require(not os.path.lexists(CONTEXT.parent/('mcp-ingestion-read-transport-'+logical+'.claim.json')),'MCP_LOGICAL_UPDATE_ALREADY_CLAIMED')
 for name in('entry','authority','owner','native'):sources['tools.mcp_read_transport_gateway82.'+name]=delivery[name]
 memory={'__name__':'qualified_mcp82_closed_loader'}
 exec(compile(delivery['runtime'],'<qualified-mcp82-loader>','exec'),memory);memory['compile_sources'](sources)
 require(len(sources)==202,'EXACT202_SOURCE_CLOSURE_REQUIRED')
 destination=Path(tempfile.mkdtemp(prefix='mcp-ingestion-read-transport-execution-',dir=CONTEXT.parent))
 claim_name='mcp-read-transport-gateway82-preparation-'+logical+'.claim.json'
 claim={'context':str(destination),'profile':PROFILE,'candidateSourceCommit':'1f2c28d7abadae78680b040ba7b58be62ef85ee9',
  'priorOAuthAttempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'existingWindowExpiresAt':1792415703,
  'automaticReplayAllowed':False,'budgetReset':False}
 write_new(CONTEXT.parent,claim_name,encoded(claim))
 case['completedGateway']=bindings;case['priorOAuthAttempts']=row['attempts']
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
 report={'schema':'ouf.mcp-read-transport-gateway82-preparation.v1','contextPath':str(destination),'sourceCommit':commit,
  'packageHash':digest(fresh),'sourceClosureHash':digest(closure),'sourceModuleCount':202,'priorOAuthAttempts':row['attempts'],
  'maximumCumulativeOAuthAttempts':256,'existingWindowExpiresAt':1792415703,'runtimeAuthorityIssued':False,
  'newLoginWindowOpened':False,'automaticReplayAllowed':False,'budgetReset':False,'gatewayWrites':0,
  'completedGatewayRouteCount':82,'completedGatewayRouteMapHash':AFTER,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination,'preparation-result.json',encoded(report));print('OUF_MCP82_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0);os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
