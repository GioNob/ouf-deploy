"""Installation-specific retained route shape diagnostic; no credential or target code execution."""
import ast,base64,hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-s_qwngj5')
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
NEW_SOURCE_HASHES={'entry': '29bbf1578f6ffaa99eeb5660e0cbe435e820c823f2fba745d1240552147d170a', 'authority': 'c6b9e72bca84dff94a9c6f2c68d715907710549f48d5721d59e1278a36fb285c', 'owner': '69e7619875a32ffaee9a287ec9213295a81c978b251367250b0bcca3a6868b60', 'compiler': 'a0f93d95a632445501826020f9bbf2337a4e75fd417323064168a27bb1a325eb'}
PROFILE='ouf.ingestion-read-gateway-publication.v1'
BEFORE='9b022a247a5777347cd7794733507bb90a9142ffd62c6497ae3e3c1cbd66fcd2'
STAGES=('VERIFY_INPUTS','GATEWAY_STATUS_ROUTE','GATEWAY_HISTORY_ROUTE','VERIFY_FINAL')
def sealed_private_guard(raw):
 require(type(raw)is bytes and 0<len(raw)<=262144,'BOUNDED_SEALED_NATIVE_SOURCE_REQUIRED')
 tree=ast.parse(raw);methods=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='private_file']
 require(len(methods)==1,'EXACT_SEALED_PRIVATE_FILE_FUNCTION_REQUIRED')
 guards=[n for n in ast.walk(methods[0])if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='require'
  and len(n.args)==2 and isinstance(n.args[1],ast.Constant)and n.args[1].value=='PRIVATE_FILE_CUSTODY_REQUIRED']
 require(len(guards)==1,'EXACT_SEALED_PRIVATE_CUSTODY_GUARD_REQUIRED')
 expression=ast.unparse(guards[0].args[0]);require(len(expression)<=4096,'BOUNDED_PUBLIC_CUSTODY_EXPRESSION_REQUIRED')
 return {'sourceSha256':sha(raw),'custodyGuardExpression':expression}

def custody_projection(binding,private=False):
 path=Path(binding['path']);require(path.is_absolute()and path.resolve()==path,'EXACT_METADATA_PATH_REQUIRED')
 for parent in path.parents:
  info=parent.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'ROOT_METADATA_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);require(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and 0<info.st_size<=8388608,'BOUNDED_CUSTODY_FILE_REQUIRED')
  maximum=8388608 if private else 65536
  require(info.st_size<=maximum and info.st_uid==0 and stat.S_IMODE(info.st_mode)in(0o440,0o600),'EXACT_PUBLIC_OR_PRIVATE_CUSTODY_MODE_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(maximum+1)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==info.st_size and pin(info)==pin(os.fstat(fd))==pin(path.lstat()),'CUSTODY_FILE_CHANGED_DURING_READ')
  approved=binding.get('custody')
  matches=approved is None or all(getattr(info,k)==v for k,v in approved.items())
  return {'member':'candidate-review.json'if private else path.name,'mode':oct(stat.S_IMODE(info.st_mode)),
   'hashMatchesApprovedBinding':sha(raw)==binding['sha256'],'approvedCustodyMatches':matches,
   'legacyPrivate0600PredicateWouldPass':info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600,
   'approvedPublic0440PredicateWouldPass':info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o440 and matches}
 finally:os.close(fd)

def journal_projection(journal,review,plan):
 scope=review['scopes']['ingestionReadGatewayUpdate'];n=journal['nextStage'];effects=journal['effects']
 require(scope['profile']==PROFILE and scope['planHash']==digest(plan)and scope['maximumGatewayWrites']==2
  and journal['schema']=='ouf.ingestion-read-gateway-journal.v1'and journal['scopeHash']==digest(scope)
  and journal['budgetReset']is False and type(n)is int and 0<=n<=4 and len(effects)in(n,n+1)
  and [e['stage']for e in effects]==list(STAGES[:len(effects)])and all(e['state']=='APPLIED'for e in effects[:n])
  and(len(effects)==n or effects[-1]['state']=='CLAIMED')
  and all(e['intentHash']==digest({'planHash':digest(plan),'stage':e['stage']})for e in effects),'EXACT_SIGNED_PLAN_STAGE_HISTORY_REQUIRED')
 rows=[{'stage':e['stage'],'state':e['state']}for e in effects]
 return {'version':journal['version'],'nextStage':n,'effects':rows,'incidentState':journal['incidentState'],
  'noGatewayDispatchByThisActionProven':not any(e['stage']in STAGES[1:3]for e in effects),
  'zeroStageClaimsProven':n==0 and effects==[]and journal['version']==0,
  'expiresAt':journal['expiresAt']}

def diagnose(parse=parsed,project=custody_projection,exists=os.path.lexists):
 logical=digest({'profile':PROFILE,'beforeRouteMapHash':BEFORE,'capabilities':['ouf.ingestion.status','ouf.ingestion.history']})
 prep_path=CONTEXT.parent/('ingestion-read-gateway-preparation-'+logical+'.claim.json');prep=parse(prep_path)
 require(prep['context']==str(CONTEXT)and prep['profile']==PROFILE and prep['maximumCumulativeOAuthAttempts']==256
  and prep['budgetReset']is False and prep['automaticReplayAllowed']is False,'EXACT_GATEWAY_PREPARATION_FENCE_REQUIRED')
 package=parse(CONTEXT/'package.json');package_hash=digest(package)
 require(package['sourceCommit']==SOURCE and package['closure']['declaration']['moduleCount']==195
  and package['closure']['declaration']['entryModule']=='tools.ingestion_read_gateway_update.entry',
  'EXACT_QUALIFIED195_GATEWAY_PACKAGE_REQUIRED')
 require(parse(CONTEXT/'runtime.claim.json')=={'packageHash':package_hash,'automaticReplayAllowed':False},'EXACT_CONSUMED_GATEWAY_RUNTIME_CLAIM_REQUIRED')
 case=parse(CONTEXT/'case.json',package['fileHashes']['case.json'])
 require(case['preparationClaimBinding']=={'path':str(prep_path),'sha256':digest(prep)}
  and case['gatewayPredecessor']['packageHash']=='c131f941202667fb52e639fd6a59f8084dbae2a2ebe9015c3fb86bdc57e394b4'
  and case['gatewayPredecessor']['sourceClosureHash']=='02d07d681c6a407e666027f7c97206f79c2235e95254e7b44140ca137bb5e206',
  'EXACT_PREPARATION_AND_STOPPED191_LINEAGE_REQUIRED')
 sources=parse(CONTEXT/'sources.json',package['fileHashes']['sources.json']);pins=package['closure']['declaration']['sourceHashes']
 require(len(sources)==195 and set(sources)==set(pins)and all(sha(base64.b64decode(raw,validate=True))==pins[name]for name,raw in sources.items())
  and all(pins['tools.ingestion_read_gateway_update.'+name]==value for name,value in NEW_SOURCE_HASHES.items()),'EXACT_FAILED_GATEWAY_EXECUTABLE_BYTES_REQUIRED')
 plan=parse(CONTEXT/'execution-plan.json');review=parse(CONTEXT/'review.json');decision=parse(CONTEXT/'decision.json')
 require(plan['schema']=='ouf.ingestion-read-gateway-plan.v1'and plan['authorityDirectory']==str(CONTEXT)
  and plan['logicalUpdateRef']==logical and digest(plan['gateway']['beforeRoutes'])==BEFORE
  and len(plan['gateway']['beforeRoutes'])==80 and len(plan['gateway']['afterRoutes'])==82
  and plan['replacements']=={}and plan['databaseMigration']is None and plan['maximumGatewayWrites']==2
  and review['sourceClosureHash']==digest(package['closure'])and decision['reviewHash']==digest(review)
  and decision['sourceClosureHash']==review['sourceClosureHash'],'EXACT_GATEWAY_PLAN_REVIEW_DECISION_REQUIRED')
 logical_claim=parse(CONTEXT.parent/('ingestion-read-gateway-'+logical+'.claim.json'))
 journal=parse(CONTEXT/'recovery.json');projection=journal_projection(journal,review,plan)
 require(logical_claim['context']==str(CONTEXT)and logical_claim['planHash']==digest(plan)
  and logical_claim['authorityHash']==journal['authorityHash']and logical_claim['automaticReplayAllowed']is False,'EXACT_STARTED_GATEWAY_ACTION_CLAIM_REQUIRED')
 require(not exists(CONTEXT/'update-result.json'),'COMPLETED_RESULT_REQUIRES_SEPARATE_RECONCILIATION')
 private=plan['privateReviewBinding'];require(private['path']==str(CONTEXT/'candidate-review.json'),'EXACT_CANDIDATE_REVIEW_PATH_REQUIRED')
 metadata=plan['retainedMcpMetadata']
 require(len(metadata)==3 and {Path(b['path']).name for b in metadata}=={'profile.json','policy.json','permit.json'},'EXACT_THREE_PUBLIC_MCP_METADATA_REQUIRED')
 checks=[project(private,private=True)]+[project(b)for b in metadata]
 require(parse(CONTEXT/'recovery.json')==journal,'GATEWAY_JOURNAL_CHANGED_DURING_DIAGNOSIS')
 return {'schema':'ouf.ingestion-read-gateway-custody-stop-read.v1','complete':True,'readOnly':True,'contextPath':str(CONTEXT),
  'packageHash':package_hash,'sourceClosureHash':digest(package['closure']),'sourceModuleCount':195,
  'artifactInventory':{name:exists(CONTEXT/name)for name in ARTIFACTS},'journal':projection,'fileCustodyChecks':checks,'planHash':digest(plan),'reviewHash':digest(review),
  'sealedPrivateFileGuard':sealed_private_guard(base64.b64decode(sources['tools.semantic_mcp_update.native'],validate=True)),
  'authorityExpiresAt':decision['expiresAt'],'authorityFilesOpened':False,'privateKeyFilesOpened':0,
  'humanCredentialJournalsRead':0,'bearerFilesOpened':0,'oauthRequests':0,'engineCalls':0,'ownerRequests':0,
  'processDispatches':0,'journalWrites':0,'sourceExecuted':False,'liveGatewayRequeried':False,
  'runtimeAuthorityIssuedByDiagnostic':False,'runtimeCompletionProven':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_CUSTODY_STOP_READ_DEADLINE')));signal.alarm(60)
 value=diagnose();signal.alarm(0);return value
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  safe={n.value for n in ast.walk(ast.parse(Path(__file__).read_bytes()))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
  result={'schema':'ouf.ingestion-read-gateway-custody-stop-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'reasonCode':str(error)if str(error)in safe else'PRIVATE_DETAILS_REDACTED','automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
