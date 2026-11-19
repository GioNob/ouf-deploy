"""Installation-specific retained route shape diagnostic; no credential or target code execution."""
import ast,base64,hashlib,json,os,re,signal,stat,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-zzp9gqcs')
ORIGIN_PACKAGE='4c63051ba4f22d3f83c33b96a5cc150824a6aadf79b9a6948ff09972b8c601be'
CLOSURE='2eb74254682d3fec8e49f2c5c08acaa83ff87b1f5d736b38124b7380e2a99a76'
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
CAPABILITIES=('ouf.ingestion.status','ouf.ingestion.history')
COMPATIBILITY_REVIEW='71ed7ce4faa930e84d7582ced9aaec56f07abf7fc1d9886e447f6fca39353c3e'
LOGIN_REVIEW='43b0caf6165b43df25e6fba7a37ccce39a1dc56597d47cffe7b6b8a8fed0b301'
HTTP_METHODS=('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','TRACE','CONNECT')
def route_shapes(routes):
 require(type(routes)is dict and len(routes)==80 and all(type(r)is dict for r in routes.values()),'EXACT80_RETAINED_ROUTE_OBJECTS_REQUIRED')
 result=[]
 for capability in CAPABILITIES:
  suffix=capability.rsplit('.',1)[1];expected='/internal/capabilities/v1/execute/'+capability
  backend='/api/internal/v1/ingestion/operations/'+suffix;rows=[]
  for rid,row in routes.items():
   uri=row.get('uri');uris=row.get('uris');paths=([uri]if type(uri)is str else[])+(uris if type(uris)is list and all(type(v)is str for v in uris)else[])
   plugins=row.get('plugins',{});rewrite=plugins.get('proxy-rewrite',{})if type(plugins)is dict else{}
   backend_match=type(rewrite)is dict and rewrite.get('uri')==backend
   if not(expected in paths or backend in paths or backend_match or rid in('mcp-ingestion-'+suffix,'operational-execute-ouf-ingestion-'+suffix)):
    continue
   require(type(rid)is str and re.fullmatch('[A-Za-z0-9._-]{1,128}',rid),'SAFE_PUBLIC_ROUTE_ID_REQUIRED')
   methods=row.get('methods');method=row.get('method')
   def kind(path):
    return 'DEDICATED_EXECUTE'if path==expected else'OWNER_INTERNAL'if path==backend else'GENERIC_EXECUTE'if path=='/internal/capabilities/v1/execute'else'OTHER_OR_ABSENT'
   rows.append({'id':rid,'uriPresent':'uri'in row,'uriType':type(uri).__name__,'uriClass':kind(uri),
    'urisPresent':'uris'in row,'urisContainsExactExecutePath':type(uris)is list and expected in uris,
    'methodsPresent':'methods'in row,'methodsType':type(methods).__name__,
    'knownMethods':[v for v in HTTP_METHODS if type(methods)is list and v in methods],
    'methodsExactlyPost':methods==['POST'],'methodPresent':'method'in row,
    'methodIsPost':method=='POST','ownerBackendPathMatches':backend_match,
    'currentGuardPass':uri==expected and methods==['POST']})
  require(len(rows)<=16,'BOUNDED_SELECTED_INGESTION_ROUTE_SHAPES_REQUIRED')
  result.append({'capability':capability,'expectedExecutePath':expected,'selectedRoutes':rows,
   'currentGuardPass':any(r['currentGuardPass']for r in rows)})
 return result

def diagnose(parse=parsed,exists=os.path.lexists):
 # One deterministic preparation fence. Never scan unrelated contexts/sessions.
 fence=CONTEXT.parent/('mcp-read-transport-compatibility-preparation-'+digest({'originPackageHash':ORIGIN_PACKAGE,
  'humanSourceSha256':'2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285','windowExpiresAt':1792415703})+'.claim.json')
 claim=parse(fence)
 require(claim['context']==str(CONTEXT)and claim['priorOAuthAttempts']==217 and claim['maximumCumulativeOAuthAttempts']==256
  and claim['budgetReset']is False and claim['automaticReplayAllowed']is False,'EXACT_DISTINCT_COMPATIBILITY_PREPARATION_REQUIRED')
 package=parse(CONTEXT/'package.json');package_hash=digest(package)
 require(package['schema']=='ouf.mcp-ingestion-read-transport-package.v1'and package['sourceCommit']==SOURCE
  and package['runtimeAuthorityIssued']is False and package['closure']['declaration']['moduleCount']==191
  and package['closure']['declaration']['entryModule']=='tools.mcp_read_transport_compatibility.entry',
  'EXACT_COMPATIBILITY191_PACKAGE_REQUIRED')
 require(parse(CONTEXT/'runtime.claim.json')=={'packageHash':package_hash,'automaticReplayAllowed':False},'EXACT_CONSUMED191_RUNTIME_CLAIM_REQUIRED')
 inventory={name:exists(CONTEXT/name)for name in ARTIFACTS}
 require(not any(inventory.values()),'LATER_AUTHORITY_OR_MCP_ARTIFACTS_REQUIRE_RECONCILIATION')
 case=parse(CONTEXT/'case.json',package['fileHashes']['case.json'])
 require(case['preparationClaimBinding']=={'path':str(fence),'sha256':digest(claim)},'EXACT_PREPARATION_CLAIM_BINDING_REQUIRED')
 ref=case['existingWindowCompatibility']
 require(ref['originPackageHash']==ORIGIN_PACKAGE and ref['originClosureHash']==CLOSURE
  and ref['originalLoginReviewHash']==LOGIN_REVIEW and ref['windowExpiresAt']==1792415703
  and ref['newLoginWindowAllowed']is False and ref['approvedLoginConsentChanged']is False and ref['budgetReset']is False,
  'EXACT_ORIGINAL_WINDOW_COMPATIBILITY_REQUIRED')
 compatibility=parse(CONTEXT/'compatibility-review.json',COMPATIBILITY_REVIEW)
 decision=parse(CONTEXT/'compatibility-decision.json');receipt=parse(CONTEXT/'login-window-receipt.json')
 require(decision['reviewHash']==COMPATIBILITY_REVIEW and compatibility['originalLoginReviewHash']==LOGIN_REVIEW
  and receipt['schema']=='ouf.mcp-read-transport-human-reauthentication-receipt.v1'
  and receipt['compatibilityReviewHash']==COMPATIBILITY_REVIEW and receipt['reviewHash']==LOGIN_REVIEW
  and receipt['priorOAuthAttempts']==217 and receipt['oauthAttemptsAfter']==225
  and receipt['expiresAt']==1792415703 and receipt['newLoginWindowOpened']is False
  and receipt['originalLoginConsentPreserved']is True and receipt['budgetReset']is False
  and receipt['runtimeAuthorityIssued']is False,'EXACT_SUCCESSFUL_LOGIN_RECEIPT225_REQUIRED')
 sources=parse(CONTEXT/'sources.json',package['fileHashes']['sources.json'])
 source_hashes=package['closure']['declaration']['sourceHashes']
 require(len(sources)==191 and set(sources)==set(source_hashes)
  and all(sha(base64.b64decode(raw,validate=True))==source_hashes[name]for name,raw in sources.items()),'EXACT191_SOURCE_HASHES_REQUIRED')
 require(source_hashes['tools.mcp_read_transport_compatibility.entry']=='3949809050ec7eb4c8cecc2da65a3a27ddc61efa96aa85db7daa9127993f74a1',
  'EXACT_FAILED_ROUTE_GUARD_ENTRY_REQUIRED')
 plan=parse(case['installedPlanBinding']['path'],case['installedPlanBinding']['sha256'])
 history=parse(case['installedJournalBinding']['path'],case['installedJournalBinding']['sha256'])
 require(history['effects'][-1]['stage']=='VERIFY_FINAL'and all(e['state']=='APPLIED'for e in history['effects'])
  and history['budgetReset']is False,'EXACT_COMPLETED_HISTORY_REQUIRED')
 routes=plan['gateway']['afterRoutes'];shapes=route_shapes(routes)
 return {'schema':'ouf.mcp-ingestion-route-stop-read.v1','complete':True,'readOnly':True,'contextPath':str(CONTEXT),
  'packageHash':package_hash,'sourceClosureHash':digest(package['closure']),'sourceModuleCount':191,
  'artifactInventory':inventory,'retainedRouteCount':len(routes),'retainedRouteMapHash':digest(routes),
  'routeShapes':shapes,'retainedGuardWouldPass':all(r['currentGuardPass']for r in shapes),
  'retainedSnapshotOnly':True,'liveGatewayRequeried':False,'loginReceiptAttempts':225,'currentHumanStateRequeried':False,
  'humanCredentialJournalsRead':0,'bearerFilesOpened':0,'privateKeyFilesOpened':0,'sourceExecuted':False,
  'oauthRequests':0,'ownerRequests':0,'engineCalls':0,'processDispatches':0,'journalWrites':0,
  'runtimeAuthorityIssued':False,'runtimeCompletionProven':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedInstallationReadbackReplayed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_ROUTE_STOP_READ_DEADLINE')));signal.alarm(60)
 result=diagnose();signal.alarm(0);return result
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  safe={n.value for n in ast.walk(ast.parse(Path(__file__).read_bytes()))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
  result={'schema':'ouf.mcp-ingestion-route-stop-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'reasonCode':str(error)if str(error)in safe else'PRIVATE_DETAILS_REDACTED','automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
