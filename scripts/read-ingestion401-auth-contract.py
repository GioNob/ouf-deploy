"""Installation-specific authentication contract metadata read; no credentials or OAuth."""
import ast,base64,hashlib,http.client,ipaddress,json,os,re,signal,socket,stat,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-srz6__wf')
SOURCE='0be8fb13db3ff1ea014920bbbbb3738a8a434240'
ROUTES='d5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927'
MCP='8b199a6767bd39dadf82f6d70f964ab6da9c914a3b327229214d88991893647b'
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

def history(parse=parsed):
 package=parse(CONTEXT/'package.json');package_hash=digest(package)
 require(package['sourceCommit']==SOURCE and package['schema']=='ouf.mcp-ingestion-read-transport-package.v1'
  and package['closure']['declaration']['moduleCount']==205
  and package['closure']['declaration']['entryModule']=='tools.mcp_read_transport_gateway82_continuation.entry',
  'EXACT_COMPLETED205_PACKAGE_REQUIRED')
 require(parse(CONTEXT/'runtime.claim.json')=={'packageHash':package_hash,'automaticReplayAllowed':False},'EXACT_CONSUMED205_RUNTIME_CLAIM_REQUIRED')
 case=parse(CONTEXT/'case.json',package['fileHashes']['case.json'])
 preparation=parse(case['preparationClaimBinding']['path'],case['preparationClaimBinding']['sha256'])
 require(preparation['context']==str(CONTEXT)and preparation['maximumCumulativeOAuthAttempts']==256
  and preparation['budgetReset']is False and preparation['automaticReplayAllowed']is False,'EXACT_COMPLETED205_PREPARATION_REQUIRED')
 sources=parse(CONTEXT/'sources.json',package['fileHashes']['sources.json']);hashes=package['closure']['declaration']['sourceHashes']
 require(len(sources)==205 and set(sources)==set(hashes)
  and all(sha(base64.b64decode(v,validate=True))==hashes[n]for n,v in sources.items()),'EXACT205_SOURCE_HASHES_REQUIRED')
 p=parse(CONTEXT/'execution-plan.json');j=parse(CONTEXT/'recovery.json');r=parse(CONTEXT/'update-result.json')
 review=parse(CONTEXT/'review.json');decision=parse(CONTEXT/'decision.json');scope=review['scopes']['mcpReadTransportUpdate']
 stages=['VERIFY_INPUTS']+['mcp.'+n for n in('IMPORT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD','DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY')]+['VERIFY_FINAL']
 require(scope['planHash']==digest(p)and decision['reviewHash']==digest(review)and review['sourceClosureHash']==digest(package['closure'])
  and j['schema']=='ouf.mcp-ingestion-read-transport-update-journal.v1'and j['scopeHash']==digest(scope)
  and j['nextStage']==len(stages)and len(j['effects'])==len(stages)and j['incidentState']=='RECOVERED'
  and [e['stage']for e in j['effects']]==stages and all(e['state']=='APPLIED'for e in j['effects'])
  and all(e['intentHash']==digest({'planHash':digest(p),'stage':e['stage']})for e in j['effects'])
  and j['budgetReset']is False and r['schema']=='ouf.mcp-ingestion-read-transport-update-result.v1'
  and r['status']=='MCP_TRANSPORT_UPDATE_READBACK_COMPLETE'and r['contextPath']==str(CONTEXT)
  and r['sourceCommit']=='1f2c28d7abadae78680b040ba7b58be62ef85ee9'and r['oauthAttemptsAfter']==236
  and r['result']['complete']is True and r['result']['applicationReady']is True
  and r['result']['journalVersion']==j['version']==27 and r['result']['acceptanceGranted']is False
  and r['finalEvidence']==j['effects'][-1]['evidence']and r['finalEvidence']['mcp']['health']['httpStatus']==204
  and r['finalEvidence']['mcp']['runtimeBinding']['containerId']==MCP
  and r['finalEvidence']['mcp']['runtimeBinding']['pid']==312624
  and r['finalEvidence']['mcp']['runtimeBinding']['startedAt']=='2026-10-19T13:07:59.712730076Z'
  and r['finalEvidence']['routeMapHash']==ROUTES
  and r['gatewayWrites']==r['databaseMigrationsPerformed']==r['grantChanges']==r['jobsRetried']==0
  and r['sourceActivated']is False and r['publicMetadataChanged']is False,'EXACT_COMPLETED_MCP236_READBACK_REQUIRED')
 require(p['gateway']['beforeRoutes']==p['gateway']['afterRoutes']and len(p['gateway']['afterRoutes'])==82
  and digest(p['gateway']['afterRoutes'])==ROUTES,'EXACT_RETAINED82_ROUTE_MAP_REQUIRED')
 return p,r,package_hash

def runtime(v,ordered=True):
 require(type(v)is dict and v['State']['Running']is True and not v['State'].get('Paused',False)
  and not v['State'].get('Restarting',False)and type(v['State']['Pid'])is int and v['State']['Pid']>0,'EXACT_RUNNING_GENERATION_REQUIRED')
 return {'containerId':v['Id'],'imageId':v['Image'],'pid':v['State']['Pid'],'startedAt':v['State']['StartedAt'],
  'configHash':digest(v['Config']),'hostConfigHash':digest(v['HostConfig']),
  'mountsHash':digest(sorted(v['Mounts'],key=lambda m:m['Destination'])if ordered else v['Mounts']),
  'networkSettingsHash':digest(v['NetworkSettings'])}

class Reader:
 def __init__(self,binding,containers):
  self.path=Path(binding['socketPath']);self.binding=tuple(binding['socketBinding']);self.calls=0
  require(len(containers)==3 and len(set(containers))==3 and all(re.fullmatch('[0-9a-f]{64}',v)for v in containers),'EXACT_THREE_CONTAINERS_REQUIRED')
  self.allowed={'/v1.44/containers/'+v+'/json'for v in containers}
 def check(self):
  require(self.path.is_absolute()and self.path.resolve()==self.path,'EXACT_ENGINE_SOCKET_PATH_REQUIRED')
  row=self.path.lstat();require(stat.S_ISSOCK(row.st_mode)and row.st_uid==0
   and stat.S_IMODE(row.st_mode)in(0o600,0o660)
   and(row.st_dev,row.st_ino,row.st_uid,row.st_gid,stat.S_IMODE(row.st_mode))==self.binding,'EXACT_RETAINED_ENGINE_SOCKET_REQUIRED')
 def get(self,path):
  require(path in self.allowed and self.calls<6,'EXACT_SIX_READ_ONLY_INSPECTS_REQUIRED')
  self.check();engine_path=str(self.path)
  class Connection(http.client.HTTPConnection):
   def connect(self):
    self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect(engine_path)
  connection=Connection('retained-engine',timeout=10)
  try:
   self.calls+=1;connection.request('GET',path);reply=connection.getresponse();raw=reply.read(4194305)
   require(reply.status==200 and len(raw)<=4194304,'BOUNDED_SUCCESSFUL_ENGINE_INSPECT_REQUIRED');self.check();return json.loads(raw)
  finally:connection.close()

NEW_CONTEXT=Path('/etc/ouf/deploy-snapshots/installation-binding-apply-execution-w8nfc1ko')
NEW_RESULT_HASH='032ed7f9f1de0be2760a79c5e36911f82e1385bf1a7c1287205fa4bd0fbeb387'
NEW_SOURCE='6e36d6f5faa8c0c8e129aac7d843fcf9e7d535e4'
NEW_ROUTES='ed619aa9415b2e70f61689c3830b3fc89135bc9ab72fc90f24daeba1e7bed8c7'
def completed_routes(parse=parsed):
 result=parse(NEW_CONTEXT/'update-result.json');require(digest(result)==NEW_RESULT_HASH,'EXACT_COMPLETED259_TARGET_RECEIPT_REQUIRED')
 package=parse(NEW_CONTEXT/'package.json');closure=package['closure'];decl=closure['declaration']
 require(package['sourceCommit']==NEW_SOURCE and decl['moduleCount']==226
  and decl['entryModule']=='tools.installation_route_reconcile.entry'and package['declarationHash']==digest(decl),'EXACT_COMPLETED226_CLOSURE_REQUIRED')
 sources=parse(NEW_CONTEXT/'sources.json',package['fileHashes']['sources.json'])
 require(len(sources)==226 and set(sources)==set(decl['sourceHashes'])
  and all(sha(base64.b64decode(v,validate=True))==decl['sourceHashes'][n]for n,v in sources.items()),'EXACT226_SOURCE_BYTES_REQUIRED')
 require(parse(NEW_CONTEXT/'runtime.claim.json')=={'packageHash':digest(package),'automaticReplayAllowed':False},'EXACT_CONSUMED226_RUNTIME_CLAIM_REQUIRED')
 plan=parse(NEW_CONTEXT/'execution-plan.json');review=parse(NEW_CONTEXT/'review.json');decision=parse(NEW_CONTEXT/'decision.json');journal=parse(NEW_CONTEXT/'recovery.json')
 scope=review['scopes']['installationRouteReconciliation'];stages=['VERIFY_INPUTS','RECONCILE_PUBLISHED_PROJECTION','GATEWAY_STATUS_ROUTE','GATEWAY_HISTORY_ROUTE','RECONCILE_PREDECESSOR_COMPLETION','VERIFY_FINAL']
 require(plan['kind']=='INSTALLATION_ROUTE_RECONCILIATION'and scope['planHash']==digest(plan)
  and scope['stages']==stages and review['sourceClosureHash']==digest(closure)and decision['reviewHash']==digest(review)
  and journal['schema']=='ouf.installation-binding-native-journal.v1'and journal['scopeHash']==digest(scope)
  and journal['nextStage']==6 and len(journal['effects'])==6 and journal['incidentState']=='RECOVERED'and journal['budgetReset']is False
  and [e['stage']for e in journal['effects']]==stages and all(e['state']=='APPLIED'and e['intentHash']==digest({'planHash':digest(plan),'stage':e['stage']})for e in journal['effects']),
  'EXACT_SIX_COMPLETED_ROUTE_RECONCILIATION_STAGES_REQUIRED')
 routes=plan['gateway']['afterRoutes'];require(len(routes)==82 and digest(routes)==NEW_ROUTES,'EXACT_COMPLETED_NEW82_ROUTES_REQUIRED')
 return routes,digest(package),digest(closure)

def auth_contract(routes,owner):
 names={'OUF_ING_IAM_ENABLED','OUF_ING_IAM_ISSUER','OUF_ING_IAM_AUDIENCE'};env={}
 for value in owner['Config'].get('Env',[]):
  key,sep,contents=value.partition('=')
  if key in names:
   require(sep and key not in env,'UNIQUE_SELECTED_OWNER_IAM_BINDINGS_REQUIRED');env[key]=contents
 enabled=env.get('OUF_ING_IAM_ENABLED','false').lower();require(enabled in('true','false'),'EXACT_BOOLEAN_OWNER_IAM_ENABLED_REQUIRED')
 rows=[]
 for mode in('status','history'):
  cap='ouf.ingestion.'+mode;selected=[r for r in routes.values()if r.get('uri')=='/internal/capabilities/v1/execute/'+cap and r.get('methods')==['POST']]
  require(len(selected)==1,'EXACT_ONE_COMPLETED_INGESTION_READ_ROUTE_REQUIRED');r=selected[0];plugin=r['plugins']['serverless-post-function']
  require(plugin['phase']=='access'and len(plugin['functions'])==1,'EXACT_ACCESS_PHASE_FUNCTION_REQUIRED');lua=plugin['functions'][0]
  require(type(lua)is str and 0<len(lua)<=131072,'BOUNDED_APPROVED_LUA_REQUIRED')
  clears=bool(re.search(r"lower\s*==\s*['\"]authorization['\"]",lua)and re.search(r'ngx\.req\.clear_header\(name\)',lua))
  sets=bool(re.search(r"ngx\.req\.set_header\(\s*['\"][Aa]uthorization['\"]",lua))
  oidc=r['plugins']['openid-connect']
  rows.append({'capability':cap,'oidcBearerOnly':oidc.get('bearer_only')is True,'oidcTlsVerification':oidc.get('ssl_verify')is True,
   'approvedLuaContainsAuthorizationRemovalLoop':clears,'approvedLuaContainsExplicitAuthorizationSetHeader':sets,
   'approvedLuaSha256':sha(lua.encode()),'candidateBearerBoundaryConflict':enabled=='true'and clears and not sets})
 return {'ownerIamEnabledEnvironment':enabled=='true','ownerIamIssuerConfigured':bool(env.get('OUF_ING_IAM_ISSUER')),
  'ownerIamAudienceConfigured':bool(env.get('OUF_ING_IAM_AUDIENCE')),'routeContracts':rows,
  'heuristicSourceProjectionOnly':True,'deployedIamFilterImplementationInspected':False,'specific401CauseProven':False}

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_AUTH_CONTRACT_READ_DEADLINE')));signal.alarm(90)
 old,result,oldhash=history();routes,packagehash,closurehash=completed_routes()
 transport=old['gateway']['transport'];expected={'gateway':transport['runtimeBinding'],'ingestion':old['unchangedApplications']['ingestion'],'mcp':result['finalEvidence']['mcp']['runtimeBinding']}
 reader=Reader(old['engine'],[v['containerId']for v in expected.values()]);values={}
 def inspect(name):
  actual=reader.get('/v1.44/containers/'+expected[name]['containerId']+'/json')
  ordered=name!='gateway'or transport.get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1'
  require(runtime(actual,ordered)==expected[name],'RETAINED_APPLICATION_GENERATION_CHANGED');return actual
 for name in expected:values[name]=inspect(name)
 projection=auth_contract(routes,values['ingestion'])
 for name in expected:inspect(name)
 signal.alarm(0)
 return {'schema':'ouf.ingestion401-auth-contract-read.v1','complete':True,'readOnly':True,'contextPath':str(NEW_CONTEXT),
  'completedRouteReconciliationProvenAsFiles':True,'packageHash':packagehash,'sourceClosureHash':closurehash,
  'retainedRouteCount':82,'retainedRouteMapHash':NEW_ROUTES,'retainedSnapshotOnly':True,'liveGatewayRoutesRequeried':False,
  'currentContainerGenerationsVerified':True,'engineGetRequests':reader.calls,**projection,
  'lastReportedOAuthAttempts':259,'maximumCumulativeOAuthAttempts':264,'currentHumanStateRequeried':False,
  'credentialFilesOpened':0,'humanCredentialJournalsRead':0,'bearerFilesOpened':0,'authorityFilesOpened':False,
  'credentialValuesPrinted':False,'credentialHashesPrinted':False,'rawIdentifiersPrinted':False,'rawLogLinesRead':0,
  'backendHttpProbes':0,'oauthRequests':0,'ownerRequests':0,'processDispatches':0,'journalWrites':0,'gatewayWrites':0,
  'containerLifecycleOperations':0,'databaseCalls':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,
  'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  safe={n.value for n in ast.walk(ast.parse(Path(__file__).read_bytes()))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
  result={'schema':'ouf.ingestion401-auth-contract-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'reasonCode':str(error)if str(error)in safe else'PRIVATE_DETAILS_REDACTED','readOnly':True,'automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
