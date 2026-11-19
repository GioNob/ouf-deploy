"""Installation-specific authentication contract metadata read; no credentials or OAuth."""
import io,tarfile,zipfile,struct
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

INGESTION='477ea664c97ebae2bf50a9fdb4d2ae92c20275cf28e5941f09c1133354908338'
MAX_JAR=268435456
APP_CLASS='BOOT-INF/classes/it/comune/trieste/ouf/ingestion/'
CLASS_NAMES=('IngestionIamSecurityConfiguration','IngestionIamDisabledConfiguration','IngestionIamSecurityConfiguration$TrustedPrincipalBridge','TrustedAuthorizationContext','OperationalAwarenessApi')
def class_markers(raw):
 require(type(raw)is bytes and 10<=len(raw)<=2097152 and raw[:4]==b'\xca\xfe\xba\xbe','BOUNDED_JAVA_CLASS_REQUIRED')
 count=int.from_bytes(raw[8:10],'big');require(1<=count<=32768,'BOUNDED_CLASS_CONSTANT_POOL_REQUIRED');pos=10;i=1;strings=[]
 sizes={3:4,4:4,5:8,6:8,7:2,8:2,9:4,10:4,11:4,12:4,15:3,16:2,17:4,18:4,19:2,20:2}
 while i<count:
  require(pos<len(raw),'COMPLETE_CONSTANT_POOL_REQUIRED');tag=raw[pos];pos+=1
  if tag==1:
   require(pos+2<=len(raw),'COMPLETE_UTF8_LENGTH_REQUIRED');size=int.from_bytes(raw[pos:pos+2],'big');pos+=2
   require(pos+size<=len(raw),'COMPLETE_UTF8_CONSTANT_REQUIRED');strings.append(raw[pos:pos+size].decode('utf-8',errors='replace'));pos+=size
  else:
   require(tag in sizes and pos+sizes[tag]<=len(raw),'KNOWN_COMPLETE_JAVA_CONSTANT_REQUIRED');pos+=sizes[tag]
   if tag in(5,6):i+=1
  i+=1
 markers=('SecurityFilterChain','ConditionalOnProperty','ouf.ingestion.iam.enabled','denyAll','authenticated','permitAll','BearerTokenAuthenticationFilter','TrustedPrincipal','TrustedPrincipalBridge','IngestionIamDisabledConfiguration','UserDetailsServiceAutoConfiguration','SpringBootWebSecurityConfiguration','BasicAuthenticationFilter')
 return {'classMajorVersion':int.from_bytes(raw[6:8],'big'),'markers':{v:any(v in text for text in strings)for v in markers}}

def zip_index(z,maximum):
 infos=z.infolist();require(len(infos)<=maximum and len({i.filename for i in infos})==len(infos),'BOUNDED_UNIQUE_JAR_MEMBERS_REQUIRED')
 return {i.filename:i for i in infos}
def member(z,index,name,maximum):
 info=index[name];require(not info.is_dir()and not info.flag_bits&1 and 0<info.file_size<=maximum,'BOUNDED_UNENCRYPTED_JAR_MEMBER_REQUIRED')
 raw=z.read(info);require(len(raw)==info.file_size,'COMPLETE_JAR_MEMBER_REQUIRED');return raw

def jar_projection(raw):
 require(type(raw)is bytes and 0<len(raw)<=MAX_JAR,'BOUNDED_JAR_BYTES_REQUIRED')
 classes=[];libraries=[];configs=[]
 with zipfile.ZipFile(io.BytesIO(raw))as jar:
  index=zip_index(jar,20000)
  for name in CLASS_NAMES:
   path=APP_CLASS+name+'.class';view={'class':name,'present':path in index}
   if path in index:
    data=member(jar,index,path,2097152);view.update(classSha256=sha(data),**class_markers(data))
   classes.append(view)
  for name in('BOOT-INF/classes/application.yml','BOOT-INF/classes/application.yaml','BOOT-INF/classes/application.properties'):
   if name not in index:continue
   data=member(jar,index,name,65536).decode('utf-8')
   configs.append({'member':name,'iamSectionPresent':'ouf.ingestion.iam'in data,
    'iamEnabledEnvironmentDefaultFalse':bool(re.search(r'enabled\s*:\s*\$\{OUF_ING_IAM_ENABLED:false\}',data)),
    'securityAutoConfigurationExclusionMentioned':'SecurityAutoConfiguration'in data and ('exclude'in data or 'Exclude'in data)})
  selected=[n for n in index if n.startswith('BOOT-INF/lib/')and re.fullmatch(r'BOOT-INF/lib/spring-(?:boot-security[^/]*|security-[^/]+)\.jar',n)]
  require(len(selected)<=40,'BOUNDED_SECURITY_LIBRARY_SET_REQUIRED');total=0
  for name in sorted(selected):
   libs={'member':name,'autoConfigurationClasses':[]}
   if '/spring-boot-security'in name:
    data=member(jar,index,name,16777216);total+=len(data);require(total<=67108864,'BOUNDED_NESTED_SECURITY_BYTES_REQUIRED')
    with zipfile.ZipFile(io.BytesIO(data))as nested:
     ni=zip_index(nested,5000)
     for path in ni:
      if path.endswith(('/SecurityAutoConfiguration.class','/SpringBootWebSecurityConfiguration.class','/UserDetailsServiceAutoConfiguration.class')):
       value=member(nested,ni,path,2097152);libs['autoConfigurationClasses'].append({'class':path,'sha256':sha(value),**class_markers(value)})
   libraries.append(libs)
 return {'jarSha256':sha(raw),'jarBytes':len(raw),'applicationClasses':classes,'selectedApplicationConfiguration':configs,'securityLibraries':libraries,
  'jarCodeExecuted':False,'classesLoadedByCurrentJvmProven':False,'specific401CauseProven':False}

def qualified_jar_path(owner):
 args=(owner['Config'].get('Entrypoint')or[])+(owner['Config'].get('Cmd')or[])
 require(type(args)is list and len(args)<=64 and all(type(v)is str and len(v)<=4096 for v in args)
  and args and args[0].rsplit('/',1)[-1]=='java'and args.count('-jar')==1,'EXACT_RETAINED_JAVA_JAR_ENTRYPOINT_REQUIRED')
 n=args.index('-jar');require(n+1<len(args)and args[n+1]=='/app/app.jar','EXACT_DOCKERFILE_APP_JAR_PATH_REQUIRED')
 require(not any('/app/app.jar'==m['Destination']or '/app/app.jar'.startswith(m['Destination'].rstrip('/')+'/')for m in owner['Mounts']),
  'APPLICATION_JAR_MUST_NOT_BE_OVERLAID_BY_MOUNT')
 return '/app/app.jar'

class ArchiveRead:
 def __init__(self,reader,owner):
  require(owner['Id']==INGESTION,'EXACT_RETAINED_INGESTION_CONTAINER_REQUIRED');qualified_jar_path(owner)
  self.reader=reader;self.calls=0
 def get(self):
  require(self.calls==0,'ONE_ARCHIVE_READ_NO_REPLAY');self.calls+=1;self.reader.check();socket_path=str(self.reader.path)
  class Connection(http.client.HTTPConnection):
   def connect(self):
    self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect(socket_path)
  connection=Connection('retained-engine',timeout=20)
  try:
   connection.request('GET','/v1.44/containers/'+INGESTION+'/archive?path=%2Fapp%2Fapp.jar');reply=connection.getresponse()
   require(reply.status==200 and reply.getheader('Content-Type','').split(';')[0]=='application/x-tar','SUCCESSFUL_EXACT_JAR_ARCHIVE_REQUIRED')
   outer=self
   class Bounded:
    used=0
    def read(self,size=-1):
     require(0<=size<=MAX_JAR+1048576 and self.used+size<=MAX_JAR+1048576,'BOUNDED_ARCHIVE_STREAM_REQUIRED')
     data=reply.read(size);self.used+=len(data);return data
   stream=Bounded()
   with tarfile.open(fileobj=stream,mode='r|')as archive:
    item=archive.next();require(item is not None and item.name=='app.jar'and item.isfile()and not item.issym()and not item.islnk()and 0<item.size<=MAX_JAR,'EXACT_SINGLE_REGULAR_JAR_MEMBER_REQUIRED')
    opened=archive.extractfile(item);require(opened is not None,'READABLE_JAR_MEMBER_REQUIRED');raw=opened.read(MAX_JAR+1)
    require(len(raw)==item.size and archive.next()is None,'ONE_COMPLETE_JAR_ARCHIVE_REQUIRED')
   self.reader.check();return raw
  finally:connection.close()

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_JAR_READ_DEADLINE')));signal.alarm(120)
 old,completed,_=history();routes,packagehash,closurehash=completed_routes()
 require(packagehash=='4b21a5733ccd6212432e3aa69dc08b8ad0f4f402d50044fa8c442da585130f82'and closurehash=='1191c3817a2c152b4070ec9c946fae29746b6f2b155e54d9dba504e3803bd965','EXACT_PREVIOUSLY_READ_COMPLETED226_CAPSULE_REQUIRED')
 expected=old['unchangedApplications']['ingestion'];require(expected['containerId']==INGESTION,'EXACT_RETAINED_INGESTION_GENERATION_REQUIRED')
 reader=Reader(old['engine'],[old['gateway']['transport']['runtimeBinding']['containerId'],INGESTION,completed['finalEvidence']['mcp']['runtimeBinding']['containerId']])
 def inspect():
  actual=reader.get('/v1.44/containers/'+INGESTION+'/json');require(runtime(actual)==expected,'RETAINED_INGESTION_GENERATION_CHANGED');return actual
 before=inspect();archive=ArchiveRead(reader,before);raw=archive.get();projection=jar_projection(raw);inspect();signal.alarm(0)
 return {'schema':'ouf.ingestion401-deployed-jar-read.v1','complete':True,'readOnly':True,'contextPath':str(NEW_CONTEXT),
  'completedRouteReconciliationProvenAsFiles':True,'packageHash':packagehash,'sourceClosureHash':closurehash,
  'currentIngestionGenerationVerified':True,'engineGetRequests':reader.calls,'engineArchiveGetRequests':archive.calls,
  'applicationJarPathQualifiedAgainstCurrentEntrypoint':True,'applicationJarCoveredByMount':False,
  'ingestionReadOnlyRootFilesystem':before['HostConfig'].get('ReadonlyRootfs',False)is True,**projection,
  'lastReportedOAuthAttempts':259,'maximumCumulativeOAuthAttempts':264,'currentHumanStateRequeried':False,
  'credentialFilesOpened':0,'humanCredentialJournalsRead':0,'bearerFilesOpened':0,'authorityFilesOpened':False,
  'credentialValuesPrinted':False,'credentialHashesPrinted':False,'rawLogLinesRead':0,'backendHttpProbes':0,
  'oauthRequests':0,'ownerRequests':0,'processDispatches':0,'journalWrites':0,'gatewayWrites':0,'containerLifecycleOperations':0,
  'databaseCalls':0,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  safe={n.value for n in ast.walk(ast.parse(Path(__file__).read_bytes()))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
  result={'schema':'ouf.ingestion401-deployed-jar-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'reasonCode':str(error)if str(error)in safe else'PRIVATE_DETAILS_REDACTED','readOnly':True,'automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
