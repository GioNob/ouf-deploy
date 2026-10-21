#!/usr/bin/env python3
"""Installation-specific retained-host acquisition metadata diagnosis; no token or property reads."""
import base64,hashlib,http.client,json,os,re,selectors,shlex,signal,socket,ssl,stat,subprocess,sys,tempfile,time
from urllib.parse import urlsplit,urlencode
from pathlib import Path
from urllib.parse import quote
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/resolution-comparison-execution-di_tb213')
REVIEW=None
POLICY_CONTEXT=Path('/etc/ouf/deploy-snapshots/ingestion-readiness-execution-d0bmyv9g')
POLICY_REVIEW='c42181ac012cd41417e2e9ec3c0f37908d3a5c0c379cc3805c918505f4bed5cd'
SOURCE='teatri-csv-6609b245'
VERSION='9860853e-e8f3-4b93-b9d2-03521a039962'
CHALLENGE='ecf36c5c-10b2-4393-bf81-0ff7d28b8d5b'
CONFIG_HASH='sha256:ae7f46b4214d09c55a9885530920026258f0dcd588462c353b06d82185e12c9b'
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
CREDENTIAL_FILES_READ=0
def emit(check,**values):
 print(json.dumps(dict(schema='ouf.teatri-reference-dependency-read.v1',check=check,readOnly=True,
  automaticRetry=False,budgetReset=False,installationSpecific=True,credentialFilesRead=CREDENTIAL_FILES_READ,credentialValuesPrinted=False,
  databaseMutations=0,grantRequests=0,readinessCalls=0,serviceMutations=0,
  completedTechnicalPhases=8,functionalMilestonesProven=2,**values),sort_keys=True),flush=True)

def runtime_pin(actual):
    return {'containerId':actual['Id'],'imageId':actual['Image'],
        'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
        **{name+'Hash':digest(actual[key])for name,key in
           (('config','Config'),('hostConfig','HostConfig'),('mounts','Mounts'),('networkSettings','NetworkSettings'))}}

def bounded(argv, seconds=15, maximum=2097152, discard=False):
    """Drain both pipes concurrently; cap bytes/time and kill the CLI on exit."""
    proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    output=bytearray(); errors=bytearray(); count=0; end=time.monotonic()+seconds
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ,'out')
            selector.register(proc.stderr,selectors.EVENT_READ,'err')
            while selector.get_map():
                require(time.monotonic()<end,'DIAGNOSTIC_HOST_TIME_BOUND_EXHAUSTED')
                for key,_ in selector.select(min(0.2,max(0,end-time.monotonic()))):
                    raw=os.read(key.fd,65536)
                    if not raw:selector.unregister(key.fileobj);continue
                    if key.data=='out':
                        count+=len(raw);require(count<=maximum,'DIAGNOSTIC_OUTPUT_BOUND_EXHAUSTED')
                        if not discard:output.extend(raw)
                    else:
                        require(len(errors)+len(raw)<=maximum,'DIAGNOSTIC_STDERR_BOUND_EXHAUSTED')
                        errors.extend(raw)
            code=proc.wait(timeout=max(0.01,end-time.monotonic()))
        return code,bytes(output),bytes(errors),count
    finally:
        if proc.poll() is None:proc.kill()
        proc.wait(timeout=5);proc.stdout.close();proc.stderr.close()

def executable(binding):
    path=Path(binding['path']);info=path.stat()
    require(path.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_uid==0 and
        not info.st_mode&0o022 and hashlib.sha256(path.read_bytes()).hexdigest()==binding['sha256'],
        'NATIVE_EXECUTABLE_BINDING_DRIFT')
    return str(path)

def literal(value):
    require(type(value)is str and re.fullmatch('[A-Za-z0-9_:.-]{1,128}',value),'CLOSED_SQL_BINDING_REQUIRED')
    return "'"+value+"'"

def acquisition_query(module,tenant):
 require(module=='udp','ONLY_UDP_READ_REQUIRED');t=literal(tenant);s=literal(SOURCE)
 return "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; "+"""
 WITH selected AS (
 SELECT h.handoff_id,h.payload_json->'contractRefs' refs,j.state,j.state_version,j.integrity_attempts,j.safe_failure_code,j.missing_ref_hashes,j.integrity_baseline_hash
 FROM ouf_udp.resolution_review_package_confirmation r
 JOIN ouf_udp.human_resolution_decision d ON d.actor_subject=r.actor_subject AND d.decided_at=r.confirmed_at AND d.authorization_decision_ref=r.authorization_decision_ref
 JOIN ouf_udp.resolution_issue q ON q.issue_id=d.issue_id AND q.tenant_id=r.tenant_id
 JOIN ouf_udp.handoff_intake h ON h.handoff_id=q.handoff_id
 JOIN ouf_udp.materialization_job j ON j.handoff_id=h.handoff_id
 WHERE r.package_id='a5183503-04ff-4e10-850f-e22bf874365e' AND r.tenant_id="""+t+"""
 AND r.actor_subject='b93d8cf6-cd14-4ee6-91d7-84cd76c4f500' AND h.source_id="""+s+""" AND d.action='CREATE_NEW'
 )
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'confirmedJobCount',(SELECT count(*) FROM selected),'distinctContractSets',(SELECT count(DISTINCT refs) FROM selected),
 'contractRefs',(SELECT refs FROM selected ORDER BY handoff_id LIMIT 1),
 'jobGroups',coalesce((SELECT jsonb_agg(x) FROM (SELECT state,safe_failure_code,integrity_attempts,(integrity_baseline_hash IS NOT NULL) baseline_present,missing_ref_hashes,count(*) count FROM selected GROUP BY state,safe_failure_code,integrity_attempts,(integrity_baseline_hash IS NOT NULL),missing_ref_hashes ORDER BY state,safe_failure_code,integrity_attempts)x),'[]'::jsonb)); ROLLBACK;"""


def normal(value):return re.sub('[^a-z0-9]','',value.lower())
def file_identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def mounted_file(actual,root,target,maximum):
 p=Path(target);require(p.is_absolute()and str(p)==target and '..'not in p.parts,'EXACT_CONFIGURED_FILE_REQUIRED')
 mounts=[m for m in actual['Mounts']if target==m['Destination']or target.startswith(m['Destination'].rstrip('/')+'/')]
 require(bool(mounts),'CONFIGURED_FILE_MOUNT_REQUIRED');m=max(mounts,key=lambda x:len(x['Destination']))
 require(m.get('Type')=='bind'and m.get('RW')is False,'READ_ONLY_CONFIGURED_BIND_REQUIRED')
 fds=[os.dup(root)]
 try:
  for part in p.parts[1:-1]:fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]))
  fds.append(os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1]));before=os.fstat(fds[-1])
  require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=maximum,'BOUNDED_CONFIGURED_FILE_REQUIRED')
  raw=os.read(fds[-1],maximum+1)
  require(len(raw)==before.st_size and file_identity(before)==file_identity(os.fstat(fds[-1])),'CONFIGURED_FILE_CHANGED')
  return raw
 finally:
  for fd in reversed(fds):os.close(fd)

def configured_properties(actual,root):
 env={};values={}
 for row in actual['Config'].get('Env')or[]:
  key,value=row.split('=',1);require(key not in env,'UNIQUE_ENVIRONMENT_REQUIRED');env[key]=value
 def add(key,value):
  if type(value)in(str,int,bool):values.setdefault(normal(key),set()).add(str(value))
 def flatten(obj,prefix='',depth=0):
  require(type(obj)is dict and depth<16,'BOUNDED_SPRING_JSON_REQUIRED')
  for key,value in obj.items():
   path=prefix+'.'+key if prefix else key
   if type(value)is dict:flatten(value,path,depth+1)
   else:add(path,value)
 for key,value in env.items():add(key,value)
 if env.get('SPRING_APPLICATION_JSON'):flatten(json.loads(env['SPRING_APPLICATION_JSON']))
 argv=(actual['Config'].get('Entrypoint')or[])+(actual['Config'].get('Cmd')or[])
 for key in('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'):argv+=shlex.split(env.get(key,''))
 for arg in argv:
  if arg.startswith(('-D','--'))and '='in arg:
   k,v=arg[2:].split('=',1);add(k,v)
 required=('ouf.udp.execution.gateway-url','ouf.udp.execution.token-file')
 def one(key):
  found=values.get(normal(key),set())-set(['']);require(len(found)==1,'EXACT_CONFIGURED_RUNTIME_CHANNEL_REQUIRED');return next(iter(found))
 # Explicit process environment / Spring JSON outrank ordinary application files.
 # Contradictory visible channels are rejected rather than silently selected.
 if all(values.get(normal(key),set())-set([''])for key in required):
  return one(required[0]),one(required[1]),None
 locations=[v for k,v in env.items()if normal(k)in('springconfiglocation','springconfigadditionallocation','springconfigimport')and v]
 require(len(locations)==1,'ONE_EXPLICIT_RUNTIME_CONFIG_SELECTOR_REQUIRED')
 location=locations[0].removeprefix('optional:');require(location.startswith('file:')and location.endswith(('.properties','.yaml','.yml'))and ','not in location,'LITERAL_PROPERTIES_CONFIG_REQUIRED')
 target=location[5:];raw=mounted_file(actual,root,target,262144)
 require(b'\\'not in raw and b'${'not in raw and b'\0'not in raw,'LITERAL_RUNTIME_CONFIGURATION_REQUIRED');seen=set()
 if location.endswith('.properties'):
  for line in raw.decode().splitlines():
   if not line.strip()or line.lstrip().startswith(('#','!')):continue
   m=re.fullmatch(r'[ \t]*([A-Za-z0-9_.-]+)[ \t]*[=:][ \t]*([^\r\n]*)',line);require(m is not None,'LITERAL_PROPERTY_REQUIRED')
   key=normal(m[1]);require(key not in seen,'UNIQUE_RUNTIME_PROPERTY_REQUIRED');seen.add(key);add(m[1],m[2].strip())
 else:
  stack=[]
  for line in raw.decode().splitlines():
   if not line.strip()or line.lstrip().startswith('#'):continue
   require('\t'not in line,'LITERAL_YAML_INDENT_REQUIRED')
   m=re.fullmatch(r'( *)([A-Za-z0-9_.-]+):(?: +(.*))?',line);require(m is not None,'LITERAL_YAML_MAPPING_REQUIRED')
   indent=len(m[1]);value=m[3]
   while stack and stack[-1][0]>=indent:stack.pop()
   key='.'.join([part for _,part in stack]+[m[2]]);normalized=normal(key)
   require(normalized not in seen,'UNIQUE_RUNTIME_PROPERTY_REQUIRED');seen.add(normalized)
   if value is None:stack.append((indent,m[2]));continue
   if value.startswith('"'):value=json.loads(value);require(type(value)is str,'LITERAL_YAML_STRING_REQUIRED')
   elif value.startswith("'"):
    require(value.endswith("'"),'LITERAL_YAML_STRING_REQUIRED');value=value[1:-1].replace("''", "'")
   else:
    require(not value.startswith(('{','[','&','*','!','|','>')),'LITERAL_YAML_SCALAR_REQUIRED');value=re.sub(r' +#.*$','',value).strip()
   add(key,value)

 return one(required[0]),one(required[1]),hashlib.sha256(raw).hexdigest()

def safe_get(origin,path,token):
 u=urlsplit(origin);require(u.scheme=='https'and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.path in('','/'),'REVIEWED_HTTPS_ORIGIN_REQUIRED')
 require(path.startswith('/api/')and '\r'not in path and '\n'not in path,'BOUNDED_DEPENDENCY_PATH_REQUIRED')
 credential=token.decode('ascii').strip();require(0<len(credential)<=16384 and not any(x.isspace()for x in credential),'PRIVATE_WORKLOAD_TOKEN_REQUIRED')
 conn=http.client.HTTPSConnection(u.hostname,u.port or 443,timeout=5,context=ssl.create_default_context())
 try:
  conn.request('GET',path,headers={'Authorization':'Bearer '+credential,'Accept':'application/json'})
  response=conn.getresponse();raw=response.read(2097153);require(len(raw)<=2097152,'DEPENDENCY_RESPONSE_BOUND_EXHAUSTED')
  try:body=json.loads(raw)
  except(ValueError,UnicodeError):body={}
  if type(body)is not dict:body={}
  safe={'httpStatus':response.status,'hostTransportOnly':True,'responseValuesPrinted':False,'ownerAuthorizationDeniedDetail':body.get('detail')=='Owner authorization denied'}
  for key in('code','errorCode','reason'):
   v=body.get(key)
   if type(v)is str and re.fullmatch('[A-Z][A-Z0-9_:.-]{0,119}',v):safe[key]=v
  return safe,body
 finally:conn.close()

def probe_dependencies(actual,refs,origin):
 global CREDENTIAL_FILES_READ
 pid=actual['State']['Pid'];require(type(pid)is int and pid>1,'CURRENT_UDP_PROCESS_REQUIRED')
 def process_pin():
  raw=Path('/proc/'+str(pid)+'/stat').read_text();return(raw[raw.rfind(')')+2:].split()[19],os.readlink('/proc/'+str(pid)+'/ns/mnt'))
 before=process_pin();root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
 try:
  gateway,target,config_hash=configured_properties(actual,root)
  require(gateway.rstrip('/')==origin.rstrip('/'),'CONFIGURED_GATEWAY_EQUALS_REVIEWED_ORIGIN_REQUIRED')
  token=mounted_file(actual,root,target,16384);CREDENTIAL_FILES_READ=1;parts=token.decode('ascii').strip().split('.')
  require(len(parts)==3 and all(re.fullmatch('[A-Za-z0-9_-]+',p)for p in parts),'WORKLOAD_JWT_SHAPE_REQUIRED')
  claims=json.loads(base64.urlsafe_b64decode(parts[1]+'='*((-len(parts[1]))%4)));expiry=claims.get('exp');require(type(expiry)is int,'WORKLOAD_EXPIRY_REQUIRED')
  emit('UDP_EXECUTION_TOKEN_METADATA',configured=True,expiredAtRead=expiry<=time.time(),expiryEpoch=expiry,claimsAreMetadataOnly=True,signatureVerifiedLocally=False,configFileSha256=config_hash)
  bundle=refs.get('bundleRef');require(type(bundle)is str and 0<len(bundle)<=2048,'EXACT_PINNED_BUNDLE_REFERENCE_REQUIRED')
  safe,envelope=safe_get(origin,'/api/onboarding/v1/runtime/publications/resolve?'+urlencode({'bundleRef':bundle}),token)
  emit('PINNED_PUBLICATION_GET',**safe)
  if safe['httpStatus']==200:
   bindings=envelope.get('bundle',{}).get('semanticReferenceBindings');require(type(bindings)is list and 0<len(bindings)<=32,'BOUNDED_SEMANTIC_REFERENCE_BINDINGS_REQUIRED')
   for i,binding in enumerate(bindings[:2]):
    sid=binding.get('semanticId');revision=binding.get('revisionId');publication=binding.get('publicationSetId')
    require(type(sid)is str and 0<len(sid)<=2048 and all(type(v)is str and re.fullmatch('[0-9a-f-]{36}',v)for v in(revision,publication)),'EXACT_PUBLISHED_SEMANTIC_BINDING_REQUIRED')
    safe,_=safe_get(origin,'/api/semantic/v1/references:resolve?'+urlencode({'semanticId':sid,'revisionId':revision,'publicationSetId':publication}),token)
    emit('SEMANTIC_REFERENCE_GET',bindingIndex=i,**safe)
    if safe['httpStatus']!=200:break
   emit('REFERENCE_PROBE_COVERAGE',semanticBindings=len(bindings),maximumSemanticGets=2,allSemanticDependenciesChecked=False)
  require(before==process_pin(),'UDP_PROCESS_CHANGED_DURING_DEPENDENCY_READ')
 finally:os.close(root)

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_READ_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(65)
 for p in(BOOT.parent,*BOOT.parent.parents):
  a=p.lstat();require(stat.S_ISDIR(a.st_mode)and a.st_uid==0 and not a.st_mode&0o022,'RETAINED_HELPER_ANCESTRY_REQUIRED')
 fd=os.open(BOOT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);require(stat.S_ISREG(a.st_mode)and a.st_uid==a.st_gid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600 and 0<a.st_size<=131072,'RETAINED_HELPER_CUSTODY_REQUIRED')
  raw=os.read(fd,131073);require(len(raw)==a.st_size and hashlib.sha256(raw).hexdigest()==BOOT_HASH,'RETAINED_HELPER_HASH_CHANGED')
 finally:os.close(fd)
 ns={'__name__':'active_acquisition_read_helpers'};exec(compile(raw,'<verified-retained-read-helpers>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);link=old['scopes']['finiteActionProcess']['bundle']
 prepared=ns['read'](link['path'],8388608,link['sha256'])['prepared']
 require(digest(prepared)==old['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_BINDING_CHANGED')
 review=ns['read'](CONTEXT/'review.json',8388608);plan=ns['read'](CONTEXT/'execution-plan.json',8388608);record=ns['read'](CONTEXT/'recovery.json',65536)
 issued=ns['read'](CONTEXT/'authority.json',131072)
 scope=review['scopes']['resolutionComparisonUpdate']
 require(review['kind']=='RESOLUTION_COMPARISON_UPDATE'and digest(plan)==scope['planHash']
  and record['scopeHash']==digest(scope)and record['authorityHash']==digest(issued)
  and issued['resolutionComparisonUpdate']==scope and record['version']==57
  and issued['scopedExecution']['reviewHash']==digest(review)
  and review['sourceClosure']['declaration']['sourceCommit']=='d6da86415abe673d9ac1a692118bd2d0a218b644'
  and digest(review['sourceClosure'])==review['sourceClosureHash']==issued['sourceClosureHash']
  and record['incidentState']=='RECOVERED'and record['nextStage']==len(record['effects'])==len(scope['stages'])==21
  and [e['stage']for e in record['effects']]==scope['stages']
  and all(e['state']=='APPLIED'and e['intentHash']==digest({'planHash':scope['planHash'],'stage':e['stage']})for e in record['effects']),
  'COMPLETE_CURRENT_RESOLUTION_UPDATE_REQUIRED')
 def current_pin(actual):
  pin=ns['runtime_pin'](actual);pin['mountsHash']=digest(sorted(actual['Mounts'],key=lambda m:m['Destination']));return pin
 pins={**{name:record['effects'][-1]['evidence']['applications'][name]['runtimeBinding']for name in('udp','onboarding')},**plan['unchangedApplications']}
 for name,pin in pins.items():
  actual=ns['engine_get'](prepared['engine'],'containers',pin['containerId'])
  require(actual is not None and actual['State']['Running']is True and current_pin(actual)==pin,'CURRENT_APPLICATION_GENERATION_CHANGED')
 db=prepared['databasePlan'];admin=db['mcpAuditRoleAdministration']['admin'];pg=ns['engine_get'](prepared['engine'],'containers',db['postgresRuntimeBinding']['containerId'])
 require(pg is not None and pg['State']['Running']is True and pg['State']['Paused']is False and runtime_pin(pg)==db['postgresRuntimeBinding'],'EXACT_POSTGRES_GENERATION_REQUIRED')
 require([v.split('=',1)[1]for v in pg['Config'].get('Env',[])if v.startswith('POSTGRES_USER=')]==[admin],'EXISTING_ADMINISTRATOR_BINDING_REQUIRED')
 selection=prepared['authorization']['plan']['selection'];tenant=selection['tenant'];require(tenant=='ouf-lab','EXACT_REVIEWED_TENANT_REQUIRED')
 emit('ROLLOUT_BINDING',contextPath=str(CONTEXT),reviewSha256=digest(review),journalVersion=57,reviewSignaturesVerifiedLocally=False)
 for module in('udp',):
  binding=next(r for r in db['modules']if r['module']==module)
  for value in(admin,binding['database']):require(type(value)is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',value),'EXACT_DATABASE_ROLE_REQUIRED')
  with tempfile.TemporaryDirectory(prefix='ouf-acquisition-db-read-')as config:
   argv=[executable(old['sourceClosure']['executables']['docker']),'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],'env','LC_ALL=C',
    'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',binding['database'],'-c',acquisition_query(module,tenant)]
   code,raw,err,_=bounded(argv,seconds=20,maximum=65536);require(code==0,'READ_ONLY_ACQUISITION_SQL_FAILED');facts=json.loads(raw)
  require(facts['database']==binding['database']and facts['databaseOid']==binding['databaseOid']and facts['role']==admin and facts['transactionReadOnly']is True,'EXACT_ACQUISITION_DATABASE_REQUIRED')
  refs=facts.pop('contractRefs');require(facts['confirmedJobCount']==11 and facts['distinctContractSets']==1 and type(refs)is dict,'EXACT_ELEVEN_SAME_CONTRACT_SET_REQUIRED')
  emit('REFERENCE_JOB_METADATA',facts=facts,rawSqlOutputPrinted=False,propertyValuesPrinted=False)
  udp=ns['engine_get'](prepared['engine'],'containers',pins['udp']['containerId'])
  probe_dependencies(udp,refs,selection['origin'])
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_GENERATION_CHANGED_DURING_READ')
 for name,pin in pins.items():
  require(current_pin(ns['engine_get'](prepared['engine'],'containers',pin['containerId']))==pin,'APPLICATION_CHANGED_DURING_READ')
 require(ns['read'](CONTEXT/'recovery.json',65536)==record,'ROLLOUT_RECORD_CHANGED_DURING_READ')
 emit('END',complete=True,dependencyProbeComplete=True,reconciliationPerformed=False,
  runtimeAuthorityIssued=False,confirmationReceipt='a5183503-04ff-4e10-850f-e22bf874365e',
  allThirteenMaterializedProven=False,cinemaHistoricalEqualityProven=False)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=65,maximumEngineReads=10,maximumSqlSessions=1,maximumCredentialFiles=1,maximumGatewayGets=3)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)
