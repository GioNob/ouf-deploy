#!/usr/bin/env python3
"""Read-only retained route, workload scope and owner policy diagnosis; credential values stay in memory."""
import fcntl,base64,hashlib,http.client,json,os,re,selectors,shlex,signal,socket,ssl,stat,subprocess,sys,tempfile,time
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
 print(json.dumps(dict(schema='ouf.teatri-reference-recovery-preflight.v1',check=check,readOnly=True,
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

def configured_properties(actual,root,required=("ouf.udp.execution.gateway-url","ouf.udp.execution.token-file")):
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
 if required==('spring.datasource.url','spring.datasource.username'):
  for alias,key in(('OUF_SEM_DB_URL',required[0]),('OUF_SEM_DB_USER',required[1])):
   if env.get(alias):add(key,env[alias])
 if required==('ouf.authorization.registry-url','ouf.authorization.registry-token-file'):
  for alias,key in(('REGISTRY_URL',required[0]),('REGISTRY_TOKEN_FILE',required[1])):
   if env.get(alias):add(key,env[alias])
 argv=(actual['Config'].get('Entrypoint')or[])+(actual['Config'].get('Cmd')or[])
 for key in('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'):argv+=shlex.split(env.get(key,''))
 for arg in argv:
  if arg.startswith(('-D','--'))and '='in arg:
   k,v=arg[2:].split('=',1);add(k,v)

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
 require((path.startswith('/api/')or path=='/internal/capabilities/v1/authorization/policy-bundle/active')and '\r'not in path and '\n'not in path,'BOUNDED_DEPENDENCY_PATH_REQUIRED')
 credential=token.decode('ascii').strip();require(0<len(credential)<=16384 and not any(x.isspace()for x in credential),'PRIVATE_WORKLOAD_TOKEN_REQUIRED')
 conn=http.client.HTTPSConnection(u.hostname,u.port or 443,timeout=5,context=ssl.create_default_context())
 try:
  conn.request('GET',path,headers={'Authorization':'Bearer '+credential,'Accept':'application/json'})
  response=conn.getresponse();raw=response.read(2097153);require(len(raw)<=2097152,'DEPENDENCY_RESPONSE_BOUND_EXHAUSTED')
  try:body=json.loads(raw)
  except(ValueError,UnicodeError):body={}
  if type(body)is not dict:body={}
  safe={'httpStatus':response.status,'hostTransportOnly':True,'responseValuesPrinted':False,'ownerAuthorizationDeniedDetail':body.get('detail')=='Owner authorization denied'}
  for key in('code','errorCode','reason','error','message','detail'):
   v=body.get(key)
   if type(v)is str and (re.fullmatch('(SEM_|UDP_|OUF_|AUTHORIZATION_)[A-Z0-9_:.-]{1,110}',v)or v in('insufficient_scope','invalid_token','access_denied','Forbidden','Unauthorized','SEM_CAPABILITY_REQUIRED:ouf.semantic.read','SEM_AUTHENTICATION_REQUIRED')):safe[key]=v
  return safe,body
 finally:conn.close()

def probe_dependencies(actual,refs,origin,plan):
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
  emit_route_access_metadata(plan,claims)
  require(before==process_pin(),'UDP_PROCESS_CHANGED_DURING_DEPENDENCY_READ')
  return claims
 finally:os.close(root)

def emit_route_access_metadata(plan,claims):
 scope=claims.get('scope');scope=set(scope.split())if type(scope)is str else set(scope or[])
 actor=claims.get('ouf_actor_type');service=claims.get('client_id')or claims.get('azp');aud=claims.get('aud');aud=[aud]if type(aud)is str else aud or[]
 rows=[route for route in plan['gateway']['afterRoutes'].values()if route.get('uri')=='/api/semantic/v1/references:resolve'and 'GET'in route.get('methods',[])]

 if len(rows)!=1:
  emit('RETAINED_ROUTE_AND_TOKEN_METADATA',exactRouteCount=len(rows),routeMetadataIsRetained=True,liveRouteInventoryProven=False,semanticReadScopePresent='ouf.semantic.read'in scope,actorIsService=actor=='SERVICE');return
 route=rows[0];plugins=route.get('plugins')or{};oidc=plugins.get('openid-connect')or{}
 required=oidc.get('required_scopes')or[];require(type(required)is list and len(required)<=16 and all(type(v)is str and len(v)<=128 for v in required),'BOUNDED_ROUTE_SCOPE_METADATA_REQUIRED')
 functions=(plugins.get('serverless-post-function')or{}).get('functions')or[]
 tables={'services':[],'actors':[]}
 for kind,key in(('services','allowed_services'),('actors','allowed_actors')):
  for fn in functions:
   matches=re.findall(r'local '+key+r'=\{([^}]+)\}',fn)
   for body in matches:
    for value in re.findall(r'\[("(?:[^"\\]|\\.)*")\]=true',body):tables[kind].append(json.loads(value))
 emit('RETAINED_ROUTE_AND_TOKEN_METADATA',routeId=route['id'],routeMetadataIsRetained=True,liveRouteInventoryProven=False,
  requiredScopes=required,requiredScopesPresentInToken=all(v in scope for v in required),
  semanticReadScopePresent='ouf.semantic.read'in scope,actorIsService=actor=='SERVICE',
  principalCategory='UDP'if service=='ouf-udp'else'INGESTION'if service=='ouf-ingestion'else'OTHER',
  audienceMatchesRoute=oidc.get('client_id')in aud,bearerOnly=oidc.get('bearer_only')is True,
  workloadGuardMetadataParsed=bool(tables['services'])and bool(tables['actors']),
  servicePrincipalAllowedByRetainedGuard=service in tables['services'],actorAllowedByRetainedGuard=actor in tables['actors'])

def policy_metadata(doc,claims):
 bundle=doc.get('bundle');version=doc.get('bundleVersion')
 require(type(bundle)is dict and type(version)is int,'ACTIVE_OWNER_POLICY_ENVELOPE_REQUIRED')
 caps=bundle.get('capabilities');grants=bundle.get('grants')
 require(type(caps)is list and type(grants)is list and len(caps)<=10000 and len(grants)<=10000 and all(type(v)is dict for v in caps+grants),'BOUNDED_OWNER_POLICY_PAYLOAD_REQUIRED')
 compact=json.dumps(bundle,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
 checksum=hashlib.sha256(compact).hexdigest()==doc.get('contentHash')
 result={'bundleVersion':version,'compactBundleHashMatchesEnvelope':checksum,'loadedOwnerSnapshotProven':False}
 if not checksum:return result
 tenant=claims.get('tenant_id');subject=claims.get('ouf_subject')or claims.get('sub');service=claims.get('client_id')or claims.get('azp')
 require(all(type(v)is str and 0<len(v)<=256 for v in(tenant,subject,service)),'UDP_IDENTITY_METADATA_REQUIRED')
 result['capabilities']=[c for c in caps if c.get('capabilityId')=='ouf.semantic.read']
 selected=[g for g in grants if g.get('capabilityId')=='ouf.semantic.read'and g.get('tenantId')==tenant]
 require(len(selected)<=64,'BOUNDED_SEMANTIC_READ_GRANTS_REQUIRED');rows=[]
 def instant(value):
  if type(value)is not str:return None
  from datetime import datetime
  return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
 for g in selected:
  constraints=g.get('constraints')or{};require(type(constraints)is dict,'OWNER_GRANT_CONSTRAINT_SHAPE_REQUIRED')
  start=instant(g.get('validFrom'));end=instant(g.get('validUntil'));attrs=constraints.get('resourceAttributes')or{}
  require(type(attrs)is dict,'OWNER_RESOURCE_ATTRIBUTES_SHAPE_REQUIRED')
  rows.append({'subjectMatchesToken':not g.get('subjectId')or g.get('subjectId')==subject,
   'servicePrincipalMatchesToken':not g.get('servicePrincipalId')or g.get('servicePrincipalId')==service,
   'organizationRestricted':bool(g.get('organizationId')),
   'validAtRead':start is not None and end is not None and start<=time.time()<end,
   'resourceTypeMatchesValidation':not constraints.get('resourceType')or constraints.get('resourceType')=='semantic.validation',
   'resourceIdMatchesUnspecified':not constraints.get('resourceId'),
   'moduleConstraintMatches':all(k=='module'and v=='SEMANTIC'for k,v in attrs.items()),'constraints':constraints})
 result['grants']=rows
 return result

def probe_owner_policy_channel(actual,origin,udp_claims=None):
 global CREDENTIAL_FILES_READ
 pid=actual['State']['Pid'];require(type(pid)is int and pid>1,'CURRENT_SEMANTIC_PROCESS_REQUIRED')
 def pin():
  raw=Path('/proc/'+str(pid)+'/stat').read_text();return(raw[raw.rfind(')')+2:].split()[19],os.readlink('/proc/'+str(pid)+'/ns/mnt'))
 before=pin();root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
 try:
  endpoint,target,config_hash=configured_properties(actual,root,('ouf.authorization.registry-url','ouf.authorization.registry-token-file'))
  path='/internal/capabilities/v1/authorization/policy-bundle/active'
  require(endpoint==origin.rstrip('/')+path,'REVIEWED_OWNER_POLICY_ENDPOINT_REQUIRED')
  token=mounted_file(actual,root,target,16384);CREDENTIAL_FILES_READ+=1
  parts=token.decode('ascii').strip().split('.');require(len(parts)==3,'OWNER_POLICY_JWT_SHAPE_REQUIRED')
  claims=json.loads(base64.urlsafe_b64decode(parts[1]+'='*((-len(parts[1]))%4)));expiry=claims.get('exp');require(type(expiry)is int,'OWNER_POLICY_TOKEN_EXPIRY_REQUIRED')
  emit('OWNER_POLICY_TOKEN_METADATA',configured=True,expiredAtRead=expiry<=time.time(),expiryEpoch=expiry,claimsAreMetadataOnly=True,signatureVerifiedLocally=False,configFileSha256=config_hash)
  safe,body=safe_get(origin,path,token)
  version=body.get('bundleVersion');version=version if type(version)is int else body.get('version')if type(body.get('version'))is int else None
  emit('OWNER_POLICY_TRANSPORT_GET',activeBundleVersion=version,loadedOwnerSnapshotProven=False,**safe)
  if safe['httpStatus']==200 and udp_claims is not None:
   emit('SEMANTIC_OWNER_POLICY_METADATA',facts=policy_metadata(body,udp_claims),policyObtainedFromConfiguredRegistryChannel=True,loadedOwnerSnapshotProven=False,rawPolicyPrinted=False)
  require(before==pin(),'SEMANTIC_PROCESS_CHANGED_DURING_POLICY_READ')
 finally:os.close(root)


def reviewed_registry(ns,engine):
 # Bind by the immutable reviewed identity, never by a guessed container name.
 review=ns['read'](POLICY_CONTEXT/'review.json',8388608,POLICY_REVIEW)
 link=review.get('workerReviewBinding',{})
 require(link.get('path')==str(POLICY_CONTEXT/'worker-review.json')and re.fullmatch('[0-9a-f]{64}',str(link.get('sha256',''))),'EXACT_WORKER_REVIEW_LINK_REQUIRED')
 worker=ns['read'](link['path'],8388608,link['sha256'])
 pin=worker['registryGeneration']
 require(type(pin)is dict and re.fullmatch('[0-9a-f]{64}',str(pin.get('containerId',''))),'EXACT_REVIEWED_REGISTRY_ID_REQUIRED')
 actual=ns['engine_get'](engine,'containers',pin['containerId'])
 require(actual is not None and actual['State']['Running']is True and ns['runtime_pin'](actual)==pin,'CURRENT_REVIEWED_REGISTRY_GENERATION_REQUIRED')
 return actual

def semantic_policy_query(tenant,claims):
 t=literal(tenant);subject=literal(claims.get('ouf_subject')or claims.get('sub'));service=literal(claims.get('client_id')or claims.get('azp'))
 return """BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s';
 WITH active AS (SELECT b.version,b.bundle_payload FROM ouf_authorization.active_policy_bundle a JOIN ouf_authorization.policy_bundle b ON b.bundle_id=a.bundle_id AND b.version=a.version WHERE a.singleton_key=true),
 selected AS (SELECT g FROM active a CROSS JOIN LATERAL jsonb_array_elements(a.bundle_payload->'grants') g WHERE g->>'capabilityId'='ouf.semantic.read' AND g->>'tenantId'="""+t+""")
 SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
 'bundleCount',(SELECT count(*) FROM active),'bundleVersion',(SELECT version FROM active),
 'capabilities',coalesce((SELECT jsonb_agg(c) FROM active a CROSS JOIN LATERAL jsonb_array_elements(a.bundle_payload->'capabilities') c WHERE c->>'capabilityId'='ouf.semantic.read'),'[]'::jsonb),
 'grants',coalesce((SELECT jsonb_agg(jsonb_build_object('servicePrincipalMatchesToken',coalesce(g->>'servicePrincipalId','')=''OR g->>'servicePrincipalId'="""+service+""",'subjectMatchesToken',coalesce(g->>'subjectId','')=''OR g->>'subjectId'="""+subject+""",'validAtRead',(g->>'validFrom')::timestamptz<=clock_timestamp()AND clock_timestamp()<(g->>'validUntil')::timestamptz,'organizationRestricted',coalesce(g->>'organizationId','')<>'','resourceTypeMatchesValidation',coalesce(g->'constraints'->>'resourceType','')IN('','semantic.validation'),'resourceIdMatchesUnspecified',coalesce(g->'constraints'->>'resourceId','')='','moduleConstraintMatches',coalesce(g->'constraints'->'resourceAttributes','{}'::jsonb)IN('null'::jsonb,'{}'::jsonb,'{"module":"SEMANTIC"}'::jsonb),'constraints',g->'constraints'))FROM selected),'[]'::jsonb)); ROLLBACK;"""

def unlocked(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600,'PRIVATE_INVOCATION_LOCK_REQUIRED')
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return False
  fcntl.flock(fd,fcntl.LOCK_UN);return True
 finally:os.close(fd)

def recovery_metadata(ns,current_review,selection):
 read=ns['read'];base=read(POLICY_CONTEXT/'review.json',8388608,POLICY_REVIEW)
 prior=base['scopes']['policyTokenFiniteWorkerSession'];path=Path(prior['fenceBinding']['path'])
 fence=read(path,16384)
 require(fence.get('schema')=='ouf.semantic-functional-session-fence.v1'and fence.get('logicalOwnerScopeHash')==prior['logicalOwnerScopeHash'],'EXACT_LOGICAL_OWNER_FENCE_REQUIRED')
 journal=Path(fence['journalPath'])
 require(journal.parent==path.parent and journal.name=='semantic-functional-worker-'+fence['reviewHash'],'EXACT_CURRENT_WORKER_DIRECTORY_REQUIRED')
 rows={n:read(journal/n,131072)for n in('owner-session.json','owner-session-review.json','recovery.json','owner-status.json','owner-admission.json')}
 signed=rows['owner-session.json'];row=rows['recovery.json'];worker_review=rows['owner-session-review.json']
 require(signed['fenceBinding']=={'path':str(path),'value':fence}and digest(worker_review)==signed['reviewHash']==fence['reviewHash'],'CURRENT_WORKER_REVIEW_CHAIN_REQUIRED')
 prior_count=signed['predecessorGrantAttempts'];attempts=row['attempts'];ceiling=signed['maximumCumulativeGrantAttempts']
 require(type(attempts)is int and type(prior_count)is int and type(ceiling)is int and 0<=attempts<=signed['policy']['max_attempts']<=128 and row['controlledPredecessorGrantAttempts']==prior_count and row['controlledCumulativeGrantAttempts']==prior_count+attempts<=ceiling,'EXACT_CURRENT_CUMULATIVE_BUDGET_REQUIRED')
 state=row['state'];reason=row.get('reason');require(state in('NEW','ACTIVE','RETRY_WAIT','CANCELLED','FAILED','BLOCKED','EXHAUSTED')and(reason is None or re.fullmatch('[A-Z_]{1,100}',reason)),'SAFE_WORKER_STATE_REQUIRED')
 emit('CURRENT_POLICY_WORKER_HISTORY',journalPath=str(journal),state=state,reason=reason,attempts=attempts,publications=row.get('publicationCount'),priorControlledGrantAttempts=prior_count,controlledCumulativeGrantAttempts=prior_count+attempts,maximumCumulativeGrantAttempts=ceiling,remainingControlledGrantAttempts=ceiling-prior_count-attempts,invocationLockUnheldAtRead=unlocked(journal/'invocation.lock'),workerReviewHash=digest(worker_review),recordHashes={n:digest(v)for n,v in rows.items()},newWorkerStarted=False)
 hb=current_review['authenticatedHuman'];directory=Path(hb['sessionDirectory'])
 require(directory.is_absolute()and directory.parent==Path('/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem')and hb['tokenPath']==str(directory/'human-access.jwt')and all(hb[k]==selection[k]for k in('issuer','tenant','subject')),'CURRENT_REVIEWED_HUMAN_DIRECTORY_REQUIRED')
 human=read(directory/'recovery.json',65536)
 require(human['binding']==hb and human['budgetReset']is False and type(human['attempts'])is int and 0<=human['attempts']<=128,'EXACT_CURRENT_HUMAN_BUDGET_REQUIRED')
 require(human['state']in('NEW','DEVICE_START','DEVICE_POLL','REQUESTING','RETRY_WAIT','VERIFYING','READY','BLOCKED'),'SAFE_HUMAN_STATE_REQUIRED')
 operation=human.get('operation');require(operation is None or operation in('DISCOVERY','DEVICE_START','DEVICE_POLL','USERINFO','REFRESH'),'SAFE_HUMAN_OPERATION_REQUIRED')
 emit('CURRENT_HUMAN_BUDGET',state=human['state'],operation=operation,attempts=human['attempts'],remainingOAuthAttempts=128-human['attempts'],maximumCumulativeOAuthAttempts=128,expiredAtRead=time.time()>=hb['expiresAt'],expiresAt=hb['expiresAt'],invocationLockUnheldAtRead=unlocked(directory/'invocation.lock'),successorClaimPresent=os.path.lexists(directory/'successor-window.claim.json'),credentialBearingJournalsRead=1,credentialValuesPrintedByProjection=False,newLoginAuthorized=False)
 require(read(directory/'recovery.json',65536)==human and read(path,16384)==fence and all(read(journal/n,131072)==v for n,v in rows.items()),'RECOVERY_METADATA_CHANGED_DURING_READ')

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_READ_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(90)
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
  claims=probe_dependencies(udp,refs,selection['origin'],plan)
  registry=reviewed_registry(ns,prepared['engine'])
  registry_pin=runtime_pin(registry)
  emit('SEMANTIC_RUNTIME_METADATA',containerPresent=True,sourceCommitLabel=registry['Config'].get('Labels',{}).get('org.opencontainers.image.revision'))
  binding=next(r for r in db['modules']if r['module']=='onboarding')
  with tempfile.TemporaryDirectory(prefix='ouf-reference-policy-read-')as config:
   argv=[executable(old['sourceClosure']['executables']['docker']),'--host','unix://'+prepared['engine']['socketPath'],'--config',config,'exec',pg['Id'],'env','LC_ALL=C',
    'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',binding['database'],'-c',semantic_policy_query(tenant,claims)]
   code,raw,err,_=bounded(argv,seconds=20,maximum=65536);require(code==0,'READ_ONLY_PUBLISHED_POLICY_SQL_FAILED');facts=json.loads(raw)
  require(facts['database']==binding['database']and facts['databaseOid']==binding['databaseOid']and facts['role']==admin and facts['transactionReadOnly']is True and facts['bundleCount']==1,'EXACT_POLICY_DATABASE_BINDING_REQUIRED')
  emit('PUBLISHED_SEMANTIC_READ_GRANTS',facts=facts,loadedRegistrySnapshotProven=False,rawSqlOutputPrinted=False)
  recovery_metadata(ns,review,selection)
  require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',registry['Id']))==registry_pin,'SEMANTIC_GENERATION_CHANGED_DURING_READ')
 require(runtime_pin(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_GENERATION_CHANGED_DURING_READ')
 for name,pin in pins.items():
  require(current_pin(ns['engine_get'](prepared['engine'],'containers',pin['containerId']))==pin,'APPLICATION_CHANGED_DURING_READ')
 require(ns['read'](CONTEXT/'recovery.json',65536)==record,'ROLLOUT_RECORD_CHANGED_DURING_READ')
 emit('END',complete=True,dependencyProbeComplete=True,reconciliationPerformed=False,
  runtimeAuthorityIssued=False,confirmationReceipt='a5183503-04ff-4e10-850f-e22bf874365e',
  allThirteenMaterializedProven=False,cinemaHistoricalEqualityProven=False)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=90,maximumEngineReads=12,maximumSqlSessions=2,maximumCredentialFiles=1,maximumGatewayGets=0,credentialBearingJournalsReadMaximum=1)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)
