#!/usr/bin/env python3
"""Installation-specific retained THS config and route snapshot metadata; no token or property reads."""
import ast,shlex,hashlib,http.client,json,os,re,selectors,signal,socket,stat,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.parse import quote
BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'
CONTEXT=Path('/etc/ouf/deploy-snapshots/onboarding-audit-execution-ybmis4le')
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
def emit(check,**values):
 print(json.dumps(dict(schema='ouf.resolution-ths-property-shape-read.v1',check=check,readOnly=True,
  automaticRetry=False,budgetReset=False,installationSpecific=True,credentialValuesPrinted=False,
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

THS_CONFIG='/opt/ouf/secrets/onboarding-ths.yaml'
CUSTODY_SOURCE_SHA='5e7182d899a25a299b103d63f6bf81822280f09e58b963c38f735aa2a4fee72f'
CURRENT_REVIEW='b258d70a9ec1e6257be8508bdce62b69b60e7b78a671356dd5defb8490796ca3'
def custody_reader(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=131072,'BOUNDED_CUSTODY_SOURCE_REQUIRED')
  raw=os.read(fd,131073);after=os.fstat(fd)
  require(len(raw)==before.st_size and (before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns)and hashlib.sha256(raw).hexdigest()==CUSTODY_SOURCE_SHA,'QUALIFIED_CONFIG_CUSTODY_SOURCE_REQUIRED')
 finally:os.close(fd)
 names={'EXTERNAL_ADMIN_KEY','_EXISTING_CONFIG_CUSTODY','selected_directory_custody','selected_file_custody','private_config'};nodes=[];seen=set()
 for node in ast.parse(raw).body:
  name=node.name if isinstance(node,ast.FunctionDef)else node.targets[0].id if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)else None
  if name in names:nodes.append(node);seen.add(name)
 require(seen==names,'EXACT_CUSTODY_READER_FUNCTIONS_REQUIRED')
 ns={'os':os,'stat':stat,'Path':Path,'hashlib':hashlib,'require':require}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<verified-config-custody-functions>','exec'),ns)
 return ns['private_config']
def normal(key):return re.sub('[^a-z0-9]','',key.lower())
def selected_metadata(raw,env,origin):
 # Report property shape and public booleans only, never configuration strings.
 keys={'enabled':'ouf.authorization.ths.enabled','gateway':'ouf.resolution.ths.gateway-base-url','scopes':'spring.security.oauth2.client.registration.ouf-ths.scope'}
 targets={normal(value):key for key,value in keys.items()};rows=[];stack=[]
 def scalar(value):
  if type(value)is bool:return {'kind':'BOOLEAN','boolean':value}
  if value is None:return {'kind':'NULL'}
  if type(value)is list:
   parts=[str(v)for v in value];return {'kind':'LIST','count':len(parts),'issueReadPresent':'resolution.issue.read'in parts,'matchApprovePresent':'resolution.match.approve'in parts}
  if type(value)is not str:return {'kind':'OTHER'}
  text=value.strip().strip("\"'");lower=text.lower()
  if lower in('true','false'):return {'kind':'BOOLEAN_STRING','boolean':lower=='true','canonicalLowercase':text==lower}
  match=re.fullmatch(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([^{}]*))?\}',text)
  if match:
   selected=env.get(match[1],match[2]);detail={'kind':'ENV_REFERENCE','environmentPresent':match[1]in env,'defaultPresent':match[2]is not None}
   if selected is not None and selected.strip().lower()in('true','false'):detail['resolvedBoolean']=selected.strip().lower()=='true'
   return detail
  parts={v.strip("[]\"'")for v in re.split(r'[,\s]+',text)}
  return {'kind':'FLOW_MAPPING'if text.startswith('{')else'FLOW_LIST'if text.startswith('[')else'SCALAR',
   'gatewayEqualsReviewedOrigin':text.rstrip('/')==origin.rstrip('/'),'placeholderPresent':'${'in text,
   'issueReadPresent':'resolution.issue.read'in parts,'matchApprovePresent':'resolution.match.approve'in parts}
 def add(path,value,channel):
  key=targets.get(normal(path))
  if key:rows.append({'property':key,'channel':channel,**scalar(value)})
 def flatten(obj,prefix=''):
  if type(obj)is not dict:return
  for key,value in obj.items():
   path=prefix+'.'+key if prefix else key
   if type(value)is dict:flatten(value,path)
   else:add(path,value,'SPRING_APPLICATION_JSON')
 for line in raw.decode().splitlines():
  if not line.strip()or line.lstrip().startswith('#'):continue
  indent=len(line)-len(line.lstrip());text=line.strip()
  if text.startswith('- '):add('.'.join(k for _,k in stack),text[2:],'YAML_LIST');continue
  match=re.fullmatch(r'["\']?([A-Za-z0-9_.-]+)["\']?:(?:\s+(.*))?',text)
  if not match:continue
  while stack and stack[-1][0]>=indent:stack.pop()
  key='.'.join([k for _,k in stack]+[match[1]])
  if match[2]is None:stack.append((indent,match[1]))
  else:add(key,match[2],'YAML')
 for key,value in env.items():add(key,value,'ENVIRONMENT')
 value=env.get('SPRING_APPLICATION_JSON')
 require(not value or len(value)<=1048576,'BOUNDED_SPRING_JSON_REQUIRED')
 application=json.loads(value)if value else{}
 require(type(application)is dict,'SPRING_JSON_OBJECT_REQUIRED');flatten(application)
 return {'selectedPropertyMetadata':rows,'springApplicationJsonPresent':bool(value),'springJsonTopLevelKeyCount':len(application),
  'yamlContainsFlowSyntax':bool(re.search(r':\s*[\[{]',raw.decode())),'yamlContainsPlaceholderSyntax':b'${'in raw,
  'effectiveConfigProven':False,'noRawConfigurationValuesPrinted':True}

def route_metadata(routes,origin_host):
 selected=[];matches=[]
 for rid,r in sorted(routes.items()):
  uris=[r['uri']]if type(r.get('uri'))is str else r.get('uris',[])
  require(type(uris)is list and all(type(u)is str for u in uris),'BOUNDED_ROUTE_URIS_REQUIRED')
  def path_matches(u,path):return u==path or u.endswith('*')and path.startswith(u[:-1])
  relevant=any('/trusted-human/'in u or '/oauth2/'in u or '/api/udp/v1/governance/'in u
   or path_matches(u,'/trusted-human/resolution/')for u in uris)
  if not relevant:continue
  p=r.get('plugins')or{};oidc=p.get('openid-connect')or{};upstream=r.get('upstream')or{}
  selected.append({'id':rid,'uris':uris,'methods':r.get('methods'),
   'requiredScopes':oidc.get('required_scopes',[]),'oidcBearerOnly':oidc.get('bearer_only'),
   'humanGuardPresent':bool(p.get('serverless-post-function')),
   'stripTrustHeadersPresent':bool(p.get('serverless-pre-function')),
   'hasHostRestriction':bool(r.get('host')or r.get('hosts')),
   'reviewedHostMatches':r.get('host')==origin_host or origin_host in(r.get('hosts')or[])if(r.get('host')or r.get('hosts'))else True,
   'upstreamHash':digest(upstream)})
  if any(path_matches(u,'/trusted-human/resolution/')for u in uris)and('GET'in(r.get('methods')or['GET'])):matches.append(rid)
 require(len(selected)<=32,'BOUNDED_RELEVANT_ROUTE_METADATA_REQUIRED')
 return {'selectedRoutes':selected,'resolutionPageMatchesByPathAndMethod':matches,'liveRouteInventoryRead':False}

def main():
 from urllib.parse import urlsplit
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==2,'ISOLATED_ROOT_READ_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(35)
 for p in(BOOT.parent,*BOOT.parent.parents):
  a=p.lstat();require(stat.S_ISDIR(a.st_mode)and a.st_uid==0 and not a.st_mode&0o022,'RETAINED_HELPER_ANCESTRY_REQUIRED')
 fd=os.open(BOOT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);require(stat.S_ISREG(a.st_mode)and a.st_uid==a.st_gid==0 and a.st_nlink==1 and stat.S_IMODE(a.st_mode)==0o600 and 0<a.st_size<=131072,'RETAINED_HELPER_CUSTODY_REQUIRED')
  raw=os.read(fd,131073);require(len(raw)==a.st_size and hashlib.sha256(raw).hexdigest()==BOOT_HASH,'RETAINED_HELPER_HASH_CHANGED')
 finally:os.close(fd)
 ns={'__name__':'resolution_metadata_read_helpers'};exec(compile(raw,'<verified-retained-read-helpers>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);link=old['scopes']['finiteActionProcess']['bundle'];prepared=ns['read'](link['path'],8388608,link['sha256'])['prepared']
 require(digest(prepared)==old['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_BINDING_CHANGED')
 review=ns['read'](CONTEXT/'review.json',8388608,CURRENT_REVIEW);plan=ns['read'](CONTEXT/'execution-plan.json',8388608);record=ns['read'](CONTEXT/'recovery.json',65536)
 scope=review['scopes']['onboardingAuditUpdate']
 require(digest(plan)==scope['planHash']and record['scopeHash']==digest(scope)and record['version']==29 and record['incidentState']=='RECOVERED'and all(e['state']=='APPLIED'for e in record['effects'])and record['nextStage']==len(record['effects'])==len(scope['stages'])==11,'EXACT_COMPLETED_ONBOARDING_FIX_REQUIRED')
 expected=record['effects'][-1]['evidence']['applications']['onboarding']['runtimeBinding'];app=ns['engine_get'](prepared['engine'],'containers',expected['containerId'])
 require(ns['runtime_pin'](app)==expected and app['State']['Running']is True,'CURRENT_ONBOARDING_GENERATION_CHANGED')
 mounts=[m for m in app['Mounts']if m.get('Source')==THS_CONFIG]
 require(len(mounts)==1 and mounts[0].get('Type')=='bind'and mounts[0].get('RW')is False,'EXACT_SELECTED_THS_CONFIG_MOUNT_REQUIRED')
 env={}
 for item in app['Config'].get('Env')or[]:
  k,v=item.split('=',1);require(k not in env,'DUPLICATE_RUNTIME_ENVIRONMENT_KEY');env[k]=v
 origin=prepared['authorization']['plan']['selection']['origin'];u=urlsplit(origin)
 require(u.scheme=='https'and u.hostname and not u.username and not u.query and not u.fragment,'REVIEWED_HTTPS_ORIGIN_REQUIRED')
 read=custody_reader(sys.argv[1]);raw,binding=read(THS_CONFIG)
 meta=selected_metadata(raw,env,origin)
 selectors=[v for k,v in env.items()if normal(k)in{'springconfiglocation','springconfigadditionallocation','springconfigimport'}]
 meta['selectedMountMentionedInRuntimeConfigSelector']=any(mounts[0]['Destination']in value for value in selectors)
 meta['springApplicationJsonPresent']=bool(env.get('SPRING_APPLICATION_JSON'))
 args=(app['Config'].get('Entrypoint')or[])+(app['Config'].get('Cmd')or[])
 meta['javaOrArgumentOverrideChannelsPresent']=any(env.get(k)for k in('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'))or any(a.startswith(('-D','--'))for a in args)
 emit('THS_CONFIGURATION_METADATA',**meta,configFileSha256=binding['sha256'],credentialConfigurationFilesRead=1,tokenFilesRead=0)
 require(ns['runtime_pin'](ns['engine_get'](prepared['engine'],'containers',app['Id']))==expected and ns['read'](CONTEXT/'recovery.json',65536)==record,'ONBOARDING_CHANGED_DURING_READ')
 require(read(THS_CONFIG,binding)[1]==binding,'THS_CONFIG_CHANGED_DURING_READ')
 emit('END',complete=True,gatewayWrites=0,credentialConfigurationFilesRead=1,tokenFilesRead=0,liveRouteInventoryRead=False,loadedSnapshotProven=False,runtimeAuthorityIssued=False)
if __name__=='__main__':
 emit('BEGIN',maximumSeconds=35,maximumEngineReads=2,maximumCredentialConfigurationFiles=1,tokenFilesRead=0,gatewayWrites=0)
 try:main()
 except Exception as error:
  reason=str(error)if type(error)is ValueError and re.fullmatch('[A-Z_]+',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False)
