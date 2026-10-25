#!/usr/bin/env python3
"""Freeze exact proposed READ infrastructure; one bounded infrastructure GET, no apply."""
import copy,hashlib,importlib.util,json,os,re,signal,stat,subprocess,sys,tarfile,types
from pathlib import Path
INPUTS=Path('/etc/ouf/deploy-snapshots/acquisition-evidence-current-inputs-v1/inputs.json')
INPUTS_HASH='c40ba6dc86e8be72ddcda2eaef65fe3eb8aa9f24b8ec4b0d5758b0bfeacf1da6'
PACKAGES=Path('/etc/ouf/deploy-snapshots/acquisition-read-packages-2f9a2336572e1bbc')
RECEIPT_HASH='11cdf347aa966b6b32bfa84f8c35a28b598e7563611bf5580282bbb36b3f6a70'
CASE_HASH='2f9a2336572e1bbc57215bc6fc7b4f3a5f9bc5fa74e160be751cc0f57dcb8a80'
ROOT=Path('/etc/ouf/deploy-snapshots/acquisition-read-native-plan-v1')
PROJECTION=Path('/opt/ouf/installation/active-projection.json')
COUNTS={'privateMetadataReads':0,'ownerConfigurationContentReads':0,'serviceCredentialFilesOpened':0,'gatewayAdminGetAttempts':0,'networkNamespaceJoins':0}
class Stop(RuntimeError):pass
PlanDenied=Stop

def require(ok,reason='PLAN_CONTRACT_REQUIRED'):
    if not ok:raise Stop(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def sha(v):return hashlib.sha256(v).hexdigest()
def unique(pairs):
    out={}
    for k,v in pairs:require(k not in out,'DUPLICATE_JSON_KEY');out[k]=v
    return out
def decode(raw):return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(Stop('NONFINITE_JSON')))
def frame(s):return(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def ancestry(path):
    require(path.is_absolute()and'..'not in path.parts,'ABSOLUTE_ROOT_PATH_REQUIRED')
    for parent in(path,*path.parents):
        v=parent.lstat();require(stat.S_ISDIR(v.st_mode)and v.st_uid==0 and not v.st_mode&0o022,'ROOT_PRIVATE_ANCESTRY_REQUIRED')
def protected(path,expected=None,limit=8*1024*1024):
    ancestry(path.parent);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        v=os.fstat(fd);require(stat.S_ISREG(v.st_mode)and v.st_uid==v.st_gid==0 and v.st_nlink==1 and stat.S_IMODE(v.st_mode)in(0o400,0o600)and 0<v.st_size<=limit,'PROTECTED_BOUNDED_METADATA_REQUIRED')
        raw=os.read(fd,v.st_size+1);require(len(raw)==v.st_size and frame(v)==frame(os.fstat(fd))==frame(path.lstat()),'PRIVATE_METADATA_CHANGED')
        require(expected is None or sha(raw)==expected,'EXACT_PRIVATE_METADATA_HASH_REQUIRED');COUNTS['privateMetadataReads']+=1
        return raw
    finally:os.close(fd)
def put(path,v):
    raw=v if isinstance(v,bytes)else encoded(v);require(len(raw)<=16*1024*1024,'BOUNDED_PRIVATE_OUTPUT_REQUIRED')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
def new_directory(path):path.mkdir(mode=0o700)
def env(config):
    result={}
    for entry in config.get('Env')or[]:
        require(type(entry)is str and'='in entry,'TYPED_CAPTURED_ENVIRONMENT_REQUIRED');k,v=entry.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',k)is not None and k not in result,'UNIQUE_CAPTURED_ENVIRONMENT_REQUIRED');result[k]=v
    return result

def process_pin(pid):
    require(type(pid)is int and pid>1,'POSITIVE_CAPTURED_PID_REQUIRED');raw=Path('/proc/'+str(pid)+'/stat').read_bytes();require(0<len(raw)<16384 and b') 'in raw,'BOUNDED_PROCESS_PIN_REQUIRED')
    ticks=int(raw.rsplit(b') ',1)[1].split()[19]);namespaces={}
    for name in('net','mnt'):
        v=Path('/proc/'+str(pid)+'/ns/'+name).stat();namespaces[name]=[v.st_dev,v.st_ino]
    return {'pid':pid,'startTicks':ticks,'namespaces':namespaces}
def check_processes(inputs):
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==inputs['bootId'],'CAPTURED_HOST_BOOT_CHANGED')
    for role,pin in inputs['currentProcessPins'].items():require(process_pin(pin['pid'])==pin,'CAPTURED_ROLE_PROCESS_CHANGED')
def stable_binding(actual):
    require(re.fullmatch('[a-f0-9]{64}',actual['Id'])is not None,'CAPTURED_CONTAINER_ID_REQUIRED')
    return {'containerId':actual['Id'],'imageId':actual['Image'],'name':actual['Name'],'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
        'configHash':digest(actual['Config']),'hostConfigHash':digest(actual['HostConfig']),'mountsHash':digest(sorted(actual['Mounts'],key=lambda v:v['Destination'])),'networkSettingsHash':digest(actual['NetworkSettings']),
        'profile':'ouf.acquisition-read.mount-set-binding.v1'}
CREATE_FIELDS=set('Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty OpenStdin StdinOnce Env Cmd Healthcheck Image Volumes WorkingDir Entrypoint Labels StopSignal StopTimeout'.split())
def config_copy(actual):
    config=actual['Config'];ignored=set(config)-CREATE_FIELDS
    require(all(config[k]in(None,False,0,'',[],{})for k in ignored),'NONDEFAULT_UNSUPPORTED_CONTAINER_CONFIG')
    return {k:copy.deepcopy(v)for k,v in config.items()if k in CREATE_FIELDS}
def network(actual,aliases):
    nets=actual['NetworkSettings']['Networks'];require(len(nets)==1,'ONE_RETAINED_ROLE_NETWORK_REQUIRED')
    name,value=next(iter(nets.items()));nid=value['NetworkID']
    require(re.fullmatch('[a-f0-9]{64}',nid)is not None and type(name)is str and name not in('host','none','bridge')and actual['HostConfig'].get('NetworkMode')in(name,nid),'BOUND_USER_DEFINED_ROLE_NETWORK_REQUIRED')
    require(all(type(v)is str and len(v)<=253 for v in aliases),'BOUNDED_NETWORK_ALIASES_REQUIRED')
    return {'name':name,'id':nid,'request':{'EndpointsConfig':{name:{'NetworkID':nid,'Aliases':list(dict.fromkeys(aliases))}}}}
def read_mounts(actual):
    mounts=[];targets=set()
    for m in actual['Mounts']:
        target=m['Destination'];require(target.startswith('/')and target not in targets and target!='/tmp','UNIQUE_READ_ONLY_MOUNT_TARGET_REQUIRED');targets.add(target)
        require(target not in('/proc','/sys','/dev')and not target.endswith('.sock')and not str(m.get('Source','')).endswith('.sock'),'NO_HOST_CONTROL_MOUNT_IN_READ_COMPONENT')
        row={'Type':m['Type'],'Target':target,'ReadOnly':True}
        if m['Type']=='bind':
            require(m['Source'].startswith('/'),'ABSOLUTE_EXISTING_BIND_REQUIRED');row.update(Source=m['Source'],BindOptions={'Propagation':m.get('Propagation')or'rprivate'})
        elif m['Type']=='volume':
            require(type(m.get('Name'))is str and m['Name'],'NAMED_EXISTING_VOLUME_REQUIRED');row.update(Source=m['Name'],VolumeOptions={'NoCopy':True})
        else:raise Stop('UNSUPPORTED_READ_COMPONENT_MOUNT_TYPE')
        mounts.append(row)
    return mounts

def read_component(role,actual,image,case_hash):
    require(role in('ingestion','udp'),'TWO_CLOSED_READ_ROLES_REQUIRED')
    name='ouf-'+role+'-evidence-read';old=config_copy(actual);ic=image['Config']
    require(old.get('User')in(ic['User'],ic['User'].split(':')[0]),'READ_COMPONENT_RETAINS_OWNER_UID_REQUIRED')
    entry=actual['Config'].get('Entrypoint')or[];args=actual['Config'].get('Cmd')or[]
    require(len(entry)>=3 and Path(entry[0]).name=='java'and entry.count('-jar')==1 and entry[-2]=='-jar','RETAINED_JAVA_JAR_LAUNCHER_REQUIRED')
    flags=entry[1:-2]
    require(all(type(v)is str and v.startswith(('-D','-X','-javaagent:','-agentlib:','-agentpath:','--add-opens=','--add-exports=','--enable-native-access='))for v in flags),'REVIEWED_RETAINED_JVM_FLAGS_REQUIRED')
    require(all(type(v)is str and v.startswith('--')and '\x00'not in v for v in args),'RETAINED_SPRING_APPLICATION_ARGUMENTS_REQUIRED')
    new_entry=[ic['Entrypoint'][0],*flags,*ic['Entrypoint'][1:]]
    old.update(Image=image['Id'],Entrypoint=new_entry,Cmd=copy.deepcopy(args)or None,Hostname=name,User=ic['User'],Labels={**(old.get('Labels')or{}),**(ic.get('Labels')or{}),'ouf.acquisition-read.case':case_hash,'ouf.component':'acquisition-evidence-read'})
    original=actual['HostConfig'];host=copy.deepcopy(original)
    require(not host.get('Privileged')and not host.get('Devices')and not host.get('DeviceRequests')and not host.get('CapAdd'),'NO_INHERITED_PRIVILEGED_READ_COMPONENT')
    for field in('Binds','VolumesFrom'):host[field]=None
    host.update(Mounts=read_mounts(actual),ReadonlyRootfs=True,CapAdd=None,CapDrop=['ALL'],SecurityOpt=['no-new-privileges:true'],PidsLimit=128,Memory=536870912,MemorySwap=536870912,Tmpfs={'/tmp':'rw,nosuid,noexec,size=64m'},PortBindings={},PublishAllPorts=False,AutoRemove=False,RestartPolicy={'Name':'no','MaximumRetryCount':0})
    net=network(actual,[name]);old.update(HostConfig=host,NetworkingConfig=net['request'])
    require(old['Env']==actual['Config']['Env'],'READ_COMPONENT_ENVIRONMENT_PRESERVED_REQUIRED')
    return {'name':name,'role':role,'request':old,'network':{'name':net['name'],'id':net['id']},'oldOwnerUnchanged':stable_binding(actual),'normalWorkloadIdentityAndPolicyTokenMountsInherited':True,'allExistingMountsReadOnly':True,'retainedJvmFlagsPreserved':True,'retainedApplicationArgumentsPreserved':True,'restartPolicyAfterVerifiedReadiness':{'Name':'unless-stopped','MaximumRetryCount':0}}
def mcp_replacement(actual,image,case_hash):
    e=env(actual['Config']);require(all(e.get(k)for k in('MCP_OIDC_TOKEN_ENDPOINT','MCP_OIDC_CLIENT_ID','MCP_OIDC_CLIENT_SECRET_FILE'))and not e.get('MCP_WORKLOAD_TOKEN')and not e.get('MCP_WORKLOAD_TOKEN_FILE'),'ONE_EXISTING_MCP_CLIENT_CREDENTIALS_SOURCE_REQUIRED')
    require(actual['Config'].get('Cmd')==['server'],'EXISTING_MCP_SERVER_MODE_REQUIRED')
    request=config_copy(actual);require(request.get('User')in(image['Config']['User'],image['Config']['User'].split(':')[0]),'MCP_OWNER_UID_PRESERVED_REQUIRED')
    request.update(Image=image['Id'],Entrypoint=image['Config']['Entrypoint'],Cmd=image['Config']['Cmd']);name=actual['Name'].removeprefix('/')
    require(type(request.get('Hostname'))is str and request['Hostname'],'EXPLICIT_RETAINED_MCP_HOSTNAME_REQUIRED')
    host=copy.deepcopy(actual['HostConfig']);restore=copy.deepcopy(host['RestartPolicy']);host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
    net_value=next(iter(actual['NetworkSettings']['Networks'].values()));net=network(actual,[name,*(net_value.get('Aliases')or[])])
    request.update(HostConfig=host,NetworkingConfig=net['request'])
    return {'name':name,'retiredName':name+'-retained-acquisition-read-'+case_hash[:12],'request':request,'network':{'name':net['name'],'id':net['id']},'oldBinding':stable_binding(actual),'restoreRestartPolicy':restore,'oldNativeHostConfig':actual['HostConfig'],'oldRetainedStopped':True,'oldMustBeStoppedAndDetachedBeforeNewStarts':True,'normalOAuthManagerCountAfterReplacement':1,'normalOAuthBootstrapMayOccur':True,'normalOAuthRequestsNotIssuedOrCountedByPlanner':True,'environmentAndExistingLabelsPreserved':request['Env']==actual['Config']['Env']and request.get('Labels')==actual['Config'].get('Labels')}

def source_capsule(package_root,receipt,root):
    raw=protected(package_root/'gateway/source.tar.gz',receipt['artifacts']['gateway']['fileHashes']['source.tar.gz'])
    import io
    selected={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz')as archive:
        members=archive.getmembers();require(len(members)<=3000,'SOURCE_CARDINALITY_BOUND')
        for name,wanted in SOURCE_HASHES.items():
            rows=[m for m in members if m.name==name];require(len(rows)==1 and rows[0].isfile()and rows[0].size<=2*1024*1024,'EXACT_REGULAR_COMPILER_SOURCE_REQUIRED')
            value=archive.extractfile(rows[0]).read(2*1024*1024+1);require(sha(value)==wanted,'QUALIFIED_COMPILER_SOURCE_HASH_REQUIRED');selected[name]=value
    capsule=root/'compiler';new_directory(capsule)
    for name,value in selected.items():
        target=capsule/name
        for parent in reversed(target.relative_to(capsule).parents):
            if str(parent)!='.'and not(capsule/parent).exists():new_directory(capsule/parent)
        put(target,value)
    require('tools'not in sys.modules,'ISOLATED_COMPILER_NAMESPACE_REQUIRED');package=types.ModuleType('tools');package.__path__=[str(capsule/'tools')];sys.modules['tools']=package
    loaded={}
    for name in('apply_installation_projection','materialize_acquisition_read','delegation_functions'):
        spec=importlib.util.spec_from_file_location('tools.'+name,capsule/'tools'/(name+'.py'));module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);loaded[name]=module
    return loaded

def literal_constants(route):
    functions=route.get('plugins',{}).get('serverless-post-function',{}).get('functions',[])
    require(len(functions)==1 and type(functions[0])is str,'ONE_RETAINED_MEDIATION_FUNCTION_REQUIRED')
    constants={}
    for key,value in re.findall(r'^local ([A-Z][A-Z0-9_]*) = ("(?:[^"\\]|\\.)*")\s*$',functions[0],re.MULTILINE):
        require(key not in constants,'UNIQUE_MEDIATION_CONSTANTS_REQUIRED');constants[key]=decode(value)
    return constants

def proposed_routes(routes,modules,projection,actual):
    require(type(routes)is list and 0<len(routes)<=256,'BOUNDED_CURRENT_ROUTE_LIST_REQUIRED')
    retained=[];ids=set()
    for entry in routes:
        row=entry.get('value',entry)
        if type(row)is dict and type(row.get('value'))is dict:row=row['value']
        require(type(row)is dict and type(row.get('id'))is str and re.fullmatch('[A-Za-z0-9._-]{1,128}',row['id'])and row['id']not in ids,'UNIQUE_CURRENT_GATEWAY_ROUTES_REQUIRED');ids.add(row['id']);retained.append({k:v for k,v in row.items()if k not in('create_time','update_time')})
    def route(uri):
        matches=[r for r in retained if r.get('uri')==uri];require(len(matches)==1,'ONE_RETAINED_BOUND_EXECUTE_ROUTE_REQUIRED');return matches[0]
    base=route('/internal/capabilities/v1/execute');ing=literal_constants(route('/internal/capabilities/v1/execute/ouf.ingestion.status'));udp=literal_constants(route('/internal/capabilities/v1/execute/urban.object.search'));common=literal_constants(base)
    runtime=modules['apply_installation_projection'].apply_projection(copy.deepcopy(RUNTIME_TEMPLATE),projection)
    installation=runtime['x-ouf-installation'];mcp_env=env(actual['mcp']['Config'])
    require(installation['mcpServiceIdentity']==mcp_env['MCP_OIDC_CLIENT_ID'],'CURRENT_MCP_AND_INSTALLATION_IDENTITY_REQUIRED')
    for constants in(common,ing,udp):
        require(constants.get('ISSUER')==installation['issuerUrl'].rstrip('/')and constants.get('AUDIENCE')==installation['gatewayAudience']and constants.get('MCP_WORKLOAD')==installation['mcpServiceIdentity'],'RETAINED_ROUTE_INSTALLATION_IDENTITY_REQUIRED')
        require(constants.get('DELEGATION_KEY_ENV')==common.get('DELEGATION_KEY_ENV'),'ONE_EXISTING_DELEGATION_KEY_REFERENCE_REQUIRED')
    keys=[common.get('DELEGATION_KEY_ENV'),ing.get('OWNER_KEY_ENV'),udp.get('OWNER_KEY_ENV')]
    gateway_env=env(actual['gateway']['Config']);require(all(type(k)is str and gateway_env.get(k)for k in keys),'EXISTING_GATEWAY_KEY_REFERENCES_REQUIRED')
    proposed=modules['materialize_acquisition_read'].materialize({'routes':retained},runtime,*keys)
    require(proposed['routes'][:-2]==retained,'ALL_EXISTING_ROUTES_PRESERVED_REQUIRED')
    return {'previousRoutes':retained,'previousRoutesHash':digest(retained),'proposedRoutesHash':digest(proposed['routes']),'newRoutes':proposed['routes'][-2:],'existingSigningKeyReferencesReused':True,'signingKeyValuesReadFromFiles':False,'installationProjectionHash':digest(projection)}

CHILD=r'''import http.client,json,os,signal,sys
signal.alarm(12)
try:
 raw=sys.stdin.buffer.read(8193)
 if not 0<len(raw)<=8192:raise ValueError()
 value=json.loads(raw)
 if set(value)!={'key'}or not isinstance(value['key'],str)or not 16<=len(value['key'])<=4096:raise ValueError()
 if len(sys.argv)!=2 or not sys.argv[1].isdigit():raise ValueError()
 fd=int(sys.argv[1]);os.setns(fd,0);os.close(fd)
 connection=http.client.HTTPConnection('127.0.0.1',9180,timeout=10)
 connection.request('GET','/apisix/admin/routes',headers={'X-API-KEY':value['key'],'Accept':'application/json','Connection':'close'})
 response=connection.getresponse();body=response.read(8388609)
 if response.status!=200 or len(body)>8388608:raise ValueError()
 sys.stdout.buffer.write(body);sys.stdout.buffer.flush();connection.close()
except BaseException:os._exit(1)
os._exit(0)
'''
def live_gateway_routes(actual,inputs,root,external_key_path=Path('/opt/ouf/secrets/apisix-admin-key')):
    mounts=[m for m in actual['gateway']['Mounts']if m.get('Destination')=='/usr/local/apisix/conf/config.yaml']
    require(len(mounts)==1 and mounts[0]['Type']=='bind'and mounts[0]['RW']is False,'EXACT_EXISTING_GATEWAY_CONFIG_BIND_REQUIRED')
    raw,config=private_config(mounts[0]['Source']);COUNTS['ownerConfigurationContentReads']+=1;key_binding=None
    try:key=selected_admin_key(raw)
    except Stop as error:
        if str(error)!='ONE_SELECTED_APISIX_ADMIN_CREDENTIAL_REQUIRED':raise
        COUNTS['serviceCredentialFilesOpened']+=1;key_raw,key_binding=private_config(str(external_key_path));key=selected_admin_key(raw,key_raw.decode('ascii').strip())
    require(hasattr(os,'setns')and COUNTS['gatewayAdminGetAttempts']==0,'ONE_INFRASTRUCTURE_NAMESPACE_GET_REQUIRED')
    pid=inputs['currentProcessPins']['gateway']['pid'];fd=os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY)
    try:
        value=os.fstat(fd);require([value.st_dev,value.st_ino]==inputs['currentProcessPins']['gateway']['namespaces']['net'],'BOUND_GATEWAY_NAMESPACE_FD_REQUIRED')
        put(root/'gateway-get-claim.json',{'path':'/apisix/admin/routes','method':'GET','attemptNotCompletion':True,'maximumAttempts':1,'namespaceProgramHash':sha(CHILD.encode())})
        COUNTS['gatewayAdminGetAttempts']+=1;COUNTS['networkNamespaceJoins']+=1
        result=subprocess.run([sys.executable,'-I','-S','-B','-c',CHILD,str(fd)],input=encoded({'key':key}),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,),timeout=15,cwd='/',env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        require(result.returncode==0 and 0<len(result.stdout)<=8388608,'ONE_GATEWAY_ROUTE_SNAPSHOT_UNPROVEN');put(root/'gateway-response.json',result.stdout)
        document=decode(result.stdout);rows=document.get('list')
        require(type(rows)is list,'APISIX_ROUTE_LIST_REQUIRED');return rows,{'configBinding':config,'adminKeyBinding':key_binding,'namespaceProgramHash':sha(CHILD.encode()),'routeSnapshotHash':sha(result.stdout)}
    finally:os.close(fd)

def prepare(inputs_path=INPUTS,inputs_hash=INPUTS_HASH,packages=PACKAGES,receipt_hash=RECEIPT_HASH,root=ROOT,case_hash=CASE_HASH,projection_path=PROJECTION,probe=live_gateway_routes,process_check=check_processes):
    require(os.geteuid()==os.getegid()==0,'ROOT_PLAN_PREPARATION_REQUIRED');ancestry(root.parent);require(not os.path.lexists(root),'NATIVE_PLAN_SCOPE_CONSUMED_NO_REPLAY');new_directory(root)
    put(root/'claim.json',{'schema':'ouf.acquisition-native-plan-claim.v1','caseHash':case_hash,'maximumEngineGets':0,'maximumAdminGets':1,'maximumServiceCredentialFiles':1,'maximumSeconds':90,'targetApplyAuthorized':False,'automaticReplayAllowed':False})
    inputs=decode(protected(inputs_path,inputs_hash));receipt=decode(protected(packages/'complete.json',receipt_hash))
    require(inputs['schema']=='ouf.acquisition-read-current-private-inputs.v1'and receipt['schema']=='ouf.acquisition-read-packages-staged.v1'and receipt['complete']is True and receipt['rootProtected']is True and receipt['caseHash']==case_hash and receipt['capturedInputsHash']==inputs_hash,'EXACT_STAGED_AND_CAPTURED_CONTEXT_REQUIRED')
    process_check(inputs);actual={}
    for role in('ingestion','udp','mcp','gateway','postgres'):
        ref=inputs['currentObservations'][role];value=decode(protected(Path(ref['path']),ref['sha256']));require(value['State']['Pid']==inputs['currentProcessPins'][role]['pid'],'SAME_CAPTURED_ROLE_CONFIGURATION_REQUIRED');env(value['Config']);actual[role]=value
    images={}
    for role in('ingestion','udp','mcp'):
        meta=receipt['artifacts'][role];name='image-config.json'if role=='mcp'else'acquisition-image-config.json';rows=decode(protected(packages/role/name,meta['fileHashes'][name]));require(type(rows)is list and len(rows)==1 and rows[0]['Id']==meta['imageId'],'EXACT_QUALIFIED_IMAGE_CONFIG_REQUIRED');images[role]=rows[0]
    modules=source_capsule(packages,receipt,root)
    raw,projection_binding=private_config(str(projection_path));COUNTS['ownerConfigurationContentReads']+=1;projection=decode(raw)
    reads={role:read_component(role,actual[role],images[role],case_hash)for role in('ingestion','udp')}
    replacement=mcp_replacement(actual['mcp'],images['mcp'],case_hash)
    mem=Path('/proc/meminfo').read_text();matches=re.findall(r'^MemAvailable:\s+([0-9]+) kB$',mem,re.MULTILINE);require(len(matches)==1,'CURRENT_CAPACITY_METADATA_REQUIRED');available=int(matches[0])*1024
    required=2*536870912+268435456;require(available>=required,'READ_COMPONENT_MEMORY_HEADROOM_REQUIRED')
    routes,gateway_binding=probe(actual,inputs,root);process_check(inputs)
    gateway=proposed_routes(routes,modules,projection,actual)
    gateway.update(transportBinding=gateway_binding,projectionBinding=projection_binding,oldGatewayBinding=stable_binding(actual['gateway']))
    plan={'schema':'ouf.acquisition-read-native-plan.v1','caseHash':case_hash,'capturedInputsHash':inputs_hash,'stagedReceiptHash':receipt_hash,'engineBinding':inputs['engineBinding'],'existingApplications':{role:stable_binding(value)for role,value in actual.items()},'readComponents':reads,'mcpReplacement':replacement,'gateway':gateway,
        'candidateArchives':{role:{'path':str(packages/role/'image.tar.gz'),'sha256':receipt['artifacts'][role]['fileHashes']['image.tar.gz'],'imageId':images[role]['Id'],'sourceCommit':receipt['artifacts'][role]['sourceCommit']}for role in images},
        'capacityAtPreparation':{'availableBytes':available,'requiredAdditionalReadBudgetBytes':1073741824,'reserveBytes':268435456,'freshAdmissionAtApplyRequired':True},'executionEntryQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False,'originalRegistryWorkerNotSelectedForAnyOperation':True,'newReadServicesCreateOAuthManager':False,'existingIngestionUdpAndPostgresRemainUnchanged':True,'currentEngineApiIdentityNotProvenByThisPlanner':True,'freshEngineAndConfigurationRevalidationRequiredBeforeApply':True,'normalMcpOAuthBootstrapMayOccurOnlyInFutureReviewedReplacement':True}
    protected(inputs_path,inputs_hash);protected(packages/'complete.json',receipt_hash);put(root/'execution-plan.json',plan)
    result={'schema':'ouf.acquisition-read-native-plan-prepared.v1','status':'ACQUISITION_READ_NATIVE_PLAN_PREPARED_NOT_AUTHORIZED','complete':True,'privatePlanPath':str(root/'execution-plan.json'),'privatePlanHash':digest(plan),'caseHash':case_hash,'readComponentsProposed':2,'mcpReplacementProposed':True,'parallelMcpManagerProposed':False,'gatewayRoutesProposed':2,'existingGatewayRoutesPreserved':True,'existingGatewayRouteCount':len(gateway['previousRoutes']),'gatewayLiveRoutesObserved':True,'capturedProcessPinsStillMatch':True,'currentRuntimeRevalidated':False,'configurationValuesPrinted':False,'configurationMayContainSensitiveValues':True,'credentialValuesPrinted':False,'addressesPrinted':False,'filePathsPrinted':False,**COUNTS,'maximumAdminGets':1,'countsAreThisPreparationOnly':True,'engineGetAttempts':0,'sqlSessions':0,'oauthRequests':0,'imageImports':0,'containerWrites':0,'databaseMigrations':0,'sourceActivations':0,'humanBudgetsGranted':0,'privateSigningKeysRead':0,'runtimeEffectsDispatched':0,'executionEntryQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationReadinessProven':False,'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
    put(root/'complete.json',result);return result

EXTERNAL_ADMIN_KEY = '/opt/ouf/secrets/apisix-admin-key'

_EXISTING_CONFIG_CUSTODY = {
    # These are the observed, already-running selections on this host. Do not
    # change ownership of /opt/ouf or the files mounted into live containers.
    '/opt/ouf/installation/active-projection.json': {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/installation': (0, 0, 0o700)},
        'file': (0, 0, 0o600)},
    '/opt/ouf/secrets/onboarding-ths.yaml': {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/secrets': (1000, 1000, 0o700)},
        'file': (10003, 10003, 0o400)},
    EXTERNAL_ADMIN_KEY: {
        'parents': {'/opt/ouf': (1000, 1000, 0o750),
                    '/opt/ouf/secrets': (1000, 1000, 0o700)},
        # 0600 does not grant group access. The observed uid/mode are fixed;
        # the actual gid is pinned by the returned file metadata.
        'file': (1000, None, 0o600)},
    '/etc/ouf/deploy-snapshots/consultation-human-read-20261002-1153/prepared/apisix-config.yaml': {
        'parents': {}, 'file': (636, 636, 0o400)},
}

def selected_directory_custody(info, path, exception):
    selected = exception['parents'].get(path) if exception else None
    if selected is not None:
        return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == selected
    return info.st_uid == 0 and not info.st_mode & 0o022

def selected_file_custody(info, exception):
    selected = exception['file'] if exception else None
    if selected is not None:
        uid,gid,mode=selected
        return info.st_uid==uid and (gid is None or info.st_gid==gid) and stat.S_IMODE(info.st_mode)==mode
    return info.st_uid == 0 and stat.S_IMODE(info.st_mode) in (0o400,0o440,0o444,0o600,0o640,0o644)

def private_config(path, expected=None):
    """Read an exact selected file with pinned, no-follow path custody.

    The three existing selections above have different named owners. All
    other paths, including newly staged APISIX config, retain root custody.
    """
    target = Path(path)
    require(target.is_absolute() and '..' not in target.parts, 'EXACT_APISIX_CONFIG_PATH_REQUIRED')
    exception = _EXISTING_CONFIG_CUSTODY.get(str(target))
    fds = []; ancestors = []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW); fds.append(parent)
        current = '/'
        for name in target.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(child); info = os.fstat(child)
            current = os.path.join(current, name)
            require(selected_directory_custody(info,current,exception),'APISIX_CONFIG_ANCESTRY_NOT_CUSTODIED')
            ancestors.append((parent,name,child,(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)))
            parent = child
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent); fds.append(fd)
        s = os.fstat(fd)
        pin = lambda v: (v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and 0 < s.st_size <= 1048576
                and selected_file_custody(s,exception),
                'ROOT_CONTROLLED_SELECTED_APISIX_CONFIG_REQUIRED')
        raw = b''
        while len(raw) <= 1048576:
            part = os.read(fd,65536)
            if not part: break
            raw += part
        require(len(raw) == s.st_size and pin(s) == pin(os.fstat(fd))
                == pin(os.stat(target.name, dir_fd=parent, follow_symlinks=False)), 'APISIX_CONFIG_READ_DRIFT')
        binding = {'path': str(target), 'sha256': hashlib.sha256(raw).hexdigest(), 'metadata': list(pin(s))}
        require(expected is None or binding == expected, 'APISIX_SELECTED_CONFIG_CHANGED')
        identity=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_gid,v.st_mode)
        for parent,name,child,seal in ancestors:
            require(seal == identity(os.fstat(child)) == identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'APISIX_CONFIG_ANCESTRY_CHANGED')
        return raw, binding
    finally:
        for fd in reversed(fds): os.close(fd)

def selected_admin_key(raw, external_key=None):
    # Closed scalar/list subset of the selected APISIX admin_key section only.
    # No YAML dependency, interpolation, aliases, tags or arbitrary configuration
    # execution in the isolated installer. Unsupported syntax requires review.
    lines = raw.decode('utf-8').splitlines()
    entries = [(i, len(line)-len(line.lstrip(' '))) for i,line in enumerate(lines)
               if re.fullmatch(r' *admin_key: *(?:#.*)?',line)]
    require(len(entries) == 1, 'ONE_LITERAL_ADMIN_KEY_SECTION_REQUIRED')
    start, indentation = entries[0]
    parents=[]
    for line in lines[:start]:
        if not line.strip() or line.lstrip().startswith('#'): continue
        match=re.fullmatch(r'( *)([A-Za-z_][A-Za-z0-9_]*): *(?:#.*)?',line)
        depth=len(line)-len(line.lstrip(' '))
        parents=[p for p in parents if p[0]<depth]
        if match: parents.append((depth,match[2]))
    require([p[1] for p in parents if p[0]<indentation] == ['deployment','admin'],
            'SELECTED_DEPLOYMENT_ADMIN_SECTION_REQUIRED')
    candidates=[]; row=None
    for line in lines[start+1:]:
        if not line.strip() or line.lstrip().startswith('#'): continue
        require('\t' not in line, 'LITERAL_ADMIN_KEY_INDENTATION_REQUIRED')
        depth=len(line)-len(line.lstrip(' '))
        if depth <= indentation: break
        match=re.fullmatch(r' +(- +)?(name|key|role): *(.*?) *',line)
        require(match is not None, 'UNSUPPORTED_ADMIN_KEY_SYNTAX')
        if match[1]:
            if row is not None: candidates.append(row)
            row={}
        require(row is not None and match[2] not in row, 'DUPLICATE_OR_UNBOUNDED_ADMIN_KEY_FIELD')
        value=match[3]
        if value.startswith('"'):
            value=json.loads(value)
        elif value.startswith("'"):
            require(len(value)>=2 and value.endswith("'"), 'ADMIN_KEY_SCALAR_INVALID')
            value=value[1:-1].replace("''", "'")
        else:
            value=value.split(' #',1)[0].strip()
        require(type(value) is str and re.fullmatch(r'[A-Za-z0-9._=+-]{1,4096}',value),
                'LITERAL_ADMIN_KEY_SCALAR_REQUIRED')
        row[match[2]]=value
    if row is not None: candidates.append(row)
    require(len(candidates)<=8 and all(set(r)=={'name','key','role'} for r in candidates),
            'CLOSED_ADMIN_CREDENTIAL_RECORD_REQUIRED')
    admin=[r for r in candidates if r.get('role') == 'admin']
    # The selected live config has a literal but empty admin_key section.
    # Its separate existing admin-key file was observed to authorize a GET.
    # No fallback is permitted for ambiguous/nonempty credential records.
    if not candidates and external_key is not None:
        key=external_key
    else:
        require(external_key is None and len(admin)==1,
                'ONE_SELECTED_APISIX_ADMIN_CREDENTIAL_REQUIRED')
        key=admin[0].get('key')
    require(type(key) is str and 16 <= len(key) <= 4096 and all(33 <= ord(c) <= 126 for c in key)
            and not key.startswith(('$ENV', '${', '$secret')), 'LITERAL_SELECTED_ADMIN_CREDENTIAL_REQUIRED')
    return key

RUNTIME_TEMPLATE={'routes': [{'id': 'acquisition-ingestion-read', 'labels': {'capability': 'ouf.ingestion.acquisition.read@1.0.0', 'exposure': 'internal', 'source': 'acquisition-ingestion-read@1.0.0'}, 'methods': ['POST'], 'plugins': {'limit-count': {'count': 100, 'rejected_code': 429, 'time_window': 60}, 'proxy-rewrite': {'uri': '/api/internal/v1/ingestion/operations/acquisition'}, 'request-id': {'algorithm': 'uuid', 'header_name': 'X-Correlation-ID', 'include_in_response': True}}, 'service_id': 'ouf-ingestion-evidence-read', 'upstream_id': 'acquisition-ingestion-read@1.0.0', 'uri': '/internal/capabilities/v1/execute/ouf.ingestion.acquisition.read', 'x-ouf-backend-binding': {'path': '/api/internal/v1/ingestion/operations/acquisition', 'port': 8080, 'service': 'ouf-ingestion-evidence-read'}, 'x-ouf-capability': {'capabilityId': 'ouf.ingestion.acquisition.read', 'humanRequired': False, 'operationType': 'READ', 'owner': 'ingestion', 'toolEligible': True, 'version': '1.0.0'}, 'x-ouf-policy': {'allowedActorTypes': ['HUMAN'], 'allowedServiceIdentities': ['installation://iam.workloadClients.mcpServer'], 'identity': 'M2M', 'maxRequestBytes': 65536, 'requiredScope': 'ingestion.lineage.read', 'timeoutSeconds': 12}, 'x-ouf-query-contract': {}, 'x-ouf-recovery-binding': None}, {'id': 'acquisition-udp-read', 'labels': {'capability': 'urban.acquisition.read@1.0.0', 'exposure': 'internal', 'source': 'acquisition-udp-read@1.0.0'}, 'methods': ['POST'], 'plugins': {'limit-count': {'count': 100, 'rejected_code': 429, 'time_window': 60}, 'proxy-rewrite': {'uri': '/api/udp/v1/operations/acquisition'}, 'request-id': {'algorithm': 'uuid', 'header_name': 'X-Correlation-ID', 'include_in_response': True}}, 'service_id': 'ouf-udp-evidence-read', 'upstream_id': 'acquisition-udp-read@1.0.0', 'uri': '/internal/capabilities/v1/execute/urban.acquisition.read', 'x-ouf-backend-binding': {'path': '/api/udp/v1/operations/acquisition', 'port': 8080, 'service': 'ouf-udp-evidence-read'}, 'x-ouf-capability': {'capabilityId': 'urban.acquisition.read', 'humanRequired': False, 'operationType': 'READ', 'owner': 'udp', 'toolEligible': True, 'version': '1.0.0'}, 'x-ouf-policy': {'allowedActorTypes': ['HUMAN'], 'allowedServiceIdentities': ['installation://iam.workloadClients.mcpServer'], 'identity': 'M2M', 'maxRequestBytes': 65536, 'requiredScope': 'lineage.object.read', 'timeoutSeconds': 12}, 'x-ouf-query-contract': {}, 'x-ouf-recovery-binding': None}]}
SOURCE_HASHES={'ouf-config/capabilities/ouf.ingestion.acquisition.read.yaml': '082b77b38899d70bd431bc21e95a5f9209a8ed1bbe7a9052f29bad8e3f7040c7', 'ouf-config/capabilities/urban.acquisition.read.yaml': '61207d07b825c66b14c06bf81ae9f9758b9ec1de121e2f8854d5795ea7f8f642', 'ouf-config/routes/northbound/acquisition-ingestion-read.yaml': '5c835980df6985f43e4f75b6d0070320f4e70fb394b33eac88756b3ab49f6c0d', 'ouf-config/routes/northbound/acquisition-udp-read.yaml': 'e4e9a77ba1a1d6d06956cdd046cc9f31b822f12006e4068a66bdae12602a0ec3', 'ouf-config/source-runtime/acquisition-ingestion-read.yaml': 'd19b377023c8402ae494783746f75aaafd6eed1c804aa1d873779497301219e9', 'ouf-config/source-runtime/acquisition-udp-read.yaml': 'f1faa28d374623dd24996a1dc6933de32f66ea05e3768785156e55c689789e30', 'schemas/mcp-gateway-status-dispatch-v1.json': 'c20e4e0db2283018cc319075c59dc2c7ebc65267b9b92e6448dfaaa37e8f2233', 'tools/apply_installation_projection.py': 'a68e480c1a75c2dd3b9dc811c95a4a5044f8d5beca2e3a0e5ac3d98c3eb73847', 'tools/delegation_functions.py': '43bc20e713a8daf990798f60e88b3e00d18fbcf1a4ad15b53c7fe5750a7f75e4', 'tools/lua/delegation.lua': 'a2286bd8e92a63ce9493730ee49850ffdecf95b74c3443764e67a194cd474dae', 'tools/lua/execute_acquisition_read.lua': '82c19d2c5587040960ebf15a1a4f03129e8833838a69f521f34b3b9fe4d66178', 'tools/materialize_acquisition_read.py': '4f7d5b75d7032fdfd0d007b8742222b326d8ac1a36ea98375d8ef28799720a4e'}


def main():
    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_PLAN_PREPARATION_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('FINITE_NATIVE_PLAN_PREPARATION_TIMEOUT')));signal.alarm(90)
        result=prepare();print(json.dumps(result,sort_keys=True,separators=(',',':')));return 0
    except Exception as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'ACQUISITION_NATIVE_PLAN_UNPROVEN'
        print(json.dumps({'schema':'ouf.acquisition-read-native-plan-prepared.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'privatePlanMayBePartial':True,**COUNTS,'engineGetAttempts':0,'sqlSessions':0,'oauthRequests':0,'containerWrites':0,'imageImports':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False},sort_keys=True,separators=(',',':')));return 2
    finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
