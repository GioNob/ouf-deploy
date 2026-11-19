#!/usr/bin/env python3
"""Bounded retained-generation startup diagnosis: no raw logs, config, credentials or mutations."""
import hashlib,ipaddress,json,re,subprocess,sys,traceback
from pathlib import Path

FORMAT='{"id":{{json .Id}},"image":{{json .Image}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},"state":{{json .State}},"restartPolicy":{{json .HostConfig.RestartPolicy}},"bindings":{{json .HostConfig.PortBindings}},"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}}}'
CANDIDATE_FORMAT='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},"bindings":{{json .HostConfig.PortBindings}},"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}}}'
KNOWN_EXCEPTIONS=set(('java.net.ConnectException','java.net.UnknownHostException','java.net.SocketTimeoutException',
 'java.sql.SQLException','java.lang.IllegalStateException','java.lang.IllegalArgumentException','java.io.FileNotFoundException',
 'java.nio.file.AccessDeniedException','java.lang.OutOfMemoryError','org.postgresql.util.PSQLException',
 'org.flywaydb.core.api.FlywayException','org.flywaydb.core.api.exception.FlywayValidateException',
 'org.springframework.beans.factory.BeanCreationException','org.springframework.beans.factory.UnsatisfiedDependencyException',
 'org.springframework.beans.factory.NoSuchBeanDefinitionException','org.springframework.beans.BeanInstantiationException',
 'org.springframework.context.ApplicationContextException','org.springframework.boot.web.server.WebServerException',
 'org.springframework.web.reactive.function.client.WebClientRequestException','com.zaxxer.hikari.pool.HikariPool$PoolInitializationException'))
def require(value,code):
    if not value:raise ValueError(code)
def invoke(args):
    reply=subprocess.run(['/usr/bin/docker',*args],stdin=subprocess.DEVNULL,capture_output=True,timeout=15,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_API_VERSION':'1.44'})
    require(reply.returncode==0,'ENGINE_READ_UNPROVEN')
    require(len(reply.stdout)<=262144 and len(reply.stderr)<=262144,'READ_OUTPUT_BOUND')
    return reply.stdout+reply.stderr if args[0]=='logs'else reply.stdout
def safe_state(value):
    state=value['state'];out={}
    require(state['Status']in ('created','running','paused','restarting','removing','exited','dead'),'STATE_SCHEMA')
    out['status']=state['Status']
    for key in ('Running','Paused','Restarting','OOMKilled','Dead'):
        require(type(state[key])is bool,'BOOLEAN_STATE_REQUIRED');out[key]=state[key]
    require(type(state['ExitCode'])is int and 0<=state['ExitCode']<=255,'EXIT_CODE_REQUIRED');out['exitCode']=state['ExitCode']
    for key in ('StartedAt','FinishedAt'):
        require(type(state[key])is str and re.fullmatch(r'[0-9TZ:.-]{1,48}',state[key]),'TIMESTAMP_REQUIRED');out[key]=state[key]
    error=state.get('Error','');require(type(error)is str,'ERROR_SCHEMA');out['engineErrorPresent']=bool(error)
    out['engineErrorMarkers']={name:bool(re.search(pattern,error,re.I))for name,pattern in {
        'missingMountSource':r'bind source path does not exist|no such file or directory',
        'mountTypeMismatch':r'not a directory|mount a directory onto a file|mount a file onto a directory',
        'portAlreadyAllocated':r'address already in use|port is already allocated|failed to bind host port',
        'networkSetupFailure':r'failed to set up container networking|failed programming external connectivity|network.*not found',
        'packetFilterFailure':r'iptables|nftables|ip6tables',
        'runtimeCreateFailure':r'OCI runtime create failed|failed to create task|failed to create shim',
        'permissionDenied':r'permission denied|operation not permitted',
        'readOnlyFilesystem':r'read-only file system'}.items()}
    policy=value['restartPolicy'];require(policy['Name']in ('no','always','on-failure','unless-stopped',''),'RESTART_POLICY_SCHEMA')
    out['restartPolicy']=policy['Name'];return out
def log_metadata(raw):
    require(type(raw)is bytes and len(raw)<=524288,'LOG_BOUND')
    text=raw.decode('utf-8',errors='replace')
    classes=sorted(set(re.findall(r'\b((?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*(?:Exception|Error))\b',text)))
    frames=re.findall(r'\bat ((?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*)\(([A-Za-z0-9_$]+\.java):([0-9]{1,6})\)',text)
    markers={name:bool(re.search(pattern,text,re.I))for name,pattern in {
        'connectionRefused':r'connection refused','connectionTimeout':r'connection timed out|connect timed out',
        'authenticationFailed':r'password authentication failed|authentication failed',
        'migrationChecksumMismatch':r'migration checksum mismatch','databaseUnavailable':r'unable to obtain connection|could not open jdbc connection',
        'readOnlyFilesystem':r'read-only file system','permissionDenied':r'permission denied',
        'certificateValidationFailure':r'PKIX path building failed|certificate_unknown|unable to find valid certification path'}.items()}
    return {'exceptionClasses':sorted(set(classes)&KNOWN_EXCEPTIONS),'otherExceptionClassCount':len(set(classes)-KNOWN_EXCEPTIONS),
        'stackFrameCount':len(frames),
        'markers':markers,'rawLogsPrinted':False,'exceptionMessagesPrinted':False}
def ports(value):
    result=[]
    for key,bindings in (value or {}).items():
        match=re.fullmatch(r'([0-9]{1,5})/(tcp|udp)',key);require(match is not None,'PORT_SCHEMA')
        for item in bindings or []:
            port=item['HostPort'];require(re.fullmatch('[0-9]{1,5}',port)is not None and 0<int(port)<=65535,'HOST_PORT_SCHEMA')
            address=item['HostIp'];require(address==''or str(ipaddress.ip_address(address))==address,'HOST_IP_SCHEMA')
            result.append({'hostIp':address,'hostPort':int(port),'protocol':match[2],'containerPort':int(match[1])})
    return result
def addresses(value,actual=False):
    result=[]
    for name,item in (value or {}).items():
        configured=item.get('IPAMConfig')or{}
        for field in ('IPv4Address','IPv6Address'):
            current=item.get('IPAddress'if field=='IPv4Address'else'GlobalIPv6Address')
            address=current if actual else configured.get(field)or current
            if address:
                require(str(ipaddress.ip_address(address))==address,'NETWORK_IP_SCHEMA')
                result.append((name,address))
    return result
def network_metadata(value):
    result=[]
    for name,item in (value or {}).items():
        configured=item.get('IPAMConfig')or{};row={'networkReferenceSha256':hashlib.sha256(name.encode()).hexdigest()}
        for label,raw in (('configuredIPv4',configured.get('IPv4Address')),('configuredIPv6',configured.get('IPv6Address')),
                          ('currentIPv4',item.get('IPAddress')),('currentIPv6',item.get('GlobalIPv6Address'))):
            require(not raw or str(ipaddress.ip_address(raw))==raw,'ADDRESS_SCHEMA');row[label]=raw or None
        result.append(row)
    return result
def network_conflicts(target,reference):
    wanted=ports(target.get('bindings'));target_ips=set(addresses(target.get('networks')))
    ids=[json.loads(line)for line in invoke(['ps','--no-trunc','--format','{{json .ID}}']).splitlines()if line]
    require(len(ids)<=64 and all(re.fullmatch('[a-f0-9]{64}',i)for i in ids),'RUNNING_ID_BOUND')
    matches=[]
    if ids:
        rows=invoke(['inspect','--type','container','--format',CANDIDATE_FORMAT,*ids]).splitlines()
        require(len(rows)==len(ids),'RUNNING_INSPECT_BOUND')
        for line in rows:
            value=json.loads(line);require(value['id']in ids,'RUNNING_GENERATION_SCHEMA')
            if value['id']==reference:continue
            live=ports(value.get('ports')or value.get('bindings'));overlap=[]
            for left in wanted:
                for right in live:
                    if left['protocol']==right['protocol']and left['hostPort']==right['hostPort']:
                        if left['hostIp']==right['hostIp']or left['hostIp']in ('','0.0.0.0','::')or right['hostIp']in ('','0.0.0.0','::'):
                            overlap.append({'hostPort':left['hostPort'],'protocol':left['protocol']})
            ip_overlap=target_ips&set(addresses(value.get('networks'),actual=True))
            configured_overlap=target_ips&set(addresses(value.get('networks')))
            if overlap or ip_overlap or configured_overlap:
                revision=value.get('revision');require(revision is None or re.fullmatch('[a-f0-9]{40}',revision),'REVISION_SCHEMA')
                name=value.get('name');require(name is None or re.fullmatch(r'/[A-Za-z0-9_.-]{1,128}',name),'CONTAINER_NAME_SCHEMA')
                matches.append({'containerId':value['id'],'containerName':name,'imageId':value['image'],'sourceCommit':revision,
                    'possibleHostPortOverlaps':overlap,'networkAddressOverlapCount':len(ip_overlap),
                    'configuredAddressOverlapCount':len(configured_overlap),'networks':network_metadata(value.get('networks'))})
    listeners=[];listener_available=False
    try:
        result=subprocess.run(['/usr/bin/ss','-H','-ltn'],stdin=subprocess.DEVNULL,capture_output=True,timeout=5,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        if result.returncode==0 and len(result.stdout)<=131072:
            listener_available=True
            for line in result.stdout.decode().splitlines():
                fields=line.split()
                if len(fields)>=5:
                    _,separator,port=fields[3].rpartition(':')
                    if separator and port.isdigit()and any(v['protocol']=='tcp'and v['hostPort']==int(port)for v in wanted):
                        listeners.append({'hostPort':int(port),'protocol':'tcp'})
    except (FileNotFoundError,subprocess.TimeoutExpired):pass
    return {'targetBindings':wanted,'targetNetworks':network_metadata(target.get('networks')),'runningContainersRead':len(ids),'candidateConflicts':matches,
        'kernelListenerReadAvailable':listener_available,'matchingKernelListeners':listeners,
        'ownerStopOrRestartPerformed':False,'rawEngineErrorPrinted':False}
def collect(selection):
    target=selection['currentApplications']['udp'];reference=target['containerId'];require(re.fullmatch('[a-f0-9]{64}',reference),'EXACT_REFERENCE')
    def inspect():
        value=json.loads(invoke(['inspect','--type','container','--format',FORMAT,reference]))
        require(value['id']==reference and value['image']==target['imageId']and value['revision']==target['sourceCommit'],'GENERATION_CHANGED')
        return value
    before=inspect();state=safe_state(before)
    metadata=log_metadata(invoke(['logs','--tail','160','--since',state['StartedAt'],reference]))
    network=network_conflicts(before,reference)if(state['engineErrorMarkers']['networkSetupFailure']or state['engineErrorMarkers']['portAlreadyAllocated'])else None
    after=inspect();require(safe_state(after)==state,'PROCESS_CHANGED_DURING_READ')
    return {'schema':'ouf.retained-udp-startup-read.v1','complete':True,'generationMatches':True,
        'sourceCommit':target['sourceCommit'],'state':state,'startup':metadata,'network':network,'runtimeMutations':0,
        'jobsRetried':0,'profilePublications':0,'databaseCalls':0,'credentialFilesRead':0,'credentialValuesPrinted':False,
        'automaticRetry':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
    try:
        require(len(sys.argv)==2,'ONE_SELECTION_REQUIRED');result=collect(json.loads(Path(sys.argv[1]).read_bytes()))
    except Exception as error:
        result={'schema':'ouf.retained-udp-startup-read.v1','complete':False,'errorClass':type(error).__name__,
            'exceptionMessagePrinted':False,'runtimeMutations':0,
            'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-4:]]}
    print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
