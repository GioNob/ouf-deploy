#!/usr/bin/env python3
"""One new bounded, read-only input capture for acquisition evidence delivery.

Retained IDs are references only: no historical executor, image, SQL session,
grant, authority or retry budget is reused. Sensitive Engine responses stay root-private.
"""
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import sys

SEED=Path('/etc/ouf/deploy-snapshots/onboarding-finite-session-ee8b7756f72f82a6/input-preparation-v1/inputs.json')
SEED_HASH='b8040ef1c49af2455d9a28d26bac4ef4bbf297315c69c0b48256aa83f18b614b'
ROOT=Path('/etc/ouf/deploy-snapshots/acquisition-evidence-current-inputs-v1')
ROLES=('ingestion','udp','mcp','gateway','postgres')
MAXIMUM_GETS=10
PROGRESS={'engineGetAttempts':0,'privateMetadataReadPasses':0}

class Stop(RuntimeError):pass
def require(ok,reason):
    if not ok:raise Stop(reason)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(value):return hashlib.sha256(value).hexdigest()
def unique(pairs):
    out={}
    for key,value in pairs:
        require(key not in out,'DUPLICATE_METADATA_KEY');out[key]=value
    return out
def decode(value):return json.loads(value,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(Stop('NONFINITE_METADATA')))
def frame(s):return(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

@contextlib.contextmanager
def protected(path):
    path=Path(path);require(path.is_absolute()and'..'not in path.parts,'ABSOLUTE_CUSTODIED_PATH_REQUIRED')
    fds=[];pins=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        for part in path.parts[1:-1]:
            require(os.fstat(fd).st_uid==0 and not os.fstat(fd).st_mode&0o022,'ROOT_ANCESTRY_REQUIRED')
            parent=fd;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(fd)
            pins.append((parent,part,fd,frame(os.fstat(fd))[:5]))
        require(os.fstat(fd).st_uid==0 and not os.fstat(fd).st_mode&0o022,'ROOT_ANCESTRY_REQUIRED')
        leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);fds.append(leaf);before=os.fstat(leaf)
        require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1
                and stat.S_IMODE(before.st_mode)in(0o400,0o600)and 0<before.st_size<=8*1024*1024,'PROTECTED_BOUNDED_METADATA_REQUIRED')
        yield leaf,before
        require(frame(before)==frame(os.fstat(leaf))==frame(os.stat(path.name,dir_fd=fd,follow_symlinks=False)),'METADATA_CHANGED_DURING_READ')
        for parent,name,child,pin in pins:require(pin==frame(os.fstat(child))[:5]==frame(os.stat(name,dir_fd=parent,follow_symlinks=False))[:5],'ANCESTRY_CHANGED_DURING_READ')
    finally:
        for fd in reversed(fds):os.close(fd)

def read_seed(path,expected):
    with protected(path)as(fd,s):
        raw=os.read(fd,s.st_size+1);require(len(raw)==s.st_size and sha(raw)==expected,'EXACT_RETAINED_INPUT_REFERENCE_REQUIRED')
        PROGRESS['privateMetadataReadPasses']+=1
        return decode(raw)
def new_file(root,name,value):
    require(re.fullmatch('[a-zA-Z0-9_.-]{1,100}',name)is not None,'CLOSED_EVIDENCE_NAME_REQUIRED')
    raw=value if isinstance(value,bytes)else encoded(value)
    require(len(raw)<=8*1024*1024,'EVIDENCE_SIZE_BOUND')
    parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        s=os.fstat(parent);require(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'PRIVATE_SCOPE_REQUIRED')
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=parent)
        try:
            with os.fdopen(os.dup(fd),'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
        finally:os.close(fd)
        os.fsync(parent)
    finally:os.close(parent)

def socket_binding(path):
    path=Path(path);require(path.is_absolute()and str(path.resolve())==str(path),'CANONICAL_ENGINE_SOCKET_REQUIRED')
    for parent in reversed(path.parents):
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_SOCKET_ANCESTRY_REQUIRED')
    s=path.lstat();require(stat.S_ISSOCK(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)in(0o600,0o660),'ROOT_ENGINE_SOCKET_REQUIRED')
    return[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]

class Engine:
    def __init__(self,path,ids,root):
        require(len(ids)==5 and all(re.fullmatch('[a-f0-9]{64}',v)for v in ids),'FIVE_DISTINCT_REFERENCE_IDS_REQUIRED')
        self.path,self.ids,self.root,self.calls,self.peer=path,ids,root,0,None
        self.binding=socket_binding(path)
    def get(self,cid):
        require(cid in self.ids and self.calls<MAXIMUM_GETS,'TEN_SELECTED_ENGINE_GETS_ONLY')
        require(socket_binding(self.path)==self.binding,'CURRENT_ENGINE_SOCKET_CHANGED')
        self.calls+=1;PROGRESS['engineGetAttempts']=self.calls
        new_file(self.root,'attempt-%02d.json'%self.calls,{'method':'GET','containerId':cid,'attemptNotCompletion':True})
        selected=self.path;outer=self
        class Local(http.client.HTTPConnection):
            def connect(connection):
                connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.sock.settimeout(4);connection.sock.connect(selected)
                peer=struct.unpack('3i',connection.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                require(peer[1]==0,'ROOT_ENGINE_PEER_REQUIRED')
                require(outer.peer is None or outer.peer==peer,'ENGINE_PEER_CHANGED');outer.peer=peer
        connection=Local('local-custodied-engine',timeout=4)
        try:
            connection.request('GET','/v1.44/containers/'+cid+'/json',headers={'Connection':'close'})
            response=connection.getresponse();raw=response.read(1048577)
            name='response-%02d.json'%self.calls;new_file(self.root,name,raw)
            new_file(self.root,'response-status-%02d.json'%self.calls,{'httpStatus':response.status,'retainedBytes':len(raw),'mayBeTruncated':len(raw)>1048576})
            require(response.status==200 and 0<len(raw)<=1048576,'BOUNDED_ENGINE_RESPONSE_REQUIRED')
            require(socket_binding(self.path)==self.binding,'CURRENT_ENGINE_SOCKET_CHANGED')
            value=decode(raw);require(isinstance(value,dict)and value.get('Id')==cid,'SELECTED_CONTAINER_SUBSTITUTED')
            return value,{'path':str(self.root/name),'sha256':sha(raw)}
        finally:connection.close()

def process(value):
    s=value['State'];pid=s['Pid']
    require(s['Running']is True and not any(s.get(k)for k in('Paused','Restarting','Dead','OOMKilled'))and not s.get('Error')and type(pid)is int and pid>1,'RUNNING_STABLE_ROLE_REQUIRED')
    raw=Path('/proc/'+str(pid)+'/stat').read_bytes();require(len(raw)<=16384 and b') 'in raw,'BOUNDED_PROCESS_IDENTITY_REQUIRED')
    ticks=int(raw.rsplit(b') ',1)[1].split()[19]);namespaces={}
    for name in('net','mnt'):
        ns=Path('/proc/'+str(pid)+'/ns/'+name).stat();namespaces[name]=[ns.st_dev,ns.st_ino]
    return {'pid':pid,'startTicks':ticks,'namespaces':namespaces}
def stable(value):
    s=value['State']
    return {k:value[k]for k in('Id','Image','Config','HostConfig','Mounts','NetworkSettings','RestartCount')}|{'state':{k:s.get(k)for k in('Running','Pid','StartedAt','Paused','Restarting','Dead','OOMKilled','Error')}}
def hints(value):
    entries=value['Config'].get('Env')or[];env={}
    for entry in entries:
        require(isinstance(entry,str)and'='in entry,'TYPED_ENGINE_ENVIRONMENT_REQUIRED')
        key,val=entry.split('=',1);env.setdefault(key,[]).append(val)
    present=lambda key:any(bool(v)for v in env.get(key,[]))
    return {'clientCredentialsDeclared':all(present(k)for k in('MCP_OIDC_TOKEN_ENDPOINT','MCP_OIDC_CLIENT_ID','MCP_OIDC_CLIENT_SECRET_FILE')),
        'staticWorkloadBearerDeclared':present('MCP_WORKLOAD_TOKEN'),'workloadTokenFileDeclared':present('MCP_WORKLOAD_TOKEN_FILE'),
        'multipleAuthenticationDeclarations':sum((all(present(k)for k in('MCP_OIDC_TOKEN_ENDPOINT','MCP_OIDC_CLIENT_ID','MCP_OIDC_CLIENT_SECRET_FILE')),present('MCP_WORKLOAD_TOKEN'),present('MCP_WORKLOAD_TOKEN_FILE')))>1,
        'duplicateEnvironmentNames':any(len(values)>1 for values in env.values()),
        'additionalConfigurationChannelsPresent':{k:present(k)for k in('SPRING_APPLICATION_JSON','SPRING_CONFIG_ADDITIONAL_LOCATION','JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS','_JAVA_OPTIONS')},
        'effectiveConfigurationNotResolvedByThisReader':True}

def capture(root=ROOT,seed_path=SEED,seed_hash=SEED_HASH):
    require(os.geteuid()==os.getegid()==0,'ROOT_CAPTURE_REQUIRED')
    root=Path(root);require(root.is_absolute()and not os.path.lexists(root),'INPUT_SCOPE_ALREADY_CONSUMED_NO_REPLAY')
    for p in(root.parent,*root.parent.parents):
        s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_SCOPE_ANCESTRY_REQUIRED')
    root.mkdir(mode=0o700)
    new_file(root,'claim.json',{'schema':'ouf.acquisition-input-claim.v1','maximumEngineGets':10,'maximumSeconds':90,
        'purpose':'NEW_OWNER_READ_DELIVERY_INPUTS_NOT_ONBOARDING_OR_RUNTIME_AUTHORITY','automaticReplayAllowed':False,'budgetReset':False})
    seed=read_seed(seed_path,seed_hash)
    require(seed.get('schema')=='ouf.onboarding-finite-session-private-inputs.v1','EXACT_REFERENCE_SCHEMA_REQUIRED')
    pins={role:seed['currentBindings'][role]['containerId']for role in ROLES}
    selected=Path(seed['engineBinding']['socketPath']).resolve(strict=True)
    engine=Engine(str(selected),set(pins.values()),root);boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    first={};processes={};observations={}
    for role,cid in pins.items():
        value,receipt=engine.get(cid);processes[role]=process(value);first[role]=value;observations[role]=receipt
    for role,cid in pins.items():
        value,_=engine.get(cid)
        require(stable(value)==stable(first[role])and process(value)==processes[role],'CURRENT_OWNER_COHORT_CHANGED_DURING_READ')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==boot,'HOST_BOOT_CHANGED')
    read_seed(seed_path,seed_hash)
    historical={}
    for role,value in first.items():
        old=seed['currentBindings'][role];now={'containerId':value['Id'],'imageId':value['Image'],'pid':value['State']['Pid'],'startedAt':value['State']['StartedAt']}
        historical[role]={'comparedFields':list(now),'changedFields':[k for k in now if old.get(k)!=now[k]],'metadataComparisonIsNotLifecycleAuthority':True}
    data={'schema':'ouf.acquisition-read-current-private-inputs.v1','kind':'INPUTS_NOT_EXECUTABLE_AUTHORITY','bootId':boot,
        'referenceSeed':{'path':str(seed_path),'sha256':seed_hash,'idsOnlyNotCandidateOrAuthorityReuse':True},
        'engineBinding':{'socketPath':str(selected),'socketBinding':engine.binding,'peerCredentials':list(engine.peer)},
        'currentObservations':observations,'currentProcessPins':processes,'currentStableHashes':{role:sha(encoded(stable(value)))for role,value in first.items()},
        'historicalComparison':historical,'authenticationDeclarations':{role:hints(value)for role,value in first.items()if role in('mcp','ingestion','udp')},
        'lifecycleDeclarations':{role:('COMPOSE_LABELS_ONLY'if'com.docker.compose.project'in(value['Config'].get('Labels')or{})else'KUBERNETES_LABELS_ONLY'if any(k.startswith('io.kubernetes.')for k in(value['Config'].get('Labels')or{}))else'NO_RECOGNIZED_MANAGER_LABEL')for role,value in first.items()},
        'readOnlyRuntime':True,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}
    new_file(root,'inputs.json',data)
    result={'schema':'ouf.acquisition-read-current-inputs-result.v1','status':'CURRENT_ACQUISITION_READ_OWNER_INPUTS_CAPTURED','complete':True,
        'privateInputsPath':str(root/'inputs.json'),'privateInputsHash':sha(encoded(data)),'currentSelectedRoles':list(ROLES),
        'engineGetAttempts':engine.calls,'maximumEngineGets':10,'maximumSeconds':90,'privateMetadataReadPasses':PROGRESS['privateMetadataReadPasses'],
        'currentCohortStable':True,'currentProcessPinsObserved':True,'rootEnginePeerObserved':True,
        'currentSocketMatchesRetainedSeed':engine.binding==seed['engineBinding']['socketBinding'],'historicalComparison':historical,
        'mcpAuthenticationDeclaration':data['authenticationDeclarations']['mcp'],
        'newBindingAcceptedForRuntime':False,'engineApiIdentityProvenByThisReader':False,'effectiveConfigurationPrecedenceResolved':False,
        'lifecycleDeclarations':data['lifecycleDeclarations'],'lifecycleOwnershipProven':False,'sourceImageProvenanceVerified':False,
        'serviceCredentialFilesOpened':0,'bearerFilesOpened':0,'privateSigningKeysRead':0,'sqlSessions':0,'oauthRequests':0,'httpApplicationRequests':0,
        'engineConfigurationRetainedPrivately':True,'engineConfigurationMayContainSensitiveValues':True,'environmentValuesPrinted':False,'addressesPrinted':False,'credentialValuesPrinted':False,
        'imageImports':0,'containerWrites':0,'sourceActivations':0,'humanBudgetsGranted':0,'databaseMigrations':0,'retainedContextWrites':0,
        'runtimeEffectsDispatched':0,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,
        'privateEvidenceWrites':True,'readOnlyRuntime':True,'applicationReadinessProven':False,'applicationE2EProven':False,'releaseAcceptance':False}
    new_file(root,'complete.json',result);return result

def main():
    try:
        require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ONE_ISOLATED_ROOT_CAPTURE_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('FINITE_INPUT_CAPTURE_TIMEOUT')));signal.alarm(90)
        result=capture();print(json.dumps(result,sort_keys=True,separators=(',',':')));return 0
    except Exception as failure:
        reason=str(failure)if isinstance(failure,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(failure))else'ACQUISITION_INPUT_CAPTURE_UNPROVEN'
        print(json.dumps({'schema':'ouf.acquisition-read-current-inputs-result.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,**PROGRESS,'attemptsAreThisInvocation':True,'privateObservationMayBePartial':True,
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False},sort_keys=True,separators=(',',':')));return 2
    finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
