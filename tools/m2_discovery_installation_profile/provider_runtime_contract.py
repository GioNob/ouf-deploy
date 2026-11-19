"""Closed read-only target fact collection; never executes a runtime or broker.

Standalone stdlib delivery. Historical input1868 is provenance only. Current
Engine selection names the one wrapper/configuration; no directory discovery,
credential/key binding traversal, imported target code, signing or lifecycle.
"""
import contextlib,hashlib,http.client,json,os,re,signal,socket,stat,struct,sys,time
from pathlib import Path

INPUT_ROOT=Path('/etc/ouf/deploy-snapshots/m2-stopped-provider-inputs-84184832-20261029-v1')
INPUT_HASH='1868b57c9fbbb3f05b6f8b2eedeb2f1afe14c0ad4cf15cc7f3e039bbedd6d083'
RESULT_HASH='e77ca61c395594ae2837961ca14c44afbed560dc0d3b72bbf84f02504b708ed3'
PROVIDER='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
IMAGE='sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366'
SCOPE=Path('/etc/ouf/deploy-snapshots/m2-provider-runtime-contract-1868-20261029-v1')
FLAGS={k:False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','historicalAuthorityReused',
    'automaticReplayAllowed','budgetReset','providerAdmissionProven','applicationE2EProven','releaseAcceptance')}
ADAPTERS=tuple('ouf.semantic-docker-runtime-adapter.v'+str(i) for i in range(1,5))

class Stop(ValueError):pass
def require(ok,reason):
    if not ok:raise Stop(reason)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(value):return sha(encoded(value))
def decode(raw):
    def pairs(items):
        value=dict(items);require(len(value)==len(items),'DUPLICATE_RUNTIME_CONTRACT_METADATA_KEY');return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:require(False,'NONFINITE_METADATA'))
def exact_path(value):
    require(type(value) is str and re.fullmatch(r'/[A-Za-z0-9_./-]+',value) and
        str(Path(value))==value and '..' not in Path(value).parts,'CLOSED_ABSOLUTE_METADATA_PATH_REQUIRED')
    return Path(value)
def identity(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]

@contextlib.contextmanager
def directory(path):
    path=exact_path(str(path));fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for name in path.parts[1:]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child;s=os.fstat(fd)
            require(s.st_uid==s.st_gid==0 and not stat.S_IMODE(s.st_mode)&0o022,'ROOT_METADATA_ANCESTRY_REQUIRED')
        yield fd
    finally:os.close(fd)

class Capture:
    def __init__(self,scope):
        require(os.geteuid()==0,'ROOT_RUNTIME_CONTRACT_READER_REQUIRED')
        self.scope=exact_path(str(scope));self.until=time.monotonic()+90;self.seals={}
        self.counts={'metadataReads':0,'engineGets':0,'bytes':0,'credentialFileReads':0,'privateKeyReads':0,
            'engineWrites':0,'containerLifecycleOperations':0,'signaturesIssued':0}
        with directory(self.scope.parent) as parent:
            require(not os.path.lexists(self.scope),'RUNTIME_CONTRACT_SCOPE_CONSUMED_NO_REPLAY')
            os.mkdir(self.scope.name,0o700,dir_fd=parent);os.fsync(parent)
        self.put('capture.claim.json',{'schema':'ouf.m2-provider-runtime-contract-claim.v1',**FLAGS})
    def guard(self):require(time.monotonic()<self.until,'RUNTIME_CONTRACT_READ_DEADLINE')
    def account(self,size):
        self.counts['bytes']+=size;self.guard()
        require(self.counts['bytes']<=16777216,'RUNTIME_CONTRACT_READ_BYTE_BUDGET')
    def put(self,name,value):
        require(re.fullmatch(r'[a-z0-9.-]+',name),'CLOSED_AUDIT_NAME_REQUIRED')
        with directory(self.scope) as parent:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
            try:
                raw=encoded(value);require(len(raw)<=131072,'BOUNDED_MINIMIZED_RESULT_REQUIRED')
                with os.fdopen(fd,'wb',closefd=False) as out:out.write(raw);out.flush();os.fsync(fd)
            finally:os.close(fd)
            os.fsync(parent)
    def read(self,path,mode=0o600,limit=131072):
        self.guard();path=exact_path(str(path));require(self.counts['metadataReads']<18,'RUNTIME_METADATA_READ_COUNT_BUDGET')
        self.counts['metadataReads']+=1
        with directory(path.parent) as parent:
            fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            try:
                before=os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
                    and stat.S_IMODE(before.st_mode)==mode and before.st_size<=limit,'PRIVATE_RUNTIME_METADATA_CUSTODY_REQUIRED')
                raw=b''
                while len(raw)<=limit:
                    part=os.read(fd,min(65536,limit+1-len(raw)))
                    if not part:break
                    raw+=part;self.guard()
                self.account(len(raw));pin=identity(before)
                require(len(raw)==before.st_size and pin==identity(os.fstat(fd))==identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),
                    'RUNTIME_METADATA_CHANGED_DURING_READ')
                value={'identity':pin,'sha256':sha(raw),'mode':mode,'limit':limit}
                require(str(path) not in self.seals or self.seals[str(path)]==value,'RUNTIME_METADATA_SOURCE_DRIFT')
                self.seals[str(path)]=value;return raw
            finally:os.close(fd)
    def metadata(self,path,expected=None,canonical=False):
        raw=self.read(path,limit=2097152 if canonical else 131072);value=decode(raw)
        require(type(value) is dict and (expected is None or (digest(value) if canonical else sha(raw))==expected),
            'EXACT_RUNTIME_METADATA_HASH_REQUIRED')
        return value
    def recheck(self):
        for name,pin in list(self.seals.items()):self.read(name,pin['mode'],pin['limit'])

class Engine:
    def __init__(self,capture,binding,cid):
        require(type(binding) is dict and set(binding)=={'socketPath','socketBinding','peerCredentials'}
            and re.fullmatch('[0-9a-f]{64}',cid),'EXACT_RUNTIME_CONTRACT_ENGINE_BINDING_REQUIRED')
        self.c,self.binding,self.cid=capture,binding,cid
    def get(self,path):
        c=self.c;c.guard();require(path in ('/v1.44/info','/v1.44/containers/'+self.cid+'/json') and c.counts['engineGets']<4,
            'CLOSED_RUNTIME_CONTRACT_ENGINE_GET_REQUIRED')
        selected=exact_path(self.binding['socketPath'])
        with directory(selected.parent) as parent:
            s=os.stat(selected.name,dir_fd=parent,follow_symlinks=False)
            require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0 and
                [s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]==self.binding['socketBinding'],'RUNTIME_ENGINE_SOCKET_DRIFT')
        c.counts['engineGets']+=1;c.put('engine-get-'+str(c.counts['engineGets'])+'-claim.json',{'method':'GET','path':path})
        binding=self.binding
        class Local(http.client.HTTPConnection):
            def connect(conn):
                conn.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);conn.sock.settimeout(min(4,c.until-time.monotonic()))
                conn.sock.connect(str(selected));peer=list(struct.unpack('3i',conn.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
                require(peer==binding['peerCredentials'] and peer[1]==peer[2]==0,'RUNTIME_ENGINE_PEER_CREDENTIAL_DRIFT')
        conn=Local('root-local-engine')
        try:
            conn.request('GET',path,headers={'Connection':'close'});response=conn.getresponse();raw=response.read(2097153);c.account(len(raw))
            require(response.status==200 and 0<len(raw)<=2097152,'BOUNDED_RUNTIME_ENGINE_READ_REQUIRED')
            value=decode(raw);require(type(value) is dict,'ENGINE_METADATA_OBJECT_REQUIRED');return value
        finally:conn.close()

def provider_binding(value):
    return {k:value[k] for k in ('Id','Image','Config','HostConfig','Mounts')}|{
        'state':{k:value['State'][k] for k in ('Pid','Running','Paused','Restarting','StartedAt')}}

def engine_binding(value):
    # /info includes volatile SystemTime and host counters; only compare the
    # selected engine/runtime contract, never mistake a new timestamp for drift.
    return {k:value[k] for k in ('ID','ServerVersion','Driver','CgroupDriver','DockerRootDir','Runtimes')}

def named_contract(c,info,provider,*,configuration_root=Path('/etc/ouf'),wrapper_root=Path('/usr/local/sbin')):
    """Follow only exact named, hash-bound metadata roles, never key bindings."""
    name=provider['HostConfig'].get('Runtime');runtimes=info.get('Runtimes',{})
    if name in ('','runc','io.containerd.runc.v2',None):
        return {'classification':'NO_NAMED_PROVIDER_ADAPTER','runtimeContractBound':False}
    require(type(name) is str and name in runtimes and type(runtimes[name]) is dict,'EXPLICIT_REGISTERED_PROVIDER_RUNTIME_REQUIRED')
    wrapper=exact_path(runtimes[name]['path'])
    require(wrapper.parent==wrapper_root and wrapper.name.startswith('ouf-'),'NAMED_OUF_WRAPPER_PATH_REQUIRED')
    raw=c.read(wrapper,0o755,65536)
    match=re.fullmatch(rb'#!/bin/sh\nexec (/[A-Za-z0-9_./-]+) -I -B (/[A-Za-z0-9_./-]+/scripts/semantic_provider_docker_runtime.py) --configuration (/[A-Za-z0-9_./-]+) "\$@"\n',raw)
    require(match is not None,'CLOSED_REVIEWED_RUNTIME_WRAPPER_REQUIRED')
    python,source,configuration=[exact_path(x.decode('ascii')) for x in match.groups()]
    require(configuration.is_relative_to(configuration_root) and configuration!=configuration_root,
        'PROVIDER_RUNTIME_CONFIGURATION_OUTSIDE_REVIEWED_ROOT')
    cfg=c.metadata(configuration)
    require(cfg.get('schema') in ADAPTERS and cfg.get('pythonPath')==str(python),'SUPPORTED_NAMED_RUNTIME_METADATA_REQUIRED')
    require(sha(c.read(source))==cfg['sourceHash'],'CURRENT_RUNTIME_ADAPTER_SOURCE_DRIFT')
    source_root=source.parent.parent;registry=exact_path(cfg['registryRoot'])
    require(registry.is_relative_to(configuration_root) and source_root.is_relative_to(configuration_root)
        and cfg['driverPath']==str(source_root/'scripts/semantic_provider_preexec_hook.py')
        and cfg['admissionPath']==str(source_root/'scripts/semantic_provider_deployment_broker.py'),
        'CLOSED_PROVIDER_RUNTIME_SOURCE_AND_REGISTRY_ROOTS_REQUIRED')
    summary={'classification':'BOUND_NAMED_RUNTIME_NO_RETAINED_PROVIDER_ENTRY','runtimeContractBound':True,
        'adapterSchema':cfg['schema'],'adapterConfigurationHash':c.seals[str(configuration)]['sha256'],
        'adapterSourceHash':cfg['sourceHash'],'wrapperHash':sha(raw),'retainedProviderEntryPresent':False}
    require(type(cfg['candidates']) is dict and len(cfg['candidates'])<=16,'BOUNDED_NAMED_RUNTIME_CANDIDATE_CATALOG_REQUIRED')
    if provider['Id'] not in cfg['candidates']:return summary
    entry=cfg if cfg['schema']==ADAPTERS[0] else cfg['candidates'][provider['Id']]
    candidate=registry/provider['Id'];broker_path=candidate/'broker.json'
    require(entry['admissionConfiguration']==str(broker_path),'EXACT_PROVIDER_BROKER_METADATA_PATH_REQUIRED')
    broker=c.metadata(broker_path,entry['admissionConfigurationHash'])
    require(broker.get('schema')=='ouf.semantic-deployment-broker.v1' and broker['sourceRoot']==str(source_root)
        and broker['candidateRoot']==str(candidate),'SUPPORTED_CURRENT_BROKER_METADATA_REQUIRED')
    bindings={'preparerTemplate':(broker['preparerTemplate'],'preparer-template.json','ouf.semantic-admission-preparer-template.v1'),
        'attestation':(broker['producers']['attestation']['configuration'],'attestation-producer.json','ouf.semantic-node-attestor.v4'),
        'approval':(broker['producers']['approval']['configuration'],'approval-producer.json','ouf.semantic-installer-approval-producer.v1')}
    schemas={};hashes={}
    for role,(binding,filename,schema) in bindings.items():
        require(set(binding)=={'path','sha256'} and binding['path']==str(candidate/filename),'CLOSED_PROVIDER_PROFILE_METADATA_PATH_REQUIRED')
        value=c.metadata(candidate/filename,binding['sha256'])
        require(value.get('schema')==schema,'SUPPORTED_CURRENT_PROVIDER_PROFILE_SCHEMA_REQUIRED')
        schemas[role]=schema;hashes[role]=binding['sha256']
    c.put('runtime-bindings.private.json',{'schema':'ouf.m2-provider-runtime-metadata-bindings.v1',
        'wrapper':{'path':str(wrapper),'sha256':sha(raw)},'configuration':{'path':str(configuration),'sha256':c.seals[str(configuration)]['sha256']},
        'metadataSeals':c.seals,**FLAGS})
    return {**summary,'classification':'BOUND_NAMED_RUNTIME_AND_RETAINED_PROVIDER_PROFILE_METADATA',
        'retainedProviderEntryPresent':True,'brokerSchema':broker['schema'],'brokerConfigurationHash':entry['admissionConfigurationHash'],
        'profileSchemas':schemas,'profileHashes':hashes,'signingKeyBindingsFollowed':False}

def collect(c,*,input_root=INPUT_ROOT,input_hash=INPUT_HASH,result_hash=RESULT_HASH,cid=PROVIDER,image=IMAGE,
            boot_path=Path('/proc/sys/kernel/random/boot_id'),engine_factory=Engine,configuration_root=Path('/etc/ouf'),wrapper_root=Path('/usr/local/sbin')):
    prior=c.metadata(input_root/'result.json',result_hash,True)
    require(prior.get('schema')=='ouf.m2-stopped-provider-inputs-result.v1'
        and prior.get('status')=='STOPPED_PROVIDER_INSTALLATION_INPUTS_PREPARED_NOT_ADMITTED'
        and prior.get('scope')==str(input_root) and prior.get('installationInputsHash')==input_hash
        and prior.get('complete') is True and prior.get('scopeConsumed') is True,'EXACT_CONSUMED_INPUT1868_PROVENANCE_REQUIRED')
    inputs=c.metadata(input_root/'installation-inputs.private.json',input_hash,True)
    require(inputs.get('schema')=='ouf.m2-discovery-stopped-provider-installation-inputs.v1'
        and all(inputs.get(k) is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','historicalAuthorityReused','automaticReplayAllowed','budgetReset')),
        'RETAINED_INPUT_IS_PROVENANCE_ONLY')
    boot=boot_path.read_text().strip();require(boot==inputs['bootId'],'CURRENT_PROVIDER_RUNTIME_BOOT_CHANGED')
    engine=engine_factory(c,inputs['engineBinding'],cid);info=engine.get('/v1.44/info');provider=engine.get('/v1.44/containers/'+cid+'/json')
    require(info.get('ServerVersion')=='29.8.1' and info.get('Driver')=='overlayfs' and info.get('CgroupDriver')=='systemd',
        'QUALIFIED_PROVIDER_RUNTIME_ENGINE_REQUIRED')
    require(provider['Id']==cid and provider['Image']==image and provider['State']['Pid']==0
        and all(provider['State'][k] is False for k in ('Running','Paused','Restarting'))
        and provider_binding(provider)==provider_binding(inputs['currentStoppedProvider']),'SAME_STOPPED_PROVIDER_REQUIRED')
    summary=named_contract(c,info,provider,configuration_root=configuration_root,wrapper_root=wrapper_root)
    require(provider_binding(engine.get('/v1.44/containers/'+cid+'/json'))==provider_binding(provider)
        and engine_binding(engine.get('/v1.44/info'))==engine_binding(info)
        and boot_path.read_text().strip()==boot,'PROVIDER_RUNTIME_CHANGED_DURING_READ')
    c.recheck()
    return {'schema':'ouf.m2-provider-runtime-contract-result.v1','status':'READ_ONLY_PROVIDER_RUNTIME_CONTRACT_OBSERVED',
        'complete':True,'scope':str(c.scope),'scopeConsumed':True,'retainedInputHash':input_hash,
        'contract':summary,'counts':dict(c.counts),'sourceCustodyRechecked':True,'providerStoppedObserved':True,
        'metadataOnlyNotAdmission':True,'rawConfigurationOrEnvironmentValuesPrinted':False,**FLAGS}

def main():
    c=None
    def deadline(*_):raise Stop('RUNTIME_CONTRACT_READ_DEADLINE')
    signal.signal(signal.SIGALRM,deadline);signal.alarm(90)
    try:
        require(not sys.argv[1:],'NO_RUNTIME_CONTRACT_ARGUMENTS_SUPPORTED')
        c=Capture(SCOPE);result=collect(c);c.put('result.json',result);code=0
    except Exception as error:
        reason=str(error)
        result={'schema':'ouf.m2-provider-runtime-contract-result.v1','status':'STOP_RECONCILE','complete':False,
            'scope':str(SCOPE),'scopeConsumed':os.path.lexists(SCOPE),'counts':dict(c.counts) if c else {},
            'reasonCode':reason if isinstance(error,Stop) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',reason)
                else 'PROVIDER_RUNTIME_CONTRACT_UNPROVEN','rawConfigurationOrEnvironmentValuesPrinted':False,**FLAGS}
        if c:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    signal.alarm(0)
    print(json.dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
