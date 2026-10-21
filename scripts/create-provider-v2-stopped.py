"""Create only exact remediated Docker metadata with the empty OUF runtime."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import types

REG=Path('/etc/ouf/deploy-snapshots/semantic-v2-runtime-registration-krSL786w')
REG_REPORT_HASH='ec93dd589733e8987d437aecc0189d947eb891dd83755664fddb0f93e0f13e9d'
REG_SOURCE_HASH='2ee5d624ec653e9cdaf1f1d4c4774735e5d151e0f5a3e41587d766d0be998924'
INPUT=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-inputs-XE7IwlGm')
INPUT_REPORT_HASH='5828744483850f175e55d4a39d134dff076932b6933ec51d4df0ca486cf8a0d4'
TRUST=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-trust-vf7B4SM5')
ACCOUNT_HASH='d3fe5e78d84e021c4a9afdade8ad01add681e1037d26238eb972e03fb9c472fb'
ARCHIVES=Path('/home/oufadmin/ouf-crypto-v2.zjJNdo')
NETWORKS={
'backend':('ouf-backend','113b5f0a3c53059b087a2ce997d2670cc057e88c0c17d4291b3b41a51ce26ba3'),
'internal':('ouf-semantic-provider-internal','2a6652422b45db6f359d94d779ab8625b1ad99b1750bb54582b4b8c4e8aa9307'),
'egress':('ouf-semantic-provider-egress','db8bc9f8feccc3c14f2818a5c843f5c08e5eb2e192530858d88a70ce1cc0a86d')}
ROLES={
'adapter':{'name':'ouf-semantic-provider-v2','uid':10006,'gid':10006,'archiveHash':'8301649b854a01d0306fabb14a5f93dd08eb4b1df98c2af356c0c84773821207','imageId':'sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320','startup':{'Entrypoint':['python3','-B','-m','tools.semantic_provider_adapter'],'Cmd':None,'WorkingDir':'/app','User':'10006:10006'}},
'southbound':{'name':'ouf-semantic-southbound-v2','uid':636,'gid':636,'archiveHash':'1588c2391f9da45f300d16dd191cfe483dff83f81ed9424baec40201e64d7641','imageId':'sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04','startup':{'Entrypoint':['/docker-entrypoint.sh'],'Cmd':['docker-start'],'WorkingDir':'/usr/local/apisix','User':'apisix'}}}
OWNER='ouf.semantic.provider.v2.creation'
STAGE='INITIAL_READ'

class Denied(RuntimeError):pass

def require(ok,why):
    if not ok:raise Denied(why)

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'
def sha(b):return hashlib.sha256(b).hexdigest()

def private(path,uid=0,gid=0,mode=0o600):
    path=Path(path)
    require(path.is_absolute() and '..' not in path.parts,'SAFE_PRIVATE_PATH_REQUIRED')
    for parent in (path.parent,*path.parent.parents):
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_ANCESTOR_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        a=os.fstat(fd);require(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and (a.st_uid,a.st_gid,stat.S_IMODE(a.st_mode))==(uid,gid,mode) and a.st_size<=1048576,'PRIVATE_FILE_REQUIRED')
        b=os.read(fd,1048577);after=os.fstat(fd)
        require(len(b)==a.st_size and all(getattr(a,k)==getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'PRIVATE_FILE_DRIFT')
        return b
    finally:os.close(fd)

def namespace(path,expected):
    raw=private(path);require(sha(raw)==expected,'HELPER_SOURCE_DRIFT')
    m=types.ModuleType('_ouf_closed_creation_helper');m.__file__=str(path)
    exec(compile(raw,str(path),'exec'),m.__dict__);require(private(path)==raw,'HELPER_SOURCE_DRIFT');return m

def snapshot(ns):
    ids=ns.docker('ps','-aq','--no-trunc').decode().splitlines()
    require(len(ids)<=256 and all(re.fullmatch('[0-9a-f]{64}',x) for x in ids),'BOUNDED_CONTAINER_IDS_REQUIRED')
    if not ids:return {}
    fmt='{"id":{{json .Id}},"pid":{{json .State.Pid}},"started":{{json .State.StartedAt}},"status":{{json .State.Status}},"running":{{json .State.Running}}}'
    rows=[ns.parse(line) for line in ns.docker('inspect','--type','container','--format',fmt,*ids).splitlines()]
    return {r['id']:r for r in rows}

def network(ns,key):
    name,nid=NETWORKS[key]
    raw=ns.docker('network','inspect','--format','{{json .}}',nid);n=ns.parse(raw)
    require(n['Id']==nid and n['Name']==name and n['Driver']=='bridge' and n['EnableIPv6'] is False,'NETWORK_IDENTITY_DRIFT')
    if key!='backend':require(not n.get('Containers') and n['Internal']==(key=='internal'),'DEDICATED_NETWORK_NOT_EMPTY')
    return n

def image(ns,imageid):
    p=ns.capture([ns.BINDS['docker'][0],'-H',ns.SOCKET,'image','inspect',imageid])
    r=ns.parse(p);require(len(r)==1 and r[0]['Id']==imageid,'EXACT_IMAGE_REQUIRED');return r[0]

def environment(spec,img):
    result={}
    for entry in img['Config'].get('Env') or []:
        key,value=entry.split('=',1);require(key not in result,'DUPLICATE_PACKAGED_ENV');result[key]=value
    if spec['envFile']:
        lines=private(spec['envFile']).decode('ascii').splitlines()
        require(len(lines)==len(spec['environmentNames']) and len({x.split('=',1)[0] for x in lines})==len(lines),'EXACT_SECRET_ENV_NAMES_REQUIRED')
        for line in lines:
            key,value=line.split('=',1);require(key in spec['environmentNames'] and key not in ('PATH','HOME','LD_PRELOAD','PYTHONPATH'),'UNEXPECTED_SECRET_ENV');result[key]=value
    return result

def mount(source,target,uid,gid,expected,mode=0o600):
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+',target) and '..' not in Path(target).parts,'SAFE_MOUNT_TARGET_REQUIRED')
    require(sha(private(source,uid,gid,mode))==expected,'MOUNT_CONTENT_DRIFT')
    return {'source':str(source),'target':target,'sha256':expected,'uid':uid,'gid':gid,'mode':mode}

def prepare(ns):
    regraw=private(REG/'registration-receipt.json');require(sha(regraw)==REG_REPORT_HASH,'REGISTRATION_RECEIPT_DRIFT');reg=ns.parse(regraw)
    require(all(sha(private(REG/'source'/name))==value for name,value in reg['sourceHashes'].items()),'REGISTERED_SOURCE_CLOSURE_DRIFT')
    require(reg['status']=='EMPTY_RUNTIME_REGISTERED' and reg['candidateCount']==0 and reg['startAuthorized'] is False,'EMPTY_REGISTRATION_REQUIRED')
    cfgraw=private(REG/'adapter-configuration.json');cfg=ns.parse(cfgraw)
    require(sha(cfgraw)==reg['adapterConfigurationHash'] and cfg['candidates']=={} and cfg['registryRoot']==str(REG/'registry'),'EMPTY_ADAPTER_CONFIGURATION_REQUIRED')
    require(sha(ns.read(ns.WRAPPER,True))==reg['wrapperHash'] and sha(private(ns.DAEMON))==reg['daemonConfigurationHash'],'REGISTERED_FILES_DRIFT')
    catalogue=ns.runtimes();require(catalogue['default']=='runc' and catalogue['runtimes'][reg['runtimeName']]['path']==str(ns.WRAPPER),'REGISTERED_RUNTIME_REQUIRED')
    raw=private(INPUT/'runtime-input-receipt.json');require(sha(raw)==INPUT_REPORT_HASH,'STARTUP_RECEIPT_DRIFT');receipt=ns.parse(raw)
    require(receipt['status']=='PRIVATE_STARTUP_INPUTS_PREPARED' and receipt['startAuthorized'] is False and receipt['directory']==str(INPUT),'PREPARED_INPUTS_REQUIRED')
    require(receipt['roleImages']=={k:v['imageId'] for k,v in ROLES.items()} and receipt['runtimeUsers']=={k:f"{v['uid']}:{v['gid']}" for k,v in ROLES.items()},'PREPARED_ROLE_BINDING_DRIFT')
    traw=private(TRUST/'trust-receipt.json');require(sha(traw)==receipt['trustReceiptHash'],'TRUST_RECEIPT_DRIFT');trust=ns.parse(traw)
    files={n:private(INPUT/n,*((10006,10006) if n=='adapter.json' else (636,636) if n in ('config.yaml','apisix.yaml') else (0,0))) for n in receipt['outputHashes']}
    require(all(sha(b)==receipt['outputHashes'][n] for n,b in files.items()),'STARTUP_OUTPUT_DRIFT')
    binding=ns.parse(files['binding.json']);plan=ns.parse(files['runtime-plan.json']);adapter=ns.parse(files['adapter.json'])
    require(adapter==binding['adapter']==plan['adapterConfiguration'],'ADAPTER_PLAN_DRIFT')
    dns=plan['dnsBinding']['selectedResolvers'];require(len(dns)==2 and set(dns)=={'46.38.252.230','46.38.225.230'},'ORIGINAL_RESOLVER_BINDING_DRIFT')
    targets={'provider-receipt.key':adapter['receiptKeyFile'],'server.crt':adapter['tlsCertificateFile'],'server.key':adapter['tlsPrivateKeyFile']}
    specs=[]
    for role,facts in ROLES.items():
        r={**facts,'role':role,'user':f"{facts['uid']}:{facts['gid']}",'memoryBytes':268435456 if role=='adapter' else 536870912,'pidsLimit':128,
            'readOnlyRoot':role=='adapter','runtimeName':reg['runtimeName'],'dns':dns,'mounts':[],
            'envFile':None if role=='adapter' else str(INPUT/'southbound.env'),
            'environmentNames':[] if role=='adapter' else receipt['environmentNames']}
        if role=='adapter':
            r['command']=['--configuration','/run/ouf-semantic-provider/adapter.json']
            r['mounts'].append(mount(INPUT/'adapter.json',r['command'][1],10006,10006,receipt['outputHashes']['adapter.json']))
            for name,target in targets.items():r['mounts'].append(mount(TRUST/'adapter'/name,target,10006,10006,trust['artifactHashes']['adapter/'+name]))
            r['networks']=[{'key':'internal','ip':'172.21.0.3'},{'key':'egress','ip':'172.22.0.3'}]
        else:
            r['command']=[]
            for name in ('config.yaml','apisix.yaml'):r['mounts'].append(mount(INPUT/name,'/usr/local/apisix/conf/'+name,636,636,receipt['outputHashes'][name]))
            r['networks']=[{'key':'backend','ip':'172.18.0.14'},{'key':'internal','ip':'172.21.0.2'},{'key':'egress','ip':'172.22.0.2'}]
        r['mounts'].append(mount(TRUST/'trust-bundle.pem',adapter['provider']['ca_file'],0,0,trust['artifactHashes']['trust-bundle.pem'],0o644))
        require(len({m['target'] for m in r['mounts']})==len(r['mounts']),'DISTINCT_MOUNTS_REQUIRED')
        specs.append(r)
    preserved={REG/'registration-receipt.json':regraw,REG/'adapter-configuration.json':cfgraw,INPUT/'runtime-input-receipt.json':raw,TRUST/'trust-receipt.json':traw}
    for n,b in files.items():preserved[INPUT/n]=b
    return specs,preserved

def freeze_archives(root,accounts):
    target=root/'images';target.mkdir(mode=0o700)
    require(shutil.disk_usage(root).free>=1610612736,'PRIVATE_SPOOL_SPACE_REQUIRED')
    for role,facts in ROLES.items():
        source=ARCHIVES/(role+'.image.tar.gz');fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as incoming:
            before=os.fstat(incoming.fileno());require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=536870912,'BOUNDED_IMAGE_ARCHIVE_REQUIRED')
            out=target/(role+'.image.tar.gz');dest=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            h=hashlib.sha256();size=0
            with os.fdopen(dest,'wb') as frozen:
                while part:=incoming.read(65536):
                    size+=len(part);require(size<=536870912,'IMAGE_ARCHIVE_UNBOUNDED');h.update(part);frozen.write(part)
                frozen.flush();os.fsync(frozen.fileno())
            after=os.fstat(incoming.fileno());require(size==before.st_size and h.hexdigest()==facts['archiveHash'] and all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'IMAGE_ARCHIVE_DRIFT')
        with out.open('rb') as verified:row=accounts.inspect_stream(verified,facts['archiveHash'],facts['imageId'][7:])
        require((row['uid'],row['gid'])==(facts['uid'],facts['gid']) and row['layerBytesVerified'] is True,'VERIFIED_ROLE_IDENTITY_REQUIRED')


def create_command(spec,transaction):
    primary=spec['networks'][0]
    args=['create','--pull=never','--name',spec['name'],'--runtime',spec['runtimeName'],
        '--user',spec['user'],'--restart','no','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--memory',str(spec['memoryBytes']),'--memory-swap',str(spec['memoryBytes']),
        '--pids-limit',str(spec['pidsLimit']),'--no-healthcheck',
        '--network',NETWORKS[primary['key']][1],'--ip',primary['ip'],'--network-alias',spec['name'],
        '--label',OWNER+'='+transaction]
    if spec['readOnlyRoot']:args.append('--read-only')
    for resolver in spec['dns']:args+=['--dns',resolver]
    for item in spec['mounts']:args+=['--mount','type=bind,source='+item['source']+',target='+item['target']+',readonly']
    if spec['envFile']:args+=['--env-file',spec['envFile']]
    return args+[spec['imageId']]+spec['command']

def verify_container(ns,spec,cid,img,transaction):
    rows=ns.parse(ns.docker('inspect','--type','container',cid));require(len(rows)==1,'SINGLE_CANDIDATE_REQUIRED');r=rows[0]
    state=r['State'];cfg=r['Config'];host=r['HostConfig']
    require(r['Id']==cid and r['Name']=='/'+spec['name'] and r['Image']==spec['imageId'],'CANDIDATE_IDENTITY_DRIFT')
    require(state['Status']=='created' and state['Running'] is False and state['Pid']==0 and state['StartedAt'].startswith('0001-'),'CANDIDATE_MUST_NEVER_START')
    expected_cmd=spec['command'] or img['Config'].get('Cmd')
    require(cfg['User']==spec['user'] and cfg['Entrypoint']==img['Config'].get('Entrypoint') and cfg['Cmd']==expected_cmd and cfg['WorkingDir']==img['Config'].get('WorkingDir'),'STARTUP_IDENTITY_DRIFT')
    got={}
    for entry in cfg.get('Env') or []:
        k,v=entry.split('=',1);require(k not in got,'DUPLICATE_CANDIDATE_ENV');got[k]=v
    require(hmac.compare_digest(encoded(got),encoded(environment(spec,img))),'CANDIDATE_ENVIRONMENT_DRIFT')
    require(cfg.get('Labels',{}).get(OWNER)==transaction,'OWNED_CANDIDATE_REQUIRED')
    require(host['Runtime']==spec['runtimeName'] and host['ReadonlyRootfs']==spec['readOnlyRoot'] and host['Privileged'] is False
        and host['CapDrop']==['ALL'] and not host.get('CapAdd') and host['SecurityOpt']==['no-new-privileges:true']
        and host['RestartPolicy']['Name']=='no' and host['Memory']==spec['memoryBytes'] and host['MemorySwap']==spec['memoryBytes']
        and host['PidsLimit']==spec['pidsLimit'] and host['Dns']==spec['dns'] and not host.get('PortBindings')
        and not host.get('PublishAllPorts') and not host.get('Devices') and not host.get('DeviceRequests'),'HOST_CONFIGURATION_DRIFT')
    mounts=sorted((x['Type'],x['Source'],x['Destination'],x['RW']) for x in r['Mounts'])
    require(mounts==sorted(('bind',x['source'],x['target'],False) for x in spec['mounts']),'READ_ONLY_MOUNT_DRIFT')
    nets=r['NetworkSettings']['Networks'];require(set(nets)=={NETWORKS[x['key']][0] for x in spec['networks']},'NETWORK_SET_DRIFT')
    for item in spec['networks']:
        n=nets[NETWORKS[item['key']][0]]
        require(n.get('NetworkID') in ('',NETWORKS[item['key']][1]) and (n.get('IPAMConfig') or {}).get('IPv4Address')==item['ip']
            and not n.get('EndpointID') and not n.get('IPAddress') and spec['name'] in (n.get('Aliases') or []),'STOPPED_NETWORK_METADATA_DRIFT')
    return {'role':spec['role'],'containerId':cid,'imageId':spec['imageId'],'neverStarted':True,'mountsVerified':True,'startupVerified':True,'configuredAddressesVerified':True,'liveAddressAllocationProven':False}

def core_create(ns,specs,root,transaction):
    rows=[]
    for spec in specs:
        img=image(ns,spec['imageId']);config=img['Config']
        require(all(config.get(k)==v for k,v in spec['startup'].items()) and not config.get('Volumes'),'PACKAGED_STARTUP_DRIFT')
        environment(spec,img)
        cid=ns.docker(*create_command(spec,transaction)).decode().strip()
        require(re.fullmatch('[0-9a-f]{64}',cid),'CREATED_CONTAINER_ID_REQUIRED')
        ns.publish(root/(spec['role']+'-created.json'),encoded({'containerId':cid,'startAuthorized':False}))
        for attach in spec['networks'][1:]:
            ns.docker('network','connect','--ip',attach['ip'],'--alias',spec['name'],NETWORKS[attach['key']][1],cid)
        rows.append(verify_container(ns,spec,cid,img,transaction))
    return rows

def operate(root):
    global STAGE
    ns=namespace(REG/'register-provider-v2-runtime.py',REG_SOURCE_HASH)
    accounts=namespace(TRUST/'provider-role-accounts.py',ACCOUNT_HASH)
    for path,expected in ns.BINDS.values():require(sha(ns.read(Path(path),True))==expected,'HOST_EXECUTABLE_DRIFT')
    own=private(Path(__file__).resolve())
    specs,preserved=prepare(ns);before=snapshot(ns);pid=ns.daemon_pid();identity=ns.identity(pid);guard=ns.preflight()
    networks={k:network(ns,k) for k in NETWORKS}
    names=ns.docker('ps','-a','--format','{{.Names}}').decode().splitlines()
    require(not any(s['name'] in names for s in specs),'CANDIDATE_NAME_ALREADY_EXISTS')
    for spec in specs:
        for item in spec['networks']:
            require(not any(x.get('IPv4Address','').split('/')[0]==item['ip'] for x in networks[item['key']].get('Containers',{}).values()),'TARGET_ADDRESS_ALREADY_LIVE')
    transaction=root.name
    ns.publish(root/'creation-claim.json',encoded({'schema':'ouf.semantic-provider-v2-stopped-creation-claim.v1','transaction':transaction,'startAuthorized':False,'stage':'BEFORE_IMAGE_IMPORT'}))
    STAGE='FREEZE_ARCHIVES';freeze_archives(root,accounts)
    import fcntl
    lockpath=Path(ns.parse(ns.read(ns.GUARD))['lockFile']);fd=os.open(lockpath,os.O_RDWR|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd);require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600,'GUARD_LOCK_CUSTODY_REQUIRED')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(snapshot(ns)==before and ns.identity(ns.daemon_pid())==identity,'TARGET_CHANGED_BEFORE_CREATE')
        require(sha(ns.read(ns.GUARD))==ns.GUARD_HASH,'GUARD_CONFIGURATION_DRIFT')
        require(prepare(ns)==(specs,preserved) and all(network(ns,k)==v for k,v in networks.items()),'PREPARED_INPUTS_DRIFT')
        imports=0
        for spec in specs:
            STAGE='IMAGE_IMPORT_'+spec['role'].upper()
            available=ns.docker('image','ls','-aq','--no-trunc').decode().splitlines()
            if spec['imageId'] not in available:
                ns.capture([ns.BINDS['docker'][0],'-H',ns.SOCKET,'image','load','--input',str(root/'images'/(spec['role']+'.image.tar.gz'))],180);imports+=1
            image(ns,spec['imageId'])
        STAGE='CREATE_STOPPED_CANDIDATES';rows=core_create(ns,specs,root,transaction)
        after=snapshot(ns);new={r['containerId'] for r in rows}
        require(set(after)==set(before)|new and all(after[k]==v for k,v in before.items()),'EXISTING_CONTAINER_STATES_DRIFT')
        for path,raw in preserved.items():
            uid,gid=(10006,10006) if path==INPUT/'adapter.json' else (636,636) if path in (INPUT/'config.yaml',INPUT/'apisix.yaml') else (0,0)
            require(private(path,uid,gid)==raw,'PREPARED_FILES_CHANGED')
        for spec in specs:
            for item in spec['mounts']:require(sha(private(item['source'],item['uid'],item['gid'],item['mode']))==item['sha256'],'MOUNT_SOURCE_DRIFT')
        require(ns.identity(ns.daemon_pid())==identity,'DAEMON_IDENTITY_CHANGED')
        for k,old in networks.items():require(network(ns,k)==old,'LIVE_NETWORK_CHANGED')
    finally:os.close(fd)
    STAGE='GUARD_READBACK';require(ns.preflight()==guard,'GUARD_CUSTODY_CHANGED');prepare(ns)
    require(private(Path(__file__).resolve())==own,'CREATION_SOURCE_DRIFT')
    report={'schema':'ouf.semantic-provider-v2-stopped-creation.v1','status':'CREATED_STOPPED_AND_READBACK_VERIFIED',
        'directory':str(root),'sourceHash':sha(own),'candidates':rows,'containerLifecycleOperations':2,'networkAttachmentOperations':3,
        'imagesImported':imports,'existingContainerCount':len(before),'existingContainerStatesUnchanged':True,
        'daemonRestarted':False,'firewallWrites':0,'privateAuthorityKeysRead':0,'providerCalls':0,
        'runtimeAllowlistChanged':False,'liveAddressAllocationProven':False,'startAuthorized':False,'acceptanceGranted':False,'notReleaseAcceptance':True}
    ns.publish(root/'creation-receipt.json',encoded(report));return report

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--create-stopped-only',action='store_true',required=True);args=parser.parse_args()
    root=None
    try:
        require(os.geteuid()==0,'ROOT_REQUIRED');os.umask(0o077)
        import tempfile
        root=Path(tempfile.mkdtemp(prefix='semantic-provider-v2-stopped-create-',dir='/etc/ouf/deploy-snapshots'));root.chmod(0o700)
        result=operate(root);print('OUF_PROVIDER_V2_STOPPED_CREATION='+encoded(result).decode().strip())
    except Exception as exc:
        reason=str(exc) if type(exc).__name__=='Denied' and re.fullmatch('[A-Z_]+',str(exc)) else 'BOUNDED_OPERATION_FAILED'
        print('OUF_PROVIDER_V2_STOPPED_CREATION=BLOCKED STAGE='+STAGE+' REASON='+reason+' PARTIAL_EVIDENCE_RETAINED=true DO_NOT_RERUN_APPLY=true NO_RAW_OUTPUT=true')
        if root:print('OUF_STOPPED_CREATION_SNAPSHOT='+str(root))
        return 1
    return 0

if __name__=='__main__':sys.exit(main())
