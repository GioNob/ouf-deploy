#!/usr/bin/env python3
"""Fixed failed successor: read ledgers, OCI, mounts and native link policy.

Never invoke installer, worker, token/credential readers, acceptance signer,
Docker mutation, DB or IAM. Execute only hash-pinned pure network compiler code.
"""
import ast, base64, copy, hashlib, http.client, json, os, re, signal, socket, stat, subprocess, sys, types
from pathlib import Path

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-6876e1b33e42a03b673d68f2acbb1f80dcf0cbb9bc50d8f945099f8535d86ad3')
REVIEW='892cc1048a526d0e4705a58ce91a9b5a3f6712796d64fb98b619d8ad397bfc8f'
AUTHORITY='fa7bdc08f0c0ea048b064774648176cf54ce51279118ce1df0ff296fc8616d3b'
SOURCE='0525c4186a5613000905ba4dfae6766827ad9f06'
CID='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
UNIT='ouf-file-cohort-6876e1b33e42a03b673d68f2acbb1f80.service'
PINS={'tools.materialize_southbound_kernel': '98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de', 'tools.materialize_semantic_shared_faces': '66986436206e9448e0bad58b651f4802a53e54eb179327c7050d963c22f33b62', 'tools.semantic_provider_peer_bindings': '4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b', 'tools.semantic_provider_deployment_admission': 'fccde9a325939b400a95dc5e8714755727ed57b476b01c82019a15ffac8f8df4'}
ERRORS=[]
class ReadDenied(Exception):pass
def require(ok,code):
    if not ok:raise ReadDenied(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def identity(s):return tuple(getattr(s,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def emit(check,**v):
    print(json.dumps(dict(schema='ouf.chatbot-paused-node-readback.v1',check=check,readOnly=True,
        automaticRetry=False,budgetReset=False,**v),sort_keys=True),flush=True)
def unique(rows):
    d={}
    for k,v in rows:require(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
    return d
def read(path,maximum=262144,expected=None):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_READ_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CONTROLLED_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
            and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_BOUNDED_RECORD_REQUIRED')
        raw=bytearray()
        while len(raw)<=maximum:
            part=os.read(fd,min(65536,maximum+1-len(raw)))
            if not part:break
            raw.extend(part)
        require(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat()),'READ_DRIFT')
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'READ_HASH_DRIFT')
        return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ReadDenied('NONFINITE_JSON')))
    finally:os.close(fd)
def attempt(check,fn):
    try:return fn()
    except Exception as e:
        ERRORS.append(check);code=str(e)if type(e)is ReadDenied else type(e).__name__
        emit(check,status='UNAVAILABLE',reason=code if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',code)else'UNCLASSIFIED')
def command(binding,args):
    path=Path(binding['path']);s=path.stat()
    require(path.is_absolute()and stat.S_ISREG(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
        and hashlib.sha256(path.read_bytes()).hexdigest()==binding['sha256'],'NATIVE_COMMAND_BINDING_DRIFT')
    r=subprocess.run([str(path),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(r.returncode==0 and len(r.stdout)<=131072,'BOUNDED_NATIVE_GET_REQUIRED')
    require(identity(path.stat())==identity(s),'NATIVE_COMMAND_CHANGED')
    return json.loads(r.stdout)
def inspect(engine):
    p=engine['socketPath'];pin=tuple(engine['socketBinding'])
    def guard():
        s=os.stat(p,follow_symlinks=False);require(stat.S_ISSOCK(s.st_mode)and(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==pin,'ENGINE_SOCKET_DRIFT')
    guard()
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(10);self.sock.connect(p)
    c=Local('localhost',timeout=10)
    try:
        c.request('GET','/v1.44/containers/'+CID+'/json');r=c.getresponse();raw=r.read(2097153)
        require(r.status==200 and len(raw)<=2097152,'BOUNDED_CONTAINER_GET_REQUIRED');guard();return json.loads(raw)
    finally:c.close()
def runtime_config(path):
    path=Path(path);require(path.resolve()==path,'EXACT_RUNTIME_CONFIG_PATH_REQUIRED')
    for parent in path.parents:
        info=parent.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'RUNTIME_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode)and before.st_uid==before.st_gid==0 and before.st_nlink==1
            and stat.S_IMODE(before.st_mode)in(0o600,0o644)and 0<before.st_size<=131072,'RUNTIME_CONFIG_CUSTODY_REQUIRED')
        raw=os.read(fd,131073)
        require(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'RUNTIME_CONFIG_READ_DRIFT')
        return raw
    finally:os.close(fd)
def projection(row):
    out={k:row[k]for k in ('state','version','attempts','controlledCumulativeGrantAttempts','publicationCount','nextPhase')if k in row}
    for k,v in out.items():require(type(v)is int or(type(v)is str and re.fullmatch('[A-Z][A-Z0-9_]{0,79}',v)),'SAFE_RECORD_PROJECTION_REQUIRED')
    return out
def proc_generation(pid):
    require(type(pid)is int and pid>1,'LIVE_PID_REQUIRED');root=Path('/proc')/str(pid)
    def one():
        raw=(root/'stat').read_bytes();require(len(raw)<=16384,'BOUNDED_PROC_STAT_REQUIRED')
        fields=raw.rsplit(b') ',1)[1].split()
        return {'pid':pid,'startTicks':int(fields[19]),'mountNamespaceInode':(root/'ns/mnt').stat().st_ino,
            'networkNamespaceInode':(root/'ns/net').stat().st_ino,'processState':fields[0].decode('ascii')}
    a=one();require(one()==a,'PROCESS_GENERATION_DRIFT');return a

def pure_network(sources):
    """Full three pure compiler modules plus four exact admission functions.

    The diagnostic check raises ReadDenied instead of the owner's PreexecDenied;
    no authority or acceptance is constructed. All function bodies are unchanged.
    """
    originals={};allow=set()
    for name,pin in PINS.items():
        raw=base64.b64decode(sources[name],validate=True);require(hashlib.sha256(raw).hexdigest()==pin,'PURE_SOURCE_PIN_DRIFT')
        originals[name]=raw
        for node in ast.walk(ast.parse(raw)):
            if isinstance(node,ast.Constant)and type(node.value)is str and 0<len(node.value)<=159:allow.add(node.value)
    package=types.ModuleType('_ouf_read_network');package.__path__=[];sys.modules[package.__name__]=package;modules={}
    for short in ('materialize_southbound_kernel','materialize_semantic_shared_faces','semantic_provider_peer_bindings'):
        raw=originals['tools.'+short].decode();module=types.ModuleType(package.__name__+'.'+short)
        module.__package__=package.__name__;sys.modules[module.__name__]=module;setattr(package,short,module)
        exec(compile(raw.replace('from tools.','from '+package.__name__+'.'),'<verified-network:'+short+'>','exec'),module.__dict__)
        modules[short]=module
    tree=ast.parse(originals['tools.semantic_provider_deployment_admission'])
    tree.body=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in {'check','application_hash','transport_hash','live_profile'}]
    require(len(tree.body)==4,'EXACT_PURE_ADMISSION_FUNCTIONS_REQUIRED')
    ns=dict(PreexecDenied=ReadDenied,digest=digest,materialize=modules['materialize_semantic_shared_faces'].materialize,
        declarations=modules['semantic_provider_peer_bindings'].declarations,resolve=modules['semantic_provider_peer_bindings'].resolve,re=re)
    exec(compile(tree,'<verified-network:live_profile>','exec'),ns)
    return ns,allow

def network_probe(prepared,native,oci,bundle,sources):
    recipe=prepared['registry']['nodeRecipe'];cfg=recipe['observationConfiguration'];cmd=cfg['commands'];pid=native['State']['Pid']
    before=proc_generation(pid);namespace='/proc/'+str(pid)+'/ns/net'
    children=command(cmd['nsenter'],['--net='+namespace,cmd['ip']['path'],'-j','addr','show'])
    children=[c for c in children if c['ifname']!='lo'];hosts=[]
    for c in children:
        name=socket.if_indextoname(c['link_index']);hosts.extend(command(cmd['ip'],['-j','link','show','dev',name]))
    candidate={**copy.deepcopy(cfg['candidate']),'containerId':CID,'transactionId':recipe['transactionId'],
        'applicationHash':digest(oci),'bundlePath':bundle}
    ns,allow=pure_network(sources);expected=ns['declarations'](candidate['transport'],CID)
    require(not expected,'PEER_DECLARATIONS_REQUIRE_SEPARATE_NATIVE_COLLECTION')
    before_inputs=encoded((candidate,oci,children,hosts));result=None
    try:
        ns['live_profile'](candidate,oci,namespace,before['networkNamespaceInode'],children,hosts,{})
        emit('EXACT_NATIVE_NETWORK_POLICY',status='PASS',sourceFunctionsUnchanged=True,nicCount=len(children))
    except Exception as e:
        code=str(e);frames=[];tb=e.__traceback__
        while tb is not None:
            filename=tb.tb_frame.f_code.co_filename
            if filename.startswith('<verified-network:'):frames.append({'source':filename[18:-1],'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno})
            tb=tb.tb_next
        emit('EXACT_NATIVE_NETWORK_POLICY',status='DENIED',errorClass=type(e).__name__,
            sourceLiteralReason=code if code in allow else None,arbitraryMessagePrinted=False,locations=frames[-8:])
        result=code if code in allow else None
    again=command(cmd['nsenter'],['--net='+namespace,cmd['ip']['path'],'-j','addr','show'])
    again=[c for c in again if c['ifname']!='lo'];again_hosts=[]
    for c in again:
        name=socket.if_indextoname(c['link_index']);again_hosts.extend(command(cmd['ip'],['-j','link','show','dev',name]))
    require(encoded((candidate,oci,again,again_hosts))==before_inputs and proc_generation(pid)==before,'NETWORK_PROBE_INPUT_OR_GENERATION_DRIFT')
    return result

def mount_projection(native,policy):
    pid=native['State']['Pid'];before=proc_generation(pid);raw=(Path('/proc')/str(pid)/'mountinfo').read_bytes()
    require(len(raw)<=131072,'BOUNDED_MOUNTINFO_REQUIRED');rows=[r.split()for r in raw.decode().splitlines()]
    expected=[*policy['sources'],policy['configtree'],policy['renewableToken']]
    for slot,b in enumerate(expected):
        source=Path(b['source']);a=source.lstat();target=b['target'];view=Path('/proc')/str(pid)/'root'/target.lstrip('/')
        matches=[r for r in rows if len(r)>6 and r[4]==target]
        emit('MOUNT_METADATA',slot=slot,sameSourceInode=identity(a)==identity(view.stat()),
            readOnly=len(matches)==1 and 'ro'in matches[0][5].split(',')and'rw'not in matches[0][5].split(','),
            subordinateMountAbsent=not any(len(r)>4 and r[4].startswith(target+'/')for r in rows),contentRead=False)
    require(proc_generation(pid)==before and (Path('/proc')/str(pid)/'mountinfo').read_bytes()==raw,'MOUNT_PROJECTION_DRIFT')

def main():
    require(os.geteuid()==0,'ROOT_READ_ACCESS_REQUIRED');signal.alarm(90)
    emit('BEGIN',serviceMutations=0,databaseMutations=0,grantRequests=0,iamCalls=0,credentialOrTokenFilesRead=False)
    review=read(CONTEXT/'review.json');require(digest(review)==REVIEW and review['sourceClosure']['declaration']['sourceCommit']==SOURCE,'EXACT_FAILED_REVIEW_REQUIRED')
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY);require(all(authority[k]==v for k,v in review['scopes'].items()),'SIGNED_SCOPE_DRIFT')
    process=review['scopes']['finiteActionProcess'];require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'EXACT_FAILED_PROCESS_REQUIRED')
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']and digest(p)==review['privateInputHashes']['preparedInputs'],'BUNDLE_OR_INPUT_DRIFT')
    status=read(CONTEXT/'delivery-status.json',16384);require(status['authorityHash']==AUTHORITY,'STATUS_AUTHORITY_DRIFT')
    require(status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'and status.get('reason')=='ValueError','EXACT_RETAINED_FAILURE_REQUIRED')
    emit('RETAINED_STATUS',phase=status['phase'],reason=status.get('reason'),runtimeAuthorityIssuedByReader=False)
    r=subprocess.run(['/usr/bin/systemctl','show',UNIT,'--property=ActiveState,SubState,MainPID,Job'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
    require(r.returncode==0 and len(r.stdout)<=8192,'PROCESS_READ_UNAVAILABLE');rows=dict(l.split('=',1)for l in r.stdout.decode().splitlines()if'='in l)
    require(rows.get('ActiveState')in('inactive','failed')and rows.get('MainPID')=='0'and rows.get('Job')=='','DELIVERY_MUST_BE_STOPPED_FOR_READBACK')
    emit('PROCESS',stopped=True)
    reservation=read(CONTEXT.parent/'chatbot-file-cohort-postgrant-7db9ea82ed6fbbdc88cfdbd8e7315404e6c958e841731d1d12b22482f8fa8f30.claim.json',8192)
    emit('CONTINUATION_RESERVATION',authorityMatches=reservation.get('authorityHash')==AUTHORITY,**projection(reservation))
    paths=p['registry']['directoryPlan'];transition=read(Path(paths['transition'])/'recovery.json')
    phase_names={'STOP_REVOKE_OLD_LEASE','QUIESCE_PRODUCERS','FENCED_BACKUP','RELEASE_OLD_ENDPOINT','CREATE_REPLACEMENT','STAGE_PAUSED_REPLACEMENT','ATTEST_NEW_OCI_PEER','ADMIT_MIGRATION','START_REPLACEMENT','VERIFY_APPLICATION','RELEASE_PRODUCERS'}
    require(all(x.get('phase')in phase_names and x.get('state')in('APPLIED','IN_FLIGHT','NO_EFFECT','UNKNOWN')for x in transition['effects']),'SAFE_PHASE_PROJECTION_REQUIRED')
    emit('REGISTRY_TRANSITION',**projection(transition),phases=[{'phase':x['phase'],'state':x['state']}for x in transition['effects']])
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    for name in ('recovery.json','owner-session.json','owner-admission.json'):
        attempt('WORKER_'+name,lambda name=name:emit('WORKER_'+name,**projection(read(owner/name))))
    for name in ('containers','databases','gateway','authorization'):
        attempt('LATER_'+name,lambda name=name:emit('LATER_'+name,**projection(read(Path(process['directoryPlan'][name])/'recovery.json'))))
    native=inspect(p['engine']);state=native['State'];pid=state['Pid']
    require(state.get('Status')in('created','running','paused','restarting','removing','exited','dead'),'SAFE_ENGINE_STATUS_REQUIRED')
    emit('REGISTRY_NATIVE',running=state['Running'],paused=state['Paused'],status=state['Status'],restartCount=native['RestartCount'],pid=pid)
    require(state['Running']is True and state['Paused']is True and type(pid)is int and pid>1,'PAUSED_GENERATION_REQUIRED')
    recipe=p['registry']['nodeRecipe'];runtime=command(recipe['observationConfiguration']['runtimeBinding'],['--root',recipe['runtimeRoot'],'state',CID])
    require(runtime['id']==CID and runtime['pid']==pid and runtime['status']=='paused','EXACT_RUNC_PAUSED_GENERATION_REQUIRED')
    cfg_path=Path(runtime['bundle'])/'config.json'
    require(cfg_path.parent.parent==Path(recipe['dockerContext']['bundleParent']),'APPROVED_BUNDLE_PARENT_REQUIRED')
    # Runtime config is root-controlled but Docker may use0644. It contains no credential file bodies.
    raw=runtime_config(cfg_path);oci=json.loads(raw);policy=read(Path(paths['node'])/'frame-policy.json',131072)
    emit('RETAINED_FRAME_POLICY',exactOciMatches=digest(oci)==digest(policy['expectedOci']),signatureClaimPresent=(Path(paths['node'])/'attestation-issuance-claim.json').exists(),privateValuesPrinted=False)
    attempt('MOUNTS',lambda:mount_projection(native,policy))
    attempt('NETWORK',lambda:network_probe(p,native,oci,runtime['bundle'],bundle['sources']))
    require(inspect(p['engine'])==native and runtime_config(cfg_path)==raw,'NATIVE_READBACK_DRIFT')
    emit('END',complete=not ERRORS,unavailableChecks=ERRORS,serviceMutations=0,databaseMutations=0,grantRequests=0,
        credentialOrTokenFilesRead=False,authorityRenewed=False,budgetReset=False,chatbotEndToEndProven=False,
        rootfsSealCheckPerformed=False,frameByteContentChecksPerformed=False,attestationAccepted=False)

if __name__=='__main__':
    try:main()
    except Exception as e:
        reason=str(e)if type(e)is ReadDenied else type(e).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',exceptionMessagePrinted=False)
        sys.exit(2)
