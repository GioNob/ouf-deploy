#!/usr/bin/env python3
"""Retained-host closed bootstrap for explicit policy remainder / one MCP update.
No SSH transport or account discovery. The sealed entry owns HUMAN review and
existing-role issuance before every effect; failed/partial claims never replay.
"""
import ast,base64,hashlib,http.client,json,os,re,signal,socket,stat,subprocess,sys,tempfile,time
from pathlib import Path
from urllib.parse import quote


class ReadDenied(Exception):pass

def require(ok,code):
    if not ok:raise ReadDenied(code)

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def digest(v):return hashlib.sha256(encoded(v)).hexdigest()

def identity(s):return tuple(getattr(s,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

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

def runtime_pin(actual):
    mounts=actual['Mounts']
    require(type(mounts)is list and all(type(m)is dict and type(m.get('Destination'))is str for m in mounts)
        and len({m['Destination'] for m in mounts})==len(mounts),'DUPLICATE_OR_INVALID_MOUNT')
    return {'containerId':actual['Id'],'imageId':actual['Image'],
        'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
        'mountsHash':digest(sorted(mounts,key=lambda m:m['Destination'])),
        **{name+'Hash':digest(actual[key])for name,key in
           (('config','Config'),('hostConfig','HostConfig'),('networkSettings','NetworkSettings'))}}

def engine_get(engine,kind,reference):
    require(kind in ('containers','images') and type(reference)is str and
        re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',reference),'FIXED_ENGINE_GET_REQUIRED')
    path=engine['socketPath'];pin=tuple(engine['socketBinding'])
    def guard():
        s=os.stat(path,follow_symlinks=False)
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0 and
            (s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==pin,'ENGINE_SOCKET_DRIFT')
    guard()
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.sock.settimeout(10);self.sock.connect(path)
    conn=Local('localhost',timeout=10)
    try:
        conn.request('GET','/v1.44/'+kind+'/'+quote(reference,safe='')+'/json')
        reply=conn.getresponse();raw=reply.read(2097153)
        require(reply.status in (200,404) and len(raw)<=2097152,'ENGINE_READ_UNAVAILABLE');guard()
        return None if reply.status==404 else json.loads(raw,object_pairs_hook=unique)
    finally:conn.close()

def stopped(program):
    path=Path(program['path']);s=path.stat()
    require(path.is_absolute() and stat.S_ISREG(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
        and hashlib.sha256(path.read_bytes()).hexdigest()==program['sha256'],'SYSTEMCTL_BINDING_DRIFT')
    result=subprocess.run([str(path),'show',UNIT,'--property=ActiveState,MainPID,Job'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(result.returncode==0 and len(result.stdout)<=4096 and len(result.stderr)<=4096,'UNIT_OBSERVATION_UNAVAILABLE')
    values=dict(line.split('=',1)for line in result.stdout.decode('ascii').splitlines()if '='in line)
    require(values.get('ActiveState')in('inactive','failed')and values.get('MainPID')=='0'
        and values.get('Job')=='','PREDECESSOR_PROCESS_MUST_BE_STOPPED')

def code_bytes(path,expected,maximum=131072):
    # Reuse exactly the private custody reader without interpreting source as JSON.
    path=Path(path);require(path.resolve()==path,'EXACT_PRIVATE_CODE_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,
            'CODE_ANCESTRY_CUSTODY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1
            and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=maximum,'PRIVATE_CODE_CUSTODY_REQUIRED')
        raw=os.read(fd,maximum+1)
        require(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat())
            and hashlib.sha256(raw).hexdigest()==expected,'EXECUTOR_CODE_HASH_DRIFT')
        return raw
    finally:os.close(fd)

def decode_sources(bundle):
    require(bundle.get('schema')=='ouf.chatbot-file-cohort-closed-source-bundle.v1','EXACT_RETAINED_SOURCE_BUNDLE_REQUIRED')
    loader=base64.b64decode(bundle['loader'],validate=True)
    sources={k:base64.b64decode(v,validate=True)for k,v in bundle['sources'].items()}
    require(0<len(loader)<=65536 and 0<sum(map(len,sources.values()))<=4194304
        and hashlib.sha256(loader).hexdigest()==bundle['declaration']['loaderHash']
        and {k:hashlib.sha256(v).hexdigest()for k,v in sources.items()}==bundle['declaration']['sourceHashes'],
        'RETAINED_CLOSED_SOURCE_HASH_DRIFT')
    return loader,sources


CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b')
REVIEW='07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc'
AUTHORITY='a604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca'
SOURCE='d7bbb768970aad1a001ca4d085bcc87c58a29cec'
UNIT='ouf-file-cohort-16e5f80e40d09772048f1575850b643a.service'
POLICY_CONTEXT=Path('/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem')
POLICY_AUTHORITY='ccac6ea4c195de2c65937fb0df581adee5a610f167cb2c125662733932312eed'
BASE_WORKER_REVIEW={'path':'/etc/ouf/deploy-snapshots/semantic-functional-session-review-e8ced3ui/review.json',
 'sha256':'beefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803'}
MCP_REVIEW={'path':'/etc/ouf/deploy-snapshots/semantic-mcp-atomic-update-review-kes27w1j/review.json',
 'sha256':'69e052d9bfab8607bc871af3027c1da3a09781faa1f2778b365d0779af0cf9e8'}
WORKER_HASHES={'owner-admission.json':'652bb9dec981208f5a5de047be9a9cd6e49216cae5012b5d7a5b62cc0a70c97b',
 'owner-session.json':'eb262363a384e3bf10a935fbe893568d10590ea4d62c17c5540008c2de819c7b',
 'owner-status.json':'42b53c8f4e5f8e44669dd90e6e1fb4d1ccdfc87f4c178a26a467301afa7a6b39',
 'recovery.json':'f06a7e0d3bcd3ccb8f05b1fcd744b6f33ba003b4d74fa472c9e7950ee00d27ac'}
OVERLAYS={'iam_binding_candidate':'iam_binding_candidate.py','migration_root_custody':'migration_root_custody.py',
 'tools.chatbot_file_cohort.continued_owner':'continued_owner.py','tools.chatbot_file_cohort.review':'review.py',
 'tools.chatbot_file_cohort.human_session':'human_session.py','tools.semantic_policy_token_owner.installed_owner':'installed_owner.py',
 'tools.semantic_policy_token_owner.supervisor':'supervisor.py',
 **{'tools.semantic_mcp_update.'+name:name+'.py'for name in('entry','authority','permit','plan','session','owner','native')}}

def emit(check,**values):
 print(json.dumps(dict(schema='ouf.semantic-mcp-scoped-bootstrap.v1',check=check,
  automaticCommandRetry=False,automaticSessionRenewal=False,budgetReset=False,acceptanceGranted=False,**values),sort_keys=True),flush=True)

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
  and len(sys.argv)==4,'ROOT_ISOLATED_CLOSED_MCP_ENTRY_REQUIRED')
 code=Path(sys.argv[1]);commit=sys.argv[2];mode=sys.argv[3]
 require(re.fullmatch('[0-9a-f]{40}',commit)and mode in('TOKEN_SESSION','MCP_UPDATE'),'EXACT_SCOPED_MODE_REQUIRED')
 signal.alarm(120)
 emit('BEGIN',mode=mode,preparationMaximumSeconds=120,completedTechnicalPhases=8,functionalMilestonesProven=0,
  runtimeAuthorityIssued=False,priorHumanOAuthAttempts=49,maximumCumulativeHumanOAuthAttempts=128,
  priorControlledGrantAttempts=128,maximumCumulativeGrantAttempts=197)
 old=read(CONTEXT/'review.json',8388608,REVIEW);old_authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
 require(old['sourceClosure']['declaration']['sourceCommit']==SOURCE
  and all(old_authority[k]==v for k,v in old['scopes'].items()),'RETAINED_WHOLE_COHORT_INPUTS_CHANGED')
 stopped(old['sourceClosure']['executables']['systemctl'])
 process=old['scopes']['finiteActionProcess'];bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256'])
 require(bundle['declaration']==old['sourceClosure']['declaration']
  and digest(bundle['prepared'])==old['privateInputHashes']['preparedInputs'],'EXACT_RETAINED_SOURCE_BUNDLE_REQUIRED')
 _,sources=decode_sources(bundle);prepared=bundle['prepared']
 private=read(MCP_REVIEW['path'],8388608,MCP_REVIEW['sha256'])
 require(private.get('schema')=='ouf.mcp-one-component-update-private-review.v2'
  and private.get('readyForExecution')is False and private.get('runtimeAuthorityIssued')is False,
  'EXACT_UNEXECUTED_ATOMIC_MCP_REVIEW_REQUIRED')
 actual=engine_get(prepared['engine'],'containers',private['oldRuntimeBinding']['containerId'])
 require(actual is not None and actual['State']['Running']is True and runtime_pin(actual)==private['oldRuntimeBinding'],
  'CURRENT_REVIEWED_MCP_GENERATION_REQUIRED')
 package=read(code/'package.json',131072)
 require(package.get('sourceCommit')==commit and set(package.get('sourceHashes',{}))==set(OVERLAYS),
  'EXACT_SCOPED_SOURCE_OVERLAYS_REQUIRED')
 for module,name in OVERLAYS.items():sources[module]=code_bytes(code/name,package['sourceHashes'][module])
 loader=code_bytes(code/'runtime.py',package['loaderSha256'],65536)
 code_bytes(code/'execute.py',package['executorSha256'])
 case=read(code/'case.json',131072,package['caseSha256'])
 require(case.get('schema')=='ouf.semantic-mcp-scoped-execution-selection.v1'
  and case.get('mcpReviewBinding')==MCP_REVIEW and case.get('mode')==mode,'EXACT_SEALED_EXECUTION_SELECTION_REQUIRED')
 resources={'mcpReview':private,'mcpReviewBinding':MCP_REVIEW}
 if mode=='TOKEN_SESSION':
  old_policy=read(POLICY_CONTEXT/'authority.json',131072,POLICY_AUTHORITY)
  scope=old_policy['policyTokenFiniteWorkerSession'];journal=Path(scope['fenceBinding']['value']['journalPath'])
  require(str(journal)==private['retainedTokenWorker']['journalPath'],'SAME_CANCELLED_TOKEN_JOURNAL_REQUIRED')
  records={name:read(journal/name,131072,expected)for name,expected in WORKER_HASHES.items()}
  require(records['owner-session.json']==scope and records['recovery.json']['controlledCumulativeGrantAttempts']==128
   and time.time()>=old_policy['expiresAt']
   and read(scope['fenceBinding']['path'],16384)==scope['fenceBinding']['value'],
   'EXACT_CANCELLED_CONTROLLED128_HISTORY_REQUIRED')
  base=read(BASE_WORKER_REVIEW['path'],8388608,BASE_WORKER_REVIEW['sha256'])
  require(base['retainedOwnerInputsHash']==digest(prepared['owner']),'EXACT_RETAINED_OWNER_INPUTS_REQUIRED')
  current=engine_get(prepared['engine'],'containers',base['registryGeneration']['containerId'])
  require(current is not None and current['State']['Running']is True and runtime_pin(current)==base['registryGeneration'],
   'CURRENT_REVIEWED_REGISTRY_GENERATION_REQUIRED')
  human_path=POLICY_CONTEXT/'human-session-window2'
  require(not os.path.lexists(human_path/'successor-window.claim.json'),'HUMAN_SUCCESSOR_ALREADY_CLAIMED_RECONCILIATION_REQUIRED')
  human=read(human_path/'recovery.json',65536)
  require(digest(human['binding'])==old_policy['semanticTokenOnlyExecution']['humanSessionHash']
   and human['attempts']==49 and human['state']=='READY'and human['operation']=='USERINFO'
   and human['binding']['expiresAt']==1792172784,'EXACT_OBSERVED_HUMAN_OAUTH49_STATE_REQUIRED')
  resources.update(workerRecords=records,workerJournal=str(journal),firstGrant=read(journal/'owner-first-grant.json',16384),
   baseWorkerReview=base,previousHumanDirectory=str(human_path),previousHumanExpiry=1792172784)
 else:
  require(type(case.get('tokenContext'))is str and Path(case['tokenContext']).parent==CONTEXT.parent
   and re.fullmatch('semantic-mcp-update-execution-[A-Za-z0-9_-]{8,64}',Path(case['tokenContext']).name),
   'EXACT_ACTIVE_POLICY_CONTEXT_SELECTION_REQUIRED')
  require(type(case.get('ownerReceiptAbsence'))is dict and case.get('ownerConnectionRef')=='link_6aafef96b4148191b767e9af7b756a07',
   'SEALED_FRESH_OWNER_RECEIPT_READ_REQUIRED')
  resources.update(tokenContext=case['tokenContext'],ownerReceiptAbsence=case['ownerReceiptAbsence'],
   ownerConnectionRef=case['ownerConnectionRef'],executionSelection=case['executionSelection'])
 namespace={'__name__':'sealed_scoped_mcp_memory_loader'}
 exec(compile(loader,'<verified-scoped-mcp-memory-loader>','exec'),namespace)
 pins={**bundle['declaration']['sourcePins'],'ouf-deploy':commit}
 execution_pins={k:package[k]for k in('executorSha256','caseSha256')};execution_pins['mode']=mode
 declaration=namespace['declaration'](commit,sources,loader,pins,execution_pins)
 closure={**old['sourceClosure'],'declaration':declaration}
 entry,_=namespace['load_entry'](commit,sources,loader,digest(declaration),pins,execution_pins)
 context=Path(tempfile.mkdtemp(prefix='semantic-mcp-update-execution-',dir=CONTEXT.parent));context.chmod(0o700)
 emit('PREPARED',mode=mode,contextPath=str(context),mcpReviewBinding=MCP_REVIEW,
  completedTechnicalPhases=8,functionalMilestonesProven=0,controlledCumulativeGrantAttempts=128,
  maximumCumulativeGrantAttempts=197,priorHumanOAuthAttempts=49,maximumCumulativeHumanOAuthAttempts=128,
  runtimeAuthorityIssued=False)
 # Human login and bounded foreground owner replace the diagnosis deadline.
 signal.alarm(0)
 if mode=='TOKEN_SESSION':entry.token_main(prepared,sources,closure,resources,context,emit=lambda value:print(value,flush=True))
 else:entry.update_main(prepared,closure,resources,context,read,emit=lambda value:print(value,flush=True))

if __name__=='__main__':
 try:main()
 except (Exception,KeyboardInterrupt)as error:
  reason=str(error)if type(error).__name__ in ('ReadDenied','UpdateDenied','HumanSessionPaused','PlanDenied')else type(error).__name__
  emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'LOCAL_EXECUTION_UNPROVEN',
   exceptionMessagePrinted=False,reconciliationRequired=True,runtimeAuthorityIssued=False)
  sys.exit(2)
