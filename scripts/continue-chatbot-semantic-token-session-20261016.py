#!/usr/bin/env python3
"""Installation-specific continuation of the observed pre-authority preparation and its original OAuth budget."""
import ast, base64, copy, hashlib, http.client, json, os, re, signal, socket, stat, subprocess, sys, tempfile, time, uuid
from contextlib import contextmanager
from types import SimpleNamespace
from pathlib import Path
from urllib.parse import quote

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b')

REVIEW='07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc'

AUTHORITY='a604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca'

SOURCE='d7bbb768970aad1a001ca4d085bcc87c58a29cec'

UNIT='ouf-file-cohort-16e5f80e40d09772048f1575850b643a.service'

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-semantic-token-execution.v1',check=check,readOnly=False,
        automaticCommandRetry=False,budgetReset=False,acceptanceGranted=False)
    require(not set(values)&set(fixed),'RESERVED_OUTPUT_FIELD')
    print(json.dumps({**fixed,**values},sort_keys=True),flush=True)

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

REGISTRY='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
def environment(rows):
    require(type(rows)is list and len(rows)<=512,'BOUNDED_ENVIRONMENT_REQUIRED')
    result={}
    for row in rows:
        require(type(row)is str and len(row)<=65536 and '='in row,'ENVIRONMENT_SHAPE_INVALID')
        k,v=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',k) and k not in result,'ENVIRONMENT_KEY_INVALID')
        result[k]=v
    return result

RETAINED={
    'recovery.json':'eb4b80f386d97621802355fb280728a8623fcd60fb2e4c62284f53bdd20c96d1',
    'owner-session.json':'a6bcc1a232b49f6783d1d7ce17404757eb2fa83909055922dc2477e75e6a86c0',
    'owner-admission.json':'163e7653c6414f4ef39cf08223e97007f7239b5f1977486dcf229a6e33b581e5',
    'owner-status.json':'42b53c8f4e5f8e44669dd90e6e1fb4d1ccdfc87f4c178a26a467301afa7a6b39'}
COMMAND='teatri-semantic-draft-be74308e098aa3a6-20261016'
PROPOSAL='be74308e098aa3a65396f3df739dd8f2837e9f8e27b6e49deb0e49d04506cb1a'

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

PRIVATE_REVIEW={'path':'/etc/ouf/deploy-snapshots/semantic-functional-session-review-e8ced3ui/review.json',
    'sha256':'beefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803'}
CANDIDATE={'path':'/etc/ouf/deploy-snapshots/semantic-session-candidate-048rn2ec/candidate.json',
    'sha256':'0f89461b7ec0d34078dbacc28d3281c935ca2f5c60dd185f2f763f4ffd3650b4'}
OVERLAYS={
    'iam_binding_candidate':'iam_binding_candidate.py',
    'migration_root_custody':'migration_root_custody.py',
    'tools.chatbot_file_cohort.continued_owner':'continued_owner.py',
    'tools.chatbot_file_cohort.review':'review.py',
    'tools.chatbot_file_cohort.human_session':'human_session.py',
    'tools.semantic_policy_token_owner.installed_owner':'installed_owner.py',
    'tools.semantic_policy_token_owner.supervisor':'supervisor.py'}

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

STAGE='/home/oufadmin/ouf-semantic-token-session.CajgP8EI'
RESUME_BINDING={
    'schema':'ouf.pre-authority-token-preparation-continuation.v1',
    'contextPath':'/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem',
    'directoryIdentity':[65028,1322063],
    'targetReadbackHash':digest({'schema':'ouf.pre-authority-token-readback-binding.v1',
        'contextPath':'/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem',
        'directoryIdentity':[65028,1322063],'matchingProcessCount':0,
        'newAuthorityArtifactsAbsent':True,'globalFencePresent':False,
        'newWorkerInitialized':False,'newJournalEntryCount':0,'priorControlledGrantAttempts':69})}

def process_matches(arguments):
    return STAGE in arguments or any(re.fullmatch(
        '/etc/ouf/deploy-snapshots/semantic-token-executor-code-[A-Za-z0-9_-]{8,64}/execute.py',arg)
        for arg in arguments)

def processes():
    # Read bounded Python argv metadata only; never print raw argv or environ.
    matches=[];count=0
    with os.scandir('/proc')as rows:
        for row in rows:
            if not row.name.isdecimal():continue
            count+=1;require(count<=8192,'PROCESS_ENUMERATION_BOUND_EXCEEDED')
            base=Path(row.path)
            try:
                if base.stat().st_uid!=0:continue
                comm=(base/'comm').read_bytes()[:64].strip()
                if not comm.startswith(b'python'):continue
                with (base/'cmdline').open('rb')as stream:raw=stream.read(65537)
                require(len(raw)<=65536,'PYTHON_ARGV_BOUND_EXCEEDED')
                args=raw.decode('utf-8','strict').rstrip('\0').split('\0')
                if process_matches(args):matches.append(int(row.name))
            except (FileNotFoundError,ProcessLookupError):continue
    return sorted(matches)


def main():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
        and sys.dont_write_bytecode and len(sys.argv)==3,'ROOT_ISOLATED_CLOSED_TOKEN_EXECUTOR_REQUIRED')
    code_directory=Path(sys.argv[1]);commit=sys.argv[2]
    require(re.fullmatch('[0-9a-f]{40}',commit),'EXACT_RELEASE_COMMIT_REQUIRED')
    emit('BEGIN',completedTechnicalPhases=8,functionalMilestonesProven=0,
        runtimeAuthorityIssued=False,automaticSessionRenewal=False,
        maximumNewTokenGrantAttempts=128,maximumCumulativeGrantAttempts=197,
        maximumSessionSeconds=3600,foreground=True)
    require(not [pid for pid in processes()if pid!=os.getpid()], 'PREVIOUS_OR_CONCURRENT_TOKEN_EXECUTOR_PRESENT')
    old_review=read(CONTEXT/'review.json',8388608,REVIEW)
    old_authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(old_review['sourceClosure']['declaration']['sourceCommit']==SOURCE
        and time.time()>=old_authority['expiresAt']
        and all(old_authority[k]==v for k,v in old_review['scopes'].items()),'RETAINED_REVIEW_AUTHORITY_DRIFT')
    process=old_review['scopes']['finiteActionProcess']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'RETAINED_PROCESS_BINDING_DRIFT')
    stopped(old_review['sourceClosure']['executables']['systemctl'])
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    require(bundle['declaration']==old_review['sourceClosure']['declaration']
        and digest(bundle['prepared'])==old_review['privateInputHashes']['preparedInputs'],'RETAINED_BUNDLE_DRIFT')
    loader,sources=decode_sources(bundle);prepared=bundle['prepared']
    proposal=read(PRIVATE_REVIEW['path'],8388608,PRIVATE_REVIEW['sha256'])
    candidate=read(CANDIDATE['path'],8388608,CANDIDATE['sha256'])
    require(digest(prepared['owner'])==proposal['retainedOwnerInputsHash']
        and digest(prepared['registry']['creationRequest'])==proposal['reviewedRegistryRequestHash']
        and proposal['predecessorReviewHash']==REVIEW and proposal['predecessorAuthorityHash']==AUTHORITY,
        'EXACT_RETAINED_OWNER_AND_REGISTRY_INPUTS_REQUIRED')
    journal=Path(prepared['postGrantWorkerDirectory'])
    require(str(journal)==proposal['predecessorJournalDirectory']==old_review['scopes']['policyTokenOwnerInstallation']['journalPath'],
        'EXACT_PREDECESSOR_JOURNAL_REQUIRED')
    records={k:read(journal/k,131072)for k in RETAINED}
    require({k:digest(v)for k,v in records.items()}==RETAINED,'CANCELLED_PREDECESSOR_CHANGED')
    first=read(journal/'owner-first-grant.json',16384)
    actual=engine_get(prepared['engine'],'containers',REGISTRY)
    require(actual is not None and actual['State'].get('Running')is True
        and runtime_pin(actual)==proposal['registryGeneration'],'CURRENT_REGISTRY_GENERATION_CHANGED')
    package=read(code_directory/'package.json',131072)
    require(package['sourceCommit']==commit and set(package['sourceHashes'])==set(OVERLAYS),
        'EXACT_TOKEN_ONLY_SOURCE_OVERLAYS_REQUIRED')
    for module,name in OVERLAYS.items():sources[module]=code_bytes(code_directory/name,package['sourceHashes'][module])
    executor_binding={'path':str(code_directory/'execute.py'),'sha256':package['executorSha256']}
    code_bytes(executor_binding['path'],executor_binding['sha256'])
    namespace={'__name__':'sealed_token_only_memory_loader'}
    exec(compile(loader,'<retained-verified-memory-loader>','exec'),namespace)
    pins={**bundle['declaration']['sourcePins'],'ouf-deploy':commit}
    manifest=namespace['declaration'](commit,sources,loader,pins)
    closure={**old_review['sourceClosure'],'declaration':manifest}
    namespace['load_entry'](commit,sources,loader,digest(manifest),pins)
    from tools.chatbot_file_cohort.continued_owner import token_only_session_main
    # Only a new private execution context is created before the HUMAN decision.
    context=Path(RESUME_BINDING['contextPath'])
    token_only_session_main(prepared,sources,closure,proposal,PRIVATE_REVIEW,candidate,CANDIDATE,
        records,first,context,executor_binding,emit=lambda value:print(value,flush=True),
        interrupted_preparation=RESUME_BINDING)

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt)as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
            exceptionMessagePrinted=False,automaticRestart=False,reconciliationRequired=True)
        sys.exit(2)

