#!/usr/bin/env python3
"""Installation-specific metadata-only readback after an interrupted token session."""
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
    fixed=dict(schema='ouf.chatbot-semantic-token-interruption-readback.v1',check=check,readOnly=True,
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

STAGE='/home/oufadmin/ouf-semantic-token-session.CajgP8EI'
PARENT=CONTEXT.parent

def directory_members(path,maximum=128):
    path=Path(path)
    require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_DIRECTORY_REQUIRED')
    for parent in (path,*path.parents):
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0
            and not s.st_mode&0o022,'PRIVATE_DIRECTORY_ANCESTRY_REQUIRED')
    before=path.lstat();require(stat.S_IMODE(before.st_mode)==0o700,'PRIVATE_DIRECTORY_MODE_REQUIRED')
    names=[]
    with os.scandir(path)as rows:
        for row in rows:
            require(len(names)<maximum,'DIRECTORY_READ_BOUND_EXCEEDED');names.append(row.name)
    after=path.lstat();require(identity(before)==identity(after),'DIRECTORY_CHANGED_DURING_READ')
    return sorted(names)

def contexts():
    # Enumerate only the exact recovery namespace; never select a latest entry.
    results=[];count=0
    with os.scandir(PARENT)as rows:
        for row in rows:
            count+=1;require(count<=8192,'SNAPSHOT_ENUMERATION_BOUND_EXCEEDED')
            if re.fullmatch('semantic-token-execution-[A-Za-z0-9_-]{8,64}',row.name):
                require(len(results)<16,'EXECUTION_CONTEXT_COUNT_UNBOUNDED')
                results.append(Path(row.path))
    return sorted(results)

def context_metadata(path):
    names=directory_members(path)
    human=path/'human-session'
    human_names=directory_members(human)if 'human-session'in names else []
    # Do not open recovery.json or any OAuth/token file in this subdirectory.
    present={name:name in names for name in ('review.json','decision.json','human.json','authority.json','issuance.claim.json')}
    signatures=sum(bool(re.fullmatch('[0-9a-f]{64}\\.(DEPLOYMENT_INTENT|FINAL_DEPLOYMENT_APPROVAL)\\.json',name))for name in names)
    unexpected=len(names)-sum(present.values())-signatures-int('human-session'in names)
    return {'contextPath':str(path),'directoryIdentity':[path.stat().st_dev,path.stat().st_ino],
        'entryCount':len(names),'artifacts':present,'signatureArtifactCount':signatures,
        'unexpectedEntryCount':unexpected,
        'humanSessionDirectoryPresent':'human-session'in names,
        'humanSessionJournalPresent':'recovery.json'in human_names,
        'humanSessionEntryCount':len(human_names),'humanSessionStateRead':False,
        'humanSessionCumulativeBudgetProven':False}

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

def new_journal_metadata(path):
    try:names=directory_members(path)
    except FileNotFoundError:return {'present':False,'entryCount':0,'workerInitialized':False}
    return {'present':True,'entryCount':len(names),'workerInitialized':'recovery.json'in names,
        'admissionPresent':'owner-admission.json'in names}

def main():
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated,'ROOT_ISOLATED_READBACK_REQUIRED')
    signal.alarm(60)
    emit('BEGIN',maximumSeconds=60,credentialFilesRead=0,humanSessionStateRead=False,
        grantRequests=0,iamCalls=0,mcpCalls=0,databaseCalls=0,serviceMutations=0)
    old=read(CONTEXT/'review.json',8388608,REVIEW)
    read(CONTEXT/'authority.json',131072,AUTHORITY)
    proposal=read(PRIVATE_REVIEW['path'],8388608,PRIVATE_REVIEW['sha256'])
    candidate=read(CANDIDATE['path'],8388608,CANDIDATE['sha256'])
    require(candidate['privateReviewHash']==PRIVATE_REVIEW['sha256'],'EXACT_CANDIDATE_PROPOSAL_REQUIRED')
    scope=candidate['compiledSessionScope'];prior=Path(proposal['predecessorJournalDirectory'])
    require(str(prior)==old['scopes']['policyTokenOwnerInstallation']['journalPath'],
        'EXACT_CANCELLED_PREDECESSOR_DIRECTORY_REQUIRED')
    records={k:read(prior/k,131072)for k in RETAINED}
    require({k:digest(v)for k,v in records.items()}==RETAINED,'CANCELLED_PREDECESSOR_RECORD_CHANGED')
    require(scope['reviewHash']==PRIVATE_REVIEW['sha256']and scope['predecessorRecordHashes']==RETAINED,
        'EXACT_NEW_SESSION_SCOPE_REQUIRED')
    journal=Path(scope['fenceBinding']['value']['journalPath']);fence=Path(scope['fenceBinding']['path'])
    require(journal.parent==fence.parent==prior.parent and journal.name=='semantic-functional-worker-'+PRIVATE_REVIEW['sha256'],
        'EXACT_NEW_SESSION_PATHS_REQUIRED')
    before_processes=processes();before_contexts=contexts()
    snapshots=[context_metadata(path)for path in before_contexts]
    before_journal=new_journal_metadata(journal);before_fence=os.path.lexists(fence)
    emit('LOCAL_METADATA',matchingProcessCount=len(before_processes),executionContexts=snapshots,
        newJournal=before_journal,globalFencePresent=before_fence,
        predecessorWorkerState=records['recovery.json']['state'],
        priorControlledGrantAttempts=records['recovery.json']['controlledCumulativeGrantAttempts'],
        rawProcessArgumentsPrinted=False,credentialFilesRead=0)
    after_processes=processes()
    require(contexts()==before_contexts and [context_metadata(path)for path in before_contexts]==snapshots
        and new_journal_metadata(journal)==before_journal and os.path.lexists(fence)==before_fence
        and all(read(prior/k,131072)==v for k,v in records.items()),'INTERRUPTION_STATE_CHANGED_DURING_READ')
    no_authority=all(not any(row['artifacts'].values())and row['signatureArtifactCount']==0 for row in snapshots)
    pre_authority=(not before_processes and not after_processes and no_authority and not before_fence
        and before_journal['entryCount']==0 and all(row['unexpectedEntryCount']==0 for row in snapshots))
    emit('END',complete=True,matchingProcessCount=len(after_processes),
        classification='PRE_AUTHORITY_PREPARATION_ONLY_OBSERVED'if pre_authority else'RECONCILIATION_REQUIRED',
        predecessorRecordsUnchanged=True,newAuthorityArtifactsAbsent=no_authority,
        newWorkerInitialized=before_journal['workerInitialized'],
        credentialFilesRead=0,humanSessionStateRead=False,humanSessionCumulativeBudgetProven=False,
        reconciliationPerformed=False,automaticRestartAllowed=False,readerIssuedRuntimeAuthority=False,
        completedTechnicalPhases=8,functionalMilestonesProven=0,recordsMayChangeIndependently=True)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
            exceptionMessagePrinted=False,reconciliationPerformed=False,automaticRestartAllowed=False)
        sys.exit(2)
