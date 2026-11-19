#!/usr/bin/env python3
"""Prepare a private review only; never grant runtime authority or resume work."""
import hashlib, http.client, json, os, re, signal, socket, stat, subprocess, sys, tempfile, time
from pathlib import Path
from urllib.parse import quote

CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-16e5f80e40d09772048f1575850b643a69d4d46520db1a56ccd79a7b1a9e055b')

REVIEW='07ee9e8adf0d645018fb70212884f43c22e85cf3c7288bd78dad5bf0d02413bc'

AUTHORITY='a604f4981d38dc19977e551402674b70146bca8768df07c631c2054c6cc727ca'

SOURCE='d7bbb768970aad1a001ca4d085bcc87c58a29cec'

UNIT='ouf-file-cohort-16e5f80e40d09772048f1575850b643a.service'

def emit(check,**values):
    fixed=dict(schema='ouf.chatbot-semantic-session-review.v1',check=check,readOnly=False,
        automaticRetry=False,budgetReset=False,acceptanceGranted=False)
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

def compile_review(prepared,records,generation,now):
    require(set(records)==set(RETAINED),'EXACT_PREDECESSOR_RECORD_SET_REQUIRED')
    require(all(digest(records[k])==v for k,v in RETAINED.items()),'PREDECESSOR_RECORD_CHANGED')
    worker=records['recovery.json'];admission=records['owner-admission.json']
    require(worker.get('state')=='CANCELLED'and worker.get('reason')=='CANCELLED_BY_OWNER'
        and type(worker.get('attempts'))is int and worker['attempts']==59
        and type(worker.get('controlledCumulativeGrantAttempts'))is int
        and worker['controlledCumulativeGrantAttempts']==69 and admission.get('state')=='BLOCKED',
        'EXACT_CANCELLED_CUMULATIVE69_PREDECESSOR_REQUIRED')
    actor=prepared['authorization']['plan']['selection']
    require(all(type(actor.get(k))is str and bool(actor[k])for k in('issuer','tenant','subject')),
            'EXACT_RETAINED_HUMAN_SELECTION_REQUIRED')
    return {
        'schema':'ouf.chatbot-semantic-functional-session-review.v1',
        'status':'REVIEW_ONLY_EXECUTOR_AND_NEW_HUMAN_AUTHORITY_REQUIRED',
        'preparedAt':now,'installationSpecific':True,'predecessorReviewHash':REVIEW,
        'predecessorAuthorityHash':AUTHORITY,'predecessorRecordHashes':dict(RETAINED),
        'predecessorJournalDirectory':prepared['postGrantWorkerDirectory'],
        'registryGeneration':generation,'reviewedRegistryRequestHash':digest(prepared['registry']['creationRequest']),
        'retainedOwnerInputsHash':digest(prepared['owner']),
        'logicalOperation':'TEATRI_FUNCTIONAL_STAGE1_EXISTING_SEMANTIC_PROPOSAL',
        'commandKey':COMMAND,'proposalHash':PROPOSAL,
        'requestedHumanActor':{k:actor[k]for k in('issuer','tenant','subject')},
        'proposedFiniteBudget':{'profile':'ouf.semantic-functional-session-bounds.v1',
            'reason':'RESTORE_FINITE_POLICY_READINESS_FOR_GOVERNED_TEATRI_REVIEW_AFTER_EXPIRED_APPLICATION_WINDOW',
            'predecessorWorkerAttempts':59,'priorControlledGrantAttempts':69,
            'maximumNewTokenGrantAttempts':128,'maximumCumulativeGrantAttempts':197,
            'maximumSeconds':3600,'renewalIntervalSeconds':60,
            'backoffSeconds':[5,15,60,300,900],'maximumJitterPercent':20,
            'respectRetryAfter':True,'automaticRenewalAllowed':False},
        'requiredOwnerDecision':{'freshAuthenticatedHumanDecisionRequired':True,
            'decisionRef':None,'decisionTimestamp':None,'authorityHash':None,
            'explicitContinuationAfterOwnerCancellationRequired':True,
            'newJournalAndPersistentFencingRequired':True,'sameLogicalIncidentAndHistoryRequired':True},
        'allowedIntendedEffects':['NEW_GOVERNED_TOKEN_WORKER_SESSION_ONLY','BOUNDED_EXISTING_POLICY_READINESS_VERIFICATION'],
        'forbiddenEffects':['REOPEN_CANCELLED_JOURNAL','REPLAY_FIRST_GRANT_OR_CONSUMED_CLAIMS',
            'REINSTALL_TECHNICAL_PHASES','CHANGE_APPLICATION_LIFECYCLE','CHANGE_AUTHORIZATION_GRANTS',
            'CHANGE_GATEWAY_ROUTES','DATABASE_MUTATION','BUDGET_RESET','AUTO_PROPOSE_RETRY',
            'SEMANTIC_APPROVAL_OR_PUBLICATION','AUTOMATIC_SESSION_RENEWAL'],
        'executorGates':['CURRENT_NATIVE_GENERATIONS_AND_AUTHORITY','PRESERVED_CUMULATIVE_HISTORY',
            'ATOMIC_SINGLE_ACTIVE_SESSION_AND_STALE_WORKER_FENCING','NO_FIRST_GRANT_REPLAY',
            'REVOKE_CANCEL_EXPIRY_STOPS_PUBLICATION','AMBIGUOUS_GRANT_REQUIRES_RECONCILIATION',
            'EXPLICIT_TRANSIENT_ONLY_FINITE_BACKOFF','NATIVE_CUSTODY_AND_TLS_QUALIFICATION',
            'REGISTRY_POLICY_READINESS_PROOF','SAME_COMMAND_RECEIPT_RECONCILIATION_BEFORE_PROPOSE'],
        'runtimeAuthorityIssued':False,'readyForExecution':False,'humanApprovalGranted':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':0,'acceptanceGranted':False,
        'credentialFilesRead':0,'grantRequests':0,'serviceMutations':0,'budgetReset':False}

def save_review(value):
    parent=CONTEXT.parent
    require(parent.resolve()==parent,'EXACT_SNAPSHOT_PARENT_REQUIRED')
    for p in (parent,*parent.parents):
        s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'SNAPSHOT_PARENT_CUSTODY_REQUIRED')
    directory=Path(tempfile.mkdtemp(prefix='semantic-functional-session-review-',dir=parent))
    directory.chmod(0o700);target=directory/'review.json';raw=encoded(value)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    require(read(target,8388608)==value,'PRIVATE_REVIEW_READBACK_FAILED')
    return target,hashlib.sha256(raw).hexdigest()

def main():
    require(os.geteuid()==0 and sys.flags.isolated,'ROOT_ISOLATED_PREPARER_REQUIRED');signal.alarm(120)
    emit('BEGIN',maximumSeconds=120,maximumEngineReads=2,credentialFilesRead=0,
        grantRequests=0,iamCalls=0,mcpCalls=0,databaseCalls=0,serviceMutations=0,
        existingConfigurationWrites=0,newPrivateReviewOnly=True)
    review=read(CONTEXT/'review.json',8388608,REVIEW);authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE and
        all(authority[k]==v for k,v in review['scopes'].items()),'RETAINED_AUTHORITY_BINDING_DRIFT')
    require(time.time()>=authority['expiresAt'],'PREDECESSOR_WINDOW_MUST_BE_EXPIRED')
    process=review['scopes']['finiteActionProcess']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'PROCESS_BINDING_DRIFT')
    program=review['sourceClosure']['executables']['systemctl'];stopped(program)
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);p=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']and
        digest(p)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_DRIFT')
    journal=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    require(str(journal)==p['postGrantWorkerDirectory'],'PREDECESSOR_JOURNAL_BINDING_DRIFT')
    records={k:read(journal/k,8388608)for k in RETAINED}
    actual=engine_get(p['engine'],'containers',REGISTRY)
    require(actual is not None and actual.get('Id')==REGISTRY and actual['State'].get('Running')is True,
            'EXACT_RUNNING_REGISTRY_REQUIRED')
    generation=runtime_pin(actual);value=compile_review(p,records,generation,int(time.time()))
    after=engine_get(p['engine'],'containers',REGISTRY)
    require(after is not None and runtime_pin(after)==generation,'REGISTRY_GENERATION_DRIFT')
    require(all(read(journal/k,8388608)==v for k,v in records.items()),'PREDECESSOR_CHANGED_DURING_PREPARATION')
    stopped(program);read(CONTEXT/'review.json',8388608,REVIEW);read(CONTEXT/'authority.json',131072,AUTHORITY)
    read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    path,sha=save_review(value)
    emit('END',complete=True,reviewPath=str(path),reviewSha256=sha,
        readyForExecution=False,runtimeAuthorityIssued=False,humanApprovalGranted=False,
        priorControlledGrantAttempts=69,maximumNewTokenGrantAttempts=128,maximumCumulativeGrantAttempts=197,
        maximumSessionSeconds=3600,credentialFilesRead=0,grantRequests=0,serviceMutations=0,
        completedTechnicalPhases=8,functionalMilestonesProven=0)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
             exceptionMessagePrinted=False,runtimeAuthorityIssued=False)
        sys.exit(2)

