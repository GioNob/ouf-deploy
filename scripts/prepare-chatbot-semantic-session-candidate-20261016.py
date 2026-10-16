#!/usr/bin/env python3
"""Prepare a private review only; never grant runtime authority or resume work."""
import ast, copy, hashlib, http.client, json, os, re, signal, socket, stat, subprocess, sys, tempfile, time, uuid
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
    fixed=dict(schema='ouf.chatbot-semantic-session-candidate.v1',check=check,readOnly=False,
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

PRIVATE_REVIEW=Path('/etc/ouf/deploy-snapshots/semantic-functional-session-review-e8ced3ui/review.json')
PRIVATE_HASH='beefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803'
SOURCE_HASHES={
    'installed-owner.py':'016cf2703333297f8c3dd8839c7228532535a2be99fa1b5694452b16ba7ca0f8',
    'supervisor.py':'1c83ad2482faa61c5ea8e76223996856221aebdb6e3acd4c9fea15c87c4cbdbf',
    'producer.py':'2b218432f719c4bb4efa47a2786238b518617ac09023e588e8e605cb18f7c4dd'}

def source(path,expected):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_CANDIDATE_SOURCE_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'SOURCE_PARENT_CUSTODY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1
            and stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=131072,'PRIVATE_CANDIDATE_SOURCE_REQUIRED')
        raw=os.read(fd,131073)
        require(len(raw)==st.st_size and identity(st)==identity(os.fstat(fd))==identity(path.lstat())
            and hashlib.sha256(raw).hexdigest()==expected,'CANDIDATE_SOURCE_DRIFT')
        return raw
    finally:os.close(fd)

def definitions(raw,names,namespace):
    parsed=ast.parse(raw);nodes=[];found=set()
    for node in parsed.body:
        if isinstance(node,(ast.FunctionDef,ast.ClassDef))and node.name in names:
            nodes.append(node);found.add(node.name)
        if isinstance(node,ast.Assign):
            selected={t.id for t in node.targets if isinstance(t,ast.Name)}&names
            if selected:nodes.append(node);found|=selected
    require(found==names,'EXACT_PURE_COMPONENT_DEFINITIONS_REQUIRED')
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<hash-bound-candidate-pure-component>','exec'),namespace)
    return namespace

def qualify_native_publication(raw):
    ns={'os':os,'stat':stat,'Path':Path,'contextmanager':contextmanager,'uuid':uuid,
        'fingerprint':digest,'check':lambda ok:require(ok,'NATIVE_PUBLICATION_CONTRACT_FAILED')}
    definitions(raw,{'protected_directory','identity','AtomicTokenFile'},ns)
    # Synthetic expired data only. No IAM/credential/authority object is created.
    with tempfile.TemporaryDirectory(prefix='semantic-session-native-fixture-',dir=CONTEXT.parent)as d:
        directory=Path(d)/'tokens';directory.mkdir(mode=0o750);os.chown(directory,0,10001)
        binding=SimpleNamespace(output_directory=str(directory),output_member='fixture.jwt',output_gid=10001,
            digest=lambda:'f'*64)
        writer=ns['AtomicTokenFile'](binding);writer.check_custody()
        writer.publish('synthetic.expired.fixture',lambda:None);writer.check_custody()
        file=directory/binding.output_member;s=file.stat()
        require((s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(0,10001,0o440),
            'NATIVE_PUBLISHER_CUSTODY_FAILED')
        require(file.read_text()=='synthetic.expired.fixture','NATIVE_PUBLISHER_READBACK_FAILED')
    return {'nativeUidGidModeProven':True,'atomicPublisherCodeUsed':True,
        'syntheticDataOnly':True,'fixtureRemoved':True,'applicationReadinessProven':False}

def save_candidate(value):
    directory=Path(tempfile.mkdtemp(prefix='semantic-session-candidate-',dir=CONTEXT.parent))
    directory.chmod(0o700);path=directory/'candidate.json';raw=encoded(value)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    require(read(path,8388608)==value,'CANDIDATE_READBACK_FAILED')
    return path,hashlib.sha256(raw).hexdigest()

def main():
    require(os.geteuid()==0 and sys.flags.isolated and len(sys.argv)==4,'ROOT_PINNED_CANDIDATE_INPUTS_REQUIRED')
    signal.alarm(120)
    emit('BEGIN',maximumSeconds=120,maximumEngineReads=2,credentialFilesRead=0,grantRequests=0,
        iamCalls=0,mcpCalls=0,databaseCalls=0,serviceMutations=0,existingConfigurationWrites=0,
        newPrivateCandidateOnly=True,temporarySyntheticPublicationOnly=True)
    sources={name:source(path,SOURCE_HASHES[name])for name,path in zip(SOURCE_HASHES,sys.argv[1:])}
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
    proposal=read(PRIVATE_REVIEW,8388608,PRIVATE_HASH)
    require(proposal['retainedOwnerInputsHash']==digest(p['owner'])and
        proposal['reviewedRegistryRequestHash']==digest(p['registry']['creationRequest'])and
        proposal['predecessorReviewHash']==REVIEW and proposal['predecessorAuthorityHash']==AUTHORITY,
        'PRIVATE_REVIEW_INPUT_DRIFT')
    journal=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    require(str(journal)==p['postGrantWorkerDirectory']==proposal['predecessorJournalDirectory'],
        'PREDECESSOR_JOURNAL_BINDING_DRIFT')
    records={k:read(journal/k,8388608)for k in RETAINED}
    require(all(digest(records[k])==v for k,v in RETAINED.items()),'PREDECESSOR_RECORD_CHANGED')
    first=read(journal/'owner-first-grant.json',16384)
    actual=engine_get(p['engine'],'containers',REGISTRY)
    require(actual is not None and actual.get('Id')==REGISTRY and actual['State'].get('Running')is True
        and runtime_pin(actual)==proposal['registryGeneration'],'REGISTRY_GENERATION_DRIFT')
    ns={'copy':copy,'Path':Path,'fingerprint':digest,'check':lambda ok:require(ok,'GOVERNED_CONTINUATION_REVIEW_DENIED')}
    definitions(sources['installed-owner.py'],{'GOVERNED_SESSION','GOVERNED_HISTORY','compile_governed_session'},ns)
    policy={'delays':[5,15,60,300,900],'max_attempts':128,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2}
    context=digest({'operation':proposal['logicalOperation'],'reviewHash':PRIVATE_HASH})
    scope=ns['compile_governed_session'](proposal,records,first,policy,context,digest(proposal['registryGeneration']),60)
    native=qualify_native_publication(sources['producer.py'])
    after=engine_get(p['engine'],'containers',REGISTRY)
    require(after is not None and runtime_pin(after)==proposal['registryGeneration'],'REGISTRY_GENERATION_DRIFT')
    require(all(read(journal/k,8388608)==v for k,v in records.items())and
        read(journal/'owner-first-grant.json',16384)==first,'PREDECESSOR_CHANGED_DURING_PREPARATION')
    stopped(program);read(PRIVATE_REVIEW,8388608,PRIVATE_HASH)
    read(CONTEXT/'review.json',8388608,REVIEW);read(CONTEXT/'authority.json',131072,AUTHORITY)
    read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    value={'schema':'ouf.semantic-functional-session-candidate.v1','privateReviewHash':PRIVATE_HASH,
        'candidateSourceHashes':SOURCE_HASHES,'compiledSessionScope':scope,'nativeQualification':native,
        'firstGrantReceiptHash':digest(first),'runtimeAuthorityIssued':False,'readyForExecution':False,
        'pendingGates':['SEALED_EXECUTOR_COMPOSITION','FULL_SIGNATURE_AND_FENCING_QUALIFICATION',
            'CURRENT_EXACT_HUMAN_DECISION','CURRENT_REGISTRY_POLICY_READINESS'],
        'acceptanceGranted':False,'budgetReset':False}
    path,sha=save_candidate(value)
    emit('END',complete=True,candidatePath=str(path),candidateSha256=sha,privateReviewHash=PRIVATE_HASH,
        nativeQualification=native,priorControlledGrantAttempts=scope['predecessorGrantAttempts'],
        maximumCumulativeGrantAttempts=scope['maximumCumulativeGrantAttempts'],
        runtimeAuthorityIssued=False,readyForExecution=False,credentialFilesRead=0,grantRequests=0,
        completedTechnicalPhases=8,functionalMilestonesProven=0)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',
             exceptionMessagePrinted=False,runtimeAuthorityIssued=False)
        sys.exit(2)

