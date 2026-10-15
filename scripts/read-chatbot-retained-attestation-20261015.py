#!/usr/bin/env python3
"""Read only the fixed failed retained-attestation checkpoint; never read bearer/secret files.

No source bodies are executed. No IAM/DB call, grant, signal, writer repair,
Docker mutation, budget change, admission, signature or runtime authority.
"""
import base64,hashlib,http.client,json,math,os,re,signal,socket,stat,subprocess,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-d8a817cd13770cd5a655b8b955ef8959588959ffb0751dd24ddd1ef28e49fd52')
REVIEW='e375f7fe868806206c42a0609d98de65fab96d3b0aafcec375af0004d91d3e25'
AUTHORITY='3a2c33eabd19545bf1128f5049a4fa7df79cf76edec450b6c4946144c3943fd8'
SOURCE='43819bc04dc40daaf119a2098945405f42d7bc6f'
UNIT='ouf-file-cohort-d8a817cd13770cd5a655b8b955ef8959.service'
CID='790c62742c92eabc095d4ab22f2070e0c40a41e4a219685a7d8120e4661e4e5d'
CLAIM='chatbot-file-cohort-mounted-token-reprocessing-8c59697f46b3ce1b54d1cff1acf1f08dde6c4087062d28e379465d9a76ec570a.claim.json'
OLD_TRANSITION='8cfb376001410bce948163aa858d88174d04612516f6537bebdf0c36a9da60c8'
PHASES=('STOP_REVOKE_OLD_LEASE','QUIESCE_PRODUCERS','FENCED_BACKUP','RELEASE_OLD_ENDPOINT','CREATE_REPLACEMENT','STAGE_PAUSED_REPLACEMENT','ATTEST_NEW_OCI_PEER','ADMIT_MIGRATION','START_REPLACEMENT','VERIFY_APPLICATION','RELEASE_PRODUCERS')
SOURCE_PINS={'paused_workload_binding': 'fc6c53dbd1d70abf81e3647055115b84a7e5cead8f1933baa713fcaa57b5e139', 'file_only_node_owner': '5447075632c1cbcc9a9772ec07ee533ef2b3a227f8ea6ce23bc748d9728f3230', 'file_only_installation': '9aa288c2636f4324395694bf837e95ba87b12cc89f1664be8ee2e233f3f9ca26'}
READS={};ERRORS=[]
class ReadDenied(Exception):pass

def require(ok,code):
    if not ok:raise ReadDenied(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def unique(pairs):
    result={}
    for key,value in pairs:require(key not in result,'DUPLICATE_JSON_KEY');result[key]=value
    return result

def read(path,maximum=262144,expected=None):
    path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_READ_PATH_REQUIRED')
    for parent in path.parents:
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CONTROLLED_ANCESTRY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600
            and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_BOUNDED_RECORD_REQUIRED')
        data=bytearray()
        while len(data)<=maximum:
            part=os.read(fd,min(65536,maximum+1-len(data)))
            if not part:break
            data.extend(part)
        h=hashlib.sha256(data).hexdigest()
        require(len(data)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(path.lstat()),'PRIVATE_RECORD_READ_DRIFT')
        require(expected is None or h==expected,'PRIVATE_RECORD_HASH_DRIFT')
        if str(path)in READS:require(READS[str(path)][0]==h,'PRIVATE_RECORD_CHANGED_DURING_DIAGNOSIS')
        READS[str(path)]=(h,maximum)
        return json.loads(data,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in()).throw(ReadDenied('NONFINITE_JSON')))
    finally:os.close(fd)

def emit(check,**values):
    fixed={'schema':'ouf.chatbot-retained-attestation-readback.v1','check':check,'readOnly':True,'automaticRetry':False,'budgetReset':False}
    require(not set(fixed)&set(values),'RESERVED_DIAGNOSTIC_FIELD')
    print(json.dumps({**fixed,**values},sort_keys=True),flush=True)
def attempt(check,call):
    try:return call()
    except Exception as error:
        ERRORS.append(check)
        # Only this reader's static codes may leave the process.
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)is not None,'CLOSED_PUBLIC_ERROR_REQUIRED')
        emit(check,status='UNAVAILABLE',reason=reason,exceptionMessagePrinted=False)

def projection(row):
    result={k:row[k]for k in('state','version','attempts','publicationCount','controlledPredecessorGrantAttempts','controlledCumulativeGrantAttempts','nextPhase','nextStep')if k in row}
    require(all(type(v)is int or(type(v)is str and re.fullmatch('[A-Z][A-Z0-9_]{0,79}',v))for v in result.values()),'CLOSED_RECORD_PROJECTION_REQUIRED')
    return result

def systemd(binding):
    path=Path(binding['path']);s=path.stat()
    require(str(path)=='/usr/bin/systemctl'and stat.S_ISREG(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022
        and hashlib.sha256(path.read_bytes()).hexdigest()==binding['sha256'],'PINNED_SYSTEMD_READ_REQUIRED')
    p=subprocess.run([str(path),'show',UNIT,'--property=LoadState,ActiveState,SubState,MainPID,Job'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(p.returncode==0 and len(p.stdout)<=8192,'BOUNDED_SYSTEMD_GET_REQUIRED')
    rows=dict(line.split('=',1)for line in p.stdout.decode('ascii').splitlines()if'='in line)
    require(rows.get('ActiveState')in('inactive','failed')and rows.get('MainPID')=='0'and rows.get('Job')=='','OLD_ACTION_MUST_BE_STOPPED_NO_REPLAY')
    require(identity(s)==identity(path.stat()),'PINNED_SYSTEMD_CHANGED')
    return {'stopped':True,'loadState':rows.get('LoadState'),'activeState':rows['ActiveState']}

def inspect(engine):
    path=engine['socketPath'];pin=tuple(engine['socketBinding'])
    def guard():
        s=os.stat(path,follow_symlinks=False);require(stat.S_ISSOCK(s.st_mode)and(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==pin,'PINNED_ENGINE_SOCKET_DRIFT')
    guard()
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(10);self.sock.connect(path)
    c=Local('localhost',timeout=10)
    try:
        c.request('GET','/v1.44/containers/'+CID+'/json');r=c.getresponse();raw=r.read(2097153)
        require(r.status==200 and len(raw)<=2097152,'BOUNDED_CONTAINER_GET_REQUIRED');guard()
        return json.loads(raw,object_pairs_hook=unique)
    finally:c.close()

def journal(label,path):
    row=read(path);emit(label,recordHash=READS[str(Path(path))][0],**projection(row));return row

def source_check(bundle):
    for name,pin in SOURCE_PINS.items():
        require(bundle['declaration']['sourceHashes'].get(name)==pin,'FAILED_SOURCE_DECLARATION_PIN_DRIFT')
        raw=base64.b64decode(bundle['sources'][name],validate=True)
        require(0<len(raw)<=262144 and hashlib.sha256(raw).hexdigest()==pin,'FAILED_SOURCE_BYTES_PIN_DRIFT')
    emit('FAILED_SOURCE',exactFrozenNodeAndBindingSources=True,sourceBodiesExecuted=False)

def transition_check(paths):
    row=read(Path(paths['transition'])/'recovery.json');effects=row.get('effects',[])
    require(type(effects)is list and len(effects)<=len(PHASES),'BOUNDED_TRANSITION_REQUIRED')
    projected=[]
    for e in effects:
        require(e.get('phase')in PHASES and e.get('state')in('APPLIED','IN_FLIGHT','NO_EFFECT','UNKNOWN'),'CLOSED_EFFECT_REQUIRED')
        value={k:e[k]for k in('intentHash','authorityEvidenceHash','nativeEvidenceHash')if k in e}
        require(all(type(v)is str and re.fullmatch('[0-9a-f]{64}',v)for v in value.values()),'CLOSED_EFFECT_DIGESTS_REQUIRED')
        projected.append({'phase':e['phase'],'state':e['state'],**value})
    marker=row.get('governedUnsignedReprocessing',{})
    emit('REGISTRY_TRANSITION',recordHash=digest(row),**projection(row),phases=projected,
        databaseMayHaveChanged=row.get('databaseMayHaveChanged')is True,
        firstSevenApplied=len(effects)>=7 and all(e.get('phase')==PHASES[i]and e.get('state')=='APPLIED'for i,e in enumerate(effects[:7])),
        bothOlderFailedIntentsRetained=marker.get('predecessorJournalHash')==OLD_TRANSITION and type(marker.get('previousReprocessing'))is dict,
        migrationNativeReceiptPresent=os.path.lexists(Path(paths['evidence'])/'ADMIT_MIGRATION.json'))
    return row

def node_check(paths,transition,review):
    root=Path(paths['node']);info=root.lstat()
    require(stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,'PRIVATE_NODE_DIRECTORY_REQUIRED')
    names=set(os.listdir(root));known={'frame-policy.json','paused-acceptance.json','attestation-issuance-claim.json'}
    emit('NODE_MEMBERS',issuanceClaimPresent='attestation-issuance-claim.json'in names,acceptancePresent='paused-acceptance.json'in names,
        unknownNodeMemberPresent=bool(names-known))
    claim=read(root/'attestation-issuance-claim.json');authorization=read(root/'paused-acceptance.json',131072)
    auth_hash=READS[str(root/'paused-acceptance.json')][0]
    require(claim.get('authorizationHash')==auth_hash,'RETAINED_NODE_AUTHORIZATION_CLAIM_DRIFT')
    expected_context=transition['contextHash'];creation_hash=transition['creationRequestHash']
    require(authorization.get('transitionContextHash')==expected_context and authorization.get('creationRequestHash')==creation_hash
        and authorization.get('containerId')==CID,'RETAINED_NODE_SCOPE_DRIFT')
    require(type(authorization.get('expiresAt'))is int,'FINITE_AUTHORIZATION_EXPIRY_REQUIRED')
    emit('NODE_ACCEPTANCE_METADATA',recordHash=auth_hash,issuanceClaimHash=digest(claim),claimMatchesAuthorization=True,
        currentSourceClosureMatches=authorization.get('sourceClosureHash')==review['sourceClosureHash'],
        authorityExpiryMatches=authorization['expiresAt']==read(CONTEXT/'authority.json',131072,AUTHORITY)['expiresAt'],
        expiredNow=authorization['expiresAt']<=time.time(),signatureReverifiedByReader=False,signatureIssuedByReader=False)
    matches=[e for e in transition['effects']if e.get('phase')=='ATTEST_NEW_OCI_PEER'and e.get('state')=='APPLIED']
    require(len(matches)==1,'ONE_COMPLETED_ATTESTATION_REQUIRED')
    receipt=read(Path(paths['evidence'])/'ATTEST_NEW_OCI_PEER.json',131072,matches[0]['nativeEvidenceHash'])
    require(receipt.get('schema')=='ouf.semantic-owner-signed-paused-node-phase.v1'and receipt.get('transitionContextHash')==expected_context
        and receipt.get('creationRequestHash')==creation_hash and receipt.get('intentHash')==matches[0]['intentHash'],
        'EXACT_COMPLETED_NODE_PHASE_RECEIPT_REQUIRED')
    emit('COMPLETED_NODE_PHASE',recordHash=digest(receipt),completeNativeObservationRecorded=receipt.get('completeNativeObservationPerformed')is True,
        scopedSignatureVerificationRecorded=receipt.get('currentScopedAcceptanceSignatureVerified')is True,
        attestationAcceptedByReader=False)

def main():
    require(os.geteuid()==0,'ROOT_READ_ACCESS_REQUIRED');signal.alarm(90)
    emit('BEGIN',serviceMutations=0,databaseMutations=0,grantRequests=0,iamCalls=0,credentialOrTokenFilesRead=False,maximumEngineGetRequests=2)
    review=read(CONTEXT/'review.json',8388608,REVIEW)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE,'EXACT_FAILED_SOURCE_REQUIRED')
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    require(all(authority.get(k)==v for k,v in review['scopes'].items()),'FAILED_SIGNED_SCOPE_DRIFT')
    process=review['scopes']['finiteActionProcess']
    require(process['unit']==UNIT and process['authorityDirectory']==str(CONTEXT),'EXACT_FAILED_PROCESS_REQUIRED')
    emit('PROCESS',**systemd(review['sourceClosure']['executables']['systemctl']))
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256']);prepared=bundle['prepared']
    require(bundle['declaration']==review['sourceClosure']['declaration']and digest(prepared)==review['privateInputHashes']['preparedInputs'],'RETAINED_PRIVATE_INPUT_DRIFT')
    source_check(bundle)
    status=read(CONTEXT/'delivery-status.json',16384)
    require(status.get('authorityHash')==AUTHORITY and status.get('phase')=='PAUSED_REQUIRES_RECONCILIATION'
        and status.get('reason')=='CURRENT_ATTESTATION_PHASE_AND_CREATION_SCOPE_REQUIRED','EXACT_RETAINED_CHECKPOINT_FAILURE_REQUIRED')
    emit('STATUS',phase=status['phase'],reason=status['reason'],sourceCommit=SOURCE,authorityExpiredNow=authority['expiresAt']<=time.time())
    decision=read(CONTEXT/'decision.json');require(decision.get('approvedReviewHash')==REVIEW,'FAILED_DECISION_REVIEW_DRIFT')
    claim=journal('INCIDENT_CLAIM',CONTEXT.parent/CLAIM);require(claim.get('authorityHash')==AUTHORITY,'FAILED_INCIDENT_CLAIM_DRIFT')
    paths=prepared['registry']['directoryPlan'];transition=transition_check(paths)
    attempt('COMPLETED_NODE_PHASE',lambda:node_check(paths,transition,review))
    owner=Path(review['scopes']['policyTokenOwnerInstallation']['journalPath'])
    worker=journal('WORKER',owner/'recovery.json');session=journal('WORKER_SESSION',owner/'owner-session.json')
    admission=journal('ADMISSION',owner/'owner-admission.json')
    require(digest(session)==worker.get('workerSessionHash')and session==review['scopes']['policyTokenFiniteWorkerSession'],'SIGNED_WORKER_SESSION_DRIFT')
    emit('WORKER_HISTORY',priorControlledGrantAttempts=worker.get('controlledPredecessorGrantAttempts'),attempts=worker.get('attempts'),
        cumulativeAttempts=worker.get('controlledCumulativeGrantAttempts'),
        cumulativeEquationPass=worker.get('controlledCumulativeGrantAttempts')==worker.get('controlledPredecessorGrantAttempts',-1)+worker.get('attempts',-1),
        firstGrantReceiptUnchanged=worker.get('firstGrantReceiptHash')=='4bb904ea93df0766647641fd397cac7d8504f1ca81252ce597d1db363a86105a')
    for label in('authorization','containers','databases','gateway'):
        def later(label=label):
            row=journal('LATER_'+label,Path(process['directoryPlan'][label])/'recovery.json')
            emit('LATER_EFFECTS_'+label,effectCount=len(row.get('effects',[])),backupCount=len(row.get('backups',{})),
                mcpMigrationPresent=row.get('mcpMigration')is not None,mcpAuditRolePresent=row.get('mcpAuditRole')is not None)
        attempt('LATER_'+label,later)
    def native():
        before=inspect(prepared['engine']);after=inspect(prepared['engine'])
        def project(row):
            state=row['State'];require(row['Id']==CID and state.get('Status')in('created','running','paused','restarting','removing','exited','dead'),'CLOSED_NATIVE_STATE_REQUIRED')
            return {'containerId':CID,'running':state['Running'],'paused':state['Paused'],'status':state['Status'],
                'pid':state['Pid'],'restartCount':row['RestartCount']}
        a,b=project(before),project(after);require(a==b and before['State']['StartedAt']==after['State']['StartedAt'],'REGISTRY_GENERATION_CHANGED_DURING_READ')
        emit('REGISTRY_NATIVE',**a,stableAcrossTwoReads=True)
    attempt('REGISTRY_NATIVE',native)
    for path,(h,maximum)in list(READS.items()):read(path,maximum,h)
    emit('END',complete=not ERRORS,unavailableChecks=ERRORS,retainedRecordsStable=True,serviceMutations=0,databaseMutations=0,
        grantRequests=0,iamCalls=0,databaseFenceQueried=False,credentialOrTokenFilesRead=False,sourceBodiesExecuted=False,
        authorityRenewed=False,runtimeAuthorityIssued=False,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error)if type(error)is ReadDenied else type(error).__name__
        emit('STOP',reason=reason if re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,100}',reason)else'UNCLASSIFIED',exceptionMessagePrinted=False)
        raise SystemExit(1)
